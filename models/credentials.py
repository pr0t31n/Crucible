"""Credential vault, credentials, PWNED systems and deployment models.

SQLite-backed storage for the Credentialed Scanning subsystem.
DB file: ``credentials.db`` in the project directory.
"""

import base64
import json
import logging
import sqlite3
import threading
from datetime import datetime
from pathlib import Path

log = logging.getLogger("crucible.models.credentials")

_db_lock = threading.Lock()

# ── Valid enum values ────────────────────────────────────────────────────────

VALID_SOURCES = frozenset({
    "user_provided", "captured_hydra", "captured_responder",
    "captured_plaintext", "captured_default", "captured_dredge",
    "captured_secretsdump", "captured_kerberoast",
})

VALID_CRED_TYPES = frozenset({
    "password", "ntlm_hash", "ssh_key", "kerberos_ticket",
})

VALID_TIERS = frozenset({"PWNED", "AUTH", "PARTIAL"})

VALID_DEPLOY_STATUSES = frozenset({
    "queued", "running", "completed", "failed", "cancelled",
})

# ── Secret fields that MUST be masked in public listings ─────────────────────

_SECRET_FIELDS = frozenset({"secret_enc", "secret_nonce", "secret_tag"})

# ── Schema DDL ───────────────────────────────────────────────────────────────

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS credential_vault (
    id              INTEGER PRIMARY KEY,
    master_salt     BLOB NOT NULL,
    master_verify   BLOB NOT NULL,
    created         TEXT NOT NULL,
    last_accessed   TEXT
);

CREATE TABLE IF NOT EXISTS credentials (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source          TEXT NOT NULL,
    cred_type       TEXT NOT NULL,
    os_tag          TEXT,
    target_ip       TEXT,
    username        TEXT NOT NULL,
    secret_enc      BLOB NOT NULL,
    secret_nonce    BLOB NOT NULL,
    secret_tag      BLOB NOT NULL,
    domain          TEXT,
    protocol        TEXT,
    verified        INTEGER DEFAULT 0,
    verified_on     TEXT,
    added_by        TEXT,
    datetime        TEXT NOT NULL,
    notes           TEXT,
    spray_eligible  INTEGER DEFAULT 1,
    UNIQUE(username, domain, cred_type, protocol, target_ip)
);

CREATE TABLE IF NOT EXISTS pwned_systems (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip              TEXT NOT NULL,
    hostname        TEXT,
    os              TEXT,
    tier            TEXT NOT NULL,
    method          TEXT NOT NULL,
    credential_id   INTEGER REFERENCES credentials(id),
    access_level    TEXT,
    details         TEXT,
    datetime        TEXT NOT NULL,
    notes           TEXT,
    UNIQUE(ip, method, credential_id)
);

CREATE TABLE IF NOT EXISTS pwned_deployments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    pwned_id        INTEGER REFERENCES pwned_systems(id),
    tool            TEXT NOT NULL,
    status          TEXT NOT NULL,
    pid             INTEGER,
    started         TEXT,
    completed       TEXT,
    output_dir      TEXT,
    notes           TEXT,
    files_placed    TEXT,
    files_cleaned   INTEGER DEFAULT 0,
    creds_harvested TEXT
);

CREATE INDEX IF NOT EXISTS idx_cred_source ON credentials(source);
CREATE INDEX IF NOT EXISTS idx_cred_type ON credentials(cred_type);
CREATE INDEX IF NOT EXISTS idx_cred_target ON credentials(target_ip);
CREATE INDEX IF NOT EXISTS idx_pwned_ip ON pwned_systems(ip);
CREATE INDEX IF NOT EXISTS idx_pwned_tier ON pwned_systems(tier);
CREATE INDEX IF NOT EXISTS idx_deploy_pwned ON pwned_deployments(pwned_id);
"""


# ── Helpers ──────────────────────────────────────────────────────────────────

def _now_iso():
    return datetime.now().isoformat()


def _row_to_dict(row):
    if row is None:
        return None
    return dict(row)


def _rows_to_dicts(rows):
    return [dict(r) for r in rows]


def _mask_secrets(cred_dict):
    """Replace secret fields with a masked placeholder."""
    if cred_dict is None:
        return None
    out = dict(cred_dict)
    for field in _SECRET_FIELDS:
        if field in out:
            out[field] = "*****"
    return out


# ── DB init / connection ─────────────────────────────────────────────────────

def _db_path(project_dir):
    return Path(project_dir) / "credentials.db"


_initialized_dbs = set()

def _get_db(project_dir):
    db = sqlite3.connect(str(_db_path(project_dir)),
                         check_same_thread=False, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    # Auto-init schema on first access per project_dir
    key = str(project_dir)
    if key not in _initialized_dbs:
        try:
            db.executescript(_SCHEMA_SQL)
            db.commit()
            _initialized_dbs.add(key)
        except Exception as exc:
            log.debug("Schema init for %s: %s", project_dir, exc)
    return db


def init_db(project_dir):
    """Create credentials.db with all tables. Returns the DB path."""
    path = _db_path(project_dir)
    with _db_lock:
        db = _get_db(project_dir)
        try:
            db.executescript(_SCHEMA_SQL)
            db.commit()
        finally:
            db.close()
    log.info("credentials.db initialised at %s", path)
    return path


# ═════════════════════════════════════════════════════════════════════════════
#  Credential Vault
# ═════════════════════════════════════════════════════════════════════════════

def create_vault(project_dir, salt, verify):
    """Create a credential vault row. Returns the vault id."""
    with _db_lock:
        db = _get_db(project_dir)
        try:
            cur = db.execute(
                "INSERT INTO credential_vault (master_salt, master_verify, created) "
                "VALUES (?, ?, ?)",
                (salt, verify, _now_iso()),
            )
            db.commit()
            return cur.lastrowid
        finally:
            db.close()


def get_vault(project_dir):
    """Return the vault row as a dict, or None if no vault exists."""
    with _db_lock:
        db = _get_db(project_dir)
        try:
            row = db.execute(
                "SELECT * FROM credential_vault ORDER BY id LIMIT 1"
            ).fetchone()
            return _row_to_dict(row)
        finally:
            db.close()


def update_vault_access(project_dir):
    """Set last_accessed on the vault to now."""
    with _db_lock:
        db = _get_db(project_dir)
        try:
            db.execute(
                "UPDATE credential_vault SET last_accessed = ? "
                "WHERE id = (SELECT id FROM credential_vault ORDER BY id LIMIT 1)",
                (_now_iso(),),
            )
            db.commit()
        finally:
            db.close()


# ═════════════════════════════════════════════════════════════════════════════
#  Credentials CRUD
# ═════════════════════════════════════════════════════════════════════════════

def add_credential(project_dir, source, cred_type, username,
                   secret_enc, secret_nonce, secret_tag,
                   domain=None, os_tag=None, target_ip=None,
                   protocol=None, added_by=None, notes=None,
                   spray_eligible=1):
    """Insert a credential. Returns the new row id."""
    with _db_lock:
        db = _get_db(project_dir)
        try:
            cur = db.execute(
                "INSERT INTO credentials "
                "(source, cred_type, os_tag, target_ip, username, "
                " secret_enc, secret_nonce, secret_tag, domain, protocol, "
                " added_by, datetime, notes, spray_eligible) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (source, cred_type, os_tag, target_ip, username,
                 secret_enc, secret_nonce, secret_tag,
                 domain, protocol, added_by, _now_iso(), notes,
                 1 if spray_eligible else 0),
            )
            db.commit()
            return cur.lastrowid
        finally:
            db.close()


def get_credential(project_dir, cred_id):
    """Return a single credential (secrets masked)."""
    with _db_lock:
        db = _get_db(project_dir)
        try:
            row = db.execute(
                "SELECT * FROM credentials WHERE id = ?", (cred_id,)
            ).fetchone()
            return _mask_secrets(_row_to_dict(row))
        finally:
            db.close()


def _get_credential_raw(project_dir, cred_id):
    """Return a single credential WITH encrypted secrets (internal only)."""
    with _db_lock:
        db = _get_db(project_dir)
        try:
            row = db.execute(
                "SELECT * FROM credentials WHERE id = ?", (cred_id,)
            ).fetchone()
            return _row_to_dict(row)
        finally:
            db.close()


def list_credentials(project_dir, source_filter=None, cred_type_filter=None):
    """List credentials with secrets masked. Optional filters."""
    clauses, params = [], []
    if source_filter:
        clauses.append("source = ?")
        params.append(source_filter)
    if cred_type_filter:
        clauses.append("cred_type = ?")
        params.append(cred_type_filter)

    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"SELECT * FROM credentials{where} ORDER BY datetime DESC"

    with _db_lock:
        db = _get_db(project_dir)
        try:
            rows = db.execute(sql, params).fetchall()
            return [_mask_secrets(_row_to_dict(r)) for r in rows]
        finally:
            db.close()


def list_credentials_raw(project_dir):
    """List ALL credentials including encrypted secrets.

    For internal use only (cred file generation, crypto operations).
    """
    with _db_lock:
        db = _get_db(project_dir)
        try:
            rows = db.execute(
                "SELECT * FROM credentials ORDER BY datetime DESC"
            ).fetchall()
            return _rows_to_dicts(rows)
        finally:
            db.close()


def update_credential(project_dir, cred_id, **fields):
    """Update arbitrary fields on a credential. Returns True on success."""
    allowed = {
        "source", "cred_type", "os_tag", "target_ip", "username",
        "secret_enc", "secret_nonce", "secret_tag", "domain", "protocol",
        "verified", "verified_on", "notes", "spray_eligible",
    }
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return False

    set_clause = ", ".join(f"{k} = ?" for k in updates)
    params = list(updates.values()) + [cred_id]

    with _db_lock:
        db = _get_db(project_dir)
        try:
            cur = db.execute(
                f"UPDATE credentials SET {set_clause} WHERE id = ?", params
            )
            db.commit()
            return cur.rowcount > 0
        finally:
            db.close()


def delete_credential(project_dir, cred_id):
    """Delete a credential by id. Returns True if deleted."""
    with _db_lock:
        db = _get_db(project_dir)
        try:
            cur = db.execute(
                "DELETE FROM credentials WHERE id = ?", (cred_id,)
            )
            db.commit()
            return cur.rowcount > 0
        finally:
            db.close()


def update_verified(project_dir, cred_id, ip, protocol, access_level):
    """Append a verification entry to the credential's verified_on JSON array."""
    with _db_lock:
        db = _get_db(project_dir)
        try:
            row = db.execute(
                "SELECT verified_on FROM credentials WHERE id = ?", (cred_id,)
            ).fetchone()
            if row is None:
                return
            existing = []
            if row["verified_on"]:
                try:
                    existing = json.loads(row["verified_on"])
                except (json.JSONDecodeError, TypeError):
                    existing = []

            existing.append({
                "ip": ip,
                "protocol": protocol,
                "access_level": access_level,
                "datetime": _now_iso(),
            })

            db.execute(
                "UPDATE credentials SET verified = 1, verified_on = ? WHERE id = ?",
                (json.dumps(existing), cred_id),
            )
            db.commit()
        finally:
            db.close()


def count_credentials(project_dir):
    """Return total credential count."""
    with _db_lock:
        db = _get_db(project_dir)
        try:
            row = db.execute("SELECT COUNT(*) AS cnt FROM credentials").fetchone()
            return row["cnt"] if row else 0
        finally:
            db.close()


# ═════════════════════════════════════════════════════════════════════════════
#  PWNED Systems
# ═════════════════════════════════════════════════════════════════════════════

def add_pwned(project_dir, ip, tier, method, credential_id,
              hostname=None, os_name=None, access_level=None, details=None):
    """Insert a PWNED system entry. Returns the new row id."""
    details_str = json.dumps(details) if isinstance(details, dict) else details
    with _db_lock:
        db = _get_db(project_dir)
        try:
            cur = db.execute(
                "INSERT OR IGNORE INTO pwned_systems "
                "(ip, hostname, os, tier, method, credential_id, "
                " access_level, details, datetime) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (ip, hostname, os_name, tier, method, credential_id,
                 access_level, details_str, _now_iso()),
            )
            db.commit()
            if cur.lastrowid:
                return cur.lastrowid
            # Row already existed — fetch its id
            row = db.execute(
                "SELECT id FROM pwned_systems "
                "WHERE ip = ? AND method = ? AND credential_id = ?",
                (ip, method, credential_id),
            ).fetchone()
            return row["id"] if row else None
        finally:
            db.close()


def get_pwned(project_dir, pwned_id):
    """Return a single PWNED system entry."""
    with _db_lock:
        db = _get_db(project_dir)
        try:
            row = db.execute(
                "SELECT * FROM pwned_systems WHERE id = ?", (pwned_id,)
            ).fetchone()
            return _row_to_dict(row)
        finally:
            db.close()


def list_pwned(project_dir, tier_filter=None, exclude_user_provided=True):
    """List PWNED systems. By default excludes entries from user-provided creds."""
    clauses, params = [], []

    if tier_filter:
        clauses.append("p.tier = ?")
        params.append(tier_filter)

    if exclude_user_provided:
        clauses.append(
            "(p.credential_id IS NULL OR c.source != 'user_provided')"
        )

    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""

    sql = (
        "SELECT p.* FROM pwned_systems p "
        "LEFT JOIN credentials c ON p.credential_id = c.id"
        f"{where} ORDER BY p.datetime DESC"
    )

    with _db_lock:
        db = _get_db(project_dir)
        try:
            rows = db.execute(sql, params).fetchall()
            return _rows_to_dicts(rows)
        finally:
            db.close()


def pwned_stats(project_dir, exclude_user_provided=True):
    """Return tier counts: {PWNED: n, AUTH: n, PARTIAL: n}."""
    stats = {"PWNED": 0, "AUTH": 0, "PARTIAL": 0}

    if exclude_user_provided:
        sql = (
            "SELECT p.tier, COUNT(*) AS cnt FROM pwned_systems p "
            "LEFT JOIN credentials c ON p.credential_id = c.id "
            "WHERE (p.credential_id IS NULL OR c.source != 'user_provided') "
            "GROUP BY p.tier"
        )
    else:
        sql = "SELECT tier, COUNT(*) AS cnt FROM pwned_systems GROUP BY tier"

    with _db_lock:
        db = _get_db(project_dir)
        try:
            for row in db.execute(sql).fetchall():
                tier = row["tier"] if "tier" in row.keys() else row[0]
                cnt = row["cnt"] if "cnt" in row.keys() else row[1]
                if tier in stats:
                    stats[tier] = cnt
            return stats
        finally:
            db.close()


def add_pwned_note(project_dir, pwned_id, note):
    """Append a timestamped note to a PWNED system entry."""
    with _db_lock:
        db = _get_db(project_dir)
        try:
            row = db.execute(
                "SELECT notes FROM pwned_systems WHERE id = ?", (pwned_id,)
            ).fetchone()
            if row is None:
                return False
            existing = row["notes"] or ""
            ts = datetime.now().strftime("%H:%M:%S")
            new_notes = f"{existing}\n[{ts}] {note}".strip()
            db.execute(
                "UPDATE pwned_systems SET notes = ? WHERE id = ?",
                (new_notes, pwned_id),
            )
            db.commit()
            return True
        finally:
            db.close()


# ═════════════════════════════════════════════════════════════════════════════
#  PWNED Deployments
# ═════════════════════════════════════════════════════════════════════════════

def add_deployment(project_dir, pwned_id, tool, status="queued"):
    """Create a new deployment record. Returns the new row id."""
    with _db_lock:
        db = _get_db(project_dir)
        try:
            cur = db.execute(
                "INSERT INTO pwned_deployments (pwned_id, tool, status, started) "
                "VALUES (?,?,?,?)",
                (pwned_id, tool, status, _now_iso()),
            )
            db.commit()
            return cur.lastrowid
        finally:
            db.close()


def update_deployment(project_dir, deploy_id, **fields):
    """Update arbitrary fields on a deployment."""
    allowed = {
        "status", "pid", "started", "completed", "output_dir",
        "notes", "files_placed", "files_cleaned", "creds_harvested",
    }
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return False

    set_clause = ", ".join(f"{k} = ?" for k in updates)
    params = list(updates.values()) + [deploy_id]

    with _db_lock:
        db = _get_db(project_dir)
        try:
            cur = db.execute(
                f"UPDATE pwned_deployments SET {set_clause} WHERE id = ?", params
            )
            db.commit()
            return cur.rowcount > 0
        finally:
            db.close()


def list_deployments(project_dir, pwned_id):
    """List all deployments for a PWNED system entry."""
    with _db_lock:
        db = _get_db(project_dir)
        try:
            rows = db.execute(
                "SELECT * FROM pwned_deployments WHERE pwned_id = ? "
                "ORDER BY started DESC",
                (pwned_id,),
            ).fetchall()
            return _rows_to_dicts(rows)
        finally:
            db.close()


def mark_deployment_cleaned(project_dir, deploy_id):
    """Mark a deployment's files as cleaned."""
    with _db_lock:
        db = _get_db(project_dir)
        try:
            cur = db.execute(
                "UPDATE pwned_deployments SET files_cleaned = 1 WHERE id = ?",
                (deploy_id,),
            )
            db.commit()
            return cur.rowcount > 0
        finally:
            db.close()
