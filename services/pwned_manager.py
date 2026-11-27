"""PWNED host management service — file-backed + DB-backed, thread-safe.

Dual-write: maintains the legacy pwned.json file AND writes to
credentials.db (pwned_systems table) for the Credentialed Scanning feature.
"""

import json
import logging
import os
import threading
import uuid

from services.utils import now_iso as _now_iso

log = logging.getLogger("crucible.services.pwned_manager")

_lock = threading.Lock()

ACCESS_TIERS = {
    "system": {"rank": 0, "risk": "CRITICAL", "label": "SYSTEM"},
    "root":   {"rank": 1, "risk": "CRITICAL", "label": "ROOT"},
    "admin":  {"rank": 2, "risk": "HIGH",     "label": "ADMIN"},
    "user":   {"rank": 3, "risk": "MEDIUM",   "label": "USER"},
}

# Map access_level to PWNED tier
_TIER_MAP = {
    "system": "PWNED",
    "root":   "PWNED",
    "admin":  "PWNED",
    "user":   "AUTH",
    "read_only": "PARTIAL",
    "write":  "AUTH",
}

_EMPTY_STORE = {"pwned": [], "schema_version": "1.0"}


# ── internal helpers ────────────────────────────────────────────────

def _pwned_path(proj_dir):
    return os.path.join(proj_dir, "pwned.json")


def _load_store(proj_dir):
    p = _pwned_path(proj_dir)
    if not os.path.isfile(p):
        return {"pwned": [], "schema_version": "1.0"}
    try:
        with open(p, "r") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        log.error("Failed to load %s: %s", p, exc)
        return {"pwned": [], "schema_version": "1.0"}


def _save_store(proj_dir, store):
    p = _pwned_path(proj_dir)
    tmp = p + ".tmp"
    try:
        with open(tmp, "w") as fh:
            json.dump(store, fh, indent=2)
        os.replace(tmp, p)
    except OSError as exc:
        log.error("Failed to save %s: %s", p, exc)
        raise


def _tier_rank(access_level):
    tier = ACCESS_TIERS.get(access_level)
    if tier is not None:
        return tier["rank"]
    return 99


def _make_record(data):
    return {
        "id":             str(uuid.uuid4()),
        "host":           data.get("host", ""),
        "port":           int(data.get("port", 0)),
        "protocol":       data.get("protocol", ""),
        "method":         data.get("method", ""),
        "access_level":   data.get("access_level", "user"),
        "credential_id":  data.get("credential_id", ""),
        "tool":           data.get("tool", ""),
        "finding_id":     data.get("finding_id", ""),
        "evidence_files": list(data.get("evidence_files", [])),
        "captured_at":    _now_iso(),
        "verified":       bool(data.get("verified", False)),
        "notes":          data.get("notes", ""),
    }


# ── public API ──────────────────────────────────────────────────────

def record_pwned(proj_dir, data):
    """Record a new PWNED entry. Returns the full record dict.

    Dual-writes to pwned.json (legacy) and credentials.db (new).
    """
    rec = _make_record(data)
    with _lock:
        store = _load_store(proj_dir)
        store["pwned"].append(rec)
        _save_store(proj_dir, store)

    # Also write to the credentials DB (pwned_systems table)
    _db_record_pwned(proj_dir, data, rec)

    log.info("Recorded PWNED %s on %s:%s via %s",
             rec["id"], rec["host"], rec["port"], rec["protocol"])
    return rec


def _db_record_pwned(proj_dir, data, rec):
    """Write PWNED entry to credentials.db if available."""
    try:
        from models.credentials import add_pwned
    except ImportError:
        return

    ip = rec.get("host", "")
    if not ip:
        return

    # Determine tier from access_level
    access_level = rec.get("access_level", "user")
    tier = data.get("tier", "").upper()
    if tier not in ("PWNED", "AUTH", "PARTIAL"):
        tier = _TIER_MAP.get(access_level, "AUTH")

    method = rec.get("protocol") or rec.get("method") or ""
    credential_id = data.get("credential_id")
    if credential_id is not None:
        try:
            credential_id = int(credential_id)
        except (ValueError, TypeError):
            credential_id = None

    details = json.dumps({
        "access_level": access_level,
        "tool": rec.get("tool", ""),
        "finding_id": rec.get("finding_id", ""),
        "evidence_files": rec.get("evidence_files", []),
    })

    try:
        add_pwned(
            proj_dir,
            ip=ip,
            tier=tier,
            method=method,
            credential_id=credential_id,
            hostname=data.get("hostname"),
            os_name=data.get("os"),
            access_level=access_level,
            details=details,
        )
    except Exception as exc:
        log.debug("_db_record_pwned: %s", exc)


def get_pwned(proj_dir):
    """List all PWNED records, sorted by access-level tier (highest first)."""
    with _lock:
        store = _load_store(proj_dir)
    records = store.get("pwned", [])
    records.sort(key=lambda r: _tier_rank(r.get("access_level", "user")))
    return records


def get_pwned_by_host(proj_dir, host):
    """Get PWNED records for a specific host."""
    with _lock:
        store = _load_store(proj_dir)
    return [r for r in store.get("pwned", []) if r.get("host") == host]


def get_pwned_by_id(proj_dir, pwned_id):
    """Get one record by id, or None."""
    with _lock:
        store = _load_store(proj_dir)
    for r in store.get("pwned", []):
        if r.get("id") == pwned_id:
            return r
    return None


def update_pwned(proj_dir, pwned_id, updates):
    """Update fields on a PWNED record. Returns updated record or None."""
    with _lock:
        store = _load_store(proj_dir)
        for r in store.get("pwned", []):
            if r.get("id") == pwned_id:
                for k, v in updates.items():
                    if k == "id":
                        continue
                    r[k] = v
                _save_store(proj_dir, store)
                log.info("Updated PWNED %s", pwned_id)
                return dict(r)
        log.warning("PWNED record %s not found for update", pwned_id)
        return None


def delete_pwned(proj_dir, pwned_id):
    """Remove a PWNED record. Returns True if deleted."""
    with _lock:
        store = _load_store(proj_dir)
        before = len(store.get("pwned", []))
        store["pwned"] = [r for r in store.get("pwned", [])
                          if r.get("id") != pwned_id]
        if len(store["pwned"]) < before:
            _save_store(proj_dir, store)
            log.info("Deleted PWNED %s", pwned_id)
            return True
        log.warning("PWNED record %s not found for deletion", pwned_id)
        return False


def get_pwned_summary(proj_dir):
    """Returns summary dict: counts by access_level, unique hosts, unique protocols."""
    with _lock:
        store = _load_store(proj_dir)
    records = store.get("pwned", [])
    by_level = {}
    hosts = set()
    protocols = set()
    for r in records:
        lvl = r.get("access_level", "user")
        by_level[lvl] = by_level.get(lvl, 0) + 1
        if r.get("host"):
            hosts.add(r["host"])
        if r.get("protocol"):
            protocols.add(r["protocol"])
    return {
        "total":          len(records),
        "by_access_level": by_level,
        "unique_hosts":   sorted(hosts),
        "unique_protocols": sorted(protocols),
    }
