"""Evidence attachment management — per-finding file storage with integrity tracking."""

import hashlib
import json
import logging
import mimetypes
import os
import sqlite3
import threading
import uuid
from datetime import datetime
from pathlib import Path

log = logging.getLogger("crucible.models.evidence")

ALLOWED_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg",
    ".pdf", ".txt", ".log", ".json", ".xml", ".csv", ".yaml", ".yml",
    ".pcap", ".pcapng", ".cap",
    ".html", ".htm", ".har",
    ".nmap", ".gnmap",
    ".doc", ".docx", ".xls", ".xlsx",
    ".md", ".conf", ".cfg", ".ini",
    ".burp",
})

BLOCKED_EXTENSIONS = frozenset({
    ".py", ".pyc", ".pyo", ".sh", ".bash", ".zsh", ".fish",
    ".exe", ".dll", ".so", ".dylib",
    ".bat", ".cmd", ".ps1", ".psm1", ".psd1",
    ".rb", ".pl", ".php", ".jsp", ".asp", ".aspx",
    ".jar", ".war", ".class",
    ".msi", ".deb", ".rpm", ".apk", ".ipa",
    ".com", ".scr", ".vbs", ".vbe", ".js", ".wsh", ".wsf",
})

IMAGE_EXTENSIONS = frozenset({".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg"})

MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB
MAX_ATTACHMENTS_PER_FINDING = 20

_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS finding_evidence (
    id           TEXT PRIMARY KEY,
    finding_id   TEXT NOT NULL,
    filename     TEXT NOT NULL,
    stored_path  TEXT NOT NULL,
    content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
    size_bytes   INTEGER NOT NULL DEFAULT 0,
    sha256       TEXT NOT NULL,
    uploaded_at  TEXT NOT NULL,
    uploaded_by  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ev_finding ON finding_evidence(finding_id);
"""

_lock = threading.Lock()


def _db(project_dir):
    """Get or create the evidence DB connection (same findings.db)."""
    db_path = Path(project_dir) / "findings.db"
    if not db_path.exists():
        return None
    conn = sqlite3.connect(str(db_path), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_CREATE_SQL)
    return conn


def _sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _sanitize_filename(raw):
    name = Path(raw).name
    for ch in ("\x00", "..", "/", "\\"):
        if ch in name:
            return None
    if not name or name.startswith("."):
        return None
    return name


def _evidence_dir(project_dir, finding_id):
    d = Path(project_dir) / "evidence" / "attachments" / finding_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def validate_file(filename, file_obj):
    """Validate file extension, size, and content. Returns (ok, error_msg)."""
    safe = _sanitize_filename(filename)
    if not safe:
        return False, "Invalid filename"

    ext = Path(safe).suffix.lower()
    if ext in BLOCKED_EXTENSIONS:
        return False, f"Blocked file type: {ext}"
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"File type not allowed: {ext}. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}"

    file_obj.seek(0, os.SEEK_END)
    size = file_obj.tell()
    file_obj.seek(0)
    if size > MAX_FILE_SIZE:
        mb = MAX_FILE_SIZE // (1024 * 1024)
        return False, f"File too large ({size:,} bytes). Maximum: {mb}MB"
    if size == 0:
        return False, "Empty file"

    return True, None


def count_attachments(project_dir, finding_id):
    conn = _db(project_dir)
    if not conn:
        return 0
    try:
        row = conn.execute(
            "SELECT COUNT(*) FROM finding_evidence WHERE finding_id=?",
            (finding_id,)
        ).fetchone()
        return row[0] if row else 0
    except sqlite3.OperationalError:
        return 0
    finally:
        conn.close()


def add_evidence(project_dir, finding_id, filename, file_obj, uploaded_by=""):
    safe = _sanitize_filename(filename)
    if not safe:
        return None, "Invalid filename"

    with _lock:
        current = count_attachments(project_dir, finding_id)
        if current >= MAX_ATTACHMENTS_PER_FINDING:
            return None, f"Maximum {MAX_ATTACHMENTS_PER_FINDING} attachments per finding"

        dest_dir = _evidence_dir(project_dir, finding_id)
        dest = dest_dir / safe

        if dest.exists():
            stem = Path(safe).stem
            ext = Path(safe).suffix
            ts = datetime.now().strftime("%H%M%S")
            safe = f"{stem}_{ts}{ext}"
            dest = dest_dir / safe

        file_obj.save(str(dest))
        size = dest.stat().st_size
        digest = _sha256(dest)

        ct = mimetypes.guess_type(safe)[0] or "application/octet-stream"
        eid = str(uuid.uuid4())
        now = datetime.now().isoformat()

        try:
            rel = str(dest.relative_to(project_dir))
        except ValueError:
            rel = str(dest)

        conn = _db(project_dir)
        if conn:
            try:
                conn.execute(
                    """INSERT INTO finding_evidence
                       (id, finding_id, filename, stored_path, content_type,
                        size_bytes, sha256, uploaded_at, uploaded_by)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (eid, finding_id, safe, rel, ct, size, digest, now, uploaded_by)
                )
                conn.commit()
            except Exception as exc:
                log.exception("DB insert evidence: %s", exc)
            finally:
                conn.close()

        return {
            "id": eid,
            "finding_id": finding_id,
            "filename": safe,
            "stored_path": rel,
            "content_type": ct,
            "size_bytes": size,
            "sha256": digest,
            "uploaded_at": now,
            "uploaded_by": uploaded_by,
            "is_image": Path(safe).suffix.lower() in IMAGE_EXTENSIONS,
        }, None


def list_evidence(project_dir, finding_id):
    conn = _db(project_dir)
    if not conn:
        return _list_from_disk(project_dir, finding_id)
    try:
        rows = conn.execute(
            "SELECT * FROM finding_evidence WHERE finding_id=? ORDER BY uploaded_at",
            (finding_id,)
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["is_image"] = Path(d["filename"]).suffix.lower() in IMAGE_EXTENSIONS
            result.append(d)
        return result
    except sqlite3.OperationalError:
        return _list_from_disk(project_dir, finding_id)
    finally:
        conn.close()


def _list_from_disk(project_dir, finding_id):
    """Fallback: list files from evidence dir when DB unavailable."""
    d = Path(project_dir) / "evidence" / "attachments" / finding_id
    if not d.is_dir():
        d = Path(project_dir) / "evidence" / finding_id
    if not d.is_dir():
        return []
    result = []
    for f in sorted(d.iterdir()):
        if f.is_file():
            ext = f.suffix.lower()
            result.append({
                "id": f.stem,
                "finding_id": finding_id,
                "filename": f.name,
                "stored_path": str(f.relative_to(project_dir)) if str(f).startswith(str(project_dir)) else str(f),
                "content_type": mimetypes.guess_type(f.name)[0] or "application/octet-stream",
                "size_bytes": f.stat().st_size,
                "sha256": "",
                "uploaded_at": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
                "uploaded_by": "",
                "is_image": ext in IMAGE_EXTENSIONS,
            })
    return result


def get_evidence(project_dir, evidence_id):
    conn = _db(project_dir)
    if not conn:
        return None
    try:
        row = conn.execute(
            "SELECT * FROM finding_evidence WHERE id=?", (evidence_id,)
        ).fetchone()
        return dict(row) if row else None
    except sqlite3.OperationalError:
        return None
    finally:
        conn.close()


def get_evidence_file(project_dir, evidence_id):
    """Returns (file_path, record) or (None, error_msg)."""
    rec = get_evidence(project_dir, evidence_id)
    if not rec:
        return None, "Evidence not found"

    fpath = Path(project_dir) / rec["stored_path"]
    if not fpath.is_file():
        return None, "Evidence file missing from disk"

    if rec.get("sha256"):
        current = _sha256(fpath)
        if current != rec["sha256"]:
            log.error("Evidence integrity mismatch: %s expected=%s actual=%s",
                      evidence_id, rec["sha256"], current)
            return None, "Integrity check failed — file hash mismatch"

    return fpath, rec


def delete_evidence(project_dir, evidence_id):
    rec = get_evidence(project_dir, evidence_id)
    if not rec:
        return False, "Evidence not found"

    fpath = Path(project_dir) / rec["stored_path"]
    if fpath.is_file():
        fpath.unlink()

    conn = _db(project_dir)
    if conn:
        try:
            conn.execute("DELETE FROM finding_evidence WHERE id=?", (evidence_id,))
            conn.commit()
        except Exception as exc:
            log.exception("DB delete evidence: %s", exc)
        finally:
            conn.close()

    return True, None


def evidence_counts(project_dir, finding_ids):
    """Bulk count: {finding_id: count} for a list of finding IDs."""
    conn = _db(project_dir)
    if not conn:
        return {}
    try:
        placeholders = ",".join("?" * len(finding_ids))
        rows = conn.execute(
            f"SELECT finding_id, COUNT(*) as cnt FROM finding_evidence "
            f"WHERE finding_id IN ({placeholders}) GROUP BY finding_id",
            finding_ids
        ).fetchall()
        return {r["finding_id"]: r["cnt"] for r in rows}
    except sqlite3.OperationalError:
        return {}
    finally:
        conn.close()


def migrate_legacy_evidence(project_dir, finding_id):
    """Migrate files from legacy evidence/<finding_id>/ to attachments/ + DB."""
    legacy = Path(project_dir) / "evidence" / finding_id
    new_dir = Path(project_dir) / "evidence" / "attachments" / finding_id
    if not legacy.is_dir() or legacy == new_dir:
        return 0
    if new_dir.exists():
        return 0

    migrated = 0
    for f in legacy.iterdir():
        if not f.is_file():
            continue
        new_dir.mkdir(parents=True, exist_ok=True)
        dest = new_dir / f.name
        try:
            import shutil
            shutil.copy2(str(f), str(dest))
        except OSError:
            continue

        digest = _sha256(dest)
        ct = mimetypes.guess_type(f.name)[0] or "application/octet-stream"
        eid = str(uuid.uuid4())
        now = datetime.now().isoformat()
        try:
            rel = str(dest.relative_to(project_dir))
        except ValueError:
            rel = str(dest)

        conn = _db(project_dir)
        if conn:
            try:
                conn.execute(
                    """INSERT OR IGNORE INTO finding_evidence
                       (id, finding_id, filename, stored_path, content_type,
                        size_bytes, sha256, uploaded_at, uploaded_by)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (eid, finding_id, f.name, rel, ct, dest.stat().st_size,
                     digest, now, "migration")
                )
                conn.commit()
            except Exception:
                pass
            finally:
                conn.close()
        migrated += 1

    return migrated
