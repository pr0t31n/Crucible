"""Version-aware project import engine.

Detects the export version of an uploaded ZIP, converts any layout to the
current v2.0 directory structure, and creates + populates a FindingsDB when
the shared module is available.

Supported source formats:
    3.0          – Crucible v2 layout + findings.db (DB-native)
    2.0          – Crucible v2 layout, JSON-only (current production)
    1.x          – Crucible v1 layout (project/ + tools/ subdirs)
    legacy       – Legacy-era export (project_meta.json, pre-Crucible v2)
    raw          – Bare tool output directory with findings.json
    file_import  – Single scanner file (.nessus, .xml, etc.)
"""

import json
import logging
import shutil
from pathlib import Path

log = logging.getLogger("crucible.services.import_engine")

_fdb = None
try:
    import sys as _s
    if "/opt/pr0t31n/shared" not in _s.path:
        _s.path.insert(0, "/opt/pr0t31n/shared")
    import pr0t31n_findings_db as _fdb
except ImportError:
    pass


# ── Version Detection ──────────────────────────────────────────

def detect_export_version(contents_dir):
    """Detect the export format from extracted ZIP contents.

    Returns a dict:
        version      – one of "3.0", "2.0", "1.x", "legacy", "raw",
                        "file_import", or "unknown"
        meta_path    – Path to the metadata file (or None)
        meta         – parsed metadata dict (or None)
        is_v2        – True if meta sits at contents root (v2 layout)
        source_db    – Path to findings.db if present (v3.0 only)
    """
    cd = Path(contents_dir)

    # ── 1. Look for crucible_meta.json ──

    # v2 layout: meta at root
    v2_meta = cd / "crucible_meta.json"
    # v1 layout: meta inside project/
    v1_meta = cd / "project" / "crucible_meta.json"

    meta_path = None
    is_v2 = False
    meta = None

    if v2_meta.exists():
        meta_path = v2_meta
        is_v2 = True
    elif v1_meta.exists():
        meta_path = v1_meta
        is_v2 = False
    else:
        for candidate in cd.rglob("crucible_meta.json"):
            meta_path = candidate
            is_v2 = (candidate.parent == cd)
            break

    if meta_path and meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text())
        except (json.JSONDecodeError, OSError):
            meta = None

    if meta:
        layout = meta.get("layout_version", "")
        db_path = meta_path.parent / "findings.db"
        if db_path.exists():
            return {
                "version": "3.0",
                "meta_path": meta_path,
                "meta": meta,
                "is_v2": is_v2,
                "source_db": db_path,
            }
        if is_v2 or layout == "2.0":
            return {
                "version": "2.0",
                "meta_path": meta_path,
                "meta": meta,
                "is_v2": is_v2,
                "source_db": None,
            }
        return {
            "version": "1.x",
            "meta_path": meta_path,
            "meta": meta,
            "is_v2": False,
            "source_db": None,
        }

    # ── 2. Look for legacy-era project_meta.json ──

    for candidate in cd.rglob("project_meta.json"):
        try:
            vmeta = json.loads(candidate.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if vmeta.get("management_app") in ("crucible", "vantage", None) or "engagement_name" in vmeta:
            return {
                "version": "legacy",
                "meta_path": candidate,
                "meta": vmeta,
                "is_v2": False,
                "source_db": None,
            }

    # ── 3. Look for raw findings output ──

    for pattern in ("findings.json", "findings_crucible.json", "findings.jsonl"):
        hits = list(cd.rglob(pattern))
        if hits:
            return {
                "version": "raw",
                "meta_path": None,
                "meta": None,
                "is_v2": False,
                "source_db": None,
            }

    # ── 4. Look for single scanner files ──

    for ext in ("*.nessus", "*.xml"):
        hits = list(cd.glob(ext))
        if hits:
            return {
                "version": "file_import",
                "meta_path": None,
                "meta": None,
                "is_v2": False,
                "source_db": None,
            }

    return {
        "version": "unknown",
        "meta_path": None,
        "meta": None,
        "is_v2": False,
        "source_db": None,
    }


# ── Meta Extraction ────────────────────────────────────────────

def extract_form_data(version_info):
    """Build form_data dict for create_project() from detected metadata."""
    meta = version_info.get("meta") or {}
    version = version_info["version"]

    if version == "legacy":
        return {
            "name": meta.get("engagement_name", meta.get("name", "Imported Engagement")),
            "client_name": meta.get("client_name", ""),
            "client_short": meta.get("client_short", "imported"),
            "scope": meta.get("scope", "external"),
            "tools": meta.get("tools", []),
            "consultant": meta.get("consultant", {}),
            "client_poc": meta.get("client_poc", {}),
            "start_date": meta.get("start_date", ""),
            "end_date": meta.get("end_date", ""),
            "scope_definition": meta.get("scope_definition", {}),
        }

    if version in ("raw", "file_import"):
        return {
            "name": "Imported Findings",
            "client_name": "",
            "client_short": "imported",
            "scope": "external",
            "tools": [],
            "consultant": {},
            "client_poc": {},
            "start_date": "",
            "end_date": "",
            "scope_definition": {},
        }

    return {
        "name": meta.get("name", "Imported Engagement"),
        "client_name": meta.get("client_name", ""),
        "client_short": meta.get("client_short", "imported"),
        "scope": meta.get("scope", "external"),
        "tools": meta.get("tools", []),
        "consultant": meta.get("consultant", {}),
        "client_poc": meta.get("client_poc", {}),
        "start_date": meta.get("start_date", ""),
        "end_date": meta.get("end_date", ""),
        "scope_definition": meta.get("scope_definition", {}),
        "active_scopes": meta.get("active_scopes", []),
        "scope_tools": meta.get("scope_tools", {}),
        "auto_queue": meta.get("auto_queue", False),
        "oos_handling": meta.get("oos_handling", "explicit"),
        "beacon_url": meta.get("beacon_url", ""),
        "beacon_token": meta.get("beacon_token", ""),
        "beacon_enabled": meta.get("beacon_enabled", False),
    }


# ── File Placement ─────────────────────────────────────────────

def place_files_v2(contents_dir, version_info, project_dir):
    """Copy v2.0/v3.0 layout contents into the new project directory."""
    src = version_info["meta_path"].parent if version_info["meta_path"] else Path(contents_dir)
    pd = Path(project_dir)

    for item in src.iterdir():
        dest = pd / item.name
        if item.name == "crucible_meta.json":
            continue
        if item.name == "findings.db":
            continue
        if item.is_dir():
            shutil.copytree(item, dest, dirs_exist_ok=True)
        else:
            shutil.copy2(item, dest)


def place_files_v1(contents_dir, new_meta):
    """Copy v1.x layout (project/ + tools/) into v2.0 directory structure."""
    cd = Path(contents_dir)
    pd = Path(new_meta.get("project_dir", ""))

    proj_content = cd / "project"
    if pd.exists() and proj_content.exists():
        for item in proj_content.iterdir():
            dest = pd / item.name
            if item.name == "crucible_meta.json":
                continue
            if item.is_dir():
                shutil.copytree(item, dest, dirs_exist_ok=True)
            else:
                shutil.copy2(item, dest)

    tools_content = cd / "tools"
    if tools_content.exists():
        for tool_dir in tools_content.iterdir():
            if tool_dir.is_dir():
                tool_id = tool_dir.name
                dest = new_meta.get("tool_dirs", {}).get(tool_id)
                if dest:
                    dest_path = Path(dest)
                    dest_path.mkdir(parents=True, exist_ok=True)
                    shutil.copytree(tool_dir, dest_path, dirs_exist_ok=True)


def place_files_legacy(contents_dir, version_info, new_meta):
    """Copy legacy-era layout into v2.0 directory structure.

    Legacy layouts have a project_meta.json alongside scope-based tool
    directories (external/ss3, external/osift, etc.) — the same pattern as
    Crucible v2 minus the crucible_meta.json naming.
    """
    src = version_info["meta_path"].parent if version_info["meta_path"] else Path(contents_dir)
    pd = Path(new_meta.get("project_dir", ""))

    for item in src.iterdir():
        dest = pd / item.name
        if item.name in ("project_meta.json", "engagement.json"):
            continue
        if item.name == "findings.db":
            continue
        if item.is_dir():
            shutil.copytree(item, dest, dirs_exist_ok=True)
        else:
            shutil.copy2(item, dest)


def place_files_raw(contents_dir, new_meta):
    """Copy raw tool output (findings.json + any evidence) into the project."""
    cd = Path(contents_dir)
    pd = Path(new_meta.get("project_dir", ""))

    tool_dirs = new_meta.get("tool_dirs", {})
    first_dir = next(iter(tool_dirs.values()), None) if tool_dirs else None
    dest_base = Path(first_dir) if first_dir else pd

    dest_base.mkdir(parents=True, exist_ok=True)
    for item in cd.rglob("*"):
        if item.is_file():
            rel = item.relative_to(cd)
            target = dest_base / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target)


# ── FindingsDB Creation ───────────────────────────────────────

def create_findings_db(project_dir, meta, source_db=None):
    """Create and populate a FindingsDB for an imported project.

    If source_db is provided (v3.0 import), copies and verifies integrity.
    Otherwise populates from JSON files via migrate_legacy_project().

    Returns (db_created: bool, finding_count: int).
    """
    if not _fdb:
        return False, 0

    from config import FINDINGS_DB_FILENAME
    db_path = Path(project_dir) / FINDINGS_DB_FILENAME

    if db_path.exists():
        return True, 0

    if source_db and Path(source_db).exists():
        return _restore_db_from_export(source_db, db_path, project_dir, meta)

    return _populate_db_from_json(db_path, project_dir, meta)


def _restore_db_from_export(source_db, db_path, project_dir, meta):
    """Copy an exported findings.db, verify integrity, rebase paths."""
    try:
        shutil.copy2(str(source_db), str(db_path))

        db = _fdb.FindingsDB(str(db_path))
        result = db.integrity_check()
        if result != "ok":
            log.warning("Imported findings.db integrity check failed: %s — "
                        "re-populating from JSON", result)
            db.close()
            db_path.unlink(missing_ok=True)
            return _populate_db_from_json(db_path, project_dir, meta)

        count = db.get_summary().get("total", 0)

        if meta:
            db.set_meta("project_id", meta.get("id", ""))
            db.set_meta("project_name", meta.get("name", ""))
            db.set_meta("engagement_dir", str(project_dir))

        db.close()
        log.info("Restored findings.db from export: %d findings, integrity OK", count)
        return True, count
    except Exception:
        log.exception("Failed to restore findings.db from export")
        db_path.unlink(missing_ok=True)
        return _populate_db_from_json(db_path, project_dir, meta)


def _populate_db_from_json(db_path, project_dir, meta):
    """Create a fresh FindingsDB and populate from JSON files."""
    try:
        db = _fdb.FindingsDB(str(db_path))
        total = db.migrate_legacy_project(str(project_dir), meta)

        fp_path = Path(project_dir) / "falsePositives.json"
        if not fp_path.exists():
            fp_path = Path(project_dir) / "false_positives.json"
        if fp_path.exists():
            try:
                fps = json.loads(fp_path.read_text())
                for fp_finding in (fps if isinstance(fps, list) else []):
                    fid = fp_finding.get("id")
                    if fid:
                        db.mark_false_positive(fid)
            except (json.JSONDecodeError, OSError):
                pass

        ro_path = Path(project_dir) / "risk_overrides.json"
        if ro_path.exists():
            try:
                overrides = json.loads(ro_path.read_text())
                for fid, info in (overrides if isinstance(overrides, dict) else {}).items():
                    risk = info.get("risk") if isinstance(info, dict) else info
                    reason = info.get("reason", "") if isinstance(info, dict) else ""
                    if risk:
                        db.override_risk(fid, risk, reason)
            except (json.JSONDecodeError, OSError):
                pass

        db.close()
        log.info("Populated findings.db from JSON: %d findings", total)
        return True, total
    except Exception:
        log.exception("Failed to create findings.db from JSON")
        Path(db_path).unlink(missing_ok=True)
        return False, 0


# ── Export Enhancement ─────────────────────────────────────────

def prepare_export_meta(project):
    """Return a modified meta dict for export with correct layout_version.

    If the project has a findings.db, sets layout_version to "3.0" so the
    receiving Crucible knows to expect a DB-native import.
    """
    meta = dict(project)
    eng_dir = meta.get("engagement_dir", meta.get("project_dir", ""))
    if eng_dir:
        try:
            from config import FINDINGS_DB_FILENAME
            if Path(eng_dir, FINDINGS_DB_FILENAME).exists():
                meta["layout_version"] = "3.0"
        except ImportError:
            pass
    meta.pop("_cached_at", None)
    return meta


# ── Rebase Absolute Paths ─────────────────────────────────────

def rebase_tool_dirs(meta, new_project_dir):
    """Rebase absolute paths in tool_dirs and scope_tool_dirs to the new
    project directory.  Imported meta contains paths from the source machine
    which don't exist on the destination.
    """
    pd = Path(new_project_dir)
    old_eng = meta.get("engagement_dir", "")

    new_tool_dirs = {}
    for tid, td in meta.get("tool_dirs", {}).items():
        if old_eng and td.startswith(old_eng):
            rel = td[len(old_eng):].lstrip("/\\")
            new_tool_dirs[tid] = str(pd / rel)
        else:
            new_tool_dirs[tid] = str(pd / tid)

    new_scope_tool_dirs = {}
    for scope_key, dirs in meta.get("scope_tool_dirs", {}).items():
        new_scope_tool_dirs[scope_key] = {}
        for tid, td in dirs.items():
            if old_eng and td.startswith(old_eng):
                rel = td[len(old_eng):].lstrip("/\\")
                new_scope_tool_dirs[scope_key][tid] = str(pd / rel)
            else:
                new_scope_tool_dirs[scope_key][tid] = str(pd / scope_key / tid)

    return new_tool_dirs, new_scope_tool_dirs


# ── High-Level Import Orchestrator ─────────────────────────────

def run_import(contents_dir, create_project_fn):
    """Full import pipeline: detect → create project → place files → create DB.

    Args:
        contents_dir: Path to extracted ZIP contents
        create_project_fn: Callable (form_data) → (pid, meta) — models.project.create_project

    Returns:
        dict with keys: ok, project_id, version, findings_count, db_created, error
    """
    cd = Path(contents_dir)

    vi = detect_export_version(cd)
    version = vi["version"]

    if version == "unknown":
        return {
            "ok": False,
            "error": "Could not detect export format. No crucible_meta.json, "
                     "project_meta.json, or findings files found in ZIP."
        }

    if version == "file_import":
        return {
            "ok": False,
            "error": "file_import",
            "version": "file_import",
            "meta": vi.get("meta"),
        }

    source_meta = vi.get("meta") or {}

    existing_id = source_meta.get("id")
    if existing_id:
        from models.project import get_project
        if get_project(existing_id):
            return {
                "ok": False,
                "error": f"Project '{existing_id}' already exists. "
                         "Delete or rename the existing project first."
            }

    form_data = extract_form_data(vi)
    pid, new_meta = create_project_fn(form_data)
    proj_dir = Path(new_meta.get("project_dir", ""))

    try:
        if version in ("3.0", "2.0"):
            place_files_v2(cd, vi, proj_dir)
            new_td, new_std = rebase_tool_dirs(source_meta, proj_dir)
            _update_project_dirs(pid, new_meta, new_td, new_std, source_meta)

        elif version == "1.x":
            place_files_v1(cd, new_meta)

        elif version == "legacy":
            place_files_legacy(cd, vi, new_meta)
            new_td, new_std = rebase_tool_dirs(source_meta, proj_dir)
            _update_project_dirs(pid, new_meta, new_td, new_std, source_meta)

        elif version == "raw":
            place_files_raw(cd, new_meta)

        db_created, finding_count = create_findings_db(
            proj_dir, new_meta, source_db=vi.get("source_db"))

        return {
            "ok": True,
            "project_id": pid,
            "version": version,
            "findings_count": finding_count,
            "db_created": db_created,
        }
    except Exception as exc:
        log.exception("Import failed after project creation (pid=%s)", pid)
        return {
            "ok": False,
            "project_id": pid,
            "error": f"Import partially completed but hit an error: {exc}",
            "version": version,
        }


def _update_project_dirs(pid, meta, new_tool_dirs, new_scope_tool_dirs, source_meta):
    """Update the project's tool_dirs and scope_tool_dirs after file placement."""
    if new_tool_dirs:
        meta["tool_dirs"] = new_tool_dirs
    if new_scope_tool_dirs:
        meta["scope_tool_dirs"] = new_scope_tool_dirs

    for key in ("active_scopes", "scope_tools", "delegations",
                "auto_queue", "oos_handling"):
        if key in source_meta and key not in meta:
            meta[key] = source_meta[key]

    from models.project import _save_project_meta, _projects_lock, _load_projects
    _save_project_meta(pid, meta)
    with _projects_lock:
        data = _load_projects()
        data[pid] = meta
