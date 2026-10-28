"""Project model — CRUD, discovery, metadata for engagements."""

import json
import logging
import sys
import uuid
import threading
from datetime import datetime
from pathlib import Path

log = logging.getLogger("crucible.models.project")

from config import APP_DIR, CLIENTS_BASE, TOOLS, TOOL_OUTPUT_DIRS, TOOL_SETTINGS_PREFIX

try:
    if "/opt/pr0t31n/shared" not in sys.path:
        sys.path.insert(0, "/opt/pr0t31n/shared")
    import pr0t31n_schema as _us
except ImportError as exc:
    log.debug("pr0t31n_schema not available: %s", exc)
    _us = None

_projects_lock = threading.RLock()
_projects_cache = None


def _scan_engagement_dirs():
    """Scan CLIENTS_BASE for crucible_meta.json files, build project dict.

    Limits scan depth to 4 levels (client/year/tool/engagement) to avoid
    walking large evidence trees.
    """
    projects = {}
    if not CLIENTS_BASE.exists():
        return projects
    for meta_file in CLIENTS_BASE.glob("*/*/crucible_meta.json"):
        _load_meta_file(projects, meta_file)
    for meta_file in CLIENTS_BASE.glob("*/*/*/crucible_meta.json"):
        _load_meta_file(projects, meta_file)
    for meta_file in CLIENTS_BASE.glob("*/*/*/*/crucible_meta.json"):
        _load_meta_file(projects, meta_file)
    return projects


def _load_meta_file(projects, meta_file):
    try:
        with open(meta_file, "r") as f:
            meta = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        log.debug("load meta %s: %s", meta_file, exc)
        return
    pid = meta.pop("id", None)
    if not pid or pid in projects:
        return
    meta["project_dir"] = str(meta_file.parent)
    meta["engagement_dir"] = str(meta_file.parent)
    projects[pid] = meta


def _migrate_legacy_projects_json():
    """One-time migration: read projects.json, write crucible_meta.json per project."""
    legacy = APP_DIR / "projects.json"
    if not legacy.exists():
        return
    try:
        with open(legacy, "r") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        log.debug("read legacy projects.json: %s", exc)
        return
    for pid, entry in data.items():
        proj_dir = Path(entry.get("project_dir", entry.get("engagement_dir", "")))
        if not proj_dir.exists():
            continue
        meta_file = proj_dir / "crucible_meta.json"
        if not meta_file.exists():
            with open(meta_file, "w") as f:
                json.dump({"id": pid, **entry}, f, indent=2)
    try:
        legacy.rename(legacy.with_suffix(".json.bak"))
    except OSError as exc:
        log.debug("rename legacy projects.json: %s", exc)


def _load_projects():
    global _projects_cache
    if _projects_cache is not None:
        return _projects_cache
    with _projects_lock:
        if _projects_cache is not None:
            return _projects_cache
        _migrate_legacy_projects_json()
        _projects_cache = _scan_engagement_dirs()
    return _projects_cache


def _save_project_meta(project_id, meta):
    """Write a single project's crucible_meta.json."""
    proj_dir = Path(meta.get("project_dir", meta.get("engagement_dir", "")))
    if not proj_dir.exists():
        return
    meta_file = proj_dir / "crucible_meta.json"
    with open(meta_file, "w") as f:
        json.dump({"id": project_id, **meta}, f, indent=2)


def _persist_system_info(project_dir):
    """Write system_info.json to the project directory."""
    try:
        import pr0t31n_system_info
        info = pr0t31n_system_info.collect(use_cache=False)
        info["collected_at"] = datetime.now().isoformat()
        si_path = Path(project_dir) / "system_info.json"
        with open(si_path, "w") as f:
            json.dump(info, f, indent=2, default=str)
    except (ImportError, OSError) as exc:
        log.debug("persist system info: %s", exc)
    _persist_network_snapshots(project_dir)


def _persist_network_snapshots(project_dir):
    """Capture ifconfig + ip route at engagement creation for auditability."""
    import platform
    import subprocess
    try:
        snap_dir = Path(project_dir) / "network_snapshots"
        snap_dir.mkdir(parents=True, exist_ok=True)
        now = datetime.now().isoformat()
        is_linux = platform.system() == "Linux"

        ifconfig_cmd = ["ifconfig", "-a"] if is_linux else ["ifconfig"]
        route_cmd = ["ip", "route"] if is_linux else ["netstat", "-rn"]

        snapshots = []

        try:
            r = subprocess.run(ifconfig_cmd, capture_output=True,
                               text=True, timeout=10)
            out = r.stdout or ""
            (snap_dir / "ifconfig_at_creation.txt").write_text(out)
            snapshots.append({
                "type": "ifconfig", "file": "ifconfig_at_creation.txt",
                "timestamp": now, "command": " ".join(ifconfig_cmd),
            })
        except Exception as exc:
            log.warning("ifconfig snapshot: %s", exc)

        try:
            r = subprocess.run(route_cmd, capture_output=True,
                               text=True, timeout=10)
            out = r.stdout or ""
            (snap_dir / "ip_route_at_creation.txt").write_text(out)
            snapshots.append({
                "type": "ip_route", "file": "ip_route_at_creation.txt",
                "timestamp": now, "command": " ".join(route_cmd),
            })
        except Exception as exc:
            log.warning("ip route snapshot: %s", exc)

        manifest = {"created_at": now, "snapshots": snapshots}
        with open(snap_dir / "manifest.json", "w") as f:
            json.dump(manifest, f, indent=2)
    except Exception as exc:
        log.warning("network snapshots: %s", exc)


def capture_post_route_snapshot(eng_dir):
    """Capture ip route after SS3 adds routes. Called once per engagement."""
    import platform
    import subprocess
    try:
        snap_dir = Path(eng_dir) / "network_snapshots"
        dest = snap_dir / "ip_route_post_routes.txt"
        if dest.exists():
            return
        snap_dir.mkdir(parents=True, exist_ok=True)
        is_linux = platform.system() == "Linux"
        route_cmd = ["ip", "route"] if is_linux else ["netstat", "-rn"]
        r = subprocess.run(route_cmd, capture_output=True,
                           text=True, timeout=10)
        dest.write_text(r.stdout or "")

        manifest_path = snap_dir / "manifest.json"
        now = datetime.now().isoformat()
        manifest = {}
        if manifest_path.exists():
            try:
                with open(manifest_path) as f:
                    manifest = json.load(f)
            except (json.JSONDecodeError, OSError) as exc:
                log.debug("load snapshot manifest: %s", exc)
                manifest = {"created_at": now, "snapshots": []}
        else:
            manifest = {"created_at": now, "snapshots": []}
        manifest.setdefault("snapshots", []).append({
            "type": "ip_route_post_routes",
            "file": "ip_route_post_routes.txt",
            "timestamp": now,
            "command": " ".join(route_cmd),
        })
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)
    except Exception as exc:
        log.warning("post-route snapshot: %s", exc)


# ── Tool version tracking ──────────────────────────────────────────────

_TOOL_VERSION_FILE = "tool_versions.json"


def _read_tool_version(tool_id):
    """Read the VERSION file for a pr0t31n tool. Returns version str or None."""
    tool_cfg = TOOLS.get(tool_id)
    if not tool_cfg:
        return None
    script = tool_cfg.get("script")
    if script:
        ver_file = Path(script).resolve().parent / "VERSION"
        try:
            return ver_file.read_text().strip()
        except OSError as exc:
            log.debug("read VERSION for %s: %s", tool_id, exc)
    return None


def record_tool_use(project_dir, tool_id, tool_name=None, version=None):
    """Append a timestamped tool-use entry to the engagement's tracking file."""
    pd = Path(project_dir)
    fp = pd / _TOOL_VERSION_FILE
    try:
        entries = []
        if fp.exists():
            with open(fp) as f:
                entries = json.load(f)
        if not isinstance(entries, list):
            entries = []
        if version is None:
            version = _read_tool_version(tool_id) or "unknown"
        if tool_name is None:
            tool_cfg = TOOLS.get(tool_id)
            tool_name = tool_cfg["name"] if tool_cfg else tool_id
        entries.append({
            "timestamp": datetime.now().isoformat(),
            "tool_id": tool_id,
            "tool_name": tool_name,
            "version": version,
        })
        with open(fp, "w") as f:
            json.dump(entries, f, indent=2)
    except OSError as exc:
        log.debug("record tool use: %s", exc)


def reset_tool_tracking(project_dir):
    """Reset tracking file to just the initial Crucible entry."""
    from config import VERSION
    pd = Path(project_dir)
    fp = pd / _TOOL_VERSION_FILE
    entries = [{
        "timestamp": datetime.now().isoformat(),
        "tool_id": "crucible",
        "tool_name": "Crucible",
        "version": VERSION,
    }]
    try:
        with open(fp, "w") as f:
            json.dump(entries, f, indent=2)
    except OSError as exc:
        log.debug("reset tool tracking: %s", exc)


def reload_projects():
    """Force-refresh the projects cache by re-scanning disk."""
    global _projects_cache
    with _projects_lock:
        _projects_cache = None
    return _load_projects()


def list_projects():
    data = _load_projects()
    projects = []
    for pid, meta in data.items():
        entry = dict(meta)
        entry["id"] = pid
        projects.append(entry)
    projects.sort(key=lambda p: p.get("created", ""), reverse=True)
    return projects


def get_project(project_id):
    data = _load_projects()
    proj = data.get(project_id)
    if proj:
        proj = dict(proj)
        proj["id"] = project_id
        proj.setdefault("auto_queue", False)
        proj.setdefault("oos_handling", "explicit")
        if "active_scopes" not in proj:
            s = proj.get("scope", "external")
            proj["active_scopes"] = [] if s == "multi" else [s]
        proj.setdefault("delegations", {})
    return proj


def create_project(form_data):
    pid = str(uuid.uuid4())
    now = datetime.now()
    ts = now.strftime("%Y%m%d_%H%M%S")
    year = str(now.year)
    client_short = form_data.get("client_short", "project").lower().replace(" ", "_")
    client_short = client_short.replace("/", "").replace("\\", "").replace("..", "").strip("._")

    active_scopes = form_data.get("active_scopes", [form_data.get("scope", "external")])
    tools = form_data.get("tools", [])
    scope_def = form_data.get("scope_definition", {
        "network_cidrs": [], "target_urls": [], "api_specs": [],
        "wireless_ssids": [], "db_targets": [], "endpoint_targets": [], "exclusions": [],
    })

    scope_tools = form_data.get("scope_tools", {})

    if active_scopes == ["multi"]:
        _TOOL_NATIVE_SCOPE = {
            "ss3": "external", "osift": "osint",
            "fracture": "webapp", "siphon": "api",
            "trawler": "pcap", "auger": "database",
            "bastion": "firewall", "forge": "cloud", "quill": "mobile",
            "isotope": "file", "dredge": "endpoint", "aether": "wifi",
            "aether_b": "bluetooth", "aether_z": "zigbee", "aether_u": "uwb",
        }
        resolved_scopes = []
        resolved_scope_tools = {}
        all_tool_ids = set(tools)
        for st_list in scope_tools.values():
            all_tool_ids.update(st_list)
        for tid in all_tool_ids:
            ns = _TOOL_NATIVE_SCOPE.get(tid, "external")
            if ns not in resolved_scopes:
                resolved_scopes.append(ns)
            resolved_scope_tools.setdefault(ns, [])
            if tid not in resolved_scope_tools[ns]:
                resolved_scope_tools[ns].append(tid)
        if not resolved_scopes:
            resolved_scopes = ["external"]
        active_scopes = sorted(resolved_scopes)
        scope_tools = resolved_scope_tools

    if not scope_tools and _us:
        for s in active_scopes:
            scope_tools[s] = list(_us.SCOPE_TOOL_DEFAULTS.get(s, []))

    engagement_id = f"{client_short}_{ts}"
    engagement_root = CLIENTS_BASE / client_short / year / engagement_id
    engagement_root.mkdir(parents=True, exist_ok=True)

    project_dir = engagement_root

    tool_dirs = {}
    scope_tool_dirs = {}

    for scope_key in active_scopes:
        scope_dir = engagement_root / scope_key
        scope_dir.mkdir(parents=True, exist_ok=True)
        if _us:
            _us.create_scope_dir(engagement_root, scope_key)
        else:
            _write_scope_meta(scope_dir, scope_key)

        scope_tool_dirs[scope_key] = {}
        for tool_id in scope_tools.get(scope_key, []):
            tool_dirname = TOOL_OUTPUT_DIRS.get(tool_id, tool_id)
            td = scope_dir / tool_dirname
            scope_tool_dirs[scope_key][tool_id] = str(td)
            if tool_id not in tool_dirs:
                tool_dirs[tool_id] = str(td)

    if _us:
        ej = _us.make_engagement_json(
            engagement_id=engagement_id,
            client_name=form_data.get("client_name", ""),
            client_short=client_short,
            engagement_name=form_data.get("name", "Untitled Engagement"),
            year=year, active_scopes=active_scopes,
            scope_tools=scope_tools, tools=tools,
            start_date=form_data.get("start_date", ""),
            end_date=form_data.get("end_date", ""),
            management_app="crucible",
        )
        _us.write_engagement_json(engagement_root, ej)

    meta = {
        "name": form_data.get("name", "Untitled Engagement"),
        "client_name": form_data.get("client_name", ""),
        "client_short": client_short,
        "year": year,
        "created": now.isoformat(),
        "scope": active_scopes[0] if len(active_scopes) == 1 else "multi",
        "active_scopes": active_scopes,
        "consultant": form_data.get("consultant", {"name": "", "title": "", "email": ""}),
        "client_poc": form_data.get("client_poc", {"name": "", "phone": "", "email": ""}),
        "start_date": form_data.get("start_date", ""),
        "end_date": form_data.get("end_date", ""),
        "tools": tools,
        "tool_dirs": tool_dirs,
        "scope_tools": scope_tools,
        "scope_tool_dirs": scope_tool_dirs,
        "scope_definition": scope_def,
        "engagement_id": engagement_id,
        "engagement_dir": str(engagement_root),
        "layout_version": "2.0",
        "auto_queue": bool(form_data.get("auto_queue", False)),
        "oos_handling": form_data.get("oos_handling", "explicit"),
        "delegations": {},
        "project_dir": str(project_dir),
        "original_tools": list(tools),
        "original_scope_tools": {k: list(v) for k, v in scope_tools.items()},
        "beacon_url": form_data.get("beacon_url", ""),
        "beacon_token": form_data.get("beacon_token", ""),
        "beacon_enabled": bool(form_data.get("beacon_enabled", False)),
    }

    _save_project_meta(pid, meta)
    _persist_system_info(project_dir)
    from config import VERSION
    record_tool_use(project_dir, "crucible", "Crucible", VERSION)

    with _projects_lock:
        data = _load_projects()
        data[pid] = meta

    _write_default_settings(project_dir, tools, form_data,
                            tool_dirs=tool_dirs,
                            scope_tool_dirs=scope_tool_dirs)

    return pid, meta


def _write_scope_meta(scope_dir, scope_key):
    """Fallback scope_meta.json writer when pr0t31n_schema is unavailable."""
    meta = {
        "schema_version": "2.0",
        "scope_key": scope_key,
        "scope_display": scope_key.replace("_", " ").title(),
        "targets": [],
        "tools": {},
    }
    meta_path = scope_dir / "scope_meta.json"
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)


def _deep_merge_settings(base, updates):
    for k, v in updates.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge_settings(base[k], v)
        else:
            base[k] = v


def _write_default_settings(project_dir, tools, form_data=None,
                            tool_dirs=None, scope_tool_dirs=None):
    from config import TOOL_SETTINGS_PREFIX
    from adapters import get_adapter
    scope_def = (form_data or {}).get("scope_definition", {})
    meta = form_data or {}
    for tool_id in tools:
        prefix = TOOL_SETTINGS_PREFIX.get(tool_id)
        if not prefix:
            continue
        settings_file = project_dir / f"{prefix}_settings.json"
        existing = {}
        if settings_file.exists():
            try:
                existing = json.loads(settings_file.read_text())
            except (json.JSONDecodeError, OSError) as exc:
                log.debug("read existing settings %s: %s", settings_file, exc)
        adapter = get_adapter(tool_id)
        defaults = adapter.default_settings() if adapter else {}
        settings = dict(defaults)
        _populate_tool_settings(tool_id, settings, meta, scope_def,
                                str(project_dir),
                                tool_dirs=tool_dirs or {},
                                scope_tool_dirs=scope_tool_dirs or {})
        tool_data = adapter.to_tool_format(settings) if adapter else settings
        _deep_merge_settings(existing, tool_data)
        with open(settings_file, "w") as f:
            json.dump(existing, f, indent=2)


def _populate_tool_settings(tool_id, settings, meta, scope_def, project_dir,
                            tool_dirs=None, scope_tool_dirs=None):
    if tool_dirs is None:
        tool_dirs = {}
    if scope_tool_dirs is None:
        scope_tool_dirs = {}
    client_short = meta.get("client_short", "")
    client_name = meta.get("client_name", "")
    eng_name = meta.get("name", "")
    cidrs = scope_def.get("network_cidrs", [])
    urls = scope_def.get("target_urls", [])
    domains = scope_def.get("domains", [])
    scope = meta.get("scope", meta.get("active_scopes", ["external"])[0]
                     if isinstance(meta.get("active_scopes"), list)
                     and meta.get("active_scopes") else "external")
    if tool_id == "ss3":
        if "scan" not in settings:
            settings["scan"] = {}
        settings["scan"]["project"] = tool_dirs.get("ss3", project_dir)
        ss3_scope_dirs = {}
        for crucible_scope, ss3_scope in (("external", "ext"),
                                          ("internal", "int")):
            sd = scope_tool_dirs.get(crucible_scope, {}).get("ss3")
            if sd:
                ss3_scope_dirs[ss3_scope] = sd
        if ss3_scope_dirs:
            settings["scan"]["scope_output_dirs"] = ss3_scope_dirs
        if cidrs:
            settings["scan"]["targets"] = cidrs
            settings["targets"] = "\n".join(cidrs)
        if "engagement" not in settings:
            settings["engagement"] = {}
        settings["engagement"]["engagement_name"] = eng_name
        settings["engagement"]["client"] = client_name
        settings["engagement"]["client_short"] = client_short
        settings["engagement_name"] = eng_name
        settings["client"] = client_name
        if scope in ("external", "internal"):
            settings["scope_type"] = scope
        elif scope == "multi":
            settings["scope_type"] = "external_and_internal"
        else:
            settings["scope_type"] = "external"
    elif tool_id == "osift":
        settings["company"] = client_name
        settings["client_short"] = client_short
        if domains:
            settings["domains"] = domains
            settings["target_domains"] = "\n".join(domains)
        settings["output_base"] = tool_dirs.get("osift", project_dir)
    elif tool_id == "fracture":
        if "scan" not in settings:
            settings["scan"] = {}
        settings["scan"]["project"] = tool_dirs.get("fracture", project_dir)
        if urls:
            settings["scan"]["target_url"] = urls[0]
            settings["scan"]["target_urls"] = urls
            settings["target_url"] = urls[0]
        if "engagement" not in settings:
            settings["engagement"] = {}
        settings["engagement"]["engagement_name"] = eng_name
        settings["engagement"]["client"] = client_name
        settings["engagement"]["client_short"] = client_short
        auth = scope_def.get("fracture_auth")
        if auth:
            settings["scan"]["auth"] = auth
        fr_roles = scope_def.get("fracture_roles", [])
        if fr_roles:
            settings["scan"]["auth_matrix"] = fr_roles
    elif tool_id == "siphon":
        if "scan" not in settings:
            settings["scan"] = {}
        api_urls = scope_def.get("api_urls", [])
        settings["scan"]["project"] = tool_dirs.get("siphon", project_dir)
        if api_urls:
            settings["scan"]["api_base_url"] = api_urls[0]
            settings["scan"]["api_base_urls"] = api_urls[1:]
            settings["api_base_url"] = api_urls[0]
            settings["api_base_urls"] = api_urls[1:]
        if "engagement" not in settings:
            settings["engagement"] = {}
        settings["engagement"]["engagement_name"] = eng_name
        settings["engagement"]["client"] = client_name
        settings["engagement"]["client_short"] = client_short
        auth = scope_def.get("siphon_auth")
        if auth:
            settings["scan"]["auth"] = auth
        si_roles = scope_def.get("siphon_roles", [])
        if si_roles:
            settings["scan"]["auth_matrix"] = si_roles
    elif tool_id == "auger":
        db_targets = scope_def.get("db_targets", [])
        settings["host"] = db_targets[0] if db_targets else ""
        settings["db_type"] = scope_def.get("auger_db_type", "postgresql")
        settings["database"] = scope_def.get("auger_database", "")
        settings["username"] = scope_def.get("auger_username", "")
        settings["password"] = scope_def.get("auger_password", "")
        settings["jdbc_url"] = scope_def.get("auger_jdbc", "")
        settings["output_dir"] = tool_dirs.get("auger", project_dir)
    elif tool_id == "trawler":
        settings["output_dir"] = tool_dirs.get("trawler", project_dir)
    elif tool_id == "quill":
        settings["mobile_platform"] = scope_def.get("mobile_platform", "android")
        settings["dynamic_analysis"] = scope_def.get("mobile_dynamic", False)
        settings["frida_device"] = scope_def.get("frida_device", "")
        app_path = scope_def.get("mobile_app_path", "")
        if app_path:
            settings["app_files"] = [app_path]


def update_project(project_id, updates):
    with _projects_lock:
        data = _load_projects()
        if project_id not in data:
            return False
        data[project_id].update(updates)
        updated = dict(data[project_id])
    _save_project_meta(project_id, updated)
    return True


def delete_project(project_id, delete_files=False):
    with _projects_lock:
        data = _load_projects()
        meta = data.pop(project_id, None)
        if meta is None:
            return False
    if delete_files:
        import shutil
        proj_dir = Path(meta.get("project_dir", ""))
        if proj_dir.exists():
            shutil.rmtree(proj_dir, ignore_errors=True)
        for td in meta.get("tool_dirs", {}).values():
            tp = Path(td)
            if tp.exists():
                shutil.rmtree(tp, ignore_errors=True)
    else:
        proj_dir = Path(meta.get("project_dir", ""))
        meta_file = proj_dir / "crucible_meta.json"
        if meta_file.exists():
            meta_file.unlink()
    return True


_PRESERVE_ON_CLEAR = {
    "crucible_meta.json", "engagement.json", "scope_meta.json",
    "project_meta.json", "gauntlet_meta.json", "vantage_meta.json",
}


def _clear_dir_preserve_meta(dirpath):
    """Remove contents of a directory but preserve engagement metadata files."""
    import shutil
    dp = Path(dirpath)
    if not dp.exists():
        return
    for child in list(dp.iterdir()):
        if child.name in _PRESERVE_ON_CLEAR:
            continue
        if child.is_dir():
            shutil.rmtree(child, ignore_errors=True)
        else:
            child.unlink(missing_ok=True)


def _save_settings_files(dirpath):
    """Back up *_settings*.json files from a directory before it is wiped."""
    saved = {}
    dp = Path(dirpath)
    if dp.exists():
        for f in dp.glob("*_settings*.json"):
            try:
                saved[f.name] = f.read_text()
            except OSError as exc:
                log.debug("save settings file %s: %s", f, exc)
    return saved


def _restore_settings_files(dirpath, saved):
    dp = Path(dirpath)
    dp.mkdir(parents=True, exist_ok=True)
    for name, content in saved.items():
        (dp / name).write_text(content)


def clear_project(project_id):
    data = _load_projects()
    meta = data.get(project_id)
    if not meta:
        return False
    proj_dir = Path(meta.get("project_dir", ""))
    eng_dir = Path(meta.get("engagement_dir", str(proj_dir)))
    cleared = set()
    import shutil

    for td in meta.get("tool_dirs", {}).values():
        tp = Path(td)
        if tp.exists() and str(tp) not in cleared:
            saved = _save_settings_files(tp)
            if tp == proj_dir:
                _clear_dir_preserve_meta(tp)
            else:
                shutil.rmtree(tp, ignore_errors=True)
            _restore_settings_files(tp, saved)
            cleared.add(str(tp))
    for scope_dirs in meta.get("scope_tool_dirs", {}).values():
        for td in scope_dirs.values():
            tp = Path(td)
            if tp.exists() and str(tp) not in cleared:
                saved = _save_settings_files(tp)
                if tp == proj_dir:
                    _clear_dir_preserve_meta(tp)
                else:
                    shutil.rmtree(tp, ignore_errors=True)
                _restore_settings_files(tp, saved)
                cleared.add(str(tp))

    auto_added = set(meta.get("auto_added_tools") or [])
    if auto_added and eng_dir.exists():
        for scope_dir in eng_dir.iterdir():
            if not scope_dir.is_dir():
                continue
            for tool_dir in scope_dir.iterdir():
                if not tool_dir.is_dir():
                    continue
                tid = tool_dir.name
                _rev_map = {v: k for k, v in TOOL_OUTPUT_DIRS.items()}
                real_tid = _rev_map.get(tid, tid)
                if real_tid in auto_added and str(tool_dir) not in cleared:
                    shutil.rmtree(tool_dir, ignore_errors=True)
                    cleared.add(str(tool_dir))

    for f in proj_dir.glob("crucible_*.jsonl"):
        f.unlink(missing_ok=True)
    for f in proj_dir.glob("action_items.json"):
        f.unlink(missing_ok=True)
    for f in proj_dir.glob("tool_history.json"):
        f.unlink(missing_ok=True)
    for f in proj_dir.glob("console_*.log"):
        f.unlink(missing_ok=True)
    for _stale_name in ("tool_versions.json", "system_info.json",
                        "audit.log", "audit.log.jsonl",
                        "falsePositives.json", "falsePositives.csv",
                        "false_positives.json", "false_positives.csv",
                        "risk_overrides.json"):
        (proj_dir / _stale_name).unlink(missing_ok=True)
    _snap_dir = proj_dir / "network_snapshots"
    if _snap_dir.is_dir():
        shutil.rmtree(_snap_dir, ignore_errors=True)

    if eng_dir.exists():
        for scope_dir in eng_dir.iterdir():
            if not scope_dir.is_dir():
                continue
            for ai_file in scope_dir.rglob("action_items.json"):
                ai_file.unlink(missing_ok=True)
            for _scope_file in scope_dir.iterdir():
                if _scope_file.is_file() and _scope_file.name not in _PRESERVE_ON_CLEAR:
                    _scope_file.unlink(missing_ok=True)

    try:
        from models.action_items import _store as _ai_store
        _ai_store.invalidate(str(proj_dir))
    except Exception as exc:
        log.warning("invalidate action items cache: %s", exc)
    try:
        from flask import current_app
        fe = current_app.extensions.get("findings_engine")
        if fe:
            fe.invalidate(project_id)
        pm = current_app.extensions.get("process_manager")
        if pm:
            pm._live_targets_clear(project_id)
    except Exception as exc:
        log.warning("invalidate findings/targets cache: %s", exc)

    orig_tools = meta.get("original_tools")
    orig_scope_tools = meta.get("original_scope_tools")
    keep_dirs = set()
    if orig_tools is not None:
        restored_scope_tools = orig_scope_tools or {}
        restored_tool_dirs = {}
        restored_scope_tool_dirs = {}
        for sn, stl in restored_scope_tools.items():
            restored_scope_tool_dirs[sn] = {
                t: d for t, d in (meta.get("scope_tool_dirs", {}).get(sn) or {}).items()
                if t in stl
            }
            for t in stl:
                if t in (meta.get("tool_dirs") or {}):
                    restored_tool_dirs[t] = meta["tool_dirs"][t]
        keep_dirs = set(restored_tool_dirs.values())
        for std in restored_scope_tool_dirs.values():
            keep_dirs.update(std.values())
        update_project(project_id, {
            "tools": orig_tools,
            "scope_tools": restored_scope_tools,
            "scope_tool_dirs": restored_scope_tool_dirs,
            "tool_dirs": restored_tool_dirs,
            "auto_added_tools": [],
        })
    else:
        if auto_added:
            tools = [t for t in (meta.get("tools") or []) if t not in auto_added]
            scope_tools = {}
            for sn, stl in (meta.get("scope_tools") or {}).items():
                scope_tools[sn] = [t for t in stl if t not in auto_added]
            scope_tool_dirs = {}
            for sn, std in (meta.get("scope_tool_dirs") or {}).items():
                scope_tool_dirs[sn] = {t: d for t, d in std.items() if t not in auto_added}
            tool_dirs = {t: d for t, d in (meta.get("tool_dirs") or {}).items() if t not in auto_added}
            keep_dirs = set(tool_dirs.values())
            for std in scope_tool_dirs.values():
                keep_dirs.update(std.values())
            update_project(project_id, {
                "tools": tools,
                "scope_tools": scope_tools,
                "scope_tool_dirs": scope_tool_dirs,
                "tool_dirs": tool_dirs,
                "auto_added_tools": [],
            })

    for d in keep_dirs:
        Path(d).mkdir(parents=True, exist_ok=True)

    # Remove stale tool directories that are no longer in the restored tool set.
    # After a run with auto-queued tools, their directories persist on disk even
    # though the project metadata is restored to original_tools.
    _keep_abs = {str(Path(d).resolve()) for d in keep_dirs if d}
    if eng_dir.exists():
        for scope_dir in eng_dir.iterdir():
            if not scope_dir.is_dir() or scope_dir.name.startswith("."):
                continue
            # Only descend into known scope directories (internal, external, etc.)
            # to avoid accidentally removing non-tool content from the project root.
            if scope_dir.name not in ("internal", "external", "multi",
                                      "wifi", "bluetooth", "zigbee", "uwb",
                                      "endpoint", "webapp", "api", "osint",
                                      "database", "pcap", "cloud", "mobile",
                                      "firewall", "file"):
                continue
            for child in list(scope_dir.iterdir()):
                if not child.is_dir():
                    continue
                if str(child.resolve()) not in _keep_abs and str(child) not in cleared:
                    shutil.rmtree(child, ignore_errors=True)

    reset_tool_tracking(str(proj_dir))

    return True


def get_tool_settings(project_id, tool_id):
    proj = get_project(project_id)
    if not proj:
        return {}
    proj_dir = Path(proj.get("project_dir", ""))
    prefix = TOOL_SETTINGS_PREFIX.get(tool_id, tool_id)
    settings_file = proj_dir / f"{prefix}_settings.json"
    if settings_file.exists():
        with open(settings_file, "r") as f:
            return json.load(f)
    return {}


def save_tool_settings(project_id, tool_id, settings):
    proj = get_project(project_id)
    if not proj:
        return False
    proj_dir = Path(proj.get("project_dir", ""))
    prefix = TOOL_SETTINGS_PREFIX.get(tool_id, tool_id)
    settings_file = proj_dir / f"{prefix}_settings.json"
    from adapters import get_adapter
    adapter = get_adapter(tool_id)
    tool_data = adapter.to_tool_format(settings) if adapter else settings
    with open(settings_file, "w") as f:
        json.dump(tool_data, f, indent=2)
    return True


def get_project_dir(project_id):
    proj = get_project(project_id)
    if not proj:
        return None
    return Path(proj.get("project_dir", ""))


def get_tool_output_dir(project_id, tool_id, scope=None):
    proj = get_project(project_id)
    if not proj:
        return None
    if scope:
        td = proj.get("scope_tool_dirs", {}).get(scope, {}).get(tool_id)
        if td:
            return Path(td)
    td = proj.get("tool_dirs", {}).get(tool_id)
    if td:
        return Path(td)
    eng_dir = proj.get("engagement_dir", proj.get("project_dir", ""))
    if eng_dir:
        from config import TOOL_OUTPUT_DIRS
        derived = Path(eng_dir) / TOOL_OUTPUT_DIRS.get(tool_id, tool_id)
        if derived.exists():
            return derived
    return None


def get_scope_tool_dir(project_id, scope, tool_id):
    """Get tool output dir for a specific scope. Falls back to tool_dirs."""
    return get_tool_output_dir(project_id, tool_id, scope=scope)
