"""Project API routes — CRUD, summary, download, import, system info."""

import io
import json
import logging
import os
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime
from pathlib import Path

log = logging.getLogger("crucible.routes.project")

from flask import Blueprint, render_template, request, jsonify, send_file, session, current_app

from config import TOOLS, TOOL_OUTPUT_DIRS, VERSION
from models.project import (
    get_project, create_project, update_project, delete_project,
    clear_project, get_project_dir, get_tool_output_dir, list_projects,
    reload_projects,
)
from routes._helpers import require_project, get_ext

try:
    from services.import_engine import (
        detect_export_version, run_import, prepare_export_meta,
    )
    _IMPORT_ENGINE = True
except ImportError:
    _IMPORT_ENGINE = False

project_bp = Blueprint("project", __name__)


@project_bp.route("/project/<project_id>")
def project_page(project_id):
    project = require_project(project_id)
    _detect_active_scopes(project)
    return render_template("project.html", project=project, project_id=project_id)


_TOOL_NATIVE_SCOPE = {
    "ss3": "external", "osift": "osint",
    "fracture": "webapp", "siphon": "api",
    "trawler": "pcap", "auger": "database",
    "bastion": "firewall", "forge": "cloud", "quill": "mobile",
    "isotope": "file", "dredge": "endpoint", "aether": "wifi",
    "aether_b": "bluetooth", "aether_z": "zigbee", "aether_u": "uwb",
}


def _detect_active_scopes(project):
    """Detect actual active scopes from engagement dir and scope_tools.
    Also repairs tool_dirs/scope_tool_dirs for legacy 'multi' projects."""
    existing = project.get("active_scopes", [])
    scope_tools = project.get("scope_tools") or {}

    if scope_tools:
        scopes = list(existing) if existing else []
        for sk in scope_tools:
            if sk not in scopes and scope_tools[sk]:
                scopes.append(sk)
        if not scopes:
            eng_dir = project.get("engagement_dir", project.get("project_dir", ""))
            if eng_dir:
                ed = Path(eng_dir)
                if (ed / "ext").is_dir() and "external" not in scopes:
                    scopes.append("external")
                if (ed / "int").is_dir() and "internal" not in scopes:
                    scopes.append("internal")
        if scopes:
            project["active_scopes"] = scopes
        _repair_multi_layout(project)
        return

    if existing and existing != ["multi"]:
        return
    eng_dir = project.get("engagement_dir", project.get("project_dir", ""))
    if not eng_dir:
        return
    ed = Path(eng_dir)
    scopes = []
    if (ed / "ext").is_dir():
        scopes.append("external")
    if (ed / "int").is_dir():
        scopes.append("internal")

    tools = project.get("tools", [])
    auto_added = set(project.get("auto_added_tools") or [])
    for t in tools:
        if t in auto_added:
            continue
        s = _TOOL_NATIVE_SCOPE.get(t)
        if s and s not in scopes:
            scopes.append(s)
    if scopes:
        project["active_scopes"] = scopes
    _repair_multi_layout(project)


def _repair_multi_layout(project):
    """Repair tool_dirs / scope_tools when the engagement has moved to a
    different filesystem path (e.g. /root/clients → /clients).

    Uses crucible_meta.json in the engagement root as the source of truth
    for scope_tools, tool_dirs, and active_scopes — rebasing paths from
    the old engagement_dir to the current one.  Never invents new scope
    directories or falls back to native-scope names."""
    tools = project.get("tools", [])
    if not tools:
        return
    eng_dir = project.get("engagement_dir", project.get("project_dir", ""))
    if not eng_dir:
        return
    ed = Path(eng_dir)
    proj_dir = project.get("project_dir", eng_dir)

    meta_file = ed / "crucible_meta.json"
    if not meta_file.exists():
        return

    try:
        with open(meta_file) as f:
            meta = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        log.debug("repair_multi_layout read meta: %s", exc)
        return

    meta_eng_dir = meta.get("engagement_dir", "")
    meta_scope_tools = meta.get("scope_tools") or {}
    meta_tool_dirs = meta.get("tool_dirs") or {}
    meta_scope_tool_dirs = meta.get("scope_tool_dirs") or {}
    meta_active = meta.get("active_scopes") or []
    meta_tools = meta.get("tools") or []
    meta_auto_added = meta.get("auto_added_tools") or []

    current_tool_dirs = project.get("tool_dirs") or {}
    current_scope_tools = project.get("scope_tools") or {}
    current_scope_tool_dirs = project.get("scope_tool_dirs") or {}
    current_active = project.get("active_scopes") or []

    def _rebase(old_path):
        if not meta_eng_dir or not old_path:
            return old_path
        if old_path.startswith(meta_eng_dir):
            return str(ed) + old_path[len(meta_eng_dir):]
        return old_path

    needs_rebase = (meta_eng_dir and meta_eng_dir != str(ed))

    stale = False
    for tid, td in current_tool_dirs.items():
        if td and meta_eng_dir and td.startswith(meta_eng_dir) and not td.startswith(str(ed)):
            stale = True
            break

    if not stale and current_scope_tools and current_scope_tools != {"multi": []}:
        for tid in tools:
            if tid not in current_tool_dirs:
                stale = True
                break

    if not stale:
        return

    tool_dirs = {}
    scope_tools = {}
    scope_tool_dirs = {}

    for sk, stl in meta_scope_tools.items():
        if sk == "multi":
            continue
        scope_tools[sk] = list(stl)

    for sk, std in meta_scope_tool_dirs.items():
        if sk == "multi":
            continue
        scope_tool_dirs[sk] = {}
        for tid, td in std.items():
            rebased = _rebase(td) if needs_rebase else td
            scope_tool_dirs[sk][tid] = rebased

    for tid, td in meta_tool_dirs.items():
        rebased = _rebase(td) if needs_rebase else td
        tool_dirs[tid] = rebased

    for tid in tools:
        if tid in tool_dirs:
            continue
        tool_dirname = TOOL_OUTPUT_DIRS.get(tid, tid)
        for sk in scope_tools:
            candidate = ed / sk / tool_dirname
            if candidate.is_dir():
                tool_dirs[tid] = str(candidate)
                scope_tool_dirs.setdefault(sk, {})[tid] = str(candidate)
                if tid not in scope_tools.get(sk, []):
                    scope_tools.setdefault(sk, []).append(tid)
                break

    for tid, td in tool_dirs.items():
        td_p = Path(td)
        if not td_p.exists():
            td_p.mkdir(parents=True, exist_ok=True)

    active = list(meta_active) if meta_active and meta_active != ["multi"] else []
    if not active:
        for sk in scope_tools:
            if sk != "multi" and sk not in active:
                active.append(sk)
    if not active:
        active = ["external"]
    if "multi" in active and len(active) > 1:
        active = [s for s in active if s != "multi"]

    project["tools"] = list(meta_tools) if meta_tools else tools
    project["tool_dirs"] = tool_dirs
    project["scope_tool_dirs"] = scope_tool_dirs
    project["scope_tools"] = scope_tools
    project["active_scopes"] = active
    if meta_auto_added:
        project["auto_added_tools"] = list(meta_auto_added)

    pid = project.get("id")
    if pid:
        update_data = {
            "tools": project["tools"],
            "tool_dirs": tool_dirs,
            "scope_tool_dirs": scope_tool_dirs,
            "scope_tools": scope_tools,
            "active_scopes": active,
        }
        if meta_auto_added:
            update_data["auto_added_tools"] = list(meta_auto_added)
        update_project(pid, update_data)

    meta["engagement_dir"] = str(ed)
    meta["project_dir"] = str(ed)
    meta["tool_dirs"] = tool_dirs
    meta["scope_tool_dirs"] = scope_tool_dirs
    try:
        with open(meta_file, "w") as f:
            json.dump(meta, f, indent=2)
    except OSError as exc:
        log.debug("repair_multi_layout write meta: %s", exc)

    _repair_tool_settings(str(ed), tool_dirs, scope_tool_dirs,
                          old_eng_dir=meta_eng_dir)


def _repair_tool_settings(eng_dir, tool_dirs, scope_tool_dirs,
                          old_eng_dir=""):
    """Rebase paths inside tool settings files after an engagement move."""
    ed = Path(eng_dir)

    def _rebase_val(val):
        if not isinstance(val, str) or not old_eng_dir or not val.startswith(old_eng_dir):
            return val
        return str(ed) + val[len(old_eng_dir):]

    _ROOT_SETTINGS = {
        "ss3": ("ss_settings.json", "scan.project"),
        "osift": ("os_settings.json", "output_base"),
    }
    for tid, (fname, key_path) in _ROOT_SETTINGS.items():
        sf = ed / fname
        if not sf.exists():
            continue
        td = tool_dirs.get(tid)
        if not td:
            continue
        try:
            with open(sf) as f:
                cfg = json.load(f)
            parts = key_path.split(".")
            obj = cfg
            for p in parts[:-1]:
                obj = obj.setdefault(p, {})
            obj[parts[-1]] = td
            if tid == "ss3":
                ss3_scope_dirs = {}
                for cs, ss in (("external", "ext"), ("internal", "int")):
                    sd = scope_tool_dirs.get(cs, {}).get("ss3")
                    if sd:
                        ss3_scope_dirs[ss] = sd
                if ss3_scope_dirs:
                    cfg.setdefault("scan", {})["scope_output_dirs"] = ss3_scope_dirs
            with open(sf, "w") as f:
                json.dump(cfg, f, indent=2)
        except (json.JSONDecodeError, OSError) as exc:
            log.debug("repair_tool_settings root %s: %s", tid, exc)

    _TOOL_SETTINGS = {
        "fracture": "fr_settings_ext.json",
        "siphon": "si_settings_ext.json",
        "isotope": "is_settings_ext.json",
    }
    for tid, fname in _TOOL_SETTINGS.items():
        td = tool_dirs.get(tid)
        if not td:
            continue
        sf = Path(td) / fname
        if not sf.exists():
            continue
        if not old_eng_dir:
            continue
        try:
            with open(sf) as f:
                cfg = json.load(f)
            rewritten = json.dumps(cfg)
            if old_eng_dir in rewritten:
                rewritten = rewritten.replace(old_eng_dir, str(ed))
                cfg = json.loads(rewritten)
                with open(sf, "w") as f:
                    json.dump(cfg, f, indent=2)
        except (json.JSONDecodeError, OSError) as exc:
            log.debug("repair_tool_settings %s: %s", tid, exc)


@project_bp.route("/api/project/<project_id>")
def api_get_project(project_id):
    return jsonify(require_project(project_id))


def _apply_wizard_scheduling(project_id, meta, data):
    """Apply engagement hours and scheduled start from wizard payload."""
    sched = get_ext("scheduler")
    if not sched:
        return
    proj_dir = meta.get("project_dir", "")
    if not proj_dir:
        return
    eh = data.get("engagement_hours")
    if eh and isinstance(eh, dict):
        sched.set_engagement_hours(project_id, eh)
    scheduled_at = data.get("scheduled_start")
    if scheduled_at:
        sched.schedule_engagement_start(
            project_id, scheduled_at,
            sudo_password=data.get("sudo_password"))


@project_bp.route("/api/create_project", methods=["POST"])
def api_create_project():
    data = request.get_json(silent=True) or {}
    try:
        pid, meta = create_project(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    from services.audit_logger import audit
    audit(meta.get("project_dir", ""), "PROJECT_CREATE",
          project_id=pid, name=meta.get("name", ""))
    _apply_wizard_scheduling(pid, meta, data)
    if meta.get("beacon_enabled") and meta.get("beacon_url"):
        _sync_beacon(pid)
    return jsonify({"ok": True, "project_id": pid, "project": meta})


_SCOPE_TO_SETTINGS = {
    "quill": {
        "mobile_platform": ("mobile_platform", "auto"),
        "mobile_app_paths": ("app_files", None),
        "analysis_mode": ("analysis_mode", "static"),
        "frida_analysis": ("frida_analysis", False),
        "frida_device": ("frida_device", ""),
        "target_process": ("target_process", ""),
        "mitm_analysis": ("mitm_analysis", False),
        "mitm_port": ("mitm_port", 8080),
        "mitm_upstream_proxy": ("mitm_upstream_proxy", ""),
        "mitm_proxy_ca_pem": ("mitm_proxy_ca_pem", ""),
        "mitm_proxy_ca_name": ("mitm_proxy_ca_name", ""),
    },
    "forge": {
        "cloud_provider": ("cloud_provider", "all"),
        "aws_auth_method": ("aws_auth_method", ""),
    },
}


def _coerce_app_files(val):
    """Normalise wizard app-files value to a list."""
    if isinstance(val, list):
        return [v for v in val if v]
    if isinstance(val, str) and val:
        return [val]
    return []


def _sync_scope_to_tool_settings(data, project):
    from models.settings import load_settings, save_settings
    scope_def = data.get("scope_definition", {})
    if not scope_def:
        return
    # Backward compat: old wizard sends mobile_app_path (string)
    if "mobile_app_path" in scope_def and "mobile_app_paths" not in scope_def:
        v = scope_def.pop("mobile_app_path")
        if v:
            scope_def["mobile_app_paths"] = [v]
    proj_dir = project.get("project_dir", "")
    ts = dict(project.get("tool_settings", {}))
    tools = project.get("tools", [])
    changed = False
    for tid, field_map in _SCOPE_TO_SETTINGS.items():
        if tid not in tools:
            continue
        tool_ts = dict(ts.get(tid, {}))
        disk_changed = False
        for scope_key, (settings_key, default) in field_map.items():
            val = scope_def.get(scope_key)
            if val is None:
                continue
            if settings_key == "app_files":
                coerced = _coerce_app_files(val)
                if coerced and tool_ts.get("app_files") != coerced:
                    tool_ts["app_files"] = coerced
                    changed = True
                    disk_changed = True
            elif tool_ts.get(settings_key) != val:
                tool_ts[settings_key] = val
                changed = True
                disk_changed = True
        if disk_changed:
            ts[tid] = tool_ts
            if proj_dir:
                disk_settings = load_settings(proj_dir, tid)
                for scope_key, (settings_key, _) in field_map.items():
                    val = scope_def.get(scope_key)
                    if val is None:
                        continue
                    if settings_key == "app_files":
                        coerced = _coerce_app_files(val)
                        if coerced:
                            disk_settings["app_files"] = coerced
                    else:
                        disk_settings[settings_key] = val
                save_settings(proj_dir, tid, disk_settings)
    if changed:
        data["tool_settings"] = ts


@project_bp.route("/api/update_project/<project_id>", methods=["POST"])
def api_update_project(project_id):
    data = request.get_json(silent=True) or {}
    if "scope" in data and "active_scopes" not in data:
        data["active_scopes"] = [data["scope"]]
    if "scope_definition" in data and "tool_settings" not in data:
        project = get_project(project_id)
        if project:
            _sync_scope_to_tool_settings(data, project)
    ok = update_project(project_id, data)
    if not ok:
        return jsonify({"error": "Not found"}), 404
    if "scope_definition" in data or "active_scopes" in data:
        sm = get_ext("scope_manager")
        if sm:
            sm.invalidate(project_id)
    project = get_project(project_id)
    if project:
        _apply_wizard_scheduling(project_id, project, data)
    if any(k in data for k in ("beacon_url", "beacon_enabled")):
        _sync_beacon(project_id)
    return jsonify({"ok": True, "project_id": project_id})


def _sync_beacon(project_id):
    """Start or stop the beacon client based on current project settings."""
    try:
        from services.beacon_client import start_beacon, stop_beacon
        project = get_project(project_id)
        if not project:
            return
        if project.get("beacon_enabled") and project.get("beacon_url"):
            start_beacon(project_id, current_app._get_current_object())
        else:
            stop_beacon(project_id)
    except Exception as exc:
        log.debug("beacon sync failed for %s: %s", project_id[:8], exc)


@project_bp.route("/api/beacon_test", methods=["POST"])
def api_beacon_test():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").rstrip("/")
    if not url:
        return jsonify({"ok": False, "error": "No URL provided"}), 400
    try:
        import requests as _req
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        r = _req.get(f"{url}/api/engagements", verify=False, timeout=5)
        if r.status_code in (200, 401, 403):
            return jsonify({"ok": True, "status": r.status_code})
        return jsonify({"ok": False, "error": f"HTTP {r.status_code}"})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 502


@project_bp.route("/api/delete_project/<project_id>", methods=["DELETE"])
def api_delete_project(project_id):
    from services.audit_logger import audit
    project = get_project(project_id)
    if project:
        audit(project.get("project_dir", ""), "PROJECT_DELETE",
              project_id=project_id, delete_files=request.args.get("files") == "1")
    try:
        from services.beacon_client import stop_beacon
        stop_beacon(project_id)
    except Exception:
        pass
    pm = get_ext("process_manager")
    if pm:
        pm.clear_project_buffers(project_id)
    qm = get_ext("queue_manager")
    if qm:
        qm.clear_queue(project_id)
    fe = get_ext("findings_engine")
    if fe:
        fe.invalidate(project_id)
    delete_files = request.args.get("files") == "1"
    ok = delete_project(project_id, delete_files=delete_files)
    if not ok:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"ok": True})


@project_bp.route("/api/clear_project/<project_id>", methods=["POST"])
def api_clear_project(project_id):
    qm = get_ext("queue_manager")
    if qm:
        qm.clear_queue(project_id)
    pm = get_ext("process_manager")
    if pm:
        pm.clear_project_buffers(project_id)
    fe = get_ext("findings_engine")
    if fe:
        fe.invalidate(project_id)
    ok = clear_project(project_id)
    if not ok:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"ok": True})


@project_bp.route("/api/purge_tool/<project_id>/<tool_id>", methods=["POST"])
def api_purge_tool(project_id, tool_id):
    """Purge one tool's output data while keeping the project."""
    if tool_id not in TOOLS:
        return jsonify({"error": f"Unknown tool: {tool_id}"}), 400
    import shutil
    project = require_project(project_id)
    td = project.get("tool_dirs", {}).get(tool_id)
    if td and Path(td).exists():
        tp = Path(td)
        saved = {}
        for f in tp.glob("*_settings*.json"):
            try:
                saved[f.name] = f.read_text()
            except OSError as exc:
                log.debug("purge_tool save settings: %s", exc)
        shutil.rmtree(td, ignore_errors=True)
        tp.mkdir(parents=True, exist_ok=True)
        for name, content in saved.items():
            (tp / name).write_text(content)
    proj_dir = project.get("project_dir", "")
    if proj_dir:
        from models.action_items import clear_action_items_by_tool
        clear_action_items_by_tool(proj_dir, tool_id)
    return jsonify({"ok": True})


def _relativize_findings_json(findings_path, eng_dir):
    """Rewrite absolute output_file paths to relative for export portability."""
    try:
        data = json.loads(findings_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        log.debug("relativize_findings read: %s", exc)
        return findings_path.read_text()
    if not isinstance(data, list):
        return json.dumps(data, indent=2)
    prefix = str(eng_dir).rstrip("/") + "/"
    for f in data:
        raw = f.get("output_file", "")
        if not raw or not isinstance(raw, str):
            continue
        if prefix in raw:
            f["output_file"] = raw.replace(prefix, "")
    return json.dumps(data, indent=2)


@project_bp.route("/api/download-project/<project_id>")
def api_download_project(project_id):
    """ZIP export of engagement directory (v2.0/v3.0) or project + tools (v1.x)."""
    project = require_project(project_id)
    scope_filter = request.args.get("scope")

    buf = io.BytesIO()
    eng_dir = Path(project.get("engagement_dir", project.get("project_dir", "")))

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if project.get("layout_version") == "2.0" and eng_dir.exists():
            export_meta = prepare_export_meta(project) if _IMPORT_ENGINE else None
            for fp in eng_dir.rglob("*"):
                if fp.is_file():
                    rel = fp.relative_to(eng_dir)
                    if scope_filter and not str(rel).startswith(scope_filter + "/"):
                        if fp.name != "engagement.json":
                            continue
                    if fp.name == "crucible_meta.json" and export_meta:
                        zf.writestr(str(rel),
                                    json.dumps(export_meta, indent=2, default=str))
                        continue
                    if fp.name == "findings.json":
                        zf.writestr(str(rel),
                                    _relativize_findings_json(fp, eng_dir))
                        continue
                    zf.write(fp, str(rel))
        else:
            proj_dir = Path(project.get("project_dir", ""))
            if proj_dir.exists():
                for fp in proj_dir.rglob("*"):
                    if fp.is_file():
                        arcname = f"project/{fp.relative_to(proj_dir)}"
                        zf.write(fp, arcname)
            for tool_id, td in project.get("tool_dirs", {}).items():
                tp = Path(td)
                if tp.exists():
                    for fp in tp.rglob("*"):
                        if fp.is_file():
                            arcname = f"tools/{tool_id}/{fp.relative_to(tp)}"
                            zf.write(fp, arcname)

    buf.seek(0)
    name = project.get("client_short", "project")
    suffix = f"_{scope_filter}" if scope_filter else ""
    return send_file(buf, mimetype="application/zip",
                     as_attachment=True,
                     download_name=f"{name}{suffix}_crucible_export.zip")


_MAX_IMPORT_SIZE = 500 * 1024 * 1024


@project_bp.route("/api/import_project", methods=["POST"])
def api_import_project():
    """Import a project from a Crucible/Vantage ZIP export.

    Delegates to the version-aware import engine which detects the export
    format (v3.0 DB-native, v2.0 JSON, v1.x legacy, Vantage, raw output),
    converts to the current layout, and creates a FindingsDB when available.
    Falls back to the legacy v1/v2 import path if the engine is unavailable.
    """
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    if not f.filename or not f.filename.lower().endswith(".zip"):
        return jsonify({"error": "ZIP file required"}), 400

    import tempfile
    import shutil

    tmp_dir = Path(tempfile.mkdtemp(prefix="crucible_import_"))
    try:
        zip_path = tmp_dir / "upload.zip"
        f.save(str(zip_path))

        with zipfile.ZipFile(zip_path, "r") as zf:
            total_size = sum(i.file_size for i in zf.infolist())
            if total_size > _MAX_IMPORT_SIZE:
                return jsonify({
                    "error": f"ZIP contents too large: {total_size // (1024*1024)}MB "
                             f"(max {_MAX_IMPORT_SIZE // (1024*1024)}MB)"
                }), 400
            for name in zf.namelist():
                if ".." in name or name.startswith("/"):
                    return jsonify({"error": f"Invalid path in ZIP: {name}"}), 400
            zf.extractall(tmp_dir / "contents")

        contents = tmp_dir / "contents"

        if _IMPORT_ENGINE:
            result = run_import(contents, create_project)
            if result.get("error") == "file_import":
                return jsonify({
                    "error": "This ZIP contains scanner output files, not a "
                             "project export. Use the Import tab within a "
                             "project to import scanner files."
                }), 400
            if not result.get("ok"):
                code = 409 if "already exists" in result.get("error", "") else 400
                return jsonify({"error": result["error"]}), code
            return jsonify(result)

        return _legacy_import(contents)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _legacy_import(contents):
    """Legacy v1/v2 import path — used when import engine is unavailable."""
    import shutil

    meta_file = contents / "project" / "crucible_meta.json"
    is_v2 = False
    if not meta_file.exists():
        meta_file = contents / "crucible_meta.json"
        is_v2 = True
    if not meta_file.exists():
        for candidate in contents.rglob("crucible_meta.json"):
            meta_file = candidate
            is_v2 = (meta_file.parent == contents)
            break
    if not meta_file.exists():
        return jsonify({"error": "No crucible_meta.json found in ZIP"}), 400

    with open(meta_file) as mf:
        meta = json.load(mf)

    existing_id = meta.get("id")
    if existing_id:
        if get_project(existing_id):
            return jsonify({
                "error": f"Project '{existing_id}' already exists. "
                         "Delete or rename the existing project first."
            }), 409

    form_data = {
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
    }

    pid, new_meta = create_project(form_data)
    proj_dir = Path(new_meta.get("project_dir", ""))

    if is_v2:
        src = meta_file.parent
        if proj_dir.exists() and src.exists():
            for item in src.iterdir():
                dest = proj_dir / item.name
                if item.is_dir():
                    shutil.copytree(item, dest, dirs_exist_ok=True)
                elif item.name != "crucible_meta.json":
                    shutil.copy2(item, dest)
    else:
        proj_content = contents / "project"
        if proj_dir.exists() and proj_content.exists():
            for item in proj_content.iterdir():
                dest = proj_dir / item.name
                if item.is_dir():
                    shutil.copytree(item, dest, dirs_exist_ok=True)
                else:
                    shutil.copy2(item, dest)

        tools_content = contents / "tools"
        if tools_content.exists():
            for tool_dir in tools_content.iterdir():
                if tool_dir.is_dir():
                    tool_id = tool_dir.name
                    dest = new_meta.get("tool_dirs", {}).get(tool_id)
                    if dest:
                        dest_path = Path(dest)
                        dest_path.mkdir(parents=True, exist_ok=True)
                        shutil.copytree(tool_dir, dest_path, dirs_exist_ok=True)

    return jsonify({"ok": True, "project_id": pid})


@project_bp.route("/api/system_info")
def api_system_info():
    try:
        import pr0t31n_system_info
        info = pr0t31n_system_info.collect()
    except ImportError:
        info = {"error": "pr0t31n_system_info not available"}
    return jsonify(info)


@project_bp.route("/api/device-ips")
def api_device_ips():
    import socket
    ips = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM):
            addr = info[4][0].split("%")[0]
            if addr and not addr.startswith("127.") and addr != "::1" and not addr.startswith("fe80"):
                ips.add(addr)
    except Exception as exc:
        log.warning("device_ips getaddrinfo: %s", exc)
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            for family in (netifaces.AF_INET, netifaces.AF_INET6):
                for entry in addrs.get(family, []):
                    addr = entry.get("addr", "").split("%")[0]
                    if addr and not addr.startswith("127.") and addr != "::1":
                        ips.add(addr)
    except ImportError:
        try:
            import subprocess
            out = subprocess.check_output(["ifconfig"], text=True, timeout=5)
            import re
            for m in re.finditer(r'inet6?\s+(\S+)', out):
                addr = m.group(1).split("%")[0]
                if addr and not addr.startswith("127.") and addr != "::1" and not addr.startswith("fe80"):
                    ips.add(addr)
        except Exception as exc:
            log.warning("device_ips ifconfig fallback: %s", exc)
    return jsonify({"ips": sorted(ips)})


@project_bp.route("/api/session_ping", methods=["POST"])
def api_session_ping():
    return jsonify({"ok": True})


@project_bp.route("/api/projects")
def api_list_projects():
    projects = list_projects()
    q = request.args.get("search", "").strip().lower()
    client = request.args.get("client", "").strip().lower()
    if q:
        projects = [p for p in projects
                    if q in p.get("name", "").lower()
                    or q in p.get("client", "").lower()
                    or q in p.get("id", "").lower()]
    if client:
        projects = [p for p in projects
                    if client in p.get("client", "").lower()]
    return jsonify({"projects": projects, "total": len(projects)})


@project_bp.route("/api/projects/refresh", methods=["POST"])
def api_refresh_projects():
    projects = reload_projects()
    return jsonify({"ok": True, "total": len(projects)})


@project_bp.route("/api/health")
def api_health():
    pm = get_ext("process_manager")
    return jsonify({
        "status": "online",
        "app": "Crucible",
        "version": VERSION,
        "tools": len(TOOLS),
        "projects": len(list_projects()),
    })


@project_bp.route("/api/engagement-summary/<project_id>")
def api_engagement_summary(project_id):
    """Lightweight engagement summary for CLI consumption."""
    project = require_project(project_id)
    pm = get_ext("process_manager")
    tool_statuses = {}
    if pm:
        tool_statuses = pm.get_all_status(project_id) or {}
    scope_tools = project.get("scope_tools", {})
    scopes = {}
    for scope_name, tool_list in scope_tools.items():
        scope_info = {"tools": {}}
        for tid in tool_list:
            ts = tool_statuses.get(tid, {})
            scope_info["tools"][tid] = {
                "name": TOOLS.get(tid, {}).get("name", tid),
                "status": ts.get("status", "idle"),
            }
        statuses = [t["status"] for t in scope_info["tools"].values()]
        if any(s == "running" for s in statuses):
            scope_info["status"] = "running"
        elif all(s in ("complete", "idle") for s in statuses) and any(s == "complete" for s in statuses):
            scope_info["status"] = "complete"
        elif any(s == "failed" for s in statuses):
            scope_info["status"] = "failed"
        else:
            scope_info["status"] = "idle"
        scopes[scope_name] = scope_info

    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    total_findings = 0
    try:
        from services.findings import FindingsEngine
        fe = FindingsEngine()
        findings = fe.get_findings(project_id, project)
        total_findings = len(findings)
        for f in findings:
            r = (f.get("risk") or "INFO").upper()
            if r in risk_counts:
                risk_counts[r] += 1
    except Exception as exc:
        log.warning("engagement_summary findings count: %s", exc)

    return jsonify({
        "project_id": project_id,
        "client": project.get("client_name", ""),
        "engagement": project.get("name", ""),
        "scopes": scopes,
        "findings": {
            "total": total_findings,
            "by_risk": risk_counts,
        },
    })


@project_bp.route("/api/queue/<project_id>")
def api_queue(project_id):
    project = require_project(project_id)
    qm = get_ext("queue_manager")
    if not qm:
        return jsonify({"queue": [], "size": 0})
    entries = qm.get_queue(project_id)
    return jsonify({"queue": entries, "size": len(entries)})


@project_bp.route("/api/auto_queue/<project_id>", methods=["POST"])
def api_toggle_auto_queue(project_id):
    """Toggle auto-queue on/off.  Permission flag for future tool completions."""
    require_project(project_id)
    data = request.get_json(silent=True) or {}
    enabled = bool(data.get("enabled", False))

    ok = update_project(project_id, {"auto_queue": enabled})
    if not ok:
        return jsonify({"error": "Failed to update project"}), 500

    return jsonify({"ok": True, "auto_queue": enabled})


_OOS_VALID = {"explicit", "separated", "combined"}


@project_bp.route("/api/oos_handling/<project_id>", methods=["POST"])
def api_set_oos_handling(project_id):
    """Set out-of-scope handling mode for this engagement."""
    require_project(project_id)
    data = request.get_json(silent=True) or {}
    mode = data.get("mode", "explicit")
    if mode not in _OOS_VALID:
        return jsonify({"error": f"Invalid mode: {mode}"}), 400

    ok = update_project(project_id, {"oos_handling": mode})
    if not ok:
        return jsonify({"error": "Failed to update project"}), 500

    return jsonify({"ok": True, "oos_handling": mode})


@project_bp.route("/api/update_scopes/<project_id>", methods=["POST"])
def api_update_scopes(project_id):
    """Set the engagement's active scopes to the provided list."""
    import sys
    try:
        if "/opt/pr0t31n/shared" not in sys.path:
            sys.path.insert(0, "/opt/pr0t31n/shared")
        import pr0t31n_schema as _us
    except ImportError:
        _us = None

    project = require_project(project_id)
    data = request.get_json(silent=True) or {}
    desired = data.get("desired_scopes", [])
    scope_data = data.get("scope_data", {})

    if not isinstance(desired, list):
        return jsonify({"error": "desired_scopes must be a list"}), 400

    existing = project.get("active_scopes", [project.get("scope", "external")])
    added = [s for s in desired if s not in existing]
    removed = [s for s in existing if s not in desired]

    scope_def = dict(project.get("scope_definition", {}))
    for key, val in scope_data.items():
        if isinstance(val, list):
            prev = scope_def.get(key, [])
            if isinstance(prev, list):
                combined = list(prev)
                for v in val:
                    if v not in combined:
                        combined.append(v)
                scope_def[key] = combined
            else:
                scope_def[key] = val
        elif val:
            scope_def[key] = val

    scope_tool_map = {
        "external": ["ss3", "osift", "trawler", "auger", "isotope"],
        "internal": ["ss3", "trawler", "auger", "isotope"],
        "webapp": ["fracture"],
        "api": ["siphon"],
        "osint": ["osift"],
        "database": ["auger"],
        "pcap": ["trawler"],
        "wifi": ["aether"],
        "bluetooth": ["aether_b"],
        "zigbee": ["aether_z"],
        "uwb": ["aether_u"],
        "firewall": ["bastion"],
        "cloud": ["forge"],
        "mobile": ["quill"],
        "file": ["isotope"],
    }

    existing_tools = list(project.get("tools", []))
    tool_dirs = dict(project.get("tool_dirs", {}))
    scope_tool_dirs = dict(project.get("scope_tool_dirs", {}))
    eng_dir = project.get("engagement_dir", project.get("project_dir", ""))

    for s in added:
        scope_dir = Path(eng_dir) / s
        scope_dir.mkdir(parents=True, exist_ok=True)
        if _us:
            _us.create_scope_dir(eng_dir, s)

        scope_tool_dirs[s] = {}
        for t in scope_tool_map.get(s, []):
            if t not in existing_tools and t in TOOLS:
                existing_tools.append(t)
            tool_dirname = TOOL_OUTPUT_DIRS.get(t, t)
            td = scope_dir / tool_dirname
            td.mkdir(parents=True, exist_ok=True)
            if _us:
                _us.init_run_dir(td)
            scope_tool_dirs[s][t] = str(td)
            if t not in tool_dirs:
                tool_dirs[t] = str(td)

    for s in removed:
        scope_tool_dirs.pop(s, None)

    scope_tools = dict(project.get("scope_tools", {}))
    for s in desired:
        if s not in scope_tools:
            scope_tools[s] = list(scope_tool_map.get(s, []))
    for s in removed:
        scope_tools.pop(s, None)

    tool_settings = dict(project.get("tool_settings", {}))
    _scope_to_settings = {
        "quill": {
            "mobile_platform": ("mobile_platform", "auto"),
            "mobile_app_paths": ("app_files", None),
            "analysis_mode": ("analysis_mode", "static"),
            "frida_analysis": ("frida_analysis", False),
            "frida_device": ("frida_device", ""),
            "target_process": ("target_process", ""),
            "mitm_analysis": ("mitm_analysis", False),
            "mitm_port": ("mitm_port", 8080),
            "mitm_upstream_proxy": ("mitm_upstream_proxy", ""),
            "mitm_proxy_ca_pem": ("mitm_proxy_ca_pem", ""),
            "mitm_proxy_ca_name": ("mitm_proxy_ca_name", ""),
        },
        "forge": {
            "cloud_provider": ("cloud_provider", "all"),
            "aws_auth_method": ("aws_auth_method", ""),
        },
    }
    # Backward compat: old wizard sends mobile_app_path (string)
    if "mobile_app_path" in scope_def and "mobile_app_paths" not in scope_def:
        v = scope_def.pop("mobile_app_path")
        if v:
            scope_def["mobile_app_paths"] = [v]
    for tid, field_map in _scope_to_settings.items():
        if tid in existing_tools:
            ts = tool_settings.get(tid, {})
            changed = False
            for scope_key, (settings_key, default) in field_map.items():
                val = scope_def.get(scope_key)
                if val is not None:
                    if settings_key == "app_files":
                        coerced = _coerce_app_files(val)
                        if coerced and ts.get("app_files") != coerced:
                            ts["app_files"] = coerced
                            changed = True
                    elif ts.get(settings_key) != val:
                        ts[settings_key] = val
                        changed = True
            if changed:
                tool_settings[tid] = ts

    updates = {
        "active_scopes": desired,
        "scope_definition": scope_def,
        "scope_tools": scope_tools,
        "scope_tool_dirs": scope_tool_dirs,
        "tools": existing_tools,
        "tool_dirs": tool_dirs,
        "tool_settings": tool_settings,
    }
    if len(desired) > 1:
        updates["scope"] = "multi"
    elif len(desired) == 1:
        updates["scope"] = desired[0]

    ok = update_project(project_id, updates)
    if not ok:
        return jsonify({"error": "Failed to update project"}), 500
    sm = get_ext("scope_manager")
    if sm:
        sm.invalidate(project_id)
    return jsonify({"ok": True, "added": added, "removed": removed, "scopes": desired})


@project_bp.route("/api/scope_tools/<project_id>", methods=["POST"])
def api_scope_tools(project_id):
    """Add a tool to a scope (cross-tool discovery). Idempotent."""
    import sys
    try:
        if "/opt/pr0t31n/shared" not in sys.path:
            sys.path.insert(0, "/opt/pr0t31n/shared")
        import pr0t31n_schema as _us
    except ImportError:
        _us = None

    project = require_project(project_id)
    data = request.get_json(silent=True) or {}
    scope_key = data.get("scope")
    tool_id = data.get("tool")
    source_tool = data.get("source_tool", "")
    source_finding = data.get("source_finding", "")

    if not scope_key or not tool_id:
        return jsonify({"error": "scope and tool required"}), 400
    if tool_id not in TOOLS:
        return jsonify({"error": f"Unknown tool: {tool_id}"}), 400

    scope_tools = dict(project.get("scope_tools", {}))
    if scope_key not in scope_tools:
        scope_tools[scope_key] = []
    if tool_id not in scope_tools[scope_key]:
        scope_tools[scope_key].append(tool_id)

    eng_dir = project.get("engagement_dir", project.get("project_dir", ""))
    scope_tool_dirs = dict(project.get("scope_tool_dirs", {}))
    tool_dirs = dict(project.get("tool_dirs", {}))

    if eng_dir:
        from config import TOOL_OUTPUT_DIRS
        tool_dirname = TOOL_OUTPUT_DIRS.get(tool_id, tool_id)
        td = Path(eng_dir) / scope_key / tool_dirname
        td.mkdir(parents=True, exist_ok=True)
        if _us:
            native = (_us.TOOL_NATIVE_SCOPES.get(tool_id) == scope_key)
            _us.create_scope_tool_dir(eng_dir, scope_key, tool_id,
                                      native=native, source_tool=source_tool,
                                      source_finding=source_finding)
        scope_tool_dirs.setdefault(scope_key, {})[tool_id] = str(td)
        if tool_id not in tool_dirs:
            tool_dirs[tool_id] = str(td)

    updates = {
        "scope_tools": scope_tools,
        "scope_tool_dirs": scope_tool_dirs,
        "tool_dirs": tool_dirs,
    }
    ok = update_project(project_id, updates)
    if not ok:
        return jsonify({"error": "Failed to update project"}), 500
    return jsonify({"ok": True, "scope_tools": scope_tools})


@project_bp.route("/api/summary/<project_id>")
def api_summary(project_id):
    """Project summary: risk counts, tool status, action items."""
    project = require_project(project_id)

    fe = get_ext("findings_engine")
    if not fe:
        from services.findings_engine import FindingsEngine
        fe = FindingsEngine()
    summary = fe.get_full_summary(project_id, project)

    from models.action_items import get_action_items_summary
    proj_dir = project.get("project_dir", "")
    if proj_dir:
        summary["action_items"] = get_action_items_summary(proj_dir)

    summary.update(_get_engagement_timing(proj_dir))

    return jsonify(summary)


@project_bp.route("/api/diag/<project_id>")
def api_diag(project_id):
    """Diagnostic: check DB availability and summary speed."""
    import time
    project = require_project(project_id)
    fe = get_ext("findings_engine")
    if not fe:
        return jsonify({"error": "no findings_engine"})
    diag = {"version": config.VERSION}
    db = fe._get_db(project_id, project)
    diag["db_available"] = db is not None
    if db is not None:
        diag["db_path"] = str(getattr(db, "_path", "?"))
        try:
            t0 = time.monotonic()
            s = db.get_summary()
            diag["db_summary_ms"] = round((time.monotonic() - t0) * 1000, 1)
            diag["db_summary"] = s
        except Exception as e:
            diag["db_summary_error"] = str(e)
        try:
            t0 = time.monotonic()
            ts = db.get_tool_summary()
            diag["db_tool_summary_ms"] = round((time.monotonic() - t0) * 1000, 1)
            diag["db_tool_count"] = len(ts)
        except Exception as e:
            diag["db_tool_summary_error"] = str(e)
        try:
            cnt = db._conn.execute(
                "SELECT COUNT(*) FROM findings").fetchone()[0]
            diag["db_total_findings"] = cnt
        except Exception as e:
            diag["db_count_error"] = str(e)
        try:
            cols = [r[1] for r in db._conn.execute(
                "PRAGMA table_info(findings)").fetchall()]
            diag["findings_columns"] = cols
        except Exception as e:
            diag["pragma_error"] = str(e)
    t0 = time.monotonic()
    summary = fe.get_full_summary(project_id, project)
    diag["full_summary_ms"] = round((time.monotonic() - t0) * 1000, 1)
    diag["full_summary"] = summary
    return jsonify(diag)


def _get_engagement_timing(proj_dir: str) -> dict:
    """Extract earliest started_at and latest ended_at from tool_history.json."""
    if not proj_dir:
        return {"engagement_start_time": None, "engagement_end_time": None}
    hist_path = Path(proj_dir) / "tool_history.json"
    if not hist_path.exists():
        return {"engagement_start_time": None, "engagement_end_time": None}
    try:
        history = json.loads(hist_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        log.debug("engagement_timing read history: %s", exc)
        return {"engagement_start_time": None, "engagement_end_time": None}
    earliest = None
    latest = None
    for entry in history.values():
        sa = entry.get("started_at", "")
        ea = entry.get("ended_at", "")
        if sa and (earliest is None or sa < earliest):
            earliest = sa
        if ea and (latest is None or ea > latest):
            latest = ea
        if sa and (latest is None or sa > latest):
            latest = sa
    return {"engagement_start_time": earliest, "engagement_end_time": latest}


@project_bp.route("/api/env_intel/<project_id>")
def api_env_intel(project_id):
    """Environmental intelligence summary."""
    project = require_project(project_id)

    from services.intel import IntelService
    intel = IntelService()
    return jsonify(intel.get_intel_summary(project))


@project_bp.route("/api/exclude_ip/<project_id>", methods=["POST"])
def api_exclude_ip(project_id):
    """Exclude an IP from the engagement.

    - Adds the IP to scope_definition.exclusions
    - Removes findings referencing the IP from findings.json files
    - Removes the IP from targets.json
    - Modifies Nessus XML files to remove the ReportHost for that IP
    - Does NOT modify non-pr0t31n tool output
    """
    import xml.etree.ElementTree as ET

    project = require_project(project_id)
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "IP address is required"}), 400

    scope_def = dict(project.get("scope_definition", {}))
    exclusions = list(scope_def.get("exclusions", []))
    if ip in exclusions:
        return jsonify({"error": f"IP {ip} is already excluded"}), 400
    exclusions.append(ip)
    scope_def["exclusions"] = exclusions

    ok = update_project(project_id, {"scope_definition": scope_def})
    if not ok:
        return jsonify({"error": "Failed to update project meta"}), 500

    eng_dir = project.get("engagement_dir", project.get("project_dir", ""))
    removed_findings = 0
    modified_nessus = 0

    if eng_dir:
        eng = Path(eng_dir)

        # ── Walk all findings.json files and remove entries for this IP ──
        for fj in eng.rglob("findings.json"):
            try:
                with open(fj) as f:
                    findings = json.load(f)
                if not isinstance(findings, list):
                    continue
                before = len(findings)
                findings = [fd for fd in findings
                            if fd.get("ip", "") != ip]
                after = len(findings)
                if after < before:
                    with open(fj, "w") as f:
                        json.dump(findings, f, indent=2)
                    removed_findings += before - after
            except (json.JSONDecodeError, OSError) as exc:
                log.debug("exclude_ip findings.json: %s", exc)
                continue

        # ── Walk all targets.json files and remove host entries ──
        for tj in eng.rglob("targets.json"):
            try:
                with open(tj) as f:
                    tdata = json.load(f)
                changed = False
                if isinstance(tdata, list):
                    before = len(tdata)
                    tdata = [t for t in tdata
                             if t.get("ip", t.get("host", "")) != ip]
                    changed = len(tdata) < before
                elif isinstance(tdata, dict):
                    for key in ("targets", "hosts", "_items"):
                        items = tdata.get(key)
                        if isinstance(items, list):
                            before = len(items)
                            tdata[key] = [t for t in items
                                          if t.get("ip", t.get("host", "")) != ip]
                            if len(tdata[key]) < before:
                                changed = True
                if changed:
                    with open(tj, "w") as f:
                        json.dump(tdata, f, indent=2)
            except (json.JSONDecodeError, OSError) as exc:
                log.debug("exclude_ip targets.json: %s", exc)
                continue

        # ── Modify Nessus XML files to remove ReportHost for this IP ──
        for nf in eng.rglob("*.nessus"):
            try:
                tree = ET.parse(str(nf))
                root = tree.getroot()
                removed_hosts = []
                for report in root.iter("Report"):
                    for host in list(report.findall("ReportHost")):
                        host_ip = host.get("name", "")
                        for tag in host.iter("tag"):
                            if tag.get("name") == "host-ip" and tag.text:
                                host_ip = tag.text.strip()
                                break
                        if host_ip == ip:
                            report.remove(host)
                            removed_hosts.append(host_ip)
                if removed_hosts:
                    tree.write(str(nf), xml_declaration=True,
                               encoding="utf-8")
                    modified_nessus += 1
            except (ET.ParseError, OSError) as exc:
                log.debug("exclude_ip nessus xml: %s", exc)
                continue

    # Invalidate caches so retroactive exclusion filtering takes effect
    sm = get_ext("scope_manager")
    if sm:
        sm.invalidate(project_id)
    fe = get_ext("findings_engine")
    if fe:
        fe.invalidate(project_id)

    return jsonify({
        "ok": True,
        "ip": ip,
        "exclusions": exclusions,
        "removed_findings": removed_findings,
        "modified_nessus": modified_nessus,
    })


@project_bp.route("/api/unexclude_ip/<project_id>", methods=["POST"])
def api_unexclude_ip(project_id):
    """Remove an IP from the exclusion list (does not restore deleted data)."""
    project = require_project(project_id)
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "IP address is required"}), 400

    scope_def = dict(project.get("scope_definition", {}))
    exclusions = list(scope_def.get("exclusions", []))
    if ip not in exclusions:
        return jsonify({"error": f"IP {ip} is not in the exclusion list"}), 400
    exclusions.remove(ip)
    scope_def["exclusions"] = exclusions

    ok = update_project(project_id, {"scope_definition": scope_def})
    if not ok:
        return jsonify({"error": "Failed to update project meta"}), 500

    # Invalidate caches so previously-excluded findings reappear
    sm = get_ext("scope_manager")
    if sm:
        sm.invalidate(project_id)
    fe = get_ext("findings_engine")
    if fe:
        fe.invalidate(project_id)

    return jsonify({"ok": True, "ip": ip, "exclusions": exclusions})


@project_bp.route("/api/frida-devices")
def api_frida_devices():
    """Discover connected Frida-compatible USB devices."""
    try:
        import frida
    except ImportError:
        return jsonify({
            "ok": False,
            "error": "frida_not_installed",
            "message": "Frida is not installed on this system.",
            "instructions": {
                "install": "pip3 install frida-tools frida",
                "server": (
                    "Download frida-server for your device from "
                    "https://github.com/frida/frida/releases — match the "
                    "version to your desktop frida-tools. Push to device: "
                    "adb push frida-server /data/local/tmp/ && "
                    "adb shell chmod 755 /data/local/tmp/frida-server && "
                    "adb shell su -c '/data/local/tmp/frida-server -D &'"
                ),
            },
            "devices": [],
        })

    try:
        all_devices = frida.enumerate_devices()
    except Exception as exc:
        return jsonify({
            "ok": False,
            "error": "exec_error",
            "message": f"Frida device enumeration failed: {exc}",
            "devices": [],
        })

    devices = []
    for d in all_devices:
        if d.type == "usb":
            devices.append({
                "id": d.id,
                "type": "usb",
                "name": d.name,
            })

    if not devices:
        return jsonify({
            "ok": False,
            "error": "no_devices",
            "message": (
                "No mobile devices detected. Connect your Android or iOS "
                "device via USB and ensure USB debugging is enabled. "
                "Frida-server must be running on the device."
            ),
            "devices": [],
        })

    return jsonify({"ok": True, "devices": devices})
