"""Action Items API routes — list, execute, dismiss, queue, launch."""

import json
import logging
from pathlib import Path
from flask import Blueprint, request, jsonify
from routes._helpers import require_project, get_ext
from services.utils import project_room as _room
from models.action_items import (
    load_action_items, update_action_item_status, dismiss_action_item,
    get_action_items_summary, bulk_update_status, add_action_item_note,
    repair_stale_running, repair_oos_flags, load_and_repair,
)

action_items_bp = Blueprint("action_items", __name__)
log = logging.getLogger("crucible.routes.action_items")

_HTTPS_PORTS = {"443", "8443", "9443", "4443", "3443", "8444"}


def _backfill_launch_settings(settings, project, tool_id):
    """Inject scope_definition values into settings before launch and persist."""
    settings.pop("_saved_keys", None)
    if tool_id != "ss3":
        return
    scope_def = project.get("scope_definition") or {}
    from adapters import get_adapter
    adapter = get_adapter(tool_id)
    defaults = adapter.default_settings() if adapter else {}
    changed = False
    _dmr = scope_def.get("ss3_discovery_min_rate", 0)
    if _dmr and settings.get("discovery_min_rate") == defaults.get("discovery_min_rate"):
        settings["discovery_min_rate"] = _dmr
        changed = True
    _dmp = scope_def.get("ss3_discovery_min_parallelism", 0)
    if _dmp and settings.get("discovery_min_parallelism") == defaults.get("discovery_min_parallelism"):
        settings["discovery_min_parallelism"] = _dmp
        changed = True
    _tt = scope_def.get("ss3_timing_template", "")
    if _tt and settings.get("timing_template") == defaults.get("timing_template"):
        settings["timing_template"] = _tt
        changed = True
    _psd = scope_def.get("ss3_passive_seed_duration", 0)
    if _psd and settings.get("passive_seed_duration") == defaults.get("passive_seed_duration"):
        settings["passive_seed_duration"] = _psd
        changed = True
    if changed:
        from models.settings import save_settings
        proj_dir = project.get("project_dir", "")
        if proj_dir:
            save_settings(proj_dir, tool_id, settings)


def _is_excluded_item(item, sm, project):
    """Check if an action item's target IP is in the exclusion list."""
    ip = item.get("ip", "")
    if not ip:
        meta = item.get("metadata") or {}
        ip = meta.get("ip", "")
    if not ip:
        target = item.get("target", "")
        if target:
            from urllib.parse import urlparse
            try:
                parsed = urlparse(target if "://" in target
                                  else f"http://{target}")
                ip = parsed.hostname or ""
            except Exception:
                ip = target
    if ip and sm.is_excluded(project, ip):
        return True
    hostname = (item.get("metadata") or {}).get("hostname", "")
    if hostname and sm.is_excluded(project, hostname):
        return True
    return False


def _ensure_url_scheme(target):
    """Ensure a target has an http(s):// scheme for tools that need a URL."""
    if not target:
        return target
    if "://" in target:
        return target
    if ":" in target and not target.startswith("["):
        host, port = target.rsplit(":", 1)
        scheme = "https" if port in _HTTPS_PORTS else "http"
        if (scheme == "https" and port == "443") or \
                (scheme == "http" and port == "80"):
            return f"{scheme}://{host}"
        return f"{scheme}://{host}:{port}"
    return f"https://{target}"


def _resolve_isotope_targets(item, project):
    """Resolve an Isotope action item to local file paths.

    Fracture-generated items store the downloaded file path in
    metadata.output_file; SS3-generated items may store paths there too.
    Falls back to scanning ALL tool output directories (tool_dirs +
    scope_tool_dirs) for files matching the target URL's basename.
    """
    meta = item.get("metadata") or {}
    found = []
    seen = set()

    def _all_tool_dirs():
        for td in (project.get("tool_dirs") or {}).values():
            yield td
        for scope_dirs in (project.get("scope_tool_dirs") or {}).values():
            for td in scope_dirs.values():
                yield td

    of_raw = meta.get("output_file", "")
    of_parts = [p.strip() for p in of_raw.split(",") if p.strip()] if of_raw else []
    for of in of_parts:
        p = Path(of)
        if p.is_absolute() and p.exists():
            s = str(p)
            if s not in seen:
                found.append(s)
                seen.add(s)
            continue
        _resolved = False
        for td in _all_tool_dirs():
            candidate = Path(td) / of
            if candidate.exists():
                s = str(candidate)
                if s not in seen:
                    found.append(s)
                    seen.add(s)
                _resolved = True
                break
        if not _resolved:
            bn = Path(of).name
            if bn:
                for td in _all_tool_dirs():
                    td_p = Path(td)
                    if not td_p.is_dir():
                        continue
                    for match in td_p.rglob(bn):
                        if match.is_file():
                            s = str(match)
                            if s not in seen:
                                found.append(s)
                                seen.add(s)
                            _resolved = True
                            break
                    if _resolved:
                        break

    if not found:
        target = item.get("target", "")
        parts = target.replace("\n", " ").split()
        for part in parts:
            basename = part.rstrip("/").rsplit("/", 1)[-1]
            if not basename or basename == "/":
                continue
            matched = False
            for td in _all_tool_dirs():
                if matched:
                    break
                td_p = Path(td)
                if not td_p.is_dir():
                    continue
                for match in td_p.rglob(basename):
                    if match.is_file():
                        s = str(match)
                        if s not in seen:
                            found.append(s)
                            seen.add(s)
                        matched = True
                        break

    return found


_TOOL_GENERATORS = {
    "fracture": ["osift", "ss3"],
    "siphon":   ["osift", "ss3"],
    "auger":    ["ss3", "fracture"],
    "ss3":      ["osift"],
}


_SCOPE_ALIASES = {"ext": "external", "int": "internal"}


def _ensure_tool_registered(project_id, project, tool_id, item_scope=None):
    """If *tool_id* is not yet in the project's tools list, add it to the
    project under the scope that the originating tool was running in,
    create its output directory, and emit ``tool_registered`` so the
    frontend can update the console + intelligence tabs live.

    *item_scope* is the ``scope`` field from the action item (set by
    the generating tool, e.g. ``"external"`` from SS3 or ``"osint"``
    from OSift).  When it matches an active project scope, the launched
    tool is placed there directly.  Otherwise we fall back to finding
    which scope contains the generating tool.
    """
    if item_scope:
        item_scope = _SCOPE_ALIASES.get(item_scope, item_scope)

    tools = list(project.get("tools", []))
    already_registered = tool_id in tools

    if already_registered:
        if not item_scope:
            return
        scope_tools = {k: list(v) for k, v in
                       (project.get("scope_tools") or {}).items()}
        in_any_scope = any(tool_id in stl
                           for sk, stl in scope_tools.items()
                           if sk != "multi")
        if in_any_scope:
            return
        already_in = any(tool_id in stl
                         for sk, stl in scope_tools.items()
                         if sk == item_scope)
        if not already_in and item_scope in scope_tools:
            scope_tools[item_scope].append(tool_id)
            from models.project import update_project
            update_project(project_id, {"scope_tools": scope_tools})
            project["scope_tools"] = scope_tools
            socketio = get_ext("socketio")
            if socketio:
                socketio.emit("tool_registered", {
                    "project_id": project_id,
                    "tool_id": tool_id,
                    "scope": item_scope,
                    "origin_scope": item_scope,
                    "tools": tools,
                    "scope_tools": scope_tools,
                }, room=_room(project_id))
        return

    from config import TOOLS, TOOL_OUTPUT_DIRS
    if tool_id not in TOOLS:
        return

    if "original_tools" not in project:
        from models.project import update_project as _up
        _up(project_id, {
            "original_tools": list(tools),
            "original_scope_tools": {
                k: list(v) for k, v in (project.get("scope_tools") or {}).items()
            },
        })
        project["original_tools"] = list(tools)
        project["original_scope_tools"] = {
            k: list(v) for k, v in (project.get("scope_tools") or {}).items()
        }

    tools.append(tool_id)

    auto_added = list(project.get("auto_added_tools") or [])
    if tool_id not in auto_added:
        auto_added.append(tool_id)

    scope_tools = {k: list(v) for k, v in (project.get("scope_tools") or {}).items()}
    scope_tool_dirs = {k: dict(v) for k, v in (project.get("scope_tool_dirs") or {}).items()}
    tool_dirs = dict(project.get("tool_dirs") or {})
    eng_dir = project.get("engagement_dir") or project.get("project_dir", "")
    active = project.get("active_scopes") or []

    target_scope = None
    _USER_SCOPES = {"external", "internal", "osint"}

    if item_scope and item_scope in _USER_SCOPES \
            and item_scope in active and item_scope in scope_tools:
        target_scope = item_scope

    if not target_scope:
        generators = _TOOL_GENERATORS.get(tool_id, [])
        for scope_name, stl in scope_tools.items():
            if scope_name == "multi":
                continue
            if scope_name in _USER_SCOPES and any(g in stl for g in generators):
                target_scope = scope_name
                break

    if not target_scope and item_scope \
            and item_scope in _USER_SCOPES \
            and item_scope in active and item_scope in scope_tools:
        target_scope = item_scope

    if not target_scope:
        generators = _TOOL_GENERATORS.get(tool_id, [])
        for scope_name, stl in scope_tools.items():
            if scope_name == "multi":
                continue
            if any(g in stl for g in generators):
                target_scope = scope_name
                break

    if not target_scope:
        generators = _TOOL_GENERATORS.get(tool_id, [])
        from routes.project import _TOOL_NATIVE_SCOPE
        project_tools = project.get("tools") or []
        if item_scope and item_scope in _USER_SCOPES:
            target_scope = item_scope
        else:
            for gen in generators:
                if gen in project_tools:
                    gen_scope = _TOOL_NATIVE_SCOPE.get(gen)
                    if gen_scope and gen_scope in _USER_SCOPES:
                        target_scope = gen_scope
                        break

    if not target_scope:
        real_active = [s for s in active if s != "multi"]
        real_active = [s for s in real_active if s in _USER_SCOPES]
        if real_active:
            target_scope = real_active[0]
        else:
            target_scope = "external"

    if target_scope:
        scope_tools.setdefault(target_scope, [])
        if tool_id not in scope_tools[target_scope]:
            scope_tools[target_scope].append(tool_id)
        if "multi" in scope_tools and tool_id in scope_tools["multi"]:
            scope_tools["multi"].remove(tool_id)

        tool_dirname = TOOL_OUTPUT_DIRS.get(tool_id, tool_id)
        scope_dir = Path(eng_dir) / target_scope
        scope_dir.mkdir(parents=True, exist_ok=True)
        td = scope_dir / tool_dirname
        td.mkdir(parents=True, exist_ok=True)

        scope_tool_dirs.setdefault(target_scope, {})
        scope_tool_dirs[target_scope][tool_id] = str(td)
        if tool_id not in tool_dirs:
            tool_dirs[tool_id] = str(td)

    from models.project import update_project
    update_project(project_id, {
        "tools": tools,
        "scope_tools": scope_tools,
        "scope_tool_dirs": scope_tool_dirs,
        "tool_dirs": tool_dirs,
        "auto_added_tools": auto_added,
    })

    project["tools"] = tools
    project["scope_tools"] = scope_tools
    project["scope_tool_dirs"] = scope_tool_dirs
    project["tool_dirs"] = tool_dirs
    project["auto_added_tools"] = auto_added

    socketio = get_ext("socketio")
    if socketio:
        socketio.emit("tool_registered", {
            "project_id": project_id,
            "tool_id": tool_id,
            "scope": target_scope,
            "origin_scope": item_scope,
            "tools": tools,
            "scope_tools": scope_tools,
        }, room=_room(project_id))


import re as _re_ai
_ASN_REJECT_RE = _re_ai.compile(r'^AS\d+$', _re_ai.IGNORECASE)
del _re_ai


def _inject_targets(proj_dir, tool_id, targets, settings, project=None,
                    scope=None):
    """Write action-item targets into the tool's settings file AND the
    in-memory settings dict before launch.

    Each tool has a different settings layout:
      fracture  — scan.target_url + scan.target_urls  (file-based)
      siphon    — scan.api_base_url + scan.api_base_urls  (file-based)
      auger     — host + port  (file-based, parsed from "ip:port")
      authprobe — target_url  (in-memory only, no settings file)

    When *project* is provided, also injects the output directory
    (``scan.project``) and engagement metadata so the tool writes to
    the location that the findings loader expects.

    When *scope* is provided, writes to a scope-qualified settings file
    (e.g. ``fr_settings_ext.json``) to prevent clobbering across scopes.

    ASN targets (e.g. AS22843) are rejected — tools cannot expand them.
    """
    if not targets:
        return

    # Reject ASN targets — no tool can expand ASN numbers into IPs
    rejected = [t for t in targets if _ASN_REJECT_RE.match(t.strip())]
    if rejected:
        log.error("Rejected ASN target(s) for %s: %s — ASNs are not valid "
                  "scan targets. Convert to IPs/CIDRs first.",
                  tool_id, ", ".join(rejected[:10]))
    targets = [t for t in targets if not _ASN_REJECT_RE.match(t.strip())]

    # Deduplicate targets (mixed newline/comma separation can cause doubles)
    seen = set()
    deduped = []
    for t in targets:
        t_key = t.strip().lower()
        if t_key and t_key not in seen:
            seen.add(t_key)
            deduped.append(t.strip())
    targets = deduped

    if not targets:
        return

    if tool_id == "authprobe":
        settings["target_url"] = targets[0]
        return

    from config import TOOL_SETTINGS_PREFIX
    prefix = TOOL_SETTINGS_PREFIX.get(tool_id, tool_id)
    fname = f"{prefix}_settings_{scope}.json" if scope else f"{prefix}_settings.json"
    # Write to the tool's output directory, not the project root
    td = (project.get("tool_dirs") or {}).get(tool_id) if project else None
    if td:
        fp = Path(td) / fname
    else:
        fp = Path(proj_dir) / fname

    existing = {}
    # Check tool dir first, then fall back to project root (legacy)
    if fp.exists():
        try:
            with open(fp) as f:
                existing = json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    elif td:
        legacy_fp = Path(proj_dir) / fname
        if legacy_fp.exists():
            try:
                with open(legacy_fp) as f:
                    existing = json.load(f)
            except (json.JSONDecodeError, OSError):
                pass

    if tool_id == "fracture":
        scan = existing.setdefault("scan", {})
        scan["target_url"] = _ensure_url_scheme(targets[0])
        scan["target_urls"] = [_ensure_url_scheme(t) for t in targets] \
            if len(targets) > 1 else []
        if project:
            td = (project.get("tool_dirs") or {}).get(tool_id)
            if td:
                scan["project"] = td
            eng = existing.setdefault("engagement", {})
            eng["client_short"] = project.get("client_short", "")
            eng["start_date"] = project.get("start_date", "")
            eng["client_name"] = project.get("client_name", "")
    elif tool_id == "siphon":
        scan = existing.setdefault("scan", {})
        scan["api_base_url"] = _ensure_url_scheme(targets[0])
        scan["api_base_urls"] = [_ensure_url_scheme(t) for t in targets[1:]] \
            if len(targets) > 1 else []
        scan.setdefault("environment", "non-production")
        if project:
            td = (project.get("tool_dirs") or {}).get(tool_id)
            if td:
                scan["project"] = td
            eng = existing.setdefault("engagement", {})
            eng["client_short"] = project.get("client_short", "")
            eng["start_date"] = project.get("start_date", "")
            eng["client_name"] = project.get("client_name", "")
    elif tool_id == "auger":
        t = targets[0]
        # File-based target: URL or local path from action item metadata
        _is_file_target = (
            t.startswith("http://") or t.startswith("https://")
            or t.startswith("file://") or t.startswith("/")
            or t.endswith((".sql", ".dump", ".sqlite", ".sqlite3", ".db",
                           ".rdb", ".h2.db", ".mv.db", ".sqlitedb", ".s3db"))
        )
        if _is_file_target:
            existing["db_file"] = t
            existing.pop("host", None)
            existing.pop("port", None)
        elif ":" in t and not t.startswith("["):
            parts = t.rsplit(":", 1)
            existing["host"] = parts[0]
            try:
                existing["port"] = int(parts[1])
            except ValueError:
                existing["host"] = t
        else:
            existing["host"] = t
        if project:
            td = (project.get("tool_dirs") or {}).get(tool_id)
            if td:
                scan = existing.setdefault("scan", {})
                scan["project"] = td
            eng = existing.setdefault("engagement", {})
            eng["client_short"] = project.get("client_short", "")
            eng["client_name"] = project.get("client_name", "")
    elif tool_id in ("ss3", "osift"):
        scan = existing.setdefault("scan", {})
        if tool_id == "ss3":
            scan["targets"] = targets
        else:
            existing["domains"] = targets
        if project:
            td = (project.get("tool_dirs") or {}).get(tool_id)
            if td:
                scan["project"] = td
            eng = existing.setdefault("engagement", {})
            eng["client_short"] = project.get("client_short", "")
            eng["start_date"] = project.get("start_date", "")
            eng["client_name"] = project.get("client_name", "")
            if tool_id == "ss3":
                _sd = project.get("scope_definition") or {}
                _dmr = _sd.get("ss3_discovery_min_rate", 0)
                if _dmr:
                    scan["discovery_min_rate"] = _dmr
                _dmp = _sd.get("ss3_discovery_min_parallelism", 0)
                if _dmp:
                    scan["discovery_min_parallelism"] = _dmp
                _tt = _sd.get("ss3_timing_template", "")
                if _tt:
                    scan["timing_template"] = _tt
    elif tool_id == "trawler":
        _pcap_exts = {".pcap", ".pcapng", ".cap", ".ntar", ".erf", ".snoop"}
        pcap_targets = [t for t in targets
                        if "/" in t and Path(t).suffix.lower() in _pcap_exts]
        ip_targets = [t for t in targets if t not in pcap_targets]
        if pcap_targets:
            existing["pcap_file"] = pcap_targets[0]
        if ip_targets:
            existing["targets"] = ip_targets
        td_out = (project.get("tool_dirs") or {}).get(tool_id) if project else None
        if td_out:
            existing["output_dir"] = td_out
        if project:
            existing["client"] = project.get("client_short", "trawler")
    elif tool_id == "isotope":
        scan = existing.setdefault("scan", {})
        scan["files"] = targets
        if project:
            td_out = (project.get("tool_dirs") or {}).get(tool_id)
            if td_out:
                scan["output"] = td_out
        scan.setdefault("max_depth", settings.get("archive_depth", 5))
        mods = settings.get("modules", [])
        if mods:
            scan["modules"] = ",".join(mods)
    elif tool_id == "dredge":
        scope_def = project.get("scope_definition", {}) if project else {}
        mode = scope_def.get("dredge_mode", "import")
        if mode == "winrm":
            existing["winrm_host"] = targets[0] if targets else scope_def.get("dredge_winrm_host", "")
            existing["winrm_user"] = scope_def.get("dredge_winrm_user", "")
            existing["winrm_pass"] = scope_def.get("dredge_winrm_pass", "")
            existing["winrm_port"] = scope_def.get("dredge_winrm_port", 5985)
            existing["winrm_ssl"] = scope_def.get("dredge_winrm_ssl", False)
        else:
            existing["collection_path"] = scope_def.get("dredge_collection_path",
                scope_def.get("dredge_collection_file", ""))
        existing["vt_api_key"] = scope_def.get("dredge_vt_key", "")
        existing["abuseipdb_key"] = scope_def.get("dredge_abuseipdb_key", "")
        existing["skip_sections"] = scope_def.get("dredge_skip_sections", "")
        if project:
            td_out = (project.get("tool_dirs") or {}).get(tool_id)
            if td_out:
                existing["output_dir"] = td_out
            existing["client"] = project.get("client_short", "")
        settings.update(existing)
    else:
        settings["target"] = ", ".join(targets)
        return

    fp.parent.mkdir(parents=True, exist_ok=True)
    with open(fp, "w") as f:
        json.dump(existing, f, indent=2)


@action_items_bp.route("/api/action-items/<project_id>")
def api_action_items(project_id):
    try:
        project = require_project(project_id)
        proj_dir = project.get("project_dir", "")
        if not proj_dir:
            return jsonify({"items": [], "summary": {}})

        sm = get_ext("scope_manager")
        pm = get_ext("process_manager")
        running = set(pm.running_tools(project_id)) if pm else set()

        items = load_and_repair(proj_dir, sm, project, running,
                                tool_dirs=project.get("tool_dirs"))

        if sm:
            items = [i for i in items
                     if not _is_excluded_item(i, sm, project)]

        summary = get_action_items_summary(proj_dir)
        return jsonify({"items": items, "summary": summary})
    except Exception as exc:
        log.exception("Error loading action items for %s", project_id)
        return jsonify({"error": str(exc)}), 500


@action_items_bp.route("/api/action-item/execute", methods=["POST"])
def api_execute_action():
    """Execute an action item — launches the recommended tool via queue manager."""
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    item_id = data.get("item_id")
    if not project_id or not item_id:
        return jsonify({"error": "project_id and item_id required"}), 400

    try:
        project = require_project(project_id)

        from models.action_items import get_action_item
        item = get_action_item(project.get("project_dir", ""), item_id)
        if not item:
            return jsonify({"error": "Action item not found"}), 404

        tool_id = (item.get("recommended_tool") or "").lower()
        if not tool_id:
            return jsonify({"error": "No recommended tool"}), 400

        item_scope = item.get("scope")
        _ensure_tool_registered(project_id, project, tool_id, item_scope=item_scope)

        pm = get_ext("process_manager")
        qm = get_ext("queue_manager")
        if not pm:
            return jsonify({"error": "Process manager not available"}), 503

        scope = item.get("metadata", {}).get("scope") or data.get("scope") or item_scope
        from models.settings import load_settings
        proj_dir = project.get("project_dir", "")
        settings = load_settings(proj_dir, tool_id, scope=scope) if proj_dir else {}

        user_settings = data.get("settings")
        if user_settings and isinstance(user_settings, dict):
            settings.update(user_settings)

        target = item.get("target", "")
        if tool_id == "isotope":
            targets = _resolve_isotope_targets(item, project)
            if not targets:
                return jsonify({
                    "error": "Could not resolve any local files for Isotope analysis. "
                             "The source tool may not have downloaded the target files."
                }), 400
        elif target:
            targets = [target]
        else:
            targets = []
        if targets and proj_dir:
            _inject_targets(proj_dir, tool_id, targets, settings, project=project,
                            scope=scope)
        extra_args = None
        meta = item.get("metadata", {})
        if meta.get("credentialled_scan") and meta.get("credentials") and qm:
            extra_args = qm._prepare_credentialled_launch(project, tool_id, meta)

        if tool_id == "deps" and meta.get("dep_tool"):
            settings["dep_tool"] = meta["dep_tool"]
            if meta["dep_tool"] == "o365spray" and meta.get("harvested_emails"):
                from adapters import get_adapter
                deps_adapter = get_adapter("deps")
                if deps_adapter and hasattr(deps_adapter, "prepare_email_file"):
                    ef = deps_adapter.prepare_email_file(
                        project, meta["harvested_emails"], scope=scope or "external")
                    if ef:
                        settings["email_file"] = ef

        can_launch = True
        reason = ""
        if qm:
            can_launch, reason = qm.can_launch(project_id, tool_id)

        custom_cmd = data.get("custom_command")

        if can_launch:
            update_action_item_status(proj_dir, item_id, "running",
                                      extra_fields={"user_reset": False})
            pm.launch(project_id, tool_id, project=project, settings=settings,
                      scope=scope, extra_args=extra_args,
                      action_item_id=item_id,
                      custom_command=custom_cmd)
            return jsonify({"ok": True, "tool_id": tool_id, "status": "running"})
        else:
            update_action_item_status(proj_dir, item_id, "queued",
                                      extra_fields={"user_reset": False})
            if qm:
                priority = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(
                    item.get("priority", "MEDIUM"), 2)
                qm.enqueue(project_id, tool_id, priority=priority,
                           settings=settings, action_item_id=item_id,
                           target=item.get("target", ""), extra_args=extra_args,
                           scope=scope)
            return jsonify({"ok": True, "tool_id": tool_id, "status": "queued",
                            "reason": reason})
    except Exception as exc:
        log.exception("Error executing action item %s", item_id)
        return jsonify({"error": str(exc)}), 500


@action_items_bp.route("/api/action-item/dismiss", methods=["POST"])
def api_dismiss_action():
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    item_id = data.get("item_id")
    if not project_id or not item_id:
        return jsonify({"error": "project_id and item_id required"}), 400
    try:
        project = require_project(project_id)
        dismiss_action_item(project.get("project_dir", ""), item_id)
        return jsonify({"ok": True})
    except Exception as exc:
        log.exception("Error dismissing action item %s", item_id)
        return jsonify({"error": str(exc)}), 500


@action_items_bp.route("/api/action-item/queue", methods=["POST"])
def api_queue_action():
    """Queue an action item for later execution."""
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    item_id = data.get("item_id")
    if not project_id or not item_id:
        return jsonify({"error": "project_id and item_id required"}), 400
    try:
        project = require_project(project_id)
        update_action_item_status(project.get("project_dir", ""), item_id,
                                  "queued",
                                  extra_fields={"user_reset": False})
        return jsonify({"ok": True})
    except Exception as exc:
        log.exception("Error queueing action item %s", item_id)
        return jsonify({"error": str(exc)}), 500


@action_items_bp.route("/api/dequeue", methods=["POST"])
def api_dequeue():
    """Remove a tool from the execution queue."""
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    tool_id = data.get("tool_id")
    if not project_id or not tool_id:
        return jsonify({"error": "project_id and tool_id required"}), 400
    try:
        require_project(project_id)
        qm = get_ext("queue_manager")
        if not qm:
            return jsonify({"error": "Queue manager not available"}), 503
        removed = qm.remove_from_queue(project_id, tool_id)
        if removed:
            return jsonify({"ok": True, "removed": True})
        return jsonify({"ok": True, "removed": False})
    except Exception as exc:
        log.exception("Error dequeuing %s for %s", tool_id, project_id)
        return jsonify({"error": str(exc)}), 500


@action_items_bp.route("/api/action-item/reset", methods=["POST"])
def api_reset_action():
    """Reset a queued/running/failed action item back to pending.

    If the tool is currently running, refuses the reset and returns the PID.
    After resetting, checks if ALL action items for that tool are now
    pending/dismissed — if so, cleans up the console log and settings file.
    """
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    item_id = data.get("item_id")
    if not project_id or not item_id:
        return jsonify({"error": "project_id and item_id required"}), 400
    try:
        project = require_project(project_id)
        proj_dir = project.get("project_dir", "")

        from models.action_items import get_action_item
        item = get_action_item(proj_dir, item_id)
        if not item:
            return jsonify({"error": "Action item not found"}), 404

        tool_id = (item.get("recommended_tool") or "").lower()
        status = item.get("status", "pending")

        # Refuse if tool is actively running
        if status == "running" and tool_id:
            pm = get_ext("process_manager")
            if pm:
                running = pm.running_tools(project_id)
                if tool_id in running:
                    pid = None
                    meta = (pm._tool_metadata.get(project_id) or {})
                    for tk, m in meta.items():
                        base = tk.split(":")[0] if ":" in tk else tk
                        if base == tool_id:
                            pid = m.get("pid")
                            break
                    return jsonify({
                        "error": f"{tool_id} is currently executing "
                                 f"and must fail, be cancelled, or complete "
                                 f"before a reset can occur."
                                 + (f" (PID: {pid})" if pid else ""),
                        "running": True,
                        "pid": pid,
                    }), 409

        update_action_item_status(proj_dir, item_id, "pending",
                                   extra_fields={"user_reset": True})

        # Only clean up when EVERY executed item for this tool has been
        # reset — items still in queued/running/failed/complete block
        # cleanup, and pending items that were never executed (no
        # user_reset flag) also block it since they indicate the tool
        # session may still be relevant.
        console_cleared = False
        unregistered = False
        if tool_id:
            from models.action_items import get_action_items_by_tool
            tool_items = get_action_items_by_tool(proj_dir, tool_id)
            still_active = [i for i in tool_items
                            if i.get("status") in ("queued", "running",
                                                    "failed", "complete")]
            pending_not_reset = [i for i in tool_items
                                 if i.get("status") == "pending"
                                 and not i.get("user_reset")]
            if not still_active and not pending_not_reset:
                console_cleared = _cleanup_tool_session(
                    project, project_id, tool_id)
                unregistered = tool_id not in (project.get("tools") or [])

        resp = {"ok": True, "console_cleared": console_cleared,
                "tool_id": tool_id, "unregistered": unregistered}
        if console_cleared:
            from config import TOOLS
            resp["tool_name"] = TOOLS.get(tool_id, {}).get("name", tool_id)
        return jsonify(resp)
    except Exception as exc:
        log.exception("Error resetting action item %s", item_id)
        return jsonify({"error": str(exc)}), 500


def _cleanup_tool_session(project, project_id, tool_id):
    """Remove console log, settings file, and unregister the tool
    when all its action items have been reset.

    Only unregisters tools that were auto-added by action items
    (tracked in ``project["auto_added_tools"]``).
    """
    from pathlib import Path
    proj_dir = project.get("project_dir", "")
    tool_dir = (project.get("tool_dirs") or {}).get(tool_id)
    cleaned = False

    # Remove console log + settings file from tool dir
    if tool_dir:
        td = Path(tool_dir)
        for log_file in td.glob("console_*.log"):
            try:
                log_file.unlink()
                cleaned = True
            except OSError:
                pass

        from config import TOOL_SETTINGS_PREFIX
        prefix = TOOL_SETTINGS_PREFIX.get(tool_id, tool_id)
        for sf in td.glob(f"{prefix}_settings_*.json"):
            try:
                sf.unlink()
                cleaned = True
            except OSError:
                pass
        plain = td / f"{prefix}_settings.json"
        if plain.exists():
            try:
                plain.unlink()
                cleaned = True
            except OSError:
                pass

    # Fully remove in-memory session (all scope-qualified keys)
    pm = get_ext("process_manager")
    if pm:
        pm.remove_tool_session(project_id, tool_id)

    # Unregister auto-added tool from the project
    auto_added = list(project.get("auto_added_tools") or [])
    if tool_id in auto_added:
        auto_added.remove(tool_id)
        tools = list(project.get("tools") or [])
        if tool_id in tools:
            tools.remove(tool_id)
        scope_tools = {k: list(v) for k, v
                       in (project.get("scope_tools") or {}).items()}
        for sk in list(scope_tools):
            if tool_id in scope_tools[sk]:
                scope_tools[sk].remove(tool_id)
        tool_dirs = dict(project.get("tool_dirs") or {})
        tool_dirs.pop(tool_id, None)
        scope_tool_dirs = {k: dict(v) for k, v
                          in (project.get("scope_tool_dirs") or {}).items()}
        for sk in list(scope_tool_dirs):
            scope_tool_dirs[sk].pop(tool_id, None)

        from models.project import update_project
        update_project(project_id, {
            "tools": tools,
            "scope_tools": scope_tools,
            "tool_dirs": tool_dirs,
            "scope_tool_dirs": scope_tool_dirs,
            "auto_added_tools": auto_added,
        })
        project["tools"] = tools
        project["scope_tools"] = scope_tools
        project["tool_dirs"] = tool_dirs
        project["scope_tool_dirs"] = scope_tool_dirs
        project["auto_added_tools"] = auto_added
        cleaned = True

    unregistered = tool_id not in (project.get("tools") or [])
    socketio = get_ext("socketio")
    if socketio:
        socketio.emit("console_cleared",
                      {"project_id": project_id, "tool_id": tool_id,
                       "unregistered": unregistered},
                      room=f"project_{project_id}")
    return cleaned


@action_items_bp.route("/api/bulk-dismiss-actions", methods=["POST"])
def api_bulk_dismiss_actions():
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    item_ids = data.get("item_ids", [])
    if not project_id or not item_ids:
        return jsonify({"error": "project_id and item_ids required"}), 400
    try:
        project = require_project(project_id)
        bulk_update_status(project.get("project_dir", ""), item_ids, "dismissed")
        return jsonify({"ok": True, "dismissed": len(item_ids)})
    except Exception as exc:
        log.exception("Error bulk dismissing action items")
        return jsonify({"error": str(exc)}), 500


@action_items_bp.route("/api/bulk-queue-actions", methods=["POST"])
def api_bulk_queue_actions():
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    item_ids = data.get("item_ids", [])
    if not project_id or not item_ids:
        return jsonify({"error": "project_id and item_ids required"}), 400
    try:
        project = require_project(project_id)
        bulk_update_status(project.get("project_dir", ""), item_ids, "queued")
        return jsonify({"ok": True, "queued": len(item_ids)})
    except Exception as exc:
        log.exception("Error bulk queueing action items")
        return jsonify({"error": str(exc)}), 500


@action_items_bp.route("/api/action-item/note", methods=["POST"])
def api_action_item_note():
    """Add a note to an action item. Persists to disk."""
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    item_id = data.get("item_id")
    note_text = (data.get("note") or "").strip()
    if not project_id or not item_id or not note_text:
        return jsonify({"error": "project_id, item_id, and note required"}), 400
    try:
        project = require_project(project_id)
        add_action_item_note(project.get("project_dir", ""), item_id, note_text)
        return jsonify({"ok": True})
    except Exception as exc:
        log.exception("Error adding note to action item %s", item_id)
        return jsonify({"error": str(exc)}), 500


@action_items_bp.route("/api/bulk-launch-tool", methods=["POST"])
def api_bulk_launch_tool():
    """Bulk-launch a tool for multiple action items.

    Starts one tool instance and marks all selected action items
    as running (or queued if concurrency limit is reached).
    """
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    tool_id = data.get("tool_id")
    item_ids = data.get("item_ids", [])
    if not project_id or not tool_id or not item_ids:
        return jsonify({"error": "project_id, tool_id, and item_ids required"}), 400

    try:
        project = require_project(project_id)
        item_scope = data.get("scope")
        _ensure_tool_registered(project_id, project, tool_id, item_scope=item_scope)

        pm = get_ext("process_manager")
        qm = get_ext("queue_manager")
        if not pm:
            return jsonify({"error": "Process manager not available"}), 503

        from models.settings import load_settings, save_settings
        proj_dir = project.get("project_dir", "")
        scope = data.get("scope")
        is_oos = data.get("oos", False)
        launch_scope = f"oos_{scope}" if is_oos and scope else ("oos" if is_oos else scope)
        settings = load_settings(proj_dir, tool_id, scope=scope) if proj_dir else {}

        targets = data.get("targets", [])
        if targets and proj_dir:
            _inject_targets(proj_dir, tool_id, targets, settings, project=project,
                            scope=scope)

        can_launch = True
        reason = ""
        if qm:
            can_launch, reason = qm.can_launch(project_id, tool_id)

        new_status = "running" if can_launch else "queued"
        bulk_update_status(proj_dir, item_ids, new_status)

        if can_launch:
            pm.launch(project_id, tool_id, project=project, settings=settings,
                      scope=launch_scope)
            return jsonify({"ok": True, "tool_id": tool_id, "status": "running",
                            "count": len(item_ids), "scope": launch_scope})
        else:
            if qm:
                qm.enqueue(project_id, tool_id, priority=1,
                           settings=settings, scope=launch_scope)
            return jsonify({"ok": True, "tool_id": tool_id, "status": "queued",
                            "reason": reason, "count": len(item_ids)})
    except Exception as exc:
        log.exception("Error bulk launching %s", tool_id)
        return jsonify({"error": str(exc)}), 500


@action_items_bp.route("/api/launch-tool/<project_id>", methods=["POST"])
def api_launch_tool(project_id):
    """Launch a tool directly (not from action items)."""
    data = request.get_json(silent=True) or {}
    tool_id = data.get("tool_id")
    if not tool_id:
        return jsonify({"error": "tool_id required"}), 400
    try:
        project = require_project(project_id)

        pm = get_ext("process_manager")
        if not pm:
            return jsonify({"error": "Process manager not available"}), 503

        resume = data.get("resume", False)
        extra_args = data.get("extra_args")

        from models.settings import load_settings
        proj_dir = project.get("project_dir", "")
        settings = load_settings(proj_dir, tool_id) if proj_dir else {}
        _backfill_launch_settings(settings, project, tool_id)

        if tool_id == "dredge":
            scope_def = project.get("scope_definition", {})
            mode = scope_def.get("dredge_mode", "import")
            if mode == "winrm":
                settings.setdefault("winrm_host", scope_def.get("dredge_winrm_host", ""))
                settings.setdefault("winrm_user", scope_def.get("dredge_winrm_user", ""))
                settings.setdefault("winrm_pass", scope_def.get("dredge_winrm_pass", ""))
                settings.setdefault("winrm_port", scope_def.get("dredge_winrm_port", 5985))
                settings.setdefault("winrm_ssl", scope_def.get("dredge_winrm_ssl", False))
            else:
                settings.setdefault("collection_path", scope_def.get("dredge_collection_path",
                    scope_def.get("dredge_collection_file", "")))
            settings.setdefault("vt_api_key", scope_def.get("dredge_vt_key", ""))
            settings.setdefault("abuseipdb_key", scope_def.get("dredge_abuseipdb_key", ""))
            settings.setdefault("skip_sections", scope_def.get("dredge_skip_sections", ""))

        pm.launch(project_id, tool_id, project=project, settings=settings,
                  resume=resume, extra_args=extra_args, scope=data.get("scope"))

        return jsonify({"ok": True, "tool_id": tool_id})
    except Exception as exc:
        log.exception("Error launching tool %s for %s", tool_id, project_id)
        return jsonify({"error": str(exc)}), 500


@action_items_bp.route("/api/preview-command", methods=["POST"])
def api_preview_command():
    """Build and return the command that would be run for an action item."""
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    item_id = data.get("item_id")
    tool_id = data.get("tool_id", "").lower()
    if not project_id or not tool_id:
        return jsonify({"error": "project_id and tool_id required"}), 400

    try:
        project = require_project(project_id)
        from adapters import get_adapter
        adapter = get_adapter(tool_id)
        if not adapter or not getattr(adapter, "is_external", False):
            return jsonify({"command": ""})

        from models.settings import load_settings
        proj_dir = project.get("project_dir", "")
        settings = load_settings(proj_dir, tool_id) if proj_dir else {}

        user_settings = data.get("settings")
        if user_settings and isinstance(user_settings, dict):
            settings.update(user_settings)

        if item_id:
            from models.action_items import get_action_item
            item = get_action_item(proj_dir, item_id)
            if item:
                target = item.get("target", "")
                if target:
                    settings["target"] = target
                scope = item.get("metadata", {}).get("scope") or item.get("scope")
                if scope:
                    _inject_targets(proj_dir, tool_id, [target], settings,
                                    project=project, scope=scope)
                meta = item.get("metadata", {})
                if tool_id == "deps" and meta.get("dep_tool"):
                    settings["dep_tool"] = meta["dep_tool"]
                    if meta["dep_tool"] == "o365spray" and meta.get("harvested_emails"):
                        if hasattr(adapter, "prepare_email_file"):
                            ef = adapter.prepare_email_file(
                                project, meta["harvested_emails"],
                                scope=scope or "external")
                            if ef:
                                settings["email_file"] = ef

        cmd = adapter.build_command(project, settings, resume=False)
        import shlex
        cmd_str = shlex.join(cmd) if cmd else ""
        return jsonify({"command": cmd_str})
    except Exception as exc:
        log.exception("Error previewing command for %s", tool_id)
        return jsonify({"error": str(exc)}), 500
