"""Console API routes — history, activity feed, health checks, subprocesses."""

import logging
import shutil
from pathlib import Path

from flask import Blueprint, request, jsonify

from config import TOOLS
from routes._helpers import require_project, get_ext

log = logging.getLogger("crucible.routes.console")

console_bp = Blueprint("console", __name__)


def _pm():
    return get_ext("process_manager")


@console_bp.route("/api/console/<project_id>/<tool_id>")
def api_console(project_id, tool_id):
    """Return console output for a specific tool.

    Running tools return the live in-memory buffer.  Completed / killed /
    failed tools return the full scan.log from disk so the output is
    auditable without truncation.

    ?tail=N  — return only the last N lines (used by mobile clients to
    avoid OOM on multi-MB console logs).
    """
    pm = _pm()
    if not pm:
        return jsonify({"lines": []})

    tail = request.args.get("tail", type=int)

    base_tid = tool_id
    scope = None
    if ":" in tool_id:
        base_tid, scope = tool_id.split(":", 1)

    if pm.is_running(project_id, tool_id):
        lines = pm.get_console(project_id, tool_id)
    else:
        lines = _load_full_console(project_id, base_tid, scope=scope)
        if not lines:
            lines = pm.get_console(project_id, tool_id)
    if tail and tail > 0 and len(lines) > tail:
        lines = lines[-tail:]
    return jsonify({"lines": lines})


def _load_full_console(project_id, tool_id, scope=None):
    """Read the full console output from disk for a completed tool.

    Prefers the persisted console log (full stdout buffer saved at
    process end) over scan.log (which only contains structured entries).
    Searches tool output directory first, then project root.
    Also checks scope-qualified console log filenames.
    """
    from config import TOOL_OUTPUT_DIRS, TOOL_SETTINGS_PREFIX
    project = require_project(project_id)
    display_tid = f"{tool_id}:{scope}" if scope else tool_id

    def _read_console_log(log_path):
        try:
            text = log_path.read_text(errors="replace")
            entries = []
            for line in text.splitlines():
                ts = ""
                content = line
                if line.startswith("[") and "] " in line:
                    bracket_end = line.index("] ")
                    ts = line[1:bracket_end]
                    content = line[bracket_end + 2:]
                entries.append({
                    "project_id": project_id,
                    "tool_id": display_tid,
                    "ts": ts,
                    "stream": "stdout",
                    "text": content,
                })
            return entries if entries else None
        except OSError as exc:
            log.debug("read console log: %s", exc)
            return None

    td = project.get("tool_dirs", {}).get(tool_id)
    if td and Path(td).is_dir():
        if scope:
            scoped = Path(td) / f"console_{scope}.log"
            if scoped.exists():
                result = _read_console_log(scoped)
                if result:
                    return result
        for cl in sorted(Path(td).glob("console*.log")):
            result = _read_console_log(cl)
            if result:
                return result

    proj_dir_str = project.get("project_dir", "")
    if proj_dir_str:
        pd = Path(proj_dir_str)
        candidates = []
        if scope:
            candidates.append(pd / f"console_{tool_id}:{scope}.log")
        candidates.append(pd / f"console_{tool_id}.log")
        candidates.extend(sorted(pd.glob(f"console_{tool_id}:*.log")))
        for cl in candidates:
            if cl.exists():
                result = _read_console_log(cl)
                if result:
                    return result

    td = project.get("tool_dirs", {}).get(tool_id)
    if not td:
        eng_dir = project.get("engagement_dir",
                              project.get("project_dir", ""))
        if eng_dir:
                td = str(Path(eng_dir) /
                     TOOL_OUTPUT_DIRS.get(tool_id, tool_id))
    if not td:
        prefix = TOOL_SETTINGS_PREFIX.get(tool_id)
        proj_dir = Path(project.get("project_dir", ""))
        if prefix and proj_dir.exists():
            import json as _json
            # Check tool output dirs for settings, then fall back to proj root
            _settings_candidates = []
            for _sd in (project.get("tool_dirs") or {}).values():
                if _sd:
                    _settings_candidates.append(Path(_sd) / f"{prefix}_settings.json")
            _settings_candidates.append(proj_dir / f"{prefix}_settings.json")
            scan_proj = "output"
            for settings_path in _settings_candidates:
                if settings_path.exists():
                    try:
                        cfg = _json.loads(settings_path.read_text())
                        scan_proj = cfg.get("scan", {}).get("project", "output")
                    except Exception as exc:
                        log.warning("read settings for console: %s", exc)
                    break
            candidate = proj_dir / scan_proj
            if candidate.is_dir():
                td = str(candidate)
    if not td:
        return []
    tool_dir = Path(td)
    entries = []
    candidates = []
    if tool_id == "ss3":
        ss3_scopes = [scope] if scope else ["ext", "int"]
        for _sc in ss3_scopes:
            sl = tool_dir / _sc / "scan.log"
            if sl.exists():
                candidates.append((sl, _sc))
    if not scope:
        sl = tool_dir / "scan.log"
        if sl.exists():
            candidates.append((sl, None))
    for logfile, log_scope in candidates:
        try:
            text = logfile.read_text(errors="replace")
        except OSError as exc:
            log.debug("read scan.log: %s", exc)
            continue
        pfx = f"[{log_scope.upper()}] " if log_scope else ""
        for line in text.splitlines():
            ts = ""
            content = line
            if line.startswith("[") and "] " in line:
                bracket_end = line.index("] ")
                ts = line[1:bracket_end]
                content = line[bracket_end + 2:]
            entries.append({
                "project_id": project_id,
                "tool_id": display_tid,
                "ts": ts,
                "stream": "stdout",
                "text": pfx + content,
            })
    return entries


@console_bp.route("/api/console/feed/<project_id>")
def api_console_feed(project_id):
    """All tools status summary for the activity feed."""
    pm = _pm()
    if not pm:
        return jsonify({"tools": {}})
    statuses = pm.get_all_status(project_id)
    return jsonify({"tools": statuses})


@console_bp.route("/api/console/instance/<project_id>/<path:tool_key>")
def api_console_instance(project_id, tool_key):
    """Return instance details for a scope-qualified tool key.

    Returns scope, OOS status, and targets from the settings file.
    """
    import json as _json
    from config import TOOL_SETTINGS_PREFIX

    project = require_project(project_id)
    proj_dir = project.get("project_dir", "")

    base_tid = tool_key
    scope = None
    if ":" in tool_key:
        base_tid, scope = tool_key.split(":", 1)

    is_oos = bool(scope and scope.endswith("_oos"))
    scope_display = ""
    if scope:
        scope_display = scope.replace("_oos", "").replace("_", " ").strip()

    targets = []
    if proj_dir:
        from config import TOOL_OUTPUT_DIRS
        prefix = TOOL_SETTINGS_PREFIX.get(base_tid, base_tid)
        td = (project.get("tool_dirs") or {}).get(base_tid)
        eng_dir = project.get("engagement_dir",
                              project.get("project_dir", ""))
        if scope:
            fname = f"{prefix}_settings_{scope}.json"
        else:
            fname = f"{prefix}_settings.json"
        candidates = []
        if td:
            candidates.append(Path(td) / fname)
        candidates.append(Path(proj_dir) / fname)
        if eng_dir and eng_dir != proj_dir:
            candidates.append(Path(eng_dir) / fname)
            out_sub = TOOL_OUTPUT_DIRS.get(base_tid)
            if out_sub:
                candidates.append(Path(eng_dir) / out_sub / fname)
        if not scope:
            base_fname = f"{prefix}_settings.json"
            if td and not (Path(td) / base_fname).exists():
                for sf in sorted(Path(td).glob(f"{prefix}_settings_*.json")):
                    candidates.append(sf)
            for search_dir in [Path(proj_dir), Path(eng_dir)] if eng_dir else [Path(proj_dir)]:
                if search_dir.is_dir():
                    for sf in sorted(search_dir.glob(f"{prefix}_settings_*.json")):
                        if sf not in candidates:
                            candidates.append(sf)
        for fp in candidates:
            if fp.exists():
                try:
                    cfg = _json.loads(fp.read_text())
                    scan = cfg.get("scan", cfg)
                    if base_tid == "fracture":
                        urls = scan.get("target_urls") or []
                        main = scan.get("target_url")
                        if main:
                            urls = [main] + [u for u in urls if u != main]
                        targets = urls
                    elif base_tid == "siphon":
                        urls = scan.get("api_base_urls") or []
                        main = scan.get("api_base_url")
                        if main:
                            urls = [main] + [u for u in urls if u != main]
                        targets = urls
                    elif base_tid == "ss3":
                        targets = scan.get("targets") or []
                        if isinstance(targets, str):
                            targets = [t.strip() for t in targets.split(",")
                                       if t.strip()]
                    elif base_tid == "osift":
                        targets = scan.get("domains") or []
                        if isinstance(targets, str):
                            targets = [t.strip() for t in targets.split(",")
                                       if t.strip()]
                    else:
                        targets = scan.get("targets") or []
                        if isinstance(targets, str):
                            targets = [t.strip() for t in targets.split(",")
                                       if t.strip()]
                        host = scan.get("host") or cfg.get("host")
                        if host and not targets:
                            port = scan.get("port") or cfg.get("port")
                            targets = [f"{host}:{port}" if port else host]
                except (OSError, _json.JSONDecodeError, ValueError) as exc:
                    log.debug("instance settings read: %s", exc)
                break

    pids = []
    tool_version = ""
    pm = _pm()
    if pm:
        pids = pm.get_pid_history(project_id, tool_key)
        tool_version = pm.get_tool_version(project_id, tool_key)

    tool_cfg = TOOLS.get(base_tid, {})
    return jsonify({
        "tool_key": tool_key,
        "base_tool": base_tid,
        "tool_name": tool_cfg.get("name", base_tid),
        "tool_version": tool_version,
        "scope": scope_display or scope or "",
        "is_oos": is_oos,
        "targets": targets,
        "pids": pids,
    })


@console_bp.route("/api/console/versions/<project_id>")
def api_console_versions(project_id):
    """Return tool versions used in this project (launched or current)."""
    require_project(project_id)
    pm = _pm()
    versions = pm.get_all_tool_versions(project_id) if pm else {}
    rows = []
    for tk, ver in sorted(versions.items()):
        base = tk.split(":")[0] if ":" in tk else tk
        cfg = TOOLS.get(base, {})
        rows.append({
            "tool_key": tk,
            "tool_name": cfg.get("name", base),
            "tool_version": ver,
        })
    return jsonify({"versions": rows})


def _find_checkpoint_candidates(project, tool_id):
    """Build a list of candidate checkpoint.json paths for a tool."""
    import json as _json
    from config import TOOL_SETTINGS_PREFIX

    candidates = []
    td = project.get("tool_dirs", {}).get(tool_id)
    if td:
        candidates.append(Path(td) / "checkpoint.json")

    for scope_dirs in project.get("scope_tool_dirs", {}).values():
        std = scope_dirs.get(tool_id)
        if std and std != td:
            candidates.append(Path(std) / "checkpoint.json")

    prefix = TOOL_SETTINGS_PREFIX.get(tool_id)
    proj_dir = Path(project.get("project_dir", ""))
    if prefix and proj_dir.exists():
        # Check tool dir first for settings, then project root (legacy)
        settings_path = None
        if td:
            _td_settings = Path(td) / f"{prefix}_settings.json"
            if _td_settings.exists():
                settings_path = _td_settings
        if not settings_path:
            _proj_settings = proj_dir / f"{prefix}_settings.json"
            if _proj_settings.exists():
                settings_path = _proj_settings
        scan_proj = "output"
        if settings_path and settings_path.exists():
            try:
                cfg = _json.loads(settings_path.read_text())
                scan_proj = cfg.get("scan", {}).get("project", "output")
            except Exception as exc:
                log.warning("checkpoint settings read: %s", exc)
        candidates.append(proj_dir / scan_proj / "checkpoint.json")

    return candidates


@console_bp.route("/api/checkpoint/<project_id>/<tool_id>")
def api_checkpoint(project_id, tool_id):
    """Resume checkpoint data for a tool."""
    import json
    project = require_project(project_id)

    for cp_file in _find_checkpoint_candidates(project, tool_id):
        if cp_file.exists():
            try:
                with open(cp_file) as f:
                    return jsonify({"exists": True, "checkpoint": json.load(f)})
            except Exception as exc:
                log.warning("checkpoint read: %s", exc)
                continue
    return jsonify({"exists": False, "checkpoint": None})


@console_bp.route("/api/health-check/<tool_id>")
def api_health_check(tool_id):
    """Pre-flight check: verify tool script exists and is executable."""
    tool_cfg = TOOLS.get(tool_id)
    if not tool_cfg:
        return jsonify({"ok": False, "error": f"Unknown tool: {tool_id}"})
    script = tool_cfg.get("script")
    if script is None:
        # API-only tools like Nessus don't have scripts
        return jsonify({"ok": True, "type": "api"})
    script_path = Path(script)
    if not script_path.exists():
        return jsonify({"ok": False, "error": f"Script not found: {script}"})
    # Check Python is available
    if not shutil.which("python3"):
        return jsonify({"ok": False, "error": "python3 not found on PATH"})
    return jsonify({"ok": True, "script": str(script_path)})


@console_bp.route("/api/subprocesses/<project_id>")
def api_subprocesses(project_id):
    """List running process PIDs for this project."""
    pm = _pm()
    if not pm:
        return jsonify({"processes": []})
    statuses = pm.get_all_status(project_id)
    processes = []
    for tool_id, info in statuses.items():
        if info.get("status") == "running":
            processes.append({
                "tool_id": tool_id,
                "tool_name": TOOLS.get(tool_id, {}).get("name", tool_id),
                "pid": info.get("pid"),
                "started": info.get("started"),
            })
    return jsonify({"processes": processes})


@console_bp.route("/api/kill_subprocess", methods=["POST"])
def api_kill_subprocess():
    """Kill a specific tool process by project_id + tool_id."""
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    tool_id = data.get("tool_id")
    if not project_id or not tool_id:
        return jsonify({"error": "project_id and tool_id required"}), 400
    pm = _pm()
    if not pm:
        return jsonify({"error": "Process manager not available"}), 503
    killed = pm.kill(project_id, tool_id)
    return jsonify({"ok": killed})


@console_bp.route("/api/pause_tool", methods=["POST"])
def api_pause_tool():
    """Request a graceful pause of a specific tool."""
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    tool_id = data.get("tool_id")
    if not project_id or not tool_id:
        return jsonify({"error": "project_id and tool_id required"}), 400
    pm = _pm()
    if not pm:
        return jsonify({"error": "Process manager not available"}), 503
    reason = data.get("reason", "paused_user")
    detail = data.get("detail", "")
    initiated_by = data.get("initiated_by", "user")
    paused = pm.pause(project_id, tool_id,
                      reason=reason, detail=detail,
                      initiated_by=initiated_by)
    return jsonify({"ok": paused})


@console_bp.route("/api/pause_all", methods=["POST"])
def api_pause_all():
    """Pause all running tools in a project."""
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    if not project_id:
        return jsonify({"error": "project_id required"}), 400
    pm = _pm()
    if not pm:
        return jsonify({"error": "Process manager not available"}), 503
    reason = data.get("reason", "paused_user")
    detail = data.get("detail", "")
    initiated_by = data.get("initiated_by", "user")
    paused = pm.pause_all(project_id, reason=reason, detail=detail,
                          initiated_by=initiated_by)
    qm = get_ext("queue_manager")
    if qm:
        qm.pause_project(project_id, reason=reason, detail=detail)
    return jsonify({"ok": True, "paused_tools": paused})


@console_bp.route("/api/resume_tool", methods=["POST"])
def api_resume_tool():
    """Resume a paused tool (re-launch with --resume)."""
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    tool_id = data.get("tool_id")
    if not project_id or not tool_id:
        return jsonify({"error": "project_id and tool_id required"}), 400
    pm = _pm()
    if not pm:
        return jsonify({"error": "Process manager not available"}), 503
    from models.project import get_project
    from models.settings import load_settings
    project = get_project(project_id)
    if not project:
        return jsonify({"error": "project not found"}), 404
    scope = data.get("scope")
    settings = load_settings(project.get("project_dir", ""),
                             tool_id, scope=scope)
    from routes.settings import _backfill_from_project
    _backfill_from_project(settings, project, tool_id)
    ok = pm.launch(project_id, tool_id,
                   project=project, settings=settings,
                   resume=True, scope=scope,
                   sudo_password=data.get("sudo_password"))
    return jsonify({"ok": ok})


@console_bp.route("/api/resume_all", methods=["POST"])
def api_resume_all():
    """Resume all paused tools in a project."""
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    if not project_id:
        return jsonify({"error": "project_id required"}), 400
    pm = _pm()
    if not pm:
        return jsonify({"error": "Process manager not available"}), 503
    from models.project import get_project
    project = get_project(project_id)
    if not project:
        return jsonify({"error": "project not found"}), 404
    resumed = pm.resume_all(project_id, project=project,
                            sudo_password=data.get("sudo_password"))
    qm = get_ext("queue_manager")
    if qm:
        qm.resume_project(project_id)
    return jsonify({"ok": True, "resumed_tools": resumed})


# ── schedule routes ──────────────────────────────────────────────────────

def _sched():
    return get_ext("scheduler")


@console_bp.route("/api/schedule_engagement", methods=["POST"])
def api_schedule_engagement():
    """Schedule the engagement to auto-start at a future date/time.

    At the scheduled time, all enabled tools launch through the
    QueueManager, respecting parallelism rules.
    """
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    scheduled_at = data.get("scheduled_at")
    if not project_id or not scheduled_at:
        return jsonify({"error": "project_id and scheduled_at required"}), 400
    sched = _sched()
    if not sched:
        return jsonify({"error": "Scheduler not available"}), 503
    entry = sched.schedule_engagement_start(
        project_id, scheduled_at,
        sudo_password=data.get("sudo_password"),
    )
    return jsonify({"ok": True, "schedule": entry})


@console_bp.route("/api/scheduled_starts/<project_id>")
def api_get_scheduled_starts(project_id):
    """Get all scheduled engagement starts for a project."""
    sched = _sched()
    if not sched:
        return jsonify({"schedules": []})
    return jsonify({"schedules": sched.get_scheduled_starts(project_id)})


@console_bp.route("/api/remove_scheduled_start", methods=["POST"])
def api_remove_scheduled_start():
    """Remove a scheduled engagement start."""
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    sched_id = data.get("sched_id")
    if not project_id or not sched_id:
        return jsonify({"error": "project_id and sched_id required"}), 400
    sched = _sched()
    if not sched:
        return jsonify({"error": "Scheduler not available"}), 503
    removed = sched.remove_scheduled_start(project_id, sched_id)
    return jsonify({"ok": removed})


# ── engagement hours routes ──────────────────────────────────────────────

@console_bp.route("/api/engagement_hours/<project_id>")
def api_get_engagement_hours(project_id):
    """Get engagement hours config for a project."""
    sched = _sched()
    if not sched:
        return jsonify({})
    return jsonify(sched.get_engagement_hours(project_id))


@console_bp.route("/api/engagement_hours", methods=["POST"])
def api_set_engagement_hours():
    """Set engagement hours for a project."""
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    if not project_id:
        return jsonify({"error": "project_id required"}), 400
    sched = _sched()
    if not sched:
        return jsonify({"error": "Scheduler not available"}), 503
    config = {
        "enabled": data.get("enabled", True),
        "start_time": data.get("start_time", "08:00"),
        "end_time": data.get("end_time", "18:00"),
        "timezone": data.get("timezone", "US/Central"),
        "days": data.get("days", [0, 1, 2, 3, 4]),
    }
    sched.set_engagement_hours(project_id, config)
    return jsonify({"ok": True, "config": config})


@console_bp.route("/api/engagement_hours/clear", methods=["POST"])
def api_clear_engagement_hours():
    """Clear engagement hours for a project."""
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    if not project_id:
        return jsonify({"error": "project_id required"}), 400
    sched = _sched()
    if not sched:
        return jsonify({"error": "Scheduler not available"}), 503
    sched.clear_engagement_hours(project_id)
    return jsonify({"ok": True})
