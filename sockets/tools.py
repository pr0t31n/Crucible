"""SocketIO tool control events — start, kill, input."""

import logging
import traceback

from flask_socketio import emit

from models.project import get_project
from services.utils import project_room as _room
from sockets._helpers import socket_auth_check, socket_validate_ids

log = logging.getLogger(__name__)


def register_tool_events(socketio, process_manager, queue_manager):

    @socketio.on("tool_start")
    def on_tool_start(data):
        if not socket_auth_check():
            return
        pid, tid, proj = socket_validate_ids(data, check_tool_enabled=True)
        if not pid:
            return

        try:
            settings = data.get("settings")
            resume = data.get("resume", False)
            sudo_password = data.get("sudo_password")
            scope = data.get("scope")

            from models.settings import load_settings
            proj_dir = proj.get("project_dir", "")
            if not settings and proj_dir:
                settings = load_settings(proj_dir, tid, scope=scope)
                from routes.settings import _backfill_from_project
                _backfill_from_project(settings, proj, tid)

            # Multi-file expansion: Quill with multiple app_files queues
            # one run per file through the queue manager.
            if tid == "quill" and not resume:
                from adapters import get_adapter
                adapter = get_adapter("quill")
                if adapter and hasattr(adapter, "expand_queue_entries"):
                    entries = adapter.expand_queue_entries(settings or {})
                    if entries:
                        for entry in entries:
                            queue_manager.enqueue(
                                pid, tid, scope=entry.get("scope"),
                                extra_args=entry.get("extra_args"),
                                sudo_password=sudo_password)
                        log.info("Expanded %s into %d file-scoped queue entries "
                                 "for project %s", tid, len(entries), pid)
                        emit("tool_queued", {
                            "project_id": pid, "tool_id": tid,
                            "reason": f"Queued {len(entries)} app files"},
                            to=_room(pid))
                        queue_manager.auto_dequeue(pid)
                        return

            can, reason = queue_manager.can_launch(pid, tid)
            if can:
                ok = process_manager.launch(
                    pid, tid,
                    project=proj,
                    settings=settings or {},
                    resume=resume,
                    sudo_password=sudo_password,
                    scope=scope,
                )
                if ok:
                    log.info("Launched %s for project %s", tid, pid)
                    emit("tool_started", {"project_id": pid, "tool_id": tid},
                         to=_room(pid))
                else:
                    emit("error", {"project_id": pid, "tool_id": tid,
                                   "message": "Already running or launch failed"})
            else:
                queue_manager.enqueue(pid, tid, scope=scope, settings=settings,
                                     resume=resume, sudo_password=sudo_password)
                log.info("Queued %s for project %s: %s", tid, pid, reason)
                emit("tool_queued", {"project_id": pid, "tool_id": tid,
                                     "reason": reason},
                     to=_room(pid))
        except Exception as exc:
            log.error("on_tool_start crashed: %s\n%s", exc, traceback.format_exc())
            emit("error", {"project_id": pid, "tool_id": tid,
                           "message": f"Launch error: {exc}"})

    @socketio.on("tool_kill")
    def on_tool_kill(data):
        if not socket_auth_check():
            return
        pid, tid, proj = socket_validate_ids(data, check_tool_enabled=True)
        if not pid:
            return

        try:
            scope = (data or {}).get("scope")
            ok = process_manager.kill(pid, tid, scope=scope)
            if ok:
                log.info("Killed %s for project %s", tid, pid)
                emit("tool_killed", {"project_id": pid, "tool_id": tid},
                     to=_room(pid))
            else:
                emit("error", {"project_id": pid, "tool_id": tid,
                               "message": "Tool not running or kill failed"})
        except Exception as exc:
            log.error("on_tool_kill crashed: %s\n%s", exc, traceback.format_exc())
            emit("error", {"project_id": pid, "tool_id": tid,
                           "message": f"Kill error: {exc}"})

    @socketio.on("tool_pause")
    def on_tool_pause(data):
        if not socket_auth_check():
            return
        pid, tid, proj = socket_validate_ids(data, check_tool_enabled=True)
        if not pid:
            return

        try:
            scope = (data or {}).get("scope")
            reason = (data or {}).get("reason", "paused_user")
            ok = process_manager.pause(pid, tid, scope=scope, reason=reason)
            if ok:
                log.info("Pause requested for %s in project %s", tid, pid)
            else:
                emit("error", {"project_id": pid, "tool_id": tid,
                               "message": "Tool not running or pause failed"})
        except Exception as exc:
            log.error("on_tool_pause crashed: %s\n%s", exc, traceback.format_exc())
            emit("error", {"project_id": pid, "tool_id": tid,
                           "message": f"Pause error: {exc}"})

    @socketio.on("tool_input")
    def on_tool_input(data):
        if not socket_auth_check():
            return
        pid, tid, proj = socket_validate_ids(data, check_tool_enabled=True)
        if not pid:
            return

        try:
            text = (data or {}).get("text", "")
            process_manager.send_input(pid, tid, text)
        except Exception as exc:
            log.error("on_tool_input crashed: %s\n%s", exc, traceback.format_exc())
            emit("error", {"project_id": pid, "tool_id": tid,
                           "message": f"Input error: {exc}"})

    @socketio.on("get_console")
    def on_get_console(data):
        if not socket_auth_check():
            return
        pid, tid, proj = socket_validate_ids(data, check_tool_enabled=True)
        if not pid:
            return

        try:
            scope = (data or {}).get("scope")
            base_tid = tid
            if ":" in tid and not scope:
                base_tid = tid.split(":")[0]
                scope = tid.split(":", 1)[1]

            if process_manager.is_running(pid, base_tid, scope=scope):
                buf = process_manager.get_console(pid, base_tid, scope=scope)
            else:
                from routes.console import _load_full_console
                buf = _load_full_console(pid, base_tid, scope=scope)
                if not buf:
                    buf = process_manager.get_console(pid, base_tid, scope=scope)
            tail = (data or {}).get("tail")
            if tail and isinstance(tail, int) and tail > 0 and len(buf) > tail:
                buf = buf[-tail:]
            emit("console_buffer", {"project_id": pid, "tool_id": tid,
                                    "lines": buf})
        except Exception as exc:
            log.error("on_get_console crashed: %s\n%s", exc, traceback.format_exc())
            emit("error", {"project_id": pid, "tool_id": tid,
                           "message": f"Console error: {exc}"})

    @socketio.on("get_status")
    def on_get_status(data):
        if not socket_auth_check():
            return
        pid = (data or {}).get("project_id")
        if not pid:
            emit("error", {"message": "Missing project_id"})
            return
        proj = get_project(pid)
        if not proj:
            emit("error", {"message": f"Project not found: {pid}"})
            return

        try:
            statuses = process_manager.get_all_status(pid)
            if "nessus" not in statuses:
                td = (proj.get("tool_dirs") or {}).get("nessus")
                if td:
                    from pathlib import Path
                    nd = Path(td)
                    if (nd / "nessus_findings.json").exists() or \
                       (nd / "nessus_results.nessus").exists():
                        statuses["nessus"] = {"status": "complete",
                                              "last_line": "Nessus results imported"}
            phase_cache = process_manager.get_phase_cache(pid)
            emit("all_status", {"project_id": pid, "tools": statuses,
                                "phases": phase_cache})
        except Exception as exc:
            log.error("on_get_status crashed: %s\n%s", exc, traceback.format_exc())
            emit("error", {"project_id": pid,
                           "message": f"Status error: {exc}"})
