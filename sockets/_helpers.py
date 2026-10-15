"""Shared helpers for SocketIO event modules."""

from flask import session
from flask_socketio import emit

from config import TOOLS
from models.project import get_project


def socket_auth_check():
    if session.get("authenticated"):
        return True
    emit("error", {"message": "Not authenticated"})
    return False


def socket_validate_ids(data, *, check_tool_enabled=False):
    pid = (data or {}).get("project_id")
    tid = (data or {}).get("tool_id")
    if not pid or not tid:
        emit("error", {"message": "Missing project_id or tool_id"})
        return None, None, None
    base_tid = tid.split(":")[0] if ":" in tid else tid
    if base_tid not in TOOLS:
        emit("error", {"message": f"Unknown tool: {tid}"})
        return None, None, None
    proj = get_project(pid)
    if not proj:
        emit("error", {"message": f"Project not found: {pid}"})
        return None, None, None
    if check_tool_enabled and base_tid not in proj.get("tools", []):
        emit("error", {"message": f"Tool {tid} not enabled for this project"})
        return None, None, None
    return pid, tid, proj
