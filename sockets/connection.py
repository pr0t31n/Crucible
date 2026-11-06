"""SocketIO connection events — connect, disconnect, join/leave project rooms."""

import logging

from flask import session, request
from flask_socketio import join_room, leave_room, emit

from services.utils import project_room as _room

_log = logging.getLogger(__name__)

_sid_to_project = {}


def register_connection_events(socketio):

    @socketio.on("connect")
    def on_connect():
        if session.get("authenticated"):
            return
        tok = session.get("session_token")
        if tok:
            try:
                import _auth
                if _auth._validate_session_token(tok):
                    session["authenticated"] = True
                    return
            except Exception:
                _log.debug("on_connect token fallback failed", exc_info=True)
        return False

    @socketio.on("disconnect")
    def on_disconnect():
        sid = request.sid
        pid = _sid_to_project.pop(sid, None)
        if pid:
            leave_room(_room(pid))

    @socketio.on("join_project")
    def on_join_project(data):
        pid = data.get("project_id")
        if not pid:
            return
        sid = request.sid
        old = _sid_to_project.get(sid)
        if old and old != pid:
            leave_room(_room(old))
        _sid_to_project[sid] = pid
        join_room(_room(pid))
        emit("joined", {"project_id": pid})

    @socketio.on("leave_project")
    def on_leave_project(data):
        pid = data.get("project_id")
        if not pid:
            return
        sid = request.sid
        if _sid_to_project.get(sid) == pid:
            del _sid_to_project[sid]
        leave_room(_room(pid))
