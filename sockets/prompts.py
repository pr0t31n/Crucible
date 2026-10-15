"""SocketIO prompt handling — answer tool prompts, provide sudo passwords."""

import logging

from flask_socketio import emit

from services.utils import project_room as _room
from sockets._helpers import socket_auth_check, socket_validate_ids

log = logging.getLogger(__name__)


def register_prompt_events(socketio, process_manager):

    @socketio.on("prompt_answer")
    def on_prompt_answer(data):
        if not socket_auth_check():
            return
        pid, tid, _ = socket_validate_ids(data)
        if not pid:
            return

        answer = (data or {}).get("answer", "")
        process_manager.answer_prompt(pid, tid, answer)
        log.info("Prompt answered for %s/%s", tid, pid)
        emit("prompt_answered", {"project_id": pid, "tool_id": tid},
             to=_room(pid))

    @socketio.on("sudo_password")
    def on_sudo_password(data):
        if not socket_auth_check():
            return
        pid, tid, _ = socket_validate_ids(data)
        if not pid:
            return

        password = (data or {}).get("password", "")
        if not password:
            emit("error", {"project_id": pid, "tool_id": tid,
                           "message": "Empty password"})
            return

        process_manager.send_input(pid, tid, password)
        log.info("Sudo password provided for %s/%s", tid, pid)
        emit("sudo_accepted", {"project_id": pid, "tool_id": tid})
