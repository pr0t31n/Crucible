"""SocketIO import events — job listing, console streaming, cancellation."""

import logging

from flask_socketio import emit

from models.project import get_project
from services.utils import project_room as _room
from sockets._helpers import socket_auth_check

log = logging.getLogger(__name__)


def register_importer_events(socketio, importer_service):

    @socketio.on("import_get_jobs")
    def _on_get_jobs(data):
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

        jobs = importer_service.get_jobs(pid)
        emit("import_jobs", {"project_id": pid, "jobs": jobs})

    @socketio.on("import_get_console")
    def _on_get_console(data):
        if not socket_auth_check():
            return
        pid = (data or {}).get("project_id")
        job_id = (data or {}).get("job_id")
        if not pid or not job_id:
            emit("error", {"message": "Missing project_id or job_id"})
            return

        lines = importer_service.get_console(job_id)
        emit("import_console_buffer",
             {"project_id": pid, "job_id": job_id, "lines": lines})

    @socketio.on("import_cancel")
    def _on_cancel(data):
        if not socket_auth_check():
            return
        pid = (data or {}).get("project_id")
        job_id = (data or {}).get("job_id")
        if not pid or not job_id:
            emit("error", {"message": "Missing project_id or job_id"})
            return

        ok, msg = importer_service.cancel_job(job_id)
        if ok:
            job = importer_service.get_job(job_id)
            emit("import_job_updated",
                 {"project_id": pid, "job": job}, to=_room(pid))
        else:
            emit("error", {"message": msg})
