"""BeaconClient — push engagement status to a Beacon server.

Runs a daemon timer that builds a snapshot from the current project state
and POSTs it every 60 seconds.  Best-effort: push failures are logged but
never crash Crucible.
"""
from __future__ import annotations

import json
import logging
import threading
from datetime import datetime

import requests
import urllib3

from models.project import get_project
from models.findings import get_risk_summary

log = logging.getLogger("crucible.beacon_client")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_PUSH_INTERVAL = 60
_clients: dict[str, "BeaconClient"] = {}
_clients_lock = threading.Lock()


class BeaconClient:

    def __init__(self, project_id: str, beacon_url: str,
                 process_manager, queue_manager, findings_engine):
        self.project_id = project_id
        self.url = beacon_url.rstrip("/")
        self.pm = process_manager
        self.qm = queue_manager
        self.fe = findings_engine
        self._timer: threading.Timer | None = None
        self._running = False

    def start(self):
        self._running = True
        log.info("beacon: starting push to %s for project %s",
                 self.url, self.project_id[:8])
        self._push()

    def stop(self):
        self._running = False
        if self._timer:
            self._timer.cancel()
            self._timer = None
        log.info("beacon: stopped push for project %s", self.project_id[:8])

    def _schedule_next(self):
        if not self._running:
            return
        self._timer = threading.Timer(_PUSH_INTERVAL, self._push)
        self._timer.daemon = True
        self._timer.start()

    def _push(self):
        if not self._running:
            return
        try:
            snapshot = self._build_snapshot()
            if snapshot:
                requests.post(
                    f"{self.url}/api/status",
                    json=snapshot,
                    headers={"Authorization": f"Bearer {self.project_id}"},
                    verify=False,
                    timeout=10,
                )
        except Exception as exc:
            log.debug("beacon push failed for %s: %s", self.project_id[:8], exc)
        self._schedule_next()

    def _build_snapshot(self) -> dict | None:
        project = get_project(self.project_id)
        if not project:
            return None

        tool_statuses = self.pm.get_all_status(self.project_id)
        tools = {}
        for tid, info in tool_statuses.items():
            if info.get("resolved_key"):
                continue
            tools[tid] = {
                "status": info.get("status", "idle"),
                "started_at": info.get("started_at"),
                "ended_at": info.get("ended_at"),
                "returncode": info.get("returncode"),
                "tool_version": info.get("tool_version", ""),
                "scope": info.get("scope", ""),
            }

        queue = []
        for entry in self.qm.get_queue(self.project_id):
            queue.append({
                "tool_id": entry.get("tool_id", ""),
                "queued_at": entry.get("queued_at", ""),
                "priority": entry.get("priority", 0),
                "scope": entry.get("scope", ""),
            })

        findings_list = self.fe.get_findings(self.project_id, project)
        risk_summary = get_risk_summary(findings_list)
        total = sum(risk_summary.values())

        return {
            "engagement_id": self.project_id,
            "name": project.get("name", ""),
            "client_name": project.get("client_name", ""),
            "start_date": project.get("start_date", ""),
            "end_date": project.get("end_date", ""),
            "scopes": project.get("active_scopes", []),
            "tools": tools,
            "queue": queue,
            "findings": risk_summary,
            "total_findings": total,
            "timestamp": datetime.now().isoformat(),
        }


def start_beacon(project_id: str, app) -> bool:
    project = get_project(project_id)
    if not project:
        return False
    url = project.get("beacon_url", "")
    enabled = project.get("beacon_enabled", False)
    if not url or not enabled:
        return False

    pm = app.extensions.get("process_manager")
    qm = app.extensions.get("queue_manager")
    fe = app.extensions.get("findings_engine")
    if not pm or not qm or not fe:
        return False

    with _clients_lock:
        existing = _clients.get(project_id)
        if existing:
            existing.stop()
        client = BeaconClient(project_id, url, pm, qm, fe)
        _clients[project_id] = client
        client.start()
    return True


def stop_beacon(project_id: str):
    with _clients_lock:
        client = _clients.pop(project_id, None)
    if client:
        client.stop()


def is_beacon_active(project_id: str) -> bool:
    with _clients_lock:
        client = _clients.get(project_id)
        return client is not None and client._running
