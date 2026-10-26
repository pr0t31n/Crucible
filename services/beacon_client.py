"""BeaconClient — push engagement status to a Beacon server.

Activity-driven: the push loop runs only while tools are active (running,
queued, or paused).  After the last tool reaches a terminal state and the
queue drains, pushes continue for a 5-minute cooldown window then stop.
Any new tool launch wakes the client back up.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime

import requests
import urllib3

from models.project import get_project
from models.findings import get_risk_summary

log = logging.getLogger("crucible.beacon_client")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_PUSH_INTERVAL = 60
_COOLDOWN = 300
_clients: dict[str, "BeaconClient"] = {}
_clients_lock = threading.Lock()

_TERMINAL_STATES = frozenset(("complete", "failed", "error", "killed"))
_ACTIVE_STATES = frozenset(("running", "paused"))


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
        self._registered = False
        self._idle_since: float | None = None

    def start(self):
        """Register the client.  Starts pushing only if tools are already active."""
        self._registered = True
        log.info("beacon: registered for %s → %s", self.project_id[:8], self.url)
        if self._has_activity():
            self._wake()

    def stop(self):
        """Full shutdown — unregister and stop push loop."""
        self._registered = False
        self._running = False
        if self._timer:
            self._timer.cancel()
            self._timer = None
        log.info("beacon: stopped for %s", self.project_id[:8])

    def notify_activity(self):
        """Wake the push loop when a tool launches, queues, or resumes."""
        if not self._registered:
            return
        self._idle_since = None
        if not self._running:
            self._wake()

    def _wake(self):
        self._idle_since = None
        if self._running:
            return
        self._running = True
        log.info("beacon: push loop active for %s", self.project_id[:8])
        self._push()

    def _go_dormant(self):
        self._running = False
        if self._timer:
            self._timer.cancel()
            self._timer = None
        log.info("beacon: dormant for %s (cooldown elapsed)", self.project_id[:8])

    def _schedule_next(self):
        if not self._running:
            return
        self._timer = threading.Timer(_PUSH_INTERVAL, self._push)
        self._timer.daemon = True
        self._timer.start()

    def _has_activity(self) -> bool:
        try:
            statuses = self.pm.get_all_status(self.project_id)
            for info in statuses.values():
                if info.get("resolved_key"):
                    continue
                if info.get("status", "idle") in _ACTIVE_STATES:
                    return True
            if self.qm.get_queue(self.project_id):
                return True
        except Exception:
            pass
        return False

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

        if self._check_idle():
            return
        self._schedule_next()

    def _check_idle(self) -> bool:
        """Returns True if the client just went dormant."""
        if self._has_activity():
            self._idle_since = None
            return False

        now = time.monotonic()
        if self._idle_since is None:
            self._idle_since = now
            return False

        if now - self._idle_since >= _COOLDOWN:
            self._go_dormant()
            return True
        return False

    def _build_snapshot(self) -> dict | None:
        project = get_project(self.project_id)
        if not project:
            return None

        tool_statuses = self.pm.get_all_status(self.project_id)
        tools = {}
        started_times = []
        ended_times = []
        all_terminal = True
        any_started = False

        for tid, info in tool_statuses.items():
            if info.get("resolved_key"):
                continue
            status = info.get("status", "idle")
            tools[tid] = {
                "status": status,
                "started_at": info.get("started_at"),
                "ended_at": info.get("ended_at") if status in _TERMINAL_STATES else None,
                "returncode": info.get("returncode"),
                "tool_version": info.get("tool_version", ""),
                "scope": info.get("scope", ""),
            }
            sa = info.get("started_at")
            ea = info.get("ended_at")
            if sa:
                any_started = True
                started_times.append(sa)
            if ea:
                ended_times.append(ea)
            if status != "idle" and status not in _TERMINAL_STATES:
                all_terminal = False

        queue = []
        for entry in self.qm.get_queue(self.project_id):
            queue.append({
                "tool_id": entry.get("tool_id", ""),
                "queued_at": entry.get("queued_at", ""),
                "priority": entry.get("priority", 0),
                "scope": entry.get("scope", ""),
            })

        start_date = min(started_times) if started_times else ""
        if any_started and all_terminal and not queue and ended_times:
            end_date = max(ended_times)
        else:
            end_date = ""

        findings_list = self.fe.get_findings(self.project_id, project)
        risk_summary = get_risk_summary(findings_list)
        total = sum(risk_summary.values())

        return {
            "engagement_id": self.project_id,
            "name": project.get("name", ""),
            "client_name": project.get("client_name", ""),
            "start_date": start_date,
            "end_date": end_date,
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


def notify_beacon_activity(project_id: str):
    """Wake the beacon push loop when a tool starts, queues, or resumes."""
    with _clients_lock:
        client = _clients.get(project_id)
    if client:
        client.notify_activity()


def is_beacon_active(project_id: str) -> bool:
    with _clients_lock:
        client = _clients.get(project_id)
        return client is not None and client._running
