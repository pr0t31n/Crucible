"""Worker delegation — remote Crucible instance management.

Manages connections to remote Crucible instances for delegated tool runs.
The remote instance runs the tool subprocess locally and streams output
back via WebSocket.
"""

import json
import logging
import threading
import time
from datetime import datetime

from config import PORT
from services.utils import project_room as _room

log = logging.getLogger("crucible.worker")

RECONNECT_INTERVAL = 10
RECONNECT_MAX_ATTEMPTS = 30  # 5 minutes


class WorkerDelegate:
    """Manages connections to remote Crucible instances for delegated work."""

    def __init__(self, socketio=None, process_manager=None, findings_engine=None):
        self._socketio = socketio
        self._pm = process_manager
        self._fe = findings_engine
        self._workers = {}
        self._delegations = {}
        self._ws_connections = {}
        self._lock = threading.Lock()

    def register_worker(self, name, url, port=PORT, credentials=None):
        """Register a remote Crucible instance as a worker."""
        with self._lock:
            self._workers[name] = {
                "name": name,
                "url": url,
                "port": port,
                "credentials": credentials or {},
                "registered": datetime.now().isoformat(),
                "status": "registered",
                "delegations": [],
            }
        log.info("Worker registered: %s at %s:%d", name, url, port)
        return True

    def remove_worker(self, name):
        """Unregister a worker."""
        with self._lock:
            if name in self._workers:
                del self._workers[name]
                if name in self._ws_connections:
                    del self._ws_connections[name]
                return True
        return False

    def get_worker(self, name):
        with self._lock:
            return self._workers.get(name)

    def list_workers(self):
        with self._lock:
            return list(self._workers.values())

    def test_worker(self, name):
        """Test connectivity to a registered worker. Returns (ok, message)."""
        worker = self.get_worker(name)
        if not worker:
            return False, "Worker not registered"

        import requests
        url = f"https://{worker['url']}:{worker['port']}/api/nexus-status"
        try:
            r = requests.get(url, verify=False, timeout=10)
            if r.status_code == 200:
                data = r.json()
                with self._lock:
                    self._workers[name]["status"] = "online"
                return True, f"Worker online: {data.get('app', 'Crucible')}"
            return False, f"HTTP {r.status_code}"
        except Exception as e:
            with self._lock:
                self._workers[name]["status"] = "offline"
            return False, str(e)

    def delegate_tool(self, project_id, tool_id, worker_name, settings,
                      project_meta=None, scope=None):
        """Delegate a tool run to a remote worker. Returns delegation_id."""
        import uuid
        worker = self.get_worker(worker_name)
        if not worker:
            raise ValueError(f"Worker '{worker_name}' not registered")

        delegation_id = str(uuid.uuid4())[:12]

        payload = {
            "delegation_id": delegation_id,
            "project_meta": project_meta or {},
            "tool_id": tool_id,
            "settings": settings,
            "scope": scope or {},
        }

        import requests
        url = f"https://{worker['url']}:{worker['port']}/api/worker/accept"
        try:
            r = requests.post(url, json=payload, verify=False, timeout=15)
            if r.status_code != 200:
                raise RuntimeError(f"Worker rejected: {r.text[:200]}")
            result = r.json()
            if not result.get("accepted"):
                raise RuntimeError(f"Worker declined: {result.get('reason', 'unknown')}")
        except Exception as e:
            raise RuntimeError(f"Delegation failed: {e}")

        with self._lock:
            self._delegations[delegation_id] = {
                "id": delegation_id,
                "project_id": project_id,
                "tool_id": tool_id,
                "worker": worker_name,
                "status": "accepted",
                "started": datetime.now().isoformat(),
                "last_event": None,
            }
            self._workers[worker_name].setdefault("delegations", []).append(delegation_id)

        threading.Thread(
            target=self._ws_connect, args=(worker_name, delegation_id),
            daemon=True,
        ).start()

        log.info("Delegated %s/%s to worker %s (id=%s)",
                 project_id, tool_id, worker_name, delegation_id)
        return delegation_id

    def recall_delegation(self, delegation_id):
        """Cancel a delegation and kill the remote tool."""
        with self._lock:
            delegation = self._delegations.get(delegation_id)
            if not delegation:
                return False

        worker_name = delegation["worker"]
        worker = self.get_worker(worker_name)
        if not worker:
            return False

        import requests
        url = f"https://{worker['url']}:{worker['port']}/api/worker/recall"
        try:
            requests.post(url, json={"delegation_id": delegation_id},
                         verify=False, timeout=10)
        except Exception:
            pass

        with self._lock:
            delegation["status"] = "recalled"

        return True

    def get_delegation(self, delegation_id):
        with self._lock:
            return self._delegations.get(delegation_id)

    def list_delegations(self, worker_name=None):
        with self._lock:
            if worker_name:
                return [d for d in self._delegations.values()
                        if d["worker"] == worker_name]
            return list(self._delegations.values())

    def _ws_connect(self, worker_name, delegation_id):
        """Open persistent WebSocket to remote worker (runs in thread)."""
        worker = self.get_worker(worker_name)
        if not worker:
            return

        try:
            import socketio as sio_client
        except ImportError:
            log.error("python-socketio[client] not installed")
            return

        ws = sio_client.Client(ssl_verify=False)
        attempts = 0

        @ws.on("console_line")
        def on_console(data):
            self._ws_on_console(delegation_id, data)

        @ws.on("finding")
        def on_finding(data):
            self._ws_on_finding(delegation_id, data)

        @ws.on("tool_status")
        def on_status(data):
            self._ws_on_status(delegation_id, data)

        @ws.on("log_entry")
        def on_log(data):
            self._ws_on_log(delegation_id, data)

        @ws.on("err_entry")
        def on_err(data):
            self._ws_on_log(delegation_id, data)

        url = f"https://{worker['url']}:{worker['port']}"

        while attempts < RECONNECT_MAX_ATTEMPTS:
            try:
                ws.connect(url, transports=["websocket"])
                ws.emit("join_delegation", {"delegation_id": delegation_id})

                with self._lock:
                    self._ws_connections[worker_name] = ws
                    self._delegations[delegation_id]["status"] = "connected"

                ws.wait()
                break
            except Exception as e:
                attempts += 1
                with self._lock:
                    if delegation_id in self._delegations:
                        self._delegations[delegation_id]["status"] = "reconnecting"
                log.warning("WS connect failed to %s (attempt %d): %s",
                            worker_name, attempts, e)
                time.sleep(RECONNECT_INTERVAL)

        with self._lock:
            if delegation_id in self._delegations:
                d = self._delegations[delegation_id]
                if d["status"] == "reconnecting":
                    d["status"] = "lost"
                    log.error("Delegation %s lost after %d reconnect attempts",
                              delegation_id, attempts)

    def _ws_on_console(self, delegation_id, data):
        with self._lock:
            d = self._delegations.get(delegation_id)
        if not d:
            return
        data["source"] = f"worker:{d['worker']}"
        if self._pm:
            self._pm.inject_console_line(d["project_id"], d["tool_id"], data)
        if self._socketio:
            self._socketio.emit("console_line", data,
                                room=_room(d['project_id']))

    def _ws_on_finding(self, delegation_id, data):
        with self._lock:
            d = self._delegations.get(delegation_id)
        if not d:
            return
        finding = data.get("finding", data)
        finding["source"] = f"worker:{d['worker']}"
        if self._fe:
            self._fe.add_live_finding(d["project_id"], finding)
        if self._socketio:
            self._socketio.emit("finding", {"tool_id": d["tool_id"], "finding": finding},
                                room=_room(d['project_id']))

    def _ws_on_status(self, delegation_id, data):
        with self._lock:
            d = self._delegations.get(delegation_id)
        if not d:
            return
        status = data.get("status", "unknown")
        if status in ("complete", "exited", "killed"):
            d["status"] = "complete"
        if self._socketio:
            self._socketio.emit("tool_status", {
                "tool_id": d["tool_id"], "status": status,
                "source": f"worker:{d['worker']}",
            }, room=_room(d['project_id']))

    def _ws_on_log(self, delegation_id, data):
        with self._lock:
            d = self._delegations.get(delegation_id)
        if not d:
            return
        data["source"] = f"worker:{d['worker']}"
        if self._socketio:
            self._socketio.emit("log_entry", data,
                                room=_room(d['project_id']))
