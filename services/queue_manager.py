"""Crucible v2.0 — job queue manager with parallelism enforcement.

Manages the execution queue for tool jobs.  Enforces cross-tool
parallelism rules so that incompatible tools never run simultaneously:

  exclusive  {ss3, fracture, siphon, forge, aether×4}  — one at a time
  osift      special: can run alongside SS3 only
  any        {trawler, auger, quill, isotope, …}       — always parallel

Thread-safe via a reentrant lock.  Queue is persisted to disk
(execute_queue.json) so it survives crashes.
"""

import json
import logging
import threading
from pathlib import Path

from config import PARALLEL_GROUPS, OSIFT_COMPAT, EXECUTE_QUEUE_FILE, AUTO_QUEUE_TOOLS
from services.utils import now_iso as _now_iso

log = logging.getLogger("crucible.queue")

_DEQUEUE_RETRY_SECONDS = 30


class QueueManager:
    """Per-project job queue with parallelism enforcement.

    Parameters
    ----------
    process_manager : ProcessManager | None
        Optional reference to the process manager.  When provided the
        queue manager can inspect which tools are currently running
        to make scheduling decisions.  When ``None`` the queue still
        works but ``can_launch`` always returns ``True`` (standalone /
        unit-test mode).
    """

    def __init__(self, process_manager=None, app=None):
        self.process_manager = process_manager
        self._app = app
        self._queue: dict[str, list[dict]] = {}  # project_id → [entry …]
        self._sudo_passwords: dict[str, str] = {}
        self._retry_timers: dict[str, threading.Timer] = {}
        self._paused: dict[str, dict] = {}  # project_id → {reason, ts, …}
        self._launching: dict[str, set[str]] = {}  # project_id → {tool_id …}
        self._clearing: set[str] = set()  # projects currently being cleared
        self._lock = threading.Lock()
        self._load_persisted_queue()

    # ── public API ───────────────────────────────────────────────────────

    def can_launch(self, project_id: str, tool_id: str,
                   scope: str | None = None) -> tuple[bool, str]:
        """Check whether *tool_id* can start right now.

        Returns ``(can_launch, reason)`` where *reason* is ``""`` on
        success or a human-readable explanation on denial.

        Rules
        -----
        0. System RAM must be below 85 %.
        1. ``"any"`` group tools can always launch.
        2. ``"exclusive"`` tools are mutually exclusive — one at a time.
        3. ``osift`` can run alongside SS3 but no other exclusive tool.
        4. An exclusive tool is blocked by osift unless that tool is SS3.
        5. Same tool_id cannot run twice (regardless of scope).
        """
        try:
            import psutil
            mem = psutil.virtual_memory()
            if mem.percent > 85:
                return False, (f"System RAM at {mem.percent:.0f}% "
                               f"({mem.available // (1024*1024)} MB free) — "
                               f"waiting for running tools to free memory")
        except ImportError:
            pass

        group = self._get_group(tool_id)

        if group == "any":
            return True, ""

        running = self._get_running_tools(project_id)
        with self._lock:
            running |= self._launching.get(project_id, set())
        if not running:
            return True, ""

        if tool_id in running:
            return False, f"{tool_id} is already running (another scope instance)"

        _exclusive = PARALLEL_GROUPS.get("exclusive", set())

        if tool_id == "osift":
            blockers = running & _exclusive - OSIFT_COMPAT
            if blockers:
                names = ", ".join(sorted(blockers))
                return False, f"Waiting for exclusive tool(s): {names}"
            return True, ""

        if group == "exclusive":
            other_excl = running & _exclusive - {tool_id}
            if other_excl:
                names = ", ".join(sorted(other_excl))
                return False, f"Exclusive tool(s) already running: {names}"
            if "osift" in running and tool_id not in OSIFT_COMPAT:
                return False, "OSift is running (can only parallel with SS3)"
            return True, ""

        return True, ""

    def enqueue(self, project_id: str, tool_id: str, priority: int = 0,
                scope: str | None = None, **kwargs) -> int:
        """Add a job to the project queue.

        Parameters
        ----------
        project_id : str
            The project that owns this job.
        tool_id : str
            Tool identifier (e.g. ``"fracture"``).
        priority : int
            Lower number = higher priority.  Default ``0``.
        **kwargs
            Arbitrary payload forwarded to the executor when the job
            is dequeued (``project``, ``settings``, ``resume``, etc.).

        Returns
        -------
        int
            Queue position (1-based) after insertion.
        """
        sudo_pw = kwargs.pop("sudo_password", None)
        entry = {
            "tool_id": tool_id,
            "queued_at": _now_iso(),
            "priority": priority,
            "scope": scope,
            "kwargs": kwargs,
        }
        with self._lock:
            if sudo_pw:
                self._sudo_passwords[project_id] = sudo_pw
            q = self._queue.setdefault(project_id, [])
            if any(e["tool_id"] == tool_id and e.get("scope") == scope
                   for e in q):
                log.info("Skipping duplicate enqueue for %s scope=%s (project %s)",
                         tool_id, scope, project_id)
                return next(i + 1 for i, e in enumerate(q)
                            if e["tool_id"] == tool_id
                            and e.get("scope") == scope)
            q.append(entry)
            q.sort(key=lambda e: e["priority"])
            position = q.index(entry) + 1
            self._persist_queue()
        return position

    def dequeue_next(self, project_id: str):
        """Called when a tool finishes.  Returns the next eligible job.

        Walks the queue in priority order and returns the first entry
        whose tool can launch according to ``can_launch``.  Returns
        ``None`` when the project is paused.

        Returns
        -------
        tuple[str, str | None, dict] | None
            ``(tool_id, scope, kwargs)`` if a job is eligible, else ``None``.
        """
        with self._lock:
            if project_id in self._paused:
                return None
            q = self._queue.get(project_id, [])
            for entry in list(q):
                tid = entry["tool_id"]
                ok, _ = self.can_launch(project_id, tid,
                                        scope=entry.get("scope"))
                if ok:
                    q.remove(entry)
                    self._persist_queue()
                    kw = entry.get("kwargs", {})
                    sudo_pw = self._sudo_passwords.get(project_id)
                    if sudo_pw:
                        kw["sudo_password"] = sudo_pw
                    return tid, entry.get("scope"), kw
        return None

    def remove_from_queue(self, project_id: str, tool_id: str) -> bool:
        """Remove the first queued job for *tool_id* in *project_id*.

        Returns ``True`` if an entry was removed, ``False`` otherwise.
        """
        with self._lock:
            q = self._queue.get(project_id, [])
            for i, entry in enumerate(q):
                if entry["tool_id"] == tool_id:
                    q.pop(i)
                    self._persist_queue()
                    return True
        return False

    def get_queue(self, project_id: str) -> list[dict]:
        """Return a snapshot of the current queue for *project_id*."""
        with self._lock:
            return list(self._queue.get(project_id, []))

    def clear_queue(self, project_id: str) -> int:
        """Clear all queued jobs for *project_id*.

        Returns the number of entries removed.
        """
        with self._lock:
            self._clearing.add(project_id)
            q = self._queue.pop(project_id, [])
            count = len(q)
            self._launching.pop(project_id, None)
            self._sudo_passwords.pop(project_id, None)
            timer = self._retry_timers.pop(project_id, None)
            if timer:
                timer.cancel()
            if count:
                self._persist_queue()
            self._clearing.discard(project_id)
            return count

    def queue_size(self, project_id: str) -> int:
        """Return the number of queued entries for *project_id*."""
        with self._lock:
            return len(self._queue.get(project_id, []))

    def auto_dequeue(self, project_id: str) -> None:
        """Called when a tool finishes — launch all eligible queued jobs.

        If jobs remain but can't launch (RAM pressure, cross-group block),
        schedules a retry after ``_DEQUEUE_RETRY_SECONDS``.  Does nothing
        when the project is paused.
        """
        with self._lock:
            if project_id in self._paused or project_id in self._clearing:
                return
        pm = self.process_manager
        if not pm:
            return
        from models.project import get_project
        project = get_project(project_id)
        if not project:
            return
        launched_any = False
        while True:
            result = self.dequeue_next(project_id)
            if result is None:
                break
            tool_id, scope, kwargs = result
            with self._lock:
                self._launching.setdefault(project_id, set()).add(tool_id)
            try:
                from models.settings import load_settings
                proj_dir = project.get("project_dir", "")
                settings = kwargs.get("settings") or (
                    load_settings(proj_dir, tool_id, scope=scope) if proj_dir else {})
                ok = pm.launch(
                    project_id, tool_id,
                    project=project,
                    settings=settings,
                    resume=kwargs.get("resume", False),
                    sudo_password=kwargs.get("sudo_password"),
                    scope=scope,
                    extra_args=kwargs.get("extra_args"),
                )
                if ok:
                    launched_any = True
                else:
                    log.warning("Dropped queued %s:%s — launch failed "
                                "(validation or missing config)",
                                tool_id, scope or "")
                    self._emit_launch_failure(
                        pm, project_id, tool_id, scope, proj_dir,
                        "Launch failed (validation or missing config)")
            except Exception as exc:
                log.exception("auto_dequeue launch error for %s:%s",
                              tool_id, scope or "")
                self._emit_launch_failure(
                    pm, project_id, tool_id, scope,
                    project.get("project_dir", ""),
                    f"Launch error: {exc}")
            finally:
                with self._lock:
                    s = self._launching.get(project_id)
                    if s:
                        s.discard(tool_id)
                        if not s:
                            self._launching.pop(project_id, None)

        if not launched_any and self.queue_size(project_id) > 0:
            self._schedule_dequeue_retry(project_id)

    def _emit_launch_failure(self, pm, project_id, tool_id, scope,
                             proj_dir, reason):
        """Emit a console error and revert action items on auto-dequeue
        launch failure so the user sees what happened."""
        from config import TOOLS
        name = TOOLS.get(tool_id, {}).get("name", tool_id)
        scope_tag = f" [{scope}]" if scope else ""
        msg = f"[Crucible] Auto-dequeue: {name}{scope_tag} — {reason}"
        if pm:
            pm._emit_console(project_id, tool_id, msg, "system")
            try:
                pm.socketio.emit("tool_status", {
                    "project_id": project_id,
                    "tool_id": tool_id,
                    "status": "failed",
                }, room=f"project_{project_id}")
            except Exception:
                pass
        if proj_dir:
            try:
                from models.action_items import update_tool_action_items_status
                update_tool_action_items_status(
                    proj_dir, tool_id,
                    from_statuses={"queued"},
                    new_status="pending")
            except Exception as exc:
                log.warning("Failed to revert action items for %s: %s",
                            tool_id, exc)

    def _schedule_dequeue_retry(self, project_id: str) -> None:
        """Schedule a deferred retry for queued jobs that couldn't launch."""
        old = self._retry_timers.pop(project_id, None)
        if old:
            old.cancel()
        t = threading.Timer(_DEQUEUE_RETRY_SECONDS,
                            self._dequeue_retry_cb, args=(project_id,))
        t.daemon = True
        t.name = f"dequeue-retry-{project_id[:8]}"
        self._retry_timers[project_id] = t
        t.start()
        log.info("Dequeue retry scheduled in %ds for %s",
                 _DEQUEUE_RETRY_SECONDS, project_id)

    def _dequeue_retry_cb(self, project_id: str) -> None:
        """Timer callback — attempt to launch queued jobs."""
        self._retry_timers.pop(project_id, None)
        if project_id in self._clearing:
            return
        if self.queue_size(project_id) == 0:
            return
        log.info("Dequeue retry firing for %s", project_id)
        if self._app:
            with self._app.app_context():
                self.auto_dequeue(project_id)
        else:
            self.auto_dequeue(project_id)

    def _nessus_is_configured(self, project):
        """Return True if Nessus API credentials exist in project settings."""
        proj_dir = project.get("project_dir", "")
        settings_path = Path(proj_dir) / "nessus_settings.json" if proj_dir else None
        if not settings_path or not settings_path.exists():
            return False
        try:
            import json
            cfg = json.loads(settings_path.read_text())
            return bool(cfg.get("access_key") and cfg.get("secret_key")
                        and (cfg.get("host") or cfg.get("server")))
        except (json.JSONDecodeError, OSError):
            return False

    def process_auto_queue(self, project_id: str, project: dict) -> int:
        """Examine pending action items and enqueue eligible tools.

        Groups in-scope items by recommended tool and launches one job
        per tool with all targets combined (matching the bulk-launch UI
        behaviour).  Picks up ``auto``-tier items unconditionally and
        ``confirm``-tier items when the tool is in AUTO_QUEUE_TOOLS.

        Returns the number of jobs enqueued.
        """
        if not project.get("auto_queue"):
            return 0
        if project_id in self._clearing:
            return 0

        pm = self.process_manager
        ae = getattr(pm, "_action_engine", None) if pm else None
        if not ae:
            return 0

        proj_dir = project.get("project_dir", "")
        if not proj_dir:
            return 0

        from models.action_items import (get_action_items_by_status,
                                         update_action_item_status,
                                         bulk_update_status)
        pending = get_action_items_by_status(proj_dir, "pending")
        if not pending:
            return 0

        nessus_ok = self._nessus_is_configured(project)
        running = self._get_running_tools(project_id)
        running_keys = self._get_running_keys(project_id)

        # Only process items whose originating tool has finished.
        # During SS3/OSift execution, live findings generate action
        # items for Fracture/Siphon — those must wait until the
        # originating recon tool completes.
        pending = [it for it in pending
                   if it.get("source_tool", "") not in running]
        if not pending:
            return 0
        queued_tools = {
            (f"{e['tool_id']}:{e['scope']}" if e.get("scope")
             else e["tool_id"])
            for e in self.get_queue(project_id)
        }

        # Group eligible items by (tool, oos_flag) — OOS items get
        # separate tool instances from in-scope items.
        tool_groups: dict[tuple[str, bool], list[dict]] = {}
        for item in pending:
            is_oos = bool(item.get("metadata", {}).get("oos_eligible"))
            if item.get("in_scope") is False and not is_oos:
                continue
            if item.get("user_reset"):
                continue
            tier = item.get("approval_tier", "confirm")
            tool = (item.get("recommended_tool") or "").lower()
            if not tool or tool not in AUTO_QUEUE_TOOLS:
                continue
            if tier == "auto":
                tool_groups.setdefault((tool, is_oos), []).append(item)
            elif tier == "confirm" and tool in AUTO_QUEUE_TOOLS:
                if tool == "nessus" and not nessus_ok:
                    continue
                tool_groups.setdefault((tool, is_oos), []).append(item)

        if not tool_groups:
            return 0

        from routes.action_items import _inject_targets, _ensure_tool_registered
        enqueued = 0

        for (tool, is_oos), items in tool_groups.items():
            item_scope = items[0].get("scope") or ""
            # OOS runs use scope suffix so settings file is separate
            settings_scope = f"{item_scope}_oos" if is_oos else item_scope
            # Queue dedup key includes OOS flag
            queue_key = f"{tool}:{settings_scope}" if settings_scope else tool
            running_key = f"{tool}:{settings_scope}" if settings_scope else tool
            if running_key in running_keys or queue_key in queued_tools:
                continue

            # Handle Nessus items individually (import-or-scan logic)
            if tool == "nessus":
                remaining = []
                for item in items:
                    target = item.get("target", "")
                    if self._handle_nessus_auto_queue(
                            project_id, project, item, target):
                        continue
                    remaining.append(item)
                items = remaining
                if not items:
                    continue

            targets = [it.get("target", "") for it in items if it.get("target")]
            item_ids = [it["id"] for it in items]

            # Register under the real scope (not the _oos variant)
            _ensure_tool_registered(project_id, project, tool,
                                    item_scope=item_scope)
            # Inject targets into a separate settings file for OOS
            if targets and proj_dir:
                _inject_targets(proj_dir, tool, targets, {}, project=project,
                                scope=settings_scope)

            bulk_update_status(proj_dir, item_ids, "queued")

            best_priority = min(
                {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(
                    it.get("priority", "MEDIUM"), 2)
                for it in items)

            self.enqueue(project_id, tool, priority=best_priority,
                         auto_queued=True, scope=settings_scope,
                         oos=is_oos)
            queued_tools.add(queue_key)
            enqueued += 1
            oos_tag = " (OOS)" if is_oos else ""
            log.info("Auto-queued %s%s for project %s (%d targets)",
                     tool, oos_tag, project_id, len(targets))
            try:
                from app import socketio
                socketio.emit("tool_queued", {
                    "project_id": project_id,
                    "tool_id": tool,
                    "reason": f"Auto-queued{oos_tag} ({len(targets)} targets)",
                    "oos": is_oos,
                }, room=f"project_{project_id}")
            except Exception:
                pass

        if enqueued:
            self.auto_dequeue(project_id)

        return enqueued

    def _prepare_credentialled_launch(self, project, tool, meta):
        """Write a credentialled settings file and return extra_args.

        Runs Test Connection in auto-detect mode to obtain session/cookie
        details, then merges everything into a settings file that the
        tool reads on startup.
        """
        import json
        from config import TOOL_SETTINGS_PREFIX

        proj_dir = Path(project.get("project_dir", ""))
        prefix = TOOL_SETTINGS_PREFIX.get(tool)
        if not prefix:
            return None

        base_settings_path = proj_dir / f"{prefix}_settings.json"
        settings = {}
        if base_settings_path.exists():
            try:
                settings = json.loads(base_settings_path.read_text())
            except (json.JSONDecodeError, OSError):
                pass

        creds = meta["credentials"]
        username = creds.get("username", "")
        password = creds.get("password", "")
        auth_method = creds.get("auth_method", "auto")

        target = meta.get("hostname") or meta.get("ip", "")
        port = meta.get("port", 0)
        service = meta.get("service", "")

        if tool in ("fracture", "siphon"):
            target_url = ""
            if tool == "fracture":
                target_url = settings.get("target_url", "")
            else:
                target_url = settings.get("api_base_url", "")
            if not target_url and target:
                scheme = "https" if port in (443, 8443, 9443, 4443) \
                    or service == "https" else "http"
                target_url = f"{scheme}://{target}" + (
                    f":{port}" if port and port not in (80, 443) else "")

            tc_result = self._run_test_connection(tool, target_url,
                                                  username, password)

            auth = settings.get("auth", {})
            auth["enabled"] = True
            auth["username"] = username
            auth["password"] = password
            if tc_result and tc_result.get("auth_method"):
                auth["method"] = tc_result["auth_method"]
                for k in ("session_cookie", "token", "token_type",
                           "login_url", "csrf_field"):
                    if tc_result.get(k):
                        auth[k] = tc_result[k]
            else:
                auth["method"] = auth_method if auth_method != "auto" \
                    else "form_login"
            settings["auth"] = auth

        elif tool == "auger":
            settings["username"] = username
            settings["password"] = password
            if target:
                settings["host"] = target
            if port:
                settings["port"] = port

        item_id = meta.get("finding_id", "cred")
        safe_id = str(item_id).replace("/", "_")[:24]
        cred_path = proj_dir / f"{prefix}_settings_cred_{safe_id}.json"
        cred_path.write_text(json.dumps(settings, indent=2))
        log.info("Wrote credentialled settings: %s", cred_path)

        return ["--settings", str(cred_path)]

    def _run_test_connection(self, tool, target_url, username, password):
        """Run testConnection.py in auto-detect mode and return result."""
        import json
        import subprocess
        from config import PYTHON3

        from adapters import get_adapter
        adapter = get_adapter(tool)
        if not adapter or not hasattr(adapter, "test_connection_script"):
            return None

        script = adapter.test_connection_script()
        if not script or not Path(script).exists():
            return None

        tc_config = {
            "url": target_url,
            "auth_method": "auto",
            "username": username,
            "password": password,
            "probe": True,
            "no_verify": True,
        }

        cmd = [PYTHON3, script, "--json", json.dumps(tc_config),
               "--output-json"]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30,
                env={**__import__("os").environ, "PYTHONUNBUFFERED": "1"},
            )
            if result.returncode == 0 and result.stdout.strip():
                parsed = json.loads(result.stdout)
                if isinstance(parsed, dict):
                    log.info("Test connection for %s: method=%s",
                             tool, parsed.get("auth_method", "unknown"))
                    return parsed
        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as exc:
            log.warning("Test connection for %s failed: %s", tool, exc)
        return None

    def _handle_nessus_auto_queue(self, project_id, project, item, target):
        """Check Nessus server for existing scan. Returns True if handled."""
        try:
            from services.nessus_client import NessusClient
            nessus_cfg = {}
            proj_dir = project.get("project_dir", "")
            settings_path = Path(proj_dir) / "nessus_settings.json"
            if settings_path.exists():
                import json
                nessus_cfg = json.loads(settings_path.read_text())

            host = nessus_cfg.get("host") or nessus_cfg.get("server")
            if not host:
                return False

            port = nessus_cfg.get("port", 8834)
            ak = nessus_cfg.get("access_key", "")
            sk = nessus_cfg.get("secret_key", "")
            if not ak or not sk:
                return False

            client = NessusClient(host, port, ak, sk,
                                  verify_ssl=nessus_cfg.get("verify_ssl", False))
            scans = client.list_scans()

            client_short = project.get("client_short", "")
            for scan in scans:
                name = scan.get("name", "")
                if client_short and client_short.lower() in name.lower():
                    status = scan.get("status", "")
                    if status == "completed":
                        self._import_completed_nessus(
                            project_id, project, client, scan["id"], item)
                        return True
                    elif status in ("running", "processing"):
                        return True
        except Exception as exc:
            log.warning("Nessus auto-queue check failed: %s", exc)
        return False

    def _import_completed_nessus(self, project_id, project, client, scan_id, item):
        """Import findings from a completed Nessus scan."""
        try:
            from models.action_items import update_action_item_status
            proj_dir = project.get("project_dir", "")
            update_action_item_status(proj_dir, item["id"], "complete")

            import tempfile
            from adapters.nessus import NessusAdapter
            with tempfile.NamedTemporaryFile(suffix=".nessus", delete=False) as tf:
                tmp_path = tf.name
            client.export_and_download(scan_id, tmp_path, fmt="nessus")

            adapter = NessusAdapter()
            tool_dir = project.get("tool_dirs", {}).get("nessus", "")
            if not tool_dir:
                return
            findings = adapter.parse_nessus_file(tmp_path, tool_dir)
            if findings:
                fe = getattr(self.process_manager, "_findings_engine", None)
                if fe:
                    fe.invalidate(project_id)
                log.info("Auto-imported %d Nessus findings from server scan %s",
                         len(findings), scan_id)
                if self.process_manager:
                    try:
                        self.process_manager.socketio.emit(
                            "nessus_done",
                            {"project_id": project_id,
                             "findings": len(findings),
                             "source": "auto_queue_import"},
                            room=f"project_{project_id}")
                    except Exception:
                        pass
            Path(tmp_path).unlink(missing_ok=True)
        except Exception as exc:
            log.warning("Nessus auto-import failed: %s", exc)

    # ── group helpers ────────────────────────────────────────────────────

    def _get_group(self, tool_id: str) -> str:
        """Find which parallel group *tool_id* belongs to."""
        for group_name, members in PARALLEL_GROUPS.items():
            if tool_id in members:
                return group_name
        return "any"

    def _get_running_tools(self, project_id: str) -> set[str]:
        """Get the set of currently running base tool_ids (scope stripped)."""
        if self.process_manager is None:
            return set()
        try:
            raw = self.process_manager.running_tools(project_id)
            return {tid.split(":")[0] for tid in raw}
        except Exception:
            return set()

    def _get_running_keys(self, project_id: str) -> set[str]:
        """Get scope-qualified keys of currently running tools."""
        if self.process_manager is None:
            return set()
        try:
            return set(self.process_manager.running_tools(project_id))
        except Exception:
            return set()

    def _get_running_groups_from_tools(self, running: set[str]) -> set[str]:
        """Map a set of running tool_ids to their group names."""
        groups = set()
        for tid in running:
            groups.add(self._get_group(tid.split(":")[0]))
        return groups

    # ── project pause ────────────────────────────────────────────────────

    def pause_project(self, project_id: str, *,
                      reason: str = "paused_user",
                      detail: str = "") -> None:
        """Mark a project as paused — blocks dequeue and auto_dequeue."""
        with self._lock:
            self._paused[project_id] = {
                "reason": reason,
                "detail": detail,
                "paused_at": _now_iso(),
            }
        log.info("Project %s paused: %s", project_id, reason)

    def resume_project(self, project_id: str) -> None:
        """Unmark a project as paused — resumes queue processing."""
        with self._lock:
            removed = self._paused.pop(project_id, None)
        if removed:
            log.info("Project %s resumed (was paused since %s)",
                     project_id, removed.get("paused_at"))
            self.auto_dequeue(project_id)

    def is_project_paused(self, project_id: str) -> bool:
        with self._lock:
            return project_id in self._paused

    def get_pause_info(self, project_id: str) -> dict:
        with self._lock:
            return dict(self._paused.get(project_id, {}))

    # ── persistence ──────────────────────────────────────────────────────

    def _persist_queue(self):
        """Save the full queue dict to disk for crash recovery.

        Caller MUST hold ``self._lock``.
        """
        try:
            data = {}
            for pid, entries in self._queue.items():
                if entries:
                    data[pid] = entries
            tmp = EXECUTE_QUEUE_FILE.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2, default=str))
            tmp.replace(EXECUTE_QUEUE_FILE)
        except OSError:
            pass  # best-effort — don't crash the server

    def _load_persisted_queue(self):
        """Load queue from disk on startup."""
        if not EXECUTE_QUEUE_FILE.exists():
            return
        try:
            raw = json.loads(EXECUTE_QUEUE_FILE.read_text())
            if not isinstance(raw, dict):
                return
            for pid, entries in raw.items():
                if isinstance(entries, list):
                    self._queue[pid] = [
                        e for e in entries
                        if isinstance(e, dict) and "tool_id" in e
                    ]
        except (json.JSONDecodeError, OSError):
            pass  # corrupt file — start fresh
