"""Crucible v2.0 — SchedulerService for scheduled engagements and engagement hours.

Provides two features:
  1. **Scheduled engagement start** — at a specified date/time, automatically
     launch all enabled tools for a project, routed through QueueManager
     for proper parallelism enforcement.
  2. **Engagement hours** — auto-pause tools outside configured testing
     windows and auto-resume when the window reopens.

Runs as a daemon thread checking every 60 seconds.
"""

import json
import logging
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

from services.utils import now_iso as _now_iso

log = logging.getLogger("crucible.scheduler")

_CHECK_INTERVAL = 60

_SCHEDULE_FILE = "schedule.json"
_ENGAGEMENT_FILE = "engagement_hours.json"


class SchedulerService:
    """Daemon service for scheduled engagement starts and engagement hours."""

    def __init__(self, process_manager, queue_manager, app=None):
        self._pm = process_manager
        self._qm = queue_manager
        self._app = app
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._schedules: dict[str, list[dict]] = {}
        self._engagement_hours: dict[str, dict] = {}
        self._paused_by_engagement: dict[str, bool] = {}
        self._loaded_projects: set[str] = set()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="scheduler-service",
            daemon=True,
        )
        self._thread.start()
        log.info("SchedulerService started")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        log.info("SchedulerService stopped")

    # ── scheduled engagement start ───────────────────────────────────────

    def schedule_engagement_start(self, project_id: str,
                                  scheduled_at: str, *,
                                  sudo_password: str | None = None) -> dict:
        """Schedule the engagement to auto-start at a future time.

        At the scheduled time, ALL enabled tools for the project are
        launched through the QueueManager, respecting parallelism rules.
        """
        import uuid
        entry = {
            "id": str(uuid.uuid4())[:8],
            "project_id": project_id,
            "scheduled_at": scheduled_at,
            "created_at": _now_iso(),
            "status": "pending",
        }
        if sudo_password:
            entry["_has_sudo"] = True
        self._schedules.setdefault(project_id, []).append(entry)
        if sudo_password:
            self._sudo_passwords[project_id] = sudo_password
        self._persist_schedules(project_id)
        log.info("Engagement start scheduled for %s at %s",
                 project_id, scheduled_at)
        return entry

    def remove_scheduled_start(self, project_id: str, sched_id: str) -> bool:
        entries = self._schedules.get(project_id, [])
        for i, e in enumerate(entries):
            if e["id"] == sched_id:
                entries.pop(i)
                self._persist_schedules(project_id)
                return True
        return False

    def get_scheduled_starts(self, project_id: str) -> list[dict]:
        self._ensure_loaded(project_id)
        return list(self._schedules.get(project_id, []))

    # ── engagement hours ─────────────────────────────────────────────────

    def set_engagement_hours(self, project_id: str, config: dict) -> None:
        """Set engagement hours for a project.

        config = {
            "enabled": True,
            "start_time": "08:00",     # HH:MM local
            "end_time": "18:00",       # HH:MM local
            "timezone": "US/Central",
            "days": [0,1,2,3,4],       # 0=Mon..6=Sun
        }
        """
        self._engagement_hours[project_id] = config
        self._persist_engagement(project_id)
        log.info("Engagement hours set for %s: %s", project_id, config)

    def get_engagement_hours(self, project_id: str) -> dict:
        self._ensure_loaded(project_id)
        return dict(self._engagement_hours.get(project_id, {}))

    def clear_engagement_hours(self, project_id: str) -> None:
        self._engagement_hours.pop(project_id, None)
        self._paused_by_engagement.pop(project_id, None)
        self._persist_engagement(project_id)

    def is_within_engagement_hours(self, project_id: str) -> bool | None:
        self._ensure_loaded(project_id)
        eh = self._engagement_hours.get(project_id, {})
        if not eh or not eh.get("enabled"):
            return None

        try:
            import zoneinfo
            tz = zoneinfo.ZoneInfo(eh.get("timezone", "UTC"))
        except Exception as exc:
            log.debug("timezone parse failed: %s", exc)
            tz = timezone.utc

        now = datetime.now(tz)
        day_of_week = now.weekday()
        allowed_days = eh.get("days", [0, 1, 2, 3, 4])
        if day_of_week not in allowed_days:
            return False

        start_parts = eh.get("start_time", "00:00").split(":")
        end_parts = eh.get("end_time", "23:59").split(":")
        start_h, start_m = int(start_parts[0]), int(start_parts[1])
        end_h, end_m = int(end_parts[0]), int(end_parts[1])

        current_minutes = now.hour * 60 + now.minute
        start_minutes = start_h * 60 + start_m
        end_minutes = end_h * 60 + end_m

        return start_minutes <= current_minutes < end_minutes

    # ── run loop ─────────────────────────────────────────────────────────

    def _run_loop(self) -> None:
        self._sudo_passwords: dict[str, str] = {}
        self._load_all_projects()
        while not self._stop.wait(_CHECK_INTERVAL):
            try:
                self._check_schedules()
                self._check_engagement_hours()
            except Exception:
                log.exception("SchedulerService tick error")

    def _load_all_projects(self) -> None:
        """Load persisted schedules and engagement hours for every project."""
        try:
            if not self._app:
                return
            with self._app.app_context():
                from models.project import list_projects
                for proj in list_projects():
                    pid = proj.get("id", "")
                    proj_dir = proj.get("project_dir", "")
                    if pid and proj_dir:
                        self.load_project_config(pid, proj_dir)
                if self._schedules or self._engagement_hours:
                    log.info("Loaded scheduler config for %d schedule(s), "
                             "%d engagement-hours config(s)",
                             sum(len(v) for v in self._schedules.values()),
                             len(self._engagement_hours))
        except Exception:
            log.exception("Failed to load project scheduler configs")

    def _check_schedules(self) -> None:
        now = datetime.now(timezone.utc)
        for project_id, entries in list(self._schedules.items()):
            for entry in list(entries):
                if entry.get("status") != "pending":
                    continue
                try:
                    sched_dt = datetime.fromisoformat(
                        entry["scheduled_at"].replace("Z", "+00:00"))
                    if sched_dt.tzinfo is None:
                        sched_dt = sched_dt.replace(tzinfo=timezone.utc)
                except (ValueError, KeyError) as exc:
                    log.debug("scheduled_at parse: %s", exc)
                    continue
                if now >= sched_dt:
                    within = self.is_within_engagement_hours(project_id)
                    if within is False:
                        entry["status"] = "deferred"
                        entry["deferred_reason"] = "outside_engagement_hours"
                        self._persist_schedules(project_id)
                        log.info("Scheduled start for %s deferred — outside "
                                 "engagement hours", project_id)
                        continue
                    self._launch_engagement(project_id, entry)

    def _launch_engagement(self, project_id: str, entry: dict) -> None:
        """Launch all enabled tools for the project through QueueManager."""
        entry["status"] = "launching"
        log.info("Scheduled engagement start firing for %s", project_id)

        if not self._app:
            entry["status"] = "failed"
            return

        with self._app.app_context():
            from models.project import get_project
            from models.settings import load_settings
            project = get_project(project_id)
            if not project:
                entry["status"] = "failed"
                entry["error"] = "project not found"
                self._persist_schedules(project_id)
                return

            tools = project.get("tools", [])
            scope_tools = project.get("scope_tools", {})
            active_scopes = project.get("active_scopes", [])
            sudo_password = self._sudo_passwords.get(project_id)

            launched = []
            queued = []
            skipped = []

            tool_scope_pairs = []
            if scope_tools:
                for scope_key, scope_tool_list in scope_tools.items():
                    if scope_key == "multi":
                        continue
                    for tid in scope_tool_list:
                        tool_scope_pairs.append((tid, scope_key))
            else:
                scope = active_scopes[0] if active_scopes else None
                for tid in tools:
                    tool_scope_pairs.append((tid, scope))

            for tid, scope in tool_scope_pairs:
                settings = load_settings(
                    project.get("project_dir", ""), tid, scope=scope)

                can, reason = self._qm.can_launch(project_id, tid,
                                                  scope=scope)
                if can:
                    ok = self._pm.launch(
                        project_id, tid,
                        project=project,
                        settings=settings,
                        resume=False,
                        scope=scope,
                        sudo_password=sudo_password,
                    )
                    if ok:
                        launched.append(f"{tid}:{scope}" if scope else tid)
                    else:
                        tk = f"{tid}:{scope}" if scope else tid
                        skipped.append(tk)
                        log.warning("Skipped %s for scheduled engagement %s "
                                    "(prerequisites not met)", tk, project_id)
                else:
                    self._qm.enqueue(
                        project_id, tid,
                        scope=scope,
                        settings=settings,
                        sudo_password=sudo_password,
                    )
                    queued.append(f"{tid}:{scope}" if scope else tid)
                    log.info("Queued %s:%s for %s: %s",
                             tid, scope, project_id, reason)

            entry["status"] = "launched"
            entry["launched_at"] = _now_iso()
            entry["launched_tools"] = launched
            entry["queued_tools"] = queued
            entry["skipped_tools"] = skipped
            self._persist_schedules(project_id)
            log.info("Engagement start complete for %s: launched=%s, "
                     "queued=%s, skipped=%s",
                     project_id, launched, queued, skipped)

            try:
                from services.utils import project_room as _room
                self._pm.socketio.emit(
                    "engagement_started",
                    {"project_id": project_id,
                     "launched": launched, "queued": queued,
                     "skipped": skipped},
                    to=_room(project_id))
            except Exception as exc:
                log.warning("socketio emit engagement_started failed: %s", exc)

    def _check_engagement_hours(self) -> None:
        for project_id, eh in list(self._engagement_hours.items()):
            if not eh.get("enabled"):
                continue

            within = self.is_within_engagement_hours(project_id)
            if within is None:
                continue

            was_paused = self._paused_by_engagement.get(project_id, False)

            if not within and not was_paused:
                log.info("Outside engagement hours — pausing project %s",
                         project_id)
                self._paused_by_engagement[project_id] = True
                self._persist_engagement(project_id)
                self._pause_for_engagement(project_id)

            elif within and was_paused:
                log.info("Within engagement hours — resuming project %s",
                         project_id)
                self._paused_by_engagement[project_id] = False
                self._persist_engagement(project_id)
                self._resume_from_engagement(project_id)

                self._check_deferred_starts(project_id)

    def _check_deferred_starts(self, project_id: str) -> None:
        """Fire any deferred scheduled starts now that the engagement
        window has reopened."""
        entries = self._schedules.get(project_id, [])
        for entry in list(entries):
            if entry.get("status") == "deferred":
                log.info("Engagement window opened — launching deferred "
                         "start for %s", project_id)
                self._launch_engagement(project_id, entry)

    def _pause_for_engagement(self, project_id: str) -> None:
        if not self._app:
            return
        with self._app.app_context():
            from models.project import get_project
            project = get_project(project_id)
            if not project:
                return

            eh = self._engagement_hours.get(project_id, {})
            detail = (f"Testing hours {eh.get('start_time', '?')}-"
                      f"{eh.get('end_time', '?')} "
                      f"({eh.get('timezone', 'UTC')})")

            self._pm.pause_all(
                project_id,
                reason="paused_engagement_hours",
                detail=detail,
                initiated_by="scheduler",
            )
            self._qm.pause_project(
                project_id,
                reason="paused_engagement_hours",
                detail=detail,
            )

    def _resume_from_engagement(self, project_id: str) -> None:
        if not self._app:
            return
        with self._app.app_context():
            from models.project import get_project
            project = get_project(project_id)
            if not project:
                return

            self._qm.resume_project(project_id)
            self._pm.resume_all(project_id, project=project)

    # ── persistence ──────────────────────────────────────────────────────

    def _persist_schedules(self, project_id: str) -> None:
        try:
            from models.project import get_project
            proj = get_project(project_id) if self._app else None
            proj_dir = (proj or {}).get("project_dir", "")
            if not proj_dir:
                return
            fp = Path(proj_dir) / _SCHEDULE_FILE
            data = self._schedules.get(project_id, [])
            clean = [{k: v for k, v in e.items() if not k.startswith("_")}
                     for e in data]
            fp.write_text(json.dumps(clean, indent=2, default=str))
        except Exception:
            log.exception("Failed to persist schedules for %s", project_id)

    def _persist_engagement(self, project_id: str) -> None:
        try:
            from models.project import get_project
            proj = get_project(project_id) if self._app else None
            proj_dir = (proj or {}).get("project_dir", "")
            if not proj_dir:
                return
            fp = Path(proj_dir) / _ENGAGEMENT_FILE
            eh = dict(self._engagement_hours.get(project_id, {}))
            if eh:
                eh["_paused"] = self._paused_by_engagement.get(project_id, False)
                fp.write_text(json.dumps(eh, indent=2))
            elif fp.exists():
                fp.unlink()
        except Exception:
            log.exception("Failed to persist engagement hours for %s",
                          project_id)

    def _ensure_loaded(self, project_id: str) -> None:
        """Lazy-load persisted config from disk if not already in memory."""
        if project_id in self._loaded_projects:
            return
        try:
            from models.project import get_project
            proj = get_project(project_id)
            if proj:
                proj_dir = proj.get("project_dir", "")
                if proj_dir:
                    self.load_project_config(project_id, proj_dir)
        except Exception as exc:
            log.warning("_ensure_loaded failed for %s: %s", project_id, exc)
        self._loaded_projects.add(project_id)

    def load_project_config(self, project_id: str, proj_dir: str) -> None:
        """Load persisted schedules and engagement hours for a project."""
        sched_file = Path(proj_dir) / _SCHEDULE_FILE
        if sched_file.exists():
            try:
                data = json.loads(sched_file.read_text())
                if isinstance(data, list):
                    self._schedules[project_id] = data
            except (json.JSONDecodeError, OSError) as exc:
                log.debug("load schedule.json failed for %s: %s", project_id, exc)

        eh_file = Path(proj_dir) / _ENGAGEMENT_FILE
        if eh_file.exists():
            try:
                data = json.loads(eh_file.read_text())
                if isinstance(data, dict):
                    was_paused = data.pop("_paused", False)
                    self._engagement_hours[project_id] = data
                    if was_paused:
                        self._paused_by_engagement[project_id] = True
            except (json.JSONDecodeError, OSError) as exc:
                log.debug("load engagement_hours.json failed for %s: %s", project_id, exc)

        self._loaded_projects.add(project_id)
