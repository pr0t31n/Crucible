"""ProcessManager — subprocess lifecycle manager for Crucible v2.0.

Launches, monitors, and kills tool processes.  Reads stdout/stderr via
daemon threads, parses protocol tokens through TokenParser, and emits
SocketIO events to the project room.

Thread-safety: every mutation of internal state goes through ``_lock``.
"""

import logging
import os
import sys
import json
import time
import uuid
import queue
import re
import threading
import subprocess
import signal
import shutil
from datetime import datetime, timezone
from pathlib import Path

from flask_socketio import SocketIO

from services.token_parser import TokenParser
from services.utils import now_iso as _now_iso, now_ts as _now_ts, project_room as _room
from services.audit_logger import audit as _audit
from config import (MAX_CONSOLE_LINES, PYTHON3, TOOLS, TOOL_ENV,
                    TOOL_SETTINGS_PREFIX, AETHER_TOOLS)

log = logging.getLogger("crucible.process_manager")

# ── Constants ────────────────────────────────────────────────────────────
_SUDO_PROMPT_RE = re.compile(
    r'(password for .+:|^\[sudo\] password|^Password:)',
    re.IGNORECASE,
)

_EXTRA_PATH_DIRS = ["/usr/local/bin", "/opt/homebrew/bin", "/usr/bin", "/bin"]

_PROMPT_TIMEOUT = 300

_KILL_GRACE = 5

_PAUSE_GRACE = 60          # initial wait before checking on tool
_PAUSE_HARD_LIMIT = 180    # absolute limit before killing the tool itself

EXIT_PAUSED = 42

_SENTINEL_NAME = "_pause_requested"


def _read_tool_version(tool_id: str) -> str:
    """Read the VERSION file for a pr0t31n tool. Returns 'unknown' on failure."""
    tool_cfg = TOOLS.get(tool_id, {})
    script = tool_cfg.get("script")
    if script:
        vf = Path(script).resolve().parent / "VERSION"
        try:
            return vf.read_text().strip()
        except (OSError, ValueError) as exc:
            log.debug("_read_tool_version(%s): %s", tool_id, exc)
    return "unknown"


def _pkey(project_id: str, tool_id: str) -> str:
    """Composite key for answer-queue / pending-prompt dicts."""
    return f"{project_id}:{tool_id}"


def _tkey(tool_id: str, scope: str | None = None) -> str:
    """Tool key that supports scope-qualified parallel runs."""
    if scope:
        return f"{tool_id}:{scope}"
    return tool_id


class ProcessManager:
    """Manage tool subprocess lifecycles and SocketIO event routing."""

    def __init__(self, socketio: SocketIO):
        self.socketio = socketio
        self._token_parser = TokenParser()
        self._queue_manager = None
        self._action_engine = None
        self._findings_engine = None

        self._procs: dict[str, dict[str, subprocess.Popen | None]] = {}
        self._tool_status: dict[str, dict[str, str]] = {}
        self._console_buffers: dict[str, dict[str, list]] = {}
        self._answer_queues: dict[str, dict[str, queue.Queue]] = {}
        self._pending_prompts: dict[str, dict[str, dict]] = {}
        self._stderr_accum: dict[str, list] = {}
        self._stderr_timers: dict[str, threading.Timer] = {}
        self._live_targets: dict[str, dict[str, dict]] = {}
        self._live_flush_timers: dict[str, threading.Timer] = {}
        self._phase_cache: dict[str, dict[str, dict]] = {}
        self._tool_output_dirs: dict[str, dict[str, str]] = {}
        self._tool_metadata: dict[str, dict[str, dict]] = {}
        self._pid_history: dict[str, dict[str, list]] = {}
        self._orphan_pids: dict[str, dict[str, int]] = {}
        self._lock = threading.Lock()
        self._history_loaded: set[str] = set()
        self._watchdog_started = False
        self._rerun_created: set[str] = set()

    # ── Resource watchdog ──────────────────────────────────────────

    def _start_resource_watchdog(self):
        if self._watchdog_started:
            return
        self._watchdog_started = True
        t = threading.Thread(target=self._resource_watchdog_loop,
                             name="crucible-resource-watchdog", daemon=True)
        t.start()
        log.info("Resource watchdog started")

    def _resource_watchdog_loop(self):
        try:
            import psutil
        except ImportError:
            log.warning("psutil not available — resource watchdog disabled")
            return
        while True:
            try:
                time.sleep(15)
                mem = psutil.virtual_memory()
                if mem.percent < 93:
                    continue
                with self._lock:
                    all_pids = {}
                    for pid_project, tools in self._procs.items():
                        for tk, proc in tools.items():
                            if proc and proc.poll() is None:
                                all_pids[proc.pid] = (pid_project, tk)
                if not all_pids:
                    continue
                biggest_pid = None
                biggest_rss = 0
                biggest_key = None
                for pid, (proj_id, tk) in all_pids.items():
                    try:
                        p = psutil.Process(pid)
                        tree_rss = p.memory_info().rss
                        for child in p.children(recursive=True):
                            try:
                                tree_rss += child.memory_info().rss
                            except (psutil.NoSuchProcess, OSError) as exc:
                                log.debug("OOM watchdog: child memory read: %s", exc)
                        if tree_rss > biggest_rss:
                            biggest_rss = tree_rss
                            biggest_pid = pid
                            biggest_key = (proj_id, tk)
                    except (psutil.NoSuchProcess, OSError) as exc:
                        log.debug("OOM watchdog: process memory read: %s", exc)
                if biggest_pid and biggest_key and biggest_rss > 512 * 1024 * 1024:
                    proj_id, tk = biggest_key
                    mb = biggest_rss // (1024 * 1024)
                    tool_id = tk.split(":")[0]
                    scope = tk.split(":")[1] if ":" in tk else None

                    snapshot = self._oom_snapshot(psutil, all_pids, mem)
                    snap_msg = "\n".join(snapshot)
                    log.warning("OOM snapshot:\n%s", snap_msg)

                    msg = (f"OOM watchdog killed {tk} (PID {biggest_pid}, "
                           f"{mb} MB RSS) — system RAM at {mem.percent:.0f}%")
                    log.warning(msg)
                    self._emit_console(proj_id, tk,
                                       f"[Crucible] {msg}", "system")
                    for line in snapshot:
                        self._emit_console(proj_id, tk,
                                           f"[OOM Snapshot] {line}", "system")
                    self._emit_error(proj_id, tk,
                                     msg + "\n\nProcess snapshot:\n" + snap_msg)
                    self._save_oom_snapshot(proj_id, snapshot, msg)
                    self._create_rerun_action_item(
                        proj_id, tool_id, scope, msg, category="rerun_oom")
                    with self._lock:
                        self._rerun_created.add(_pkey(proj_id, tk))
                    self.kill(proj_id, tool_id, scope=scope)
            except Exception:
                log.exception("Resource watchdog error")

    # ── OOM snapshot helpers ─────────────────────────────────────────

    @staticmethod
    def _oom_snapshot(psutil, all_pids, mem):
        """Build a list of human-readable lines describing every managed
        process tree and their RSS at the moment OOM trips."""
        lines = [
            f"=== OOM Process Snapshot — {datetime.now(timezone.utc).isoformat()} ===",
            f"System RAM: {mem.percent:.1f}% used  "
            f"({mem.used // (1024**2)} MB / {mem.total // (1024**2)} MB)",
            "",
        ]
        for pid, (proj_id, tk) in sorted(all_pids.items()):
            try:
                p = psutil.Process(pid)
                pi = p.memory_info()
                cmdline = " ".join(p.cmdline()) or p.name()
                lines.append(
                    f"[{tk}] PID {pid}  RSS {pi.rss // (1024**2)} MB  "
                    f"cmd: {cmdline[:200]}")
                for child in p.children(recursive=True):
                    try:
                        ci = child.memory_info()
                        ccmd = " ".join(child.cmdline()) or child.name()
                        lines.append(
                            f"  └─ PID {child.pid}  RSS {ci.rss // (1024**2)} MB  "
                            f"cmd: {ccmd[:200]}")
                    except (psutil.NoSuchProcess, OSError) as exc:
                        log.debug("OOM snapshot: child info: %s", exc)
            except (psutil.NoSuchProcess, OSError):
                lines.append(f"[{tk}] PID {pid}  (exited before snapshot)")
        lines.append("")
        return lines

    def _save_oom_snapshot(self, project_id, snapshot_lines, kill_msg):
        """Write OOM snapshot to a JSON file in the project directory."""
        proj_dir = self._resolve_project_dir(project_id)
        if not proj_dir:
            return
        try:
            snap_dir = Path(proj_dir) / "oom_snapshots"
            snap_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            snap_file = snap_dir / f"oom_{ts}.json"
            snap_file.write_text(json.dumps({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "trigger": kill_msg,
                "snapshot": snapshot_lines,
            }, indent=2))
        except OSError:
            log.exception("Failed to save OOM snapshot")

    # ── Tool version helpers ──────────────────────────────────────────

    def get_tool_version(self, project_id, tool_key):
        """Return the version for a tool: live metadata → history → VERSION file."""
        base_tid = tool_key.split(":")[0] if ":" in tool_key else tool_key
        with self._lock:
            meta = (self._tool_metadata.get(project_id) or {}).get(tool_key, {})
            if meta.get("tool_version"):
                return meta["tool_version"]
        proj_dir = self._resolve_project_dir(project_id)
        if proj_dir:
            try:
                fp = self._history_path(proj_dir)
                if fp.exists():
                    history = json.loads(fp.read_text())
                    entry = history.get(tool_key, {})
                    if entry.get("tool_version"):
                        return entry["tool_version"]
            except (json.JSONDecodeError, OSError) as exc:
                log.warning("get_tool_version: history read for %s: %s",
                            tool_key, exc)
        return _read_tool_version(base_tid)

    def get_all_tool_versions(self, project_id):
        """Return {tool_key: version} for every tool that has run or is running."""
        result = {}
        with self._lock:
            for tk, meta in (self._tool_metadata.get(project_id) or {}).items():
                if meta.get("tool_version"):
                    result[tk] = meta["tool_version"]
        proj_dir = self._resolve_project_dir(project_id)
        if proj_dir:
            try:
                fp = self._history_path(proj_dir)
                if fp.exists():
                    history = json.loads(fp.read_text())
                    for tk, entry in history.items():
                        if tk not in result and entry.get("tool_version"):
                            result[tk] = entry["tool_version"]
            except (json.JSONDecodeError, OSError) as exc:
                log.warning("get_all_tool_versions: history read: %s", exc)
        return result

    # ── History persistence ─────────────────────────────────────────

    @staticmethod
    def _history_path(project_dir: str) -> Path:
        return Path(project_dir) / "tool_history.json"

    @staticmethod
    def _console_log_path(project_dir: str, tool_id: str,
                          tool_output_dir: str | None = None) -> Path:
        base_tool = tool_id.split(":")[0] if ":" in tool_id else tool_id
        scope = tool_id.split(":", 1)[1] if ":" in tool_id else ""
        if tool_output_dir and Path(tool_output_dir).is_dir():
            name = f"console_{scope}.log" if scope else "console.log"
            return Path(tool_output_dir) / name
        return Path(project_dir) / f"console_{tool_id}.log"

    def _persist_history(self, project_id: str, tool_id: str,
                         final_status: str, returncode: int) -> None:
        proj_dir = self._resolve_project_dir(project_id)
        if not proj_dir:
            return
        try:
            fp = self._history_path(proj_dir)
            history = {}
            if fp.exists():
                try:
                    history = json.loads(fp.read_text())
                except (json.JSONDecodeError, OSError) as exc:
                    log.warning("_persist_history: read existing: %s", exc)
            with self._lock:
                buf = (self._console_buffers.get(project_id) or {}).get(tool_id, [])
                last_lines = list(buf[-500:]) if buf else []
                meta = (self._tool_metadata.get(project_id) or {}).get(tool_id, {})
                pids = list((self._pid_history.get(project_id) or {}).get(tool_id, []))
            base_tool = tool_id.split(":")[0] if ":" in tool_id else tool_id
            scope = tool_id.split(":", 1)[1] if ":" in tool_id else ""
            ended_now = _now_iso()
            with self._lock:
                ms = self._tool_metadata.setdefault(project_id, {})
                if tool_id in ms:
                    ms[tool_id]["ended_at"] = ended_now
            history[tool_id] = {
                "status": final_status,
                "returncode": returncode,
                "ended_at": ended_now,
                "started_at": meta.get("started_at", ""),
                "pid": meta.get("pid"),
                "pids": pids,
                "scope": scope,
                "base_tool": base_tool,
                "tool_version": meta.get("tool_version", ""),
                "command": meta.get("command", ""),
                "console": last_lines,
            }
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(json.dumps(history, indent=2))
        except OSError as exc:
            log.warning("_persist_history: write failed for %s/%s: %s",
                        project_id[:8], tool_id, exc)

    def _load_history(self, project_id: str) -> None:
        if project_id in self._history_loaded:
            return
        self._history_loaded.add(project_id)
        proj = self._resolve_project(project_id)
        if not proj:
            return
        proj_dir = proj.get("project_dir", "")
        if not proj_dir:
            return
        fp = self._history_path(proj_dir)
        loaded_tids = set()
        if fp.exists():
            try:
                history = json.loads(fp.read_text())
            except (json.JSONDecodeError, OSError) as exc:
                log.warning("_load_history: read failed for %s: %s",
                            project_id[:8], exc)
                history = {}
            with self._lock:
                statuses = self._tool_status.setdefault(project_id, {})
                buffers = self._console_buffers.setdefault(project_id, {})
                pid_hist = self._pid_history.setdefault(project_id, {})
                meta_store = self._tool_metadata.setdefault(project_id, {})
                for tid, entry in history.items():
                    loaded_tids.add(tid)
                    if tid not in statuses:
                        statuses[tid] = entry.get("status", "halted")
                    if tid not in buffers:
                        buffers[tid] = entry.get("console", [])
                    if tid not in pid_hist:
                        if entry.get("pids"):
                            pid_hist[tid] = entry["pids"]
                        elif entry.get("pid"):
                            pid_hist[tid] = [{"pid": entry["pid"],
                                              "started_at": entry.get("started_at", "")}]
                    if tid not in meta_store:
                        meta_store[tid] = {
                            "started_at": entry.get("started_at", ""),
                            "ended_at": entry.get("ended_at", ""),
                            "pid": entry.get("pid"),
                            "tool_version": entry.get("tool_version", ""),
                        }
        self._load_scan_logs_fallback(project_id, proj, proj_dir, loaded_tids)

    def _load_scan_logs_fallback(self, project_id: str, proj: dict,
                                 proj_dir: str, skip_tids: set) -> None:
        """Load console lines from scan.log files when tool_history.json
        has no entry for a tool.  Gives console output for scans that
        completed before the history persistence was deployed."""
        from config import TOOL_OUTPUT_DIRS
        tools = proj.get("tools", [])
        pd = Path(proj_dir)
        for tid in tools:
            if tid in skip_tids:
                continue
            with self._lock:
                if tid in (self._console_buffers.get(project_id) or {}):
                    continue
            td = proj.get("tool_dirs", {}).get(tid)
            if td and Path(td).exists():
                tool_dir = Path(td)
            else:
                tool_dir = pd / TOOL_OUTPUT_DIRS.get(tid, tid)
            lines = self._read_scan_log_lines(tool_dir, tid)
            if not lines:
                continue
            status = self._infer_scan_status(lines, tool_dir, tid)
            with self._lock:
                statuses = self._tool_status.setdefault(project_id, {})
                buffers = self._console_buffers.setdefault(project_id, {})
                if tid not in statuses:
                    statuses[tid] = status
                if tid not in buffers:
                    buffers[tid] = lines

    @staticmethod
    def _infer_scan_status(lines: list[dict], tool_dir: Path,
                           tool_id: str) -> str:
        """Infer whether a scan completed or was killed from its log lines."""
        last_texts = [
            (e.get("text") or "").lower() for e in lines[-20:]
        ]
        for t in last_texts:
            if "killed" in t or "cancelled" in t or "canceled" in t:
                return "killed"
            if "signal" in t and ("sigterm" in t or "sigkill" in t or "sigint" in t):
                return "killed"
        last_text = last_texts[-1] if last_texts else ""
        if "exited" in last_text and "status: killed" in last_text:
            return "killed"
        if "exited" in last_text and "status: complete" in last_text:
            return "complete"
        if "exited" in last_text and "return code 0" in last_text:
            return "complete"
        for t in last_texts:
            if "exited" in t and ("complete" in t or "finished" in t):
                return "complete"
            if ("scan complete" in t or "scan finished" in t or
                    "scan done" in t or "all phases complete" in t):
                return "complete"
        if last_text and ("complete" in last_text or "finished" in last_text or "done" in last_text):
            if "phase" not in last_text:
                return "complete"
        return "halted"

    @staticmethod
    def _read_scan_log_lines(tool_dir: Path, tool_id: str) -> list[dict]:
        """Read scan.log (and scope subdirs for SS3) into console-entry dicts."""
        candidates = []
        if tool_id == "ss3":
            for scope in ("ext", "int"):
                sl = tool_dir / scope / "scan.log"
                if sl.exists():
                    candidates.append((sl, scope))
        sl = tool_dir / "scan.log"
        if sl.exists():
            candidates.append((sl, None))
        if not candidates:
            return []
        entries = []
        for logfile, scope in candidates:
            try:
                text = logfile.read_text(errors="replace")
            except OSError as exc:
                log.warning("_read_scan_log_lines: %s: %s", logfile, exc)
                continue
            prefix = f"[{scope.upper()}] " if scope else ""
            for line in text.splitlines()[-2000:]:
                ts = ""
                content = line
                if line.startswith("[") and "] " in line:
                    bracket_end = line.index("] ")
                    ts = line[1:bracket_end]
                    content = line[bracket_end + 2:]
                entries.append({
                    "project_id": "",
                    "tool_id": tool_id,
                    "ts": ts,
                    "stream": "stdout",
                    "text": prefix + content,
                })
        return entries[-2000:]

    def set_queue_manager(self, qm):
        self._queue_manager = qm

    def set_action_engine(self, ae):
        self._action_engine = ae

    def set_findings_engine(self, fe):
        self._findings_engine = fe

    # ── Startup recovery ─────────────────────────────────────────────

    def startup_recovery(self, app):
        """Scan all projects for tools that completed while Crucible was down.

        For each project:
          1. Read tool_history.json for last-known state.
          2. Check if recorded PIDs are still alive → monitor them.
          3. Check if tool output is newer than history → run completion hooks.
          4. Repair action items stuck in 'running'.
        """
        t = threading.Thread(target=self._startup_recovery_worker,
                             args=(app,),
                             name="crucible-startup-recovery", daemon=True)
        t.start()

    def _startup_recovery_worker(self, app):
        time.sleep(2)
        with app.app_context():
            try:
                self._do_startup_recovery()
            except Exception:
                log.exception("Startup recovery failed")

    def _do_startup_recovery(self):
        from models.project import list_projects
        projects = list_projects()
        if not projects:
            return

        recovered = 0
        monitored = 0

        for proj in projects:
            pid = proj.get("id", "")
            proj_dir = proj.get("project_dir", "")
            if not pid or not proj_dir:
                continue
            fp = self._history_path(proj_dir)
            if not fp.exists():
                continue
            try:
                history = json.loads(fp.read_text())
            except (json.JSONDecodeError, OSError) as exc:
                log.warning("startup_recovery: history read for %s: %s",
                            pid[:8], exc)
                continue

            for tid, entry in history.items():
                status = entry.get("status", "")
                rec_pid = entry.get("pid")

                if status == "running" and rec_pid:
                    if self._is_pid_alive(rec_pid):
                        self._monitor_orphan(pid, tid, rec_pid, entry, proj)
                        monitored += 1
                        continue
                    else:
                        r = self._recover_completed_tool(
                            pid, tid, entry, proj_dir, proj)
                        if r:
                            recovered += 1
                        continue

                if status == "pausing":
                    with self._lock:
                        self._tool_status.setdefault(pid, {})[tid] = "paused"
                    entry["status"] = "paused"
                    fp.write_text(json.dumps(history, indent=2))
                    recovered += 1
                    continue

                if status in ("running", "halted"):
                    r = self._recover_completed_tool(
                        pid, tid, entry, proj_dir, proj)
                    if r:
                        recovered += 1

            self._repair_stale_action_items(pid, proj_dir)

            try:
                from flask import current_app
                sched = current_app.extensions.get("scheduler")
                if sched:
                    sched.load_project_config(pid, proj_dir)
            except Exception as exc:
                log.warning("startup_recovery: scheduler config load "
                            "for %s: %s", pid[:8], exc)

        if recovered or monitored:
            log.info("Startup recovery: %d tool(s) recovered, "
                     "%d orphan(s) monitored", recovered, monitored)

    @staticmethod
    def _is_pid_alive(pid):
        try:
            os.kill(int(pid), 0)
            return True
        except (OSError, ValueError, TypeError) as exc:
            log.debug("_is_pid_alive(%s): %s", pid, exc)
            return False

    def _recover_completed_tool(self, project_id, tool_id, entry,
                                proj_dir, project):
        """Check if a tool's output is newer than its history record and
        run post-completion hooks if so."""
        base_tool = tool_id.split(":")[0] if ":" in tool_id else tool_id
        tool_dir = (project.get("tool_dirs") or {}).get(base_tool, "")
        if not tool_dir or not Path(tool_dir).is_dir():
            with self._lock:
                self._tool_status.setdefault(project_id, {})[tool_id] = "halted"
            return False

        ended_at = entry.get("ended_at", "")
        output_files = ["findings.json", "findings_report.json",
                        "findings_vantage.json", "action_items.json",
                        "targets_osint.json", "summary.json"]
        td = Path(tool_dir)
        has_newer = False
        for fname in output_files:
            fp = td / fname
            if fp.exists():
                try:
                    mtime = datetime.fromtimestamp(fp.stat().st_mtime).isoformat()
                    if not ended_at or mtime > ended_at:
                        has_newer = True
                        break
                except OSError as exc:
                    log.debug("_recover_completed_tool: stat %s: %s", fp, exc)
                    continue

        if not has_newer and entry.get("status") != "running":
            return False

        rc = entry.get("returncode", 1)
        if rc == 0:
            final_status = "complete"
        elif entry.get("status") == "killed":
            final_status = "killed"
        else:
            final_status = "failed"

        with self._lock:
            self._tool_status.setdefault(project_id, {})[tool_id] = final_status

        log.info("Startup recovery: processing %s/%s (status=%s)",
                 project_id[:8], tool_id, final_status)

        try:
            self._post_completion(project_id, tool_id, base_tool,
                                  final_status, rc)
        except Exception:
            log.exception("Recovery post-completion failed for %s/%s",
                          project_id[:8], tool_id)

        entry["status"] = final_status
        entry["_recovered"] = True
        entry["recovered_at"] = _now_iso()
        try:
            fp = self._history_path(proj_dir)
            all_history = {}
            if fp.exists():
                all_history = json.loads(fp.read_text())
            all_history[tool_id] = entry
            fp.write_text(json.dumps(all_history, indent=2))
        except OSError as exc:
            log.warning("_recover_completed_tool: history write for "
                        "%s: %s", tool_id, exc)

        return True

    def _monitor_orphan(self, project_id, tool_id, pid, entry, project):
        """Monitor a still-alive orphan process and run completion hooks
        when it exits."""
        with self._lock:
            self._tool_status.setdefault(project_id, {})[tool_id] = "running"
            self._orphan_pids.setdefault(project_id, {})[tool_id] = int(pid)

        log.info("Startup recovery: monitoring orphan PID %s for %s/%s",
                 pid, project_id[:8], tool_id)

        t = threading.Thread(
            target=self._orphan_poll_loop,
            args=(project_id, tool_id, int(pid), project),
            name=f"orphan-monitor-{tool_id}-{pid}",
            daemon=True)
        t.start()

    def _orphan_poll_loop(self, project_id, tool_id, pid, project):
        """Poll an orphaned process until it exits, then run recovery."""
        try:
            while True:
                time.sleep(5)
                if not self._is_pid_alive(pid):
                    break
        except Exception:
            log.exception("_orphan_poll_loop: poll loop crashed for "
                          "%s/%s (PID %s)", project_id[:8], tool_id, pid)

        with self._lock:
            orphans = self._orphan_pids.get(project_id)
            if orphans:
                orphans.pop(tool_id, None)

        base_tool = tool_id.split(":")[0] if ":" in tool_id else tool_id

        try:
            rc = os.waitpid(pid, os.WNOHANG)[1] >> 8
        except (ChildProcessError, OSError) as exc:
            log.debug("_orphan_poll_loop: waitpid for PID %s: %s", pid, exc)
            rc = -1

        if rc == 0:
            final_status = "complete"
        else:
            final_status = "failed"

        try:
            with self._lock:
                self._tool_status.setdefault(project_id, {})[tool_id] = final_status

            tool_name = TOOLS.get(base_tool, {}).get("name", tool_id)
            self._emit_console(project_id, tool_id,
                               f"[Crucible] {tool_name} (orphan PID {pid}) exited — "
                               f"status: {final_status}",
                               "system")

            self._persist_history(project_id, tool_id, final_status, rc)

            proj_dir = project.get("project_dir", "")
            if proj_dir:
                self._repair_stale_action_items(project_id, proj_dir)
        except Exception:
            log.exception("_orphan_poll_loop: recovery failed for "
                          "%s/%s (PID %s)", project_id[:8], tool_id, pid)

        app = getattr(self._queue_manager, "_app", None) \
            if self._queue_manager else None
        ctx = app.app_context() if app else None
        if ctx:
            ctx.__enter__()
        try:
            self._post_completion(project_id, tool_id, base_tool,
                                  final_status, rc)
        except Exception:
            log.exception("Orphan post-completion failed for %s/%s",
                          project_id[:8], tool_id)
        finally:
            if ctx:
                ctx.__exit__(None, None, None)

        log.info("Startup recovery: orphan %s/%s completed (status=%s)",
                 project_id[:8], tool_id, final_status)

    def _repair_stale_action_items(self, project_id, proj_dir):
        """Reset action items stuck in 'running' for tools no longer running."""
        try:
            from models.action_items import repair_stale_running
            with self._lock:
                running = set(
                    k for k, v in
                    (self._tool_status.get(project_id) or {}).items()
                    if v == "running"
                )
            repaired = repair_stale_running(proj_dir, running)
            if repaired:
                log.info("Startup recovery: reset %d stale action items "
                         "for %s", len(repaired), project_id[:8])
        except Exception:
            log.exception("Startup recovery: action item repair failed "
                          "for %s", project_id[:8])

    def _resolve_project(self, project_id):
        try:
            from models.project import get_project
            return get_project(project_id)
        except Exception as exc:
            log.warning("_resolve_project(%s): %s", project_id[:8], exc)
            return None

    def _resolve_project_dir(self, project_id):
        proj = self._resolve_project(project_id)
        return proj.get("project_dir", "") if proj else ""

    # Tools whose native scope differs from the project scope they may run in.
    _SCOPE_DYNAMIC_TOOLS = {"fracture", "siphon", "ss3", "osift"}

    def _get_tool_scope(self, project_id, tool_id):
        """Return the project scope a tool is registered under, or None."""
        if tool_id not in self._SCOPE_DYNAMIC_TOOLS:
            return None
        proj = self._resolve_project(project_id)
        if not proj:
            return None
        scope_tools = proj.get("scope_tools") or {}
        for scope_key, tools in scope_tools.items():
            if tool_id in tools:
                return scope_key
        return None

    _OSIFT_SUBDIRS = ("logs", "domains", "company",
                      "ip_addresses", "api_intel", "reports")

    def _ensure_tool_dir(self, project_id: str, tool_id: str,
                         project: dict) -> None:
        """Ensure tool_dirs[tool_id] is populated and required subdirs exist."""
        tool_dirs = project.get("tool_dirs") or {}
        already_registered = tool_id in tool_dirs and tool_dirs[tool_id]

        if already_registered:
            td = tool_dirs[tool_id]
            try:
                Path(td).mkdir(parents=True, exist_ok=True)
                if tool_id == "osift":
                    for _sd in self._OSIFT_SUBDIRS:
                        (Path(td) / _sd).mkdir(exist_ok=True)
            except OSError as exc:
                log.warning("_ensure_tool_dir: mkdir %s: %s", td, exc)
            return

        eng_dir = project.get("engagement_dir", project.get("project_dir", ""))
        if not eng_dir:
            return

        from config import TOOL_OUTPUT_DIRS
        from models.project import update_project

        if tool_id == "ss3":
            td = eng_dir
        else:
            tool_dirname = TOOL_OUTPUT_DIRS.get(tool_id, tool_id)
            td = str(Path(eng_dir) / tool_dirname)
            try:
                Path(td).mkdir(parents=True, exist_ok=True)
                if tool_id == "osift":
                    for _sd in self._OSIFT_SUBDIRS:
                        (Path(td) / _sd).mkdir(exist_ok=True)
            except OSError as exc:
                log.warning("_ensure_tool_dir: mkdir new %s: %s", td, exc)

        new_tool_dirs = dict(tool_dirs)
        new_tool_dirs[tool_id] = td

        scope_tool_dirs = dict(project.get("scope_tool_dirs") or {})
        for s in (project.get("active_scopes") or []):
            scope_tool_dirs.setdefault(s, {})[tool_id] = td

        update_project(project_id, {
            "tool_dirs": new_tool_dirs,
            "scope_tool_dirs": scope_tool_dirs,
        })
        project["tool_dirs"] = new_tool_dirs
        project["scope_tool_dirs"] = scope_tool_dirs
        log.info("Auto-populated tool_dirs[%s] = %s", tool_id, td)

    _SETTINGS_FILE_TOOLS = {"fracture", "siphon"}

    def _inject_output_dir(self, project: dict, tool_id: str,
                           scope: str | None = None) -> None:
        """Ensure ``scan.project`` in the tool's settings file points to the
        Crucible-managed output directory so findings land inside the
        engagement tree and are included in project exports."""
        if tool_id not in self._SETTINGS_FILE_TOOLS:
            return
        td = (project.get("tool_dirs") or {}).get(tool_id)
        if not td:
            return
        proj_dir = project.get("project_dir", "")
        if not proj_dir:
            return
        prefix = TOOL_SETTINGS_PREFIX.get(tool_id, tool_id)
        fname = f"{prefix}_settings_{scope}.json" if scope else f"{prefix}_settings.json"
        tool_path = Path(td)
        tool_path.mkdir(parents=True, exist_ok=True)
        fp = tool_path / fname
        # Migrate: if old file exists in proj_dir but not in tool dir, move it
        old_fp = Path(proj_dir) / fname
        if old_fp.exists() and not fp.exists():
            old_fp.rename(fp)
        elif old_fp.exists() and fp.exists():
            old_fp.unlink()
        try:
            existing = {}
            if fp.exists():
                with open(fp) as f:
                    existing = json.load(f)
            scan = existing.setdefault("scan", {})
            if scan.get("project") == td:
                return
            scan["project"] = td
            eng = existing.setdefault("engagement", {})
            eng["client_short"] = project.get("client_short", "")
            eng["start_date"] = project.get("start_date", "")
            eng["client_name"] = project.get("client_name", "")
            with open(fp, "w") as f:
                json.dump(existing, f, indent=2)
        except Exception as exc:
            log.warning("Failed to inject output dir for %s: %s", tool_id, exc)

    # ── public API ───────────────────────────────────────────────────────

    def launch(self, project_id: str, tool_id: str, *, project: dict,
               settings: dict, resume: bool = False, extra_args: list | None = None,
               sudo_password: str | None = None,
               scope: str | None = None,
               action_item_id: str | None = None,
               custom_command: str | None = None) -> bool:
        """Launch a tool subprocess.

        Returns ``True`` if launched, ``False`` if already running.
        ``scope`` enables parallel runs: ``tool_id:scope`` is the tracking key.
        """
        tk = _tkey(tool_id, scope)
        with self._lock:
            if self._is_running_locked(project_id, tk):
                return False
            self._ensure_buffers_locked(project_id, tk)

        self._archive_previous_console(project_id, tk, project)
        self._ensure_tool_dir(project_id, tool_id, project)
        _tool_dir = (project.get("tool_dirs") or {}).get(tool_id)
        if _tool_dir:
            with self._lock:
                self._tool_output_dirs.setdefault(project_id, {})[tk] = _tool_dir
        self._inject_output_dir(project, tool_id, scope=scope)
        self._update_system_info(project)

        tool_cfg = TOOLS.get(tool_id)
        if not tool_cfg:
            self._emit_console(project_id, tool_id,
                               f"[Crucible] Unknown tool: {tool_id}", "system")
            return False

        # -- Build environment ------------------------------------------------
        env = dict(os.environ)
        tool_env = TOOL_ENV.get(tool_id, {})
        env.update(tool_env)
        cur_path = env.get("PATH", "")
        extra = ":".join(d for d in _EXTRA_PATH_DIRS
                         if d not in cur_path.split(":"))
        if extra:
            env["PATH"] = extra + (":" + cur_path if cur_path else "")

        # -- Build command (adapter preferred, inline fallback) ---------------
        from adapters import get_adapter
        adapter = get_adapter(tool_id)
        _launch_project = dict(project)
        if scope:
            _launch_project["_launch_scope"] = scope
            env["CRUCIBLE_SCOPE"] = scope

        # -- Validate prerequisites --------------------------------------------
        if adapter and not (custom_command and custom_command.strip()):
            _valid, _reason = adapter.validate_launch(_launch_project, settings)
            if not _valid:
                tool_name = tool_cfg.get("name", tool_id)
                self._emit_console(
                    project_id, tool_id,
                    f"[Crucible] Cannot launch {tool_name}: {_reason}",
                    "system")
                log.warning("Launch blocked for %s: %s", tk, _reason)
                return False

        if custom_command and custom_command.strip():
            import shlex
            cmd = shlex.split(custom_command)
        else:
            cmd = (adapter.build_command(_launch_project, settings,
                                         resume=resume, extra_args=extra_args)
                   if adapter else [])

        if not cmd:
            script_path = tool_cfg.get("script")
            if not script_path or not Path(script_path).exists():
                self._emit_console(project_id, tool_id,
                                   f"[Crucible] Script not found: {script_path}",
                                   "system")
                return False
            cmd = []
            if tool_cfg.get("sudo"):
                cmd.extend(["sudo", "-S", "-E"])
            cmd.extend([PYTHON3, str(script_path)])
            settings_prefix = TOOL_SETTINGS_PREFIX.get(tool_id)
            if settings_prefix:
                proj_dir = project.get("project_dir", "")
                _tool_td = (project.get("tool_dirs") or {}).get(tool_id, "")
                _sfname = f"{settings_prefix}_settings_{scope}.json" if scope else f"{settings_prefix}_settings.json"
                _sfname_unscoped = f"{settings_prefix}_settings.json"
                # Prefer tool dir, fall back to project root (legacy)
                _candidates = []
                if _tool_td:
                    _candidates.append(Path(_tool_td) / _sfname)
                    if scope:
                        _candidates.append(Path(_tool_td) / _sfname_unscoped)
                _candidates.append(Path(proj_dir) / _sfname)
                if scope:
                    _candidates.append(Path(proj_dir) / _sfname_unscoped)
                settings_path = next((c for c in _candidates if c.exists()), None)
                if settings_path:
                    cmd.extend(["--settings", str(settings_path)])
            if resume and tool_id in ("fracture", "siphon"):
                cmd.append("--resume")
            if extra_args:
                cmd.extend(extra_args)

        # -- Fixup sudo env: env_reset in sudoers strips -E on most distros.
        # Replace  sudo [-S] [-E] <cmd>  with  sudo -S env K=V ... <cmd>
        # so PATH and CRUCIBLE_* vars survive into the tool process.
        if cmd and cmd[0] == "sudo":
            _base_env = dict(os.environ)
            _sudo_env = [f"{k}={v}" for k, v in env.items()
                         if v and (k not in _base_env or _base_env[k] != v)]
            _rest = []
            _skip = True
            for _tok in cmd:
                if _skip and _tok in ("sudo", "-S", "-E"):
                    continue
                _skip = False
                _rest.append(_tok)
            cmd = ["sudo", "-S", "env"] + _sudo_env + _rest

        # -- Working directory ------------------------------------------------
        # Use tool output dir as CWD so tool-created files (ferox state,
        # technologies.json, etc.) land in the right place, not project root.
        cwd = _tool_dir if _tool_dir and Path(_tool_dir).is_dir() else project.get("project_dir", "")
        if cwd:
            Path(cwd).mkdir(parents=True, exist_ok=True)
        else:
            cwd = None

        # -- Launch -----------------------------------------------------------
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                text=True,
                bufsize=1,
                cwd=cwd,
                env=env,
                errors="replace",
                start_new_session=True,
            )
        except Exception as exc:
            self._emit_console(project_id, tool_id,
                               f"[Crucible] Launch failed: {exc}", "system")
            return False

        started_at = _now_iso()
        tool_name = tool_cfg.get("name", tool_id)
        tool_version = _read_tool_version(tool_id)
        if scope:
            tool_name = f"{tool_name} [{scope}]"

        with self._lock:
            self._procs.setdefault(project_id, {})[tk] = proc
            self._tool_status.setdefault(project_id, {})[tk] = "running"
            self._answer_queues.setdefault(project_id, {})[tk] = queue.Queue()
            self._pending_prompts.setdefault(project_id, {})[tk] = {}
            self._tool_metadata.setdefault(project_id, {})[tk] = {
                "started_at": _now_iso(),
                "pid": proc.pid,
                "scope": scope,
                "base_tool": tool_id,
                "command": " ".join(str(c) for c in cmd),
                "tool_version": tool_version,
            }
            self._pid_history.setdefault(project_id, {}).setdefault(tk, []).append(
                {"pid": proc.pid, "started_at": started_at}
            )

        self._start_resource_watchdog()
        self._emit_console(project_id, tk,
                           f"[Crucible] {tool_name} v{tool_version} started — PID {proc.pid}",
                           "system")
        _audit(cwd, "TOOL_LAUNCH", tool=tool_id, scope=scope,
               pid=proc.pid, resume=resume, tool_version=tool_version)
        try:
            from models.project import record_tool_use
            _proj_dir = project.get("project_dir", "")
            if _proj_dir:
                record_tool_use(_proj_dir, tool_id)
        except Exception as exc:
            log.warning("launch: record_tool_use for %s: %s", tool_id, exc)
        self.socketio.emit("tool_status",
                           {"project_id": project_id,
                            "tool_id": tk, "status": "running",
                            "pid": proc.pid, "started_at": started_at,
                            "scope": scope,
                            "tool_version": tool_version},
                           room=_room(project_id))

        try:
            from services.beacon_client import notify_beacon_activity
            notify_beacon_activity(project_id)
        except Exception:
            pass

        self._persist_history(project_id, tk, "running", -1)

        if sudo_password and tool_cfg.get("sudo"):
            self._write_stdin(proc, sudo_password, project_id, tk)

        threading.Thread(
            target=self._stdout_reader,
            args=(project_id, tk, proc.stdout, proc),
            name=f"stdout-{tk}-{project_id[:8]}",
            daemon=True,
        ).start()

        threading.Thread(
            target=self._stderr_reader,
            args=(project_id, tk, proc.stderr, proc),
            name=f"stderr-{tk}-{project_id[:8]}",
            daemon=True,
        ).start()

        threading.Thread(
            target=self._wait_proc,
            args=(project_id, tk, proc),
            name=f"wait-{tk}-{project_id[:8]}",
            daemon=True,
        ).start()

        return True

    def kill(self, project_id: str, tool_id: str, *,
             scope: str | None = None,
             children_only: bool = False) -> bool:
        """Kill a running tool process (SIGTERM, then SIGKILL after grace).

        When *children_only* is True, only subprocesses are signalled — the
        parent tool is left alive so it can detect the pause sentinel,
        checkpoint its state, and exit cleanly with code 42.

        Returns ``True`` if a signal was sent, ``False`` if nothing to kill.
        """
        tk = _tkey(tool_id, scope)
        orphan_pid = None
        with self._lock:
            proc = (self._procs.get(project_id) or {}).get(tk)
            if (not proc or proc.poll() is not None) and not scope:
                for k in (self._procs.get(project_id) or {}):
                    if k.startswith(f"{tool_id}:"):
                        p = self._procs[project_id][k]
                        if p and p.poll() is None:
                            proc = p
                            tk = k
                            break
            if not proc or proc.poll() is not None:
                orphan_pid = (self._orphan_pids.get(project_id) or {}).get(tk)
                if not orphan_pid or not self._is_pid_alive(orphan_pid):
                    if not scope:
                        for k, op in (self._orphan_pids.get(project_id) or {}).items():
                            if k.startswith(f"{tool_id}:") and self._is_pid_alive(op):
                                orphan_pid = op
                                tk = k
                                break
                        else:
                            return False
                    else:
                        return False

        tool_name = TOOLS.get(tool_id, {}).get("name", tool_id)

        if orphan_pid and not proc:
            try:
                import psutil
                parent = psutil.Process(orphan_pid)
                for child in parent.children(recursive=True):
                    try:
                        child.send_signal(signal.SIGTERM)
                    except (psutil.NoSuchProcess, OSError) as exc:
                        log.debug("kill: orphan child SIGTERM: %s", exc)
                if not children_only:
                    parent.send_signal(signal.SIGTERM)
            except Exception as exc:
                log.warning("kill: psutil orphan SIGTERM for PID %s: %s",
                            orphan_pid, exc)
                if not children_only:
                    try:
                        os.kill(orphan_pid, signal.SIGTERM)
                    except (ProcessLookupError, PermissionError, OSError) as exc2:
                        log.debug("kill: os.kill orphan SIGTERM: %s", exc2)
            if not children_only:
                with self._lock:
                    orphans = self._orphan_pids.get(project_id)
                    if orphans:
                        orphans.pop(tk, None)
        else:
            try:
                import psutil
                parent = psutil.Process(proc.pid)
                for child in parent.children(recursive=True):
                    try:
                        child.send_signal(signal.SIGTERM)
                    except (psutil.NoSuchProcess, OSError) as exc:
                        log.debug("kill: child SIGTERM: %s", exc)
                if not children_only:
                    parent.send_signal(signal.SIGTERM)
            except Exception as exc:
                log.warning("kill: psutil SIGTERM for PID %s: %s",
                            proc.pid if proc else "?", exc)
                if not children_only:
                    try:
                        proc.terminate()
                    except OSError as exc2:
                        log.debug("kill: proc.terminate: %s", exc2)

        if children_only:
            self._emit_console(
                project_id, tk,
                f"[Crucible] {tool_name} subprocesses killed — "
                f"waiting for tool to checkpoint and exit",
                "system",
            )
        else:
            self._emit_console(
                project_id, tk,
                f"[Crucible] {tool_name} kill signal sent — "
                f"force-kill in {_KILL_GRACE} s",
                "system",
            )
        from models.project import get_project
        _proj = get_project(project_id)
        _audit(_proj.get("project_dir", "") if _proj else "",
               "TOOL_KILL_CHILDREN" if children_only else "TOOL_KILL",
               tool=tool_id, scope=scope)

        if not children_only:
            with self._lock:
                self._tool_status.setdefault(project_id, {})[tk] = "killed"

            self.socketio.emit("tool_status",
                               {"project_id": project_id,
                                "tool_id": tk, "status": "killed"},
                               room=_room(project_id))

        _kill_pid = orphan_pid if (orphan_pid and not proc) else (proc.pid if proc else None)

        def _force_kill():
            time.sleep(_KILL_GRACE)
            if children_only:
                try:
                    import psutil
                    _pid = _kill_pid or (proc.pid if proc else None)
                    if _pid and self._is_pid_alive(_pid):
                        for child in psutil.Process(_pid).children(recursive=True):
                            try:
                                child.send_signal(signal.SIGKILL)
                            except (psutil.NoSuchProcess, OSError) as exc:
                                log.debug("force_kill: child SIGKILL: %s", exc)
                except Exception as exc:
                    log.warning("force_kill: psutil children SIGKILL: %s", exc)
                return
            if proc and proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError) as exc:
                    log.debug("force_kill: killpg: %s", exc)
                    try:
                        proc.kill()
                    except OSError as exc2:
                        log.debug("force_kill: proc.kill: %s", exc2)
            elif _kill_pid and self._is_pid_alive(_kill_pid):
                try:
                    os.kill(_kill_pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError) as exc:
                    log.debug("force_kill: os.kill(%s): %s", _kill_pid, exc)

        threading.Thread(target=_force_kill, daemon=True).start()
        return True

    def pause(self, project_id: str, tool_id: str, *,
              scope: str | None = None,
              reason: str = "paused_user",
              detail: str = "",
              initiated_by: str = "user") -> bool:
        """Request a graceful pause of a running tool.

        Writes a sentinel file to the tool's output directory.  The tool
        polls for this file, checkpoints its state, and exits with code 42.
        If the tool does not exit within ``_PAUSE_GRACE`` seconds, it is
        killed via the normal kill path.

        Returns ``True`` if the sentinel was written, ``False`` if the
        tool is not running or the output dir is unknown.
        """
        tk = _tkey(tool_id, scope)
        with self._lock:
            proc = (self._procs.get(project_id) or {}).get(tk)
            if not proc or proc.poll() is not None:
                return False
            tool_dir = (self._tool_output_dirs.get(project_id) or {}).get(tk)

        if not tool_dir:
            from models.project import get_project
            proj = get_project(project_id)
            tool_dir = ((proj or {}).get("tool_dirs") or {}).get(
                tool_id.split(":")[0] if ":" in tool_id else tool_id, "")

        if not tool_dir or not Path(tool_dir).is_dir():
            log.warning("Cannot pause %s — no output dir found", tk)
            return False

        sentinel = Path(tool_dir) / _SENTINEL_NAME
        payload = json.dumps({
            "reason": reason,
            "detail": detail,
            "initiated_by": initiated_by,
            "requested_at": _now_iso(),
        })
        try:
            sentinel.write_text(payload)
        except OSError as exc:
            log.warning("Failed to write pause sentinel for %s: %s", tk, exc)
            return False

        with self._lock:
            self._tool_status.setdefault(project_id, {})[tk] = "pausing"

        base_tool = tool_id.split(":")[0] if ":" in tool_id else tool_id
        tool_name = TOOLS.get(base_tool, {}).get("name", tool_id)
        self._emit_console(project_id, tk,
                           f"[Crucible] {tool_name} pause requested — "
                           f"waiting up to {_PAUSE_GRACE}s for checkpoint",
                           "system")

        _audit(tool_dir, "TOOL_PAUSE_REQUESTED",
               tool=tool_id, scope=scope, reason=reason)

        self.socketio.emit("tool_status",
                           {"project_id": project_id,
                            "tool_id": tk, "status": "pausing"},
                           room=_room(project_id))

        def _pause_timeout():
            deadline = time.monotonic() + _PAUSE_HARD_LIMIT
            time.sleep(_PAUSE_GRACE)
            while time.monotonic() < deadline:
                with self._lock:
                    st = (self._tool_status.get(project_id) or {}).get(tk)
                    proc = (self._procs.get(project_id) or {}).get(tk)
                if st != "pausing":
                    return
                if proc is None or proc.poll() is not None:
                    return
                log.info("Pause wait for %s — tool still running, "
                         "waiting for checkpoint (%.0fs left)",
                         tk, deadline - time.monotonic())
                self._emit_console(project_id, tk,
                                   f"[Crucible] {tool_name} still checkpointing "
                                   f"— waiting for subprocess cleanup",
                                   "system")
                time.sleep(10)
            with self._lock:
                st = (self._tool_status.get(project_id) or {}).get(tk)
                proc = (self._procs.get(project_id) or {}).get(tk)
            if st == "pausing" and proc and proc.poll() is None:
                log.warning("Pause hard limit for %s — killing after %ds",
                            tk, _PAUSE_HARD_LIMIT)
                self._emit_console(project_id, tk,
                                   f"[Crucible] {tool_name} did not pause within "
                                   f"{_PAUSE_HARD_LIMIT}s — killing subprocesses",
                                   "system")
                self.kill(project_id, tool_id, scope=scope,
                          children_only=True)
                time.sleep(30)
                with self._lock:
                    st2 = (self._tool_status.get(project_id) or {}).get(tk)
                    proc2 = (self._procs.get(project_id) or {}).get(tk)
                if st2 == "pausing" and proc2 and proc2.poll() is None:
                    log.warning("Pause escalation for %s — sending SIGTERM "
                                "to parent after children_only failed", tk)
                    self._emit_console(
                        project_id, tk,
                        f"[Crucible] {tool_name} still alive after "
                        f"subprocess kill — sending SIGTERM to tool",
                        "system")
                    self.kill(project_id, tool_id, scope=scope,
                              children_only=False)

        threading.Thread(target=_pause_timeout, daemon=True,
                         name=f"pause-timeout-{tk}").start()
        return True

    def pause_all(self, project_id: str, *,
                  reason: str = "paused_user",
                  detail: str = "",
                  initiated_by: str = "user") -> list[str]:
        """Pause all running tools in a project.

        Returns a list of tool keys that were sent pause requests.
        """
        paused = []
        with self._lock:
            running = {
                tk: proc for tk, proc
                in (self._procs.get(project_id) or {}).items()
                if proc and proc.poll() is None
            }
        for tk in running:
            base_tool = tk.split(":")[0]
            scope = tk.split(":", 1)[1] if ":" in tk else None
            if self.pause(project_id, base_tool, scope=scope,
                          reason=reason, detail=detail,
                          initiated_by=initiated_by):
                paused.append(tk)
        return paused

    def resume_all(self, project_id: str, *, project: dict,
                   sudo_password: str | None = None) -> list[str]:
        """Resume all paused or killed-with-checkpoint tools in a project.

        Returns a list of tool keys that were relaunched.
        """
        resumed = []
        with self._lock:
            statuses = dict((self._tool_status.get(project_id) or {}))
        for tk, status in statuses.items():
            if status not in ("paused", "killed"):
                continue
            base_tool = tk.split(":")[0]
            scope = tk.split(":", 1)[1] if ":" in tk else None
            if status == "killed":
                from routes.console import _find_checkpoint_candidates
                has_cp = any(cp.exists()
                             for cp in _find_checkpoint_candidates(project, base_tool))
                if not has_cp:
                    continue
            from models.settings import load_settings
            settings = load_settings(project.get("project_dir", ""),
                                     base_tool, scope=scope)
            from routes.settings import _backfill_from_project
            _backfill_from_project(settings, project, base_tool)
            ok = self.launch(project_id, base_tool,
                             project=project, settings=settings,
                             resume=True, scope=scope,
                             sudo_password=sudo_password)
            if ok:
                resumed.append(tk)
        return resumed

    def send_input(self, project_id: str, tool_id: str, text: str, *,
                   scope: str | None = None) -> None:
        """Write raw text to a tool's stdin (for sudo password, etc.)."""
        tk = _tkey(tool_id, scope)
        with self._lock:
            proc = (self._procs.get(project_id) or {}).get(tk)
            if not proc and not scope:
                for k in (self._procs.get(project_id) or {}):
                    if k.startswith(f"{tool_id}:"):
                        p = self._procs[project_id][k]
                        if p and p.poll() is None:
                            proc = p
                            tk = k
                            break
        if proc:
            self._write_stdin(proc, text, project_id, tk)

    def answer_prompt(self, project_id: str, tool_id: str,
                      answer: str, *, scope: str | None = None) -> None:
        """Answer a pending interactive prompt."""
        tk = _tkey(tool_id, scope)
        with self._lock:
            q = (self._answer_queues.get(project_id) or {}).get(tk)
            self._pending_prompts.setdefault(project_id, {})[tk] = {}
        if q:
            q.put(answer)

    def get_status(self, project_id: str) -> dict[str, str]:
        """Return ``{tool_id: status_str}`` for all tools in a project."""
        self._load_history(project_id)
        with self._lock:
            return dict(self._tool_status.get(project_id, {}))

    def set_status(self, project_id: str, tool_id: str, status: str):
        """Set tool status for non-process-managed tools (e.g. nessus import)."""
        with self._lock:
            self._tool_status.setdefault(project_id, {})[tool_id] = status

    def get_phase_cache(self, project_id: str) -> dict[str, dict]:
        """Return cached phase data for all tools in a project."""
        with self._lock:
            return {tid: dict(phases)
                    for tid, phases in
                    self._phase_cache.get(project_id, {}).items()}

    def get_all_status(self, project_id: str) -> dict[str, dict]:
        """Return ``{tool_id: {status, last_line}}`` for all tools.

        Scope-qualified keys (e.g. ``fracture:ext``) are returned as-is,
        AND a base tool_id entry is added so the frontend can match by
        plain tool name.
        """
        self._load_history(project_id)
        with self._lock:
            statuses = dict(self._tool_status.get(project_id, {}))
            buffers = self._console_buffers.get(project_id, {})
            result = {}
            _ACTIVE = {"running", "queued", "pausing"}
            metadata = self._tool_metadata.get(project_id, {})
            for tid, st in statuses.items():
                buf = buffers.get(tid, [])
                last = buf[-1]["text"] if buf else ""
                meta = metadata.get(tid, {})
                entry = {"status": st, "last_line": last}
                if meta.get("started_at"):
                    entry["started_at"] = meta["started_at"]
                if meta.get("ended_at"):
                    entry["ended_at"] = meta["ended_at"]
                if meta.get("pid"):
                    entry["pid"] = meta["pid"]
                if meta.get("tool_version"):
                    entry["tool_version"] = meta["tool_version"]
                if ":" in tid:
                    result[tid] = entry
                    base = tid.split(":")[0]
                    scope = tid.split(":", 1)[1]
                    cur = result.get(base)
                    cur_active = cur.get("status") in _ACTIVE if cur else False
                    new_active = st in _ACTIVE
                    if not cur or (cur.get("resolved_key")
                                  and (cur.get("status") in ("idle", "halted")
                                       or (new_active and not cur_active))):
                        entry_b = dict(entry)
                        entry_b["scope"] = scope
                        entry_b["resolved_key"] = tid
                        result[base] = entry_b
                else:
                    cur = result.get(tid)
                    if not cur or "resolved_key" not in cur:
                        result[tid] = entry
        if self._queue_manager:
            for entry in self._queue_manager.get_queue(project_id):
                tid = entry.get("tool_id", "")
                if tid and tid not in result:
                    result[tid] = {"status": "queued", "last_line": ""}
        return result

    def get_pid_history(self, project_id: str, tool_key: str) -> list[dict]:
        self._load_history(project_id)
        with self._lock:
            pids = (self._pid_history.get(project_id) or {}).get(tool_key, [])
            if pids:
                return list(pids)
            buf = (self._console_buffers.get(project_id) or {}).get(tool_key, [])
        result = []
        _seen = set()
        for entry in buf:
            txt = entry.get("text", "")
            if "started — PID " in txt:
                try:
                    p = int(txt.split("PID ", 1)[1].split()[0])
                    if p not in _seen:
                        _seen.add(p)
                        result.append({"pid": p,
                                       "started_at": entry.get("ts", "")})
                except (ValueError, IndexError) as exc:
                    log.debug("PID parse from history line: %s", exc)
            elif "(orphan PID " in txt:
                try:
                    p = int(txt.split("orphan PID ", 1)[1].split(")")[0])
                    if p not in _seen:
                        _seen.add(p)
                        result.append({"pid": p,
                                       "started_at": entry.get("ts", "")})
                except (ValueError, IndexError) as exc:
                    log.debug("orphan PID parse from history line: %s", exc)
        return result

    def get_console(self, project_id: str, tool_id: str, *,
                    scope: str | None = None) -> list[dict]:
        """Return console ring buffer (list of entry dicts).

        When no scope is given and multiple scope-qualified buffers exist,
        prefer the one whose tool is currently running/queued so the
        console shows the active instance, not a stale completed one.
        """
        self._load_history(project_id)
        tk = _tkey(tool_id, scope)
        with self._lock:
            buf = (self._console_buffers.get(project_id) or {}).get(tk)
            if buf:
                return list(buf)
            if not scope:
                project_bufs = self._console_buffers.get(project_id) or {}
                statuses = self._tool_status.get(project_id, {})
                active_buf = None
                fallback_buf = None
                for k in project_bufs:
                    if k.startswith(f"{tool_id}:") and project_bufs[k]:
                        if statuses.get(k) in ("running", "queued"):
                            active_buf = project_bufs[k]
                        elif fallback_buf is None:
                            fallback_buf = project_bufs[k]
                chosen = active_buf or fallback_buf
                if chosen:
                    return list(chosen)
            return []

    def clear_project_buffers(self, project_id: str) -> None:
        """Wipe all in-memory buffers for a project (console, status, prompts,
        tool metadata).  Called by clear-scan-data."""
        with self._lock:
            self._console_buffers.pop(project_id, None)
            self._tool_status.pop(project_id, None)
            self._tool_metadata.pop(project_id, None)
            self._phase_cache.pop(project_id, None)
            self._pending_prompts.pop(project_id, None)
            self._answer_queues.pop(project_id, None)
            self._history_loaded.discard(project_id)

    def is_running(self, project_id: str, tool_id: str, *,
                   scope: str | None = None) -> bool:
        """Check if a specific tool is running."""
        tk = _tkey(tool_id, scope)
        with self._lock:
            if self._is_running_locked(project_id, tk):
                return True
            if not scope:
                for k, st in (self._tool_status.get(project_id) or {}).items():
                    if k.startswith(f"{tool_id}:") and st == "running":
                        return True
            return False

    def any_running(self, project_id: str) -> bool:
        """Check if any tool is currently running in a project."""
        with self._lock:
            statuses = self._tool_status.get(project_id, {})
            return any(s == "running" for s in statuses.values())

    def get_pending_prompt(self, project_id: str, tool_id: str, *,
                           scope: str | None = None) -> dict:
        """Return current pending prompt (empty dict if none)."""
        tk = _tkey(tool_id, scope)
        with self._lock:
            return dict(
                (self._pending_prompts.get(project_id) or {}).get(tk, {})
            )

    def running_tools(self, project_id: str) -> list[str]:
        """Return list of tool_ids currently running in a project."""
        with self._lock:
            result = []
            seen = set()
            procs = self._procs.get(project_id, {})
            statuses = self._tool_status.get(project_id, {})
            for tid, proc in procs.items():
                if proc and proc.poll() is None:
                    result.append(tid)
                    seen.add(tid)
                elif statuses.get(tid) == "running":
                    statuses[tid] = "failed"
            for tid, pid in (self._orphan_pids.get(project_id) or {}).items():
                if tid not in seen and self._is_pid_alive(pid):
                    result.append(tid)
            return result

    def inject_console_line(self, project_id: str, tool_id: str,
                            data: dict) -> None:
        """Inject an external console line into the buffer (for worker relay)."""
        entry = {
            "tool_id": tool_id,
            "ts": data.get("ts", _now_ts()),
            "stream": data.get("stream", "stdout"),
            "text": data.get("text", data.get("line", "")),
            "source": data.get("source", ""),
        }
        self._append_console(project_id, tool_id, entry)

    def _archive_previous_console(self, project_id: str, tool_id: str,
                                   project: dict) -> None:
        """Archive the previous run's console so a re-launch doesn't wipe it.

        Skips archiving when the tool was paused — the console must persist
        and the resumed run appends to it.
        """
        with self._lock:
            buf = (self._console_buffers.get(project_id) or {}).get(tool_id, [])
            has_content = bool(buf)
            cur_status = (self._tool_status.get(project_id) or {}).get(tool_id)
        if not has_content:
            return
        if cur_status == "paused":
            return
        try:
            proj_dir = self._resolve_project_dir(project_id)
            if not proj_dir:
                return
            with self._lock:
                tool_dir = (self._tool_output_dirs.get(project_id) or {}).get(tool_id)
            cl = self._console_log_path(proj_dir, tool_id, tool_dir)
            if cl.exists() and cl.stat().st_size > 0:
                ts = time.strftime("%Y%m%d_%H%M%S")
                archive = cl.with_name(cl.stem + f"_{ts}" + cl.suffix)
                try:
                    cl.rename(archive)
                except OSError as exc:
                    log.warning("reset_for_new_run: archive rename: %s", exc)
        except Exception as exc:
            log.warning("reset_for_new_run: console archive for %s: %s",
                        tool_id, exc)
        hp = self._history_path(self._resolve_project_dir(project_id) or "")
        if hp.exists():
            try:
                history = json.loads(hp.read_text())
                if tool_id in history:
                    prev = history.pop(tool_id)
                    history[f"{tool_id}:{prev.get('ended_at', 'prev')}"] = prev
                    hp.write_text(json.dumps(history, indent=2))
            except (json.JSONDecodeError, OSError) as exc:
                log.warning("reset_for_new_run: history rotate for %s: %s",
                            tool_id, exc)
        with self._lock:
            bufs = self._console_buffers.get(project_id)
            if bufs and tool_id in bufs:
                bufs[tool_id] = []

    def clear_console(self, project_id: str, tool_id: str, *,
                      scope: str | None = None) -> None:
        """Clear the console buffer for a tool."""
        tk = _tkey(tool_id, scope)
        with self._lock:
            bufs = self._console_buffers.get(project_id)
            if bufs and tk in bufs:
                bufs[tk].clear()

    def remove_tool_session(self, project_id: str, tool_id: str) -> None:
        """Fully remove a tool's session data — all scope-qualified keys,
        console buffers, status, metadata, and history."""
        prefix = tool_id + ":"
        with self._lock:
            for store in (self._console_buffers, self._tool_status,
                          self._phase_cache,
                          self._procs, self._tool_metadata,
                          self._answer_queues, self._pending_prompts,
                          self._tool_output_dirs):
                d = store.get(project_id)
                if not d:
                    continue
                keys = [k for k in d
                        if k == tool_id or k.startswith(prefix)]
                for k in keys:
                    d.pop(k, None)

        # Remove from persisted history
        proj = self._resolve_project(project_id)
        if proj:
            pd = proj.get("project_dir", "")
            if pd:
                hf = Path(pd) / ".crucible" / "tool_history.json"
                if hf.exists():
                    try:
                        history = json.loads(hf.read_text())
                        keys = [k for k in history
                                if k == tool_id or k.startswith(prefix)]
                        for k in keys:
                            history.pop(k, None)
                        hf.write_text(json.dumps(history, indent=2))
                    except (json.JSONDecodeError, OSError) as exc:
                        log.warning("remove_tool_session: history "
                                    "update for %s: %s", tool_id, exc)

    # ── internal helpers ─────────────────────────────────────────────────

    def _is_running_locked(self, project_id: str, tool_id: str) -> bool:
        """Check running state — caller MUST hold ``_lock``."""
        proc = (self._procs.get(project_id) or {}).get(tool_id)
        if proc and proc.poll() is None:
            return True
        orphan_pid = (self._orphan_pids.get(project_id) or {}).get(tool_id)
        if orphan_pid and self._is_pid_alive(orphan_pid):
            return True
        # Status might say "running"/"pausing" but process is gone — fix it.
        status = (self._tool_status.get(project_id) or {}).get(tool_id)
        if status == "running":
            self._tool_status.setdefault(project_id, {})[tool_id] = "failed"
        elif status == "pausing":
            self._tool_status.setdefault(project_id, {})[tool_id] = "paused"
        return False

    def _ensure_buffers_locked(self, project_id: str, tool_id: str) -> None:
        """Initialise buffer structures — caller MUST hold ``_lock``."""
        self._procs.setdefault(project_id, {})
        self._tool_status.setdefault(project_id, {})
        self._console_buffers.setdefault(project_id, {}).setdefault(tool_id, [])
        self._answer_queues.setdefault(project_id, {})
        self._pending_prompts.setdefault(project_id, {})

    def _append_console(self, project_id: str, tool_id: str,
                        entry: dict) -> None:
        """Add entry to console ring buffer (enforces MAX_CONSOLE_LINES)
        and stream to console log on disk so full output survives."""
        with self._lock:
            buf = (self._console_buffers
                   .setdefault(project_id, {})
                   .setdefault(tool_id, []))
            buf.append(entry)
            if len(buf) > MAX_CONSOLE_LINES:
                del buf[0]
        self._stream_console_line(project_id, tool_id, entry)

    def _stream_console_line(self, project_id: str, tool_id: str,
                             entry: dict) -> None:
        """Append a single console line to the on-disk log (real-time).

        Persists the timestamp alongside the text so console replay for
        completed tools retains auditability (§14j).  Format:
        ``[HH:MM:SS] text`` — parsed back by ``_read_console_log``.
        """
        try:
            proj_dir = self._resolve_project_dir(project_id)
            if not proj_dir:
                return
            with self._lock:
                tool_dir = (self._tool_output_dirs.get(project_id) or {}).get(tool_id)
            cl = self._console_log_path(proj_dir, tool_id, tool_dir)
            cl.parent.mkdir(parents=True, exist_ok=True)
            ts = entry.get("ts") or ""
            text = entry.get("text") or ""
            line = f"[{ts}] {text}" if ts else text
            with open(cl, "a", errors="replace") as fh:
                fh.write(line + "\n")
        except OSError as exc:
            log.debug("_persist_console_line: write %s: %s", cl, exc)

    def _update_system_info(self, project):
        """Write/update system_info.json in the project directory."""
        try:
            from models.project import _persist_system_info
            proj_dir = project.get("project_dir", "")
            if proj_dir:
                _persist_system_info(proj_dir)
        except Exception as exc:
            log.warning("_update_system_info: %s", exc)

    def _emit_console(self, project_id: str, tool_id: str, text: str,
                      stream: str = "stdout") -> None:
        """Append to buffer, emit ``console_line`` event, persist to disk."""
        entry = {
            "project_id": project_id,
            "tool_id": tool_id,
            "ts": _now_ts(),
            "stream": stream,
            "text": text,
        }
        self._append_console(project_id, tool_id, entry)
        try:
            self.socketio.emit("console_line", entry,
                               room=_room(project_id))
        except Exception as exc:
            log.warning("_emit_console: socketio emit failed: %s", exc)
        if stream in ("system", "stderr"):
            self._persist_log_entry(project_id, tool_id, text, stream)

    def _persist_log_entry(self, project_id: str, tool_id: str,
                           text: str, stream: str,
                           level: str | None = None) -> None:
        """Persist a log/error entry to the project's on-disk JSONL files."""
        try:
            from models.project import get_project
            proj = get_project(project_id)
            if not proj:
                return
            proj_dir = proj.get("project_dir", "")
            if not proj_dir:
                return
            from models.logs import append_log, append_error
            if level is None:
                level = "ERROR" if stream == "stderr" else "INFO"
            log_entry = {
                "ts": _now_iso(),
                "tool": tool_id,
                "level": level,
                "message": text,
                "source": "crucible",
            }
            append_log(proj_dir, log_entry)
            if level in ("ERROR", "EXCEPTION", "TOOL_ERROR", "FATAL", "CRITICAL"):
                append_error(proj_dir, log_entry)
        except Exception as exc:
            log.warning("_persist_log_entry: %s", exc)

    def _emit_error(self, project_id: str, tool_id: str, msg: str) -> None:
        """Emit an ERROR-level entry to the Errors tab."""
        self._persist_log_entry(project_id, tool_id, msg, "system",
                                level="ERROR")
        try:
            self.socketio.emit("err_entry", {
                "project_id": project_id,
                "tool_id": tool_id,
                "ts": _now_iso(),
                "level": "ERROR",
                "message": msg,
                "source": "crucible",
            }, room=_room(project_id))
        except Exception as exc:
            log.warning("_emit_error: socketio emit failed: %s", exc)

    def _create_rerun_action_item(self, project_id: str, tool_id: str,
                                   scope: str | None, reason: str,
                                   category: str = "rerun") -> None:
        """Create an action item to rerun a tool that was killed or failed."""
        try:
            from models.project import get_project
            proj = get_project(project_id)
            if not proj:
                return
            proj_dir = proj.get("project_dir", "")
            if not proj_dir:
                return
            target = ""
            original_settings = {}
            try:
                from models.settings import load_settings
                original_settings = load_settings(proj_dir, tool_id, scope=scope)
                _target_keys = ("target_url", "api_base_url", "targets", "host")
                for _tk in _target_keys:
                    if original_settings.get(_tk):
                        target = original_settings[_tk]
                        if isinstance(target, list):
                            target = target[0] if target else ""
                        break
            except Exception:
                pass
            from models.action_items import add_action_item
            add_action_item(proj_dir, {
                "title": f"Rerun {tool_id}" + (f" [{scope}]" if scope else ""),
                "description": f"Tool did not complete: {reason}. "
                               f"Rerun to complete testing.",
                "recommended_tool": tool_id,
                "source_tool": "crucible",
                "category": category,
                "scope": scope or "",
                "target": target,
                "priority": "RECOMMENDED",
                "approval_tier": "confirm",
                "status": "pending",
                "in_scope": True,
                "metadata": {
                    "reason": reason, "source": category,
                    "original_settings": original_settings,
                },
            })
        except Exception:
            log.exception("Failed to create rerun action item for %s", tool_id)

    @staticmethod
    def _write_stdin(proc: subprocess.Popen, text: str,
                     project_id: str = "", tool_id: str = "") -> None:
        """Safely write a line to a subprocess stdin."""
        try:
            if proc.stdin and not proc.stdin.closed:
                proc.stdin.write(text + "\n")
                proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            log.debug("_write_stdin: pipe write for %s: %s", tool_id, exc)
        except Exception as exc:
            log.warning("_write_stdin: unexpected error for %s: %s",
                        tool_id, exc)

    # ── reader threads ───────────────────────────────────────────────────

    def _stdout_reader(self, project_id: str, tool_id: str,
                       pipe, proc: subprocess.Popen) -> None:
        """Daemon thread: read stdout line by line, parse tokens, emit."""
        from services.engagement_log_handler import set_engagement_context as _sec
        try:
            from models.project import get_project as _gp
            _prj = _gp(project_id)
            if _prj and _prj.get("project_dir"):
                _sec(project_id, _prj["project_dir"], tool_id)
        except Exception:
            pass
        try:
            for raw_line in pipe:
                try:
                    line = raw_line.rstrip("\n\r")
                    if not line:
                        continue
                    self._process_stdout_line(project_id, tool_id, line, proc)
                except Exception as exc:
                    try:
                        self._emit_console(project_id, tool_id,
                                           f"[Crucible] stdout reader error: {exc}",
                                           "system")
                    except Exception:
                        log.debug("stdout reader: _emit_console fallback "
                                  "failed for %s/%s", project_id[:8], tool_id)
        except (ValueError, OSError) as exc:
            log.debug("stdout reader: pipe closed for %s/%s: %s",
                      project_id[:8], tool_id, exc)
        finally:
            try:
                pipe.close()
            except (BrokenPipeError, OSError) as exc:
                log.debug("stdout reader: pipe.close for %s/%s: %s",
                          project_id[:8], tool_id, exc)

    def _process_stdout_line(self, project_id: str, tool_id: str,
                             line: str, proc: subprocess.Popen) -> None:
        """Handle one stdout line: parse token or emit raw console."""
        token_type, family, payload = self._token_parser.parse_line(line)

        if token_type is None:
            # Plain stdout — emit to console, detect error patterns.
            self._emit_console(project_id, tool_id, line, "stdout")
            if line.lstrip().startswith("[ERROR]"):
                self._persist_log_entry(project_id, tool_id, line,
                                        "stdout", level="TOOL_ERROR")
            return

        # Parse the structured payload.
        data = self._token_parser.parse_payload(token_type, family, payload)
        data["tool_id"] = tool_id
        data["project_id"] = project_id

        # Dispatch by token type.
        if token_type == "log":
            self._handle_log(project_id, tool_id, data, line)
        elif token_type == "error":
            self._handle_error(project_id, tool_id, data, line)
        elif token_type == "status":
            self._handle_status(project_id, tool_id, data, line)
        elif token_type == "prompt":
            self._handle_prompt(project_id, tool_id, data, proc)
        elif token_type == "action_item":
            self._handle_action_item(project_id, tool_id, data)
        elif token_type == "target":
            self._handle_target(project_id, tool_id, data)
        elif token_type == "port":
            self._handle_port(project_id, tool_id, data)
        elif token_type == "finding":
            self._handle_finding(project_id, tool_id, data)
        else:
            # Unknown token type — pass through as console line.
            self._emit_console(project_id, tool_id, line, "stdout")

    def _handle_log(self, project_id: str, tool_id: str, data: dict,
                    raw_line: str) -> None:
        """Route a LOG token: emit to tool_log, mirror to console, persist."""
        data["project_id"] = project_id
        data["tool_id"] = tool_id
        level = data.get("level", "INFO")
        msg = data.get("message", "")
        self._emit_console(project_id, tool_id,
                           f"[{level}] {msg}", "stdout")
        self._persist_log_entry(project_id, tool_id, msg, "stdout",
                                level=level)
        try:
            self.socketio.emit("tool_log", data,
                               room=_room(project_id))
        except Exception as exc:
            log.warning("_handle_log: socketio emit failed: %s", exc)
        msg_lower = (msg or "").lower()
        if tool_id == "ss3" and "route" in msg_lower and (
                "added" in msg_lower or "setup" in msg_lower
                or "complete" in msg_lower):
            self._capture_post_route_snapshot(project_id)

    def _capture_post_route_snapshot(self, project_id: str) -> None:
        """Capture ip route after SS3 adds routes (once per engagement)."""
        try:
            proj = self._resolve_project(project_id)
            eng_dir = (proj or {}).get(
                "engagement_dir", (proj or {}).get("project_dir", ""))
            if not eng_dir:
                return
            from models.project import capture_post_route_snapshot
            capture_post_route_snapshot(eng_dir)
        except Exception as exc:
            log.warning("_capture_post_route_snapshot: %s", exc)

    def _handle_error(self, project_id: str, tool_id: str, data: dict,
                      raw_line: str) -> None:
        """Route an ERROR token: emit to tool_error, mirror to console, persist."""
        data["project_id"] = project_id
        data["tool_id"] = tool_id
        msg = data.get("message", "")
        level = data.get("level", "ERROR")
        self._emit_console(project_id, tool_id,
                           f"[ERR] {msg}", "stderr")
        self._persist_log_entry(project_id, tool_id, msg, "stderr",
                                level=level)
        try:
            self.socketio.emit("tool_error", data,
                               room=_room(project_id))
        except Exception as exc:
            log.warning("_handle_error: socketio emit failed: %s", exc)

    def _handle_status(self, project_id: str, tool_id: str, data: dict,
                       raw_line: str) -> None:
        """Route a STATUS token: emit to tool_status, mirror phase to console."""
        data["project_id"] = project_id
        data["tool_id"] = tool_id
        phase_key = data.get("phase")
        if phase_key:
            with self._lock:
                pc = self._phase_cache.setdefault(project_id, {})
                entry = pc.setdefault(tool_id, {}).get(phase_key, {})
                new_entry = {
                    k: data.get(k) for k in
                    ("status", "step", "label", "tools", "active_tools",
                     "active_tool", "ts", "target", "target_total",
                     "progress", "total")
                    if data.get(k) is not None
                }
                # Build accumulated per-subtool status from active_tool(s)
                # or from step field when no active_tool(s) are provided
                at = data.get("active_tools") or (
                    [data["active_tool"]] if data.get("active_tool") else None)
                prev_subtools = entry.get("_subtool_status", {})
                if at is not None:
                    for name in at:
                        n = name if isinstance(name, str) else (
                            name.get("name", "") if isinstance(name, dict) else str(name))
                        if n:
                            prev_subtools[n] = {"status": "running"}
                    # Mark previously-running subtools not in current list as complete
                    phase_st = data.get("status", "running")
                    if phase_st == "running":
                        at_set = set(
                            (x if isinstance(x, str) else x.get("name", ""))
                            for x in at)
                        for n, info in prev_subtools.items():
                            if info.get("status") == "running" and n not in at_set:
                                prev_subtools[n] = {"status": "complete"}
                elif data.get("step") and data.get("status") == "running":
                    step_name = data["step"]
                    _is_counter = bool(re.search(r'\b\d+/\d+\b', step_name))
                    if _is_counter:
                        for n, info in prev_subtools.items():
                            if info.get("status") == "running":
                                prev_subtools[n] = {"status": "complete"}
                    else:
                        for n, info in prev_subtools.items():
                            if info.get("status") == "running" and n != step_name:
                                prev_subtools[n] = {"status": "complete"}
                        prev_subtools[step_name] = {"status": "running"}
                if data.get("status") in ("complete", "skipped", "error"):
                    for n in prev_subtools:
                        if prev_subtools[n].get("status") == "running":
                            prev_subtools[n] = {"status": data["status"]}
                if data.get("tools"):
                    for n, info in data["tools"].items():
                        prev_subtools[n] = info
                new_entry["_subtool_status"] = prev_subtools
                if prev_subtools:
                    new_entry["tools"] = prev_subtools
                pc.setdefault(tool_id, {})[phase_key] = new_entry
                if prev_subtools and "tools" not in data:
                    data["tools"] = dict(prev_subtools)
        step = data.get("step", "")
        label = data.get("label", data.get("phase", "?"))
        if step:
            self._emit_console(project_id, tool_id,
                               f"[{label}] {step}", "stdout")
        try:
            self.socketio.emit("tool_status", data,
                               room=_room(project_id))
        except Exception as exc:
            log.warning("_handle_status: socketio emit failed: %s", exc)

    def _handle_prompt(self, project_id: str, tool_id: str, data: dict,
                       proc: subprocess.Popen) -> None:
        """Route a PROMPT token: emit modal, block until answer, feed stdin."""
        prompt_id = data.get("id", str(uuid.uuid4()))
        data.setdefault("id", prompt_id)

        with self._lock:
            self._pending_prompts.setdefault(project_id, {})[tool_id] = data

        try:
            self.socketio.emit("tool_prompt",
                               {"project_id": project_id,
                                "tool_id": tool_id, "payload": data},
                               room=_room(project_id))
        except Exception as exc:
            self._emit_console(project_id, tool_id,
                               f"[Crucible] prompt emit error: {exc}", "system")

        # Block the stdout reader until the UI answers.
        with self._lock:
            q = (self._answer_queues.get(project_id) or {}).get(tool_id)

        if q:
            try:
                answer = q.get(timeout=_PROMPT_TIMEOUT)
            except queue.Empty:
                answer = ""
            self._write_stdin(proc, answer, project_id, tool_id)
        else:
            self._emit_console(project_id, tool_id,
                               "[Crucible] No answer queue for prompt — "
                               "subprocess may be stuck", "system")

        with self._lock:
            self._pending_prompts.setdefault(project_id, {})[tool_id] = {}

        try:
            self.socketio.emit("prompt_resolved",
                               {"project_id": project_id,
                                "tool_id": tool_id, "prompt_id": prompt_id},
                               room=_room(project_id))
        except Exception as exc:
            log.warning("_handle_prompt: prompt_resolved emit: %s", exc)

    def _handle_action_item(self, project_id: str, tool_id: str,
                            data: dict) -> None:
        """Route an ACTION_ITEM token and persist via ActionEngine."""
        data.setdefault("source_tool", tool_id)
        self._emit_console(project_id, tool_id,
                           f"[ACTION] {data.get('title', data.get('message', ''))}",
                           "stdout")
        saved = None
        if self._action_engine:
            try:
                proj = self._resolve_project(project_id)
                proj_dir = proj.get("project_dir", "") if proj else ""
                if proj_dir:
                    saved = self._action_engine.process_action_item_token(
                        proj_dir, data, project=proj)
            except Exception as exc:
                log.warning("ActionEngine token error: %s", exc)
        if saved:
            try:
                self.socketio.emit("tool_action_item", saved,
                                   room=_room(project_id))
            except Exception as exc:
                log.warning("_handle_action_item: socketio emit: %s", exc)

    # ── Live targets cache + disk persistence ──────────────────────────

    _RISK_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    def _live_record_target(self, project_id, tool_id, tdata):
        ip = (tdata.get("ip") or tdata.get("host") or "").strip()
        if not ip:
            return
        with self._lock:
            bucket = self._live_targets.setdefault(project_id, {})
            ent = bucket.get(ip)
            if ent is None:
                ent = {
                    "ip": ip,
                    "scope": tdata.get("scope") or "",
                    "hostname": tdata.get("hostname") or "",
                    "os": tdata.get("os") or "",
                    "tools": ["nmap"],
                    "ports": {},
                    "top_risk": "",
                    "finding_count": 0,
                }
                bucket[ip] = ent
            else:
                if tdata.get("hostname") and not ent.get("hostname"):
                    ent["hostname"] = tdata["hostname"]
                if tdata.get("os") and not ent.get("os"):
                    ent["os"] = tdata["os"]
                if tdata.get("scope") and not ent.get("scope"):
                    ent["scope"] = tdata["scope"]
        self._schedule_live_flush(project_id, tool_id)

    def _live_record_port(self, project_id, tool_id, pdata):
        ip = (pdata.get("ip") or "").strip()
        if not ip or pdata.get("port") is None:
            return
        try:
            port = int(pdata["port"])
        except (TypeError, ValueError):
            return
        svc_parts = [p for p in (pdata.get("name", ""),
                                  pdata.get("product", ""),
                                  pdata.get("version", "")) if p]
        sw_str = " ".join(p for p in (pdata.get("product", ""),
                                       pdata.get("version", "")) if p).strip()
        with self._lock:
            bucket = self._live_targets.setdefault(project_id, {})
            ent = bucket.get(ip)
            if ent is None:
                ent = {
                    "ip": ip,
                    "scope": pdata.get("scope") or "",
                    "hostname": pdata.get("hostname") or "",
                    "os": "",
                    "tools": ["nmap"],
                    "ports": {},
                    "top_risk": "",
                    "finding_count": 0,
                }
                bucket[ip] = ent
            existing = ent["ports"].get(port)
            if existing is None:
                ent["ports"][port] = {
                    "port": port,
                    "protocol": pdata.get("proto") or "tcp",
                    "service": " / ".join(svc_parts) if svc_parts
                               else (pdata.get("name") or ""),
                    "state": pdata.get("state", "open"),
                    "software": [sw_str] if sw_str else [],
                }
            else:
                if svc_parts and not existing.get("service"):
                    existing["service"] = " / ".join(svc_parts)
                if sw_str and sw_str not in existing.get("software", []):
                    existing.setdefault("software", []).append(sw_str)
                if pdata.get("state") == "open":
                    existing["state"] = "open"
        self._schedule_live_flush(project_id, tool_id)

    def _live_record_finding(self, project_id, fdata):
        ip = (fdata.get("ip") or "").strip()
        risk = (fdata.get("risk") or "INFO").upper()
        if not ip:
            return
        with self._lock:
            bucket = self._live_targets.get(project_id, {})
            ent = bucket.get(ip)
            if not ent:
                return
            ent["finding_count"] = ent.get("finding_count", 0) + 1
            cur = ent.get("top_risk") or ""
            try:
                if not cur or self._RISK_ORDER.index(risk) < self._RISK_ORDER.index(cur):
                    ent["top_risk"] = risk
            except ValueError as exc:
                log.debug("_live_record_finding: unknown risk %r: %s", risk, exc)
            port = fdata.get("port")
            if port is not None:
                try:
                    port = int(port)
                except (TypeError, ValueError):
                    port = None
            if port and port in ent.get("ports", {}):
                pent = ent["ports"][port]
                pent["finding_count"] = pent.get("finding_count", 0) + 1
                pcur = pent.get("risk") or ""
                try:
                    if not pcur or self._RISK_ORDER.index(risk) < self._RISK_ORDER.index(pcur):
                        pent["risk"] = risk
                except ValueError as exc:
                    log.debug("_live_record_finding: unknown port risk %r: %s",
                              risk, exc)

    def _schedule_live_flush(self, project_id, tool_id):
        key = _pkey(project_id, tool_id)
        with self._lock:
            old = self._live_flush_timers.get(key)
            if old:
                old.cancel()
            timer = threading.Timer(
                2.0, self._flush_live_targets,
                args=(project_id, tool_id, key))
            timer.daemon = True
            self._live_flush_timers[key] = timer
            timer.start()

    def _flush_live_targets(self, project_id, tool_id, key):
        with self._lock:
            self._live_flush_timers.pop(key, None)
            bucket = self._live_targets.get(project_id, {})
            if not bucket:
                return
            hosts_by_scope = {}
            services = {}
            for ip, ent in bucket.items():
                scope = ent.get("scope") or "ext"
                host_entry = {
                    "ip": ent["ip"],
                    "hostname": ent.get("hostname") or "",
                    "os": ent.get("os") or "",
                    "tools": list(ent.get("tools", [])),
                    "top_risk": ent.get("top_risk") or "",
                    "finding_count": ent.get("finding_count", 0),
                    "ports": [],
                }
                for pnum, pent in sorted(ent.get("ports", {}).items()):
                    port_entry = {
                        "port": pent["port"],
                        "protocol": pent.get("protocol", "tcp"),
                        "service": pent.get("service", ""),
                        "state": pent.get("state", "open"),
                        "software": pent.get("software", []),
                    }
                    host_entry["ports"].append(port_entry)
                    svc_name = pent.get("service") or "unknown"
                    services.setdefault(svc_name, []).append({
                        "ip": ip, "port": pent["port"],
                        "protocol": pent.get("protocol", "tcp"),
                        "state": pent.get("state", "open"),
                    })
                hosts_by_scope.setdefault(scope, []).append(host_entry)

        project = self._resolve_project(project_id)
        if not project:
            return
        eng_dir = project.get("engagement_dir", project.get("project_dir", ""))
        if not eng_dir:
            return

        base_tool = tool_id.split(":")[0] if ":" in tool_id else tool_id
        try:
            for scope, hosts in hosts_by_scope.items():
                from config import TOOL_OUTPUT_DIRS
                if base_tool == "ss3":
                    scope_name = "internal" if scope == "int" else "external"
                    tool_dirname = TOOL_OUTPUT_DIRS.get("ss3", "scattershot")
                    scope_dir = Path(eng_dir) / scope_name / tool_dirname
                else:
                    td = (project.get("tool_dirs") or {}).get(base_tool, "")
                    if td:
                        scope_dir = Path(td) / scope
                    else:
                        scope_dir = Path(eng_dir) / TOOL_OUTPUT_DIRS.get(base_tool, base_tool)
                scope_dir.mkdir(parents=True, exist_ok=True)
                hosts_file = scope_dir / "hosts.json"
                hosts_file.write_text(json.dumps(hosts, indent=2))
                svc_file = scope_dir / "services.json"
                svc_file.write_text(json.dumps(services, indent=2))
        except Exception as exc:
            log.warning("Failed to flush live targets to disk: %s", exc)

    def get_live_targets(self, project_id):
        with self._lock:
            bucket = self._live_targets.get(project_id, {})
            out = []
            for ip, ent in bucket.items():
                out.append({
                    "ip": ent["ip"],
                    "scope": ent.get("scope") or "",
                    "hostname": ent.get("hostname") or "",
                    "os": ent.get("os") or "",
                    "tools": list(ent.get("tools", [])),
                    "ports": list(ent.get("ports", {}).values()),
                    "top_risk": ent.get("top_risk") or "",
                    "finding_count": int(ent.get("finding_count") or 0),
                })
            return out

    def _live_targets_clear(self, project_id):
        with self._lock:
            self._live_targets.pop(project_id, None)

    # ── token handlers ───────────────────────────────────────────────

    def _handle_target(self, project_id: str, tool_id: str,
                       data: dict) -> None:
        """Route a TARGET token and generate action items."""
        data["project_id"] = project_id
        data["tool_id"] = tool_id
        ip = data.get("ip", data.get("host", ""))
        self._emit_console(project_id, tool_id,
                           f"[TARGET] {ip}", "stdout")
        self._live_record_target(project_id, tool_id, data)
        if self._action_engine:
            try:
                proj_dir = self._resolve_project_dir(project_id)
                project = self._resolve_project(project_id)
                if proj_dir:
                    base_tool = tool_id.split(":")[0] if ":" in tool_id else tool_id
                    reg_scope = self._get_tool_scope(project_id, base_tool)
                    if reg_scope:
                        data.setdefault("scope", reg_scope)
                    self._action_engine.process_target_discovery(
                        proj_dir, data, tool_id, project=project)
            except Exception as exc:
                log.warning("ActionEngine target error: %s", exc)
        try:
            self.socketio.emit("tool_target", data,
                               room=_room(project_id))
        except Exception as exc:
            log.warning("_handle_target: socketio emit: %s", exc)

    def _handle_port(self, project_id: str, tool_id: str,
                     data: dict) -> None:
        """Route a PORT token and generate action items."""
        data["project_id"] = project_id
        data["tool_id"] = tool_id
        ip = data.get("ip", "")
        port = data.get("port", "")
        self._emit_console(project_id, tool_id,
                           f"[PORT] {ip}:{port}", "stdout")
        self._live_record_port(project_id, tool_id, data)
        if self._action_engine:
            try:
                proj_dir = self._resolve_project_dir(project_id)
                project = self._resolve_project(project_id)
                if proj_dir:
                    base_tool = tool_id.split(":")[0] if ":" in tool_id else tool_id
                    reg_scope = self._get_tool_scope(project_id, base_tool)
                    if reg_scope:
                        data.setdefault("scope", reg_scope)
                    self._action_engine.process_port_discovery(
                        proj_dir, data, tool_id, project=project)
            except Exception as exc:
                log.warning("ActionEngine port error: %s", exc)
        try:
            self.socketio.emit("tool_port", data,
                               room=_room(project_id))
        except Exception as exc:
            log.warning("_handle_port: socketio emit: %s", exc)

    def _handle_finding(self, project_id: str, tool_id: str,
                        data: dict) -> None:
        """Route a FINDING token and generate action items."""
        data["project_id"] = project_id
        data["tool_id"] = tool_id
        title = data.get("title", data.get("message", ""))
        if not title or not title.strip():
            return
        risk = data.get("risk", "INFO")
        self._emit_console(project_id, tool_id,
                           f"[FINDING/{risk}] {title}", "stdout")
        self._live_record_finding(project_id, data)
        base_tool = tool_id.split(":")[0] if ":" in tool_id else tool_id
        data.setdefault("tool", base_tool)
        registered_scope = self._get_tool_scope(project_id, base_tool)
        if registered_scope:
            data["scope"] = registered_scope
        if self._findings_engine:
            try:
                project = self._resolve_project(project_id)
                self._findings_engine.add_live_finding(
                    project_id, data, project=project)
            except Exception as exc:
                log.warning("FindingsEngine live inject error: %s", exc)
        try:
            self.socketio.emit("tool_finding", data,
                               room=_room(project_id))
        except Exception as exc:
            log.warning("_handle_finding: socketio emit: %s", exc)
        if self._action_engine:
            try:
                proj_dir = self._resolve_project_dir(project_id)
                project = self._resolve_project(project_id)
                if proj_dir:
                    base_tool = tool_id.split(":")[0] if ":" in tool_id else tool_id
                    self._action_engine.process_finding(
                        proj_dir, data, base_tool, project=project)
            except Exception as exc:
                log.warning("ActionEngine finding error: %s", exc)

    # ── stderr reader ────────────────────────────────────────────────────

    def _stderr_reader(self, project_id: str, tool_id: str,
                       pipe, proc: subprocess.Popen) -> None:
        """Daemon thread: read stderr char-by-char.

        Accumulates characters into lines.  When a sudo password prompt is
        detected (which may not end with a newline), immediately emits a
        ``tool_prompt`` event and blocks until the UI answers.
        """
        from services.engagement_log_handler import set_engagement_context as _sec
        try:
            from models.project import get_project as _gp
            _prj = _gp(project_id)
            if _prj and _prj.get("project_dir"):
                _sec(project_id, _prj["project_dir"], tool_id)
        except Exception:
            pass
        buf = ""
        try:
            while True:
                try:
                    ch = pipe.read(1)
                except (ValueError, OSError):
                    break
                if not ch:
                    # EOF — flush remaining buffer.
                    if buf.strip():
                        self._process_stderr_line(project_id, tool_id,
                                                  buf.rstrip("\r"), proc)
                    break
                if ch == "\n":
                    self._process_stderr_line(project_id, tool_id,
                                             buf.rstrip("\r"), proc)
                    buf = ""
                else:
                    buf += ch
                    # Check for sudo password prompt mid-line (no newline).
                    if _SUDO_PROMPT_RE.search(buf):
                        self._handle_sudo_prompt(project_id, tool_id,
                                                 buf.strip(), proc)
                        buf = ""
        except Exception as exc:
            log.warning("stderr reader: unexpected error for %s/%s: %s",
                        project_id[:8], tool_id, exc)
        finally:
            try:
                pipe.close()
            except (BrokenPipeError, OSError) as exc:
                log.debug("stderr reader: pipe.close for %s/%s: %s",
                          project_id[:8], tool_id, exc)

    def _process_stderr_line(self, project_id: str, tool_id: str,
                             line: str, proc=None) -> None:
        """Handle one complete stderr line.

        Lines are emitted to the console immediately for real-time display
        but buffered for persistence — consecutive lines are merged into a
        single error entry after a brief quiet period.

        If the line carries a known protocol token (tools sometimes write
        tokens to stderr via Python's logging module), route it through
        the stdout token parser instead.
        """
        if not line:
            return
        if _SUDO_PROMPT_RE.search(line):
            return

        if self._token_parser.is_token(line) and proc is not None:
            self._process_stdout_line(project_id, tool_id, line, proc)
            return

        entry = {
            "project_id": project_id,
            "tool_id": tool_id,
            "ts": _now_ts(),
            "stream": "stderr",
            "text": line,
        }
        self._append_console(project_id, tool_id, entry)
        try:
            self.socketio.emit("console_line", entry,
                               room=_room(project_id))
        except Exception as exc:
            log.warning("_process_stderr_line: emit failed for %s/%s: %s",
                        project_id[:8], tool_id, exc)

        key = _pkey(project_id, tool_id)
        with self._lock:
            self._stderr_accum.setdefault(key, []).append(line)
            old_timer = self._stderr_timers.get(key)
            if old_timer:
                old_timer.cancel()
            timer = threading.Timer(
                0.5, self._flush_stderr,
                args=(project_id, tool_id, key))
            timer.daemon = True
            self._stderr_timers[key] = timer
            timer.start()

    def _flush_stderr(self, project_id: str, tool_id: str,
                      key: str) -> None:
        """Flush buffered stderr lines as a single merged error entry."""
        with self._lock:
            lines = self._stderr_accum.pop(key, [])
            self._stderr_timers.pop(key, None)
        if not lines:
            return
        merged = "\n".join(lines)
        self._persist_log_entry(project_id, tool_id, merged, "stderr")
        try:
            self.socketio.emit("tool_error", {
                "project_id": project_id,
                "tool_id": tool_id,
                "ts": _now_iso(),
                "source": tool_id,
                "message": merged,
                "stream": "stderr",
            }, room=_room(project_id))
        except Exception as exc:
            log.warning("_flush_stderr: emit failed for %s/%s: %s",
                        project_id[:8], tool_id, exc)

    def _handle_sudo_prompt(self, project_id: str, tool_id: str,
                            prompt_text: str,
                            proc: subprocess.Popen) -> None:
        """Emit a sudo password prompt event and block for the answer."""
        payload = {
            "id": str(uuid.uuid4()),
            "question": f"Sudo password required  ({prompt_text})",
            "type": "password",
            "options": [],
            "skippable": False,
        }

        with self._lock:
            self._pending_prompts.setdefault(project_id, {})[tool_id] = payload

        try:
            self.socketio.emit("tool_prompt",
                               {"project_id": project_id,
                                "tool_id": tool_id, "payload": payload},
                               room=_room(project_id))
        except Exception as exc:
            log.warning("_handle_sudo_prompt: emit failed for %s/%s: %s",
                        project_id[:8], tool_id, exc)

        with self._lock:
            q = (self._answer_queues.get(project_id) or {}).get(tool_id)

        if q:
            try:
                answer = q.get(timeout=300)
            except queue.Empty:
                answer = ""
            self._write_stdin(proc, answer, project_id, tool_id)

        with self._lock:
            self._pending_prompts.setdefault(project_id, {})[tool_id] = {}

    # ── wait thread ──────────────────────────────────────────────────────

    def _wait_proc(self, project_id: str, tool_id: str,
                   proc: subprocess.Popen) -> None:
        """Daemon thread: wait for process exit and update state."""
        from services.engagement_log_handler import set_engagement_context as _sec
        try:
            from models.project import get_project as _gp
            _prj = _gp(project_id)
            if _prj and _prj.get("project_dir"):
                _sec(project_id, _prj["project_dir"], tool_id)
        except Exception:
            pass
        try:
            self._wait_proc_inner(project_id, tool_id, proc)
        except Exception:
            log.exception("_wait_proc crashed for %s/%s — "
                          "setting status to failed as safety net",
                          project_id[:8], tool_id)
            try:
                with self._lock:
                    self._tool_status.setdefault(
                        project_id, {})[tool_id] = "failed"
                    self._procs.setdefault(
                        project_id, {})[tool_id] = None
            except Exception:
                log.warning("_wait_proc: failed to set status for %s/%s",
                            project_id[:8], tool_id)
            try:
                self.socketio.emit("tool_status", {
                    "project_id": project_id,
                    "tool_id": tool_id,
                    "status": "failed",
                }, room=_room(project_id))
            except Exception:
                log.warning("_wait_proc: socketio emit failed for %s/%s",
                            project_id[:8], tool_id)
            try:
                self._emit_console(
                    project_id, tool_id,
                    f"[Crucible] INTERNAL ERROR: wait thread crashed — "
                    f"tool marked as failed. Check system logs.",
                    "system")
            except Exception:
                log.debug("_wait_proc: _emit_console fallback failed for %s/%s",
                          project_id[:8], tool_id)

    def _wait_proc_inner(self, project_id: str, tool_id: str,
                         proc: subprocess.Popen) -> None:
        """Inner body of _wait_proc — separated so the outer method
        can catch any unhandled exception."""
        rc = proc.wait()

        # Close any remaining pipes.
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            if pipe is not None:
                try:
                    pipe.close()
                except (BrokenPipeError, OSError) as exc:
                    log.debug("_wait_proc: pipe close for %s: %s",
                              tool_id, exc)

        # Flush any remaining buffered stderr lines.
        key = _pkey(project_id, tool_id)
        with self._lock:
            old_timer = self._stderr_timers.get(key)
            if old_timer:
                old_timer.cancel()
        self._flush_stderr(project_id, tool_id, key)

        # Determine final status.
        with self._lock:
            cur_status = (self._tool_status.get(project_id) or {}).get(tool_id)
            if cur_status == "killed":
                final_status = "killed"
            elif rc == EXIT_PAUSED or cur_status == "pausing":
                final_status = "paused"
            elif rc == 0:
                final_status = "complete"
            elif rc is not None and rc < 0:
                # Negative rc = killed by signal (OOM, external kill -9, etc.)
                final_status = "killed"
            else:
                final_status = "failed"

            self._tool_status.setdefault(project_id, {})[tool_id] = final_status
            self._procs.setdefault(project_id, {})[tool_id] = None

            # Clean up answer queue and pending prompt.
            aq = self._answer_queues.get(project_id)
            if aq:
                aq.pop(tool_id, None)
            pp = self._pending_prompts.get(project_id)
            if pp:
                pp.pop(tool_id, None)

        base_tool = tool_id.split(":")[0] if ":" in tool_id else tool_id
        tool_name = TOOLS.get(base_tool, {}).get("name", tool_id)

        self._emit_console(project_id, tool_id,
                           f"[Crucible] {tool_name} exited — "
                           f"return code {rc}  (status: {final_status})",
                           "system")

        self.socketio.emit("tool_status",
                           {"project_id": project_id,
                            "tool_id": tool_id, "status": final_status,
                            "returncode": rc},
                           room=_room(project_id))

        self.socketio.emit("tool_done",
                           {"project_id": project_id,
                            "tool_id": tool_id, "returncode": rc,
                            "status": final_status},
                           room=_room(project_id))

        self._persist_history(project_id, tool_id, final_status, rc)

        if final_status in ("paused", "killed", "failed"):
            self._emit_checkpoint_status(project_id, tool_id)

        app = getattr(self._queue_manager, "_app", None) if self._queue_manager else None
        ctx = app.app_context() if app else None
        if ctx:
            ctx.__enter__()
        try:
            self._post_completion(project_id, tool_id, base_tool, final_status, rc)
        finally:
            if ctx:
                ctx.__exit__(None, None, None)

        with self._lock:
            post_status = (self._tool_status.get(project_id) or {}).get(tool_id)
        if post_status != final_status:
            log.warning("_wait_proc: status for %s changed during "
                        "_post_completion: expected %s, found %s — "
                        "restoring", tool_id, final_status, post_status)
            self._emit_console(project_id, tool_id,
                f"[DIAG] Status changed during post-completion! "
                f"Expected {final_status}, found {post_status}. Restoring.",
                "system")
            with self._lock:
                self._tool_status.setdefault(project_id, {})[tool_id] = final_status
        self.socketio.emit("tool_status",
                           {"project_id": project_id,
                            "tool_id": tool_id, "status": final_status,
                            "returncode": rc,
                            "_reemit": True},
                           room=_room(project_id))

    def _post_completion(self, project_id, tool_id, base_tool, final_status, rc):
        """Post-completion tasks that need Flask app context."""
        from models.project import get_project
        _proj = get_project(project_id)
        _audit(_proj.get("project_dir", "") if _proj else "",
               "TOOL_DONE", tool=tool_id, status=final_status, returncode=rc)

        if base_tool in AETHER_TOOLS:
            try:
                from services.wireless import force_radio_cleanup
                force_radio_cleanup()
            except Exception as exc:
                log.warning("force_radio_cleanup failed for %s: %s",
                            tool_id, exc)

        self._emit_checkpoint_status(project_id, tool_id)

        if self._findings_engine:
            self._findings_engine.invalidate(project_id)
            if _proj:
                try:
                    self._findings_engine.refresh(project_id, _proj)
                except Exception as exc:
                    log.warning("post-completion findings refresh: %s", exc)
            self.socketio.emit("findings_updated",
                               {"project_id": project_id},
                               room=_room(project_id))

        # Update action items that launched this tool
        proj_dir = _proj.get("project_dir", "") if _proj else ""
        if proj_dir:
            try:
                from models.action_items import update_tool_action_items_status
                ai_status = "complete" if final_status == "complete" else "failed"
                updated_ids = update_tool_action_items_status(
                    proj_dir, base_tool,
                    from_statuses={"pending", "queued", "running"},
                    new_status=ai_status)
                if updated_ids:
                    self.socketio.emit("action_items_updated",
                        {"project_id": project_id,
                         "status_update": ai_status,
                         "tool_id": base_tool,
                         "item_ids": updated_ids},
                        room=_room(project_id))
            except Exception as exc:
                log.warning("Action item status update error: %s", exc)

        if final_status in ("killed", "failed"):
            rerun_key = _pkey(project_id, tool_id)
            with self._lock:
                already = rerun_key in self._rerun_created
            if not already:
                scope = tool_id.split(":", 1)[1] if ":" in tool_id else None
                cat = "rerun_killed" if final_status == "killed" else "rerun_failed"
                reason = (f"{tool_name} was killed (return code {rc})"
                          if final_status == "killed"
                          else f"{tool_name} failed with return code {rc}")
                self._create_rerun_action_item(
                    project_id, base_tool, scope, reason, category=cat)
            with self._lock:
                self._rerun_created.discard(rerun_key)

        if self._action_engine:
            try:
                if proj_dir:
                    generated = 0
                    if final_status == "complete":
                        generated = self._action_engine.process_completed_findings(
                            proj_dir, project=_proj)
                    elif base_tool == "osift":
                        generated = self._action_engine._process_osift_oos_targets(
                            proj_dir, project=_proj)
                    if generated:
                        self._emit_console(project_id, tool_id,
                            f"[Crucible] Generated {generated} action items from findings",
                            "system")
                        self.socketio.emit("action_items_updated",
                            {"project_id": project_id, "generated": generated},
                            room=_room(project_id))
            except Exception as exc:
                log.warning("Post-completion action generation error: %s", exc)
            self.socketio.emit("action_items_updated",
                               {"project_id": project_id},
                               room=_room(project_id))

        # NOTE: No late sweep or cross-tool sweep here.
        # The first sweep (above) marks items for the completing tool.
        # Items created by process_completed_findings() are for NEW runs
        # of potentially the same tool against different targets (e.g. OOS)
        # and must remain pending for auto-queue to pick them up.

        if self._queue_manager:
            try:
                if _proj and _proj.get("auto_queue"):
                    self._emit_console(project_id, tool_id,
                        f"[DIAG] auto_queue=True, calling process_auto_queue "
                        f"(tool_id={tool_id}, status={final_status})",
                        "system")
                    enqueued = self._queue_manager.process_auto_queue(
                        project_id, _proj)
                    self._emit_console(project_id, tool_id,
                        f"[DIAG] process_auto_queue returned: {enqueued} enqueued",
                        "system")
                    if enqueued:
                        self._emit_console(project_id, tool_id,
                            f"[Crucible] Auto-queued {enqueued} tool(s)",
                            "system")
                else:
                    self._emit_console(project_id, tool_id,
                        f"[DIAG] auto_queue={_proj.get('auto_queue') if _proj else 'no_proj'}, "
                        f"skipping process_auto_queue",
                        "system")
            except Exception as exc:
                log.warning("Auto-queue error for %s: %s", project_id, exc)
                self._emit_console(project_id, tool_id,
                    f"[Crucible] Auto-queue error: {exc}", "system")
            try:
                self._emit_console(project_id, tool_id,
                    "[DIAG] calling auto_dequeue", "system")
                self._queue_manager.auto_dequeue(project_id)
                self._emit_console(project_id, tool_id,
                    "[DIAG] auto_dequeue returned", "system")
            except Exception as exc:
                log.warning("Auto-dequeue error for %s: %s", project_id, exc)
                self._emit_console(project_id, tool_id,
                    f"[Crucible] Auto-dequeue error: {exc}", "system")
            with self._lock:
                _diag_st = (self._tool_status.get(project_id) or {}).get(tool_id)
            self._emit_console(project_id, tool_id,
                f"[DIAG] post-completion done. {tool_id} status={_diag_st} "
                f"(expected {final_status})",
                "system")

    def _emit_checkpoint_status(self, project_id: str, tool_id: str) -> None:
        """Notify frontend whether a checkpoint exists for resume."""
        try:
            from models.project import get_project
            from routes.console import _find_checkpoint_candidates
            proj = get_project(project_id)
            if not proj:
                return
            for cp_file in _find_checkpoint_candidates(proj, tool_id):
                if cp_file.exists():
                    try:
                        ck_data = json.loads(cp_file.read_text())
                        info = {
                            "exists": True,
                            "has_checkpoint": True,
                            "version": ck_data.get("version", 1),
                            "resumable": ck_data.get("version", 1) >= 2,
                            "checkpoint_ts": ck_data.get("checkpoint_ts", ""),
                            "completed": len(ck_data.get("completed_phases", [])),
                        }
                        self.socketio.emit(
                            "checkpoint_status",
                            {"project_id": project_id,
                             "tool_id": tool_id, **info},
                            room=_room(project_id))
                        return
                    except Exception as exc:
                        log.debug("checkpoint parse failed for %s: %s",
                                  cp_file, exc)
                        continue
            self.socketio.emit(
                "checkpoint_status",
                {"project_id": project_id, "tool_id": tool_id,
                 "exists": False, "has_checkpoint": False, "resumable": False},
                room=_room(project_id))
        except Exception as exc:
            log.warning("_emit_checkpoint_status failed for %s/%s: %s",
                        project_id[:8], tool_id, exc)
