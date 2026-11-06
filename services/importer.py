"""ImporterService — job lifecycle, queue, threading, console, scope
detection, file placement, and finding injection for the Import tab."""

import json
import logging
import os
import shutil
import threading
import traceback
import uuid
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from config import (IMPORT_MAX_CONCURRENT, IMPORT_TOOL_MAP,
                    TOOL_OUTPUT_DIRS, MAX_CONSOLE_LINES)
from models.logs import append_log, append_error

log = logging.getLogger("crucible.importer")


class ImporterService:
    """Central orchestrator for file imports.

    Manages import jobs, a bounded thread pool, console buffers,
    scope detection, file routing, and finding injection.
    """

    def __init__(self, socketio, findings_engine, action_engine,
                 scope_manager):
        self._sio = socketio
        self._fe = findings_engine
        self._ae = action_engine
        self._sm = scope_manager
        self._lock = threading.Lock()
        self._jobs = {}
        self._active = 0
        self._queue = []
        self._console_buffers = {}
        self._registry = None

    @property
    def registry(self):
        if self._registry is None:
            import sys
            _app_dir = str(Path(__file__).resolve().parent.parent)
            if _app_dir not in sys.path:
                sys.path.insert(0, _app_dir)
            from parsers.registry import ParserRegistry
            self._registry = ParserRegistry()
        return self._registry

    # ── Job creation ────────────────────────────────────────────

    def _create_job(self, project_id, project, file_path,
                    manual_tool=None, scope_override=None):
        """Create an import job for a single file.
        Returns the job dict or None on unrecognized file."""
        fp = Path(file_path)
        if not fp.is_file():
            return None

        if manual_tool:
            parser_cls = self.registry.get_parser(manual_tool)
            tool_name = manual_tool
            reg_tool_id = manual_tool
        else:
            result = self.registry.identify(str(fp))
            if result is None:
                return None
            tool_name, parser_cls = result
            reg_tool_id = self.registry.get_tool_id(tool_name) or tool_name

        if parser_cls is None:
            return None

        crucible_tool_id = (IMPORT_TOOL_MAP.get(reg_tool_id)
                            or IMPORT_TOOL_MAP.get(tool_name, reg_tool_id))

        job_id = str(uuid.uuid4())[:8]
        job = {
            "id": job_id,
            "project_id": project_id,
            "file_path": str(fp),
            "filename": fp.name,
            "tool": tool_name,
            "tool_id": crucible_tool_id,
            "manual_tool": manual_tool,
            "scope_override": scope_override,
            "status": "QUEUED",
            "created": datetime.now().isoformat(),
            "started": None,
            "finished": None,
            "counts": {"findings": 0, "targets": 0, "ports": 0,
                        "intel": 0, "errors": 0, "skipped_oos": 0},
            "scopes": [],
            "error": None,
            "_parser_cls": parser_cls,
            "_project": project,
        }
        with self._lock:
            self._jobs[job_id] = job
            self._console_buffers[job_id] = []
            self._queue.append(job_id)

        self._emit("import_job_created", job, project_id)
        self._drain_queue()
        return self._safe_job(job)

    def submit_file(self, project_id, project, file_path,
                    manual_tool=None, scope_override=None):
        """Public API — create and enqueue a single file import job."""
        job = self._create_job(project_id, project, file_path,
                               manual_tool=manual_tool,
                               scope_override=scope_override)
        if not job:
            raise ValueError(f"Unrecognized file format: {Path(file_path).name}")
        return job

    def submit_folder(self, project_id, project, folder_path,
                      manual_tool=None):
        """Public API — recursively scan a folder, fingerprint all files,
        create QUEUED jobs, then start parsing."""
        folder = Path(folder_path)
        if not folder.is_dir():
            return {"jobs": [], "skipped": 0}

        jobs = []
        skipped = []
        for fp in sorted(folder.rglob("*")):
            if not fp.is_file():
                continue
            if fp.name.startswith("."):
                continue
            job = self._create_job(project_id, project, str(fp),
                                   manual_tool=manual_tool)
            if job:
                jobs.append(job)
            else:
                skipped.append(str(fp))

        if skipped:
            project_dir = project.get("project_dir", "")
            if project_dir:
                append_log(project_dir, {
                    "ts": datetime.now().isoformat(),
                    "level": "INFO",
                    "tool": "import",
                    "event": "folder_scan_skipped",
                    "message": f"Skipped {len(skipped)} unrecognized file(s)",
                    "files": skipped[:50],
                })
        return {"jobs": jobs, "skipped": len(skipped)}

    # ── Queue management ────────────────────────────────────────

    def _drain_queue(self):
        with self._lock:
            while self._active < IMPORT_MAX_CONCURRENT and self._queue:
                job_id = self._queue.pop(0)
                job = self._jobs.get(job_id)
                if not job or job["status"] != "QUEUED":
                    continue
                self._active += 1
                job["status"] = "PARSING"
                job["started"] = datetime.now().isoformat()
                self._emit("import_job_updated", job, job["project_id"])
                t = threading.Thread(target=self._parse_job,
                                     args=(job_id,), daemon=True)
                t.start()

    def _job_done(self, job_id, status, error=None):
        with self._lock:
            self._active = max(0, self._active - 1)
            job = self._jobs.get(job_id)
            if job:
                job["status"] = status
                job["finished"] = datetime.now().isoformat()
                if error:
                    job["error"] = str(error)[:2000]

        if job:
            self._emit("import_job_updated", job, job["project_id"])
            self._emit("import_complete", {
                "job_id": job_id, "status": status,
                "counts": job["counts"],
            }, job["project_id"])
            self._log_import_summary(job)

        self._drain_queue()

    # ── Parse execution ─────────────────────────────────────────

    def _parse_job(self, job_id):
        job = self._jobs.get(job_id)
        if not job:
            self._job_done(job_id, "FAILED", "Job not found")
            return

        project = job.get("_project")
        project_id = job["project_id"]
        project_dir = project.get("project_dir", "") if project else ""
        parser_cls = job.get("_parser_cls")

        try:
            file_path = job["file_path"]
            self._console(job_id, project_id,
                          f"[IMPORT] Parsing {job['filename']} as {job['tool']}")

            # Scope detection
            scopes = self._detect_scopes(job, project)
            job["scopes"] = scopes

            # Copy file to scope/tool directories
            dest_paths = self._place_file(job, project, scopes)
            if dest_paths:
                self._console(job_id, project_id,
                              f"[IMPORT] File placed in {len(dest_paths)} "
                              f"scope dir(s)")

            # Parse — emit_fn accepts either emit("log", "msg")
            # or emit("msg") from parsers
            def emit_fn(*args):
                if len(args) == 2:
                    item_type, data = args
                    if item_type == "log":
                        self._console(job_id, project_id, str(data))
                    else:
                        self._console(job_id, project_id,
                                      f"[{item_type}] {data}")
                elif len(args) == 1:
                    self._console(job_id, project_id, str(args[0]))

            parser = parser_cls(file_path, emit_fn=emit_fn)

            for item_type, data in parser.parse():
                try:
                    self._handle_item(job, project, project_id,
                                      item_type, data)
                except Exception:
                    job["counts"]["errors"] += 1
                    log.exception("Error handling %s item", item_type)

            self._console(job_id, project_id,
                          f"[IMPORT] Complete — "
                          f"{job['counts']['findings']} findings, "
                          f"{job['counts']['targets']} targets, "
                          f"{job['counts']['ports']} ports")

            if job.get("_findings") and dest_paths:
                rel = dest_paths[0]
                if project_dir:
                    try:
                        rel = str(Path(dest_paths[0]).relative_to(project_dir))
                    except ValueError as exc:
                        log.debug("relative_to for output_file: %s", exc)
                for f in job["_findings"]:
                    f.setdefault("output_file", rel)
                self._persist_findings(job, project, project_id, dest_paths)

            self._cleanup_staging(file_path)
            self._job_done(job_id, "IMPORTED")

        except Exception as exc:
            tb = traceback.format_exc()
            self._console(job_id, project_id,
                          f"[ERROR] Parser crashed: {exc}")
            log.exception("Import job %s failed", job_id)
            if project_dir:
                append_error(project_dir, {
                    "ts": datetime.now().isoformat(),
                    "level": "ERROR",
                    "tool": "import",
                    "event": "parser_crash",
                    "file": job.get("filename", ""),
                    "parser": job.get("tool", ""),
                    "message": str(exc),
                    "traceback": tb,
                })
            self._cleanup_staging(file_path)
            self._job_done(job_id, "FAILED", exc)

    # ── Item handling ───────────────────────────────────────────

    def _handle_item(self, job, project, project_id, item_type, data):
        project_dir = project.get("project_dir", "") if project else ""

        if item_type == "finding":
            if not isinstance(data, dict):
                return
            target = data.get("ip") or data.get("hostname", "")
            if target and project and self._sm:
                if self._sm.is_in_scope(project, target):
                    data["oos"] = False
                else:
                    oos = project.get("oos_handling", "explicit")
                    if oos == "skip":
                        job["counts"]["skipped_oos"] += 1
                        return
                    data["oos"] = True

            scopes = job.get("scopes", [])
            if scopes:
                data.setdefault("scope", scopes[0])

            data.setdefault("tool", job["tool_id"])
            data.setdefault("source_tool", job["tool"])
            data["imported"] = True
            self._fe.add_live_finding(project_id, data, project=project)
            job["counts"]["findings"] += 1
            job.setdefault("_findings", []).append(data)
            self._sio.emit("finding_added", {
                "project_id": project_id,
                "finding": _safe_finding(data),
            })

        elif item_type == "port":
            if not isinstance(data, dict):
                return
            job["counts"]["ports"] += 1
            if self._ae and project_dir and project:
                source = IMPORT_TOOL_MAP.get(job["tool"], job["tool_id"])
                self._ae.process_port_discovery(
                    project_dir, data, source, project=project)

        elif item_type == "target":
            job["counts"]["targets"] += 1

        elif item_type == "intel":
            job["counts"].setdefault("intel", 0)
            job["counts"]["intel"] += 1

        elif item_type == "log":
            self._console(job["id"], project_id, str(data))

    # ── Scope detection ─────────────────────────────────────────

    _TOOL_NATIVE_SCOPE = {
        "nessus": "external", "ss3": "external",
        "fracture": "webapp", "siphon": "api",
        "osift": "osint", "auger": "database",
        "trawler": "pcap", "bastion": "firewall",
        "forge": "cloud", "quill": "mobile",
        "isotope": "file", "dredge": "endpoint",
        "aether": "wifi", "aether_b": "bluetooth",
        "aether_z": "zigbee", "aether_u": "uwb",
    }

    def _detect_scopes(self, job, project):
        active = project.get("active_scopes", ["external"]) if project else ["external"]
        if not active:
            active = ["external"]

        override = job.get("scope_override")
        if override and override in active:
            return [override]

        tool_id = job.get("tool_id", "")
        native = self._TOOL_NATIVE_SCOPE.get(tool_id)
        if native and native in active:
            return [native]

        return [active[0]]

    # ── File placement ──────────────────────────────────────────

    def _place_file(self, job, project, scopes):
        if not project:
            return []
        scope_tool_dirs = project.get("scope_tool_dirs", {})
        tool_id = job["tool_id"]
        tool_dirname = TOOL_OUTPUT_DIRS.get(tool_id, tool_id)
        src = Path(job["file_path"])
        placed = []

        for scope_key in scopes:
            scope_dirs = scope_tool_dirs.get(scope_key, {})
            dest_dir = scope_dirs.get(tool_id)
            if not dest_dir:
                project_dir = Path(project.get("project_dir", ""))
                dest_dir = str(project_dir / scope_key / tool_dirname)

            Path(dest_dir).mkdir(parents=True, exist_ok=True)

            dest = Path(dest_dir) / src.name
            if dest.exists():
                stem = src.stem
                ext = src.suffix
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                dest = Path(dest_dir) / f"{stem}_{ts}{ext}"

            try:
                shutil.copy2(str(src), str(dest))
                placed.append(str(dest))
            except OSError as exc:
                log.warning("Failed to copy %s → %s: %s", src, dest, exc)

        return placed

    @staticmethod
    def _cleanup_staging(file_path):
        """Remove the staging copy after the file has been placed."""
        try:
            p = Path(file_path)
            if p.exists() and "_import_staging" in p.parts:
                p.unlink()
                parent = p.parent
                if parent.name == "_import_staging" and not any(parent.iterdir()):
                    parent.rmdir()
        except OSError as exc:
            log.debug("cleanup_staging failed: %s", exc)

    # ── Duplicate detection ─────────────────────────────────────

    def check_duplicate(self, project_id, job):
        with self._lock:
            for jid, existing in self._jobs.items():
                if jid == job["id"]:
                    continue
                if existing["project_id"] != project_id:
                    continue
                if existing["tool"] != job["tool"]:
                    continue
                if existing["status"] in ("FAILED", "DUPLICATE"):
                    continue
                e_created = existing.get("created", "")
                j_created = job.get("created", "")
                if e_created and j_created:
                    try:
                        t1 = datetime.fromisoformat(e_created)
                        t2 = datetime.fromisoformat(j_created)
                        if abs((t2 - t1).total_seconds()) > 3600:
                            continue
                    except (ValueError, TypeError) as exc:
                        log.debug("check_duplicate datetime parse: %s", exc)
                return existing
        return None

    # ── Console management ──────────────────────────────────────

    def _console(self, job_id, project_id, line):
        ts = datetime.now().strftime("%H:%M:%S")
        entry = f"[{ts}] {line}"
        with self._lock:
            buf = self._console_buffers.get(job_id)
            if buf is not None:
                buf.append(entry)
                if len(buf) > MAX_CONSOLE_LINES:
                    del buf[:len(buf) - MAX_CONSOLE_LINES]

        self._sio.emit("import_console_line", {
            "project_id": project_id,
            "job_id": job_id,
            "line": entry,
        })

    def get_console(self, job_id):
        with self._lock:
            return list(self._console_buffers.get(job_id, []))

    # ── Job queries ─────────────────────────────────────────────

    def get_jobs(self, project_id):
        with self._lock:
            return [self._safe_job(j)
                    for j in self._jobs.values()
                    if j["project_id"] == project_id]

    def get_job(self, job_id):
        with self._lock:
            j = self._jobs.get(job_id)
            return self._safe_job(j) if j else None

    def cancel_job(self, job_id):
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return False, "Job not found"
            if job["status"] == "QUEUED":
                job["status"] = "CANCELLED"
                job["finished"] = datetime.now().isoformat()
                if job_id in self._queue:
                    self._queue.remove(job_id)
                self._emit("import_job_updated", job, job["project_id"])
                return True, "Job cancelled"
            if job["status"] == "PARSING":
                return False, "Cannot cancel a running job"
        return False, "Job is not in a cancellable state"

    def list_tools(self):
        return self.registry.list_tools()

    # ── Finding persistence ────────────────────────────────────

    def _persist_findings(self, job, project, project_id, dest_paths):
        """Write findings.json to each tool output dir and register the
        tool in project metadata so findings survive refresh/reload."""
        from models.project import update_project
        findings = job.get("_findings", [])
        if not findings:
            return

        tool_id = job["tool_id"]
        written_dirs = set()
        for dp in dest_paths:
            tool_dir = str(Path(dp).parent)
            if tool_dir in written_dirs:
                continue
            fj = Path(tool_dir) / "findings.json"
            existing = []
            if fj.exists():
                try:
                    with open(fj) as f:
                        existing = json.load(f)
                    if not isinstance(existing, list):
                        existing = existing.get("findings", [])
                except Exception as exc:
                    log.warning("persist_findings JSON load failed: %s", exc)
                    existing = []
            if tool_id == "nessus":
                self._write_nessus_evidence(findings, tool_dir)
            merged = existing + findings
            try:
                with open(fj, "w") as f:
                    json.dump(merged, f, indent=2, default=str)
                written_dirs.add(tool_dir)
            except OSError:
                log.exception("Failed to write %s", fj)

        if not written_dirs:
            return

        tool_dirs = dict(project.get("tool_dirs", {}))
        scope_tool_dirs = dict(project.get("scope_tool_dirs", {}))
        tools = list(project.get("tools", []))

        if tool_id not in tools:
            tools.append(tool_id)

        for tool_dir in written_dirs:
            tool_dirs[tool_id] = tool_dir
            for scope_key in job.get("scopes", []):
                if scope_key in scope_tool_dirs:
                    scope_tool_dirs[scope_key] = dict(scope_tool_dirs[scope_key])
                    scope_tool_dirs[scope_key][tool_id] = tool_dir
                else:
                    scope_tool_dirs[scope_key] = {tool_id: tool_dir}

        update_project(project_id, {
            "tool_dirs": tool_dirs,
            "scope_tool_dirs": scope_tool_dirs,
            "tools": tools,
        })
        if hasattr(self._fe, "bulk_add_findings"):
            try:
                self._fe.bulk_add_findings(project_id, findings, project=project)
            except Exception:
                log.debug("bulk_add_findings in persist failed, skipping")

        self._console(job["id"], project_id,
                      f"[IMPORT] Persisted {len(findings)} findings to disk "
                      f"and registered {tool_id} in project")

    @staticmethod
    def _write_nessus_evidence(findings, tool_dir):
        """Write per-finding evidence files from Nessus plugin_output."""
        ev_dir = Path(tool_dir) / "evidence"
        written = 0
        for f in findings:
            output = (f.get("output") or "").strip()
            if not output:
                continue
            ev_dir.mkdir(parents=True, exist_ok=True)
            fid = f.get("id", "unknown")[:16]
            pid = f.get("nessus_plugin_id") or "0"
            ip = (f.get("ip") or "unknown").replace(":", "_")
            port = f.get("port") or 0
            fname = f"plugin_{pid}_{ip}_{port}_{fid}.txt"
            ev_path = ev_dir / fname
            try:
                lines = []
                lines.append(f"Nessus Plugin: {f.get('nessus_plugin_name', '')} "
                             f"(ID {pid})")
                lines.append(f"Host: {f.get('ip', '')}:{port}")
                if f.get("hostname"):
                    lines.append(f"Hostname: {f['hostname']}")
                lines.append(f"Risk: {f.get('risk', 'INFO')}")
                if f.get("cvss_score"):
                    lines.append(f"CVSS: {f['cvss_score']}")
                lines.append("")
                lines.append("--- Plugin Output ---")
                lines.append(output)
                if f.get("description"):
                    lines.append("")
                    lines.append("--- Description ---")
                    lines.append(f["description"])
                if f.get("remediation"):
                    lines.append("")
                    lines.append("--- Solution ---")
                    lines.append(f["remediation"])
                ev_path.write_text("\n".join(lines), encoding="utf-8")
                f["output_file"] = f"evidence/{fname}"
                written += 1
            except OSError:
                log.warning("Failed to write evidence file %s", ev_path)
        if written:
            log.info("Wrote %d Nessus evidence files to %s", written, ev_dir)

    # ── Logging ─────────────────────────────────────────────────

    def _log_import_summary(self, job):
        project = job.get("_project")
        project_dir = project.get("project_dir", "") if project else ""
        if not project_dir:
            return
        counts = job["counts"]
        parts = []
        if counts.get("findings"):
            parts.append(f"{counts['findings']} findings")
        if counts.get("targets"):
            parts.append(f"{counts['targets']} targets")
        if counts.get("ports"):
            parts.append(f"{counts['ports']} ports")
        if counts.get("intel"):
            parts.append(f"{counts['intel']} intel")
        if counts.get("errors"):
            parts.append(f"{counts['errors']} errors")
        if counts.get("skipped_oos"):
            parts.append(f"{counts['skipped_oos']} skipped (OOS)")
        count_str = ", ".join(parts) if parts else "0 items"

        if job["status"] == "IMPORTED":
            msg = f"Import complete: {job['tool']} — {job['filename']} — {count_str}"
        else:
            msg = f"Import failed: {job['tool']} — {job['filename']} — {job.get('error', 'unknown error')}"

        entry = {
            "ts": datetime.now().isoformat(),
            "level": "INFO" if job["status"] == "IMPORTED" else "ERROR",
            "tool": "import",
            "event": "import_complete" if job["status"] == "IMPORTED"
                     else "import_failed",
            "message": msg,
            "import_tool": job["tool"],
            "file": job["filename"],
            "status": job["status"],
            "scopes": job.get("scopes", []),
        }
        entry.update(counts)
        if job.get("error"):
            entry["error"] = job["error"]
        append_log(project_dir, entry)

    # ── SocketIO helpers ────────────────────────────────────────

    def _emit(self, event, data, project_id):
        if "id" in data and "status" in data:
            safe = self._safe_job(data)
            self._sio.emit(event, {"project_id": project_id, "job": safe})
        else:
            self._sio.emit(event, {"project_id": project_id, **data})

    @staticmethod
    def _safe_job(job):
        if not job:
            return None
        safe = {k: v for k, v in job.items() if not k.startswith("_")}
        counts = safe.get("counts", {})
        safe["findings_count"] = counts.get("findings", 0)
        safe["targets_count"] = counts.get("targets", 0)
        safe["tool_name"] = safe.get("tool", "")
        scopes = safe.get("scopes", [])
        safe["scope"] = ", ".join(scopes) if scopes else ""
        if safe.get("started") and safe.get("finished"):
            try:
                t0 = datetime.fromisoformat(safe["started"])
                t1 = datetime.fromisoformat(safe["finished"])
                secs = int((t1 - t0).total_seconds())
                safe["duration"] = f"{secs}s" if secs < 60 else f"{secs // 60}m {secs % 60}s"
            except (ValueError, TypeError):
                safe["duration"] = ""
        return safe


def _safe_finding(f):
    safe = dict(f)
    for big in ("output", "plugin_output"):
        if big in safe and isinstance(safe[big], str) and len(safe[big]) > 4096:
            safe[big] = safe[big][:4096] + "… [truncated]"
    return safe
