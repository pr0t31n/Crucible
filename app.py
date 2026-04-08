#!/usr/bin/env python3
"""
Crucible — Web & API Assessment Platform
Flask/SocketIO orchestration wrapper for Fracture (web app pentest)
and Siphon (API pentest), modelled after the Vantage/Gauntlet architecture.
"""
from __future__ import annotations

VERSION = "1.0.1"

import json
import os
import platform
import queue
import re
import signal
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Flask — https://github.com/pallets/flask
from flask import Flask, jsonify, redirect, render_template, request, session, url_for
# Flask-SocketIO — https://github.com/miguelgrinberg/Flask-SocketIO
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
import _auth

# ---------------------------------------------------------------------------
# App bootstrap
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = _auth.load_secret_key()
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

CRUCIBLE_DIR  = Path(__file__).parent.resolve()
PROJECTS_FILE = CRUCIBLE_DIR / "projects.json"
PROJECTS_DIR  = CRUCIBLE_DIR / "projects"
FRACTURE_SCRIPT = Path("/Users/pr0t31n/Fracture/fracture.py")
SIPHON_SCRIPT   = Path("/Users/pr0t31n/Siphon/siphon.py")

PROJECTS_DIR.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# Protocol tokens emitted by tools when running under Vantage/Crucible
# ---------------------------------------------------------------------------
_VP_LOG    = "__VANTAGE_LOG__:"
_VP_ERR    = "__VANTAGE_ERR__:"
_VP_PROMPT = "__VANTAGE_PROMPT__:"
_VP_STATUS = "__VANTAGE_STATUS__:"

# Sudo password prompt patterns
_SUDO_PROMPT_RE = re.compile(
    r'(password for .+:|^\[sudo\] password|^Password:)',
    re.IGNORECASE
)

# ---------------------------------------------------------------------------
# Buffer limits
# ---------------------------------------------------------------------------
_MAX_CONSOLE = 5000
_MAX_LOG     = 2000
_MAX_ERR     = 500

# ---------------------------------------------------------------------------
# Per-project runtime state  (all keyed by project_id)
# ---------------------------------------------------------------------------
_procs:        dict[str, dict[str, subprocess.Popen | None]] = {}
_buffers:      dict[str, dict[str, list]] = {}   # console lines
_tool_status:  dict[str, dict[str, str]]  = {}
_all_findings: dict[str, list]            = {}
_watchers:     dict[str, threading.Thread] = {}
_watcher_flags: dict[str, bool]           = {}
_sid_to_project: dict[str, str]           = {}

# Interaction — answer queues keyed by "project_id:tool"
_answer_queues:  dict[str, queue.Queue] = {}
_pending_prompts: dict[str, dict]       = {}   # "project_id:tool" -> prompt payload

# Structured log buffers  { project_id -> [{ts, level, tool, message}] }
_log_buffers: dict[str, list] = {}

# Structured error buffers  { project_id -> [{ts, source, tool, message, detail, category}] }
_err_buffers: dict[str, list] = {}

# Status cache  { project_id -> {"fr": {phases}, "si": {phases}} }
_status_cache: dict[str, dict] = {}

_projects_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Default settings templates
# ---------------------------------------------------------------------------
FR_DEFAULTS: dict = {
    "engagement": {
        "consultant": "", "client_name": "", "client_short": "",
        "consultant_email": "", "start_date": "", "end_date": ""
    },
    "scan": {
        "project": "fracture_output",
        "target_url": "",
        "target_urls": [],
        "wordlist": "/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt",
        "threads": 30,
        "timeout": 10,
        "follow_redirects": True,
        "user_agent": "Mozilla/5.0 (compatible; Fracture/1.0; Security Assessment)",
        "extra_headers": {},
        "proxy": "",
        "verify_ssl": False,
        "phases": {
            "recon": True, "tls": True, "headers": True, "crawl": True,
            "injection": True, "traversal": True, "ssrf": True,
            "auth_bypass": True, "files": True, "vulnscan": True,
            "graphql": False, "auth_recon": False, "authorization": False,
            "session": False, "csrf": False, "cross_user": False
        },
        "auth": {
            "enabled": False, "username": "", "password": "",
            "auth_type": "form", "login_url": "", "login_data": "",
            "auth_token": "", "token_type": "Bearer", "session_cookie": ""
        },
        "auth2": {
            "enabled": False, "username": "", "password": "",
            "auth_token": "", "session_cookie": ""
        },
        "sqlmap_timeout": 300, "nuclei_timeout": 600,
        "crawl_depth": 3, "crawl_max_pages": 150,
        "gobuster_wordlist": "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
        "wpscan_token": ""
    }
}

SI_DEFAULTS: dict = {
    "engagement": {
        "consultant": "", "client_name": "", "client_short": "",
        "consultant_email": "", "start_date": "", "end_date": ""
    },
    "scan": {
        "project": "siphon_output",
        "target_url": "",
        "target_urls": [],
        "api_spec_url": "", "api_spec_file": "",
        "threads": 20, "timeout": 10,
        "user_agent": "Mozilla/5.0 (compatible; Siphon/1.0; Security Assessment)",
        "extra_headers": {}, "proxy": "", "verify_ssl": False,
        "phases": {
            "discovery": True, "recon": True, "fuzzing": True,
            "injection": True, "auth_bypass": True, "rate_limiting": True,
            "mass_assignment": True, "ssrf": True, "data_exposure": True,
            "graphql": False, "bola": False, "bfla": False,
            "cross_user": False, "session": False, "jwt": False
        },
        "auth": {
            "enabled": False, "type": "bearer", "token": "",
            "username": "", "password": "", "api_key": "",
            "api_key_header": "X-API-Key", "oauth_url": "",
            "client_id": "", "client_secret": ""
        },
        "auth2": {
            "enabled": False, "type": "bearer", "token": "",
            "username": "", "password": "", "api_key": ""
        },
        "rate_limit_threshold": 100, "bola_id_range": 20,
        "wordlist": "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"
    }
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _room(pid: str) -> str:
    return f"crucible_{pid}"

def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")

def _pkey(project_id: str, tool: str) -> str:
    """Key for answer queue / pending prompt dicts."""
    return f"{project_id}:{tool}"

def _emit_line(project_id: str, tool: str, text: str, stream: str = "stdout") -> None:
    entry = {"text": text, "stream": stream, "ts": _now_ts()}
    buf = _buffers.setdefault(project_id, {"fr": [], "si": []})
    lst = buf.setdefault(tool, [])
    lst.append(entry)
    if len(lst) > _MAX_CONSOLE:
        del lst[0]
    proj = _get_project(project_id)
    if proj:
        _append_jsonl(
            Path(proj["project_dir"]) / f"vantage_console_{tool}.jsonl", entry
        )
    socketio.emit(f"{tool}_output", entry, room=_room(project_id))

def _deepcopy_template(t: dict) -> dict:
    return json.loads(json.dumps(t))

# ---------------------------------------------------------------------------
# JSONL persistence helpers
# ---------------------------------------------------------------------------
def _append_jsonl(path: Path, entry: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass

def _read_jsonl(path: Path, limit: int = 2000) -> list:
    if not path.exists():
        return []
    entries = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        pass
    except Exception:
        pass
    return entries[-limit:]

def _buf_append_log(project_id: str, entry: dict, proj: dict | None = None) -> None:
    lst = _log_buffers.setdefault(project_id, [])
    lst.append(entry)
    if len(lst) > _MAX_LOG:
        del lst[0]
    if proj:
        _append_jsonl(Path(proj["project_dir"]) / "vantage_logs.jsonl", entry)
    socketio.emit("log_entry", {"tool": entry.get("tool", ""), "entry": entry},
                  room=_room(project_id))

def _buf_append_err(project_id: str, entry: dict, proj: dict | None = None) -> None:
    lst = _err_buffers.setdefault(project_id, [])
    lst.append(entry)
    if len(lst) > _MAX_ERR:
        del lst[0]
    if proj:
        _append_jsonl(Path(proj["project_dir"]) / "vantage_errors.jsonl", entry)
    socketio.emit("err_entry", {"tool": entry.get("tool", ""), "entry": entry},
                  room=_room(project_id))

def _categorise_error(msg: str) -> str:
    m = msg.lower()
    if any(k in m for k in ("connection", "socket", "timeout", "refused",
                              "network", "unreachable", "timed out")):
        return "Network"
    if any(k in m for k in ("tool", "binary", "not found", "command",
                              "executable", "stderr", "exit code", "crashed")):
        return "Tool"
    return "Scan"

# ---------------------------------------------------------------------------
# Project persistence
# ---------------------------------------------------------------------------
def _load_projects() -> dict:
    if PROJECTS_FILE.exists():
        try:
            return json.loads(PROJECTS_FILE.read_text())
        except Exception:
            pass
    return {"projects": {}}

def _save_projects(data: dict) -> None:
    with _projects_lock:
        PROJECTS_FILE.write_text(json.dumps(data, indent=2))

def _get_project(project_id: str) -> dict | None:
    return _load_projects()["projects"].get(project_id)

def _update_project_field(project_id: str, **kwargs) -> None:
    data = _load_projects()
    if project_id in data["projects"]:
        data["projects"][project_id].update(kwargs)
        _save_projects(data)

# ---------------------------------------------------------------------------
# Route helpers
# ---------------------------------------------------------------------------
def _init_project_state(project_id: str) -> None:
    _procs.setdefault(project_id,       {"fr": None, "si": None})
    _buffers.setdefault(project_id,     {"fr": [],   "si": []})
    _tool_status.setdefault(project_id, {"fr": "idle", "si": "idle"})
    _all_findings.setdefault(project_id, [])
    _status_cache.setdefault(project_id, {"fr": {}, "si": {}})

# ---------------------------------------------------------------------------
# Project directory helpers
# ---------------------------------------------------------------------------
def _clients_base() -> Path:
    """Return the OS-appropriate clients root directory."""
    system = platform.system()
    if system == "Darwin":
        return Path.home() / "clients"
    elif system == "Windows":
        return Path("C:\\clients")
    else:
        return Path("/clients")

def _extract_year(date_str: str) -> str:
    """Parse YYYY-MM-DD or MM/DD/YYYY and return the 4-digit year."""
    if not date_str:
        return datetime.now(timezone.utc).strftime("%Y")
    m = re.match(r'^(\d{4})-', date_str)
    if m:
        return m.group(1)
    m = re.match(r'\d{1,2}/\d{1,2}/(\d{4})', date_str)
    if m:
        return m.group(1)
    return datetime.now(timezone.utc).strftime("%Y")

# ---------------------------------------------------------------------------
# Auth bootstrap
# ---------------------------------------------------------------------------
_auth.init_auth()

@app.before_request
def before_request():
    gate = _auth.auth_gate()
    if gate:
        return gate

@app.after_request
def after_request(response):
    return _auth.apply_security_headers(response)

# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not _auth.validate_csrf(request.form.get("csrf_token")):
            return render_template("login.html",
                                   error="Invalid request. Please try again.",
                                   csrf_token=_auth.generate_csrf())
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if _auth.verify_credentials(username, password):
            session["authenticated"] = True
            session["username"] = username
            return redirect(url_for("index"))
        return render_template("login.html",
                               error="Invalid username or password.",
                               username=username,
                               csrf_token=_auth.generate_csrf())
    return render_template("login.html",
                           error=None,
                           username="",
                           csrf_token=_auth.generate_csrf())

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/auth/change-password", methods=["GET", "POST"])
def change_password():
    force = _auth.must_change_password()
    if request.method == "POST":
        if not _auth.validate_csrf(request.form.get("csrf_token")):
            return render_template("change_password.html",
                                   error="Invalid request.",
                                   force=force,
                                   csrf_token=_auth.generate_csrf())
        new_password    = request.form.get("new_password", "")
        confirm         = request.form.get("confirm_password", "")
        new_username    = request.form.get("new_username", "").strip()

        if new_password != confirm:
            return render_template("change_password.html",
                                   error="Passwords do not match.",
                                   force=force,
                                   csrf_token=_auth.generate_csrf())

        if force:
            err_u = _auth.is_weak_username(new_username)
            if err_u:
                return render_template("change_password.html",
                                       error=err_u, force=force,
                                       csrf_token=_auth.generate_csrf())
            err_p = _auth.is_weak_password(new_password, new_username)
            if err_p:
                return render_template("change_password.html",
                                       error=err_p, force=force,
                                       csrf_token=_auth.generate_csrf())
            _auth.update_credentials(new_username, new_password)
            session["username"] = new_username
        else:
            current = request.form.get("current_password", "")
            if not _auth.check_current_password(current):
                return render_template("change_password.html",
                                       error="Current password is incorrect.",
                                       force=False,
                                       csrf_token=_auth.generate_csrf())
            err_p = _auth.is_weak_password(new_password)
            if err_p:
                return render_template("change_password.html",
                                       error=err_p, force=False,
                                       csrf_token=_auth.generate_csrf())
            _auth.update_password(new_password)
        return redirect(url_for("index"))
    return render_template("change_password.html",
                           error=None,
                           force=force,
                           csrf_token=_auth.generate_csrf())

# ---------------------------------------------------------------------------
# Nexus status — unauthenticated
# ---------------------------------------------------------------------------
@app.route("/api/nexus-status")
def nexus_status():
    """Unauthenticated status probe for the Nexus hub."""
    active = any(
        p is not None and p.poll() is None
        for procs in _procs.values()
        for p in procs.values()
    )
    return jsonify({"app": "crucible", "scanning": active, "version": VERSION})

# ---------------------------------------------------------------------------
# HTTP routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    data = _load_projects()
    projects = sorted(
        data["projects"].items(),
        key=lambda kv: kv[1].get("created", ""),
        reverse=True,
    )
    return render_template("index.html", projects=projects)


@app.route("/project/<project_id>")
def project_page(project_id: str):
    proj = _get_project(project_id)
    if not proj:
        return redirect(url_for("index"))
    _init_project_state(project_id)
    return render_template("project.html", project=proj, project_id=project_id)


@app.route("/new_project")
def new_project_page():
    return render_template("new_project.html")


@app.route("/edit_project/<project_id>")
def edit_project_page(project_id: str):
    proj = _get_project(project_id)
    if not proj:
        return redirect(url_for("index"))
    fr_settings: dict = {}
    si_settings: dict = {}
    try:
        fr_settings = json.loads(Path(proj["fr_settings_file"]).read_text())
    except Exception:
        pass
    try:
        si_settings = json.loads(Path(proj["si_settings_file"]).read_text())
    except Exception:
        pass
    return render_template(
        "edit_project.html",
        project=proj,
        project_id=project_id,
        fr=fr_settings,
        si=si_settings,
    )

# ---------------------------------------------------------------------------
# API — project management
# ---------------------------------------------------------------------------
@app.route("/api/create_project", methods=["POST"])
def api_create_project():
    body = request.json or {}
    project_id = str(uuid.uuid4())
    cfg_dir    = PROJECTS_DIR / project_id
    cfg_dir.mkdir(parents=True, exist_ok=True)

    # Derive client-scoped project directory
    client_short = (body.get("client_short") or "client").strip().lower()
    client_short = re.sub(r'[^\w-]', '_', client_short)

    scope_raw = body.get("scope", "webapp").lower()
    scope_map = {
        "webapp":   "webapp",
        "api":      "api",
        "both":     "both",
        "web":      "webapp",
        "webapi":   "both",
    }
    scope_str = scope_map.get(scope_raw, "webapp")

    year = _extract_year(body.get("start_date", ""))

    clients_base = _clients_base()
    client_dir   = clients_base / client_short
    project_dir  = client_dir / f"{client_short}_{scope_str}_{year}"

    try:
        client_dir.mkdir(parents=True, exist_ok=True)
        project_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        project_dir = CRUCIBLE_DIR / "output" / project_id
        project_dir.mkdir(parents=True, exist_ok=True)

    # Build Fracture settings
    fr = _deepcopy_template(FR_DEFAULTS)
    for k in fr["engagement"]:
        fr["engagement"][k] = body.get(k, "")
    fr["scan"]["project"] = body.get("fr_project_name", "fracture_output")
    fr["scan"]["target_url"] = body.get("fr_target_url", "")
    raw_urls = body.get("fr_target_urls", "")
    fr["scan"]["target_urls"] = [u.strip() for u in raw_urls.splitlines() if u.strip()]

    # Build Siphon settings
    si = _deepcopy_template(SI_DEFAULTS)
    for k in si["engagement"]:
        si["engagement"][k] = body.get(k, "")
    si["scan"]["project"] = body.get("si_project_name", "siphon_output")
    si["scan"]["target_url"] = body.get("si_target_url", "")
    si["scan"]["api_spec_url"] = body.get("si_api_spec_url", "")

    fr_path = project_dir / "fr_settings.json"
    si_path = project_dir / "si_settings.json"
    fr_path.write_text(json.dumps(fr, indent=2))
    si_path.write_text(json.dumps(si, indent=2))

    include_fr = body.get("include_fr", True)
    include_si = body.get("include_si", True)
    tools = []
    if include_fr:
        tools.append("fr")
    if include_si:
        tools.append("si")
    if not tools:
        tools = ["fr", "si"]

    proj = {
        "name":              body.get("engagement_name") or f"Engagement {project_id[:8]}",
        "client_name":       body.get("client_name", ""),
        "client_short":      client_short,
        "scope":             scope_str,
        "created":           datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "project_dir":       str(project_dir),
        "fr_settings_file":  str(fr_path),
        "si_settings_file":  str(si_path),
        "fracture_output_dir": str(project_dir / "fracture_output"),
        "siphon_output_dir":   str(project_dir / "siphon_output"),
        "tools":             tools,
        "fr_status":         "idle",
        "si_status":         "idle",
        "fr_last_run":       None,
        "si_last_run":       None,
    }

    data = _load_projects()
    data["projects"][project_id] = proj
    _save_projects(data)
    return jsonify({"success": True, "project_id": project_id})


@app.route("/api/update_project/<project_id>", methods=["POST"])
def api_update_project(project_id: str):
    body = request.json or {}
    proj = _get_project(project_id)
    if not proj:
        return jsonify({"error": "not found"}), 404

    if body.get("engagement_name"):
        proj["name"] = body["engagement_name"]
    if "client_name" in body:
        proj["client_name"] = body["client_name"]
    if "client_short" in body:
        proj["client_short"] = re.sub(r'[^\w-]', '_', body["client_short"].strip().lower())

    # Update Fracture settings on disk
    try:
        fr_path = Path(proj["fr_settings_file"])
        fr = json.loads(fr_path.read_text())
        for k in ("consultant", "consultant_email", "client_name", "client_short",
                  "start_date", "end_date"):
            if k in body:
                fr["engagement"][k] = body[k]
        if body.get("fr_project_name"):
            fr["scan"]["project"] = body["fr_project_name"]
        if body.get("fr_target_url") is not None:
            fr["scan"]["target_url"] = body["fr_target_url"]
        fr_path.write_text(json.dumps(fr, indent=2))
    except Exception:
        pass

    # Update Siphon settings on disk
    try:
        si_path = Path(proj["si_settings_file"])
        si = json.loads(si_path.read_text())
        for k in ("consultant", "consultant_email", "client_name", "client_short",
                  "start_date", "end_date"):
            if k in body:
                si["engagement"][k] = body[k]
        if body.get("si_project_name"):
            si["scan"]["project"] = body["si_project_name"]
        if body.get("si_target_url") is not None:
            si["scan"]["target_url"] = body["si_target_url"]
        if body.get("si_api_spec_url") is not None:
            si["scan"]["api_spec_url"] = body["si_api_spec_url"]
        si_path.write_text(json.dumps(si, indent=2))
    except Exception:
        pass

    # Update tools list
    include_fr = body.get("include_fr", "fr" in proj.get("tools", ["fr"]))
    include_si = body.get("include_si", "si" in proj.get("tools", ["si"]))
    tools = []
    if include_fr:
        tools.append("fr")
    if include_si:
        tools.append("si")
    if not tools:
        tools = ["fr", "si"]
    proj["tools"] = tools

    data = _load_projects()
    data["projects"][project_id] = proj
    _save_projects(data)
    return jsonify({"success": True, "project_id": project_id})


@app.route("/api/project/<project_id>")
def api_get_project(project_id: str):
    proj = _get_project(project_id)
    if not proj:
        return jsonify({"error": "not found"}), 404
    proj = dict(proj)
    live = _tool_status.get(project_id, {"fr": "idle", "si": "idle"})
    proj["fr_live_status"] = live.get("fr", "idle")
    proj["si_live_status"] = live.get("si", "idle")
    return jsonify(proj)


@app.route("/api/settings/<project_id>/<tool>", methods=["GET", "POST"])
def api_settings(project_id: str, tool: str):
    proj = _get_project(project_id)
    if not proj:
        return jsonify({"error": "not found"}), 404
    key  = "fr_settings_file" if tool == "fr" else "si_settings_file"
    path = Path(proj[key])
    if request.method == "GET":
        if path.exists():
            return jsonify(json.loads(path.read_text()))
        return jsonify(FR_DEFAULTS if tool == "fr" else SI_DEFAULTS)
    body = request.json or {}
    path.write_text(json.dumps(body, indent=2))
    return jsonify({"success": True})


@app.route("/api/console/<project_id>/<tool>")
def api_console(project_id: str, tool: str):
    buf = _buffers.get(project_id, {}).get(tool, [])
    return jsonify(buf)


@app.route("/api/findings/<project_id>")
def api_findings(project_id: str):
    proj_findings = _all_findings.get(project_id)
    if proj_findings:
        return jsonify(proj_findings)

    proj = _get_project(project_id)
    if not proj:
        return jsonify([])

    fallback: list[dict] = []
    seen: set[tuple] = set()

    # Fracture findings
    fr_cfg_path = Path(proj.get("fr_settings_file", ""))
    if fr_cfg_path.exists():
        try:
            fr_cfg  = json.loads(fr_cfg_path.read_text())
            fr_proj = fr_cfg.get("scan", {}).get("project", "fracture_output")
            fp = Path(proj["project_dir"]) / fr_proj / "findings.json"
            if fp.exists():
                for raw in json.loads(fp.read_text()):
                    f = dict(raw)
                    f["_tool"] = "fracture"
                    k = _fkey(f)
                    if k not in seen:
                        seen.add(k)
                        fallback.append(f)
        except Exception:
            pass

    # Siphon findings
    si_cfg_path = Path(proj.get("si_settings_file", ""))
    if si_cfg_path.exists():
        try:
            si_cfg  = json.loads(si_cfg_path.read_text())
            si_proj = si_cfg.get("scan", {}).get("project", "siphon_output")
            fp = Path(proj["project_dir"]) / si_proj / "findings.json"
            if fp.exists():
                for raw in json.loads(fp.read_text()):
                    f = dict(raw)
                    f["_tool"] = "siphon"
                    k = _fkey(f)
                    if k not in seen:
                        seen.add(k)
                        fallback.append(f)
        except Exception:
            pass

    if fallback:
        _all_findings[project_id] = fallback
    return jsonify(fallback)


@app.route("/api/logs/<project_id>")
def api_logs(project_id: str):
    proj = _get_project(project_id)
    in_mem = _log_buffers.get(project_id, [])
    if in_mem:
        return jsonify(in_mem)
    if proj:
        entries = _read_jsonl(Path(proj["project_dir"]) / "vantage_logs.jsonl")
        if entries:
            _log_buffers[project_id] = entries
        return jsonify(entries)
    return jsonify([])


@app.route("/api/errors/<project_id>")
def api_errors(project_id: str):
    proj = _get_project(project_id)
    in_mem = _err_buffers.get(project_id, [])
    if in_mem:
        return jsonify(in_mem)
    if proj:
        entries = _read_jsonl(Path(proj["project_dir"]) / "vantage_errors.jsonl",
                              limit=_MAX_ERR)
        if entries:
            _err_buffers[project_id] = entries
        return jsonify(entries)
    return jsonify([])


@app.route("/api/status/<project_id>")
def api_status(project_id: str):
    return jsonify(_status_cache.get(project_id, {"fr": {}, "si": {}}))


@app.route("/api/checkpoint/<project_id>/<tool>")
def api_checkpoint(project_id: str, tool: str):
    proj = _get_project(project_id)
    if not proj:
        return jsonify({}), 404
    try:
        settings_file = proj["fr_settings_file"] if tool == "fr" else proj["si_settings_file"]
        cfg = json.loads(Path(settings_file).read_text())
        proj_name = cfg.get("scan", {}).get("project", "fracture_output" if tool == "fr" else "siphon_output")
        cp = Path(proj["project_dir"]) / proj_name / "checkpoint.json"
    except Exception:
        return jsonify({})
    if cp.exists():
        try:
            return jsonify(json.loads(cp.read_text()))
        except Exception:
            pass
    return jsonify({})


@app.route("/api/summary/<project_id>")
def api_summary(project_id: str):
    proj = _get_project(project_id)
    if not proj:
        return jsonify({}), 404
    result: dict = {"fracture": {}, "siphon": {}}

    fr_settings_path = Path(proj.get("fr_settings_file", ""))
    if fr_settings_path.exists():
        try:
            fr_cfg  = json.loads(fr_settings_path.read_text())
            fr_proj = fr_cfg.get("scan", {}).get("project", "")
            summary = Path(proj["project_dir"]) / fr_proj / "summary.json"
            if summary.exists():
                result["fracture"] = json.loads(summary.read_text())
        except Exception:
            pass

    si_settings_path = Path(proj.get("si_settings_file", ""))
    if si_settings_path.exists():
        try:
            si_cfg  = json.loads(si_settings_path.read_text())
            si_proj = si_cfg.get("scan", {}).get("project", "")
            summary = Path(proj["project_dir"]) / si_proj / "summary.json"
            if summary.exists():
                result["siphon"] = json.loads(summary.read_text())
        except Exception:
            pass

    return jsonify(result)


@app.route("/api/delete_project/<project_id>", methods=["DELETE"])
def api_delete_project(project_id: str):
    data = _load_projects()
    data["projects"].pop(project_id, None)
    _save_projects(data)
    return jsonify({"success": True})


# ---------------------------------------------------------------------------
# SocketIO — lifecycle
# ---------------------------------------------------------------------------
@socketio.on("connect")
def on_connect():
    pass


@socketio.on("disconnect")
def on_disconnect():
    _sid_to_project.pop(request.sid, None)


@socketio.on("join_project")
def on_join_project(data):
    project_id = data.get("project_id", "")
    proj = _get_project(project_id)
    if not proj:
        return
    _init_project_state(project_id)
    _sid_to_project[request.sid] = project_id
    join_room(_room(project_id))

    proj_dir = Path(proj["project_dir"])

    # Tool status
    emit("tool_status", _tool_status.get(project_id, {"fr": "idle", "si": "idle"}))

    # Console output (with disk fallback for post-restart joins)
    for tool in ("fr", "si"):
        lines = _buffers.get(project_id, {}).get(tool, [])
        if not lines:
            lines = _read_jsonl(proj_dir / f"vantage_console_{tool}.jsonl",
                                limit=_MAX_CONSOLE)
            if lines:
                _buffers.setdefault(project_id, {"fr": [], "si": []})[tool] = lines
        for entry in lines:
            emit(f"{tool}_output", entry)

    # Findings
    for f in _all_findings.get(project_id, []):
        emit("finding", {"tool": f.get("_tool", ""), "finding": f})

    # Phase status
    sc = _status_cache.get(project_id, {})
    for tool, phases in sc.items():
        for phase_key, phase_data in phases.items():
            emit("vantage_status", {"tool": tool, **phase_data})

    # Structured log entries (with disk fallback)
    log_entries = _log_buffers.get(project_id, [])
    if not log_entries:
        log_entries = _read_jsonl(proj_dir / "vantage_logs.jsonl", limit=_MAX_LOG)
        if log_entries:
            _log_buffers[project_id] = log_entries
    for entry in log_entries:
        emit("log_entry", {"tool": entry.get("tool", ""), "entry": entry})

    # Structured error entries (with disk fallback)
    err_entries = _err_buffers.get(project_id, [])
    if not err_entries:
        err_entries = _read_jsonl(proj_dir / "vantage_errors.jsonl", limit=_MAX_ERR)
        if err_entries:
            _err_buffers[project_id] = err_entries
    for entry in err_entries:
        emit("err_entry", {"tool": entry.get("tool", ""), "entry": entry})

    # Pending prompt
    for tool in ("fr", "si"):
        pkey    = _pkey(project_id, tool)
        pending = _pending_prompts.get(pkey)
        if pending:
            emit("vantage_prompt", {"tool": tool, "payload": pending})


@socketio.on("leave_project")
def on_leave_project(data):
    project_id = data.get("project_id", "")
    leave_room(_room(project_id))
    _sid_to_project.pop(request.sid, None)


# ---------------------------------------------------------------------------
# SocketIO — prompt answer
# ---------------------------------------------------------------------------
@socketio.on("vantage_answer")
def on_vantage_answer(data):
    project_id = data.get("project_id", "")
    tool       = data.get("tool", "")
    answer     = data.get("answer", "")
    pkey       = _pkey(project_id, tool)

    q = _answer_queues.get(pkey)
    if q:
        q.put(answer)

    pending = _pending_prompts.get(pkey, {})
    is_pw = (pending.get("type") == "password" or
             bool(re.search(r'password|passphrase|secret|sudo',
                            pending.get("question", ""), re.I)))
    echo = "[password entered]" if is_pw else f"< {answer}"
    _emit_line(project_id, tool, f"[Crucible] Prompt response: {echo}", "system")
    _pending_prompts.pop(pkey, None)
    socketio.emit("prompt_resolved", {"tool": tool}, room=_room(project_id))


# ---------------------------------------------------------------------------
# SocketIO — Fracture control
# ---------------------------------------------------------------------------
@socketio.on("fr_start")
def on_fr_start(data):
    project_id = data.get("project_id", "")
    proj = _get_project(project_id)
    if not proj:
        return emit("fr_error", {"error": "Project not found"})
    if _procs.get(project_id, {}).get("fr"):
        return emit("fr_error", {"error": "Fracture already running"})

    fr_settings_path = proj["fr_settings_file"]
    cmd = ["sudo", "-S", "-E",
           "python3", str(FRACTURE_SCRIPT),
           "--settings", fr_settings_path]

    try:
        fr_cfg = json.loads(Path(fr_settings_path).read_text())
        fr_proj_name = fr_cfg.get("scan", {}).get("project", "fracture_output")
    except Exception:
        fr_proj_name = "fracture_output"

    cwd = proj["project_dir"]
    Path(cwd).mkdir(parents=True, exist_ok=True)

    env = dict(os.environ)
    env["VANTAGE_MANAGED"]  = "1"
    env["PYTHONUNBUFFERED"] = "1"

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            text=True, bufsize=1, cwd=cwd, env=env,
        )
    except Exception as exc:
        return emit("fr_error", {"error": str(exc)})

    _init_project_state(project_id)
    _procs[project_id]["fr"]       = proc
    _tool_status[project_id]["fr"] = "running"
    _answer_queues[_pkey(project_id, "fr")] = queue.Queue()
    _update_project_field(project_id,
        fr_status="running",
        fr_last_run=datetime.now(timezone.utc).isoformat(),
        fr_proj_name=fr_proj_name,
    )

    socketio.emit("fr_started",   {"pid": proc.pid}, room=_room(project_id))
    socketio.emit("tool_status",  _tool_status[project_id], room=_room(project_id))
    _emit_line(project_id, "fr",
        f"[Crucible] Fracture started — PID {proc.pid}  cwd={cwd}", "system")

    threading.Thread(target=_reader,
        args=(project_id, "fr", proc.stdout, "stdout", proc), daemon=True).start()
    threading.Thread(target=_reader,
        args=(project_id, "fr", proc.stderr, "stderr", proc), daemon=True).start()
    threading.Thread(target=_wait_proc,
        args=(project_id, "fr", proc), daemon=True).start()
    _ensure_watcher(project_id, proj)


@socketio.on("fr_kill")
def on_fr_kill(data):
    _kill_tool(data.get("project_id", ""), "fr")


@socketio.on("fr_input")
def on_fr_input(data):
    on_vantage_answer({**data, "tool": "fr"})


# ---------------------------------------------------------------------------
# SocketIO — Siphon control
# ---------------------------------------------------------------------------
@socketio.on("si_start")
def on_si_start(data):
    project_id = data.get("project_id", "")
    proj = _get_project(project_id)
    if not proj:
        return emit("si_error", {"error": "Project not found"})
    if _procs.get(project_id, {}).get("si"):
        return emit("si_error", {"error": "Siphon already running"})

    si_settings_path = proj["si_settings_file"]
    cmd = ["sudo", "-S", "-E",
           "python3", str(SIPHON_SCRIPT),
           "--settings", si_settings_path]

    try:
        si_cfg = json.loads(Path(si_settings_path).read_text())
        si_proj_name = si_cfg.get("scan", {}).get("project", "siphon_output")
    except Exception:
        si_proj_name = "siphon_output"

    cwd = proj["project_dir"]
    Path(cwd).mkdir(parents=True, exist_ok=True)

    env = dict(os.environ)
    env["VANTAGE_MANAGED"]  = "1"
    env["PYTHONUNBUFFERED"] = "1"

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            text=True, bufsize=1, cwd=cwd, env=env,
        )
    except Exception as exc:
        return emit("si_error", {"error": str(exc)})

    _init_project_state(project_id)
    _procs[project_id]["si"]       = proc
    _tool_status[project_id]["si"] = "running"
    _answer_queues[_pkey(project_id, "si")] = queue.Queue()
    _update_project_field(project_id,
        si_status="running",
        si_last_run=datetime.now(timezone.utc).isoformat(),
        si_proj_name=si_proj_name,
    )

    socketio.emit("si_started",   {"pid": proc.pid}, room=_room(project_id))
    socketio.emit("tool_status",  _tool_status[project_id], room=_room(project_id))
    _emit_line(project_id, "si",
        f"[Crucible] Siphon started — PID {proc.pid}  cwd={cwd}", "system")

    threading.Thread(target=_reader,
        args=(project_id, "si", proc.stdout, "stdout", proc), daemon=True).start()
    threading.Thread(target=_reader,
        args=(project_id, "si", proc.stderr, "stderr", proc), daemon=True).start()
    threading.Thread(target=_wait_proc,
        args=(project_id, "si", proc), daemon=True).start()
    _ensure_watcher(project_id, proj)


@socketio.on("si_kill")
def on_si_kill(data):
    _kill_tool(data.get("project_id", ""), "si")


@socketio.on("si_input")
def on_si_input(data):
    on_vantage_answer({**data, "tool": "si"})


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------
def _write_to_stdin(proc: subprocess.Popen, text: str) -> None:
    """Safely write a line to a subprocess stdin."""
    try:
        if proc.stdin and not proc.stdin.closed:
            proc.stdin.write(text + "\n")
            proc.stdin.flush()
    except Exception:
        pass


def _reader(project_id: str, tool: str, stream,
            stream_name: str, proc: subprocess.Popen) -> None:
    """Drain one stdout/stderr stream.

    stdout: iterated line-by-line (fast).
    stderr: read char-by-char so sudo's password prompt (no trailing newline)
            is detected and forwarded to the browser modal immediately.

    Handles protocol tokens:
      __VANTAGE_LOG__:    -> structured log entry
      __VANTAGE_ERR__:    -> structured error entry
      __VANTAGE_PROMPT__: -> interactive prompt (show modal, block on stdin)
      __VANTAGE_STATUS__: -> phase/step status update
    """
    proj = _get_project(project_id)
    pkey = _pkey(project_id, tool)

    def _process_line(line: str) -> None:
        if not line:
            return

        # Structured log
        if line.startswith(_VP_LOG):
            try:
                entry = json.loads(line[len(_VP_LOG):])
                entry["tool"] = tool
                _buf_append_log(project_id, entry, proj)
            except Exception:
                _emit_line(project_id, tool, line, stream_name)
            return

        # Structured error
        if line.startswith(_VP_ERR):
            try:
                entry = json.loads(line[len(_VP_ERR):])
                entry["tool"] = tool
                if "category" not in entry:
                    entry["category"] = _categorise_error(entry.get("message", ""))
                _buf_append_err(project_id, entry, proj)
            except Exception:
                _emit_line(project_id, tool, line, "stderr")
            return

        # Interactive prompt
        if line.startswith(_VP_PROMPT):
            try:
                payload = json.loads(line[len(_VP_PROMPT):])
                _pending_prompts[pkey] = payload
                socketio.emit("vantage_prompt",
                    {"tool": tool, "payload": payload},
                    room=_room(project_id))
                q = _answer_queues.get(pkey)
                if q:
                    try:
                        answer = q.get(timeout=1800)
                    except queue.Empty:
                        answer = ""
                    _write_to_stdin(proc, answer)
                _pending_prompts.pop(pkey, None)
            except Exception:
                _emit_line(project_id, tool, line, stream_name)
            return

        # Phase status
        if line.startswith(_VP_STATUS):
            try:
                sdata = json.loads(line[len(_VP_STATUS):])
                sdata["tool"] = tool
                sc = _status_cache.setdefault(project_id, {"fr": {}, "si": {}})
                sc.setdefault(tool, {})[sdata.get("phase", "?")] = sdata
                socketio.emit("vantage_status", sdata, room=_room(project_id))
            except Exception:
                _emit_line(project_id, tool, line, stream_name)
            return

        # Sudo password prompt (stderr, possibly no trailing newline)
        if stream_name == "stderr" and _SUDO_PROMPT_RE.search(line):
            payload = {
                "id":        str(uuid.uuid4()),
                "question":  f"Sudo password required  ({line.strip()})",
                "type":      "password",
                "options":   [],
                "skippable": False,
            }
            _pending_prompts[pkey] = payload
            socketio.emit("vantage_prompt",
                {"tool": tool, "payload": payload},
                room=_room(project_id))
            q = _answer_queues.get(pkey)
            if q:
                try:
                    answer = q.get(timeout=300)
                except queue.Empty:
                    answer = ""
                _write_to_stdin(proc, answer)
            _pending_prompts.pop(pkey, None)
            return

        # Regular stderr -> console + error buffer
        if stream_name == "stderr":
            _emit_line(project_id, tool, line, "stderr")
            _buf_append_err(project_id, {
                "ts":       datetime.now(timezone.utc).isoformat(),
                "source":   tool,
                "tool":     tool,
                "message":  line,
                "detail":   "",
                "category": _categorise_error(line),
            }, proj)
            return

        # Regular stdout
        _emit_line(project_id, tool, line, stream_name)

    try:
        if stream_name == "stdout":
            for raw in stream:
                try:
                    _process_line(raw.rstrip("\n"))
                except Exception as _exc:
                    try:
                        _emit_line(project_id, tool,
                                   f"[Crucible] reader error: {_exc}", "system")
                    except Exception:
                        pass
        else:
            # Stderr: read one character at a time so sudo's "Password: " prompt
            # (which has no trailing newline) is detected and shown immediately.
            buf = ""
            while True:
                try:
                    ch = stream.read(1)
                except Exception:
                    break
                if not ch:
                    if buf.strip():
                        try:
                            _process_line(buf)
                        except Exception:
                            pass
                    break
                if ch == "\n":
                    try:
                        _process_line(buf.rstrip("\r"))
                    except Exception as _exc:
                        try:
                            _emit_line(project_id, tool,
                                       f"[Crucible] reader error: {_exc}", "system")
                        except Exception:
                            pass
                    buf = ""
                else:
                    buf += ch
                    if _SUDO_PROMPT_RE.search(buf):
                        try:
                            _process_line(buf.strip())
                        except Exception as _exc:
                            try:
                                _emit_line(project_id, tool,
                                           f"[Crucible] reader error: {_exc}", "system")
                            except Exception:
                                pass
                        buf = ""
    finally:
        try:
            stream.close()
        except (BrokenPipeError, OSError):
            pass


def _wait_proc(project_id: str, tool: str, proc: subprocess.Popen) -> None:
    rc = proc.wait()
    for _pipe in (proc.stdin, proc.stdout, proc.stderr):
        if _pipe is not None:
            try:
                _pipe.close()
            except (BrokenPipeError, OSError):
                pass
    _procs.setdefault(project_id, {"fr": None, "si": None})
    _procs[project_id][tool] = None
    _tool_status.setdefault(project_id, {"fr": "idle", "si": "idle"})
    _tool_status[project_id][tool] = "done"
    _update_project_field(project_id, **{f"{tool}_status": "done"})
    _answer_queues.pop(_pkey(project_id, tool), None)
    _pending_prompts.pop(_pkey(project_id, tool), None)

    label = "Fracture" if tool == "fr" else "Siphon"
    _emit_line(project_id, tool,
        f"[Crucible] {label} exited — return code {rc}", "system")
    socketio.emit(f"{tool}_done",   {"returncode": rc}, room=_room(project_id))
    socketio.emit("tool_status",    _tool_status[project_id], room=_room(project_id))


def _kill_tool(project_id: str, tool: str) -> None:
    proc = (_procs.get(project_id) or {}).get(tool)
    if not proc:
        return
    label = "Fracture" if tool == "fr" else "Siphon"

    try:
        import psutil
        parent = psutil.Process(proc.pid)
        for child in parent.children(recursive=True):
            child.send_signal(signal.SIGTERM)
        parent.send_signal(signal.SIGTERM)
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass

    _emit_line(project_id, tool,
        f"[Crucible] {label} kill signal sent — force-kill in 8 s", "system")

    def _force():
        time.sleep(8)
        try:
            proc.kill()
        except Exception:
            pass

    threading.Thread(target=_force, daemon=True).start()
    socketio.emit(f"{tool}_stopped", {}, room=_room(project_id))


# ---------------------------------------------------------------------------
# Findings watcher — polls output dirs every 5 s
# ---------------------------------------------------------------------------
def _ensure_watcher(project_id: str, proj: dict) -> None:
    if project_id in _watchers and _watchers[project_id].is_alive():
        return
    _watcher_flags[project_id] = True
    t = threading.Thread(target=_finding_watcher, args=(project_id, proj), daemon=True)
    _watchers[project_id] = t
    t.start()


def _finding_watcher(project_id: str, proj: dict) -> None:
    seen: set[tuple] = {_fkey(f) for f in _all_findings.get(project_id, [])}

    while _watcher_flags.get(project_id, False):
        time.sleep(5)
        proj = _get_project(project_id) or proj

        fr_cfg_path = Path(proj.get("fr_settings_file", ""))
        if fr_cfg_path.exists():
            try:
                fr_cfg      = json.loads(fr_cfg_path.read_text())
                fr_proj_name = fr_cfg.get("scan", {}).get("project", "fracture_output")
                fp = Path(proj["project_dir"]) / fr_proj_name / "findings.json"
                _ingest(project_id, fp, "fracture", "webapp", seen)
            except Exception:
                pass

        si_cfg_path = Path(proj.get("si_settings_file", ""))
        if si_cfg_path.exists():
            try:
                si_cfg      = json.loads(si_cfg_path.read_text())
                si_proj_name = si_cfg.get("scan", {}).get("project", "siphon_output")
                fp = Path(proj["project_dir"]) / si_proj_name / "findings.json"
                _ingest(project_id, fp, "siphon", "api", seen)
            except Exception:
                pass

        status = _tool_status.get(project_id, {})
        if status.get("fr") != "running" and status.get("si") != "running":
            time.sleep(60)
            _ingest_all_final(project_id, proj, seen)
            break

    _watcher_flags.pop(project_id, None)


def _ingest_all_final(project_id: str, proj: dict, seen: set) -> None:
    fr_cfg_path = Path(proj.get("fr_settings_file", ""))
    if fr_cfg_path.exists():
        try:
            fr_cfg       = json.loads(fr_cfg_path.read_text())
            fr_proj_name = fr_cfg.get("scan", {}).get("project", "fracture_output")
            fp = Path(proj["project_dir"]) / fr_proj_name / "findings.json"
            _ingest(project_id, fp, "fracture", "webapp", seen)
        except Exception:
            pass
    si_cfg_path = Path(proj.get("si_settings_file", ""))
    if si_cfg_path.exists():
        try:
            si_cfg       = json.loads(si_cfg_path.read_text())
            si_proj_name = si_cfg.get("scan", {}).get("project", "siphon_output")
            fp = Path(proj["project_dir"]) / si_proj_name / "findings.json"
            _ingest(project_id, fp, "siphon", "api", seen)
        except Exception:
            pass


def _fkey(f: dict) -> tuple:
    return (
        (f.get("title") or f.get("detail") or "").strip().lower(),
        (f.get("ip") or "").strip(),
        str(f.get("port") or "0"),
        (f.get("_scope") or "").lower(),
        (f.get("hostname") or f.get("url") or "").strip().lower(),
    )


def _ingest(project_id: str, fp: Path, tool: str, scope: str, seen: set) -> None:
    if not fp.exists():
        return
    try:
        raw_content = json.loads(fp.read_text())
    except Exception:
        return

    if isinstance(raw_content, list):
        items = raw_content
    else:
        return

    proj_findings = _all_findings.setdefault(project_id, [])

    for raw in items:
        f = dict(raw)
        f["_tool"]  = tool
        f["_scope"] = scope or f.get("_scope", "")
        k = _fkey(f)
        if k in seen:
            # Merge sources and cves into existing entry
            for existing in proj_findings:
                if _fkey(existing) == k:
                    changed = False
                    ex_srcs = set(s.strip() for s in (existing.get("sources") or "").split(",") if s.strip())
                    new_srcs = set(s.strip() for s in (f.get("sources") or "").split(",") if s.strip())
                    if new_srcs - ex_srcs:
                        existing["sources"] = ",".join(sorted(ex_srcs | new_srcs))
                        changed = True
                    ex_cves = set(c.strip() for c in (existing.get("cves") or "").split(",") if c.strip())
                    new_cves = set(c.strip() for c in (f.get("cves") or "").split(",") if c.strip())
                    if new_cves - ex_cves:
                        existing["cves"] = ",".join(sorted(ex_cves | new_cves))
                        changed = True
                    if changed:
                        socketio.emit("finding",
                            {"tool": tool[:2], "finding": existing},
                            room=_room(project_id))
                    break
        else:
            seen.add(k)
            proj_findings.append(f)
            socketio.emit("finding",
                {"tool": tool[:2], "finding": f},
                room=_room(project_id))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 54)
    print(f" Crucible — Web & API Assessment Platform  v{VERSION}")
    print(" https://0.0.0.0:5500")
    print("=" * 54)
    socketio.run(app, host="0.0.0.0", port=5500, debug=False,
                 allow_unsafe_werkzeug=True,
                 ssl_context=_auth.make_ssl_context())
