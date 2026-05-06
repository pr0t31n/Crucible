#!/usr/bin/env python3
"""
Crucible — Web & API Assessment Platform
Flask/SocketIO orchestration wrapper for Fracture (web app pentest)
and Siphon (API pentest).
"""
from __future__ import annotations

VERSION = "1.8.27"

import io
import socket
import json
import os
import platform
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

# Flask — https://github.com/pallets/flask
from flask import Flask, jsonify, redirect, render_template, request, send_file, session, url_for
# Flask-SocketIO — https://github.com/miguelgrinberg/Flask-SocketIO
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
import _auth

# ---------------------------------------------------------------------------
# App bootstrap
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = _auth.load_secret_key()
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB — prevents oversized request buffering

# Restrict SocketIO CORS to localhost origins; override via env var if needed
_raw_origins = os.environ.get("CRUCIBLE_ALLOWED_ORIGINS", "").strip()
_cors_origins = (
    [o.strip() for o in _raw_origins.split(",") if o.strip()]
    if _raw_origins
    else [
        "http://localhost:5500",  "http://127.0.0.1:5500",
        "https://localhost:5500", "https://127.0.0.1:5500",
        "http://localhost:5000",  "http://127.0.0.1:5000",  # Nexus hub
        "https://localhost:5000", "https://127.0.0.1:5000",
    ]
)
socketio = SocketIO(app, cors_allowed_origins=_cors_origins, async_mode="threading")

CRUCIBLE_DIR  = Path(__file__).parent.resolve()
PROJECTS_FILE = CRUCIBLE_DIR / "projects.json"
PROJECTS_DIR  = CRUCIBLE_DIR / "projects"
FRACTURE_SCRIPT = Path("/opt/pr0t31n/Fracture/fracture.py")
SIPHON_SCRIPT   = Path("/opt/pr0t31n/Siphon/siphon.py")

PROJECTS_DIR.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# Spec-file upload staging
# ---------------------------------------------------------------------------
SPEC_STAGING_DIR = CRUCIBLE_DIR / "spec_staging"
SPEC_STAGING_DIR.mkdir(exist_ok=True)

_ALLOWED_SPEC_EXTS: frozenset = frozenset({".json", ".yaml", ".yml", ".graphql", ".gql"})
_MAX_SPEC_BYTES: int = 5 * 1024 * 1024  # 5 MB


def _validate_spec_content(content: bytes, ext: str) -> tuple:
    """Validate API spec content.  Returns (format_name, error_string_or_None)."""
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return ("unknown", "File must be UTF-8 encoded text")

    if ext == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            return ("unknown", f"Invalid JSON: {exc}")
        if not isinstance(data, dict):
            return ("unknown", "JSON root must be an object")
        if str(data.get("openapi", "")).startswith("3"):
            return ("openapi3", None)
        if data.get("swagger") == "2.0":
            return ("swagger2", None)
        info = data.get("info", {})
        if isinstance(info, dict) and (
            "_postman_id" in info or "postman" in info.get("schema", "").lower()
        ):
            return ("postman", None)
        if "__schema" in data or (
            isinstance(data.get("data"), dict) and "__schema" in data["data"]
        ):
            return ("graphql_introspection", None)
        if data.get("_type") == "export" and "resources" in data:
            return ("insomnia", None)
        if isinstance(data.get("log"), dict) and "entries" in data["log"]:
            return ("har", None)
        if "paths" in data:
            return ("openapi_json", None)
        return ("json", None)

    if ext in (".yaml", ".yml"):
        try:
            import yaml as _yaml
            data = _yaml.safe_load(text)
            if not isinstance(data, dict):
                return ("unknown", "YAML root must be a mapping")
        except Exception as exc:
            return ("unknown", f"Invalid YAML: {exc}")
        if str(data.get("openapi", "")).startswith("3"):
            return ("openapi3_yaml", None)
        if data.get("swagger") == "2.0":
            return ("swagger2_yaml", None)
        return ("yaml", None)

    if ext in (".graphql", ".gql"):
        import re as _re
        if not _re.search(r'\btype\s+\w+', text):
            return ("unknown", "Does not appear to be a valid GraphQL schema")
        return ("graphql_sdl", None)

    return ("unknown", None)

# ---------------------------------------------------------------------------
# Protocol tokens emitted by Fracture/Siphon when running under Crucible
# ---------------------------------------------------------------------------
_CP_LOG    = "__CRUCIBLE_LOG__:"
_CP_ERR    = "__CRUCIBLE_ERR__:"
_CP_PROMPT = "__CRUCIBLE_PROMPT__:"
_CP_STATUS = "__CRUCIBLE_STATUS__:"

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

# Job queue — execute-project requests that arrive while a scan is running
_job_queue: list = []
_queue_lock = threading.Lock()
_QUEUE_FILE = CRUCIBLE_DIR / "execute_queue.json"

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
            "session": False, "csrf": False, "cross_user": False,
            "logout": False
        },
        "auth": {
            "enabled": False, "auth_method": "form_login",
            "username": "", "password": "",
            "login_url": "", "login_mode": "fields",
            "login_username_field": "username", "login_password_field": "password",
            "login_data": "",
            "auth_token": "", "token_type": "Bearer", "token_response_field": "token",
            "oauth_token_url": "", "oauth_client_id": "", "oauth_client_secret": "",
            "oauth_scope": "",
            "api_key_header": "X-API-Key", "api_key_cookie_name": "api_key",
            "api_key_value": "",
            "session_cookie": "", "domain": "", "custom_headers": {},
        },
        "auth2": {
            "enabled": False, "auth_method": "form_login",
            "username": "", "password": "",
            "login_url": "", "login_mode": "fields",
            "login_username_field": "username", "login_password_field": "password",
            "login_data": "",
            "auth_token": "", "token_type": "Bearer",
            "session_cookie": "", "domain": "", "custom_headers": {},
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
        "api_spec_url": "", "api_spec_file": "", "api_spec_files": [],
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
            Path(proj["project_dir"]) / f"crucible_console_{tool}.jsonl", entry
        )
    socketio.emit(f"{tool}_output", entry, room=_room(project_id))

def _deepcopy_template(t: dict) -> dict:
    return json.loads(json.dumps(t))


def _parse_url_list(raw: str) -> list:
    """Parse a comma or newline-delimited string of URLs into a deduplicated list."""
    urls = []
    seen: set = set()
    for part in re.split(r'[,\n]+', raw or ""):
        u = part.strip().rstrip("/")
        if u and u not in seen:
            seen.add(u)
            urls.append(u)
    return urls


def _commit_staged_spec_files(file_ids: list, dest_dir: Path) -> list:
    """Move staged spec files to dest_dir and return their absolute paths.

    file_ids is a list of UUIDs returned by /api/upload_spec_temp.
    Files not found in staging are silently skipped.
    """
    paths: list = []
    if not file_ids:
        return paths
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        return paths
    for fid in file_ids:
        fid = str(fid).strip()
        if not fid:
            continue
        # Find the staged file (any allowed extension)
        for ext in _ALLOWED_SPEC_EXTS:
            staged = SPEC_STAGING_DIR / f"{fid}{ext}"
            if staged.exists():
                dest = dest_dir / staged.name
                try:
                    shutil.move(str(staged), str(dest))
                    paths.append(str(dest))
                except Exception:
                    pass
                break
    return paths

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
        _append_jsonl(Path(proj["project_dir"]) / "crucible_logs.jsonl", entry)
    socketio.emit("log_entry", {"tool": entry.get("tool", ""), "entry": entry},
                  room=_room(project_id))

def _buf_append_err(project_id: str, entry: dict, proj: dict | None = None) -> None:
    lst = _err_buffers.setdefault(project_id, [])
    lst.append(entry)
    if len(lst) > _MAX_ERR:
        del lst[0]
    if proj:
        _append_jsonl(Path(proj["project_dir"]) / "crucible_errors.jsonl", entry)
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
def _checkpoint_status(proj: dict, tool: str) -> str:
    """Return 'complete' if the tool's checkpoint.json has completed phases, else 'idle'."""
    try:
        settings_file = proj.get("fr_settings_file" if tool == "fr" else "si_settings_file", "")
        cfg = json.loads(Path(settings_file).read_text())
        proj_name = cfg.get("scan", {}).get(
            "project", "fracture_output" if tool == "fr" else "siphon_output"
        )
        cp = Path(proj["project_dir"]) / proj_name / "checkpoint.json"
        if cp.exists():
            data = json.loads(cp.read_text())
            if data.get("completed_phases"):
                return "complete"
    except Exception:
        pass
    return "idle"


def _init_project_state(project_id: str) -> None:
    _procs.setdefault(project_id,    {"fr": None, "si": None})
    _buffers.setdefault(project_id,  {"fr": [],   "si": []})
    _all_findings.setdefault(project_id, [])
    _status_cache.setdefault(project_id, {"fr": {}, "si": {}})
    if project_id not in _tool_status:
        proj_data = _get_project(project_id)
        fr_s = "idle"
        si_s = "idle"
        if proj_data:
            for _tool, _var in (("fr", "fr_status"), ("si", "si_status")):
                raw = proj_data.get(_var, "idle")
                if raw in ("complete", "done"):
                    if _tool == "fr":
                        fr_s = raw
                    else:
                        si_s = raw
                elif raw == "running":
                    # Process was killed / server restarted — derive real status from checkpoint
                    derived = _checkpoint_status(proj_data, _tool)
                    if _tool == "fr":
                        fr_s = derived
                    else:
                        si_s = derived
                    _update_project_field(project_id, **{_var: derived})
        _tool_status[project_id] = {"fr": fr_s, "si": si_s}

# ---------------------------------------------------------------------------
# Project directory helpers
# ---------------------------------------------------------------------------
def _clients_base() -> Path:
    """Return the OS-appropriate clients root directory, creating it if absent."""
    system = platform.system()
    if system == "Darwin":
        base = Path("/Users/Shared/clients")
    elif system == "Windows":
        base = Path("C:/clients")
    else:
        base = Path("/clients")
    try:
        base.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        base = Path.home() / "clients"
        base.mkdir(parents=True, exist_ok=True)
    return base

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

def _build_project_dir(client_short: str, year: str, tool_name: str) -> Path:
    """
    Return structured project directory (created if absent):
      <clients_base>/<client_short>/<year>/<tool_name>/<client_short>_<datetime>/
    """
    slug = re.sub(r'[^\w-]', '_', (client_short or 'client').strip().lower()).strip('_') or 'client'
    dt_str = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    path = _clients_base() / slug / year / tool_name / f"{slug}_{dt_str}"
    try:
        path.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        path = CRUCIBLE_DIR / "output" / tool_name / f"{slug}_{dt_str}"
        path.mkdir(parents=True, exist_ok=True)
    return path

def _build_si_auth_from_body(body: dict, existing: "dict | None" = None) -> dict:
    """
    Build a Siphon scan.auth dict from the form body keys (si_auth_*).

    In edit mode pass `existing` to preserve password/secret fields that were
    intentionally left blank (the UI does not echo sensitive values back).
    """
    method = body.get("si_auth_method", "none")
    if method == "none":
        return {"enabled": False, "method": "bearer"}

    ex = existing or {}

    def _keep(field: str, form_key: str, default: str = "") -> str:
        """Return form value; fall back to existing setting when blank."""
        v = body.get(form_key, "").strip()
        return v if v else ex.get(field, default)

    def _json_field(form_key: str, existing_key: str, default: str = "{}") -> object:
        raw = body.get(form_key, "").strip()
        if raw:
            try:
                return json.loads(raw)
            except Exception:
                return raw
        return ex.get(existing_key, default)

    auth: dict = {
        "enabled":               True,
        "method":                method,
        # Bearer / JWT
        "auth_token":            _keep("auth_token",         "si_auth_token"),
        "token_type":            _keep("token_type",         "si_auth_token_type",     "Bearer"),
        # Basic / Digest / NTLM / NTLMv2
        "username":              _keep("username",           "si_auth_username"),
        "password":              _keep("password",           "si_auth_password"),
        "domain":                _keep("domain",             "si_auth_domain"),
        # Kerberos
        "kerberos_principal":    _keep("kerberos_principal", "si_auth_kerberos_principal"),
        # API Key (header / query)
        "api_key":               _keep("api_key",            "si_auth_api_key"),
        "api_key_header":        _keep("api_key_header",     "si_auth_api_key_header", "X-API-Key"),
        "api_key_query":         _keep("api_key_query",      "si_auth_api_key_query"),
        # API Key Cookie
        "api_key_cookie_name":   _keep("api_key_cookie_name","si_auth_api_key_cookie_name",   "api_key"),
        "api_key_cookie_domain": _keep("api_key_cookie_domain","si_auth_api_key_cookie_domain"),
        # Login endpoint
        "login_url":             _keep("login_url",          "si_auth_login_url"),
        "login_method":          _keep("login_method",       "si_auth_login_method",   "POST"),
        "login_mode":            _keep("login_mode",         "si_auth_login_mode",     "fields"),
        "login_data":            _keep("login_data",         "si_auth_login_data",     "{}"),
        "login_content_type":    _keep("login_content_type", "si_auth_login_ct",       "application/json"),
        "login_username_field":  _keep("login_username_field","si_auth_login_ufield",  "username"),
        "login_password_field":  _keep("login_password_field","si_auth_login_pfield",  "password"),
        "login_token_path":      _keep("login_token_path",   "si_auth_token_path",     "token"),
        # CSRF (session_cookie)
        "csrf_field":            _keep("csrf_field",         "si_auth_csrf_field"),
        "csrf_header":           _keep("csrf_header",        "si_auth_csrf_header"),
        # OAuth2 (CC / Password / OIDC)
        "oauth_token_url":       _keep("oauth_token_url",    "si_auth_oauth_token_url"),
        "oauth_client_id":       _keep("oauth_client_id",    "si_auth_oauth_client_id"),
        "oauth_client_secret":   _keep("oauth_client_secret","si_auth_oauth_client_secret"),
        "oauth_scope":           _keep("oauth_scope",        "si_auth_oauth_scope"),
        # OAuth 1.0a
        "oauth1_consumer_key":   _keep("oauth1_consumer_key",  "si_auth_oauth1_consumer_key"),
        "oauth1_consumer_secret":_keep("oauth1_consumer_secret","si_auth_oauth1_consumer_secret"),
        "oauth1_token":          _keep("oauth1_token",         "si_auth_oauth1_token"),
        "oauth1_token_secret":   _keep("oauth1_token_secret",  "si_auth_oauth1_token_secret"),
        # OIDC
        "oidc_id_token":         _keep("oidc_id_token",      "si_auth_oidc_id_token"),
        # SAML
        "saml_assertion":        _keep("saml_assertion",     "si_auth_saml_assertion"),
        "saml_token_url":        _keep("saml_token_url",     "si_auth_saml_token_url"),
        # mTLS
        "mtls_cert":             _keep("mtls_cert",          "si_auth_mtls_cert"),
        "mtls_key":              _keep("mtls_key",           "si_auth_mtls_key"),
        "mtls_ca_bundle":        _keep("mtls_ca_bundle",     "si_auth_mtls_ca_bundle"),
        # TOTP MFA
        "totp_secret":           _keep("totp_secret",        "si_auth_totp_secret"),
        "totp_field":            _keep("totp_field",         "si_auth_totp_field",     "otp"),
        # HMAC Signature
        "hmac_key_id":           _keep("hmac_key_id",        "si_auth_hmac_key_id"),
        "hmac_secret":           _keep("hmac_secret",        "si_auth_hmac_secret"),
        "hmac_algorithm":        _keep("hmac_algorithm",     "si_auth_hmac_algorithm", "sha256"),
        "hmac_header":           _keep("hmac_header",        "si_auth_hmac_header",    "Authorization"),
        # AWS SigV4
        "aws_access_key_id":     _keep("aws_access_key_id",     "si_auth_aws_access_key_id"),
        "aws_secret_access_key": _keep("aws_secret_access_key", "si_auth_aws_secret_access_key"),
        "aws_region":            _keep("aws_region",            "si_auth_aws_region",  "us-east-1"),
        "aws_service":           _keep("aws_service",           "si_auth_aws_service", "execute-api"),
        "aws_session_token":     _keep("aws_session_token",     "si_auth_aws_session_token"),
        # Custom headers
        "custom_headers":        _json_field("si_auth_custom_headers", "custom_headers", "{}"),
    }
    return auth


def _build_fr_auth_from_body(body: dict, existing: "dict | None" = None) -> dict:
    """
    Build a Fracture scan.auth dict from form body keys (fr_auth_*).
    In edit mode pass `existing` to preserve password/secret fields left blank.
    """
    method = body.get("fr_auth_method", "none")
    if method == "none":
        return {"enabled": False, "auth_method": "form_login"}

    ex = existing or {}

    def _keep(field: str, form_key: str, default: str = "") -> str:
        v = body.get(form_key, "").strip()
        return v if v else ex.get(field, default)

    def _json_field(form_key: str, existing_key: str, default: str = "{}") -> object:
        raw = body.get(form_key, "").strip()
        if raw:
            try:
                return json.loads(raw)
            except Exception:
                return raw
        return ex.get(existing_key, default)

    auth: dict = {
        "enabled":               True,
        "method":                method,
        "auth_method":           method,   # legacy alias kept for compat
        # Universal credentials
        "username":              _keep("username",              "fr_auth_username"),
        "password":              _keep("password",              "fr_auth_password"),
        "domain":                _keep("domain",                "fr_auth_domain"),
        # Token / bearer
        "auth_token":            _keep("auth_token",            "fr_auth_token"),
        "token_type":            _keep("token_type",            "fr_auth_token_type",     "Bearer"),
        "token_response_field":  _keep("token_response_field",  "fr_auth_token_field",    "token"),
        # Form / token login endpoint
        "login_url":             _keep("login_url",             "fr_auth_login_url"),
        "login_mode":            _keep("login_mode",            "fr_auth_login_mode",     "fields"),
        "login_data":            _keep("login_data",            "fr_auth_login_data",     "{}"),
        "login_content_type":    _keep("login_content_type",    "fr_auth_login_ct",       "application/x-www-form-urlencoded"),
        "login_username_field":  _keep("login_username_field",  "fr_auth_login_ufield",   "username"),
        "login_password_field":  _keep("login_password_field",  "fr_auth_login_pfield",   "password"),
        "login_token_path":      _keep("login_token_path",      "fr_auth_token_path",     "token"),
        # OAuth2
        "oauth_token_url":       _keep("oauth_token_url",       "fr_auth_oauth_token_url"),
        "oauth_client_id":       _keep("oauth_client_id",       "fr_auth_oauth_client_id"),
        "oauth_client_secret":   _keep("oauth_client_secret",   "fr_auth_oauth_client_secret"),
        "oauth_scope":           _keep("oauth_scope",           "fr_auth_oauth_scope"),
        "client_auth_method":    _keep("client_auth_method",    "fr_auth_oauth_client_auth", "body"),
        # OAuth 1.0a
        "oauth1_consumer_key":   _keep("oauth1_consumer_key",   "fr_auth_oauth1_consumer_key"),
        "oauth1_consumer_secret":_keep("oauth1_consumer_secret","fr_auth_oauth1_consumer_secret"),
        "oauth1_access_token":   _keep("oauth1_access_token",   "fr_auth_oauth1_access_token"),
        "oauth1_token_secret":   _keep("oauth1_token_secret",   "fr_auth_oauth1_token_secret"),
        # SAML
        "saml_acs_url":          _keep("saml_acs_url",          "fr_auth_saml_acs_url"),
        "saml_assertion":        _keep("saml_assertion",        "fr_auth_saml_assertion"),
        "saml_relay_state":      _keep("saml_relay_state",      "fr_auth_saml_relay_state"),
        # OIDC
        "oidc_id_token":         _keep("oidc_id_token",         "fr_auth_oidc_id_token"),
        "oidc_userinfo_url":     _keep("oidc_userinfo_url",     "fr_auth_oidc_userinfo_url"),
        # mTLS
        "mtls_cert":             _keep("mtls_cert",             "fr_auth_mtls_cert"),
        "mtls_key":              _keep("mtls_key",              "fr_auth_mtls_key"),
        "mtls_ca_bundle":        _keep("mtls_ca_bundle",        "fr_auth_mtls_ca_bundle"),
        # TOTP MFA
        "totp_secret":           _keep("totp_secret",           "fr_auth_totp_secret"),
        "totp_mfa_url":          _keep("totp_mfa_url",          "fr_auth_totp_mfa_url"),
        "totp_field":            _keep("totp_field",            "fr_auth_totp_field",     "otp"),
        # WebAuthn
        "webauthn_probe_url":    _keep("webauthn_probe_url",    "fr_auth_webauthn_probe_url"),
        # API key
        "api_key":               _keep("api_key",               "fr_auth_api_key_value"),
        "api_key_header":        _keep("api_key_header",        "fr_auth_api_key_header", "X-API-Key"),
        "api_key_cookie":        _keep("api_key_cookie",        "fr_auth_api_key_cookie", "api_key"),
        # Pre-captured session
        "session_cookie":        _keep("session_cookie",        "fr_auth_session_cookie"),
        # Kerberos
        "kerberos_impersonate":  _keep("kerberos_impersonate",  "fr_auth_kerberos_impersonate"),
        # Proxy / gateway auth header
        "proxy_header_name":     _keep("proxy_header_name",     "fr_auth_proxy_header_name",  "X-Remote-User"),
        "proxy_header_value":    _keep("proxy_header_value",    "fr_auth_proxy_header_value"),
        # Custom headers
        "custom_headers":        _json_field("fr_auth_custom_headers", "custom_headers", "{}"),
        # Login profile — ID of a stored Fracture login profile to replay.
        # Populated automatically from AuthProbe output; can also be set manually.
        # Empty string means auto-detect (fingerprint matching); a specific ID
        # pins the profile; "none" forces a fresh browser-assisted login.
        "login_profile_id":      _keep("login_profile_id",      "fr_auth_login_profile_id"),
    }
    return auth


def _parse_auth_matrix_from_body(body: dict) -> list:
    """Parse the auth_matrix JSON string from the form body into a list of role dicts."""
    raw = body.get("auth_matrix", "")
    if not raw:
        return []
    try:
        matrix = json.loads(raw) if isinstance(raw, str) else raw
        if not isinstance(matrix, list):
            return []
        result = []
        for entry in matrix:
            if not isinstance(entry, dict):
                continue
            role     = (entry.get("role") or "").strip()
            username = (entry.get("username") or "").strip()
            password = entry.get("password") or ""
            if role and username:
                result.append({"role": role, "username": username, "password": password})
        return result
    except Exception:
        return []


def _discover_client_projects(tools: list) -> list:
    """
    Walk <clients_base>/<client>/<year>/<tool>/<run>/project_meta.json
    and return records for matching tools that are not already registered.
    """
    base = _clients_base()
    registered = set(_load_projects()["projects"].keys())
    found = []
    if not base.exists():
        return found
    for meta_file in base.glob("*/*/*/*/project_meta.json"):
        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
            if meta.get("tool") not in tools:
                continue
            proj_path = str(meta_file.parent)
            # Skip if already registered by path
            if any(p.get("project_dir") == proj_path or
                   p.get("fracture_output_dir", "").startswith(proj_path) or
                   p.get("siphon_output_dir", "").startswith(proj_path)
                   for p in _load_projects()["projects"].values()):
                continue
            found.append({"path": proj_path, "meta": meta})
        except Exception:
            pass
    return found

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
# ---------------------------------------------------------------------------
# Spec file upload — staging area (used before project creation/update)
# ---------------------------------------------------------------------------
@app.route("/api/upload_spec_temp", methods=["POST"])
def api_upload_spec_temp():
    """Stage an API spec file upload with real-time format validation.

    Security controls:
    - Extension allowlist (.json, .yaml, .yml, .graphql, .gql)
    - Hard 5 MB size cap (read-limited before save)
    - UTF-8 content enforcement
    - secure_filename() prevents path traversal
    - UUID-prefixed filenames prevent collision/guessing
    - Content validated (JSON parsed, YAML parsed, GraphQL pattern checked)
    """
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f = request.files["file"]
    original_name = (f.filename or "").strip()
    if not original_name:
        return jsonify({"error": "Empty filename"}), 400

    safe_name = secure_filename(original_name)
    ext = Path(safe_name).suffix.lower()
    if ext not in _ALLOWED_SPEC_EXTS:
        return jsonify({
            "error": f"File type '{ext}' not allowed. "
                     f"Allowed: {', '.join(sorted(_ALLOWED_SPEC_EXTS))}"
        }), 400

    # Read content with hard cap (read one byte over limit to detect oversize)
    content = f.read(_MAX_SPEC_BYTES + 1)
    if len(content) > _MAX_SPEC_BYTES:
        return jsonify({"error": f"File exceeds maximum size of {_MAX_SPEC_BYTES // 1024 // 1024} MB"}), 400

    fmt, err = _validate_spec_content(content, ext)
    if err:
        return jsonify({"error": f"Invalid spec file: {err}"}), 400

    file_id = str(uuid.uuid4())
    staged_path = SPEC_STAGING_DIR / f"{file_id}{ext}"
    staged_path.write_bytes(content)

    return jsonify({
        "file_id":  file_id,
        "filename": safe_name,
        "format":   fmt,
        "size":     len(content),
        "ext":      ext,
    })


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
    return jsonify({"app": "crucible", "tool": "crucible", "hostname": socket.gethostname(), "scanning": active, "version": VERSION})

# ---------------------------------------------------------------------------
# Arbiter integration — project list endpoint
# ---------------------------------------------------------------------------
@app.route("/api/arbiter-projects")
def api_arbiter_projects():
    """Return a normalized project list for Arbiter discovery."""
    data = _load_projects()
    out = []
    for pid, proj in data.get("projects", {}).items():
        scope = proj.get("scope", "")
        # Determine which tools are in scope — scope field is authoritative
        if scope == "both":
            tools = ["fracture", "siphon"]
        elif scope in ("api", "siphon"):
            tools = ["siphon"]
        else:
            # "webapp", "fracture", legacy, or unknown → fracture only
            tools = ["fracture"]
        # Determine project status from per-tool status fields
        fr_status = proj.get("fr_status", "idle")
        si_status = proj.get("si_status", "idle")
        in_scope_statuses = []
        if "fracture" in tools:
            in_scope_statuses.append(fr_status)
        if "siphon" in tools:
            in_scope_statuses.append(si_status)
        if in_scope_statuses and all(s in ("complete", "done") for s in in_scope_statuses):
            proj_status = "complete"
        elif any(s == "running" for s in in_scope_statuses):
            proj_status = "running"
        else:
            proj_status = "idle"
        # Count findings on disk
        finding_count = 0
        for _tool_name, _dir_key in (("fracture", "fracture_output_dir"), ("siphon", "siphon_output_dir")):
            d = proj.get(_dir_key, "")
            if d:
                fp = Path(d) / "findings.json"
                if not fp.exists():
                    fp = Path(proj.get("project_dir", "")) / _dir_key / "findings.json"
                try:
                    finding_count += len(json.loads(fp.read_text())) if fp.exists() else 0
                except Exception:
                    pass
        out.append({
            "id":            pid,
            "name":          proj.get("name", pid),
            "client_name":   proj.get("client_name") or proj.get("client_short", ""),
            "tools":         tools,
            "scope":         scope,
            "status":        proj_status,
            "completed":     proj_status == "complete",
            "created":       proj.get("created", ""),
            "project_dir":   proj.get("project_dir", ""),
            "fracture_dir":  proj.get("fracture_output_dir", ""),
            "siphon_dir":    proj.get("siphon_output_dir", ""),
            "finding_count": finding_count,
            "has_findings":  finding_count > 0,
        })
    return jsonify(out)

# ---------------------------------------------------------------------------
# HTTP routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    data = _load_projects()
    # Auto-import projects discovered in the clients directory
    discovered = _discover_client_projects(["fracture", "siphon"])
    if discovered:
        changed = False
        for item in discovered:
            pid = str(uuid.uuid4())
            meta = item["meta"]
            tool = meta.get("tool", "fracture")
            proj_path = Path(item["path"])
            # Locate settings file written alongside the run
            fr_path = proj_path / "fr_settings.json"
            si_path = proj_path / "si_settings.json"
            data["projects"][pid] = {
                "name":              f"{meta.get('client_short','?')} — discovered ({tool})",
                "client_name":       meta.get("client_short", ""),
                "client_short":      meta.get("client_short", ""),
                "scope":             tool,
                "created":           meta.get("created_at", "")[:10],
                "project_dir":       str(proj_path),
                "fr_settings_file":  str(fr_path) if fr_path.exists() else "",
                "si_settings_file":  str(si_path) if si_path.exists() else "",
                "fracture_output_dir": str(proj_path) if tool == "fracture" else "",
                "siphon_output_dir":   str(proj_path) if tool == "siphon"   else "",
                "tools":             [tool[:2]],
                "fr_status":         "complete" if tool == "fracture" else "idle",
                "si_status":         "complete" if tool == "siphon"   else "idle",
                "fr_last_run":       None,
                "si_last_run":       None,
            }
            changed = True
        if changed:
            _save_projects(data)
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
def _write_initial_access_matrix(output_dir: Path, auth_matrix: list) -> None:
    """Create or update access_matrix.json with role columns pre-initialized.

    Preserves any existing path data; adds null entries for new roles so
    Crucible shows all columns immediately (displaying — for unprobed slots).
    """
    roles = [r.get("role") or f"role_{i+1}" for i, r in enumerate(auth_matrix)]
    if "unauthenticated" not in roles:
        roles.append("unauthenticated")
    am_path = output_dir / "access_matrix.json"
    try:
        existing = json.loads(am_path.read_text()) if am_path.exists() else {}
    except Exception:
        existing = {}
    merged_roles = list(existing.get("roles", []))
    for r in roles:
        if r not in merged_roles:
            merged_roles.append(r)
    paths = existing.get("paths", [])
    for entry in paths:
        acc = entry.setdefault("access", {})
        for r in merged_roles:
            if r not in acc:
                acc[r] = None
    output_dir.mkdir(parents=True, exist_ok=True)
    am_path.write_text(json.dumps({
        "roles":            merged_roles,
        "most_privileged":  existing.get("most_privileged") or (merged_roles[0] if len(merged_roles) > 1 else None),
        "privilege_counts": existing.get("privilege_counts", {}),
        "paths":            paths,
    }, indent=2))


@app.route("/api/create_project", methods=["POST"])
def api_create_project():
    body = request.json or {}
    project_id = str(uuid.uuid4())
    cfg_dir    = PROJECTS_DIR / project_id
    cfg_dir.mkdir(parents=True, exist_ok=True)

    # Derive client-scoped project directory using structured layout:
    # <clients_base>/<client_short>/<year>/<tool>/<client_short>_<datetime>/
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

    # Per-tool output directories under the structured client path
    fr_output_dir = _build_project_dir(client_short, year, "fracture")
    si_output_dir = _build_project_dir(client_short, year, "siphon")
    # Config/settings files live alongside the Fracture output directory
    project_dir   = fr_output_dir

    # Build Fracture settings — output goes to its own structured directory
    fr = _deepcopy_template(FR_DEFAULTS)
    for k in fr["engagement"]:
        fr["engagement"][k] = body.get(k, "")
    fr["scan"]["project"] = str(fr_output_dir)
    # Multi-URL: textarea sends comma/newline delimited URLs
    fr_urls_raw = body.get("fr_target_urls", "") or body.get("fr_target_url", "")
    fr_url_list = _parse_url_list(fr_urls_raw)
    fr["scan"]["target_url"]  = fr_url_list[0] if fr_url_list else ""
    fr["scan"]["target_urls"] = fr_url_list

    # Build Siphon settings — output goes to its own structured directory
    si = _deepcopy_template(SI_DEFAULTS)
    for k in si["engagement"]:
        si["engagement"][k] = body.get(k, "")
    si["scan"]["project"] = str(si_output_dir)
    # Multi-URL: textarea sends comma/newline delimited URLs
    si_urls_raw = body.get("si_target_urls", "") or body.get("si_target_url", "")
    si_url_list = _parse_url_list(si_urls_raw)
    si["scan"]["api_base_url"]  = si_url_list[0] if si_url_list else ""
    si["scan"]["api_base_urls"] = si_url_list[1:] if len(si_url_list) > 1 else []
    si["scan"]["api_spec_url"]  = body.get("si_api_spec_url", "")

    # Move staged spec files into the siphon output directory
    spec_dir = si_output_dir / "spec_files"
    spec_file_paths = _commit_staged_spec_files(
        body.get("si_api_spec_file_ids", []), spec_dir
    )
    si["scan"]["api_spec_files"] = spec_file_paths

    # Fracture auth
    if body.get("fr_auth_method") and body["fr_auth_method"] != "none":
        fr["scan"]["auth"] = _build_fr_auth_from_body(body)
        # Enable auth-dependent phases now that credentials are configured
        for _ap in ("auth_recon", "authorization", "session", "csrf", "logout"):
            fr["scan"]["phases"][_ap] = True

    # Siphon auth
    si["scan"]["auth"] = _build_si_auth_from_body(body)

    # Multi-credential access matrix
    auth_matrix = _parse_auth_matrix_from_body(body)
    if auth_matrix:
        fr["scan"]["auth_matrix"] = auth_matrix
        si["scan"]["auth_matrix"] = auth_matrix

    fr_path = fr_output_dir / "fr_settings.json"
    si_path = si_output_dir / "si_settings.json"
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
        "fracture_output_dir": str(fr_output_dir),
        "siphon_output_dir":   str(si_output_dir),
        "tools":             tools,
        "fr_status":         "idle",
        "si_status":         "idle",
        "fr_last_run":       None,
        "si_last_run":       None,
    }

    data = _load_projects()
    data["projects"][project_id] = proj
    _save_projects(data)
    if auth_matrix:
        try:
            _write_initial_access_matrix(fr_output_dir, auth_matrix)
            _write_initial_access_matrix(si_output_dir, auth_matrix)
        except Exception:
            pass
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
        # Multi-URL textarea
        if body.get("fr_target_urls") is not None or body.get("fr_target_url") is not None:
            fr_urls_raw = body.get("fr_target_urls", "") or body.get("fr_target_url", "")
            fr_url_list = _parse_url_list(fr_urls_raw)
            fr["scan"]["target_url"]  = fr_url_list[0] if fr_url_list else ""
            fr["scan"]["target_urls"] = fr_url_list
        # Fracture auth (only update when method key present in body)
        if "fr_auth_method" in body:
            fr["scan"]["auth"] = _build_fr_auth_from_body(body, fr["scan"].get("auth"))
            if body.get("fr_auth_method") and body["fr_auth_method"] != "none":
                for _ap in ("auth_recon", "authorization", "session", "csrf", "logout"):
                    fr["scan"]["phases"][_ap] = True
        if "auth_matrix" in body:
            fr["scan"]["auth_matrix"] = _parse_auth_matrix_from_body(body)
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
        # Multi-URL textarea
        if body.get("si_target_urls") is not None or body.get("si_target_url") is not None:
            si_urls_raw = body.get("si_target_urls", "") or body.get("si_target_url", "")
            si_url_list = _parse_url_list(si_urls_raw)
            si["scan"]["api_base_url"]  = si_url_list[0] if si_url_list else ""
            si["scan"]["api_base_urls"] = si_url_list[1:] if len(si_url_list) > 1 else []
        if body.get("si_api_spec_url") is not None:
            si["scan"]["api_spec_url"] = body["si_api_spec_url"]
        # Commit any newly staged spec files
        spec_file_ids = body.get("si_api_spec_file_ids", [])
        if spec_file_ids:
            si_out_dir = Path(proj.get("siphon_output_dir", si["scan"].get("project", "")))
            spec_dir = si_out_dir / "spec_files"
            new_paths = _commit_staged_spec_files(spec_file_ids, spec_dir)
            existing = si["scan"].get("api_spec_files", [])
            si["scan"]["api_spec_files"] = existing + [p for p in new_paths if p not in existing]
        # Siphon auth (only update when method key present in body)
        if "si_auth_method" in body:
            si["scan"]["auth"] = _build_si_auth_from_body(body, si["scan"].get("auth"))
        if "auth_matrix" in body:
            si["scan"]["auth_matrix"] = _parse_auth_matrix_from_body(body)
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
    if "auth_matrix" in body:
        try:
            _upd_am = _parse_auth_matrix_from_body(body)
            if _upd_am:
                _write_initial_access_matrix(Path(proj["fracture_output_dir"]), _upd_am)
                _write_initial_access_matrix(Path(proj["siphon_output_dir"]), _upd_am)
        except Exception:
            pass
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


@app.route("/api/test_siphon_auth", methods=["POST"])
def api_test_siphon_auth():
    """Run testConnection.py to verify Siphon auth config without starting a full scan."""
    body = request.json or {}
    test_url = (body.get("url") or "").strip()
    if not test_url:
        return jsonify({"success": False, "message": "No API URL provided"})

    tc_script = Path(__file__).parent.parent / "Siphon" / "testConnection.py"
    if not tc_script.exists():
        return jsonify({"success": False, "message": "testConnection.py not found alongside Siphon"})

    payload = {
        "url":        test_url,
        "auth":       body.get("auth", {}),
        "timeout":    int(body.get("timeout", 10)),
        "verify_ssl": bool(body.get("verify_ssl", False)),
        "proxy":      body.get("proxy", ""),
    }
    try:
        proc = subprocess.run(
            [sys.executable, str(tc_script), "--json", json.dumps(payload),
             "--output-json", "--no-verify"],
            capture_output=True, text=True, timeout=35,
        )
        try:
            return jsonify(json.loads(proc.stdout.strip()))
        except Exception:
            return jsonify({
                "success": proc.returncode == 0,
                "message": (proc.stdout.strip() or proc.stderr.strip() or "No output"),
                "auth_info": "",
                "status_code": None,
            })
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "message": "Test timed out (35 s)"})
    except Exception as exc:
        return jsonify({"success": False, "message": str(exc)})


@app.route("/api/test_fracture_auth", methods=["POST"])
def api_test_fracture_auth():
    """Run Fracture's testConnection.py to verify web app auth config."""
    body = request.json or {}
    test_url = (body.get("url") or "").strip()
    if not test_url:
        return jsonify({"success": False, "message": "No target URL provided"})

    tc_script = Path("/opt/pr0t31n/Fracture/testConnection.py")
    if not tc_script.exists():
        return jsonify({"success": False, "message": "Fracture testConnection.py not found"})

    payload = {
        "url":        test_url,
        "auth":       body.get("auth", {}),
        "timeout":    int(body.get("timeout", 10)),
        "verify_ssl": bool(body.get("verify_ssl", False)),
        "proxy":      body.get("proxy", ""),
    }
    try:
        proc = subprocess.run(
            [sys.executable, str(tc_script), "--json", json.dumps(payload),
             "--output-json", "--no-verify"],
            capture_output=True, text=True, timeout=35,
        )
        try:
            return jsonify(json.loads(proc.stdout.strip()))
        except Exception:
            return jsonify({
                "success": proc.returncode == 0,
                "message": (proc.stdout.strip() or proc.stderr.strip() or "No output"),
                "auth_info": "",
                "status_code": None,
            })
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "message": "Test timed out (35 s)"})
    except Exception as exc:
        return jsonify({"success": False, "message": str(exc)})


@app.route("/api/test-connection", methods=["POST"])
def api_test_connection():
    """Unified connection test endpoint for both Fracture (fr) and Siphon (si).

    Body: {"tool": "fr"|"si", "url": "...", "auth": {...}, "timeout": 10, ...}
    Returns the same shape as the per-tool test endpoints.
    """
    body = request.json or {}
    tool = (body.get("tool") or "fr").strip().lower()
    test_url = (body.get("url") or "").strip()
    if not test_url:
        return jsonify({"success": False, "message": "No URL provided"}), 400
    if tool not in ("fr", "si"):
        return jsonify({"success": False, "message": f"Unknown tool '{tool}'. Use 'fr' or 'si'"}), 400

    if tool == "fr":
        tc_script = Path("/opt/pr0t31n/Fracture/testConnection.py")
        if not tc_script.exists():
            tc_script = CRUCIBLE_DIR.parent / "Fracture" / "testConnection.py"
        if not tc_script.exists():
            return jsonify({"success": False,
                            "message": "Fracture testConnection.py not found"}), 500
    else:
        tc_script = CRUCIBLE_DIR.parent / "Siphon" / "testConnection.py"
        if not tc_script.exists():
            return jsonify({"success": False,
                            "message": "Siphon testConnection.py not found"}), 500

    payload = {
        "url":        test_url,
        "auth":       body.get("auth", {}),
        "timeout":    int(body.get("timeout", 10)),
        "verify_ssl": bool(body.get("verify_ssl", False)),
        "proxy":      body.get("proxy", ""),
    }
    try:
        proc = subprocess.run(
            [sys.executable, str(tc_script), "--json", json.dumps(payload),
             "--output-json", "--no-verify"],
            capture_output=True, text=True, timeout=35,
        )
        try:
            return jsonify(json.loads(proc.stdout.strip()))
        except Exception:
            return jsonify({
                "success":     proc.returncode == 0,
                "message":     (proc.stdout.strip() or proc.stderr.strip() or "No output"),
                "auth_info":   "",
                "status_code": None,
            })
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "message": "Test timed out (35 s)"})
    except Exception as exc:
        return jsonify({"success": False, "message": str(exc)})


@app.route("/api/authprobe", methods=["POST"])
def api_authprobe():
    """Run AuthProbe against a target URL and return plain-text output."""
    body = request.json or {}
    target_url = (body.get("url") or "").strip()
    if not target_url:
        return jsonify({"success": False, "error": "No URL provided"})

    authprobe_script = Path("/opt/pr0t31n/AuthProbe/authprobe.py")
    if not authprobe_script.exists():
        return jsonify({"success": False,
                        "error": "AuthProbe not found at /opt/pr0t31n/AuthProbe/authprobe.py"})

    cmd = [sys.executable, str(authprobe_script), "--url", target_url]
    username = (body.get("username") or "").strip()
    password = (body.get("password") or "").strip()
    if username:
        cmd += ["--username", username]
    if password:
        cmd += ["--password", password]
    if body.get("rendered"):
        cmd.append("--rendered")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
        raw = proc.stdout + (("\n" + proc.stderr) if proc.stderr.strip() else "")
        # Strip ANSI escape codes (AuthProbe disables them for non-tty, but just in case)
        output = re.sub(r'\x1b\[[0-9;]*m', '', raw).strip()

        # Extract matched login profile ID from the output so the UI can surface
        # it and optionally pre-fill fr_auth_login_profile_id for the next scan.
        _lp_id = ""
        _lp_conf = 0
        for _ln in output.splitlines():
            _ln = _ln.strip()
            if _ln.startswith("Profile ID:"):
                _lp_id = _ln.split(":", 1)[1].strip()
            elif _ln.startswith("Confidence:"):
                try:
                    _lp_conf = int(re.sub(r"[^0-9]", "", _ln.split(":", 1)[1]))
                except Exception:
                    pass

        _resp: dict = {"success": True, "output": output}
        if _lp_id:
            _resp["login_profile_id"]   = _lp_id
            _resp["login_profile_conf"] = _lp_conf
        return jsonify(_resp)
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "AuthProbe timed out (60 s)"})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)})


@app.route("/api/settings/<project_id>/<tool>", methods=["GET", "POST"])
def api_settings(project_id: str, tool: str):
    proj = _get_project(project_id)
    if not proj:
        return jsonify({"error": "not found"}), 404
    key  = "fr_settings_file" if tool == "fr" else "si_settings_file"
    _sf  = proj.get(key) or ""
    path = Path(_sf) if _sf else None
    if request.method == "GET":
        if path and path.is_file():
            return jsonify(json.loads(path.read_text()))
        return jsonify(FR_DEFAULTS if tool == "fr" else SI_DEFAULTS)
    body = request.json or {}
    if not path or not path.parent.is_dir():
        _pdir = proj.get("project_dir", "")
        _fname = "fr_settings.json" if tool == "fr" else "si_settings.json"
        path = Path(_pdir) / _fname if _pdir else None
    if not path:
        return jsonify({"error": "no settings path available"}), 400
    path.write_text(json.dumps(body, indent=2))
    _update_project_field(project_id, **{key: str(path)})
    return jsonify({"success": True})


@app.route("/api/console/<project_id>/<tool>")
def api_console(project_id: str, tool: str):
    buf = _buffers.get(project_id, {}).get(tool, [])
    return jsonify(buf)


@app.route("/api/findings/<project_id>")
def api_findings(project_id: str):
    proj = _get_project(project_id)
    if not proj:
        return jsonify([])

    # Always start from in-memory findings then merge any disk findings not yet ingested.
    # This ensures the response is complete even when the watcher hasn't caught up yet.
    result: list[dict] = list(_all_findings.get(project_id, []))
    seen: set[tuple]   = {_fkey(f) for f in result}

    for _tool_name, _tool_key, _default in (
        ("fracture", "fr_settings_file", "fracture_output"),
        ("siphon",   "si_settings_file", "siphon_output"),
    ):
        _cfg_path = Path(proj.get(_tool_key, ""))
        if not _cfg_path.exists():
            continue
        try:
            _cfg      = json.loads(_cfg_path.read_text())
            _proj_dir = _cfg.get("scan", {}).get("project", _default)
            _fp       = Path(proj["project_dir"]) / _proj_dir / "findings.json"
            if not _fp.exists():
                continue
            _scope = "webapp" if _tool_name == "fracture" else "api"
            _mem_findings = _all_findings.setdefault(project_id, [])
            for raw in json.loads(_fp.read_text()):
                f = dict(raw)
                f["_tool"]  = _tool_name
                f["_scope"] = f.get("_scope") or _scope
                k = _fkey(f)
                if k not in seen:
                    seen.add(k)
                    result.append(f)
                    _mem_findings.append(f)
                else:
                    # Merge accounts from disk into the cached in-memory entry
                    new_accts = f.get("accounts") or []
                    if new_accts:
                        for _ex in _mem_findings:
                            if _fkey(_ex) == k:
                                _ex_roles = {a.get("role", "") for a in (_ex.get("accounts") or [])}
                                _added = [a for a in new_accts if a.get("role", "") not in _ex_roles]
                                if _added:
                                    _ex.setdefault("accounts", []).extend(_added)
                                break
        except Exception:
            pass

    suppressions = _load_suppressions(project_id)
    if suppressions:
        result = [f for f in result if _fkey_hash(f) not in suppressions]
    return jsonify(result)


def _suppressions_path(project_id: str) -> Path:
    proj = _get_project(project_id)
    if not proj:
        return PROJECTS_DIR / project_id / "suppressions.json"
    return Path(proj.get("project_dir", str(PROJECTS_DIR / project_id))) / "suppressions.json"


def _load_suppressions(project_id: str) -> set:
    """Load suppressed finding keys as a set of sha256 hex strings."""
    sp = _suppressions_path(project_id)
    if not sp.exists():
        return set()
    try:
        return set(json.loads(sp.read_text()))
    except Exception:
        return set()


def _false_positives_path(project_id: str) -> Path:
    proj = _get_project(project_id)
    if not proj:
        return PROJECTS_DIR / project_id / "falsePositives.json"
    return Path(proj.get("project_dir", str(PROJECTS_DIR / project_id))) / "falsePositives.json"


def _load_false_positives(project_id: str) -> list:
    fpp = _false_positives_path(project_id)
    if not fpp.exists():
        return []
    try:
        return json.loads(fpp.read_text())
    except Exception:
        return []


def _tool_findings_path(proj: dict, tool_name: str) -> "Path | None":
    key     = "fr_settings_file" if tool_name == "fracture" else "si_settings_file"
    default = "fracture_output"  if tool_name == "fracture" else "siphon_output"
    cfg_path = Path(proj.get(key, ""))
    if not cfg_path.exists():
        return None
    try:
        cfg      = json.loads(cfg_path.read_text())
        proj_dir = cfg.get("scan", {}).get("project", default)
        return Path(proj["project_dir"]) / proj_dir / "findings.json"
    except Exception:
        return None


def _fkey_hash(f: dict) -> str:
    """Return the suppression key for finding *f*.

    Must match _fkeyF() in project.html exactly:
      `${title}|${ip}|${port}|${_scope}|${hostname}`
    The frontend stores this raw pipe-joined string as the suppression key —
    NOT a hash — so the backend must produce the same string, not a digest.
    """
    t = _fkey(f)  # (title, ip, port, _scope, hostname)
    return f"{t[0]}|{t[1]}|{t[2]}|{t[3]}|{t[4]}"


@app.route("/api/suppress-finding/<project_id>", methods=["POST"])
def api_suppress_finding(project_id: str):
    """Mark a finding as a false positive.

    Moves the finding from findings.json to falsePositives.json and records
    the key in suppressions.json for backward compatibility.
    Body: {"key_hash": "<pipe-joined key>", "finding": {<full finding object>}}
    """
    proj = _get_project(project_id)
    if not proj:
        return jsonify({"error": "not found"}), 404
    body     = request.json or {}
    key_hash = (body.get("key_hash") or "").strip()
    finding  = body.get("finding")
    if not key_hash:
        return jsonify({"error": "Invalid key_hash"}), 400

    # Record in suppressions index (backward compat)
    sp = _suppressions_path(project_id)
    suppressions = _load_suppressions(project_id)
    suppressions.add(key_hash)
    sp.parent.mkdir(parents=True, exist_ok=True)
    sp.write_text(json.dumps(sorted(suppressions), indent=2))

    if finding:
        key_tuple = _fkey(finding)

        # Remove from the tool's findings.json
        tool_fp_path = _tool_findings_path(proj, finding.get("_tool", ""))
        if tool_fp_path and tool_fp_path.exists():
            try:
                existing = json.loads(tool_fp_path.read_text())
                tool_fp_path.write_text(
                    json.dumps([f for f in existing if _fkey(f) != key_tuple], indent=2)
                )
            except Exception:
                pass

        # Add to falsePositives.json (deduplicated)
        fpp     = _false_positives_path(project_id)
        fp_list = _load_false_positives(project_id)
        if not any(_fkey(f) == key_tuple for f in fp_list):
            fp_list.append(finding)
            fpp.parent.mkdir(parents=True, exist_ok=True)
            fpp.write_text(json.dumps(fp_list, indent=2))

        # Remove from in-memory cache
        if project_id in _all_findings:
            _all_findings[project_id] = [
                f for f in _all_findings[project_id] if _fkey(f) != key_tuple
            ]

    return jsonify({"success": True, "suppressed": key_hash})


@app.route("/api/unsuppress-finding/<project_id>", methods=["POST"])
def api_unsuppress_finding(project_id: str):
    """Recover a false positive back to the active findings list.

    Moves the finding from falsePositives.json back into findings.json and
    removes the key from suppressions.json.
    Body: {"key_hash": "<pipe-joined key>"}
    Response: {"success": true, "finding": {<recovered finding object>}}
    """
    proj = _get_project(project_id)
    if not proj:
        return jsonify({"error": "not found"}), 404
    body     = request.json or {}
    key_hash = (body.get("key_hash") or "").strip()
    if not key_hash:
        return jsonify({"error": "Missing key_hash"}), 400

    # Remove from suppressions index
    sp = _suppressions_path(project_id)
    suppressions = _load_suppressions(project_id)
    suppressions.discard(key_hash)
    sp.write_text(json.dumps(sorted(suppressions), indent=2))

    # Find and remove from falsePositives.json
    fpp       = _false_positives_path(project_id)
    fp_list   = _load_false_positives(project_id)
    recovered = None
    remaining = []
    for f in fp_list:
        if _fkey_hash(f) == key_hash:
            recovered = f
        else:
            remaining.append(f)

    if recovered:
        fpp.write_text(json.dumps(remaining, indent=2))

        # Write back to tool's findings.json
        tool_fp_path = _tool_findings_path(proj, recovered.get("_tool", ""))
        if tool_fp_path:
            try:
                existing  = json.loads(tool_fp_path.read_text()) if tool_fp_path.exists() else []
                key_tuple = _fkey(recovered)
                if not any(_fkey(f) == key_tuple for f in existing):
                    clean = {k: v for k, v in recovered.items() if not k.startswith("_")}
                    existing.append(clean)
                    tool_fp_path.parent.mkdir(parents=True, exist_ok=True)
                    tool_fp_path.write_text(json.dumps(existing, indent=2))
            except Exception:
                pass

        # Add back to in-memory cache
        if project_id in _all_findings:
            key_tuple = _fkey(recovered)
            if not any(_fkey(f) == key_tuple for f in _all_findings[project_id]):
                _all_findings[project_id].append(recovered)

    return jsonify({"success": True, "finding": recovered})


@app.route("/api/suppressions/<project_id>")
def api_suppressions(project_id: str):
    """Return the set of suppressed finding key hashes for a project."""
    return jsonify(sorted(_load_suppressions(project_id)))


@app.route("/api/false-positives/<project_id>")
def api_false_positives(project_id: str):
    """Return all false positive findings from falsePositives.json."""
    if not _get_project(project_id):
        return jsonify([])
    fp_list = _load_false_positives(project_id)
    for f in fp_list:
        if not f.get("_scope"):
            f["_scope"] = "webapp" if f.get("_tool") == "fracture" else "api"
    return jsonify(fp_list)


@app.route("/api/compare-scans", methods=["POST"])
def api_compare_scans():
    """Compare findings between two Crucible projects.

    Body: {"project_a": "<id>", "project_b": "<id>"}
    Returns: {
      "new_in_b":      [...],   # findings in B not in A (newly introduced)
      "resolved_in_b": [...],   # findings in A not in B (fixed/resolved)
      "common":        [...],   # findings in both
      "counts": {a, b, new, resolved, common}
    }
    """
    body = request.json or {}
    pid_a = body.get("project_a", "").strip()
    pid_b = body.get("project_b", "").strip()
    if not pid_a or not pid_b:
        return jsonify({"error": "project_a and project_b are required"}), 400
    if pid_a == pid_b:
        return jsonify({"error": "project_a and project_b must be different"}), 400

    def _load_findings(pid: str) -> list:
        from flask import current_app as _app
        cached = _all_findings.get(pid)
        if cached:
            return cached
        proj = _get_project(pid)
        if not proj:
            return []
        items: list = []
        seen: set   = set()
        for tool, cfg_key, scan_key, default_dir in [
            ("fracture", "fr_settings_file", "project", "fracture_output"),
            ("siphon",   "si_settings_file", "project", "siphon_output"),
        ]:
            cp = Path(proj.get(cfg_key, ""))
            if not cp.exists():
                continue
            try:
                cfg  = json.loads(cp.read_text())
                pdir = cfg.get("scan", {}).get(scan_key, default_dir)
                fp   = Path(proj["project_dir"]) / pdir / "findings.json"
                if fp.exists():
                    for raw in json.loads(fp.read_text()):
                        f = dict(raw)
                        f["_tool"] = tool
                        k = _fkey(f)
                        if k not in seen:
                            seen.add(k)
                            items.append(f)
            except Exception:
                pass
        return items

    fa = _load_findings(pid_a)
    fb = _load_findings(pid_b)

    keys_a = {_fkey_hash(f): f for f in fa}
    keys_b = {_fkey_hash(f): f for f in fb}

    new_in_b      = [fb_f for h, fb_f in keys_b.items() if h not in keys_a]
    resolved_in_b = [fa_f for h, fa_f in keys_a.items() if h not in keys_b]
    common        = [fb_f for h, fb_f in keys_b.items() if h in keys_a]

    return jsonify({
        "new_in_b":      new_in_b,
        "resolved_in_b": resolved_in_b,
        "common":        common,
        "counts": {
            "a":        len(fa),
            "b":        len(fb),
            "new":      len(new_in_b),
            "resolved": len(resolved_in_b),
            "common":   len(common),
        },
    })


def _backfill_matrix_codes(matrix: dict, map_path: "Path") -> None:
    """Ensure every declared role has an entry in every path's access dict.

    For the first role (roles[0] — the most privileged by configuration),
    null entries are provisionally backfilled with structure_map HTTP status
    codes so the Access Matrix shows live response codes during scanning,
    before Fracture's per-role probing (_probe_role_paths) completes.
    All other role columns remain None (shown as —) until Fracture fills
    them in with actual probed values.

    This is a display-only operation on the in-memory dict returned by the
    API — it does not write to disk and does not affect Fracture's probing.
    """
    try:
        all_roles = list(matrix.get("roles") or [])
        # First role gets provisional backfill from structure_map; others stay None
        first_role = all_roles[0] if all_roles else None
        sm_by_path: dict = {}
        if first_role and map_path and map_path.exists():
            try:
                sm_data = json.loads(map_path.read_text())
                sm_by_path = sm_data.get("paths", {})
            except Exception:
                pass
        for entry in matrix.get("paths", []):
            access = entry.setdefault("access", {})
            path = entry.get("path", "")
            sm_entry = sm_by_path.get(path) if path else None
            sm_status = sm_entry.get("status") if isinstance(sm_entry, dict) else None
            for role in all_roles:
                if role not in access:
                    access[role] = None
                if access[role] is None and role == first_role and sm_status is not None:
                    access[role] = sm_status
    except Exception:
        pass


def _annotate_access_hints(matrix: dict) -> None:
    """Add size-based restriction flags to access_meta for display in Crucible.

    For each path entry that has access_meta body_len data, compares every
    secondary role's response body length to the most privileged role (roles[0]).
    If a role's body is less than 50% of roles[0]'s body, sets _size_restricted=True
    in that role's access_meta so the frontend can show a RESTRICTED pill.

    Display-only — does not write to disk.
    """
    try:
        roles = list(matrix.get("roles") or [])
        if len(roles) < 2:
            return
        priv_role = roles[0]
        for entry in matrix.get("paths", []):
            meta = entry.get("access_meta") or {}
            priv_meta = meta.get(priv_role) or {}
            priv_len = priv_meta.get("body_len", 0) or 0
            for role in roles[1:]:
                role_meta = meta.get(role)
                if not isinstance(role_meta, dict):
                    continue
                role_len = role_meta.get("body_len", 0) or 0
                if priv_len > 0 and role_len > 0 and role_len < priv_len * 0.5:
                    role_meta["_size_restricted"] = True
    except Exception:
        pass


@app.route("/api/structure/<project_id>")
def api_structure(project_id: str):
    """Return structure maps for Fracture (structure_map.json) and Siphon (api_map.json)."""
    proj = _get_project(project_id)
    if not proj:
        return jsonify({"error": "not found"}), 404

    result: dict = {"fr_map": None, "si_map": None}

    # Fracture structure map
    fr_proj_dir = ""
    try:
        _sf = proj.get("fr_settings_file") or ""
        if _sf and Path(_sf).is_file():
            fr_cfg = json.loads(Path(_sf).read_text())
            _fp = fr_cfg.get("scan", {}).get("project", "")
            if _fp:
                fr_proj_dir = _fp
                sm = Path(_fp) / "structure_map.json"
                if sm.exists():
                    result["fr_map"] = json.loads(sm.read_text())
        # Fallback: use fracture_output_dir directly (discovered projects)
        if result["fr_map"] is None:
            _fdir = proj.get("fracture_output_dir") or ""
            if _fdir:
                sm = Path(_fdir) / "structure_map.json"
                if sm.exists():
                    fr_proj_dir = _fdir
                    result["fr_map"] = json.loads(sm.read_text())
    except Exception:
        pass

    # Backfill structure_map path statuses from access_matrix unauthenticated codes
    if result["fr_map"] and fr_proj_dir:
        try:
            am_file = Path(fr_proj_dir) / "access_matrix.json"
            if am_file.exists():
                am_data = json.loads(am_file.read_text())
                unauth = {
                    ep["path"]: ep["access"].get("unauthenticated")
                    for ep in am_data.get("paths", [])
                    if isinstance(ep.get("access", {}).get("unauthenticated"), int)
                }
                for p, data in (result["fr_map"].get("paths") or {}).items():
                    if isinstance(data, dict) and data.get("status") is None and p in unauth:
                        data["status"] = unauth[p]
        except Exception:
            pass

    # Siphon API map
    try:
        _sf = proj.get("si_settings_file") or ""
        if _sf and Path(_sf).is_file():
            si_cfg = json.loads(Path(_sf).read_text())
            _sp = si_cfg.get("scan", {}).get("project", "")
            if _sp:
                am = Path(_sp) / "api_map.json"
                if am.exists():
                    result["si_map"] = json.loads(am.read_text())
        if result["si_map"] is None:
            _sdir = proj.get("siphon_output_dir") or ""
            if _sdir:
                am = Path(_sdir) / "api_map.json"
                if am.exists():
                    result["si_map"] = json.loads(am.read_text())
    except Exception:
        pass

    return jsonify(result)


@app.route("/api/access-matrix/<project_id>")
def api_access_matrix(project_id: str):
    """Return access_matrix.json produced by Phase 20 from Fracture and/or Siphon."""
    proj = _get_project(project_id)
    if not proj:
        return jsonify({"error": "not found"}), 404

    result: dict = {"fr_matrix": None, "si_matrix": None}

    try:
        _sf = proj.get("fr_settings_file") or ""
        _fr_proj = ""
        if _sf and Path(_sf).is_file():
            fr_cfg = json.loads(Path(_sf).read_text())
            _fr_proj = fr_cfg.get("scan", {}).get("project", "")
        if not _fr_proj:
            _fr_proj = proj.get("fracture_output_dir") or ""
        if _fr_proj:
            am = Path(_fr_proj) / "access_matrix.json"
            if am.exists():
                matrix = json.loads(am.read_text())
                _backfill_matrix_codes(matrix, Path(_fr_proj) / "structure_map.json")
                _annotate_access_hints(matrix)
                result["fr_matrix"] = matrix
    except Exception:
        pass

    try:
        _sf = proj.get("si_settings_file") or ""
        _si_proj = ""
        if _sf and Path(_sf).is_file():
            si_cfg = json.loads(Path(_sf).read_text())
            _si_proj = si_cfg.get("scan", {}).get("project", "")
        if not _si_proj:
            _si_proj = proj.get("siphon_output_dir") or ""
        if _si_proj:
            am = Path(_si_proj) / "access_matrix.json"
            if am.exists():
                matrix = json.loads(am.read_text())
                _backfill_matrix_codes(matrix, Path(_si_proj) / "api_map.json")
                _annotate_access_hints(matrix)
                result["si_matrix"] = matrix
    except Exception:
        pass

    return jsonify(result)


@app.route("/api/auth-status/<project_id>")
def api_auth_status(project_id: str):
    """Return authentication_status.json produced by Fracture and/or Siphon."""
    proj = _get_project(project_id)
    if not proj:
        return jsonify({"error": "not found"}), 404

    result: dict = {"fr_auth": None, "si_auth": None}

    try:
        _sf = proj.get("fr_settings_file") or ""
        _fr_proj = ""
        if _sf and Path(_sf).is_file():
            fr_cfg = json.loads(Path(_sf).read_text())
            _fr_proj = fr_cfg.get("scan", {}).get("project", "")
        if not _fr_proj:
            _fr_proj = proj.get("fracture_output_dir") or ""
        if _fr_proj:
            af = Path(_fr_proj) / "authentication_status.json"
            if af.exists():
                result["fr_auth"] = json.loads(af.read_text())
    except Exception:
        pass

    try:
        _sf = proj.get("si_settings_file") or ""
        _si_proj = ""
        if _sf and Path(_sf).is_file():
            si_cfg = json.loads(Path(_sf).read_text())
            _si_proj = si_cfg.get("scan", {}).get("project", "")
        if not _si_proj:
            _si_proj = proj.get("siphon_output_dir") or ""
        if _si_proj:
            af = Path(_si_proj) / "authentication_status.json"
            if af.exists():
                result["si_auth"] = json.loads(af.read_text())
    except Exception:
        pass

    return jsonify(result)


@app.route("/api/export-access-matrix-xlsx/<project_id>")
def api_export_access_matrix_xlsx(project_id: str):
    """Generate and download an XLSX file from the project's access_matrix.json."""
    proj = _get_project(project_id)
    if not proj:
        return jsonify({"error": "not found"}), 404

    import io
    try:
        import openpyxl
        from openpyxl.styles import Font, PatternFill, Alignment
    except ImportError:
        return jsonify({"error": "openpyxl not installed"}), 500

    def _load_matrix(settings_key: str) -> "dict | None":
        try:
            cfg_path = Path(proj.get(settings_key, ""))
            if not cfg_path.exists():
                return None
            cfg = json.loads(cfg_path.read_text())
            pdir = cfg.get("scan", {}).get("project", "")
            if not pdir:
                return None
            am_file = Path(pdir) / "access_matrix.json"
            if not am_file.exists():
                return None
            return json.loads(am_file.read_text())
        except Exception:
            return None

    wb = openpyxl.Workbook()
    wb.remove(wb.active)  # remove default sheet

    hdr_fill  = PatternFill("solid", fgColor="161B22")
    hdr_font  = Font(color="C9D1D9", bold=True)
    ok_font   = Font(color="3FB950")
    warn_font = Font(color="D29922")
    err_font  = Font(color="F85149")

    def _add_sheet(title: str, matrix: dict) -> None:
        all_roles = list(matrix.get("roles") or ["unauthenticated"])
        items     = matrix.get("paths") or []
        ws = wb.create_sheet(title=title[:31])
        def _dr(r): return "Unauthenticated" if r == "unauthenticated" else r
        # Header row
        ws.append(["Path"] + [_dr(r) for r in all_roles])
        for cell in ws[1]:
            cell.font = hdr_font
            cell.fill = hdr_fill
            cell.alignment = Alignment(horizontal="center")
        ws.column_dimensions["A"].width = 50
        for i in range(len(all_roles)):
            ws.column_dimensions[chr(66 + i)].width = 18
        # Data rows
        for item in items:
            path   = item.get("path", "")
            access = item.get("access") or {}
            row = [path]
            for role in all_roles:
                st = access.get(role)
                row.append(st if st is not None else "—")
            ws.append(row)
            data_row = ws.max_row
            for col_idx, role in enumerate(all_roles, start=2):
                cell = ws.cell(row=data_row, column=col_idx)
                st = access.get(role)
                if isinstance(st, int):
                    if st < 300:
                        cell.font = ok_font
                    elif st < 400:
                        cell.font = warn_font
                    else:
                        cell.font = err_font

    fr_matrix = _load_matrix("fr_settings_file")
    si_matrix = _load_matrix("si_settings_file")

    if fr_matrix:
        _add_sheet("FR - Web App", fr_matrix)
    if si_matrix:
        _add_sheet("SI - API", si_matrix)

    if not wb.sheetnames:
        ws = wb.create_sheet("Access Matrix")
        ws.append(["No access matrix data found."])

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    proj_name = (proj.get("name") or project_id).replace(" ", "_")
    filename  = f"access_matrix_{proj_name}.xlsx"
    return app.response_class(
        buf.read(),
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Structure export helpers ──────────────────────────────────────────────────

def _load_fr_structure_map(proj: dict) -> "dict | None":
    """Load structure_map.json from the Fracture project directory."""
    try:
        _sf = proj.get("fr_settings_file") or ""
        _pdir = ""
        if _sf and Path(_sf).is_file():
            cfg  = json.loads(Path(_sf).read_text())
            _pdir = cfg.get("scan", {}).get("project", "")
        if not _pdir:
            _pdir = proj.get("fracture_output_dir") or ""
        if not _pdir:
            return None
        sm = Path(_pdir) / "structure_map.json"
        return json.loads(sm.read_text()) if sm.exists() else None
    except Exception:
        return None


def _build_structure_tree(paths: dict) -> dict:
    """Convert flat {path: data} dict into a nested tree of nodes.

    Each node: {"_data": {...}, "children": {name: node, ...}}
    """
    root: dict = {"_data": paths.get("/", {}), "children": {}}
    for path, data in sorted(paths.items()):
        if path == "/":
            continue
        segments = [s for s in path.strip("/").split("/") if s]
        node = root
        for seg in segments:
            if seg not in node["children"]:
                node["children"][seg] = {"_data": {}, "children": {}}
            node = node["children"][seg]
        node["_data"] = data
    return root


def _status_class(status: "int | None") -> str:
    if status is None:
        return ""
    if status < 300:
        return "ok"
    if status < 400:
        return "redir"
    return "err"


def _render_html_node(name: str, node: dict, depth: int = 0) -> str:
    """Recursively render a tree node as HTML using <details>/<summary>."""
    data      = node.get("_data", {})
    children  = node.get("children", {})
    status    = data.get("status")
    redirect  = data.get("redirect_to", "")
    is_dir    = bool(children)
    is_root   = depth == 0

    cls  = _status_class(status)
    badge = f'<span class="st {cls}">{status}</span>' if status is not None else ""
    arrow = f' <span class="redir-arrow">&#x2192; {redirect}</span>' if redirect else ""

    label = "/" if is_root else (name + "/" if is_dir else name)
    icon  = "&#128193;" if (is_dir or is_root) else "&#128196;"

    row_inner = f'{icon} <span class="name">{label}</span> {badge}{arrow}'

    if is_dir or is_root:
        open_attr = " open" if is_root else ""
        html = f'<details{open_attr}>\n<summary class="node">{row_inner}</summary>\n'
        html += '<div class="children">\n'
        for child_name, child_node in sorted(children.items()):
            html += _render_html_node(child_name, child_node, depth + 1)
        html += '</div>\n</details>\n'
    else:
        html = f'<div class="node leaf">{row_inner}</div>\n'
    return html


def _generate_structure_html(sm: dict, proj_name: str) -> str:
    """Return a complete self-contained HTML document for the structure map."""
    target    = sm.get("target", "")
    generated = sm.get("generated_at", "")
    paths     = sm.get("paths", {})
    tree      = _build_structure_tree(paths)
    body      = _render_html_node("/", tree, depth=0)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Structure Map — {proj_name}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0d1117;color:#e6edf3;font-family:'Fira Code','Cascadia Code','Consolas',monospace;
        font-size:13px;line-height:1.65;padding:2rem}}
  h1{{font-size:1.1rem;color:#58a6ff;margin-bottom:.25rem}}
  .meta{{font-size:.8rem;color:#8b949e;margin-bottom:1.5rem}}
  details>summary{{cursor:pointer;list-style:none;user-select:none}}
  details>summary::-webkit-details-marker{{display:none}}
  .node{{display:flex;align-items:center;gap:.4rem;padding:.18rem .3rem;
          border-radius:4px;white-space:nowrap}}
  .node:hover{{background:rgba(88,166,255,.08)}}
  .children{{padding-left:1.5rem;border-left:1px dashed #30363d;margin-left:.6rem}}
  .name{{color:#e6edf3;font-weight:500}}
  .st{{padding:.1rem .35rem;border-radius:3px;font-size:.75rem;font-weight:700}}
  .ok{{background:#1b4332;color:#3fb950}}
  .redir{{background:#332e14;color:#d29922}}
  .err{{background:#3d1a1a;color:#f85149}}
  .redir-arrow{{color:#6e7681;font-style:italic;font-size:.8rem}}
</style>
</head>
<body>
<h1>Structure Map</h1>
<div class="meta">
  Target: {target} &nbsp;|&nbsp; Generated: {generated} &nbsp;|&nbsp;
  Paths: {len(paths)} &nbsp;|&nbsp; Project: {proj_name}
</div>
{body}
</body>
</html>"""


@app.route("/api/export-structure-html/<project_id>")
def api_export_structure_html(project_id: str):
    """Generate and download a self-contained HTML structure map."""
    proj = _get_project(project_id)
    if not proj:
        return jsonify({"error": "not found"}), 404
    sm = _load_fr_structure_map(proj)
    if not sm:
        return jsonify({"error": "No structure map found"}), 404
    proj_name = (proj.get("name") or project_id).replace(" ", "_")
    html      = _generate_structure_html(sm, proj_name)
    filename  = f"structure_{proj_name}.html"
    return app.response_class(
        html,
        mimetype="text/html",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/api/export-structure-pdf/<project_id>")
def api_export_structure_pdf(project_id: str):
    """Generate and download a multi-page PDF structure map using reportlab."""
    proj = _get_project(project_id)
    if not proj:
        return jsonify({"error": "not found"}), 404
    sm = _load_fr_structure_map(proj)
    if not sm:
        return jsonify({"error": "No structure map found"}), 404

    try:
        import io
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        KeepTogether, HRFlowable)
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.colors import HexColor, black, white
        from reportlab.lib.units import mm
        from reportlab.lib.enums import TA_LEFT
    except ImportError:
        return jsonify({"error": "reportlab not installed"}), 500

    proj_name = (proj.get("name") or project_id).replace(" ", "_")
    target    = sm.get("target", "")
    generated = sm.get("generated_at", "")
    paths     = sm.get("paths", {})
    tree      = _build_structure_tree(paths)

    # ── Styles ──────────────────────────────────────────────────────────────
    PAGE_W, PAGE_H = A4
    MARGIN = 18 * mm

    base = ParagraphStyle(
        "base",
        fontName="Courier",
        fontSize=8.5,
        leading=13,
        leftIndent=0,
        textColor=HexColor("#1a1a2e"),
    )
    title_style = ParagraphStyle(
        "title",
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=HexColor("#1a1a2e"),
        spaceAfter=2 * mm,
    )
    meta_style = ParagraphStyle(
        "meta",
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=HexColor("#555555"),
        spaceAfter=4 * mm,
    )

    C_OK    = HexColor("#1a7a3c")
    C_REDIR = HexColor("#8a6a00")
    C_ERR   = HexColor("#b02020")
    C_GRAY  = HexColor("#555555")

    def _status_tag(status):
        if status is None:
            return ""
        if status < 300:
            return f'<font color="#1a7a3c">[{status}]</font>'
        if status < 400:
            return f'<font color="#8a6a00">[{status}]</font>'
        return f'<font color="#b02020">[{status}]</font>'

    # ── Flatten tree to paragraphs ───────────────────────────────────────────
    story = []

    story.append(Paragraph(f"Structure Map — {proj_name}", title_style))
    story.append(Paragraph(
        f"Target: {target} &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"Generated: {generated} &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"Paths: {len(paths)}",
        meta_style,
    ))
    story.append(HRFlowable(width="100%", thickness=0.5,
                            color=HexColor("#cccccc"), spaceAfter=4 * mm))

    def _flatten(node: dict, name: str, depth: int, out: list):
        data      = node.get("_data", {})
        children  = node.get("children", {})
        is_dir    = bool(children)
        is_root   = depth == 0
        status    = data.get("status")
        redirect  = data.get("redirect_to", "")

        label = "/" if is_root else (name + "/" if is_dir else name)
        icon  = "&#9658;" if is_dir or is_root else "&#9642;"   # ▶ or ▪
        indent = (depth * 12)                                    # points

        st_tag  = _status_tag(status)
        arr_tag = (f' <font color="#888888"><i>&#x2192; {redirect}</i></font>'
                   if redirect else "")
        weight  = "Bold" if (is_dir or is_root) else ""
        fn      = f"Courier-{weight}" if weight else "Courier"

        style = ParagraphStyle(
            f"n{depth}",
            parent=base,
            fontName=fn,
            leftIndent=indent,
            spaceAfter=1,
            spaceBefore=2 if (is_dir and depth > 0) else 0,
        )
        text = f'{icon} {label} {st_tag}{arr_tag}'
        out.append(Paragraph(text, style))

        for child_name, child_node in sorted(children.items()):
            _flatten(child_node, child_name, depth + 1, out)

    _flatten(tree, "/", 0, story)

    # ── Page numbering callback ──────────────────────────────────────────────
    def _on_page(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(HexColor("#888888"))
        canvas.drawRightString(
            PAGE_W - MARGIN, 10 * mm,
            f"Page {doc.page}  |  {proj_name}  |  {target}",
        )
        canvas.restoreState()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN,  bottomMargin=16 * mm,
        title=f"Structure Map — {proj_name}",
        author="Crucible",
    )
    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    buf.seek(0)

    filename = f"structure_{proj_name}.pdf"
    return app.response_class(
        buf.read(),
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/api/export-status-report-pdf/<project_id>")
def api_export_status_report_pdf(project_id: str):
    """Generate and download a Status Report PDF for the engagement."""
    proj = _get_project(project_id)
    if not proj:
        return jsonify({"error": "not found"}), 404

    try:
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle, KeepTogether,
                                        HRFlowable, PageBreak)
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.colors import HexColor, white, black
        from reportlab.lib.units import mm
    except ImportError:
        return jsonify({"error": "reportlab not installed"}), 500

    # ── Engagement metadata ──────────────────────────────────────────────────
    engagement: dict = {}
    fr_target = ""
    si_target = ""
    fr_proj_dir = ""
    si_proj_dir = ""

    try:
        fr_cfg = json.loads(Path(proj.get("fr_settings_file", "")).read_text())
        engagement = fr_cfg.get("engagement", {})
        fr_scan = fr_cfg.get("scan", {})
        fr_target = fr_scan.get("target_url", "")
        fr_proj_dir = fr_scan.get("project", "fracture_output")
    except Exception:
        pass

    try:
        si_cfg = json.loads(Path(proj.get("si_settings_file", "")).read_text())
        if not engagement:
            engagement = si_cfg.get("engagement", {})
        si_scan = si_cfg.get("scan", {})
        si_target = si_scan.get("target_url", "")
        si_proj_dir = si_scan.get("project", "siphon_output")
    except Exception:
        pass

    consultant       = engagement.get("consultant", "") or ""
    consultant_email = engagement.get("consultant_email", "") or ""
    client_name      = proj.get("client_name") or engagement.get("client_name", "") or ""
    proj_name        = proj.get("name", project_id)
    scope_str        = proj.get("scope", "") or ""
    start_date       = engagement.get("start_date", "") or ""
    end_date         = engagement.get("end_date", "") or ""
    generated_at     = datetime.now(timezone.utc).strftime("%Y-%m-%d (%Y-%m-%d %H:%M:%S UTC)")

    # ── Load target profile ──────────────────────────────────────────────────
    target_profile: dict = {}
    try:
        _tp_paths = []
        if fr_proj_dir and proj.get("project_dir"):
            _tp_paths.append(Path(proj["project_dir"]) / fr_proj_dir / "target_profile.json")
        if proj.get("project_dir"):
            _tp_paths.append(Path(proj["project_dir"]) / "target_profile.json")
        for _tp_p in _tp_paths:
            if _tp_p.exists():
                target_profile = json.loads(_tp_p.read_text())
                break
    except Exception:
        pass

    # ── Load findings — LOW and above only, excluding false positives ────────
    INCLUDE_RISKS = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    RISK_ORDER    = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    RISK_HEX      = {"CRITICAL": "dc2626", "HIGH": "ea580c", "MEDIUM": "d97706", "LOW": "2563eb"}

    _suppressions = _load_suppressions(project_id)

    all_findings: list[dict] = []
    for _tool_name, _subdir, _scope_lbl in [
        ("fracture", fr_proj_dir, "webapp"),
        ("siphon",   si_proj_dir, "api"),
    ]:
        if not _subdir:
            continue
        _fp = Path(proj["project_dir"]) / _subdir / "findings.json"
        if _fp.exists():
            try:
                for _f in json.loads(_fp.read_text()):
                    _f = dict(_f)
                    if (_f.get("risk") or "INFO").upper() not in INCLUDE_RISKS:
                        continue
                    _f.setdefault("_tool", _tool_name)
                    _f.setdefault("_scope", _scope_lbl)
                    if _fkey_hash(_f) in _suppressions:
                        continue
                    all_findings.append(_f)
            except Exception:
                pass

    all_findings.sort(key=lambda _f: (
        RISK_ORDER.get((_f.get("risk") or "LOW").upper(), 99),
        _f.get("datetime", ""),
    ))

    web_findings = [_f for _f in all_findings if _f.get("_scope") == "webapp"]
    api_findings = [_f for _f in all_findings if _f.get("_scope") == "api"]

    # ── Scope parsing ────────────────────────────────────────────────────────
    scope_parts   = [s.strip() for s in re.split(r'[\n,;]+', scope_str) if s.strip()]
    scope_ips     = [s for s in scope_parts if re.match(r'^\d+\.\d+\.\d+\.\d+', s)]
    scope_domains = [s for s in scope_parts if not re.match(r'^\d+\.\d+\.\d+\.\d+', s)]

    # ── Layout constants ─────────────────────────────────────────────────────
    PAGE_W, PAGE_H = A4
    MARGIN = 20 * mm
    CW     = PAGE_W - 2 * MARGIN

    C_GRAY   = HexColor("#6b7280")
    C_LIGHT  = HexColor("#f3f4f6")
    C_BORDER = HexColor("#e5e7eb")

    def _ps(name, **kw):
        d = dict(fontName="Helvetica", fontSize=9, leading=13, textColor=black)
        d.update(kw)
        return ParagraphStyle(name, **d)

    s_base  = _ps("sr_base")
    s_h1    = _ps("sr_h1",  fontName="Helvetica-Bold", fontSize=20, leading=24,
                  textColor=HexColor("#1a1a2e"), spaceAfter=3*mm)
    s_h2    = _ps("sr_h2",  fontName="Helvetica-Bold", fontSize=13, leading=16,
                  textColor=HexColor("#1a1a2e"), spaceBefore=5*mm, spaceAfter=3*mm)
    s_h3    = _ps("sr_h3",  fontName="Helvetica-Bold", fontSize=10.5, leading=13,
                  textColor=HexColor("#1a1a2e"), spaceBefore=3*mm, spaceAfter=2*mm)
    s_label = _ps("sr_lbl", fontName="Helvetica-Bold", fontSize=8.5, leading=12, textColor=C_GRAY)
    s_val   = _ps("sr_val", fontSize=9, leading=12)
    s_meta  = _ps("sr_met", fontSize=8, leading=11, textColor=C_GRAY, spaceAfter=1*mm)
    s_mono  = _ps("sr_mon", fontName="Courier", fontSize=8, leading=11)
    s_issue = _ps("sr_iss", fontSize=9, leading=12, leftIndent=8, spaceAfter=1)

    # ── Story ────────────────────────────────────────────────────────────────
    story = []

    # Title + generated stamp
    story.append(Paragraph("Status Report", s_h1))
    story.append(Paragraph(f"Generated: {generated_at}", s_meta))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER, spaceAfter=4*mm))

    # Metadata grid
    meta_rows = [
        [Paragraph("Customer:", s_label), Paragraph(client_name or "—", s_val),
         Paragraph("Engagement:", s_label), Paragraph(proj_name, s_val)],
        [Paragraph("Consultant:", s_label), Paragraph(consultant or "—", s_val),
         Paragraph("Consultant Email:", s_label), Paragraph(consultant_email or "—", s_val)],
    ]
    if start_date or end_date:
        meta_rows.append([
            Paragraph("Start Date:", s_label), Paragraph(start_date or "—", s_val),
            Paragraph("End Date:", s_label), Paragraph(end_date or "—", s_val),
        ])
    meta_t = Table(meta_rows, colWidths=[CW*0.14, CW*0.36, CW*0.16, CW*0.34])
    meta_t.setStyle(TableStyle([
        ("VALIGN",         (0,0), (-1,-1), "TOP"),
        ("TOPPADDING",     (0,0), (-1,-1), 2),
        ("BOTTOMPADDING",  (0,0), (-1,-1), 3),
    ]))
    story.append(meta_t)
    story.append(Spacer(1, 4*mm))

    # ── Summary of Findings ──────────────────────────────────────────────────
    story.append(Paragraph("Summary of Findings", s_h2))

    def _summary_table(findings, label):
        if not findings:
            return
        story.append(Paragraph(f"Summary of Findings — {label} ({len(findings)})", s_h3))
        rows = [[
            Paragraph("<b>Date</b>", s_base),
            Paragraph("<b>Risk</b>", s_base),
            Paragraph("<b>Description</b>", s_base),
            Paragraph("<b>Status</b>", s_base),
        ]]
        for _f in findings:
            _risk = (_f.get("risk") or "LOW").upper()
            _hx   = RISK_HEX.get(_risk, "6b7280")
            rows.append([
                Paragraph((_f.get("datetime") or "")[:10], s_base),
                Paragraph(f'<font color="#{_hx}">{_risk.capitalize()}</font>', s_base),
                Paragraph(str(_f.get("title") or ""), s_base),
                Paragraph(str(_f.get("status") or "Open"), s_base),
            ])
        tbl = Table(rows, colWidths=[CW*0.12, CW*0.10, CW*0.61, CW*0.17])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0),  C_LIGHT),
            ("LINEBELOW",     (0,0), (-1,0),  0.5, C_BORDER),
            ("LINEBELOW",     (0,1), (-1,-1), 0.3, C_BORDER),
            ("VALIGN",        (0,0), (-1,-1), "TOP"),
            ("TOPPADDING",    (0,0), (-1,-1), 3),
            ("BOTTOMPADDING", (0,0), (-1,-1), 3),
            ("LEFTPADDING",   (0,0), (-1,-1), 4),
        ]))
        story.append(tbl)
        story.append(Spacer(1, 2*mm))

    _summary_table(web_findings, "Web")
    _summary_table(api_findings, "API")
    if not all_findings:
        story.append(Paragraph("No findings (Low severity or higher) recorded.", s_base))
        story.append(Spacer(1, 3*mm))

    # ── 1. Scope ─────────────────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceBefore=2*mm, spaceAfter=2*mm))
    story.append(Paragraph("1. Scope", s_h2))
    scope_tbl = Table([
        [Paragraph(f"<b>External IPs ({len(scope_ips)})</b>", s_base),
         Paragraph("<b>Internal IPs (0)</b>", s_base),
         Paragraph(f"<b>Associated Domains / FQDNs ({len(scope_domains)})</b>", s_base)],
        [Paragraph("\n".join(scope_ips) if scope_ips else "none", s_mono),
         Paragraph("none", s_mono),
         Paragraph("\n".join(scope_domains) if scope_domains else "none", s_mono)],
    ], colWidths=[CW/3]*3)
    scope_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  C_LIGHT),
        ("LINEBELOW",     (0,0), (-1,0),  0.5, C_BORDER),
        ("BOX",           (0,0), (-1,-1), 0.5, C_BORDER),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING",   (0,0), (-1,-1), 6),
    ]))
    story.append(scope_tbl)
    story.append(Spacer(1, 3*mm))

    targets = []
    if fr_target:
        targets.append(fr_target)
    if si_target and si_target not in targets:
        targets.append(si_target)
    if targets:
        story.append(Paragraph("Target URLs:", s_label))
        for _tu in targets:
            story.append(Paragraph(_tu, s_mono))
        story.append(Spacer(1, 3*mm))

    # ── 2. Target Profile ────────────────────────────────────────────────────
    if target_profile:
        story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER,
                                spaceBefore=2*mm, spaceAfter=2*mm))
        story.append(Paragraph("2. Target Profile", s_h2))

        # Key-value rows — only emit rows that have a value
        def _tp_kv_rows():
            rows = []
            def _add(label, val):
                if val:
                    rows.append([Paragraph(label, s_label), Paragraph(str(val), s_val)])
            _add("Server",          target_profile.get("server") or "")
            _add("Powered By",      target_profile.get("powered_by") or "")
            _add("Web Structure",   target_profile.get("web_structure") or "")
            _add("CMS",             ", ".join(target_profile.get("cms") or []))
            _add("CDN",             target_profile.get("cdn") or "")
            _add("WAF",             target_profile.get("waf") or "")
            _add("Edge Security",   ", ".join(target_profile.get("edge_security") or []))
            _add("Auth Method",     target_profile.get("auth_method") or "")
            _add("Auth Page",       target_profile.get("auth_page") or "")
            _add("MFA",             ", ".join(target_profile.get("mfa_providers") or []))
            _add("TLS Cert",        target_profile.get("tls_cert") or "")
            _add("Cert Expiry",     target_profile.get("cert_expiry") or "")
            _tlsp = target_profile.get("protocols")
            if _tlsp:
                _add("TLS Protocols", ", ".join(_tlsp) if isinstance(_tlsp, list) else str(_tlsp))
            return rows

        _tp_rows = _tp_kv_rows()
        if _tp_rows:
            _tp_tbl = Table(_tp_rows, colWidths=[CW * 0.22, CW * 0.78])
            _tp_tbl.setStyle(TableStyle([
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING",    (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING",   (0, 0), (-1, -1), 0),
                ("LINEBELOW",     (0, 0), (-1, -1), 0.3, C_BORDER),
            ]))
            story.append(_tp_tbl)
            story.append(Spacer(1, 3*mm))

        # Technologies pill list
        _tp_techs = target_profile.get("technologies") or []
        if isinstance(_tp_techs, list) and _tp_techs:
            _tech_names = []
            for _t in _tp_techs:
                if isinstance(_t, dict):
                    _tn = _t.get("name", "")
                    _tv = _t.get("version", "")
                    _tech_names.append(f"{_tn} {_tv}".strip() if _tv else _tn)
                elif isinstance(_t, str):
                    _tech_names.append(_t)
            if _tech_names:
                story.append(Paragraph("Technologies", s_label))
                story.append(Paragraph(", ".join(_tech_names), s_val))
                story.append(Spacer(1, 2*mm))

        # BI / Monitoring tools
        _tp_bi = target_profile.get("bi_tools") or []
        if _tp_bi:
            story.append(Paragraph("BI / Monitoring", s_label))
            story.append(Paragraph(", ".join(_tp_bi), s_val))
            story.append(Spacer(1, 2*mm))

        # Security headers
        _tp_sh = target_profile.get("security_headers") or {}
        _sh_present = _tp_sh.get("present") or []
        _sh_missing = _tp_sh.get("missing") or []
        if _sh_present or _sh_missing:
            story.append(Paragraph("Security Headers", s_label))
            if _sh_present:
                story.append(Paragraph(
                    f"<font color='#16a34a'>Present:</font> {', '.join(_sh_present)}", s_val))
            if _sh_missing:
                story.append(Paragraph(
                    f"<font color='#dc2626'>Missing:</font> {', '.join(_sh_missing)}", s_val))
            story.append(Spacer(1, 2*mm))

        # Cookies
        _tp_ck = target_profile.get("cookies") or []
        if _tp_ck:
            story.append(Paragraph("Cookies", s_label))
            story.append(Paragraph(", ".join(_tp_ck), s_val))
            story.append(Spacer(1, 2*mm))

    # ── 3. Detailed Findings ─────────────────────────────────────────────────
    if all_findings:
        story.append(PageBreak())
        story.append(Paragraph("3. Detailed Findings", s_h2))

        def _detail_section(findings, section_label):
            if not findings:
                return
            story.append(Paragraph(f"{section_label} ({len(findings)})", s_h3))
            for _risk_level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                grp = [_f for _f in findings if (_f.get("risk") or "LOW").upper() == _risk_level]
                if not grp:
                    continue
                _hx = RISK_HEX[_risk_level]
                story.append(Paragraph(
                    f'<font color="#{_hx}">{_risk_level.capitalize()} Severity Findings ({len(grp)})</font>',
                    _ps(f"sr_rl_{_risk_level}", fontName="Helvetica-Bold", fontSize=10.5, leading=14,
                        spaceBefore=4*mm, spaceAfter=2*mm),
                ))
                for _f in grp:
                    _title    = str(_f.get("title") or "Untitled")
                    _status   = str(_f.get("status") or "Open")
                    _date_str = (_f.get("datetime") or "")[:10]
                    _desc     = str(_f.get("description") or "")
                    _affected = _f.get("affected") or []
                    if isinstance(_affected, str):
                        _affected = [a.strip() for a in re.split(r'[\n,]+', _affected) if a.strip()]

                    block = [
                        Paragraph(f"<b>{_title}</b>",
                                  _ps("sr_ft", fontName="Helvetica-Bold", fontSize=10,
                                      leading=13, spaceBefore=3*mm, spaceAfter=1*mm)),
                        Paragraph(
                            f'Risk: <font color="#{_hx}">{_risk_level.capitalize()}</font>'
                            f'&nbsp;&nbsp;|&nbsp;&nbsp;Status: {_status}'
                            f'&nbsp;&nbsp;|&nbsp;&nbsp;Promoted: {_date_str}',
                            s_meta,
                        ),
                        HRFlowable(width="100%", thickness=0.3, color=C_BORDER, spaceAfter=2*mm),
                    ]

                    if _desc:
                        block.append(Paragraph("Observed Issues",
                                               _ps("sr_oih", fontName="Helvetica-Bold",
                                                   fontSize=9, leading=12, spaceAfter=1*mm)))
                        for _line in _desc.split('\n'):
                            _line = _line.strip()
                            if _line:
                                block.append(Paragraph(_line, s_issue))

                    if _affected:
                        block.append(Spacer(1, 2*mm))
                        block.append(Paragraph("Affected Instances",
                                               _ps("sr_aih", fontName="Helvetica-Bold",
                                                   fontSize=9, leading=12, spaceAfter=1*mm)))
                        aff_rows = [[Paragraph("<b>ID</b>", s_base),
                                     Paragraph("<b>System</b>", s_base)]]
                        for _idx, _item in enumerate(_affected[:50], 1):
                            if isinstance(_item, dict):
                                _sys = _item.get("url") or _item.get("system") or str(_item)
                            else:
                                _sys = str(_item)
                            aff_rows.append([
                                Paragraph(str(_idx), s_base),
                                Paragraph(_sys[:250], s_mono),
                            ])
                        aff_t = Table(aff_rows, colWidths=[CW*0.07, CW*0.93])
                        aff_t.setStyle(TableStyle([
                            ("BACKGROUND",    (0,0), (-1,0),  C_LIGHT),
                            ("LINEBELOW",     (0,0), (-1,0),  0.5, C_BORDER),
                            ("LINEBELOW",     (0,1), (-1,-1), 0.3, C_BORDER),
                            ("VALIGN",        (0,0), (-1,-1), "TOP"),
                            ("TOPPADDING",    (0,0), (-1,-1), 2),
                            ("BOTTOMPADDING", (0,0), (-1,-1), 2),
                            ("LEFTPADDING",   (0,0), (-1,-1), 4),
                        ]))
                        block.append(aff_t)

                    story.append(KeepTogether(block))
                    story.append(Spacer(1, 3*mm))

        _detail_section(web_findings, "Web Application Findings")
        _detail_section(api_findings, "API Findings")

    # ── Build PDF ────────────────────────────────────────────────────────────
    def _on_page(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(C_GRAY)
        canvas.drawString(MARGIN, 10*mm, proj_name)
        canvas.drawRightString(PAGE_W - MARGIN, 10*mm, f"Page {doc.page}")
        canvas.restoreState()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=18*mm, bottomMargin=15*mm,
        title=f"Status Report — {proj_name}",
        author="Crucible",
    )
    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    buf.seek(0)

    _client_short = re.sub(r"[^\w\-]", "_", proj.get("client_short", "") or proj.get("name", project_id))
    _dt_stamp = datetime.now().strftime("%Y%m%d")
    filename = f"StatusReport_{_client_short}_{_dt_stamp}.pdf"
    return app.response_class(
        buf.read(), mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/api/logs/<project_id>")
def api_logs(project_id: str):
    proj = _get_project(project_id)
    in_mem = _log_buffers.get(project_id, [])
    if in_mem:
        return jsonify(in_mem)
    if proj:
        entries = _read_jsonl(Path(proj["project_dir"]) / "crucible_logs.jsonl")
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
        entries = _read_jsonl(Path(proj["project_dir"]) / "crucible_errors.jsonl",
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


@app.route("/api/file_content/<project_id>")
def api_file_content(project_id: str):
    """Return the text content of a finding output file.

    The path query parameter must resolve to a file inside the project's
    project_dir (enforced server-side to prevent directory traversal).
    """
    proj = _get_project(project_id)
    if not proj:
        return jsonify({"error": "project not found"}), 404

    raw_path = request.args.get("path", "").strip()
    if not raw_path:
        return jsonify({"error": "path required"}), 400

    try:
        target = Path(raw_path).resolve()
        project_dir = Path(proj["project_dir"]).resolve()
        if not str(target).startswith(str(project_dir)):
            return jsonify({"error": "access denied"}), 403
        if not target.exists() or not target.is_file():
            return jsonify({"error": "file not found"}), 404
        # Cap at 512 KB to avoid sending huge outputs to the browser
        content = target.read_text(encoding="utf-8", errors="replace")[:524288]
        return jsonify({"path": str(target), "content": content})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/file_serve/<project_id>")
def api_file_serve(project_id: str):
    """Serve a binary evidence file (e.g. screenshot PNG) directly.

    Validates that the requested path is within the project directory to
    prevent directory-traversal attacks.
    """
    import mimetypes
    proj = _get_project(project_id)
    if not proj:
        return jsonify({"error": "project not found"}), 404

    raw_path = request.args.get("path", "").strip()
    if not raw_path:
        return jsonify({"error": "path required"}), 400

    try:
        target_path  = Path(raw_path).resolve()
        project_dir  = Path(proj["project_dir"]).resolve()
        if not str(target_path).startswith(str(project_dir)):
            return jsonify({"error": "access denied"}), 403
        if not target_path.exists() or not target_path.is_file():
            return jsonify({"error": "file not found"}), 404
        mime_type, _ = mimetypes.guess_type(str(target_path))
        return send_file(str(target_path), mimetype=mime_type or "application/octet-stream")
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


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


@app.route("/api/target_profile/<project_id>")
def api_target_profile(project_id: str):
    """Return target_profile.json written by Fracture during a scan."""
    proj = _get_project(project_id)
    if not proj:
        return jsonify({}), 404
    _sf   = proj.get("fr_settings_file") or ""
    _pdir = Path(proj["project_dir"]) if proj.get("project_dir") else None
    try:
        if _sf and Path(_sf).is_file():
            fr_cfg  = json.loads(Path(_sf).read_text())
            fr_proj = fr_cfg.get("scan", {}).get("project", "")
            if fr_proj and _pdir:
                tp_path = _pdir / fr_proj / "target_profile.json"
                if tp_path.exists():
                    return jsonify(json.loads(tp_path.read_text()))
        # Fallback: target_profile.json directly in project_dir (discovered projects)
        if _pdir:
            tp_path = _pdir / "target_profile.json"
            if tp_path.exists():
                return jsonify(json.loads(tp_path.read_text()))
    except Exception:
        pass
    return jsonify({}), 200


@app.route("/api/delete_project/<project_id>", methods=["DELETE"])
def api_delete_project(project_id: str):
    data = _load_projects()
    data["projects"].pop(project_id, None)
    _save_projects(data)
    return jsonify({"success": True})


@app.route("/api/download-project/<project_id>", methods=["GET"])
def api_download_project(project_id: str):
    """Download the entire project directory as a zip archive."""
    proj = _get_project(project_id)
    if not proj:
        return jsonify({"error": "not found"}), 404
    project_dir = proj.get("project_dir", "")
    if not project_dir or not os.path.isdir(project_dir):
        return jsonify({"error": "project directory not found"}), 404
    buf = io.BytesIO()
    base = os.path.basename(project_dir.rstrip("/"))
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _dirs, files in os.walk(project_dir):
            for fname in files:
                abs_path = os.path.join(root, fname)
                arc_name = os.path.join(base, os.path.relpath(abs_path, project_dir))
                zf.write(abs_path, arc_name)
    buf.seek(0)
    client_short = re.sub(r"[^\w\-]", "_", proj.get("client_short", "") or proj.get("name", project_id))
    dt_stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    is_complete = (proj.get("fr_status") == "complete" or proj.get("si_status") == "complete")
    if is_complete:
        dl_name = f"{client_short}_Fracture_AllFiles_{dt_stamp}.zip"
    else:
        dl_name = f"{client_short}_Fracture_AllFiles_Incomplete_{dt_stamp}.zip"
    return send_file(
        buf,
        mimetype="application/zip",
        as_attachment=True,
        download_name=dl_name,
    )


@app.route("/api/clear_project/<project_id>", methods=["POST"])
def api_clear_project(project_id: str):
    """Clear all scan data for an engagement, preserving config files only."""
    proj = _get_project(project_id)
    if not proj:
        return jsonify({"error": "not found"}), 404

    fr_settings = Path(proj.get("fr_settings_file", ""))
    si_settings = Path(proj.get("si_settings_file", ""))
    proj_dir    = Path(proj.get("project_dir", ""))
    si_out_dir  = Path(proj.get("siphon_output_dir", ""))

    # Build set of absolute paths to preserve
    keep: set[Path] = set()
    for p in [fr_settings, si_settings, proj_dir / "project_meta.json"]:
        try:
            if p and str(p) not in ("", ".") and p.exists():
                keep.add(p.resolve())
        except Exception:
            pass

    def _wipe_dir(directory: Path) -> None:
        """Delete all contents of directory except paths in keep."""
        if not directory.is_dir() or str(directory) in ("", "."):
            return
        for item in list(directory.iterdir()):
            try:
                if item.resolve() in keep:
                    continue
                if item.is_dir():
                    shutil.rmtree(item, ignore_errors=True)
                else:
                    item.unlink(missing_ok=True)
            except Exception:
                pass

    # Clear project_dir — removes tool output subdirs + all Crucible JSONL runtime files
    _wipe_dir(proj_dir)

    # For newer project layouts where siphon lives in a separate top-level directory
    if (si_out_dir.is_dir() and str(si_out_dir) not in ("", ".") and
            si_out_dir.resolve() != proj_dir.resolve()):
        _wipe_dir(si_out_dir)

    data = _load_projects()
    p = data["projects"].get(project_id)
    if p:
        p["fr_status"]   = "idle"
        p["si_status"]   = "idle"
        p["fr_last_run"] = None
        p["si_last_run"] = None
        _save_projects(data)

    # Clear all in-memory caches so stale data doesn't persist for the session
    _all_findings.pop(project_id, None)
    _buffers.pop(project_id, None)
    _log_buffers.pop(project_id, None)
    _err_buffers.pop(project_id, None)
    _status_cache.pop(project_id, None)
    ts = _tool_status.get(project_id)
    if ts:
        ts["fr"] = "idle"
        ts["si"] = "idle"

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
            lines = _read_jsonl(proj_dir / f"crucible_console_{tool}.jsonl",
                                limit=_MAX_CONSOLE)
            if lines:
                _buffers.setdefault(project_id, {"fr": [], "si": []})[tool] = lines
        for entry in lines:
            emit(f"{tool}_output", entry)

    # Findings — emit to this socket only (no room broadcast)
    # Disk fallback when in-memory store is empty (e.g. after Crucible restart)
    proj_findings = _all_findings.get(project_id, [])
    if not proj_findings:
        _pf = _all_findings.setdefault(project_id, [])
        _loaded_keys: set = set()
        for _tool_key, _tool_name, _scope_name in (
            ("fr_settings_file", "fracture", "webapp"),
            ("si_settings_file", "siphon", "api"),
        ):
            _cfg_path = Path(proj.get(_tool_key, ""))
            if _cfg_path.exists():
                try:
                    _cfg_data = json.loads(_cfg_path.read_text())
                    _proj_name = _cfg_data.get("scan", {}).get(
                        "project",
                        "fracture_output" if _tool_name == "fracture" else "siphon_output",
                    )
                    _fp = Path(proj["project_dir"]) / _proj_name / "findings.json"
                    if _fp.exists():
                        _existing = {_fkey(f) for f in _pf}
                        for _raw in json.loads(_fp.read_text()):
                            _f = dict(_raw)
                            _f["_tool"]  = _tool_name
                            _f["_scope"] = _scope_name
                            _k = _fkey(_f)
                            if _k not in _existing and _k not in _loaded_keys:
                                _loaded_keys.add(_k)
                                _pf.append(_f)
                except Exception:
                    pass
        proj_findings = _all_findings.get(project_id, [])
    for f in proj_findings:
        emit("finding", {"tool": f.get("_tool", ""), "finding": f})

    # Restart watcher if a tool is currently running (handles reconnects mid-scan)
    _live_status = _tool_status.get(project_id, {})
    if _live_status.get("fr") == "running" or _live_status.get("si") == "running":
        _ensure_watcher(project_id, proj)

    # Phase status
    sc = _status_cache.get(project_id, {})
    for tool, phases in sc.items():
        for phase_key, phase_data in phases.items():
            emit("crucible_status", {"tool": tool, **phase_data})

    # Structured log entries (with disk fallback)
    log_entries = _log_buffers.get(project_id, [])
    if not log_entries:
        log_entries = _read_jsonl(proj_dir / "crucible_logs.jsonl", limit=_MAX_LOG)
        if log_entries:
            _log_buffers[project_id] = log_entries
    for entry in log_entries:
        emit("log_entry", {"tool": entry.get("tool", ""), "entry": entry})

    # Structured error entries (with disk fallback)
    err_entries = _err_buffers.get(project_id, [])
    if not err_entries:
        err_entries = _read_jsonl(proj_dir / "crucible_errors.jsonl", limit=_MAX_ERR)
        if err_entries:
            _err_buffers[project_id] = err_entries
    for entry in err_entries:
        emit("err_entry", {"tool": entry.get("tool", ""), "entry": entry})

    # Pending prompt
    for tool in ("fr", "si"):
        pkey    = _pkey(project_id, tool)
        pending = _pending_prompts.get(pkey)
        if pending:
            emit("crucible_prompt", {"tool": tool, "payload": pending})


@socketio.on("leave_project")
def on_leave_project(data):
    project_id = data.get("project_id", "")
    leave_room(_room(project_id))
    _sid_to_project.pop(request.sid, None)


# ---------------------------------------------------------------------------
# SocketIO — prompt answer
# ---------------------------------------------------------------------------
@socketio.on("crucible_answer")
def on_crucible_answer(data):
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
    # NOTE: do NOT emit prompt_resolved here — the _reader thread emits it
    # after _write_to_stdin() completes, ensuring no race with the next prompt.


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

    fr_settings_path = proj.get("fr_settings_file", "")
    if not fr_settings_path:
        return emit("fr_error", {"error": "Fracture settings file not configured for this project."})
    if not Path(fr_settings_path).exists():
        return emit("fr_error", {"error": f"Fracture settings file not found: {fr_settings_path}"})
    cmd = [sys.executable, str(FRACTURE_SCRIPT),
           "--settings", fr_settings_path]

    resume = bool(data.get("resume", False))

    try:
        fr_cfg = json.loads(Path(fr_settings_path).read_text())
        fr_proj_name = fr_cfg.get("scan", {}).get("project", "fracture_output")
        if fr_cfg.get("scan", {}).get("browser_auth"):
            cmd.append("--browser-auth")
    except Exception:
        fr_proj_name = "fracture_output"

    cwd = proj["project_dir"]
    Path(cwd).mkdir(parents=True, exist_ok=True)

    if not resume:
        try:
            _cp = Path(cwd) / fr_proj_name / "checkpoint.json"
            if _cp.exists():
                _cp.unlink()
        except Exception:
            pass

    env = dict(os.environ)
    env["CRUCIBLE_MANAGED"] = "1"
    env["PYTHONUNBUFFERED"] = "1"
    # Ensure standard tool directories are in PATH so shutil.which() works in
    # subprocesses even when launched from a LaunchDaemon with a minimal PATH.
    _tool_path_dirs = ["/usr/local/bin", "/opt/homebrew/bin", "/usr/bin", "/bin"]
    _cur_path = env.get("PATH", "")
    _extra = ":".join(d for d in _tool_path_dirs if d not in _cur_path.split(":"))
    if _extra:
        env["PATH"] = _extra + (":" + _cur_path if _cur_path else "")

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
    _fr_started_at = datetime.now(timezone.utc).isoformat()
    _update_project_field(project_id,
        fr_status="running",
        fr_last_run=_fr_started_at,
        fr_proj_name=fr_proj_name,
    )

    socketio.emit("fr_started",   {"pid": proc.pid, "started_at": _fr_started_at}, room=_room(project_id))
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
    on_crucible_answer({**data, "tool": "fr"})


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

    si_settings_path = proj.get("si_settings_file", "")
    if not si_settings_path:
        return emit("si_error", {"error": "Siphon settings file not configured for this project."})
    if not Path(si_settings_path).exists():
        return emit("si_error", {"error": f"Siphon settings file not found: {si_settings_path}"})
    cmd = [sys.executable, str(SIPHON_SCRIPT),
           "--settings", si_settings_path]

    resume = bool(data.get("resume", False))

    try:
        si_cfg = json.loads(Path(si_settings_path).read_text())
        si_proj_name = si_cfg.get("scan", {}).get("project", "siphon_output")
    except Exception:
        si_proj_name = "siphon_output"

    cwd = proj["project_dir"]
    Path(cwd).mkdir(parents=True, exist_ok=True)

    if not resume:
        try:
            _cp = Path(cwd) / si_proj_name / "checkpoint.json"
            if _cp.exists():
                _cp.unlink()
        except Exception:
            pass

    env = dict(os.environ)
    env["CRUCIBLE_MANAGED"] = "1"
    env["PYTHONUNBUFFERED"] = "1"
    # Ensure standard tool directories are in PATH so shutil.which() works in
    # subprocesses even when launched from a LaunchDaemon with a minimal PATH.
    _tool_path_dirs = ["/usr/local/bin", "/opt/homebrew/bin", "/usr/bin", "/bin"]
    _cur_path = env.get("PATH", "")
    _extra = ":".join(d for d in _tool_path_dirs if d not in _cur_path.split(":"))
    if _extra:
        env["PATH"] = _extra + (":" + _cur_path if _cur_path else "")

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
    _si_started_at = datetime.now(timezone.utc).isoformat()
    _update_project_field(project_id,
        si_status="running",
        si_last_run=_si_started_at,
        si_proj_name=si_proj_name,
    )

    socketio.emit("si_started",   {"pid": proc.pid, "started_at": _si_started_at}, room=_room(project_id))
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
    on_crucible_answer({**data, "tool": "si"})


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------
def _write_to_stdin(proc: subprocess.Popen, text: str,
                    project_id: str = "", tool: str = "") -> None:
    """Safely write a line to a subprocess stdin."""
    try:
        if proc.stdin and not proc.stdin.closed:
            proc.stdin.write(text + "\n")
            proc.stdin.flush()
        elif proc.stdin and proc.stdin.closed:
            # Pipe is closed. If the process has already exited this is expected
            # (the reader thread was blocked on a prompt answer when the process
            # finished and _wait_proc closed stdin). Suppress the log in that case
            # — it is not an error. Only log when the process is still running but
            # stdin is unexpectedly closed, which indicates a real pipe failure.
            if project_id and proc.poll() is None:
                _emit_line(project_id, tool,
                           "[Crucible] stdin write skipped — pipe closed while process running",
                           "system")
    except Exception as _e:
        if project_id:
            _emit_line(project_id, tool,
                       f"[Crucible] stdin write error: {_e}", "system")


def _reader(project_id: str, tool: str, stream,
            stream_name: str, proc: subprocess.Popen) -> None:
    """Drain one stdout/stderr stream.

    stdout: iterated line-by-line (fast).
    stderr: read char-by-char so sudo's password prompt (no trailing newline)
            is detected and forwarded to the browser modal immediately.

    Handles protocol tokens:
      __CRUCIBLE_LOG__:    -> structured log entry
      __CRUCIBLE_ERR__:    -> structured error entry
      __CRUCIBLE_PROMPT__: -> interactive prompt (show modal, block on stdin)
      __CRUCIBLE_STATUS__: -> phase/step status update
    """
    proj = _get_project(project_id)
    pkey = _pkey(project_id, tool)

    def _process_line(line: str) -> None:
        if not line:
            return

        # Structured log
        if line.startswith(_CP_LOG):
            try:
                entry = json.loads(line[len(_CP_LOG):])
                entry["tool"] = tool
                _buf_append_log(project_id, entry, proj)
                # Mirror to console so progress is visible
                lvl = entry.get("level", "INFO")
                _emit_line(project_id, tool,
                           f"[{lvl}] {entry.get('message', '')}", stream_name)
                # WARNING messages that are informational noise — do not route
                # to the Errors tab.  These indicate expected fallback conditions,
                # not actionable scan failures.
                _WARN_SUPPRESS = (
                    "could not build xauthority",
                    "could not automate js navigation",
                    "vhost hits suppressed",
                )
                _msg_lower = entry.get("message", "").lower()
                _suppress_err_tab = (
                    lvl == "WARNING"
                    and any(s in _msg_lower for s in _WARN_SUPPRESS)
                )
                # Also route WARNING/ERROR level entries to the Errors tab
                if lvl in ("WARNING", "ERROR") and not _suppress_err_tab:
                    _buf_append_err(project_id, {
                        "ts":       entry.get("ts", datetime.now(timezone.utc).isoformat()),
                        "source":   tool,
                        "tool":     tool,
                        "message":  entry.get("message", ""),
                        "detail":   "",
                        "category": _categorise_error(entry.get("message", "")),
                    }, proj)
            except Exception:
                _emit_line(project_id, tool, line, stream_name)
            return

        # Structured error
        if line.startswith(_CP_ERR):
            try:
                entry = json.loads(line[len(_CP_ERR):])
                entry["tool"] = tool
                if "category" not in entry:
                    entry["category"] = _categorise_error(entry.get("message", ""))
                _buf_append_err(project_id, entry, proj)
                # Mirror to console
                _emit_line(project_id, tool,
                           f"[ERR] {entry.get('message', '')}", "stderr")
            except Exception:
                _emit_line(project_id, tool, line, "stderr")
            return

        # Interactive prompt
        if line.startswith(_CP_PROMPT):
            # Parse payload — bail out on bad JSON
            try:
                payload = json.loads(line[len(_CP_PROMPT):])
            except Exception:
                _emit_line(project_id, tool, line, stream_name)
                return
            _pending_prompts[pkey] = payload
            # Notify browser — log any emit error but don't skip the stdin write
            try:
                socketio.emit("crucible_prompt",
                    {"tool": tool, "payload": payload},
                    room=_room(project_id))
            except Exception as _pe:
                _emit_line(project_id, tool,
                           f"[Crucible] prompt emit error: {_pe}", "system")
            # Always wait for the answer and deliver it to the subprocess stdin
            q = _answer_queues.get(pkey)
            if q:
                try:
                    answer = q.get(timeout=1800)
                except queue.Empty:
                    answer = ""
                _write_to_stdin(proc, answer, project_id, tool)
            else:
                _emit_line(project_id, tool,
                           "[Crucible] No answer queue for prompt — subprocess may be stuck",
                           "system")
            _prompt_id = payload.get("id", "")
            _pending_prompts.pop(pkey, None)
            socketio.emit("prompt_resolved",
                {"tool": tool, "prompt_id": _prompt_id},
                room=_room(project_id))
            return

        # Phase status
        if line.startswith(_CP_STATUS):
            try:
                sdata = json.loads(line[len(_CP_STATUS):])
                sdata["tool"] = tool
                sc = _status_cache.setdefault(project_id, {"fr": {}, "si": {}})
                sc.setdefault(tool, {})[sdata.get("phase", "?")] = sdata
                socketio.emit("crucible_status", sdata, room=_room(project_id))
                # Mirror phase transitions to console
                step = sdata.get("step", "")
                if step:
                    _emit_line(project_id, tool,
                               f"[{sdata.get('label', sdata.get('phase', '?'))}] {step}",
                               stream_name)
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
            socketio.emit("crucible_prompt",
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
    _final_status = "complete" if rc == 0 else "done"
    _tool_status[project_id][tool] = _final_status
    _update_project_field(project_id, **{f"{tool}_status": _final_status})
    _answer_queues.pop(_pkey(project_id, tool), None)
    _pending_prompts.pop(_pkey(project_id, tool), None)
    threading.Thread(target=_dequeue_next, daemon=True).start()

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
    _watcher_flags[project_id] = True  # revive flag even if watcher is mid-sleep
    if project_id in _watchers and _watchers[project_id].is_alive():
        return
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
            # Re-check: a new scan may have started during the 60 s cooldown
            _rechk = _tool_status.get(project_id, {})
            if _rechk.get("fr") == "running" or _rechk.get("si") == "running":
                continue
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
            # Merge sources, cves, and accounts into existing entry
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
                    ex_accts = existing.get("accounts") or []
                    new_accts = f.get("accounts") or []
                    if new_accts:
                        ex_roles = {a.get("role", "") for a in ex_accts}
                        added = [a for a in new_accts if a.get("role", "") not in ex_roles]
                        if added:
                            existing["accounts"] = ex_accts + added
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
# Job queue helpers
# ---------------------------------------------------------------------------

def _load_execute_queue() -> None:
    global _job_queue
    try:
        if _QUEUE_FILE.exists():
            _job_queue = json.loads(_QUEUE_FILE.read_text())
    except Exception:
        _job_queue = []


def _save_execute_queue() -> None:
    try:
        _QUEUE_FILE.write_text(json.dumps(_job_queue, indent=2))
    except Exception:
        pass


def _is_any_running() -> bool:
    for procs in _procs.values():
        if procs and (procs.get("fr") or procs.get("si")):
            return True
    return False


def _launch_tool_bg(project_id: str, tool: str) -> None:
    """Launch fr or si for a project without requiring a SocketIO context."""
    proj = _get_project(project_id)
    if not proj:
        return
    if (_procs.get(project_id) or {}).get(tool):
        return
    settings_key = "fr_settings_file" if tool == "fr" else "si_settings_file"
    script = FRACTURE_SCRIPT if tool == "fr" else SIPHON_SCRIPT
    settings_path = proj.get(settings_key, "")
    if not settings_path or not Path(settings_path).exists():
        logger.warning(f"[queue] {tool} settings not found for {project_id}")
        return
    try:
        cfg = json.loads(Path(settings_path).read_text())
        proj_name = cfg.get("scan", {}).get("project", f"{tool}_output")
    except Exception:
        proj_name = f"{tool}_output"
    cwd = proj["project_dir"]
    Path(cwd).mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["CRUCIBLE_MANAGED"] = "1"
    env["PYTHONUNBUFFERED"] = "1"
    _tp = ["/usr/local/bin", "/opt/homebrew/bin", "/usr/bin", "/bin"]
    _cp = env.get("PATH", "")
    _extra = ":".join(d for d in _tp if d not in _cp.split(":"))
    if _extra:
        env["PATH"] = _extra + (":" + _cp if _cp else "")
    cmd = [sys.executable, str(script), "--settings", settings_path]
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.PIPE, text=True, bufsize=1, cwd=cwd, env=env,
        )
    except Exception as exc:
        logger.error(f"[queue] Failed to launch {tool} for {project_id}: {exc}")
        return
    _init_project_state(project_id)
    _procs[project_id][tool] = proc
    _tool_status[project_id][tool] = "running"
    _answer_queues[_pkey(project_id, tool)] = queue.Queue()
    label = "Fracture" if tool == "fr" else "Siphon"
    _update_project_field(project_id, **{
        f"{tool}_status": "running",
        f"{tool}_last_run": datetime.now(timezone.utc).isoformat(),
        f"{tool}_proj_name": proj_name,
    })
    socketio.emit("tool_status", _tool_status[project_id], room=_room(project_id))
    _emit_line(project_id, tool,
        f"[Crucible] {label} started (queued) — PID {proc.pid}", "system")
    threading.Thread(target=_reader,
        args=(project_id, tool, proc.stdout, "stdout", proc), daemon=True).start()
    threading.Thread(target=_reader,
        args=(project_id, tool, proc.stderr, "stderr", proc), daemon=True).start()
    threading.Thread(target=_wait_proc,
        args=(project_id, tool, proc), daemon=True).start()
    _ensure_watcher(project_id, proj)


def _execute_queued_job(job: dict) -> None:
    project_id = job.get("project_id", "")
    tools = job.get("tools", ["fr", "si"])
    if not project_id:
        return
    for tool in tools:
        _launch_tool_bg(project_id, tool)


def _dequeue_next() -> None:
    with _queue_lock:
        if not _job_queue or _is_any_running():
            return
        job = _job_queue.pop(0)
        _save_execute_queue()
    threading.Thread(target=_execute_queued_job, args=(job,), daemon=True).start()


# ---------------------------------------------------------------------------
# API: Project template + remote execute
# ---------------------------------------------------------------------------

@app.route("/api/project-template")
def api_project_template():
    return jsonify({
        "tool": "crucible",
        "description": "Web application and API assessment platform",
        "fields": {
            "engagement_name":   {"type": "string",  "required": True,  "label": "Engagement Name"},
            "client_name":       {"type": "string",  "required": True,  "label": "Client Name"},
            "client_short":      {"type": "string",  "required": False, "label": "Client Short Name"},
            "scope":             {"type": "select",  "required": False, "label": "Scope",
                                  "options": ["webapp", "api", "both"], "default": "both"},
            "start_date":        {"type": "date",    "required": False, "label": "Start Date"},
            "include_fr":        {"type": "boolean", "required": False, "label": "Include Fracture", "default": True},
            "include_si":        {"type": "boolean", "required": False, "label": "Include Siphon",   "default": True},
            "fr_target_urls":    {"type": "text",    "required": False, "label": "Fracture Target URL(s)", "hint": "One URL per line"},
            "fr_auth_method":    {"type": "select",  "required": False, "label": "Fracture Auth Method",
                                  "options": ["none", "basic", "form", "token", "api_key", "oauth2"], "default": "none"},
            "fr_auth_username":  {"type": "string",  "required": False, "label": "Fracture Username"},
            "fr_auth_password":  {"type": "string",  "required": False, "label": "Fracture Password", "sensitive": True},
            "fr_auth_token":     {"type": "string",  "required": False, "label": "Fracture Token",    "sensitive": True},
            "fr_auth_login_url": {"type": "string",  "required": False, "label": "Fracture Login URL"},
            "si_target_urls":    {"type": "text",    "required": False, "label": "Siphon Target URL(s)", "hint": "One URL per line"},
            "si_api_spec_url":   {"type": "string",  "required": False, "label": "Siphon API Spec URL"},
            "si_auth_method":    {"type": "select",  "required": False, "label": "Siphon Auth Method",
                                  "options": ["none", "basic", "token", "api_key", "oauth2"], "default": "none"},
            "si_auth_username":  {"type": "string",  "required": False, "label": "Siphon Username"},
            "si_auth_password":  {"type": "string",  "required": False, "label": "Siphon Password",  "sensitive": True},
            "si_auth_token":     {"type": "string",  "required": False, "label": "Siphon Token",     "sensitive": True},
        },
    })


@app.route("/api/execute-project", methods=["POST"])
def api_execute_project():
    body = request.get_json(force=True, silent=True) or {}
    execute = body.get("execute", True)

    project_id = str(uuid.uuid4())
    cfg_dir    = PROJECTS_DIR / project_id
    cfg_dir.mkdir(parents=True, exist_ok=True)

    client_short = re.sub(r'[^\w-]', '_',
        (body.get("client_short") or "client").strip().lower())
    scope_str = {"webapp": "webapp", "api": "api", "both": "both"}.get(
        body.get("scope", "both").lower(), "both")
    year = _extract_year(body.get("start_date", ""))

    fr_output_dir = _build_project_dir(client_short, year, "fracture")
    si_output_dir = _build_project_dir(client_short, year, "siphon")

    fr = _deepcopy_template(FR_DEFAULTS)
    for k in fr["engagement"]:
        fr["engagement"][k] = body.get(k, "")
    fr["scan"]["project"] = str(fr_output_dir)
    fr_url_list = _parse_url_list(body.get("fr_target_urls", "") or body.get("fr_target_url", ""))
    fr["scan"]["target_url"]  = fr_url_list[0] if fr_url_list else ""
    fr["scan"]["target_urls"] = fr_url_list
    if body.get("fr_auth_method") and body["fr_auth_method"] != "none":
        fr["scan"]["auth"] = _build_fr_auth_from_body(body)

    si = _deepcopy_template(SI_DEFAULTS)
    for k in si["engagement"]:
        si["engagement"][k] = body.get(k, "")
    si["scan"]["project"] = str(si_output_dir)
    si_url_list = _parse_url_list(body.get("si_target_urls", "") or body.get("si_target_url", ""))
    si["scan"]["api_base_url"]  = si_url_list[0] if si_url_list else ""
    si["scan"]["api_base_urls"] = si_url_list[1:] if len(si_url_list) > 1 else []
    si["scan"]["api_spec_url"]  = body.get("si_api_spec_url", "")
    si["scan"]["auth"] = _build_si_auth_from_body(body)

    fr_path = fr_output_dir / "fr_settings.json"
    si_path = si_output_dir / "si_settings.json"
    fr_path.write_text(json.dumps(fr, indent=2))
    si_path.write_text(json.dumps(si, indent=2))

    tools = []
    if body.get("include_fr", True):
        tools.append("fr")
    if body.get("include_si", True):
        tools.append("si")
    if not tools:
        tools = ["fr", "si"]

    proj = {
        "name":              body.get("engagement_name") or f"Engagement {project_id[:8]}",
        "client_name":       body.get("client_name", ""),
        "client_short":      client_short,
        "scope":             scope_str,
        "created":           datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "project_dir":       str(fr_output_dir),
        "fr_settings_file":  str(fr_path),
        "si_settings_file":  str(si_path),
        "fracture_output_dir": str(fr_output_dir),
        "siphon_output_dir":   str(si_output_dir),
        "tools":             tools,
        "fr_status":         "idle",
        "si_status":         "idle",
        "fr_last_run":       None,
        "si_last_run":       None,
    }
    data = _load_projects()
    data["projects"][project_id] = proj
    _save_projects(data)

    if not execute:
        return jsonify({"ok": True, "project_id": project_id, "queued": False, "started": False})

    job = {"project_id": project_id, "tools": tools}
    with _queue_lock:
        if _is_any_running():
            position = len(_job_queue) + 1
            _job_queue.append(job)
            _save_execute_queue()
            return jsonify({"ok": True, "project_id": project_id, "queued": True, "position": position})

    threading.Thread(target=_execute_queued_job, args=(job,), daemon=True).start()
    return jsonify({"ok": True, "project_id": project_id, "queued": False, "started": True})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    _load_execute_queue()
    print("=" * 54)
    print(f" Crucible — Web & API Assessment Platform  v{VERSION}")
    print(" https://0.0.0.0:5500")
    print("=" * 54)
    socketio.run(app, host="0.0.0.0", port=5500, debug=False,
                 allow_unsafe_werkzeug=True,
                 ssl_context=_auth.make_ssl_context())
