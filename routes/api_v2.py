"""Crucible API v2 — programmatic access for Gauntlet and external orchestrators.

Provides a RESTful JSON API secured by API-key authentication (sha256-hashed
keys stored in crucible_settings.json).  Every endpoint returns Content-Type
application/json with a consistent error envelope: {"error": "<message>"}.

Endpoints:
    POST   /api/v2/projects/create       — create (and optionally auto-start) a project
    GET    /api/v2/projects/<id>/status   — project status, phase, progress, findings counts
    GET    /api/v2/projects/<id>/findings — findings in universal schema v1.1
    POST   /api/v2/projects/<id>/stop     — stop a running project
    GET    /api/v2/tools                  — list available tools and their status
    POST   /api/v2/keys/generate          — generate a new API key (session-auth only)
    DELETE /api/v2/keys/<key_hash>        — revoke an API key (session-auth only)
"""

import hashlib
import json
import logging
import os
import re
import secrets
import threading
import time
import uuid
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import Blueprint, request, jsonify, current_app, session

from config import (
    APP_DIR, CLIENTS_BASE, TOOLS, TOOL_OUTPUT_DIRS,
    TOOL_SETTINGS_PREFIX, VALID_RISKS, VERSION,
)
from models.project import (
    get_project, create_project, update_project, list_projects,
    get_project_dir, get_tool_output_dir, reload_projects,
)
from routes._helpers import require_project, get_ext

log = logging.getLogger("crucible.api_v2")

api_v2 = Blueprint("api_v2", __name__, url_prefix="/api/v2")

# ── Settings file for API keys ──────────────────────────────────────────────

_SETTINGS_FILE = APP_DIR / "crucible_settings.json"
_settings_lock = threading.Lock()


def _load_settings():
    """Load crucible_settings.json. Returns empty dict if missing/corrupt."""
    if not _SETTINGS_FILE.exists():
        return {}
    try:
        return json.loads(_SETTINGS_FILE.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("Failed to load crucible_settings.json: %s", exc)
        return {}


def _save_settings(data):
    """Atomically write crucible_settings.json."""
    tmp = _SETTINGS_FILE.with_suffix(".json.tmp")
    try:
        tmp.write_text(json.dumps(data, indent=2))
        tmp.replace(_SETTINGS_FILE)
    except OSError as exc:
        log.error("Failed to save crucible_settings.json: %s", exc)
        raise


# ── API key authentication ──────────────────────────────────────────────────

def _hash_key(raw_key):
    """SHA-256 hash of an API key."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def require_api_key(f):
    """Decorator: require a valid X-Api-Key header on the request."""
    @wraps(f)
    def decorated(*args, **kwargs):
        raw_key = request.headers.get("X-Api-Key", "").strip()
        if not raw_key:
            log.warning("API v2: missing X-Api-Key from %s %s [%s]",
                        request.method, request.path,
                        request.remote_addr)
            return jsonify({"error": "Missing X-Api-Key header"}), 401

        with _settings_lock:
            settings = _load_settings()
        api_keys = settings.get("api_keys", [])
        key_hash = _hash_key(raw_key)

        if not isinstance(api_keys, list) or key_hash not in api_keys:
            log.warning("API v2: invalid key from %s %s [%s]",
                        request.method, request.path,
                        request.remote_addr)
            return jsonify({"error": "Invalid API key"}), 401

        log.info("API v2: authenticated request %s %s [%s]",
                 request.method, request.path, request.remote_addr)
        return f(*args, **kwargs)
    return decorated


# ── Session-auth check for key management endpoints ────────────────────────

def _require_session_auth():
    """Return an error response tuple if the caller lacks a valid web session,
    or ``None`` if authenticated."""
    if not session.get("authenticated"):
        return jsonify({"error": "Admin session required"}), 401
    import _auth
    if not _auth._validate_session_token(session.get("session_token")):
        return jsonify({"error": "Session expired"}), 401
    return None


# ── Input validation helpers ────────────────────────────────────────────────

_SAFE_NAME_RE = re.compile(r"^[a-zA-Z0-9 _.'-]{1,128}$")
_SAFE_SHORT_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
_SAFE_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}$")
_SAFE_URL_RE = re.compile(r"^https?://[^\s]{1,2048}$")
_SAFE_CIDR_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$"
)
_SAFE_HOST_RE = re.compile(
    r"^[a-zA-Z0-9.:/_-]{1,256}$"
)

# Supported pr0t31n tools that can be launched via API v2
_LAUNCHABLE_TOOLS = {
    "fracture", "siphon", "ss3", "osift", "auger", "trawler",
    "aether", "aether_b", "aether_z", "aether_u",
    "bastion", "forge", "quill", "isotope", "dredge", "vault", "pain",
}

_AUTH_METHODS = {
    "none", "basic", "bearer", "header", "cookie", "ntlm",
    "digest", "oauth2", "api_key", "custom",
}


def _validate_string(value, label, pattern=None, max_len=256, required=True):
    """Validate a string field. Returns (cleaned, error_msg)."""
    if value is None or (isinstance(value, str) and not value.strip()):
        if required:
            return None, f"{label} is required"
        return "", None
    if not isinstance(value, str):
        return None, f"{label} must be a string"
    cleaned = value.strip()
    if len(cleaned) > max_len:
        return None, f"{label} exceeds maximum length ({max_len})"
    if pattern and not pattern.match(cleaned):
        return None, f"{label} contains invalid characters"
    return cleaned, None


def _validate_url(value, label, required=True):
    """Validate a URL field."""
    if not value or (isinstance(value, str) and not value.strip()):
        if required:
            return None, f"{label} is required"
        return "", None
    if not isinstance(value, str):
        return None, f"{label} must be a string"
    cleaned = value.strip()
    if not _SAFE_URL_RE.match(cleaned):
        return None, f"{label} must be a valid HTTP/HTTPS URL"
    return cleaned, None


def _validate_hosts(hosts, label):
    """Validate a list of CIDR/IP addresses. Returns (cleaned_list, error_msg)."""
    if not hosts:
        return [], f"{label} is required"
    if not isinstance(hosts, list):
        return None, f"{label} must be a list"
    cleaned = []
    for i, h in enumerate(hosts):
        if not isinstance(h, str) or not h.strip():
            return None, f"{label}[{i}] is empty or not a string"
        h = h.strip()
        if not _SAFE_CIDR_RE.match(h) and not _SAFE_HOST_RE.match(h):
            return None, f"{label}[{i}] is not a valid CIDR, IP, or hostname: {h}"
        cleaned.append(h)
    if not cleaned:
        return None, f"{label} must contain at least one entry"
    return cleaned, None


def _validate_auth_object(auth):
    """Validate an auth configuration object. Returns (cleaned, error_msg)."""
    if auth is None:
        return {"method": "none"}, None
    if not isinstance(auth, dict):
        return None, "auth must be an object"
    method = auth.get("method", "none")
    if not isinstance(method, str) or method.lower() not in _AUTH_METHODS:
        return None, f"auth.method must be one of: {', '.join(sorted(_AUTH_METHODS))}"
    cleaned = {"method": method.lower()}

    if method in ("basic", "ntlm", "digest"):
        for field in ("username", "password"):
            val = auth.get(field, "")
            if not isinstance(val, str):
                return None, f"auth.{field} must be a string"
            cleaned[field] = val

    elif method == "bearer":
        token = auth.get("token", "")
        if not isinstance(token, str):
            return None, "auth.token must be a string"
        cleaned["token"] = token

    elif method in ("header", "api_key"):
        for field in ("header_name", "header_value"):
            val = auth.get(field, "")
            if not isinstance(val, str):
                return None, f"auth.{field} must be a string"
            cleaned[field] = val

    elif method == "cookie":
        cookie_str = auth.get("cookie", "")
        if not isinstance(cookie_str, str):
            return None, "auth.cookie must be a string"
        cleaned["cookie"] = cookie_str

    elif method == "oauth2":
        for field in ("token_url", "client_id", "client_secret", "scope"):
            val = auth.get(field, "")
            if not isinstance(val, str):
                return None, f"auth.{field} must be a string"
            cleaned[field] = val

    elif method == "custom":
        headers = auth.get("headers", {})
        if not isinstance(headers, dict):
            return None, "auth.headers must be an object"
        for k, v in headers.items():
            if not isinstance(k, str) or not isinstance(v, str):
                return None, "auth.headers keys and values must be strings"
        cleaned["headers"] = headers

    return cleaned, None


# ── Service accessors ───────────────────────────────────────────────────────

def _pm():
    """Get the ProcessManager from app extensions."""
    return get_ext("process_manager")


def _qm():
    """Get the QueueManager from app extensions."""
    return get_ext("queue_manager")


def _fe():
    """Get the FindingsEngine from app extensions."""
    return get_ext("findings_engine")


# ── Tool installation check ─────────────────────────────────────────────────

def _is_tool_installed(tool_id):
    """Check whether a tool's script exists on disk."""
    tool_cfg = TOOLS.get(tool_id)
    if not tool_cfg:
        return False
    script = tool_cfg.get("script")
    if script is None:
        return False
    return Path(script).exists()


def _get_tool_version(tool_id):
    """Read the VERSION file for a tool. Returns version string or 'unknown'."""
    tool_cfg = TOOLS.get(tool_id)
    if not tool_cfg:
        return "unknown"
    script = tool_cfg.get("script")
    if not script:
        return "unknown"
    ver_file = Path(script).resolve().parent / "VERSION"
    try:
        return ver_file.read_text().strip()
    except OSError:
        return "unknown"


# ── Project creation lock ───────────────────────────────────────────────────

_create_lock = threading.Lock()


# ── Scope mapping ───────────────────────────────────────────────────────────

_TOOL_NATIVE_SCOPE = {
    "ss3": "external", "osift": "osint",
    "fracture": "webapp", "siphon": "api",
    "trawler": "pcap", "auger": "database",
    "bastion": "firewall", "forge": "cloud", "quill": "mobile",
    "isotope": "file", "dredge": "endpoint", "aether": "wifi",
    "aether_b": "bluetooth", "aether_z": "zigbee", "aether_u": "uwb",
}


# ═══════════════════════════════════════════════════════════════════════════
#  Endpoints
# ═══════════════════════════════════════════════════════════════════════════


# ── POST /api/v2/projects/create ────────────────────────────────────────────

@api_v2.route("/projects/create", methods=["POST"])
@require_api_key
def create_project_endpoint():
    """Create a managed-tool project and optionally auto-start it.

    Required body fields: tool, client_name, client_short
    Tool-specific: target_url (fracture/siphon), target_hosts (ss3)
    Optional: auth, source, source_project_id, auto_start, year,
              consultant_name, consultant_email
    """
    body = request.get_json(silent=True)
    if not body or not isinstance(body, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    # ── Required fields ────────────────────────────────────────
    tool_id = body.get("tool", "").strip().lower() if isinstance(body.get("tool"), str) else ""
    if not tool_id:
        return jsonify({"error": "tool is required"}), 400
    if tool_id not in _LAUNCHABLE_TOOLS:
        return jsonify({
            "error": f"Unsupported tool: {tool_id}. "
                     f"Must be one of: {', '.join(sorted(_LAUNCHABLE_TOOLS))}"
        }), 400

    if not _is_tool_installed(tool_id):
        return jsonify({"error": f"Tool '{tool_id}' is not installed on this system"}), 503

    client_name, err = _validate_string(body.get("client_name"), "client_name",
                                        pattern=_SAFE_NAME_RE, max_len=128)
    if err:
        return jsonify({"error": err}), 400

    raw_short = body.get("client_short", "")
    client_short, err = _validate_string(raw_short, "client_short",
                                         pattern=_SAFE_SHORT_RE, max_len=64)
    if err:
        return jsonify({"error": err}), 400
    client_short = client_short.lower().replace(" ", "_")

    # ── Tool-specific target validation ────────────────────────
    target_url = ""
    target_hosts = []

    if tool_id in ("fracture", "siphon"):
        target_url, err = _validate_url(body.get("target_url"), "target_url")
        if err:
            return jsonify({"error": err}), 400
    elif tool_id == "ss3":
        target_hosts, err = _validate_hosts(body.get("target_hosts"), "target_hosts")
        if err:
            return jsonify({"error": err}), 400

    # ── Optional auth ──────────────────────────────────────────
    auth_obj, err = _validate_auth_object(body.get("auth"))
    if err:
        return jsonify({"error": err}), 400

    # ── Optional fields ────────────────────────────────────────
    source, _ = _validate_string(body.get("source"), "source",
                                 max_len=64, required=False)
    source_project_id, _ = _validate_string(body.get("source_project_id"),
                                            "source_project_id",
                                            max_len=64, required=False)
    auto_start = bool(body.get("auto_start", False))
    year = body.get("year", "")
    if year:
        if not isinstance(year, (str, int)):
            return jsonify({"error": "year must be a string or integer"}), 400
        year = str(year).strip()
        if not re.match(r"^\d{4}$", year):
            return jsonify({"error": "year must be a 4-digit year"}), 400
    else:
        year = str(datetime.now().year)

    consultant_name, _ = _validate_string(body.get("consultant_name"),
                                          "consultant_name",
                                          pattern=_SAFE_NAME_RE,
                                          max_len=128, required=False)
    consultant_email, _ = _validate_string(body.get("consultant_email"),
                                           "consultant_email",
                                           max_len=256, required=False)

    # ── Check for running tool conflict ────────────────────────
    pm = _pm()
    if pm:
        all_projects = list_projects()
        for proj in all_projects:
            running = pm.running_tools(proj["id"])
            if tool_id in running:
                return jsonify({
                    "error": f"Tool '{tool_id}' is already running in project '{proj.get('name', proj['id'])}'"
                }), 409

    # ── Build scope definition ─────────────────────────────────
    scope_def = {
        "network_cidrs": target_hosts if tool_id == "ss3" else [],
        "target_urls": [target_url] if target_url and tool_id == "fracture" else [],
        "api_urls": [target_url] if target_url and tool_id == "siphon" else [],
        "wireless_ssids": [],
        "db_targets": [],
        "endpoint_targets": [],
        "exclusions": [],
    }

    # ── Inject auth into scope definition ──────────────────────
    if auth_obj and auth_obj.get("method", "none") != "none":
        if tool_id == "fracture":
            scope_def["fracture_auth"] = auth_obj
        elif tool_id == "siphon":
            scope_def["siphon_auth"] = auth_obj

    # ── Determine scope ────────────────────────────────────────
    native_scope = _TOOL_NATIVE_SCOPE.get(tool_id, "external")

    # ── Build form_data for create_project ─────────────────────
    engagement_name = f"{client_name} - {TOOLS[tool_id]['name']}"
    form_data = {
        "name": engagement_name,
        "client_name": client_name,
        "client_short": client_short,
        "scope": native_scope,
        "active_scopes": [native_scope],
        "tools": [tool_id],
        "scope_tools": {native_scope: [tool_id]},
        "scope_definition": scope_def,
        "consultant": {
            "name": consultant_name or "",
            "title": "",
            "email": consultant_email or "",
        },
        "client_poc": {"name": "", "phone": "", "email": ""},
        "start_date": datetime.now().strftime("%Y-%m-%d"),
        "end_date": "",
        "auto_queue": auto_start,
        "oos_handling": "explicit",
        "beacon_url": "",
        "beacon_token": "",
        "beacon_enabled": False,
    }

    # ── Thread-safe project creation ───────────────────────────
    with _create_lock:
        try:
            project_id, meta = create_project(form_data)
        except Exception as exc:
            log.exception("API v2: project creation failed")
            return jsonify({"error": f"Project creation failed: {exc}"}), 500

    project_dir = meta.get("project_dir", "")

    # ── Write tool-specific settings file ──────────────────────
    _write_api_tool_settings(project_id, tool_id, meta, body, auth_obj)

    # ── Auto-start if requested ────────────────────────────────
    launch_status = "created"
    if auto_start and pm:
        project = get_project(project_id)
        if project:
            settings = _load_tool_settings(project_dir, tool_id)
            try:
                launched = pm.launch(
                    project_id, tool_id,
                    project=project,
                    settings=settings,
                    scope=native_scope,
                )
                if launched:
                    launch_status = "running"
                    log.info("API v2: auto-started %s for project %s",
                             tool_id, project_id)
                else:
                    launch_status = "start_failed"
                    log.warning("API v2: auto-start returned False for %s/%s",
                                tool_id, project_id)
            except Exception as exc:
                launch_status = "start_failed"
                log.exception("API v2: auto-start failed for %s/%s",
                              tool_id, project_id)

    # ── Build response ─────────────────────────────────────────
    # Resolve the settings file path for reference
    prefix = TOOL_SETTINGS_PREFIX.get(tool_id, "")
    settings_path = ""
    if prefix and project_dir:
        settings_path = str(Path(project_dir) / f"{prefix}_settings.json")

    response = {
        "project_id": project_id,
        "status": launch_status,
        "tool": tool_id,
        "tool_name": TOOLS[tool_id]["name"],
        "yaml_path": settings_path,
        "project_dir": project_dir,
        "created_at": meta.get("created", datetime.now().isoformat()),
    }

    log.info("API v2: created project %s (tool=%s, client=%s, status=%s)",
             project_id, tool_id, client_short, launch_status)

    return jsonify(response), 201


def _write_api_tool_settings(project_id, tool_id, meta, body, auth_obj):
    """Write tool-specific settings from API request data.

    This supplements the defaults written by create_project by overlaying
    any API-specific fields (target URLs, auth, etc.).
    """
    project_dir = meta.get("project_dir", "")
    if not project_dir:
        return
    prefix = TOOL_SETTINGS_PREFIX.get(tool_id)
    if not prefix:
        return

    settings_file = Path(project_dir) / f"{prefix}_settings.json"
    settings = {}
    if settings_file.exists():
        try:
            settings = json.loads(settings_file.read_text())
        except (json.JSONDecodeError, OSError):
            pass

    # Overlay API-provided values
    if tool_id == "fracture":
        target_url = body.get("target_url", "")
        if target_url:
            settings.setdefault("scan", {})
            settings["scan"]["target_url"] = target_url
            settings["scan"]["target_urls"] = [target_url]
        if auth_obj and auth_obj.get("method", "none") != "none":
            settings.setdefault("scan", {})
            settings["scan"]["auth"] = auth_obj

    elif tool_id == "siphon":
        target_url = body.get("target_url", "")
        if target_url:
            settings.setdefault("scan", {})
            settings["scan"]["api_base_url"] = target_url
            settings["scan"]["api_base_urls"] = []
        if auth_obj and auth_obj.get("method", "none") != "none":
            settings.setdefault("scan", {})
            settings["scan"]["auth"] = auth_obj

    elif tool_id == "ss3":
        target_hosts = body.get("target_hosts", [])
        if target_hosts:
            settings.setdefault("scan", {})
            settings["scan"]["targets"] = target_hosts
            settings["targets"] = "\n".join(target_hosts)

    # Source tracking
    if body.get("source"):
        settings["_api_source"] = body["source"]
    if body.get("source_project_id"):
        settings["_api_source_project_id"] = body["source_project_id"]

    try:
        with open(settings_file, "w") as f:
            json.dump(settings, f, indent=2)
    except OSError as exc:
        log.error("API v2: failed to write settings for %s/%s: %s",
                  project_id, tool_id, exc)


def _load_tool_settings(project_dir, tool_id):
    """Load the tool settings JSON for a given tool in a project dir."""
    prefix = TOOL_SETTINGS_PREFIX.get(tool_id, "")
    if not prefix or not project_dir:
        return {}
    settings_file = Path(project_dir) / f"{prefix}_settings.json"
    if not settings_file.exists():
        return {}
    try:
        return json.loads(settings_file.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("API v2: failed to load settings %s: %s", settings_file, exc)
        return {}


# ── GET /api/v2/projects/<id>/status ────────────────────────────────────────

@api_v2.route("/projects/<project_id>/status", methods=["GET"])
@require_api_key
def project_status(project_id):
    """Return status, phase info, and finding counts for a project."""
    project = get_project(project_id)
    if not project:
        return jsonify({"error": "Project not found"}), 404

    pm = _pm()
    fe = _fe()

    # ── Tool status ────────────────────────────────────────────
    tool_id = None
    tools = project.get("tools", [])
    if tools:
        tool_id = tools[0]

    status = "idle"
    started_at = None
    ended_at = None
    error_message = None

    if pm and tool_id:
        all_status = pm.get_all_status(project_id)
        # Find matching status — may be scoped (e.g. fracture:webapp)
        tool_status_entry = all_status.get(tool_id, {})
        if not tool_status_entry:
            for key, entry in all_status.items():
                if key.startswith(f"{tool_id}:"):
                    tool_status_entry = entry
                    break
        status = tool_status_entry.get("status", "idle")
        started_at = tool_status_entry.get("started_at")
        ended_at = tool_status_entry.get("ended_at")

    # ── Phase info ─────────────────────────────────────────────
    phase = None
    phase_number = 0
    total_phases = 0
    progress_pct = 0

    if pm and tool_id:
        phase_cache = pm.get_phase_cache(project_id)
        tool_phases = phase_cache.get(tool_id, {})
        if not tool_phases:
            # Check scoped keys
            for key, phases in phase_cache.items():
                if key.startswith(f"{tool_id}:"):
                    tool_phases = phases
                    break

        if tool_phases:
            total_phases = len(tool_phases)
            completed = 0
            current_phase = None
            for pname, pdata in tool_phases.items():
                pstatus = pdata.get("status", "")
                if pstatus in ("complete", "skipped"):
                    completed += 1
                elif pstatus == "running":
                    current_phase = pname
                elif pstatus == "" and current_phase is None:
                    current_phase = pname

            phase_number = completed + (1 if current_phase else 0)
            phase = current_phase

            if total_phases > 0:
                progress_pct = round((completed / total_phases) * 100, 1)
                if status in ("complete", "halted", "killed"):
                    progress_pct = 100.0

    # ── Elapsed time ───────────────────────────────────────────
    elapsed_sec = 0
    if started_at:
        try:
            start_dt = datetime.fromisoformat(started_at)
            if ended_at and status in ("complete", "halted", "killed", "failed"):
                end_dt = datetime.fromisoformat(ended_at)
            else:
                end_dt = datetime.now()
            elapsed_sec = round((end_dt - start_dt).total_seconds(), 1)
        except (ValueError, TypeError):
            elapsed_sec = 0

    # ── Findings counts ────────────────────────────────────────
    findings_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    total_findings = 0

    if fe:
        try:
            summary = fe.get_full_summary(project_id, project)
            rc = summary.get("risk_counts", summary.get("risk_summary", {}))
            for risk in VALID_RISKS:
                findings_count[risk] = rc.get(risk, 0)
            total_findings = summary.get("findings_count", summary.get("total", 0))
        except Exception as exc:
            log.warning("API v2: findings count failed for %s: %s",
                        project_id, exc)

    # ── Error message (last error from console) ────────────────
    if pm and tool_id and status in ("failed", "killed", "halted"):
        try:
            all_st = pm.get_all_status(project_id)
            entry = all_st.get(tool_id, {})
            last_line = entry.get("last_line", "")
            if last_line:
                error_message = last_line
        except Exception:
            pass

    return jsonify({
        "project_id": project_id,
        "project_name": project.get("name", ""),
        "status": status,
        "tool": tool_id or "",
        "tool_name": TOOLS.get(tool_id, {}).get("name", tool_id or ""),
        "phase": phase,
        "phase_number": phase_number,
        "total_phases": total_phases,
        "progress_pct": progress_pct,
        "findings_count": findings_count,
        "total_findings": total_findings,
        "started_at": started_at,
        "ended_at": ended_at,
        "elapsed_sec": elapsed_sec,
        "error_message": error_message,
    }), 200


# ── GET /api/v2/projects/<id>/findings ──────────────────────────────────────

@api_v2.route("/projects/<project_id>/findings", methods=["GET"])
@require_api_key
def project_findings(project_id):
    """Return all findings in universal schema v1.1 format."""
    project = get_project(project_id)
    if not project:
        return jsonify({"error": "Project not found"}), 404

    tool_id = None
    tools = project.get("tools", [])
    if tools:
        tool_id = tools[0]

    fe = _fe()
    findings = []

    if fe:
        try:
            findings = fe.get_findings(project_id, project)
        except Exception as exc:
            log.exception("API v2: findings retrieval failed for %s", project_id)
            return jsonify({"error": "Failed to retrieve findings"}), 500

    # ── Optional query parameters for filtering ────────────────
    risk_filter = request.args.get("risk", "").upper()
    if risk_filter and risk_filter in VALID_RISKS:
        findings = [f for f in findings
                    if f.get("risk", "").upper() == risk_filter]

    tool_filter = request.args.get("tool", "").lower()
    if tool_filter:
        findings = [f for f in findings
                    if f.get("tool", "").lower() == tool_filter]

    limit = request.args.get("limit")
    offset = request.args.get("offset", "0")
    try:
        offset = max(0, int(offset))
    except (ValueError, TypeError):
        offset = 0

    total = len(findings)

    if limit is not None:
        try:
            limit = max(1, int(limit))
        except (ValueError, TypeError):
            limit = None

    if limit is not None:
        findings = findings[offset:offset + limit]
    elif offset > 0:
        findings = findings[offset:]

    return jsonify({
        "project_id": project_id,
        "tool": tool_id or "",
        "findings": findings,
        "total": total,
        "offset": offset,
        "limit": limit,
        "schema_version": "1.1",
    }), 200


# ── POST /api/v2/projects/<id>/stop ─────────────────────────────────────────

@api_v2.route("/projects/<project_id>/stop", methods=["POST"])
@require_api_key
def stop_project(project_id):
    """Stop a running project by killing the tool's subprocesses.

    Uses children_only=True so the tool can checkpoint and exit cleanly.
    Falls back to full kill if body includes force=true.
    """
    project = get_project(project_id)
    if not project:
        return jsonify({"error": "Project not found"}), 404

    pm = _pm()
    if not pm:
        return jsonify({"error": "Process manager not available"}), 503

    tools = project.get("tools", [])
    if not tools:
        return jsonify({"error": "No tools configured for this project"}), 409

    body = request.get_json(silent=True) or {}
    force = bool(body.get("force", False))

    stopped_tools = []
    not_running = []

    for tool_id in tools:
        running = pm.running_tools(project_id)
        # Check both bare and scoped keys
        is_running = False
        matched_key = tool_id
        for r in running:
            if r == tool_id or r.startswith(f"{tool_id}:"):
                is_running = True
                matched_key = r
                break

        if not is_running:
            not_running.append(tool_id)
            continue

        # Extract scope if present
        scope = None
        if ":" in matched_key:
            scope = matched_key.split(":", 1)[1]

        killed = pm.kill(
            project_id, tool_id,
            scope=scope,
            children_only=not force,
        )
        if killed:
            stopped_tools.append(tool_id)
            log.info("API v2: stopped %s in project %s (force=%s)",
                     tool_id, project_id, force)
        else:
            not_running.append(tool_id)

    if not stopped_tools:
        return jsonify({
            "error": "No running tools found to stop",
            "not_running": not_running,
        }), 409

    return jsonify({
        "project_id": project_id,
        "status": "stopping",
        "stopped_tools": stopped_tools,
        "not_running": not_running,
    }), 200


# ── GET /api/v2/tools ───────────────────────────────────────────────────────

@api_v2.route("/tools", methods=["GET"])
@require_api_key
def list_tools():
    """List all available tools with installation and running status."""
    pm = _pm()
    result = []

    # Collect all currently running tools across all projects
    running_set = set()
    if pm:
        for proj in list_projects():
            for t in pm.running_tools(proj["id"]):
                # Strip scope suffix
                base = t.split(":")[0] if ":" in t else t
                running_set.add(base)

    for tool_id in sorted(_LAUNCHABLE_TOOLS):
        tool_cfg = TOOLS.get(tool_id, {})
        installed = _is_tool_installed(tool_id)
        version = _get_tool_version(tool_id) if installed else None

        result.append({
            "id": tool_id,
            "name": tool_cfg.get("name", tool_id),
            "description": tool_cfg.get("desc", ""),
            "domain": tool_cfg.get("domain", ""),
            "installed": installed,
            "running": tool_id in running_set,
            "version": version,
        })

    return jsonify({"tools": result}), 200


# ── POST /api/v2/keys/generate ──────────────────────────────────────────────

@api_v2.route("/keys/generate", methods=["POST"])
def generate_api_key():
    """Generate a new API key. Requires an authenticated admin session."""
    auth_err = _require_session_auth()
    if auth_err:
        return auth_err

    body = request.get_json(silent=True) or {}
    label = body.get("label", "").strip()[:64] if isinstance(body.get("label"), str) else ""

    raw_key = secrets.token_urlsafe(48)
    key_hash = _hash_key(raw_key)

    with _settings_lock:
        settings = _load_settings()
        api_keys = settings.setdefault("api_keys", [])
        if not isinstance(api_keys, list):
            api_keys = []
            settings["api_keys"] = api_keys
        api_keys.append(key_hash)

        # Store key metadata (label, created_at) separately
        key_meta = settings.setdefault("api_key_meta", {})
        key_meta[key_hash] = {
            "label": label or "API Key",
            "created_at": datetime.now().isoformat(),
            "created_by": session.get("username", "unknown"),
        }

        _save_settings(settings)

    log.info("API v2: new key generated (label=%s) by %s",
             label, session.get("username", "unknown"))

    return jsonify({
        "key": raw_key,
        "key_hash": key_hash,
        "label": label or "API Key",
        "message": "Store this key securely — it cannot be retrieved after this response.",
    }), 201


# ── DELETE /api/v2/keys/<key_hash> ──────────────────────────────────────────

@api_v2.route("/keys/<key_hash>", methods=["DELETE"])
def revoke_api_key(key_hash):
    """Revoke an API key by its sha256 hash. Requires an authenticated admin session."""
    auth_err = _require_session_auth()
    if auth_err:
        return auth_err

    if not key_hash or not re.match(r"^[a-f0-9]{64}$", key_hash):
        return jsonify({"error": "Invalid key hash format"}), 400

    with _settings_lock:
        settings = _load_settings()
        api_keys = settings.get("api_keys", [])
        if not isinstance(api_keys, list):
            return jsonify({"error": "No API keys configured"}), 404

        if key_hash not in api_keys:
            return jsonify({"error": "API key not found"}), 404

        api_keys.remove(key_hash)
        settings["api_keys"] = api_keys

        key_meta = settings.get("api_key_meta", {})
        key_meta.pop(key_hash, None)

        _save_settings(settings)

    log.info("API v2: key revoked (hash=%s…) by %s",
             key_hash[:12], session.get("username", "unknown"))

    return jsonify({"message": "API key revoked", "key_hash": key_hash}), 200


# ── GET /api/v2/keys (list keys — session auth) ────────────────────────────

@api_v2.route("/keys", methods=["GET"])
def list_api_keys():
    """List all API key hashes and their metadata. Requires admin session."""
    auth_err = _require_session_auth()
    if auth_err:
        return auth_err

    with _settings_lock:
        settings = _load_settings()

    api_keys = settings.get("api_keys", [])
    key_meta = settings.get("api_key_meta", {})

    result = []
    for kh in api_keys:
        meta = key_meta.get(kh, {})
        result.append({
            "key_hash": kh,
            "label": meta.get("label", ""),
            "created_at": meta.get("created_at", ""),
            "created_by": meta.get("created_by", ""),
        })

    return jsonify({"keys": result}), 200


# ── GET /api/v2/projects (list projects — API key auth) ────────────────────

@api_v2.route("/projects", methods=["GET"])
@require_api_key
def list_projects_endpoint():
    """List all projects with basic metadata."""
    projects = list_projects()
    pm = _pm()

    result = []
    for proj in projects:
        pid = proj.get("id", "")
        tools = proj.get("tools", [])
        status = "idle"

        if pm and tools:
            running = pm.running_tools(pid)
            for t in tools:
                if t in running or any(r.startswith(f"{t}:") for r in running):
                    status = "running"
                    break

        result.append({
            "project_id": pid,
            "name": proj.get("name", ""),
            "client_name": proj.get("client_name", ""),
            "client_short": proj.get("client_short", ""),
            "tools": tools,
            "status": status,
            "created_at": proj.get("created", ""),
            "active_scopes": proj.get("active_scopes", []),
        })

    return jsonify({"projects": result}), 200


# ── GET /api/v2/projects/<id>/summary ───────────────────────────────────────

@api_v2.route("/projects/<project_id>/summary", methods=["GET"])
@require_api_key
def project_summary(project_id):
    """Return the full findings summary (risk counts, tool breakdown, etc.)."""
    project = get_project(project_id)
    if not project:
        return jsonify({"error": "Project not found"}), 404

    fe = _fe()
    if not fe:
        return jsonify({"error": "Findings engine not available"}), 503

    try:
        summary = fe.get_full_summary(project_id, project)
    except Exception as exc:
        log.exception("API v2: summary failed for %s", project_id)
        return jsonify({"error": "Failed to generate summary"}), 500

    return jsonify({
        "project_id": project_id,
        "risk_counts": summary.get("risk_counts", {}),
        "tool_breakdown": summary.get("tool_breakdown", {}),
        "findings_count": summary.get("findings_count", 0),
        "total": summary.get("total", 0),
        "accepted_count": summary.get("accepted_count", 0),
        "fp_count": summary.get("fp_count", 0),
    }), 200


# ── Health check (no auth required) ────────────────────────────────────────

@api_v2.route("/health", methods=["GET"])
def health_check():
    """Simple health check endpoint. No auth required."""
    return jsonify({
        "status": "ok",
        "version": VERSION,
        "timestamp": datetime.now().isoformat(),
    }), 200
