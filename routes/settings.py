"""Settings API routes — tool settings, test connection, AuthProbe, wireless."""

import json
import logging
import os
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

log = logging.getLogger("crucible.routes.settings")

from flask import Blueprint, request, jsonify, current_app

from config import TOOLS, TOOL_DIR, PYTHON3
from models.settings import load_settings, save_settings, get_settings_schema, validate_settings
from routes._helpers import require_project

settings_bp = Blueprint("settings", __name__)


_OSIFT_KEY_MAP = {
    "shodan_api_key": "shodan_key",
    "censys_api_id": "censys_id",
    "censys_api_secret": "censys_secret",
    "virustotal_api_key": "virustotal_key",
    "securitytrails_api_key": "securitytrails_key",
    "hunter_api_key": "hunter_key",
    "dehashed_api_key": "dehashed_key",
    "urlscan_api_key": "urlscan_key",
    "netlas_api_key": "netlas_key",
    "intelx_api_key": "intelx_key",
    "binaryedge_api_key": "binaryedge_key",
    "onyphe_api_key": "onyphe_key",
    "c99_api_key": "c99_key",
    "zoomeye_api_key": "zoomeye_key",
    "fofa_api_key": "fofa_key",
    "builtwith_api_key": "builtwith_key",
    "passivetotal_api_key": "passivetotal_key",
    "whoisxml_api_key": "whoisxml_key",
    "fullcontact_api_key": "fullcontact_key",
    "clearbit_api_key": "clearbit_key",
}

_osift_global_cache = None


def _backfill_osift_api_keys(settings):
    """Pre-populate empty API key fields from OSift's global settings file."""
    global _osift_global_cache
    if _osift_global_cache is None:
        _osift_global_cache = {}
        gp = Path(TOOL_DIR) / "OSift" / "osift_settings.json"
        if gp.exists():
            try:
                raw = json.loads(gp.read_text())
                if isinstance(raw, dict):
                    for section in raw.values():
                        if isinstance(section, dict):
                            _osift_global_cache.update(section)
                        elif isinstance(raw.get("shodan_key"), str):
                            _osift_global_cache = raw
                            break
            except (json.JSONDecodeError, OSError) as exc:
                log.debug("osift global settings read failed: %s", exc)
    for crucible_key, osift_key in _OSIFT_KEY_MAP.items():
        if not settings.get(crucible_key):
            val = _osift_global_cache.get(osift_key, "")
            if val:
                settings[crucible_key] = val


def _backfill_from_project(settings, project, tool_id):
    """Populate empty flat UI keys from the project's scope_definition."""
    scope_def = project.get("scope_definition", {})
    scope = project.get("scope", "external")
    meta_name = project.get("name", "")
    meta_client = project.get("client_name", "")
    if tool_id == "ss3":
        if not settings.get("targets"):
            cidrs = scope_def.get("network_cidrs", [])
            if cidrs:
                settings["targets"] = "\n".join(cidrs)
        if not settings.get("engagement_name") and meta_name:
            settings["engagement_name"] = meta_name
        if not settings.get("client") and meta_client:
            settings["client"] = meta_client
        if not settings.get("client_name") and meta_client:
            settings["client_name"] = meta_client
        if not settings.get("client_short"):
            settings["client_short"] = project.get("client_short", "")
        if not settings.get("consultant"):
            con = project.get("consultant") or {}
            settings["consultant"] = con.get("name", "") if isinstance(con, dict) else str(con)
        if not settings.get("consultant_email"):
            con = project.get("consultant") or {}
            settings["consultant_email"] = con.get("email", "") if isinstance(con, dict) else ""
        if not settings.get("start_date"):
            settings["start_date"] = project.get("start_date", "")
        if not settings.get("end_date"):
            settings["end_date"] = project.get("end_date", "")
        from adapters import get_adapter as _ga
        _ss3_defaults = (_ga("ss3").default_settings() if _ga("ss3") else {})
        _dmr = scope_def.get("ss3_discovery_min_rate", 0)
        if _dmr and settings.get("discovery_min_rate") == _ss3_defaults.get("discovery_min_rate"):
            settings["discovery_min_rate"] = _dmr
        _dmp = scope_def.get("ss3_discovery_min_parallelism", 0)
        if _dmp and settings.get("discovery_min_parallelism") == _ss3_defaults.get("discovery_min_parallelism"):
            settings["discovery_min_parallelism"] = _dmp
        _tt = scope_def.get("ss3_timing_template", "")
        if _tt and settings.get("timing_template") == _ss3_defaults.get("timing_template"):
            settings["timing_template"] = _tt
        _psd = scope_def.get("ss3_passive_seed_duration", 0)
        if _psd and settings.get("passive_seed_duration") == _ss3_defaults.get("passive_seed_duration"):
            settings["passive_seed_duration"] = _psd
        if settings.get("scope_type") == "internal" and scope in ("external", "multi"):
            settings["scope_type"] = scope if scope != "multi" else "external_and_internal"
    elif tool_id == "osift":
        if not settings.get("target_domains"):
            domains = scope_def.get("domains", [])
            if domains:
                settings["target_domains"] = "\n".join(domains)
        _backfill_osift_api_keys(settings)
    elif tool_id == "fracture":
        if not settings.get("target_url"):
            urls = scope_def.get("target_urls", [])
            if urls:
                settings["target_url"] = urls[0]
    elif tool_id == "siphon":
        if not settings.get("api_base_url"):
            api_urls = scope_def.get("api_urls", [])
            if api_urls:
                settings["api_base_url"] = api_urls[0]
                settings["api_base_urls"] = api_urls[1:]
    elif tool_id == "dredge":
        mode = scope_def.get("dredge_mode", "import")
        if mode == "winrm":
            if not settings.get("winrm_host"):
                settings["winrm_host"] = scope_def.get("dredge_winrm_host", "")
            if not settings.get("winrm_user"):
                settings["winrm_user"] = scope_def.get("dredge_winrm_user", "")
            if not settings.get("winrm_pass"):
                settings["winrm_pass"] = scope_def.get("dredge_winrm_pass", "")
            if not settings.get("winrm_port") or settings["winrm_port"] == 5985:
                settings["winrm_port"] = scope_def.get("dredge_winrm_port", 5985)
            if not settings.get("winrm_ssl"):
                settings["winrm_ssl"] = scope_def.get("dredge_winrm_ssl", False)
        else:
            if not settings.get("collection_path"):
                settings["collection_path"] = scope_def.get("dredge_collection_path",
                    scope_def.get("dredge_collection_file", ""))
        if not settings.get("vt_api_key"):
            settings["vt_api_key"] = scope_def.get("dredge_vt_key", "")
        if not settings.get("abuseipdb_key"):
            settings["abuseipdb_key"] = scope_def.get("dredge_abuseipdb_key", "")


def _archive_tool_output(project, tool_id):
    """Move existing tool output to an archive subfolder."""
    import shutil
    td = project.get("tool_dirs", {}).get(tool_id)
    if not td:
        return
    td_path = Path(td)
    if not td_path.exists() or not any(td_path.iterdir()):
        return
    archive_dir = td_path.parent / f"{td_path.name}_archived_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    shutil.move(str(td_path), str(archive_dir))
    td_path.mkdir(parents=True, exist_ok=True)


def _queue_rescan(project_id, project, tool_id):
    """Queue a re-scan for the tool via the queue manager."""
    try:
        qm = current_app.extensions.get("queue_manager")
        if qm:
            qm.enqueue(project_id, tool_id, project)
    except Exception as exc:
        log.warning("queue rescan failed: %s", exc)


@settings_bp.route("/api/settings/<project_id>/<tool_id>", methods=["GET", "POST"])
def api_settings(project_id, tool_id):
    project = require_project(project_id)
    proj_dir = project.get("project_dir", "")
    if not proj_dir:
        return jsonify({"error": "No project directory"}), 400

    if request.method == "GET":
        settings = load_settings(proj_dir, tool_id)
        _backfill_from_project(settings, project, tool_id)
        schema = get_settings_schema(tool_id)
        from adapters import get_adapter
        adapter = get_adapter(tool_id)
        is_ext = getattr(adapter, "is_external", False) if adapter else False
        return jsonify({"settings": settings, "schema": schema,
                        "is_external": is_ext})

    # POST — save settings
    data = request.get_json(silent=True) or {}
    archive = data.pop("__archive_and_rescan", False)
    errors = validate_settings(tool_id, data)
    if errors:
        return jsonify({"error": "Validation failed", "errors": errors}), 400

    if archive:
        _archive_tool_output(project, tool_id)

    save_settings(proj_dir, tool_id, data)

    if archive:
        _queue_rescan(project_id, project, tool_id)

    return jsonify({"ok": True, "archived": archive})


@settings_bp.route("/api/upload_tool_file", methods=["POST"])
def api_upload_tool_file():
    """Upload a file for a tool into the project's tool output directory."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400
    project_id = request.form.get("project_id", "")
    tool_id = request.form.get("tool_id", "")
    if not project_id or not tool_id:
        return jsonify({"error": "project_id and tool_id required"}), 400
    project = require_project(project_id)
    td = project.get("tool_dirs", {}).get(tool_id)
    if not td:
        return jsonify({"error": "No output directory for tool"}), 400
    td_path = Path(td)
    td_path.mkdir(parents=True, exist_ok=True)
    safe_name = Path(f.filename).name
    if ".." in safe_name or "/" in safe_name or "\\" in safe_name:
        return jsonify({"error": "Invalid filename"}), 400
    _ALLOWED_UPLOAD_EXT = {
        ".json", ".csv", ".xml", ".txt", ".nessus", ".html", ".log",
        ".yaml", ".yml", ".md", ".conf", ".cfg", ".ini", ".nmap",
        ".gnmap", ".pcap", ".cap",
    }
    ext = Path(safe_name).suffix.lower()
    if ext not in _ALLOWED_UPLOAD_EXT:
        return jsonify({"error": f"File type not allowed: {ext}"}), 400
    dest = td_path / safe_name
    f.save(str(dest))
    return jsonify({"ok": True, "filename": safe_name})


@settings_bp.route("/api/upload_spec_temp", methods=["POST"])
def api_upload_spec():
    """Stage an API spec file (OpenAPI/Swagger) to a temp location."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400
    # Validate extension
    allowed = {".json", ".yaml", ".yml"}
    ext = Path(f.filename).suffix.lower()
    if ext not in allowed:
        return jsonify({"error": f"Invalid file type: {ext}"}), 400
    # Save to temp
    fd, tmp_path = tempfile.mkstemp(suffix=ext, prefix="crucible_spec_")
    os.close(fd)
    f.save(tmp_path)
    import hashlib
    ref_id = hashlib.sha256(tmp_path.encode()).hexdigest()[:16]
    current_app.config.setdefault("_SPEC_TEMP_MAP", {})[ref_id] = tmp_path
    return jsonify({"ok": True, "ref": ref_id, "filename": f.filename})


@settings_bp.route("/api/test-connection/<tool_id>", methods=["POST"])
def api_test_connection(tool_id):
    """Run the tool's testConnection.py with full auth config via --json."""
    from adapters import get_adapter
    adapter = get_adapter(tool_id)
    if not adapter or not adapter.supports_test_connection():
        return jsonify({"error": "Tool does not support test connection"}), 400

    data = request.get_json(silent=True) or {}
    target = data.get("target", "")
    if not target:
        return jsonify({"error": "Target URL required"}), 400

    script = adapter.test_connection_script()
    if not script or not Path(script).exists():
        return jsonify({"error": "Test connection script not found"}), 500

    auth_in = data.get("auth") or {}
    _AUTH_FIELD_MAP = {
        "username": "username", "password": "password", "domain": "domain",
        "token": "token", "auth_token": "token",
        "token_type": "token_type", "session_cookie": "session_cookie",
        "login_url": "login_url", "login_data": "login_data",
        "login_content_type": "login_content_type",
        "login_username_field": "login_username_field",
        "login_password_field": "login_password_field",
        "login_mode": "login_mode", "login_method": "login_mode",
        "login_token_path": "login_token_path",
        "oauth_token_url": "oauth_token_url",
        "oauth_client_id": "oauth_client_id",
        "oauth_client_secret": "oauth_client_secret",
        "oauth_scope": "oauth_scope",
        "oauth_client_auth": "oauth_client_auth",
        "oauth1_consumer_key": "oauth1_consumer_key",
        "oauth1_consumer_secret": "oauth1_consumer_secret",
        "oauth1_token": "oauth1_access_token",
        "oauth1_token_secret": "oauth1_token_secret",
        "saml_assertion": "saml_assertion",
        "saml_token_url": "saml_acs_url", "saml_acs_url": "saml_acs_url",
        "saml_relay_state": "saml_relay_state",
        "oidc_id_token": "oidc_id_token",
        "oidc_issuer": "oidc_userinfo_url", "oidc_userinfo_url": "oidc_userinfo_url",
        "mtls_cert": "mtls_cert", "client_cert": "mtls_cert",
        "mtls_key": "mtls_key", "client_key": "mtls_key",
        "mtls_ca_bundle": "mtls_ca_bundle",
        "totp_secret": "totp_secret", "totp_field": "totp_field",
        "totp_mfa_url": "totp_mfa_url",
        "api_key": "api_key", "api_key_header": "api_key_header",
        "api_key_name": "api_key_header",
        "api_key_cookie_name": "api_key_cookie",
        "proxy_header_name": "proxy_header_name",
        "proxy_header_value": "proxy_header_value",
        "cookie_name": "session_cookie", "cookie_value": "session_cookie",
        "kerberos_realm": "kerberos_impersonate",
    }
    auth_obj = {}
    method = auth_in.get("method") or auth_in.get("auth_method", "")
    if method:
        auth_obj["method"] = method
    for src_key, dst_key in _AUTH_FIELD_MAP.items():
        val = auth_in.get(src_key, "")
        if val and dst_key not in auth_obj:
            auth_obj[dst_key] = val

    tc_config = {"url": target, "auth": auth_obj}
    if data.get("proxy"):
        tc_config["proxy"] = data["proxy"]
    if data.get("timeout"):
        tc_config["timeout"] = data["timeout"]
    if data.get("no_verify") or not data.get("verify_ssl", True):
        tc_config["no_verify"] = True
    if data.get("probe"):
        tc_config["probe"] = True

    cmd = [PYTHON3, script, "--json", json.dumps(tc_config), "--output-json"]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=45,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
        parsed = None
        if result.stdout.strip():
            try:
                parsed = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                log.debug("test-connection stdout not JSON: %s", exc)
        return jsonify({
            "ok": result.returncode == 0,
            "result": parsed,
            "stdout": result.stdout if not parsed else "",
            "stderr": result.stderr,
            "exit_code": result.returncode,
        })
    except subprocess.TimeoutExpired:
        return jsonify({"ok": False, "error": "Connection test timed out"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@settings_bp.route("/api/fingerprint-auth", methods=["POST"])
def api_fingerprint_auth():
    """Launch fingerprint_auth.py to record an auth flow via MITM browser."""
    data = request.get_json(silent=True) or {}
    target = data.get("target", "")
    if not target:
        return jsonify({"error": "Target URL required"}), 400

    output_dir = data.get("output_dir", "")
    if not output_dir:
        output_dir = str(Path(tempfile.mkdtemp(prefix="fp_auth_out_")))

    script = str(TOOL_DIR / "Fracture" / "fingerprint_auth.py")
    if not Path(script).exists():
        return jsonify({"ok": False, "error": "fingerprint_auth.py not found"}), 500

    cmd = [
        PYTHON3, script,
        "--target-url", target,
        "--output-dir", output_dir,
        "--no-control-page",
    ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
        fp_path = Path(output_dir) / "auth_fingerprint.json"
        fingerprint = None
        if fp_path.exists():
            try:
                fingerprint = json.loads(fp_path.read_text())
            except Exception as exc:
                log.warning("fingerprint JSON parse failed: %s", exc)
        return jsonify({
            "ok": result.returncode == 0 and fingerprint is not None,
            "fingerprint": fingerprint,
            "stdout": result.stdout[-2000:] if result.stdout else "",
            "stderr": result.stderr[-1000:] if result.stderr else "",
            "output_dir": output_dir,
        })
    except subprocess.TimeoutExpired:
        return jsonify({"ok": False, "error": "Fingerprint recording timed out (5m)"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@settings_bp.route("/api/authprobe", methods=["POST"])
def api_authprobe():
    """Run AuthProbe against a target URL with full CLI options."""
    data = request.get_json(silent=True) or {}
    target = data.get("target", "")
    if not target:
        return jsonify({"error": "Target URL required"}), 400

    script = TOOLS.get("authprobe", {}).get("script")
    if not script or not Path(script).exists():
        return jsonify({"error": "AuthProbe not found"}), 500

    cmd = [PYTHON3, str(script), "--url", target, "--json"]

    _STR_FLAGS = {
        "type": "--type", "username": "--username", "password": "--password",
        "token": "--token", "api_key": "--api-key",
        "api_key_header": "--api-key-header", "api_key_cookie": "--api-key-cookie",
        "login_url": "--login-url", "totp_secret": "--totp-secret",
        "proxy": "--proxy", "output_dir": "--output-dir",
        "client_short": "--client-short", "client_name": "--client-name",
        "engagement_name": "--engagement-name", "driver_path": "--driver-path",
    }
    for key, flag in _STR_FLAGS.items():
        val = data.get(key, "")
        if val:
            cmd.extend([flag, str(val)])

    timeout_val = data.get("timeout")
    if timeout_val:
        cmd.extend(["--timeout", str(int(timeout_val))])

    if data.get("rendered"):
        cmd.append("--rendered")
    if data.get("no_verify"):
        cmd.append("--no-verify")

    run_timeout = max(int(data.get("timeout", 60)), 60) + 30

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=run_timeout,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
        output = result.stdout
        try:
            parsed = json.loads(output)
        except json.JSONDecodeError:
            parsed = {"raw": output}
        return jsonify({
            "ok": result.returncode == 0,
            "result": parsed,
            "stderr": result.stderr,
        })
    except subprocess.TimeoutExpired:
        return jsonify({"ok": False, "error": "AuthProbe timed out"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@settings_bp.route("/api/wifi-interfaces")
def api_wifi_interfaces():
    """List wireless network interfaces."""
    from services.wireless import get_wifi_interfaces, get_interface_info
    ifaces = get_wifi_interfaces()
    interfaces = [get_interface_info(i) for i in ifaces]
    return jsonify({"interfaces": interfaces})


@settings_bp.route("/api/wifi-scan")
def api_wifi_scan():
    """Scan visible SSIDs using iwlist or airport."""
    from services.wireless import scan_ssids
    interface = request.args.get("interface")
    networks = scan_ssids(interface)
    return jsonify({"networks": networks})


@settings_bp.route("/api/wifi/fix", methods=["GET", "POST"])
def api_wifi_fix():
    """Fix wireless interface issues (Linux only)."""
    import platform as _plat
    if _plat.system() != "Linux":
        return jsonify({"error": "Only available on Linux"}), 400

    if request.method == "GET":
        return jsonify({"message": "POST to fix wireless interfaces"})

    from services.wireless import fix_interface
    data = request.get_json(silent=True) or {}
    interface = data.get("interface", "wlan0")
    ok, message = fix_interface(interface)
    return jsonify({"ok": ok, "message": message})


@settings_bp.route("/api/beacon/test", methods=["POST"])
def api_beacon_test():
    """Test connectivity to a Beacon status server."""
    import requests as _req
    import urllib3 as _u3
    _u3.disable_warnings(_u3.exceptions.InsecureRequestWarning)

    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip().rstrip("/")
    token = data.get("token", "")
    if not url or not token:
        return jsonify({"ok": False, "error": "URL and token are required"}), 400
    try:
        r = _req.post(
            f"{url}/api/ping",
            json={},
            headers={"Authorization": f"Bearer {token}"},
            verify=False,
            timeout=8,
        )
        if r.status_code == 200:
            return jsonify({"ok": True})
        elif r.status_code == 401:
            return jsonify({"ok": False, "error": "Authentication failed"})
        else:
            return jsonify({"ok": False, "error": f"HTTP {r.status_code}"})
    except _req.exceptions.ConnectionError:
        return jsonify({"ok": False, "error": "Connection refused"})
    except _req.exceptions.Timeout:
        return jsonify({"ok": False, "error": "Connection timed out"})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)})
