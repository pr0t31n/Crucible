"""Nessus API routes — configuration, scan management, import/export."""

import datetime
import ipaddress
import json
import logging
import os
import re
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from flask import Blueprint, request, jsonify, send_file, abort, make_response
from werkzeug.utils import secure_filename

from config import NESSUS_DEFAULT_PORT
from models.project import get_tool_output_dir
from routes._helpers import require_project, get_ext

nessus_bp = Blueprint("nessus", __name__)
log = logging.getLogger("crucible.routes.nessus")

# ── Nessus → native title normalization ───────────────────────
# Maps Nessus pluginName titles to the canonical pr0t31n format
# so imported findings merge and render consistently.
_NESSUS_TITLE_MAP = {
    "HSTS Missing From HTTPS Server (RFC 6797)":
        "Missing Security Header: Strict-Transport-Security",
    "HSTS Missing From HTTPS Server":
        "Missing Security Header: Strict-Transport-Security",
    "HTTP Strict Transport Security (HSTS) Not Enforced":
        "Missing Security Header: Strict-Transport-Security",
    "Web Application Potentially Vulnerable to Clickjacking":
        "Missing Security Header: X-Frame-Options",
    "Missing X-Frame-Options Header":
        "Missing Security Header: X-Frame-Options",
    "X-Content-Type-Options Header Missing":
        "Missing Security Header: X-Content-Type-Options",
    "Missing Content-Security-Policy Header":
        "Missing Security Header: Content-Security-Policy",
    "Missing or Permissive X-Frame-Options HTTP Response Header":
        "Missing Security Header: X-Frame-Options",
    "SSL Certificate Cannot Be Trusted":
        "SSL/TLS Certificate: Untrusted",
    "SSL Self-Signed Certificate":
        "SSL/TLS Certificate: Self-Signed",
    "SSL Certificate Expiry":
        "SSL/TLS Certificate: Expired",
    "SSL Certificate with Wrong Hostname":
        "SSL/TLS Certificate: Hostname Mismatch",
    "SSL Medium Strength Cipher Suites Supported (SWEET32)":
        "SSL/TLS Vulnerability: SWEET32",
    "SSL/TLS Diffie-Hellman Modulus <= 1024 Bits (Logjam)":
        "SSL/TLS Vulnerability: LOGJAM",
    "SSL DROWN Attack Vulnerability (Decrypting RSA with Obsolete and Weakened eNcryption)":
        "SSL/TLS Vulnerability: DROWN",
    "SSL Version 2 and 3 Protocol Detection":
        "Deprecated Protocol Enabled: SSLv2/SSLv3",
    "TLS Version 1.0 Protocol Detection":
        "Deprecated Protocol Enabled: TLSv1.0",
    "TLS Version 1.1 Protocol Deprecated":
        "Deprecated Protocol Enabled: TLSv1.1",
    "TLS Version 1.1 Protocol Detection":
        "Deprecated Protocol Enabled: TLSv1.1",
    "SSL RC4 Cipher Suites Supported (Bar Mitzvah)":
        "SSL/TLS Ciphers: Obsolete Cipher — RC4",
    "SSL Weak Cipher Suites Supported":
        "SSL/TLS Ciphers: Weak Cipher Suites",
    "SSL Certificate Chain Contains RSA Keys Less Than 2048 bits":
        "SSL/TLS Certificate: Short Key Length",
    "SSL Certificate Signed Using Weak Hashing Algorithm":
        "SSL/TLS Certificate: Weak Signature Algorithm",
    "Web Server HTTP Header Internal IP Disclosure":
        "Information Disclosure: Internal IP in HTTP Response",
    # ── LDAP ──
    "LDAP Server Detection":
        "Discovery: LDAP Service",
    "LDAP NULL BASE Search Access":
        "LDAP: Anonymous Bind",
    "Microsoft Windows LDAP Signing Not Required":
        "LDAP: Signing Not Required",
    "LDAP Server Allows Cleartext Authentication":
        "LDAP: Cleartext Authentication Permitted",
    # ── RPC ──
    "RPC portmapper (TCP)":
        "RPC: Portmapper Exposed",
    "DCE Services Enumeration":
        "RPC: DCE Services Enumeration",
    "Microsoft Windows SMB : DCE-RPC Services Enumerable":
        "RPC: DCE Services Enumeration",
    # ── NTP ──
    "NTP Server Detection":
        "Discovery: NTP Service",
    "NTP monlist Command Enabled":
        "NTP: Monlist Amplification (CVE-2013-5211)",
    "NTP Mode 6 Queries Enabled":
        "NTP: Mode 6 Queries Enabled",
}
_NESSUS_TITLE_MAP_LOWER = {k.lower(): v for k, v in _NESSUS_TITLE_MAP.items()}


def _normalize_nessus_title(title):
    mapped = _NESSUS_TITLE_MAP_LOWER.get((title or "").strip().lower())
    return mapped if mapped else title


def _nessus_dir(project_id, scope=None):
    d = get_tool_output_dir(project_id, "nessus", scope=scope)
    if d:
        Path(d).mkdir(parents=True, exist_ok=True)
        return d
    from models.project import get_project
    proj = get_project(project_id)
    if proj:
        proj_dir = proj.get("project_dir", "")
        if proj_dir:
            ne = Path(proj_dir) / "nessus"
            ne.mkdir(parents=True, exist_ok=True)
            return str(ne)
    return None


def _nessus_scope(project_id):
    """Determine which scope Nessus belongs to (network-targeted → external/internal)."""
    from models.project import get_project
    proj = get_project(project_id)
    if not proj:
        return "external"
    active = proj.get("active_scopes", [])
    scope_tools = proj.get("scope_tools", {})
    for scope in ("external", "internal"):
        if scope in active:
            tools = scope_tools.get(scope, [])
            if "nessus" in tools or "ss3" in tools:
                return scope
    if "external" in active:
        return "external"
    return active[0] if active else "external"


def _register_nessus_tool(project_id, nessus_dir):
    """Register nessus in project tool_dirs/scope_tool_dirs so findings persist across refreshes."""
    from models.project import get_project, update_project
    proj = get_project(project_id)
    if not proj:
        return
    ndir = str(nessus_dir)
    tool_dirs = dict(proj.get("tool_dirs", {}))
    scope_tool_dirs = dict(proj.get("scope_tool_dirs", {}))
    tools = list(proj.get("tools", []))

    if tool_dirs.get("nessus") == ndir and "nessus" in tools:
        return

    tool_dirs["nessus"] = ndir
    if "nessus" not in tools:
        tools.append("nessus")

    scope = _nessus_scope(project_id)
    if scope in scope_tool_dirs:
        scope_tool_dirs[scope] = dict(scope_tool_dirs[scope])
        scope_tool_dirs[scope]["nessus"] = ndir
    else:
        scope_tool_dirs[scope] = {"nessus": ndir}

    update_project(project_id, {
        "tool_dirs": tool_dirs,
        "scope_tool_dirs": scope_tool_dirs,
        "tools": tools,
    })


def _load_config(project):
    proj_dir = project.get("project_dir", "")
    cfg_file = Path(proj_dir) / "nessus_settings.json"
    if cfg_file.exists():
        with open(cfg_file) as f:
            return json.load(f)
    return {
        "host": "", "port": NESSUS_DEFAULT_PORT,
        "access_key": "", "secret_key": "",
        "verify_ssl": False,
    }


def _make_client(cfg):
    from services.nessus_client import NessusClient
    host = cfg.get("host", "")
    if not host:
        return None
    return NessusClient(
        host=host,
        port=cfg.get("port", NESSUS_DEFAULT_PORT),
        access_key=cfg.get("access_key", ""),
        secret_key=cfg.get("secret_key", ""),
        verify_ssl=cfg.get("verify_ssl", False),
    )


def _require_nessus_client(project_id):
    """Return (project, cfg, client), aborting on missing project or unconfigured Nessus."""
    project = require_project(project_id)
    cfg = _load_config(project)
    client = _make_client(cfg)
    if not client:
        abort(make_response(jsonify({"error": "Nessus not configured"}), 400))
    return project, cfg, client


# ── Scope helpers ──────────────


def _extract_hosts_from_xml(nessus_file):
    """Extract all unique host IPs from a .nessus XML file."""
    hosts = set()
    try:
        tree = ET.parse(str(nessus_file))
        root = tree.getroot()
        for host in root.iter("ReportHost"):
            ip = host.get("name", "")
            for tag in host.iter("tag"):
                if tag.get("name") == "host-ip" and tag.text:
                    ip = tag.text.strip()
                    break
            if ip:
                hosts.add(ip)
    except Exception:
        pass
    return hosts


def _get_scope_ips(project_id):
    """Return the set of in-scope IP strings for a project."""
    from models.project import get_project
    proj = get_project(project_id)
    if not proj:
        return set()

    scope_ips = set()
    scope_def = proj.get("scope_definition", {})

    for cidr in scope_def.get("network_cidrs", []):
        if not cidr:
            continue
        try:
            for addr in ipaddress.ip_network(cidr, strict=False):
                scope_ips.add(str(addr))
        except ValueError:
            scope_ips.add(cidr.strip())

    return scope_ips


def _parse_nessus_xml(nessus_file, ne_dir, project_id):
    """Parse .nessus XML and write findings.json. Returns findings list."""
    RISK_MAP = {"4": "CRITICAL", "3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
    scope = _nessus_scope(project_id)

    from models.project import get_project
    _proj = get_project(project_id)
    _excluded_ips = set((_proj or {}).get("scope_definition", {}).get("exclusions", []))

    findings = []
    try:
        tree = ET.parse(str(nessus_file))
        root = tree.getroot()
        for host in root.iter("ReportHost"):
            ip = host.get("name", "")
            for tag in host.iter("tag"):
                if tag.get("name") == "host-ip" and tag.text:
                    ip = tag.text.strip()
                    break
            if ip in _excluded_ips:
                continue
            hostname = ""
            for tag in host.iter("tag"):
                if tag.get("name") == "host-fqdn" and tag.text:
                    hostname = tag.text.strip()
                    break

            for item in host.iter("ReportItem"):
                sev = item.get("severity", "0")
                if sev == "0":
                    continue
                risk = RISK_MAP.get(sev, "INFO")
                port = int(item.get("port", "0"))
                plugin_id = item.get("pluginID", "")
                title = _normalize_nessus_title(item.get("pluginName", "Unknown"))
                desc = (item.findtext("description") or "").strip()
                solution = (item.findtext("solution") or "").strip()
                output = (item.findtext("plugin_output") or "").strip()
                synopsis = (item.findtext("synopsis") or "").strip()
                service = item.get("svc_name", "")
                protocol = item.get("protocol", "tcp")

                cves = []
                for cve_el in item.iter("cve"):
                    if cve_el.text:
                        cves.append(cve_el.text.strip())

                cvss_score = None
                cvss_vec = ""
                for tag_name in ("cvss3_base_score", "cvss_base_score"):
                    val = item.findtext(tag_name)
                    if val:
                        try:
                            cvss_score = float(val)
                        except ValueError:
                            pass
                        break
                for tag_name in ("cvss3_vector", "cvss_vector"):
                    val = item.findtext(tag_name)
                    if val:
                        cvss_vec = val
                        break

                _has_exploit = (item.findtext("exploit_available") or "").lower() == "true"
                _has_msf = (item.findtext("exploit_framework_metasploit") or "").lower() == "true"
                _msf_name = (item.findtext("metasploit_name") or "").strip()
                _ease = (item.findtext("exploitability_ease") or "").strip()

                _has_edb = False
                _edb_ids = []
                _github_urls = []
                _see_also = []
                for xr in item.iter("xref"):
                    if xr.text and xr.text.startswith("EDB-ID:"):
                        _has_edb = True
                        _edb_ids.append(xr.text)
                for sa in item.iter("see_also"):
                    if sa.text:
                        for _url in sa.text.strip().splitlines():
                            _url = _url.strip()
                            if _url:
                                _see_also.append(_url)
                                if "github.com" in _url.lower():
                                    _github_urls.append(_url)

                _exploit_details = []
                if _has_msf and _msf_name:
                    _exploit_details.append({
                        "type": "metasploit",
                        "name": _msf_name,
                    })
                for _eid in _edb_ids:
                    _exploit_details.append({
                        "type": "exploitdb",
                        "id": _eid,
                    })
                for _gu in _github_urls:
                    _exploit_details.append({
                        "type": "github",
                        "url": _gu,
                    })

                finding = {
                    "id":               str(uuid.uuid4()),
                    "tool":             "nessus",
                    "title":            title,
                    "scope":            scope,
                    "datetime":         datetime.datetime.now().isoformat(),
                    "ip":               ip,
                    "port":             port,
                    "hostname":         hostname,
                    "risk":             risk,
                    "command":          f"Nessus Plugin {plugin_id}",
                    "description":      desc or synopsis,
                    "output":           output[:4096],
                    "output_file":      "nessus/nessus_results.nessus",
                    "cves":             ",".join(cves),
                    "sources":          "nessus",
                    "service":          f"{service}/{protocol}" if service else protocol,
                    "affected":         f"{ip}:{port}",
                    "remediation":      solution,
                    "exploitdb":        _has_edb or _has_exploit,
                    "metasploit":       _has_msf,
                    "exploit_details":  _exploit_details,
                    "nessus_plugin_id": int(plugin_id) if plugin_id.isdigit() else None,
                    "nessus_plugin_name": title,
                    "cvss_score":       cvss_score,
                    "cvss_vector":      cvss_vec,
                    "see_also":         _see_also,
                    "exploitability_ease": _ease,
                }
                findings.append(finding)
    except Exception as exc:
        log.error("Nessus XML parse error: %s", exc)

    if findings:
        out_path = Path(ne_dir) / "findings.json"
        out_path.write_text(
            json.dumps(findings, indent=2, default=str) + "\n",
            encoding="utf-8",
        )
    return findings


def _nessus_ingest_live(project_id, findings, project):
    """Feed parsed Nessus findings into FindingsEngine and emit SocketIO events."""
    fe = get_ext("findings_engine")
    socketio = get_ext("socketio")
    from services.utils import project_room as _room
    room = _room(project_id)

    for f in findings:
        if fe:
            fe.add_live_finding(project_id, f, project=project)
        if socketio:
            socketio.emit("finding",
                          {"tool": "nessus", "finding": f},
                          room=room)


def _nessus_update_ai(project_id, project, status, detail=""):
    """Update Nessus action items status and persist to disk."""
    proj_dir = project.get("project_dir", "")
    if not proj_dir:
        return
    from models.action_items import load_action_items
    items = load_action_items(proj_dir)
    updated = False
    for item in items:
        if (item.get("recommended_tool") or "").lower() == "nessus":
            item["status"] = status
            if detail:
                item["_detail"] = detail
            item["updated"] = datetime.datetime.now().isoformat()
            if status == "complete":
                item["completed_at"] = datetime.datetime.now().isoformat()
            updated = True

    if updated:
        ai_path = Path(proj_dir) / "action_items.json"
        ai_path.write_text(
            json.dumps(items, indent=2, default=str) + "\n",
            encoding="utf-8",
        )

    socketio = get_ext("socketio")
    if socketio:
        from services.utils import project_room as _room
        socketio.emit("nessus_ai_status",
                      {"status": status, "detail": detail},
                      room=_room(project_id))


def _emit_nessus_tool_status(project_id, status, detail=""):
    """Emit tool_status so the console tab reflects nessus state."""
    socketio = get_ext("socketio")
    if not socketio:
        return
    from services.utils import project_room as _room
    socketio.emit("tool_status", {
        "project_id": project_id,
        "tool_id": "nessus",
        "status": status,
        "phase": detail or ("Import complete" if status == "complete" else ""),
    }, room=_room(project_id))
    pm = get_ext("process_manager")
    if pm:
        pm.set_status(project_id, "nessus", status)


# ── API routes ──────────────────────────────────────────────────


@nessus_bp.route("/api/nessus/config/<project_id>", methods=["GET", "POST"])
def nessus_config(project_id):
    project = require_project(project_id)
    proj_dir = project.get("project_dir", "")

    if request.method == "GET":
        cfg = _load_config(project)
        return jsonify(cfg)

    data = request.get_json(silent=True) or {}
    cfg_file = Path(proj_dir) / "nessus_settings.json"
    with open(cfg_file, "w") as f:
        json.dump(data, f, indent=2)
    return jsonify({"ok": True})


def _client_from_inline(body):
    """Try to create a NessusClient from inline credentials in request body."""
    url = (body.get("nessus_url") or "").strip()
    user = (body.get("nessus_user") or "").strip()
    pw = body.get("nessus_pass") or ""
    if not user or not pw:
        return None
    from services.nessus_client import NessusClient
    return NessusClient.from_credentials(url=url, username=user, password=pw)


@nessus_bp.route("/api/nessus/test/<project_id>", methods=["POST"])
def nessus_test(project_id):
    project = require_project(project_id)
    body = request.get_json(silent=True) or {}

    inline_client = None
    try:
        inline_client = _client_from_inline(body)
    except Exception as e:
        return jsonify({"ok": False, "message": str(e)})

    if inline_client:
        ok, msg = inline_client.test_connection()
        if not ok:
            return jsonify({"ok": ok, "message": msg})
        try:
            policies = inline_client.list_policies()
            policies = [
                {"id": p.get("id"), "name": p.get("name", ""),
                 "description": p.get("description", "")}
                for p in policies
            ]
        except Exception:
            policies = []
        return jsonify({"ok": True, "message": msg, "policies": policies})

    cfg = _load_config(project)
    client = _make_client(cfg)
    if not client:
        return jsonify({"ok": False, "message": "Nessus not configured"})
    ok, msg = client.test_connection()
    return jsonify({"ok": ok, "message": msg})


@nessus_bp.route("/api/nessus/templates/<project_id>")
def nessus_templates(project_id):
    _, _, client = _require_nessus_client(project_id)
    try:
        templates = client.list_templates()
        return jsonify({"templates": templates})
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@nessus_bp.route("/api/nessus/policies/<project_id>")
def nessus_policies(project_id):
    """Fetch custom scan policies from the connected Nessus server."""
    _, _, client = _require_nessus_client(project_id)
    try:
        policies = client.list_policies()
        return jsonify({"policies": [
            {"id": p.get("id"), "name": p.get("name", ""),
             "description": p.get("description", "")}
            for p in policies
        ]})
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@nessus_bp.route("/api/nessus/scan/<project_id>", methods=["POST"])
def nessus_scan(project_id):
    data = request.get_json(silent=True) or {}

    inline_client = None
    try:
        inline_client = _client_from_inline(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 502

    if inline_client:
        client = inline_client
        project = require_project(project_id)
        cfg = {}
    else:
        project, cfg, client = _require_nessus_client(project_id)
    scan_type = data.get("scan_type", "basic")
    name = data.get("name", cfg.get("scan_name", f"Crucible-{project_id}"))
    targets = data.get("targets", cfg.get("targets", ""))
    template = data.get("template_uuid", "")
    policy_id = data.get("policy_id", cfg.get("policy_id"))
    folder_id = data.get("folder_id", cfg.get("folder_id"))

    _scope_def = (project or {}).get("scope_definition", {})
    exclusions = data.get("exclusions", _scope_def.get("exclusions", []))

    if not targets:
        return jsonify({"error": "No targets specified"}), 400

    if not template:
        templates = client.list_templates()
        if scan_type == "basic":
            tmpl_name = "basic"
        else:
            tmpl_name = "advanced"
        match = [t for t in templates if t.get("name") == tmpl_name]
        if not match:
            match = [t for t in templates
                     if t.get("title", "").lower().startswith(tmpl_name)]
        if match:
            template = match[0]["uuid"]
        elif templates:
            template = templates[0]["uuid"]
        else:
            return jsonify({"error": "No scan templates available"}), 400

    advanced_settings = {}
    if scan_type == "advanced":
        adv = data.get("advanced", {})
        discovery = {}
        if adv.get("ping_host"):
            ping_methods = []
            if adv.get("ping_arp"):
                ping_methods.append("ARP")
            if adv.get("ping_tcp"):
                ping_methods.append("TCP")
            if adv.get("ping_icmp"):
                ping_methods.append("ICMP")
            if adv.get("ping_udp"):
                ping_methods.append("UDP")
            if ping_methods:
                discovery["ping_methods"] = ping_methods
        else:
            discovery["ping_methods"] = []

        port_range = adv.get("port_range", "default")
        port_scanners = []
        if adv.get("scanner_tcp"):
            port_scanners.append("tcp")
        if adv.get("scanner_syn", True):
            port_scanners.append("syn")
        if adv.get("scanner_udp"):
            port_scanners.append("udp")
        advanced_settings = {
            "discovery": discovery,
            "port_range": port_range,
            "port_scanners": port_scanners,
            "webapp_scanning": adv.get("webapp_scanning", False),
        }

    try:
        scan_id = client.create_scan(
            name, targets, template, policy_id, folder_id,
            advanced_settings=advanced_settings,
            exclusions=exclusions)
        scan_uuid = client.launch_scan(scan_id)
        ndir = _nessus_dir(project_id)
        if ndir:
            state = {
                "scan_id": scan_id, "scan_uuid": scan_uuid,
                "status": "launched", "scan_type": scan_type,
            }
            with open(Path(ndir) / "scan_state.json", "w") as f:
                json.dump(state, f, indent=2)
        return jsonify({"scan_id": scan_id, "scan_uuid": scan_uuid})
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@nessus_bp.route("/api/nessus/status/<project_id>")
def nessus_status(project_id):
    _, _, client = _require_nessus_client(project_id)

    ndir = _nessus_dir(project_id)
    state_file = Path(ndir) / "scan_state.json" if ndir else None
    if not state_file or not state_file.exists():
        return jsonify({"status": "no_scan", "message": "No active scan"})

    with open(state_file) as f:
        state = json.load(f)

    scan_id = state.get("scan_id")
    if not scan_id:
        return jsonify({"status": "no_scan"})

    try:
        info = client.scan_status(scan_id)
        state["status"] = info.get("status", "unknown")
        with open(state_file, "w") as f:
            json.dump(state, f, indent=2)
        return jsonify(info)
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@nessus_bp.route("/api/nessus/export/<project_id>", methods=["POST"])
def nessus_export(project_id):
    _, cfg, client = _require_nessus_client(project_id)

    ndir = _nessus_dir(project_id)
    state_file = Path(ndir) / "scan_state.json" if ndir else None
    if not state_file or not state_file.exists():
        return jsonify({"error": "No scan to export"}), 400

    with open(state_file) as f:
        state = json.load(f)
    scan_id = state.get("scan_id")
    if not scan_id:
        return jsonify({"error": "No scan ID"}), 400

    data = request.get_json(silent=True) or {}
    fmt = data.get("format", "nessus")
    if fmt not in ("nessus", "csv", "html"):
        return jsonify({"error": "Invalid format"}), 400

    try:
        content = client.export_and_download(scan_id, fmt)
        ext = {"nessus": ".nessus", "csv": ".csv", "html": ".html"}[fmt]
        out_file = Path(ndir) / f"nessus_export{ext}"
        with open(out_file, "wb") as f:
            f.write(content)
        state["export_file"] = str(out_file)
        state["export_format"] = fmt
        with open(state_file, "w") as f:
            json.dump(state, f, indent=2)
        return jsonify({"ok": True, "file": str(out_file), "size": len(content)})
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@nessus_bp.route("/api/nessus/download/<project_id>")
def nessus_download(project_id):
    ndir = _nessus_dir(project_id)
    if not ndir:
        return jsonify({"error": "Project not found"}), 404
    state_file = Path(ndir) / "scan_state.json"
    if not state_file.exists():
        return jsonify({"error": "No export available"}), 404

    with open(state_file) as f:
        state = json.load(f)
    export_file = state.get("export_file")
    if not export_file or not Path(export_file).exists():
        return jsonify({"error": "Export file not found"}), 404

    return send_file(export_file, as_attachment=True)


@nessus_bp.route("/api/nessus/parse/<project_id>", methods=["POST"])
def nessus_parse(project_id):
    from services.nessus_client import NessusClient

    ndir = _nessus_dir(project_id)
    if not ndir:
        return jsonify({"error": "Project not found"}), 404

    nessus_file = Path(ndir) / "nessus_export.nessus"
    if not nessus_file.exists():
        return jsonify({"error": "No .nessus file to parse. Export first."}), 400

    findings = NessusClient.parse_nessus_xml(str(nessus_file))
    out_path = Path(ndir) / "nessus_findings.json"
    NessusClient.save_findings(findings, str(out_path))

    return jsonify({
        "ok": True,
        "count": len(findings),
        "file": str(out_path),
    })


@nessus_bp.route("/api/nessus/upload/<project_id>", methods=["POST"])
def nessus_upload(project_id):
    """Upload a .nessus file with two-phase scope-validated import.

    Phase 1 (validate_only=true, or out-of-scope hosts without force):
      Returns scope validation: in_scope, out_of_scope, all_in_scope.

    Phase 2 (force=true, or all hosts in scope):
      Saves file, parses XML, ingests findings live, updates action item.
    """
    project = require_project(project_id)

    f = request.files.get("file")
    force = request.form.get("force", "").lower() in ("true", "1", "yes")
    validate_only = request.form.get("validate_only", "").lower() in ("true", "1", "yes")
    if not f or not f.filename:
        return jsonify({"error": "No file provided"}), 400

    ext = Path(f.filename).suffix.lower()
    if ext not in (".nessus", ".xml"):
        return jsonify({"error": "Only .nessus/.xml files accepted"}), 400

    tmp = tempfile.NamedTemporaryFile(suffix=".nessus", delete=False)
    try:
        f.save(tmp.name)

        nessus_hosts = _extract_hosts_from_xml(tmp.name)
        scope_ips = _get_scope_ips(project_id)
        out_of_scope = sorted(nessus_hosts - scope_ips) if scope_ips else []
        in_scope_list = sorted(nessus_hosts & scope_ips) if scope_ips else sorted(nessus_hosts)

        if validate_only or (not force and out_of_scope):
            try:
                os.unlink(tmp.name)
            except Exception:
                pass
            return jsonify({
                "scope_warning":  len(out_of_scope) > 0,
                "all_in_scope":   len(out_of_scope) == 0,
                "out_of_scope":   out_of_scope,
                "in_scope":       in_scope_list,
                "total_hosts":    len(nessus_hosts),
                "scope_defined":  len(scope_ips) > 0,
            })

        ndir = _nessus_dir(project_id)
        if not ndir:
            ndir = project.get("project_dir", "/tmp")
        ne_dir = Path(ndir)
        ne_dir.mkdir(parents=True, exist_ok=True)
        nessus_file = ne_dir / "nessus_results.nessus"

        import shutil as _shu
        _shu.move(tmp.name, str(nessus_file))

        findings = _parse_nessus_xml(nessus_file, ne_dir, project_id)
        _register_nessus_tool(project_id, ne_dir)
        _nessus_ingest_live(project_id, findings, project)
        _nessus_update_ai(project_id, project, "complete",
                          f"Imported from file — {len(findings)} findings")
        _emit_nessus_tool_status(project_id, "complete",
                                 f"Imported from file — {len(findings)} findings")

        socketio = get_ext("socketio")
        if socketio:
            from services.utils import project_room as _room
            socketio.emit("nessus_done",
                          {"status": "ok", "mode": "import",
                           "finding_count": len(findings)},
                          room=_room(project_id))

        return jsonify({"ok": True, "finding_count": len(findings)})
    except Exception:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass
        raise


@nessus_bp.route("/api/nessus/import/<project_id>", methods=["POST"])
def nessus_import(project_id):
    _, cfg, client = _require_nessus_client(project_id)

    ndir = _nessus_dir(project_id)
    nessus_file = Path(ndir) / "nessus_export.nessus"
    if not nessus_file.exists():
        return jsonify({"error": "No .nessus file to import"}), 400

    try:
        file_key = client.upload_nessus_file(str(nessus_file))
        result = client.import_scan(file_key, cfg.get("folder_id"))
        return jsonify({"ok": True, "result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@nessus_bp.route("/api/nessus/scans/<project_id>")
def nessus_scans(project_id):
    """List scans available on the Nessus server."""
    _, _, client = _require_nessus_client(project_id)
    try:
        scans = client.list_scans()
        result = []
        for s in scans:
            result.append({
                "id": s.get("id"),
                "name": s.get("name", ""),
                "status": s.get("status", ""),
                "folder_id": s.get("folder_id"),
                "creation_date": s.get("creation_date"),
                "last_modification_date": s.get("last_modification_date"),
            })
        result.sort(key=lambda x: x.get("last_modification_date") or 0, reverse=True)
        return jsonify({"scans": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@nessus_bp.route("/api/nessus/fetch/<project_id>", methods=["POST"])
def nessus_fetch(project_id):
    """Fetch results from a completed scan on the Nessus server.

    Exports the scan as .nessus XML, downloads it, parses findings,
    and ingests them into the project — all in one step.
    """
    project, cfg, client = _require_nessus_client(project_id)
    data = request.get_json(silent=True) or {}
    scan_id = data.get("scan_id")
    if not scan_id:
        return jsonify({"error": "scan_id required"}), 400

    try:
        info = client.scan_status(scan_id)
        status = info.get("status", "")
        if status not in ("completed", "imported", "canceled"):
            return jsonify({
                "error": "Scan is not finished (status: %s)" % status,
                "status": status,
            }), 400
    except Exception as e:
        return jsonify({"error": "Cannot check scan status: %s" % str(e)}), 502

    ndir = _nessus_dir(project_id)
    if not ndir:
        ndir = project.get("project_dir", "/tmp")
    ne_dir = Path(ndir)
    ne_dir.mkdir(parents=True, exist_ok=True)

    try:
        content = client.export_and_download(scan_id, "nessus")
        nessus_file = ne_dir / "nessus_results.nessus"
        with open(nessus_file, "wb") as fh:
            fh.write(content)

        state = {"scan_id": scan_id, "status": "fetched", "source": "server"}
        with open(ne_dir / "scan_state.json", "w") as fh:
            json.dump(state, fh, indent=2)

        findings = _parse_nessus_xml(nessus_file, ne_dir, project_id)
        _register_nessus_tool(project_id, ne_dir)
        _nessus_ingest_live(project_id, findings, project)
        _nessus_update_ai(project_id, project, "complete",
                          "Fetched from Nessus server — %d findings" % len(findings))
        _emit_nessus_tool_status(project_id, "complete",
                                 "Fetched from Nessus server — %d findings" % len(findings))

        socketio = get_ext("socketio")
        if socketio:
            from services.utils import project_room as _room
            socketio.emit("nessus_done",
                          {"status": "ok", "mode": "fetch",
                           "finding_count": len(findings)},
                          room=_room(project_id))

        return jsonify({"ok": True, "finding_count": len(findings)})
    except Exception as e:
        log.error("Nessus fetch failed: %s", e)
        return jsonify({"error": str(e)}), 502


@nessus_bp.route("/api/nessus/purge/<project_id>", methods=["DELETE"])
def nessus_purge(project_id):
    import shutil

    project = require_project(project_id)
    ndir = _nessus_dir(project_id)
    if not ndir:
        return jsonify({"error": "Project not found"}), 404

    ndir_path = Path(ndir)
    if ndir_path.exists():
        shutil.rmtree(ndir_path)
        ndir_path.mkdir(parents=True, exist_ok=True)

    fe = get_ext("findings_engine")
    if fe:
        cached = fe._cache.get(project_id)
        if cached is not None:
            fe._cache[project_id] = [
                f for f in cached if f.get("tool") != "nessus"
            ]

    _nessus_update_ai(project_id, project, "pending",
                      "Purged — ready for new scan")

    socketio = get_ext("socketio")
    if socketio:
        from services.utils import project_room as _room
        socketio.emit("nessus_purged", {}, room=_room(project_id))

    return jsonify({"ok": True})


@nessus_bp.route("/api/nessus/console/<project_id>")
def nessus_console(project_id):
    """Return nessus findings summary for console display."""
    project = require_project(project_id)
    ndir = _nessus_dir(project_id)
    if not ndir:
        return jsonify({"lines": [], "status": "no_data"})
    nd = Path(ndir)
    nessus_file = nd / "nessus_results.nessus"
    findings_file = nd / "nessus_findings.json"
    lines = []
    if nessus_file.exists():
        size = nessus_file.stat().st_size
        mtime = datetime.datetime.fromtimestamp(
            nessus_file.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        lines.append({"text": f"Nessus file: {nessus_file.name}  ({size:,} bytes)",
                       "level": "info"})
        lines.append({"text": f"Imported: {mtime}", "level": "info"})
    if findings_file.exists():
        try:
            with open(findings_file) as f:
                data = json.load(f)
            items = data if isinstance(data, list) else data.get("findings", [])
            risk_counts = {}
            for fi in items:
                r = (fi.get("risk") or "INFO").upper()
                risk_counts[r] = risk_counts.get(r, 0) + 1
            lines.append({"text": f"Total findings: {len(items)}", "level": "info"})
            for r in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                c = risk_counts.get(r, 0)
                if c:
                    lines.append({"text": f"  {r}: {c}", "level": "info"})
            lines.append({"text": "", "level": "info"})
            for fi in items[:50]:
                risk = (fi.get("risk") or "INFO").upper()
                title = fi.get("title", "Unknown")
                ip = fi.get("ip", "")
                port = fi.get("port", "")
                tag = f"[{risk}]".ljust(11)
                loc = f"{ip}:{port}" if port else ip
                lines.append({"text": f"{tag} {title}  ({loc})",
                               "level": "error" if risk in ("CRITICAL", "HIGH")
                                        else "warn" if risk == "MEDIUM" else "info"})
            if len(items) > 50:
                lines.append({"text": f"... and {len(items) - 50} more findings",
                               "level": "info"})
        except (json.JSONDecodeError, OSError):
            lines.append({"text": "Failed to parse nessus_findings.json",
                           "level": "error"})
    elif nessus_file.exists():
        lines.append({"text": "Nessus XML present but findings not yet parsed.",
                       "level": "warn"})
    if not lines:
        return jsonify({"lines": [], "status": "no_data"})
    return jsonify({"lines": lines, "status": "complete"})


# ── API-connect import flow (credentials in modal) ───────────────

import secrets as _secrets
import threading as _threading

_nessus_sessions: dict[str, dict] = {}
_nessus_sessions_lock = _threading.Lock()


def _store_nessus_session(token: str, api_token: str, url: str) -> str:
    ref = _secrets.token_hex(16)
    with _nessus_sessions_lock:
        _nessus_sessions[ref] = {
            "token": token, "api_token": api_token, "url": url,
            "created": time.time(),
        }
        expired = [k for k, v in _nessus_sessions.items()
                   if time.time() - v["created"] > 3600]
        for k in expired:
            del _nessus_sessions[k]
    return ref


def _get_nessus_session(ref: str) -> dict | None:
    with _nessus_sessions_lock:
        return _nessus_sessions.get(ref)


@nessus_bp.route("/api/nessus/api-connect", methods=["POST"])
def nessus_api_connect():
    """Authenticate with a Nessus server using username/password and list scans."""
    import requests as _req

    body = request.get_json(silent=True) or {}
    url  = (body.get("url") or "").strip().rstrip("/") or f"https://127.0.0.1:{NESSUS_DEFAULT_PORT}"
    user = (body.get("username") or "").strip()
    pw   = (body.get("password") or "").strip()
    if not user or not pw:
        return jsonify({"error": "Username and password required"}), 400

    sess = _req.Session()
    sess.verify = False

    try:
        r = sess.post(f"{url}/session",
                      json={"username": user, "password": pw}, timeout=15)
    except Exception as exc:
        return jsonify({"error": f"Connection failed: {exc}"}), 502
    if r.status_code != 200:
        return jsonify({"error": f"Authentication failed (HTTP {r.status_code})"}), 401

    token = r.json().get("token", "")
    sess.headers.update({"X-Cookie": f"token={token}"})

    api_token = ""
    try:
        js_r = sess.get(f"{url}/nessus6.js", timeout=10)
        m = re.search(
            r'["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']',
            js_r.text[:50000],
        )
        if m:
            api_token = m.group(1)
            sess.headers["X-API-Token"] = api_token
    except Exception:
        pass

    try:
        sr = sess.get(f"{url}/scans", timeout=15)
        if sr.status_code != 200:
            return jsonify({"error": f"Failed to list scans (HTTP {sr.status_code})"}), 502
        scans = sr.json().get("scans") or []
    except Exception as exc:
        return jsonify({"error": f"Failed to list scans: {exc}"}), 502

    STATUS_MAP = {
        "completed": "Completed", "running": "Running",
        "paused": "Paused", "canceled": "Canceled",
        "stopped": "Stopped",
    }
    result = []
    for s in scans:
        status_raw = s.get("status", "unknown")
        result.append({
            "id":         s.get("id"),
            "name":       s.get("name", "—"),
            "status":     STATUS_MAP.get(status_raw, status_raw.title()),
            "can_import": status_raw == "completed",
        })

    session_ref = _store_nessus_session(token, api_token, url)
    return jsonify({"scans": result, "_session_ref": session_ref})


@nessus_bp.route("/api/nessus/api-import/<project_id>", methods=["POST"])
def nessus_api_import(project_id):
    """Import a completed scan from a Nessus server using a server-side session reference."""
    import requests as _req

    project = require_project(project_id)

    body    = request.get_json(silent=True) or {}
    scan_id = body.get("scan_id")
    session_ref = body.get("session_ref", "") or body.get("token", "")
    if not scan_id or not session_ref:
        return jsonify({"error": "scan_id and session_ref required"}), 400

    ns = _get_nessus_session(session_ref)
    if not ns:
        return jsonify({"error": "Nessus session expired — reconnect"}), 401
    token = ns["token"]
    api_token = ns["api_token"]
    url = ns["url"]

    sess = _req.Session()
    sess.verify = False
    sess.headers.update({"X-Cookie": f"token={token}"})
    if api_token:
        sess.headers["X-API-Token"] = api_token

    try:
        er = sess.post(f"{url}/scans/{scan_id}/export",
                       json={"format": "nessus"}, timeout=15)
        if er.status_code != 200:
            return jsonify({"error": f"Export request failed (HTTP {er.status_code})"}), 502
        file_id = er.json().get("file")
    except Exception as exc:
        return jsonify({"error": f"Export request failed: {exc}"}), 502

    for _ in range(60):
        try:
            sr = sess.get(f"{url}/scans/{scan_id}/export/{file_id}/status",
                          timeout=10)
            if sr.json().get("status") == "ready":
                break
        except Exception:
            pass
        time.sleep(2)
    else:
        return jsonify({"error": "Export timed out"}), 504

    try:
        dr = sess.get(f"{url}/scans/{scan_id}/export/{file_id}/download",
                      timeout=60)
        if dr.status_code != 200:
            return jsonify({"error": f"Download failed (HTTP {dr.status_code})"}), 502
        nessus_xml = dr.content
    except Exception as exc:
        return jsonify({"error": f"Download failed: {exc}"}), 502

    tmp_nessus = tempfile.NamedTemporaryFile(suffix=".nessus", delete=False)
    tmp_nessus.write(nessus_xml)
    tmp_nessus.close()

    if not body.get("force"):
        nessus_hosts = _extract_hosts_from_xml(tmp_nessus.name)
        scope_ips = _get_scope_ips(project_id)
        if scope_ips:
            out_of_scope = sorted(nessus_hosts - scope_ips)
            if out_of_scope:
                try:
                    os.unlink(tmp_nessus.name)
                except Exception:
                    pass
                return jsonify({
                    "scope_warning": True,
                    "out_of_scope": out_of_scope,
                    "in_scope": sorted(nessus_hosts & scope_ips),
                    "total_hosts": len(nessus_hosts),
                })

    ndir = _nessus_dir(project_id)
    if not ndir:
        ndir = project.get("project_dir", "/tmp")
    ne_dir = Path(ndir)
    ne_dir.mkdir(parents=True, exist_ok=True)
    nessus_file = ne_dir / "nessus_results.nessus"

    import shutil as _shu
    _shu.move(tmp_nessus.name, str(nessus_file))

    findings = _parse_nessus_xml(nessus_file, ne_dir, project_id)
    _register_nessus_tool(project_id, ne_dir)
    _nessus_ingest_live(project_id, findings, project)
    _nessus_update_ai(project_id, project, "complete",
                      f"Imported from API — {len(findings)} findings")

    socketio = get_ext("socketio")
    if socketio:
        from services.utils import project_room as _room
        socketio.emit("nessus_done",
                      {"status": "ok", "mode": "import",
                       "finding_count": len(findings)},
                      room=_room(project_id))

    return jsonify({"ok": True, "finding_count": len(findings)})
