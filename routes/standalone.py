"""Standalone tools — routes for tools accessible from the homepage."""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import xml.etree.ElementTree as ET
from pathlib import Path

from flask import Blueprint, jsonify, render_template, request

standalone_bp = Blueprint("standalone", __name__)

_merge_jobs = {}
_merge_lock = threading.Lock()

_SAFE_TARGET_RE = re.compile(r'^[a-zA-Z0-9.:\-/\s,]+$')
_PYTHON3 = shutil.which("python3") or sys.executable


@standalone_bp.route("/tools/merger")
def merger_page():
    return render_template("merger.html")


@standalone_bp.route("/tools/encoder")
def encoder_page():
    return render_template("encoder.html")


@standalone_bp.route("/api/merger/browse", methods=["POST"])
def api_merger_browse():
    data = request.get_json(silent=True) or {}
    folder = data.get("folder", "").strip() or "/"
    folder_path = Path(folder)
    if not folder_path.is_dir():
        folder_path = folder_path.parent
        if not folder_path.is_dir():
            folder_path = Path("/")
    entries = []
    try:
        for item in sorted(folder_path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
            if item.name.startswith("."):
                continue
            entries.append({
                "name": item.name,
                "path": str(item),
                "is_dir": item.is_dir(),
            })
    except PermissionError:
        return jsonify({"error": f"Permission denied: {folder_path}",
                        "current": str(folder_path), "entries": []}), 403
    return jsonify({
        "current": str(folder_path),
        "parent": str(folder_path.parent) if folder_path != folder_path.parent else None,
        "entries": entries,
    })


@standalone_bp.route("/api/dredge/detect", methods=["POST"])
def api_dredge_detect():
    data = request.get_json(silent=True) or {}
    path_str = data.get("path", "").strip()
    if not path_str:
        return jsonify({"valid": False, "error": "No path provided"})

    p = Path(path_str)
    if not p.exists():
        return jsonify({"valid": False, "error": f"Path not found: {path_str}"})

    from adapters.dredge import _detect_collection
    resolved, ctype = _detect_collection(path_str)
    if resolved is None:
        return jsonify({
            "valid": False,
            "path": path_str,
            "error": "Not a recognisable Dredge collection (expected PS1 JSON or CMD batch directory)",
        })

    labels = {"ps1_json": "PowerShell Collection JSON", "cmd_dir": "CMD Batch Output Directory"}
    return jsonify({
        "valid": True,
        "path": resolved,
        "type": ctype,
        "label": labels.get(ctype, ctype),
    })


@standalone_bp.route("/api/merger/scan", methods=["POST"])
def api_merger_scan():
    data = request.get_json(silent=True) or {}
    folder = data.get("folder", "").strip()
    if not folder:
        return jsonify({"error": "Folder path required"}), 400

    folder_path = Path(folder)
    if not folder_path.is_dir():
        return jsonify({"error": f"Not a valid directory: {folder}"}), 400

    from tools.merger import EngagementMerger

    logs = []
    merger = EngagementMerger(folder, callback=lambda m: logs.append(m))
    sources = merger.scan()

    source_list = []
    for src in sources:
        source_list.append({
            "type": src.type,
            "path": str(src.path),
            "name": src.meta.get("name", src.path.name) if src.meta else src.path.name,
            "label": src.label,
        })

    return jsonify({"sources": source_list, "logs": logs})


@standalone_bp.route("/api/merger/merge", methods=["POST"])
def api_merger_merge():
    data = request.get_json(silent=True) or {}
    folder = data.get("folder", "").strip()
    name = data.get("name", "").strip() or None

    if not folder:
        return jsonify({"error": "Folder path required"}), 400

    folder_path = Path(folder)
    if not folder_path.is_dir():
        return jsonify({"error": f"Not a valid directory: {folder}"}), 400

    from tools.merger import EngagementMerger

    logs = []
    merger = EngagementMerger(folder, output_name=name,
                              callback=lambda m: logs.append(m))
    sources = merger.scan()
    if not sources:
        return jsonify({"error": "No mergeable sources found", "logs": logs}), 400

    eng_dir = merger.merge(sources)
    if not eng_dir:
        return jsonify({"error": "Merge failed", "logs": logs}), 500

    from models.project import reload_projects
    reload_projects()

    meta_path = eng_dir / "crucible_meta.json"
    project_id = None
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text())
            project_id = meta.get("id")
        except (json.JSONDecodeError, OSError):
            pass

    return jsonify({
        "ok": True,
        "engagement_dir": str(eng_dir),
        "project_id": project_id,
        "source_count": len(sources),
        "logs": logs,
    })


# ── Host Discovery ─────────────────────────────────────────────────────────

@standalone_bp.route("/api/standalone/host-discovery", methods=["POST"])
def api_host_discovery():
    data = request.get_json(silent=True) or {}
    raw_targets = data.get("targets", "").strip()
    if not raw_targets:
        return jsonify({"error": "At least one target IP/CIDR required"}), 400

    targets = [t.strip() for t in raw_targets.replace(",", "\n").splitlines() if t.strip()]
    for t in targets:
        if not _SAFE_TARGET_RE.match(t):
            return jsonify({"error": f"Invalid target: {t}"}), 400

    rate = max(50, min(5000, int(data.get("rate", 300))))
    extra_ports = data.get("extra_ports", "").strip()

    nmap = shutil.which("nmap")
    if not nmap:
        return jsonify({"error": "nmap not found on this system"}), 500

    tcp_ports = "80,443,22,21,25,3389,8080,8443"
    if extra_ports and re.match(r'^[0-9,\-]+$', extra_ports):
        tcp_ports += "," + extra_ports

    cmd = [nmap, "-sn", "-PE", "-PP", "-PM",
           f"-PS{tcp_ports}", "-PA80,443",
           "-PU53,161",
           "--min-rate", str(rate), "--max-retries", "2",
           "-oX", "-"] + targets

    if os.geteuid() != 0:
        cmd = ["sudo"] + cmd

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Host discovery timed out (120s)"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    hosts = []
    try:
        root = ET.fromstring(result.stdout)
        for host_el in root.findall(".//host"):
            addr_el = host_el.find("address[@addrtype='ipv4']")
            if addr_el is None:
                addr_el = host_el.find("address[@addrtype='ipv6']")
            if addr_el is None:
                continue
            ip = addr_el.get("addr", "")
            status_el = host_el.find("status")
            status = status_el.get("state", "unknown") if status_el is not None else "unknown"
            reason = status_el.get("reason", "") if status_el is not None else ""
            hosts.append({"ip": ip, "status": status, "reason": reason})
    except ET.ParseError:
        if result.returncode != 0:
            return jsonify({"error": result.stderr or "nmap failed", "exit_code": result.returncode}), 500
        return jsonify({"error": "Failed to parse nmap output"}), 500

    alive = sum(1 for h in hosts if h["status"] == "up")
    cmd_str = " ".join(cmd)
    return jsonify({"ok": True, "hosts": hosts, "total": len(hosts), "alive": alive,
                     "command": cmd_str})


# ── Wordlist Generator ─────────────────────────────────────────────────────

@standalone_bp.route("/api/standalone/wordlist", methods=["POST"])
def api_wordlist():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "Target URL required"}), 400

    try:
        if "/opt/pr0t31n/shared" not in sys.path:
            sys.path.insert(0, "/opt/pr0t31n/shared")
        import pr0t31n_wordlist as _wl
    except ImportError:
        return jsonify({"error": "pr0t31n_wordlist module not found"}), 500

    logs = []
    try:
        result_path = _wl.build_website_wordlist(
            url=url,
            max_depth=max(1, min(7, int(data.get("depth", 2)))),
            org_name=data.get("org", "").strip() or None,
            min_len=max(1, int(data.get("min_len", 1))),
            max_len=max(1, int(data.get("max_len", 63))),
            max_pages=max(1, min(500, int(data.get("max_pages", 80)))),
            include_defaults=not data.get("no_defaults", False),
            include_leet=not data.get("no_leet", False),
            log_fn=lambda m: logs.append(m),
        )
    except Exception as e:
        return jsonify({"error": str(e), "logs": logs}), 500

    if not result_path:
        return jsonify({"error": "Wordlist generation failed", "logs": logs}), 500

    count = 0
    try:
        with open(result_path) as f:
            count = sum(1 for _ in f)
    except OSError:
        pass

    return jsonify({"ok": True, "path": result_path, "count": count, "logs": logs})


# ── Port Probe ─────────────────────────────────────────────────────────────

@standalone_bp.route("/api/standalone/port-probe", methods=["POST"])
def api_port_probe():
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "Target IP or hostname required"}), 400
    if not _SAFE_TARGET_RE.match(target):
        return jsonify({"error": f"Invalid target: {target}"}), 400

    nmap = shutil.which("nmap")
    if not nmap:
        return jsonify({"error": "nmap not found on this system"}), 500

    ports = data.get("ports", "top1000").strip().lower()
    timing = data.get("timing", "T4").strip()
    if timing not in ("T1", "T2", "T3", "T4", "T5"):
        timing = "T4"

    custom_ports = data.get("custom_ports", "").strip()

    port_flag = []
    timeout = 120
    if ports == "all":
        port_flag = ["-p-"]
        timeout = 300
    elif ports == "top100":
        port_flag = ["--top-ports", "100"]
    elif ports == "custom" and custom_ports and re.match(r'^[0-9,\-]+$', custom_ports):
        port_flag = ["-p", custom_ports]
    else:
        port_flag = ["--top-ports", "1000"]

    cmd = [nmap, "-sS", "-sV", "--open", f"-{timing}",
           "-oX", "-"] + port_flag + [target]

    if os.geteuid() != 0:
        cmd = ["sudo"] + cmd

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return jsonify({"error": f"Port scan timed out ({timeout}s)"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    hosts = []
    try:
        root = ET.fromstring(result.stdout)
        for host_el in root.findall(".//host"):
            addr_el = host_el.find("address[@addrtype='ipv4']")
            if addr_el is None:
                addr_el = host_el.find("address[@addrtype='ipv6']")
            ip = addr_el.get("addr", "") if addr_el is not None else target

            hostname = ""
            hn_el = host_el.find(".//hostname")
            if hn_el is not None:
                hostname = hn_el.get("name", "")

            port_list = []
            for port_el in host_el.findall(".//port"):
                state_el = port_el.find("state")
                svc_el = port_el.find("service")
                port_list.append({
                    "port": int(port_el.get("portid", 0)),
                    "protocol": port_el.get("protocol", "tcp"),
                    "state": state_el.get("state", "") if state_el is not None else "",
                    "service": svc_el.get("name", "") if svc_el is not None else "",
                    "version": " ".join(filter(None, [
                        svc_el.get("product", "") if svc_el is not None else "",
                        svc_el.get("version", "") if svc_el is not None else "",
                        svc_el.get("extrainfo", "") if svc_el is not None else "",
                    ])).strip(),
                })
            hosts.append({"ip": ip, "hostname": hostname, "ports": port_list})
    except ET.ParseError:
        if result.returncode != 0:
            return jsonify({"error": result.stderr or "nmap failed"}), 500
        return jsonify({"error": "Failed to parse nmap output"}), 500

    cmd_str = " ".join(cmd)
    return jsonify({"ok": True, "hosts": hosts, "command": cmd_str})


# ── SSL/TLS Audit ──────────────────────────────────────────────────────────

@standalone_bp.route("/api/standalone/ssl-audit", methods=["POST"])
def api_ssl_audit():
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "Target host:port required"}), 400
    if not re.match(r'^[a-zA-Z0-9.\-:]+(:\d+)?$', target):
        return jsonify({"error": f"Invalid target: {target}"}), 400

    testssl = shutil.which("testssl") or shutil.which("testssl.sh")
    sslscan = shutil.which("sslscan")

    if not testssl and not sslscan:
        return jsonify({"error": "Neither testssl.sh nor sslscan found"}), 500

    tool_used = ""
    if testssl:
        tool_used = "testssl.sh"
        cmd = [testssl, "--quiet", "--color", "0", target]
    else:
        tool_used = "sslscan"
        cmd = [sslscan, "--no-colour", target]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return jsonify({"error": f"{tool_used} timed out (120s)"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    output = result.stdout
    if result.returncode != 0 and not output:
        output = result.stderr or f"{tool_used} exited with code {result.returncode}"

    return jsonify({"ok": True, "output": output, "tool_used": tool_used})


# ── Security Headers Analyzer ──────────────────────────────────────────────

_SEC_HEADERS = [
    {"name": "Strict-Transport-Security", "required": True,
     "good": "HSTS enabled", "bad": "Missing — browsers will not enforce HTTPS"},
    {"name": "Content-Security-Policy", "required": True,
     "good": "CSP policy defined", "bad": "Missing — no XSS/injection defense"},
    {"name": "X-Content-Type-Options", "required": True,
     "good": "nosniff set", "bad": "Missing — MIME-type sniffing possible"},
    {"name": "X-Frame-Options", "required": True,
     "good": "Clickjacking protection", "bad": "Missing — clickjacking possible"},
    {"name": "Referrer-Policy", "required": True,
     "good": "Referrer policy set", "bad": "Missing — referrer leakage possible"},
    {"name": "Permissions-Policy", "required": False,
     "good": "Feature restrictions defined", "bad": "Missing — browser features unrestricted"},
    {"name": "Cross-Origin-Opener-Policy", "required": False,
     "good": "COOP set", "bad": "Missing — cross-origin window access possible"},
    {"name": "Cross-Origin-Resource-Policy", "required": False,
     "good": "CORP set", "bad": "Missing — resource embedding unrestricted"},
    {"name": "Cross-Origin-Embedder-Policy", "required": False,
     "good": "COEP set", "bad": "Missing"},
    {"name": "X-XSS-Protection", "required": False,
     "good": "Legacy XSS filter enabled (deprecated)", "bad": "Absent (expected — use CSP instead)"},
    {"name": "Cache-Control", "required": False,
     "good": "Caching restricted", "bad": "May cache sensitive responses"},
    {"name": "X-Permitted-Cross-Domain-Policies", "required": False,
     "good": "Cross-domain policy restricted", "bad": "Missing — Flash/PDF cross-domain uncontrolled"},
]

_VALID_HSTS_RE = re.compile(r'max-age=(\d+)', re.I)
_VALID_XCT = {"nosniff"}
_VALID_XFO = {"DENY", "SAMEORIGIN"}
_VALID_RP = {"no-referrer", "strict-origin-when-cross-origin", "strict-origin",
             "same-origin", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin"}
_VALID_COOP = {"same-origin", "same-origin-allow-popups"}
_VALID_CORP = {"same-origin", "same-site", "cross-origin"}
_VALID_COEP = {"require-corp", "credentialless"}
_VALID_XCDP = {"none", "master-only"}


def _check_header(name, value):
    v = (value or "").strip()
    vl = v.lower()
    if name == "Strict-Transport-Security":
        m = _VALID_HSTS_RE.search(vl)
        return bool(m and int(m.group(1)) >= 31536000)
    if name == "Content-Security-Policy":
        return bool(v)
    if name == "X-Content-Type-Options":
        return vl in _VALID_XCT
    if name == "X-Frame-Options":
        return v.upper() in _VALID_XFO
    if name == "Referrer-Policy":
        return vl in _VALID_RP
    if name == "Permissions-Policy":
        return bool(v)
    if name == "Cross-Origin-Opener-Policy":
        return vl in _VALID_COOP
    if name == "Cross-Origin-Resource-Policy":
        return vl in _VALID_CORP
    if name == "Cross-Origin-Embedder-Policy":
        return vl in _VALID_COEP
    if name == "X-XSS-Protection":
        return v.startswith("1")
    if name == "Cache-Control":
        return "no-store" in vl or "no-cache" in vl
    if name == "X-Permitted-Cross-Domain-Policies":
        return vl in _VALID_XCDP
    return bool(v)


@standalone_bp.route("/api/standalone/sec-headers", methods=["POST"])
def api_sec_headers():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL required"}), 400

    follow = data.get("follow_redirects", True)

    try:
        import requests as _req
    except ImportError:
        return jsonify({"error": "requests library not available"}), 500

    try:
        resp = _req.get(url, timeout=15, verify=False, allow_redirects=follow,
                        headers={"User-Agent": "Crucible-SecHeaders/1.0"})
    except Exception as e:
        return jsonify({"error": f"Request failed: {e}"}), 500

    headers_result = []
    passed = 0
    total = len(_SEC_HEADERS)

    for hdef in _SEC_HEADERS:
        name = hdef["name"]
        value = resp.headers.get(name)
        present = value is not None
        is_pass = present and _check_header(name, value)
        if is_pass:
            passed += 1
        headers_result.append({
            "name": name,
            "value": value or "",
            "present": present,
            "pass": is_pass,
            "note": hdef["good"] if is_pass else hdef["bad"],
            "required": hdef["required"],
        })

    score = round(passed / total * 100) if total else 0
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    return jsonify({
        "ok": True,
        "url": str(resp.url),
        "status_code": resp.status_code,
        "headers": headers_result,
        "passed": passed,
        "total": total,
        "score": score,
        "grade": grade,
        "server": resp.headers.get("Server", ""),
        "powered_by": resp.headers.get("X-Powered-By", ""),
    })


# ── DNS Resolver ───────────────────────────────────────────────────────────

@standalone_bp.route("/api/standalone/dns-resolve", methods=["POST"])
def api_dns_resolve():
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "Domain or IP required"}), 400
    if not re.match(r'^[a-zA-Z0-9.\-:]+$', target):
        return jsonify({"error": f"Invalid target: {target}"}), 400

    dig = shutil.which("dig")
    if not dig:
        return jsonify({"error": "dig not found on this system"}), 500

    types = data.get("types", ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"])
    valid_types = {"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR", "SRV", "CAA"}
    types = [t.upper() for t in types if t.upper() in valid_types]

    records = {}
    for rtype in types:
        try:
            result = subprocess.run(
                [dig, "+short", target, rtype],
                capture_output=True, text=True, timeout=15)
            lines = [l.strip() for l in result.stdout.strip().splitlines() if l.strip()]
            records[rtype] = lines
        except (subprocess.TimeoutExpired, Exception):
            records[rtype] = []

    reverse_result = None
    if data.get("reverse"):
        try:
            result = subprocess.run(
                [dig, "+short", "-x", target],
                capture_output=True, text=True, timeout=15)
            reverse_result = result.stdout.strip() or None
        except (subprocess.TimeoutExpired, Exception):
            pass

    whois_result = None
    if data.get("whois"):
        whois_bin = shutil.which("whois")
        if whois_bin:
            try:
                result = subprocess.run(
                    [whois_bin, target],
                    capture_output=True, text=True, timeout=30)
                lines = result.stdout.strip().splitlines()[:200]
                whois_result = "\n".join(lines) if lines else None
            except (subprocess.TimeoutExpired, Exception):
                pass

    return jsonify({
        "ok": True,
        "target": target,
        "records": records,
        "reverse": reverse_result,
        "whois": whois_result,
    })


# ── Traffic Dump ──────────────────────────────────────────────────────────

_INTERNAL_NETS = [
    (0x0A000000, 0xFF000000),   # 10.0.0.0/8
    (0xAC100000, 0xFFF00000),   # 172.16.0.0/12
    (0xC0A80000, 0xFFFF0000),   # 192.168.0.0/16
    (0x7F000000, 0xFF000000),   # 127.0.0.0/8
]

_IP_IN_TCPDUMP = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\.\d+)?')


def _is_internal_ip(ip_str):
    parts = ip_str.split(".")
    if len(parts) != 4:
        return False
    try:
        n = (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])
    except (ValueError, IndexError):
        return False
    return any((n & mask) == net for net, mask in _INTERNAL_NETS)


@standalone_bp.route("/api/standalone/traffic-interfaces")
def api_traffic_interfaces():
    tshark = shutil.which("tshark")
    tcpdump = shutil.which("tcpdump")
    tool = tshark or tcpdump
    if not tool:
        return jsonify({"error": "Neither tshark nor tcpdump found"}), 500
    try:
        cmd = [tool, "-D"]
        if os.geteuid() != 0:
            cmd = ["sudo"] + cmd
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        interfaces = []
        for line in result.stdout.strip().splitlines():
            parts = line.strip().split(".", 1)
            if len(parts) < 2:
                continue
            tok = parts[1].strip().split(None, 1)
            name = tok[0] if tok else parts[1].strip()
            desc = tok[1].strip("() ") if len(tok) > 1 else ""
            interfaces.append({"name": name, "description": desc})
        return jsonify({"ok": True, "interfaces": interfaces,
                        "tool": os.path.basename(tool)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@standalone_bp.route("/api/standalone/traffic-dump", methods=["POST"])
def api_traffic_dump():
    data = request.get_json(silent=True) or {}
    interface = data.get("interface", "").strip()
    if not interface:
        return jsonify({"error": "Network interface required"}), 400
    if not re.match(r'^[a-zA-Z0-9._\-]+$', interface):
        return jsonify({"error": f"Invalid interface: {interface}"}), 400

    duration = max(5, min(120, int(data.get("duration", 30))))
    bpf_filter = data.get("filter", "").strip()
    promisc = bool(data.get("promiscuous", False))

    tshark = shutil.which("tshark")
    tcpdump = shutil.which("tcpdump")
    if not tshark and not tcpdump:
        return jsonify({"error": "Neither tshark nor tcpdump found"}), 500

    fd, capture_file = tempfile.mkstemp(suffix=".pcap", prefix="crucible_cap_")
    os.close(fd)

    tool_used = "tshark" if tshark else "tcpdump"

    if tshark:
        cmd = [tshark, "-i", interface, "-a", f"duration:{duration}",
               "-w", capture_file, "-q"]
        if not promisc:
            cmd.append("-p")
        if bpf_filter:
            cmd.extend(["-f", bpf_filter])
        if os.geteuid() != 0:
            cmd = ["sudo"] + cmd
        try:
            subprocess.run(cmd, capture_output=True, text=True,
                           timeout=duration + 30)
        except subprocess.TimeoutExpired:
            pass
    else:
        cmd = [tcpdump, "-i", interface, "-w", capture_file, "-nn"]
        if not promisc:
            cmd.append("-p")
        if bpf_filter:
            cmd.append(bpf_filter)
        if os.geteuid() != 0:
            cmd = ["sudo"] + cmd
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        try:
            proc.wait(timeout=duration)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    if not os.path.exists(capture_file) or os.path.getsize(capture_file) == 0:
        try:
            os.unlink(capture_file)
        except OSError:
            pass
        return jsonify({"error": "No packets captured — check interface and permissions"}), 500

    # ── Analysis ──
    all_ips = set()
    ip_counts = {}
    protocols = {}
    packet_count = 0

    if tshark:
        try:
            r = subprocess.run(
                [tshark, "-r", capture_file, "-T", "fields",
                 "-e", "ip.src", "-e", "ip.dst", "-e", "_ws.col.Protocol"],
                capture_output=True, text=True, timeout=120)
            for line in r.stdout.strip().splitlines():
                cols = line.split("\t")
                src = cols[0].strip() if len(cols) > 0 else ""
                dst = cols[1].strip() if len(cols) > 1 else ""
                proto = cols[2].strip() if len(cols) > 2 else ""
                for ip in (src, dst):
                    if ip:
                        all_ips.add(ip)
                        ip_counts[ip] = ip_counts.get(ip, 0) + 1
                if proto:
                    protocols[proto] = protocols.get(proto, 0) + 1
                packet_count += 1
        except (subprocess.TimeoutExpired, Exception):
            pass
    else:
        try:
            r = subprocess.run(
                [tcpdump, "-r", capture_file, "-nn", "-q"],
                capture_output=True, text=True, timeout=120)
            for line in r.stdout.strip().splitlines():
                found = _IP_IN_TCPDUMP.findall(line)
                for ip in found:
                    all_ips.add(ip)
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
                packet_count += 1
                if " ARP" in line:
                    protocols["ARP"] = protocols.get("ARP", 0) + 1
                elif " ICMP " in line:
                    protocols["ICMP"] = protocols.get("ICMP", 0) + 1
                elif " UDP " in line:
                    protocols["UDP"] = protocols.get("UDP", 0) + 1
                else:
                    protocols["TCP"] = protocols.get("TCP", 0) + 1
        except (subprocess.TimeoutExpired, Exception):
            pass

    def _sort_ip(ip):
        try:
            return tuple(int(x) for x in ip.split("."))
        except (ValueError, AttributeError):
            return (999, 999, 999, 999)

    internal = sorted([ip for ip in all_ips if _is_internal_ip(ip)], key=_sort_ip)
    external = sorted([ip for ip in all_ips if not _is_internal_ip(ip)], key=_sort_ip)
    top_talkers = [{"ip": ip, "packets": c}
                   for ip, c in sorted(ip_counts.items(), key=lambda x: -x[1])[:20]]
    proto_list = [{"protocol": p, "packets": c}
                  for p, c in sorted(protocols.items(), key=lambda x: -x[1])]

    return jsonify({
        "ok": True,
        "tool_used": tool_used,
        "duration": duration,
        "packets": packet_count,
        "file_size": os.path.getsize(capture_file),
        "capture_file": capture_file,
        "internal_ips": internal,
        "external_ips": external,
        "top_talkers": top_talkers,
        "protocols": proto_list,
    })


# ── Standalone tools registry ──────────────────────────────────────────────

STANDALONE_TOOLS = [
    {
        "id": "merger",
        "name": "Engagement Merger",
        "desc": "Merge multiple Crucible/Vantage engagements and Nessus results into one",
        "icon": "merge",
        "url": "/tools/merger",
    },
    {
        "id": "authprobe",
        "name": "AuthProbe",
        "desc": "Detect authentication methods, fingerprint software, probe well-known endpoints",
        "icon": "shield",
        "url": None,
        "modal": True,
    },
    {
        "id": "host-discovery",
        "name": "Host Discovery",
        "desc": "Quick nmap live-host scan with ICMP, TCP, and UDP probing for 95%+ accuracy",
        "icon": "radar",
        "url": None,
        "modal": True,
    },
    {
        "id": "wordlist",
        "name": "Wordlist Generator",
        "desc": "Scrape a client website and build targeted password-candidate wordlists",
        "icon": "list",
        "url": None,
        "modal": True,
    },
    {
        "id": "port-probe",
        "name": "Port Probe",
        "desc": "Lightweight nmap TCP SYN scan with service and version detection",
        "icon": "scan",
        "url": None,
        "modal": True,
    },
    {
        "id": "ssl-audit",
        "name": "SSL/TLS Audit",
        "desc": "Quick TLS configuration and cipher suite audit via testssl.sh or sslscan",
        "icon": "lock",
        "url": None,
        "modal": True,
    },
    {
        "id": "sec-headers",
        "name": "Security Headers",
        "desc": "Pass/fail scorecard for HTTP security headers with grade",
        "icon": "headers",
        "url": None,
        "modal": True,
    },
    {
        "id": "encoder",
        "name": "Encode / Decode",
        "desc": "Base64, URL, HTML entities, hex, JWT decode, hash identification",
        "icon": "code",
        "url": "/tools/encoder",
    },
    {
        "id": "dns-resolve",
        "name": "DNS Resolver",
        "desc": "Quick DNS lookups for A/AAAA/CNAME/MX/NS/TXT/SOA + reverse DNS + WHOIS",
        "icon": "globe",
        "url": None,
        "modal": True,
    },
    {
        "id": "wifi-scan",
        "name": "WiFi Scanner",
        "desc": "Scan visible wireless networks and manage interfaces",
        "icon": "wifi",
        "url": None,
        "modal": True,
    },
    {
        "id": "traffic-dump",
        "name": "Traffic Dump",
        "desc": "Quick packet capture with tshark/tcpdump and internal IP analysis",
        "icon": "activity",
        "url": None,
        "modal": True,
    },
]


@standalone_bp.route("/api/standalone_tools")
def api_standalone_tools():
    return jsonify(STANDALONE_TOOLS)
