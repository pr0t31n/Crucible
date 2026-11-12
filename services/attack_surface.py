"""Attack Surface service — per-project host/port inventory from FindingsDB."""

import json
import logging
from pathlib import Path

log = logging.getLogger("crucible.services.attack_surface")


_CORRELATED_TOOL_ALIASES = {
    "nmap-nse": "nmap", "nmap-udp": "nmap",
    "nmap-udp-enterprise": "nmap", "http-probe": "curl",
    "banner-grab": None, "nc-probe": None,
}

_WEB_PORTS = frozenset({80, 443, 8080, 8443, 8000, 8888, 3000, 5000})


def _load_correlated_tools(project):
    """Read correlated.json + tools_used.json from tool dirs.

    Returns ({(ip, port): set(tools)}, set(engagement_level_tools)).
    """
    per_port = {}
    engagement_tools = set()
    seen_dirs = set()
    raw_dicts = [project.get("tool_dirs") or {}]
    for scope_val in (project.get("scope_tool_dirs") or {}).values():
        if isinstance(scope_val, dict):
            raw_dicts.append(scope_val)
    for dirs_dict in raw_dicts:
        if not isinstance(dirs_dict, dict):
            continue
        for td_path in dirs_dict.values():
            if not td_path or td_path in seen_dirs:
                continue
            seen_dirs.add(td_path)
            corr = Path(td_path) / "correlated.json"
            if corr.is_file():
                try:
                    data = json.loads(corr.read_text())
                except Exception:
                    pass
                else:
                    for ip, host in (data.get("hosts") or {}).items():
                        for port_key, pdata in (host.get("ports") or {}).items():
                            key = (ip, str(port_key))
                            tools = per_port.setdefault(key, set())
                            for tr in pdata.get("tool_results") or []:
                                raw = (tr.get("tool") or "").lower()
                                if raw in _CORRELATED_TOOL_ALIASES:
                                    mapped = _CORRELATED_TOOL_ALIASES[raw]
                                    if mapped:
                                        tools.add(mapped)
                                else:
                                    tools.add(raw)
            tu = Path(td_path) / "tools_used.json"
            if tu.is_file():
                try:
                    tu_data = json.loads(tu.read_text())
                except Exception:
                    pass
                else:
                    for entry in tu_data:
                        name = (entry.get("name") or "").lower()
                        if name:
                            engagement_tools.add(name)
    return per_port, engagement_tools

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

COVERAGE_HEURISTICS = {
    "http": ["fracture", "nuclei"],
    "https": ["fracture", "nuclei"],
    "ssl": ["sslscan", "testssl"],
    "tls": ["sslscan", "testssl"],
    "ssh": ["ssh-audit"],
    "smb": ["smbmap", "enum4linux"],
    "snmp": ["snmpwalk"],
    "ftp": ["ftp"],
    "dns": ["dnsx"],
    "smtp": ["smtp"],
}

WEB_SERVICES = frozenset({"http", "https", "http-proxy", "http-alt", "https-alt"})
API_SERVICES = frozenset({"http", "https"})

_ENGAGEMENT_LEVEL_TOOLS = {
    "nuclei": WEB_SERVICES | _WEB_PORTS,
    "gobuster": WEB_SERVICES | _WEB_PORTS,
    "shcheck": WEB_SERVICES | _WEB_PORTS,
    "webanalyze": WEB_SERVICES | _WEB_PORTS,
    "xsstrike": WEB_SERVICES | _WEB_PORTS,
}


def build_surface(findings_engine, project_id, project, sort="severity",
                  filter_risk=None):
    host_data = findings_engine.get_host_correlation(project_id, project)

    correlated_tools, engagement_tools = _load_correlated_tools(project)
    if correlated_tools or engagement_tools:
        for h in host_data:
            ip = h.get("ip", "")
            for p in h.get("ports", []):
                port_num = p.get("port", 0)
                port_str = str(port_num)
                svc_lower = (p.get("service") or "").lower()
                existing = set(p.get("tools", []))
                extra = correlated_tools.get((ip, port_str))
                if extra:
                    existing.update(extra)
                for eng_tool, svc_or_port_match in _ENGAGEMENT_LEVEL_TOOLS.items():
                    if eng_tool in engagement_tools and eng_tool not in existing:
                        if svc_lower in svc_or_port_match or port_num in svc_or_port_match:
                            existing.add(eng_tool)
                p["tools"] = sorted(existing)
                host_tools = set(h.get("tools", []))
                host_tools.update(existing)
                h["tools"] = sorted(host_tools)

    risk_filter = None
    if filter_risk:
        risk_filter = set(r.strip().upper() for r in filter_risk.split(",") if r.strip())

    hosts = []
    summary = {
        "total_hosts": 0,
        "total_ports": 0,
        "total_findings": 0,
        "severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "coverage_pct": 0,
    }

    scope_tools = set()
    for td in (project.get("scope_tools") or {}).values():
        if isinstance(td, list):
            scope_tools.update(td)

    for h in host_data:
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        port_details = []
        tools_set = set(h.get("tools", []))

        for p in h.get("ports", []):
            port_risk = p.get("risk_counts", {})
            for r, c in port_risk.items():
                r_upper = r.upper()
                severity_counts[r_upper] = severity_counts.get(r_upper, 0) + c

            svc = (p.get("service") or "").lower()
            expected = set()
            for svc_key, svc_tools in COVERAGE_HEURISTICS.items():
                if svc_key in svc:
                    expected.update(svc_tools)
            if svc in WEB_SERVICES or p.get("port") in (80, 443, 8080, 8443):
                expected.update(COVERAGE_HEURISTICS.get("http", []))
            if svc in API_SERVICES and "siphon" in scope_tools:
                expected.add("siphon")

            port_tools = set(p.get("tools", []))
            missing_tools = sorted(expected - port_tools - tools_set)

            findings_summary = []
            for f in p.get("findings", []):
                f_risk = (f.get("risk") or "INFO").upper()
                if risk_filter and f_risk not in risk_filter:
                    continue
                findings_summary.append({
                    "id": f.get("id"),
                    "title": f.get("title", ""),
                    "risk": f_risk,
                    "tool": f.get("tool", ""),
                    "kev": f.get("kev", False),
                    "cvss_score": f.get("cvss_score"),
                })

            port_details.append({
                "port": p.get("port", 0),
                "service": p.get("service", ""),
                "protocol": "tcp",
                "tools": sorted(port_tools),
                "risk_counts": port_risk,
                "findings": findings_summary,
                "missing_tools": missing_tools,
            })

        if risk_filter:
            has_match = any(
                any(f["risk"] in risk_filter for f in pd["findings"])
                for pd in port_details
            )
            if not has_match:
                continue

        total_expected = 0
        total_covered = 0
        for pd in port_details:
            svc = (pd.get("service") or "").lower()
            expected = set()
            for svc_key, svc_tools in COVERAGE_HEURISTICS.items():
                if svc_key in svc:
                    expected.update(svc_tools)
            if svc in WEB_SERVICES or pd.get("port") in (80, 443, 8080, 8443):
                expected.update(COVERAGE_HEURISTICS.get("http", []))
            if expected:
                total_expected += len(expected)
                total_covered += len(expected - set(pd.get("missing_tools", [])))

        host_entry = {
            "ip": h.get("ip", ""),
            "hostname": h.get("hostname", ""),
            "ports": port_details,
            "port_count": len(port_details),
            "tools": sorted(tools_set),
            "cves": h.get("cves", []),
            "max_risk": h.get("max_risk", "INFO"),
            "total_findings": h.get("total_findings", 0),
            "severity_counts": severity_counts,
            "coverage_pct": round(total_covered / total_expected * 100) if total_expected else 100,
        }
        hosts.append(host_entry)

        summary["total_hosts"] += 1
        summary["total_ports"] += len(port_details)
        summary["total_findings"] += host_entry["total_findings"]
        for r, c in severity_counts.items():
            summary["severity"][r] = summary["severity"].get(r, 0) + c

    if sort == "ip":
        hosts.sort(key=lambda h: _ip_sort_key(h.get("ip", "")))
    elif sort == "ports":
        hosts.sort(key=lambda h: -h["port_count"])
    elif sort == "findings":
        hosts.sort(key=lambda h: -h["total_findings"])
    else:
        hosts.sort(key=lambda h: RISK_ORDER.get(h["max_risk"], 5))

    if hosts:
        total_cov = sum(h["coverage_pct"] for h in hosts)
        summary["coverage_pct"] = round(total_cov / len(hosts))

    return {"hosts": hosts, "summary": summary}


def _ip_sort_key(ip):
    try:
        parts = ip.split(".")
        return tuple(int(p) for p in parts)
    except (ValueError, AttributeError):
        return (999, 999, 999, 999)
