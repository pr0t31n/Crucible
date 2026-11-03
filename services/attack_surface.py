"""Attack Surface service — per-project host/port inventory from FindingsDB."""

import logging

log = logging.getLogger("crucible.services.attack_surface")

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


def build_surface(findings_engine, project_id, project, sort="severity",
                  filter_risk=None):
    host_data = findings_engine.get_host_correlation(project_id, project)

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
