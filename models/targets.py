"""Targets model — host/port/OSINT target aggregation from tool outputs."""

import json
from pathlib import Path

from config import TOOL_OUTPUT_DIRS


def load_network_targets(tool_output_dir):
    """Load network targets from SS3's output files.
    Checks targets.json, correlated.json, and inventory/hosts.json."""
    td = Path(tool_output_dir)
    targets = []
    for scope in ["int", "ext"]:
        sd = td / scope
        if not sd.is_dir():
            continue
        scope_name = "internal" if scope == "int" else "external"
        found = _load_hosts_from_dir(sd)
        for t in found:
            t["scope"] = scope_name
        targets.extend(found)
    if not targets:
        targets = _load_hosts_from_dir(td)
    return targets


def _load_hosts_from_dir(d):
    """Try multiple SS3 output files in priority order."""
    d = Path(d)
    for candidate in ("targets.json", "correlated.json"):
        fp = d / candidate
        if fp.exists():
            hosts = _parse_host_file(fp)
            if hosts:
                return hosts
    inv = d / "inventory" / "hosts.json"
    if inv.exists():
        hosts = _parse_host_file(inv)
        if hosts:
            return hosts
    return []


def _parse_host_file(fp):
    """Parse a host-level JSON file into a list of target dicts."""
    try:
        with open(fp) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []
    if isinstance(data, list):
        return [_normalise_host(h) for h in data if isinstance(h, dict)]
    if isinstance(data, dict):
        items = data.get("targets") or data.get("hosts") or data.get("_items") or []
        if isinstance(items, list):
            return [_normalise_host(h) for h in items if isinstance(h, dict)]
    return []


def _normalise_host(h):
    """Normalise a host dict from various SS3 formats into a consistent shape."""
    ip = h.get("ip", h.get("host", ""))
    hostname = h.get("hostname", h.get("fqdn", ""))
    os_info = h.get("os", h.get("os_name", ""))
    ports = h.get("ports", [])
    services = h.get("services", [])
    if not services and ports:
        services = []
        for p in ports:
            if isinstance(p, dict):
                svc = p.get("service") or p.get("name") or ""
                if svc and svc not in services:
                    services.append(svc)
    return {
        "ip": ip,
        "hostname": hostname,
        "os": os_info,
        "ports": ports,
        "services": services,
        "scope": h.get("scope", ""),
        "status": h.get("status", "up"),
    }


def load_osint_targets(tool_output_dir):
    """Load OSINT targets from OSift outputs.
    Checks reports/targets_osint.json and root targets_osint.json,
    then flattens the structured data into a flat list of assets."""
    td = Path(tool_output_dir)
    for candidate in (td / "reports" / "targets_osint.json",
                      td / "targets_osint.json"):
        if candidate.exists():
            try:
                with open(candidate) as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue
            primary = data.get("domain", "")
            all_domains = [primary] if primary else []
            domains_dir = td / "domains"
            if domains_dir.is_dir():
                for d in sorted(domains_dir.iterdir()):
                    if d.is_dir() and d.name not in all_domains:
                        all_domains.append(d.name)
            if len(all_domains) > 1:
                data["domains"] = all_domains
            return _flatten_osint_data(data)
    return []


def _flatten_osint_data(data):
    """Flatten targets_osint.json structure into [{type, value, source, details}]."""
    if isinstance(data, list):
        return data
    assets = []
    for sub in data.get("subdomains", []):
        if isinstance(sub, dict):
            sources = sub.get("sources", [])
            source_str = ", ".join(sources) if isinstance(sources, list) else str(sources)
            details_parts = []
            if sub.get("ip"):
                details_parts.append(sub["ip"])
            if sub.get("http_status"):
                details_parts.append("HTTP " + str(sub["http_status"]))
            if sub.get("redirect_to"):
                details_parts.append("→ " + str(sub["redirect_to"]))
            assets.append({
                "type": "subdomain",
                "value": sub.get("host", sub.get("subdomain", "")),
                "source": source_str,
                "details": " | ".join(details_parts) if details_parts else "",
            })
    for email in data.get("emails", []):
        if isinstance(email, dict):
            sources = email.get("sources", [])
            source_str = ", ".join(sources) if isinstance(sources, list) else str(sources)
            assets.append({
                "type": "email",
                "value": email.get("email", ""),
                "source": source_str,
                "details": email.get("severity", ""),
            })
    for ip_entry in data.get("ips", []):
        if isinstance(ip_entry, dict):
            sources = ip_entry.get("sources", [])
            source_str = ", ".join(sources) if isinstance(sources, list) else str(sources)
            fqdns = ip_entry.get("fqdns", [])
            fqdn_list = []
            for fq in fqdns:
                if isinstance(fq, dict):
                    fqdn_list.append(fq.get("fqdn", ""))
                elif isinstance(fq, str):
                    fqdn_list.append(fq)
            assets.append({
                "type": "ip",
                "value": ip_entry.get("ip", ""),
                "source": source_str,
                "details": ", ".join(fqdn_list) if fqdn_list else "",
            })
    seen_domains = set()
    if data.get("domains"):
        for dom in data["domains"]:
            if dom and dom not in seen_domains:
                seen_domains.add(dom)
                assets.insert(len(seen_domains) - 1, {
                    "type": "domain",
                    "value": dom,
                    "source": "root",
                    "details": data.get("company", "") if dom == data.get("domain") else "",
                })
    elif data.get("domain"):
        assets.insert(0, {
            "type": "domain",
            "value": data["domain"],
            "source": "root",
            "details": data.get("company", ""),
        })
    return assets


def _resolve_tool_dir(project, tool_key):
    """Return tool output dir from tool_dirs, falling back to engagement_dir."""
    td = project.get("tool_dirs", {}).get(tool_key)
    if td:
        return td
    eng_dir = project.get("engagement_dir", project.get("project_dir", ""))
    if not eng_dir:
        return None
    if tool_key == "ss3":
        return eng_dir
    return str(Path(eng_dir) / TOOL_OUTPUT_DIRS.get(tool_key, tool_key))


def load_all_targets(project):
    """Load all targets from all tools in a project."""
    result = {"network": [], "osint": []}
    ss3_dir = _resolve_tool_dir(project, "ss3")
    if ss3_dir:
        result["network"] = load_network_targets(ss3_dir)
    if not result["network"]:
        nessus_dir = _resolve_tool_dir(project, "nessus")
        if nessus_dir:
            result["network"] = load_network_targets(nessus_dir)
    osift_dir = _resolve_tool_dir(project, "osift")
    if osift_dir:
        result["osint"] = load_osint_targets(osift_dir)

    excluded = set(project.get("scope_definition", {}).get("exclusions", []))
    if excluded:
        result["network"] = [t for t in result["network"]
                             if t.get("ip", t.get("host", "")) not in excluded]

    return result


def get_target_summary(project):
    """Return summary: total hosts, total ports, total OSINT assets."""
    targets = load_all_targets(project)
    hosts = len(targets["network"])
    ports = sum(len(t.get("ports", [])) for t in targets["network"])
    osint = len(targets["osint"])
    return {"hosts": hosts, "ports": ports, "osint_assets": osint}
