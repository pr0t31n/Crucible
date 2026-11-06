"""Intelligence API routes — structure maps, access matrices, auth status."""

import io
import re
import json
import urllib.parse
from pathlib import Path

from flask import Blueprint, request, jsonify, send_file
from routes._helpers import require_project, get_ext
from services.intel import IntelService
from config import TOOL_OUTPUT_DIRS

intelligence_bp = Blueprint("intelligence", __name__)
_intel = IntelService()

import ipaddress as _ipaddress
import logging as _logging
_intel_log = _logging.getLogger("crucible.routes.intelligence")


def _filter_excluded_intel(data, sm, project):
    """Remove entries with excluded IPs from intelligence data.

    Handles lists of dicts (filter by 'ip'/'host' key) and dicts keyed by IP.
    Top-level only — no recursion into nested port/tool structures.
    """
    if data is None:
        return data

    if isinstance(data, list):
        filtered = []
        for entry in data:
            if not isinstance(entry, dict):
                filtered.append(entry)
                continue
            ip = entry.get("ip") or entry.get("host") or ""
            if ip and sm.is_excluded(project, str(ip)):
                continue
            filtered.append(entry)
        return filtered

    if isinstance(data, dict):
        filtered = {}
        for key, val in data.items():
            if key.startswith("_") or key in ("available", "meta"):
                filtered[key] = val
                continue
            try:
                _ipaddress.ip_address(key)
                if sm.is_excluded(project, key):
                    continue
            except ValueError:
                pass
            filtered[key] = val
        return filtered

    return data


def _filter_oos_intel(data, sm, project):
    """Remove entries whose IP is not in any scope CIDR / IP list.

    Works on the same shapes as _filter_excluded_intel (list-of-dicts with
    'ip'/'host' key, or dict keyed by IP).  Falls through gracefully when
    the project has no scope definition — returns data unchanged.
    Top-level only — no recursion into nested structures.
    """
    if data is None or sm is None:
        return data

    scope_def = project.get("scope_definition", {})
    has_cidrs = bool(scope_def.get("network_cidrs"))
    has_urls = bool(scope_def.get("target_urls"))
    if not has_cidrs and not has_urls:
        return data

    if isinstance(data, list):
        filtered = []
        for entry in data:
            if not isinstance(entry, dict):
                filtered.append(entry)
                continue
            ip = entry.get("ip") or entry.get("host") or ""
            if ip and not sm.is_ip_in_scope(project, str(ip)):
                continue
            filtered.append(entry)
        return filtered

    if isinstance(data, dict):
        filtered = {}
        for key, val in data.items():
            if key.startswith("_") or key in ("available", "meta"):
                filtered[key] = val
                continue
            try:
                _ipaddress.ip_address(key)
                if not sm.is_ip_in_scope(project, key):
                    continue
            except ValueError:
                pass
            filtered[key] = val
        return filtered

    return data


def _slim_host_entry(entry):
    """Project a single host dict to renderer-needed fields only.

    Returns the slim dict, or None if the host has zero confirmed open ports
    and no findings — those hosts are noise for the Host Map.
    """
    raw_ports = entry.get("ports", [])
    confirmed = []
    if isinstance(raw_ports, list):
        for p in raw_ports:
            if isinstance(p, dict):
                if not _is_confirmed_port(p):
                    continue
                confirmed.append({
                    "port": p.get("port", 0),
                    "protocol": p.get("protocol", "tcp"),
                    "service": p.get("service", p.get("name", "")),
                    "state": p.get("state", "open"),
                })
            else:
                confirmed.append(p)
    elif isinstance(raw_ports, dict):
        for pnum, pd in raw_ports.items():
            if isinstance(pd, dict):
                if not _is_confirmed_port(pd):
                    continue
                confirmed.append({
                    "port": pd.get("port", pnum),
                    "protocol": pd.get("protocol", "tcp"),
                    "service": pd.get("service", pd.get("name", "")),
                    "state": pd.get("state", "open"),
                })
            else:
                confirmed.append(pd)
    if not confirmed and not entry.get("finding_count"):
        return None
    return {
        "ip": entry.get("ip", ""),
        "hostname": entry.get("hostname", entry.get("fqdn", "")),
        "os": entry.get("os", entry.get("os_name", entry.get("os_hint", ""))),
        "risk": entry.get("risk", entry.get("top_risk", "")),
        "tools": entry.get("tools", []),
        "first_seen": entry.get("first_seen", ""),
        "alive": entry.get("alive", True),
        "finding_count": entry.get("finding_count", 0),
        "top_risk": entry.get("top_risk", ""),
        "ports": confirmed,
        "port_count": len(confirmed),
    }


def _slim_hosts_payload(data):
    """Project host payloads to renderer fields and drop dead/portless hosts.

    Hosts with zero confirmed open ports and no findings are excluded —
    the Host Map only needs hosts with accessible services.
    """
    if data is None:
        return data

    if isinstance(data, list):
        out = []
        for e in data:
            if not isinstance(e, dict):
                out.append(e)
                continue
            slim = _slim_host_entry(e)
            if slim is not None:
                out.append(slim)
        _intel_log.debug("slim_hosts: %d -> %d hosts (list)",
                         len(data), len(out))
        return out

    if isinstance(data, dict):
        if "hosts" in data:
            result = {}
            for k, v in data.items():
                if k == "hosts":
                    result["hosts"] = _slim_hosts_payload(v)
                elif k.startswith("_") or k in ("meta", "available", "total_ports",
                                                  "os_list", "services"):
                    result[k] = v
                else:
                    try:
                        _ipaddress.ip_address(k)
                        slim = _slim_host_entry(v) if isinstance(v, dict) else v
                        if slim is not None:
                            result[k] = slim
                        continue
                    except ValueError:
                        pass
                    result[k] = v
            return result
        has_ip_keys = False
        for k in data:
            if k.startswith("_") or k in ("available", "meta"):
                continue
            try:
                _ipaddress.ip_address(k)
                has_ip_keys = True
                break
            except ValueError:
                pass
        if has_ip_keys:
            result = {}
            dropped = 0
            for k, v in data.items():
                if k.startswith("_") or k in ("available", "meta"):
                    result[k] = v
                    continue
                try:
                    _ipaddress.ip_address(k)
                    slim = _slim_host_entry(v) if isinstance(v, dict) else v
                    if slim is not None:
                        result[k] = slim
                    else:
                        dropped += 1
                except ValueError:
                    result[k] = v
            _intel_log.debug("slim_hosts: %d -> %d hosts (dict, dropped %d)",
                             len(data), len(result), dropped)
            return result

    return data


def _slim_services_payload(data):
    """Strip heavyweight nested data from service payloads.

    The net-services renderer needs: service name, ip, port, protocol,
    product, version.
    """
    if data is None:
        return data

    _SVC_KEYS = ("ip", "hostname", "port", "protocol", "service",
                 "state", "product", "version", "software", "name")

    if isinstance(data, list):
        slimmed = []
        for entry in data:
            if not isinstance(entry, dict):
                slimmed.append(entry)
                continue
            if "ports" in entry:
                ip = entry.get("ip", "")
                hostname = entry.get("hostname", "")
                for p in entry.get("ports", []):
                    if isinstance(p, dict):
                        slimmed.append({
                            "ip": ip, "hostname": hostname,
                            "port": p.get("port", 0),
                            "protocol": p.get("protocol", "tcp"),
                            "service": p.get("service", p.get("name", "")),
                            "state": p.get("state", "open"),
                            "product": p.get("product", ""),
                            "version": p.get("version", ""),
                        })
            else:
                slimmed.append({k: entry[k] for k in _SVC_KEYS if k in entry})
        return slimmed

    if isinstance(data, dict):
        if "hosts" in data:
            hosts = data["hosts"]
            return _slim_services_payload(
                hosts if isinstance(hosts, list)
                else list(hosts.values()) if isinstance(hosts, dict)
                else hosts
            )
        result = {}
        for k, v in data.items():
            if k.startswith("_") or k in ("available", "meta"):
                result[k] = v
                continue
            if isinstance(v, list):
                result[k] = [
                    {sk: e[sk] for sk in _SVC_KEYS if sk in e}
                    if isinstance(e, dict) else e
                    for e in v
                ]
            else:
                result[k] = v
        return result

    return data


_TOOL_STANDARD_DIRNAME = {
    "ss3": "scattershot3", "osift": "osift", "fracture": "fracture",
    "siphon": "siphon", "auger": "auger", "trawler": "trawler",
    "bastion": "bastion", "forge": "forge", "quill": "quill",
    "isotope": "isotope", "aether": "aether", "aether_b": "aether_b",
    "aether_z": "aether_z", "aether_u": "aether_u",
    "dredge": "dredge",
}


def _resolve_tool_dirs(project, tool_key):
    """Return list of candidate tool output dirs, most specific first."""
    candidates = []
    td = project.get("tool_dirs", {}).get(tool_key)
    if td:
        candidates.append(td)
    eng_dir = project.get("engagement_dir", project.get("project_dir", ""))
    if eng_dir:
        if tool_key == "ss3":
            if eng_dir not in candidates:
                candidates.append(eng_dir)
        else:
            derived = str(Path(eng_dir) / TOOL_OUTPUT_DIRS.get(tool_key, tool_key))
            if derived not in candidates:
                candidates.append(derived)
        std_name = _TOOL_STANDARD_DIRNAME.get(tool_key)
        if std_name:
            std_dir = Path(eng_dir).parent / std_name
            if std_dir.is_dir():
                for sub in sorted(std_dir.iterdir(), reverse=True):
                    if sub.is_dir() and sub.name[0] != '.':
                        s = str(sub)
                        if s not in candidates:
                            candidates.append(s)
                s = str(std_dir)
                if s not in candidates:
                    candidates.append(s)
    return candidates


def _resolve_tool_dir(project, tool_key):
    """Return tool output dir from tool_dirs, falling back to engagement_dir."""
    dirs = _resolve_tool_dirs(project, tool_key)
    return dirs[0] if dirs else None


def _load_with_target_filter(tool_output_dir, filename, target=None):
    """Load JSON with optional per-target subdirectory filtering.
    When target is specified, load from <dir>/<target>/<filename>.
    When omitted, merge all subdirs that contain the file.
    Returns (data, targets_list)."""
    td = Path(tool_output_dir)
    targets = []

    # Find all target subdirs that have this file
    for sub in sorted(td.iterdir()) if td.exists() else []:
        if sub.is_dir() and (sub / filename).exists():
            targets.append(sub.name)

    if target and target in targets:
        fp = td / target / filename
        with open(fp) as f:
            return json.load(f), targets

    # Load from root or merge all
    root_file = td / filename
    if root_file.exists():
        with open(root_file) as f:
            return json.load(f), targets

    # Merge from subdirs
    if targets:
        merged = {}
        for t in targets:
            fp = td / t / filename
            with open(fp) as f:
                data = json.load(f)
            if isinstance(data, dict):
                merged[t] = data
            elif isinstance(data, list):
                merged.setdefault("_items", []).extend(data)
        return merged, targets

    return None, targets


@intelligence_bp.route("/api/structure/<project_id>")
def api_structure(project_id):
    project = require_project(project_id)
    target = request.args.get("target")
    tool = request.args.get("tool", "").lower()
    result = {}

    if tool != "siphon":
        fr_dir = _resolve_tool_dir(project, "fracture")
        if fr_dir:
            data, targets = _load_with_target_filter(fr_dir, "structure_map.json", target)
            result["structure_map"] = data
            result["_targets"] = targets

    if tool != "fracture":
        si_dir = _resolve_tool_dir(project, "siphon")
        if si_dir:
            am_data, _ = _load_with_target_filter(si_dir, "api_map.json", target)
            if isinstance(am_data, dict):
                non_int = {k: v for k, v in am_data.items() if not k.startswith("_")}
                if len(non_int) == 1:
                    am_data = list(non_int.values())[0]
            result["api_map"] = am_data

    return jsonify(result)


@intelligence_bp.route("/api/access-matrix/<project_id>")
def api_access_matrix(project_id):
    project = require_project(project_id)
    target = request.args.get("target")
    tool = request.args.get("tool", "").lower()
    result = {}

    candidates = [tool] if tool in ("fracture", "siphon") else ["fracture", "siphon"]
    for tool_id in candidates:
        td = _resolve_tool_dir(project, tool_id)
        if td:
            data, targets = _load_with_target_filter(td, "access_matrix.json", target)
            if data:
                result["access_matrix"] = data
                result["_targets"] = targets
                break

    return jsonify(result)


@intelligence_bp.route("/api/auth-status/<project_id>")
def api_auth_status(project_id):
    project = require_project(project_id)
    target = request.args.get("target")
    tool = request.args.get("tool", "").lower()
    result = {}

    candidates = [tool] if tool in ("fracture", "siphon") else ["fracture", "siphon"]
    for tool_id in candidates:
        td = _resolve_tool_dir(project, tool_id)
        if td:
            data, targets = _load_with_target_filter(td, "authentication_status.json", target)
            if data:
                if isinstance(data, dict) and "_items" in data:
                    data = data["_items"]
                result["auth_status"] = data
                result["_targets"] = targets
                break

    return jsonify(result)


def _aggregate_cookie_intelligence(project, tool_filter=None):
    """Build cookie intelligence by aggregating authentication_status.json."""
    candidates = ([tool_filter] if tool_filter in ("fracture", "siphon")
                  else ["fracture", "siphon"])
    auth_entries = []
    for tool_id in candidates:
        td = _resolve_tool_dir(project, tool_id)
        if not td:
            continue
        td = Path(td)
        ci_path = td / "cookie_inventory.json"
        if ci_path.exists():
            try:
                data = json.loads(ci_path.read_text())
                if data:
                    return data
            except (json.JSONDecodeError, OSError) as exc:
                _intel_log.debug("cookie_inventory load: %s", exc)
                pass
        for sub in sorted(td.iterdir()) if td.is_dir() else []:
            if sub.is_dir() and (sub / "authentication_status.json").exists():
                try:
                    entries = json.loads(
                        (sub / "authentication_status.json").read_text())
                    if isinstance(entries, list):
                        auth_entries.extend(entries)
                except (json.JSONDecodeError, OSError) as exc:
                    _intel_log.debug("auth_status subdir load: %s", exc)
                    pass
        root_as = td / "authentication_status.json"
        if root_as.exists():
            try:
                entries = json.loads(root_as.read_text())
                if isinstance(entries, list):
                    auth_entries.extend(entries)
            except (json.JSONDecodeError, OSError) as exc:
                _intel_log.debug("auth_status root load: %s", exc)
                pass
        if auth_entries:
            break
    if not auth_entries:
        return None

    cookie_map = {}
    all_role_names = []
    for entry in auth_entries:
        role = entry.get("role", "unknown")
        if role not in all_role_names:
            all_role_names.append(role)
        for ck in entry.get("cookies", []):
            name = ck.get("name", "")
            if not name:
                continue
            if name not in cookie_map:
                cookie_map[name] = {
                    "name": name,
                    "domain": ck.get("domain", ""),
                    "path": ck.get("path", ""),
                    "secure": ck.get("secure", False),
                    "httpOnly": ck.get("httpOnly", False),
                    "samesite": ck.get("samesite", ck.get("sameSite", "")),
                    "expires": ck.get("expires"),
                    "roles": [],
                    "values": {},
                }
            cm = cookie_map[name]
            if role not in cm["roles"]:
                cm["roles"].append(role)
            cm["values"][role] = ck.get("value", "")
            if ck.get("domain"):
                cm["domain"] = ck["domain"]
            if ck.get("path"):
                cm["path"] = ck["path"]
            if ck.get("secure"):
                cm["secure"] = True
            if ck.get("httpOnly"):
                cm["httpOnly"] = True
            ss = ck.get("samesite", ck.get("sameSite", ""))
            if ss and not cm["samesite"]:
                cm["samesite"] = ss

    if not cookie_map:
        return None

    auth_roles = [r for r in all_role_names
                  if r.lower() not in ("unauthenticated", "")]
    n_auth = max(len(auth_roles), 1)

    site_wide = []
    per_role = {}

    for name, cm in sorted(cookie_map.items()):
        first_role = cm["roles"][0] if cm["roles"] else ""
        display_val = cm["values"].get(first_role, "")
        base = {
            "name": cm["name"], "value": display_val,
            "domain": cm["domain"], "path": cm["path"],
            "secure": cm["secure"], "httpOnly": cm["httpOnly"],
            "samesite": cm["samesite"], "expires": cm["expires"],
            "roles": cm["roles"],
        }
        auth_count = sum(1 for r in cm["roles"]
                         if r.lower() not in ("unauthenticated", ""))
        if auth_count >= n_auth and n_auth > 0:
            site_wide.append(base)
        else:
            for role in cm["roles"]:
                per_role.setdefault(role, [])
                role_entry = dict(base)
                role_entry["value"] = cm["values"].get(role, "")
                per_role[role].append(role_entry)

    all_ck = list(cookie_map.values())
    stats = {
        "total": len(all_ck),
        "site_wide": len(site_wide),
        "role_specific": len(all_ck) - len(site_wide),
        "missing_httponly": sum(1 for c in all_ck if not c["httpOnly"]),
        "missing_secure": sum(1 for c in all_ck if not c["secure"]),
        "missing_samesite": sum(1 for c in all_ck if not c.get("samesite")),
        "roles": all_role_names,
    }
    return {
        "cookies": {
            "site_wide": site_wide,
            "per_role": per_role,
            "stats": stats,
        }
    }


@intelligence_bp.route("/api/intel/cookies/<project_id>")
def api_intel_cookies(project_id):
    project = require_project(project_id)
    tool = request.args.get("tool", "").lower()
    data = _aggregate_cookie_intelligence(project, tool_filter=tool or None)
    if data is None:
        return jsonify({"cookies": None, "available": False})
    data["available"] = True
    return jsonify(data)


@intelligence_bp.route("/api/target-profile/<project_id>")
def api_target_profile(project_id):
    project = require_project(project_id)
    target = request.args.get("target")
    result = {}

    fr_dir = _resolve_tool_dir(project, "fracture")
    if fr_dir:
        data, targets = _load_with_target_filter(fr_dir, "target_profile.json", target)
        result["target_profile"] = data
        result["_targets"] = targets

    if not result.get("target_profile"):
        ss3_dir = _resolve_tool_dir(project, "ss3")
        if ss3_dir:
            profile = _build_profile_from_ss3(Path(ss3_dir))
            if profile:
                result["target_profile"] = profile

    return jsonify(result)


import re as _re

_BOGUS_OS_RE = _re.compile(
    r"^(bad gateway|not found|redirect|moved|error|ok|forbidden|unauthorized|n/a)$",
    _re.IGNORECASE,
)


def _is_confirmed_port(p):
    """Return True for ports that are genuinely open (not UDP open|filtered)."""
    if not isinstance(p, dict):
        return True
    state = (p.get("state") or "open").lower()
    if state == "open":
        return True
    if "filtered" in state:
        return False
    return state not in ("closed",)


def _clean_os(os_name):
    """Return empty string for bogus OS values."""
    if not os_name or _BOGUS_OS_RE.match(os_name.strip()):
        return ""
    return os_name


def _build_profile_from_ss3(ss3_dir):
    """Build a target profile from SS3 correlated/inventory data."""
    for scope in ("ext", "int", ""):
        base = ss3_dir / scope if scope else ss3_dir
        for fn in ("correlated.json", "inventory/hosts.json", "targets.json"):
            fp = base / fn
            if not fp.exists():
                continue
            try:
                data = json.loads(fp.read_text())
            except (json.JSONDecodeError, OSError) as exc:
                _intel_log.debug("ss3 profile load: %s", exc)
                continue
            hosts = data if isinstance(data, list) else (
                data.get("hosts") or data.get("targets") or data.get("_items") or [])
            if not isinstance(hosts, list) or not hosts:
                continue
            profile = {"hosts": [], "services": {}, "os_list": [], "total_ports": 0}
            os_seen = set()
            for h in hosts:
                if not isinstance(h, dict):
                    continue
                ip = h.get("ip", h.get("host", ""))
                hostname = h.get("hostname", h.get("fqdn", ""))
                os_name = _clean_os(h.get("os", h.get("os_name", "")))
                all_ports = h.get("ports", [])
                ports = [p for p in all_ports if _is_confirmed_port(p)]
                profile["hosts"].append({
                    "ip": ip, "hostname": hostname, "os": os_name,
                    "port_count": len(ports),
                })
                profile["total_ports"] += len(ports)
                if os_name and os_name not in os_seen:
                    os_seen.add(os_name)
                    profile["os_list"].append(os_name)
                for p in ports:
                    if isinstance(p, dict):
                        svc = p.get("service") or p.get("name") or "unknown"
                        profile["services"].setdefault(svc, 0)
                        profile["services"][svc] += 1
            return profile
    return None


@intelligence_bp.route("/api/access-points/<project_id>")
def api_access_points(project_id):
    project = require_project(project_id)
    ap_dir = _resolve_tool_dir(project, "authprobe")
    data = _intel.get_access_points(ap_dir) if ap_dir else None
    return jsonify({"access_points": data})


@intelligence_bp.route("/api/api-inventory/<project_id>")
def api_api_inventory(project_id):
    project = require_project(project_id)
    si_dir = _resolve_tool_dir(project, "siphon")
    data = None
    if si_dir:
        data, _ = _load_with_target_filter(si_dir, "api_inventory.json")
        if isinstance(data, dict) and "_items" in data:
            data = data["_items"]
    return jsonify({"api_inventory": data})


@intelligence_bp.route("/api/intel/<project_id>")
def api_intel(project_id):
    project = require_project(project_id)
    intel_data = _intel.get_all_intel(project)
    return jsonify(intel_data)


# ── Generic panel route for all tool-specific intelligence sub-tabs ────
# Maps panel name → (tool_key, [candidate filenames to try in order])
_PANEL_MAP = {
    # Bastion (firewall)
    "fw-rules":       ("bastion", ["firewall_rules.json", "rules.json"]),
    "fw-zones":       ("bastion", ["zone_map.json", "zones.json"]),
    "fw-compliance":  ("bastion", ["policy_compliance.json", "compliance.json"]),
    "fw-config":      ("bastion", ["config_summary.json", "config.json"]),
    # Forge (cloud)
    "cloud-resources": ("forge", ["cloud_inventory.json", "resources.json"]),
    "cloud-iam":       ("forge", ["iam_matrix.json", "iam.json"]),
    "cloud-services":  ("forge", ["service_dashboard.json", "services.json"]),
    # Quill (mobile)
    "mobile-components": ("quill", ["component_map.json", "components.json"]),
    "mobile-perms":      ("quill", ["permission_matrix.json", "permissions.json"]),
    "mobile-hardening":  ("quill", ["binary_hardening.json", "hardening.json"]),
    "mobile-data":       ("quill", ["data_flow.json", "data.json"]),
    "mobile-traffic":    ("quill", ["traffic_analysis.json"]),
    "mobile-api":        ("quill", ["api_inventory.json"]),
    "mobile-domains":    ("quill", ["domains.json", "url_domain_analysis.json"]),
    "mobile-emails":     ("quill", ["emails.json", "email_analysis.json"]),
    # Trawler (traffic)
    "traffic-overview": ("trawler", ["traffic.json", "overview.json"]),
    "traffic-convos":   ("trawler", ["conversations.json", "flows.json"]),
    # Scattershot3 (network)
    "net-hosts":    ("ss3", ["inventory/hosts.json", "hosts.json", "correlated.json", "targets.json"]),
    "net-services": ("ss3", ["inventory/services.json", "services.json", "correlated.json", "results.json", "targets.json"]),
    "net-software": ("ss3", ["inventory/software.json", "software_inventory.json"]),
    "net-ports":    ("ss3", ["port_matrix.json", "ports.json", "correlated.json", "inventory/hosts.json", "hosts.json", "targets.json"]),
    "net-roles":    ("ss3", ["server_roles.json"]),
    "net-hostname-env":  ("ss3", ["hostname_intelligence.json"]),
    "net-hostname-apps": ("ss3", ["hostname_intelligence.json"]),
    "net-hostname-hw":   ("ss3", ["hostname_intelligence.json"]),
    "net-posture":       ("ss3", ["network_posture.json"]),
    # OSift (OSINT) — first tries pre-built files, falls back to aggregation
    "osint-domains": ("osift", ["domains.json", "discovered_domains.json", "targets_osint.json"]),
    "osint-dns":     ("osift", ["dns_records.json", "dns.json"]),
    "osint-certs":   ("osift", ["certificates.json", "certs.json"]),
    # Auger (database)
    "db-schema": ("auger", ["db_schema.json", "db_inventory.json", "schema.json"]),
    "db-privs":  ("auger", ["db_privileges.json", "privileges.json"]),
    # Isotope (file analysis)
    "iso-properties": ("isotope", ["properties.json", "file_properties.json"]),
    "iso-entropy":    ("isotope", ["entropy.json", "entropy_analysis.json"]),
    "iso-contents":   ("isotope", ["contents.json", "archive_contents.json"]),
    "iso-strings":    ("isotope", ["strings.json", "string_analysis.json"]),
    "iso-code":       ("isotope", ["code_analysis.json", "code.json"]),
    "iso-metadata":   ("isotope", ["metadata.json", "file_metadata.json"]),
    "iso-binary":     ("isotope", ["binary_analysis.json", "binary.json"]),
    "iso-secrets":    ("isotope", ["secrets.json", "secrets_detection.json"]),
    "iso-ioc":        ("isotope", ["ioc_matches.json", "ioc.json"]),
    # OSINT emails and breaches (aggregated from targets_osint.json)
    "osint-emails":   ("osift", []),
    "osint-breaches": ("osift", ["dehashed_results.json", "breach_results.json"]),
    # OSINT people (employees, phone numbers)
    "osint-people":   ("osift", []),
    # OSINT phone numbers (from people/email intelligence)
    "osint-phones":   ("osift", []),
    # OSINT typosquatting (dnstwist results)
    "osint-typosquat": ("osift", []),
    "osint-wayback":   ("osift", []),
    # Fracture (webapp) — for XLSX export
    "fr-structure":  ("fracture", ["structure_map.json"]),
    "fr-access":     ("fracture", ["access_matrix.json"]),
    "fr-auth":       ("fracture", ["authentication_status.json"]),
    "fr-screenshots": ("fracture", []),
    "webapp-intel":    ("fracture", ["dns_resolution.json", "target_profile.json"]),
    # Siphon (api) — for XLSX export
    "si-structure":  ("siphon", ["api_map.json"]),
    "si-access":     ("siphon", ["access_matrix.json"]),
    "si-auth":       ("siphon", ["authentication_status.json"]),
    "si-api":        ("siphon", ["api_inventory.json"]),
    # Dredge (endpoint)
    "endpoint-overview":   ("dredge", ["endpoint_status.json"]),
    "endpoint-hardening":  ("dredge", ["hardening_results.json"]),
    "endpoint-software":   ("dredge", ["software_inventory.json"]),
    "endpoint-ad":         ("dredge", ["ad_assessment.json"]),
    "endpoint-network":    ("dredge", ["network_posture.json"]),
    "endpoint-browser":    ("dredge", ["browser_audit.json"]),
    # Dredge disk/storage and hardware inventory (v1.3.0+)
    "endpoint-disk":       ("dredge", ["disk_storage_report.json"]),
    "endpoint-hardware":   ("dredge", ["hardware_report.json"]),
    # Dredge compliance assessments (v1.8.0+)
    "endpoint-cis":        ("dredge", ["cis_assessment.json"]),
    "endpoint-nist":       ("dredge", ["nist_assessment.json"]),
    "endpoint-stig":       ("dredge", ["stig_assessment.json"]),
    # Aether (wireless)
    "wifi-aps":            ("aether", ["contextual_intel/inventory.json", "access_points.json"]),
    "wifi-clients":        ("aether", ["contextual_intel/inventory.json", "access_points.json"]),
    "wifi-encryption":     ("aether", ["contextual_intel/inventory.json", "access_points.json"]),
    "wifi-vendors":        ("aether", ["vendor_recon/vendor_inventory.json", "vendor_recon/ap_fingerprints.json", "contextual_intel/inventory.json"]),
    "wifi-channels":       ("aether", ["contextual_intel/inventory.json", "access_points.json"]),
    "wifi-probes":         ("aether", ["contextual_intel/inventory.json", "access_points.json"]),
    "wifi-wps":            ("aether", ["contextual_intel/inventory.json", "access_points.json"]),
    "wifi-firmware":       ("aether", ["firmware_risk.json"]),
}


def _aggregate_osift_domains(td):
    """Build domain data from OSift's reports/targets_osint.json."""
    data = None
    for candidate in (td / "reports" / "targets_osint.json",
                      td / "targets_osint.json"):
        if candidate.exists():
            try:
                data = json.loads(candidate.read_text())
                break
            except (json.JSONDecodeError, OSError) as exc:
                _intel_log.debug("osift targets_osint load: %s", exc)
                pass
    if data is None:
        return None
    primary = data.get("domain", "")
    all_domains = [primary] if primary else []
    domains_dir = td / "domains"
    if domains_dir.is_dir():
        for d in sorted(domains_dir.iterdir()):
            if d.is_dir() and d.name not in all_domains:
                all_domains.append(d.name)
    if len(all_domains) > 1:
        data["domains"] = all_domains
    # Supplement WHOIS data from per-domain _whois.json files if missing
    if not data.get("whois") and domains_dir.is_dir():
        whois_entries = []
        for dname in all_domains:
            for wf in (domains_dir / dname / f"{dname}_whois.json",
                       td / f"{dname}_whois.json"):
                if wf.exists():
                    try:
                        wd = json.loads(wf.read_text())
                        if wd:
                            whois_entries.append({
                                "domain":          dname,
                                "registrar":       wd.get("registrar"),
                                "creation_date":   wd.get("creation_date"),
                                "expiration_date": wd.get("expiration_date"),
                                "updated_date":    wd.get("updated_date"),
                                "name_servers":    wd.get("name_servers") or [],
                                "org":             wd.get("org"),
                                "registrant":      wd.get("registrant"),
                                "privacy_service": wd.get("privacy_service"),
                                "privacy_emails":  wd.get("privacy_emails") or [],
                            })
                        break
                    except (json.JSONDecodeError, OSError) as exc:
                        _intel_log.debug("osift whois load: %s", exc)
                        pass
        if whois_entries:
            data["whois"] = whois_entries
    return data


def _aggregate_osift_dns(td):
    """Aggregate DNS records from per-domain directories."""
    domains_dir = td / "domains"
    if not domains_dir.is_dir():
        return None
    result = {}
    for domain_dir in sorted(domains_dir.iterdir()):
        if not domain_dir.is_dir():
            continue
        domain = domain_dir.name
        records_dir = domain_dir / "dns" / "records"
        if not records_dir.is_dir():
            continue
        for rf in records_dir.glob("*_records.json"):
            try:
                data = json.loads(rf.read_text())
                result[domain] = data
                break
            except (json.JSONDecodeError, OSError) as exc:
                _intel_log.debug("osift dns records load: %s", exc)
                pass
    return result if result else None


def _aggregate_osift_certs(td):
    """Aggregate certificate data from OSift output.

    Sources checked in order:
      1. certificates/parsed/*.json  (per-host parsed certs)
      2. reports/final_report.json → "certificates" key
      3. targets_osint.json → per-IP "certificates" arrays
    """
    parsed_dir = td / "certificates" / "parsed"
    if parsed_dir.is_dir():
        certs = []
        for cf in sorted(parsed_dir.glob("*.json")):
            try:
                data = json.loads(cf.read_text())
                if isinstance(data, dict):
                    data["_host"] = cf.stem
                    certs.append(data)
                elif isinstance(data, list):
                    certs.extend(data)
            except (json.JSONDecodeError, OSError) as exc:
                _intel_log.debug("osift parsed certs load: %s", exc)
                pass
        if certs:
            return certs

    for rp in (td / "reports" / "final_report.json", td / "final_report.json"):
        if rp.exists():
            try:
                report = json.loads(rp.read_text())
                rc = report.get("certificates")
                if rc and isinstance(rc, list):
                    return rc
            except (json.JSONDecodeError, OSError) as exc:
                _intel_log.debug("osift final_report certs load: %s", exc)
                pass

    for tp in (td / "reports" / "targets_osint.json", td / "targets_osint.json"):
        if tp.exists():
            try:
                targets = json.loads(tp.read_text())
                certs = []
                items = targets if isinstance(targets, list) else targets.get("targets", [])
                for t in items:
                    for c in (t.get("certificates") or []):
                        c.setdefault("_host", t.get("ip") or t.get("hostname", ""))
                        certs.append(c)
                if certs:
                    return certs
            except (json.JSONDecodeError, OSError) as exc:
                _intel_log.debug("osift targets_osint certs load: %s", exc)
                pass

    # crt.sh CT log data — transform into renderer-compatible format
    crtsh_paths = [td / "company" / "tools" / "crtsh" / "crtsh_results.json"]
    domains_dir = td / "domains"
    if domains_dir.is_dir():
        for dd in sorted(domains_dir.iterdir()):
            if dd.is_dir():
                crtsh_paths.append(dd / "tools" / "crtsh" / "crtsh_results.json")
    certs = []
    seen = set()
    for cp in crtsh_paths:
        if not cp.exists():
            continue
        try:
            entries = json.loads(cp.read_text())
            if not isinstance(entries, list):
                continue
            for e in entries:
                cn = e.get("common_name") or ""
                serial = e.get("serial_number") or ""
                key = (cn, serial)
                if key in seen:
                    continue
                seen.add(key)
                names = (e.get("name_value") or "").replace("\n", ", ")
                certs.append({
                    "common_name": cn,
                    "issuer": e.get("issuer_name") or "",
                    "not_before": e.get("not_before") or "",
                    "not_after": e.get("not_after") or "",
                    "san": names,
                    "_host": cn,
                })
        except (json.JSONDecodeError, OSError) as exc:
            _intel_log.debug("osift crtsh load: %s", exc)
            pass
    if certs:
        return certs

    return None


def _aggregate_osift_emails(td):
    """Extract emails from targets_osint.json with root domain context."""
    for candidate in (td / "reports" / "targets_osint.json",
                      td / "targets_osint.json"):
        if candidate.exists():
            try:
                data = json.loads(candidate.read_text())
                emails = data.get("emails", [])
                if emails:
                    root_domains = []
                    primary = data.get("domain", "")
                    if primary:
                        root_domains.append(primary)
                    for d in data.get("domains", []):
                        if d and d not in root_domains:
                            root_domains.append(d)
                    domains_dir = td / "domains"
                    if domains_dir.is_dir():
                        for dd in sorted(domains_dir.iterdir()):
                            if dd.is_dir() and dd.name not in root_domains:
                                root_domains.append(dd.name)
                    rd_lower = {d.lower() for d in root_domains}
                    for em in emails:
                        if not isinstance(em, dict):
                            continue
                        addr = (em.get("email") or "").lower()
                        if "@" in addr:
                            domain = addr.rsplit("@", 1)[1]
                            em["in_scope"] = domain in rd_lower
                        else:
                            em["in_scope"] = False
                    return {"emails": emails, "root_domains": root_domains}
            except (json.JSONDecodeError, OSError) as exc:
                _intel_log.debug("osift emails load: %s", exc)
                pass
    return None


def _aggregate_osift_breaches(td):
    """Aggregate Dehashed / breach results from OSift output."""
    for candidate in (td / "reports" / "dehashed_results.json",
                      td / "dehashed_results.json",
                      td / "company" / "breach_data" / "dehashed_results.json",
                      td / "reports" / "breach_results.json"):
        if candidate.exists():
            try:
                data = json.loads(candidate.read_text())
                results = data if isinstance(data, list) else data.get("results", [])
                if results:
                    return {"breaches": results}
            except (json.JSONDecodeError, OSError) as exc:
                _intel_log.debug("osift breaches load: %s", exc)
                pass
    return None


def _aggregate_osift_people(td):
    """Aggregate employee/people data from OSift output."""
    employees = []
    phones = []
    seen_names = set()
    for candidate in (td / "company" / "employees" / "employees.json",
                      td / "employees.json"):
        if candidate.exists():
            try:
                data = json.loads(candidate.read_text())
                if isinstance(data, list):
                    for e in data:
                        key = (e.get("name", ""), e.get("email", ""))
                        if key not in seen_names:
                            seen_names.add(key)
                            employees.append(e)
                break
            except (json.JSONDecodeError, OSError) as exc:
                _intel_log.debug("osift employees load: %s", exc)
                pass
    for candidate in (td / "reports" / "targets_osint.json",
                      td / "targets_osint.json"):
        if candidate.exists():
            try:
                data = json.loads(candidate.read_text())
                ei = data.get("email_intelligence", {})
                for e in ei.get("employees", []):
                    key = (e.get("name", ""), e.get("email", ""))
                    if key not in seen_names:
                        seen_names.add(key)
                        employees.append(e)
                phones.extend(ei.get("phone_numbers", []))
                emails_dict = data.get("emails", [])
                for em in emails_dict:
                    if not isinstance(em, dict):
                        continue
                    phone = em.get("phone_number")
                    if phone and phone not in phones:
                        phones.append(phone)
                    fn = em.get("first_name", "")
                    ln = em.get("last_name", "")
                    if fn or ln:
                        name = f"{fn} {ln}".strip()
                        email_addr = em.get("email", "")
                        key = (name, email_addr)
                        if key not in seen_names:
                            seen_names.add(key)
                            employees.append({
                                "name": name,
                                "email": email_addr,
                                "title": em.get("position", ""),
                                "department": em.get("department", ""),
                                "phone": em.get("phone_number", ""),
                                "linkedin": em.get("linkedin", ""),
                                "source": em.get("source", ""),
                            })
                break
            except (json.JSONDecodeError, OSError) as exc:
                _intel_log.debug("osift people targets_osint load: %s", exc)
                pass
    for candidate in (td / "company" / "people_dorking" / "discovered_people.json",
                      td / "discovered_people.json"):
        if candidate.exists():
            try:
                data = json.loads(candidate.read_text())
                if isinstance(data, list):
                    for p in data:
                        name = p.get("full_name", "")
                        email = p.get("email", "")
                        key = (name, email)
                        if key not in seen_names:
                            seen_names.add(key)
                            employees.append({
                                "name": name,
                                "email": email,
                                "title": "",
                                "department": "",
                                "phone": p.get("phone", ""),
                                "linkedin": "",
                                "source": p.get("source", "people_dorker"),
                            })
                        phone = p.get("phone", "")
                        if phone and phone not in phones:
                            phones.append(phone)
                break
            except (json.JSONDecodeError, OSError) as exc:
                _intel_log.debug("osift discovered_people load: %s", exc)
                pass
    if not employees and not phones:
        return None
    return {"employees": employees, "phone_numbers": phones}


def _aggregate_osift_phones(td):
    """Extract phone numbers matched with names associated with target domains."""
    people_data = _aggregate_osift_people(td)
    if not people_data:
        return None
    root_domains = set()
    for candidate in (td / "reports" / "targets_osint.json",
                      td / "targets_osint.json"):
        if candidate.exists():
            try:
                data = json.loads(candidate.read_text())
                primary = data.get("domain", "")
                if primary:
                    root_domains.add(primary.lower())
                for d in data.get("domains", []):
                    if d:
                        root_domains.add(d.lower())
            except (json.JSONDecodeError, OSError) as exc:
                _intel_log.debug("osift phones domain load: %s", exc)
                pass
            break
    domains_dir = td / "domains"
    if domains_dir.is_dir():
        for dd in sorted(domains_dir.iterdir()):
            if dd.is_dir():
                root_domains.add(dd.name.lower())
    phones = []
    seen = set()
    for emp in people_data.get("employees", []):
        phone = (emp.get("phone") or "").strip()
        if not phone:
            continue
        name = (emp.get("name") or "").strip()
        email = (emp.get("email") or "").strip()
        if not name:
            continue
        associated = False
        if email:
            email_domain = email.rsplit("@", 1)[-1].lower() if "@" in email else ""
            if email_domain and email_domain in root_domains:
                associated = True
        if not associated and root_domains:
            source = (emp.get("source") or "").lower()
            if any(d in source for d in root_domains):
                associated = True
        if not associated:
            linkedin = (emp.get("linkedin") or "").lower()
            if linkedin and any(d in linkedin for d in root_domains):
                associated = True
        if associated and phone not in seen:
            seen.add(phone)
            phones.append({
                "name": name,
                "phone": phone,
                "email": email,
                "title": emp.get("title", ""),
                "source": emp.get("source", ""),
            })
    if not phones:
        return None
    return {"phones": phones}


def _aggregate_osift_typosquat(td):
    """Aggregate dnstwist typosquatting results from OSift output."""
    domains_dir = td / "domains"
    if not domains_dir.is_dir():
        return None
    results = []
    for domain_dir in sorted(domains_dir.iterdir()):
        if not domain_dir.is_dir():
            continue
        twist_dir = domain_dir / "tools" / "dnstwist"
        if not twist_dir.is_dir():
            continue
        for jf in sorted(twist_dir.glob("dnstwist_*.json")):
            try:
                data = json.loads(jf.read_text())
                if not isinstance(data, list):
                    continue
                for entry in data:
                    if entry.get("fuzzer") == "*original":
                        continue
                    dns_a = [v for v in entry.get("dns_a", [])
                             if not str(v).startswith("!")]
                    dns_aaaa = [v for v in entry.get("dns_aaaa", [])
                                if not str(v).startswith("!")]
                    dns_mx = [v for v in entry.get("dns_mx", [])
                              if not str(v).startswith("!")]
                    dns_ns = [v for v in entry.get("dns_ns", [])
                              if not str(v).startswith("!")]
                    if not any((dns_a, dns_aaaa, dns_mx, dns_ns,
                                entry.get("whois_registrar"),
                                entry.get("whois_created"))):
                        continue
                    if dns_mx:
                        risk = "HIGH"
                    elif dns_a:
                        risk = "MEDIUM"
                    elif entry.get("whois_registrar") or entry.get("whois_created"):
                        risk = "MEDIUM"
                    else:
                        risk = "INFO"
                    results.append({
                        "domain": entry.get("domain", ""),
                        "fuzzer": entry.get("fuzzer", ""),
                        "dns_a": dns_a,
                        "dns_aaaa": dns_aaaa,
                        "dns_mx": dns_mx,
                        "dns_ns": dns_ns,
                        "whois_registrar": entry.get("whois_registrar", ""),
                        "whois_created": entry.get("whois_created", ""),
                        "_risk": risk,
                        "_source_domain": domain_dir.name,
                    })
            except (json.JSONDecodeError, OSError) as exc:
                _intel_log.debug("osift dnstwist load: %s", exc)
                pass
    if not results:
        return None
    results.sort(key=lambda d: {"HIGH": 0, "MEDIUM": 1, "INFO": 2}.get(d.get("_risk", "INFO"), 3))
    return {"domains": results}


def _aggregate_osift_wayback(td):
    """Aggregate waybackurls + crawled URL results from OSift output."""
    domains_dir = td / "domains"
    results = []
    seen_domains = set()
    if domains_dir.is_dir():
        for domain_dir in sorted(domains_dir.iterdir()):
            if not domain_dir.is_dir():
                continue
            wb_dir = domain_dir / "tools" / "waybackurls"
            if not wb_dir.is_dir():
                continue
            domain_name = domain_dir.name
            for uf in sorted(wb_dir.glob("wayback_urls_*.txt")):
                try:
                    urls = [u.strip() for u in uf.read_text().splitlines()
                            if u.strip() and u.strip().startswith(("http://", "https://"))]
                except OSError as exc:
                    _intel_log.debug("wayback urls read: %s", exc)
                    continue
                if not urls:
                    continue
                seen_domains.add(domain_name)
                results.append({
                    "domain": domain_name,
                    "url_count": len(urls),
                    "urls": urls,
                })
            for ef in sorted(wb_dir.glob("wayback_endpoints_*.txt")):
                try:
                    endpoints = [e.strip() for e in ef.read_text().splitlines() if e.strip()]
                except OSError as exc:
                    _intel_log.debug("wayback endpoints read: %s", exc)
                    continue
                for r in results:
                    if r["domain"] == domain_name:
                        r["endpoint_count"] = len(endpoints)
                        r["endpoints"] = endpoints
                        break
    for candidate in (td / "reports" / "final_report.json",):
        if not candidate.exists():
            continue
        try:
            data = json.loads(candidate.read_text())
            crawled = data.get("web_intelligence", {}).get("crawled_urls", {})
            if not isinstance(crawled, dict):
                continue
            by_domain = {}
            for url, meta in crawled.items():
                if not url.startswith(("http://", "https://")):
                    continue
                try:
                    from urllib.parse import urlparse
                    domain = urlparse(url).hostname or ""
                except Exception:
                    domain = ""
                if domain:
                    by_domain.setdefault(domain, []).append(url)
            for domain, urls in sorted(by_domain.items()):
                if domain in seen_domains:
                    continue
                results.append({
                    "domain": domain,
                    "url_count": len(urls),
                    "urls": urls,
                })
        except (json.JSONDecodeError, OSError) as exc:
            _intel_log.debug("osift wayback final_report load: %s", exc)
            pass
    if not results:
        return None
    return {"domains": results}



# ── Aether (wireless) aggregators ──────────────────────────────────────────

def _load_wifi_inventory(td):
    """Load the Aether wireless inventory from contextual_intel or root."""
    for candidate in (td / "contextual_intel" / "inventory.json",
                      td / "access_points.json"):
        if candidate.exists():
            data = _safe_load_json(candidate)
            if data:
                return data
    return None


def _safe_load_json(fp):
    try:
        with open(fp) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _aggregate_wifi_aps(td):
    """AP inventory table: BSSID, SSID, vendor, model, encryption, channel, signal, clients."""
    inv = _load_wifi_inventory(td)
    if not inv:
        return None
    aps = inv.get("aps") or inv if isinstance(inv, list) else inv.get("aps", [])
    rows = []
    for ap in aps:
        fp = ap.get("fingerprint") or {}
        rows.append({
            "bssid": ap.get("bssid", ""),
            "ssid": ap.get("ssid") or ap.get("essid", ""),
            "vendor": fp.get("vendor") or ap.get("vendor", "Unknown"),
            "model": fp.get("model", ""),
            "encryption": ap.get("encryption") or ap.get("privacy", ""),
            "cipher": ap.get("cipher", ""),
            "auth": ap.get("auth") or ap.get("authentication", ""),
            "channel": ap.get("channel", ""),
            "signal": ap.get("signal") or ap.get("power", ""),
            "clients": ap.get("client_count") or len(ap.get("clients") or []),
            "wps": ap.get("wps", False),
            "laa": ap.get("laa", False),
        })
    return {"aps": rows, "total": len(rows)}


def _aggregate_wifi_clients(td):
    """Client table: MAC, vendor, associated AP, signal, probed SSIDs."""
    inv = _load_wifi_inventory(td)
    if not inv:
        return None
    clients = inv.get("clients", [])
    if not clients:
        aps = inv.get("aps") or inv if isinstance(inv, list) else inv.get("aps", [])
        for ap in aps:
            for c in (ap.get("clients") or []):
                c_copy = dict(c)
                c_copy["associated_ap"] = ap.get("bssid", "")
                c_copy["associated_ssid"] = ap.get("ssid") or ap.get("essid", "")
                clients.append(c_copy)
    rows = []
    for c in clients:
        probed = c.get("probed") or c.get("probed_essids", [])
        if isinstance(probed, str):
            probed = [s.strip() for s in probed.split(",") if s.strip()]
        rows.append({
            "mac": c.get("mac") or c.get("station", ""),
            "vendor": c.get("vendor", "Unknown"),
            "associated_ap": c.get("associated_ap") or c.get("bssid", ""),
            "associated_ssid": c.get("associated_ssid", ""),
            "signal": c.get("signal") or c.get("power", ""),
            "packets": c.get("packets", 0),
            "probed_ssids": probed,
        })
    return {"clients": rows, "total": len(rows)}


def _aggregate_wifi_encryption(td):
    """Encryption posture breakdown: auth types, cipher distribution."""
    inv = _load_wifi_inventory(td)
    if not inv:
        return None
    aps = inv.get("aps") or inv if isinstance(inv, list) else inv.get("aps", [])
    auth_counts = {}
    cipher_counts = {}
    enc_counts = {}
    for ap in aps:
        enc = (ap.get("encryption") or ap.get("privacy") or "Open").strip()
        auth = (ap.get("auth") or ap.get("authentication") or "").strip() or enc
        cipher = (ap.get("cipher") or "").strip() or "Unknown"
        enc_counts[enc] = enc_counts.get(enc, 0) + 1
        auth_counts[auth] = auth_counts.get(auth, 0) + 1
        cipher_counts[cipher] = cipher_counts.get(cipher, 0) + 1
    return {
        "encryption": sorted(enc_counts.items(), key=lambda x: -x[1]),
        "auth_types": sorted(auth_counts.items(), key=lambda x: -x[1]),
        "ciphers": sorted(cipher_counts.items(), key=lambda x: -x[1]),
        "total_aps": len(aps),
        "open_count": enc_counts.get("Open", 0) + enc_counts.get("OPN", 0),
        "wep_count": enc_counts.get("WEP", 0),
    }


def _aggregate_wifi_vendors(td):
    """Vendor distribution from AP fingerprints."""
    fp_data = _safe_load_json(td / "vendor_recon" / "ap_fingerprints.json")
    inv = _load_wifi_inventory(td)
    if not fp_data and not inv:
        return None
    vendor_counts = {}
    vendor_models = {}
    if fp_data and isinstance(fp_data, list):
        for fp in fp_data:
            v = fp.get("vendor") or "Unknown"
            vendor_counts[v] = vendor_counts.get(v, 0) + 1
            m = fp.get("model", "")
            if m:
                vendor_models.setdefault(v, set()).add(m)
    elif inv:
        aps = inv.get("aps") or inv if isinstance(inv, list) else inv.get("aps", [])
        for ap in aps:
            fp = ap.get("fingerprint") or {}
            v = fp.get("vendor") or ap.get("vendor", "Unknown")
            vendor_counts[v] = vendor_counts.get(v, 0) + 1
            m = fp.get("model", "")
            if m:
                vendor_models.setdefault(v, set()).add(m)
    rows = []
    for v, count in sorted(vendor_counts.items(), key=lambda x: -x[1]):
        rows.append({
            "vendor": v,
            "ap_count": count,
            "models": sorted(vendor_models.get(v, set())),
        })
    return {"vendors": rows, "total": len(rows)}


def _aggregate_wifi_channels(td):
    """Channel analysis: utilisation, overlap, band distribution."""
    inv = _load_wifi_inventory(td)
    if not inv:
        return None
    aps = inv.get("aps") or inv if isinstance(inv, list) else inv.get("aps", [])
    channel_aps = {}
    for ap in aps:
        ch = ap.get("channel")
        if ch is None:
            continue
        try:
            ch = int(str(ch).split("+")[0].split(",")[0])
        except (ValueError, TypeError):
            continue
        channel_aps.setdefault(ch, []).append({
            "bssid": ap.get("bssid", ""),
            "ssid": ap.get("ssid") or ap.get("essid", ""),
            "signal": ap.get("signal") or ap.get("power", ""),
        })
    band_24 = sum(len(v) for k, v in channel_aps.items() if k <= 14)
    band_5 = sum(len(v) for k, v in channel_aps.items() if 36 <= k <= 177)
    band_6 = sum(len(v) for k, v in channel_aps.items() if k > 177)
    channels = []
    for ch in sorted(channel_aps):
        channels.append({
            "channel": ch,
            "band": "2.4 GHz" if ch <= 14 else ("5 GHz" if ch <= 177 else "6 GHz"),
            "ap_count": len(channel_aps[ch]),
            "aps": channel_aps[ch],
        })
    return {
        "channels": channels,
        "band_2_4_count": band_24,
        "band_5_count": band_5,
        "band_6_count": band_6,
        "total_aps": len(aps),
    }


def _aggregate_wifi_probes(td):
    """Probe request intelligence: preferred network lists disclosed by clients."""
    inv = _load_wifi_inventory(td)
    if not inv:
        return None
    probes_set = set()
    ssid_clients = {}
    clients = inv.get("clients", [])
    if not clients:
        aps = inv.get("aps") or inv if isinstance(inv, list) else inv.get("aps", [])
        for ap in aps:
            for c in (ap.get("clients") or []):
                clients.append(c)
    for c in clients:
        probed = c.get("probed") or c.get("probed_essids", [])
        if isinstance(probed, str):
            probed = [s.strip() for s in probed.split(",") if s.strip()]
        mac = c.get("mac") or c.get("station", "")
        for ssid in probed:
            if not ssid:
                continue
            probes_set.add(ssid)
            ssid_clients.setdefault(ssid, set()).add(mac)
    rows = []
    for ssid in sorted(probes_set):
        macs = ssid_clients.get(ssid, set())
        rows.append({
            "ssid": ssid,
            "client_count": len(macs),
            "clients": sorted(macs),
        })
    return {"probed_ssids": rows, "total": len(rows),
            "unique_clients": len({m for ms in ssid_clients.values() for m in ms})}


def _aggregate_wifi_wps(td):
    """WPS exposure: APs with WPS enabled and their lock status."""
    inv = _load_wifi_inventory(td)
    if not inv:
        return None
    aps = inv.get("aps") or inv if isinstance(inv, list) else inv.get("aps", [])
    wps_aps = []
    for ap in aps:
        wps = ap.get("wps")
        wps_data = ap.get("wps_data") or {}
        wps_info = ap.get("wps_info") or {}
        if not wps and not wps_data:
            continue
        wps_aps.append({
            "bssid": ap.get("bssid", ""),
            "ssid": ap.get("ssid") or ap.get("essid", ""),
            "vendor": (ap.get("fingerprint") or {}).get("vendor") or ap.get("vendor", "Unknown"),
            "wps_version": wps_data.get("wps_version", ""),
            "wps_locked": wps_data.get("locked", False),
            "manufacturer": wps_info.get("manufacturer", ""),
            "model_name": wps_info.get("model_name", ""),
            "model_number": wps_info.get("model_number", ""),
            "device_name": wps_info.get("device_name", ""),
        })
    return {"wps_aps": wps_aps, "total": len(wps_aps),
            "locked_count": sum(1 for a in wps_aps if a.get("wps_locked")),
            "unlocked_count": sum(1 for a in wps_aps if not a.get("wps_locked"))}


_WIFI_AGGREGATORS = {
    "wifi_aps": _aggregate_wifi_aps,
    "wifi_clients": _aggregate_wifi_clients,
    "wifi_encryption": _aggregate_wifi_encryption,
    "wifi_vendors": _aggregate_wifi_vendors,
    "wifi_channels": _aggregate_wifi_channels,
    "wifi_probes": _aggregate_wifi_probes,
    "wifi_wps": _aggregate_wifi_wps,
}


_OSIFT_AGGREGATORS = {
    "osint_domains": _aggregate_osift_domains,
    "osint_dns": _aggregate_osift_dns,
    "osint_certs": _aggregate_osift_certs,
    "osint_emails": _aggregate_osift_emails,
    "osint_people": _aggregate_osift_people,
    "osint_phones": _aggregate_osift_phones,
    "osint_breaches": _aggregate_osift_breaches,
    "osint_typosquat": _aggregate_osift_typosquat,
    "osint_wayback": _aggregate_osift_wayback,
}


def _people_from_findings(project_id, project):
    """Extract people data from people-dorking findings when no file exists."""
    try:
        from flask import current_app
        fe = current_app.extensions.get("findings_engine")
        if not fe:
            return None
        findings = fe.get_findings(project_id, project)
        employees = []
        seen = set()
        for f in findings:
            title = f.get("title", "")
            if "people dorking" not in title.lower() and \
               "names discovered" not in title.lower():
                continue
            affected = f.get("affected_locations") or f.get("affected") or ""
            if isinstance(affected, list):
                names = affected
            elif isinstance(affected, str):
                names = [n.strip() for n in affected.split("\n") if n.strip()]
            else:
                continue
            for name in names:
                name = name.strip().strip("-•· ")
                if not name or name.lower() in seen:
                    continue
                seen.add(name.lower())
                employees.append({
                    "name": name, "email": "", "title": "",
                    "department": "", "phone": "",
                    "linkedin": "", "source": "people_dorker",
                })
        if not employees:
            return None
        return {"employees": employees, "phone_numbers": []}
    except Exception as exc:
        _intel_log.warning("people_from_findings: %s", exc)
        return None


def _get_live_targets(project_id, tool_key):
    """Get live targets from ProcessManager if available."""
    try:
        from flask import current_app
        pm = current_app.extensions.get("process_manager")
        if pm and tool_key == "ss3":
            return pm.get_live_targets(project_id)
    except Exception as exc:
        _intel_log.warning("get_live_targets: %s", exc)
        pass
    return None


@intelligence_bp.route("/api/intel/<panel>/<project_id>")
def api_intel_panel(panel, project_id):
    spec = _PANEL_MAP.get(panel)
    if not spec:
        return jsonify({"error": f"Unknown intel panel: {panel}"}), 404
    tool_key, filenames = spec
    project = require_project(project_id)
    all_tool_dirs = _resolve_tool_dirs(project, tool_key)
    key = panel.replace("-", "_")

    # Retroactive exclusion + OOS scope filter + payload projection
    sm = get_ext("scope_manager")
    _net_panels = frozenset(("net-hosts", "net-services", "net-ports"))
    _SLIM_FN = {"net-hosts": _slim_hosts_payload,
                "net-services": _slim_services_payload,
                "net-ports": _slim_hosts_payload}

    def _maybe_filter(d):
        if sm and d is not None:
            d = _filter_excluded_intel(d, sm, project)
            if panel in _net_panels:
                d = _filter_oos_intel(d, sm, project)
        slim = _SLIM_FN.get(panel)
        if slim and d is not None:
            d = slim(d)
        return d

    if not all_tool_dirs:
        return jsonify({key: None, "available": False})
    for tool_dir in all_tool_dirs:
        td = Path(tool_dir)
        if not td.is_dir():
            continue
        search_dirs = [td]
        if tool_key == "ss3":
            for scope in ("ext", "int"):
                sd = td / scope
                if sd.is_dir():
                    search_dirs.append(sd)
        if tool_key == "osift":
            for sub in ("reports", "domains"):
                sd = td / sub
                if sd.is_dir():
                    search_dirs.append(sd)
        if tool_key == "isotope":
            agg = []
            analysis = td / "analysis"
            if analysis.is_dir():
                for sub in sorted(analysis.iterdir()):
                    if not sub.is_dir():
                        continue
                    for fn in filenames:
                        fp = sub / fn
                        if fp.exists():
                            try:
                                with open(fp) as f:
                                    entry = json.load(f)
                                if isinstance(entry, dict):
                                    entry["_source_file"] = sub.name
                                elif isinstance(entry, list):
                                    for e in entry:
                                        if isinstance(e, dict):
                                            e["_source_file"] = sub.name
                                agg.append(entry)
                            except (json.JSONDecodeError, OSError) as exc:
                                _intel_log.debug("isotope analysis load: %s", exc)
                                pass
                            break
            if agg:
                return jsonify({key: _maybe_filter(agg), "available": True})
        if tool_key == "quill":
            agg_apps = []
            for qtd in all_tool_dirs:
                qtd_p = Path(qtd)
                if not qtd_p.is_dir():
                    continue
                _quill_search = [qtd_p]
                for sub in sorted(qtd_p.iterdir()):
                    if sub.is_dir() and sub.name[0] != '.':
                        _quill_search.append(sub)
                for _qsd in _quill_search:
                    for fn in filenames:
                        fp = _qsd / fn
                        if fp.exists():
                            try:
                                with open(fp) as f:
                                    entry = json.load(f)
                                apps = entry.get("apps", []) if isinstance(entry, dict) else []
                                agg_apps.extend(apps)
                            except (json.JSONDecodeError, OSError):
                                pass
                            break
            if agg_apps:
                return jsonify({key: _maybe_filter({"apps": agg_apps}),
                                "available": True})
        file_data = None
        for sd in search_dirs:
            for fn in filenames:
                fp = sd / fn
                if fp.exists():
                    try:
                        raw_size = fp.stat().st_size
                        with open(fp) as f:
                            data = json.load(f)
                        if panel in ("net-services", "net-hosts"):
                            data = _filter_confirmed_ports(data)
                        if data:
                            filtered = _maybe_filter(data)
                            resp = jsonify({key: filtered, "available": True})
                            if panel in _net_panels:
                                _intel_log.info(
                                    "intel %s: file=%s raw=%dKB resp=%dKB",
                                    panel, fn, raw_size // 1024,
                                    resp.content_length // 1024
                                    if resp.content_length else -1)
                            return resp
                        file_data = data
                    except (json.JSONDecodeError, OSError) as exc:
                        _intel_log.debug("panel json load: %s", exc)
                        pass
        aggregator = _OSIFT_AGGREGATORS.get(key)
        if aggregator and tool_key == "osift":
            data = aggregator(td)
            if data is not None:
                return jsonify({key: _maybe_filter(data), "available": True})
        wifi_agg = _WIFI_AGGREGATORS.get(key)
        if wifi_agg and tool_key == "aether":
            data = wifi_agg(td)
            if data is not None:
                return jsonify({key: data, "available": True})
        if file_data is not None:
            return jsonify({key: _maybe_filter(file_data), "available": True})
    # Fallback: people dorking from findings cache
    if panel == "osint-people":
        data = _people_from_findings(project_id, project)
        if data is not None:
            return jsonify({key: _maybe_filter(data), "available": True})
    # Fallback: live targets cache for SS3 host/service panels
    if tool_key == "ss3" and key in ("net_hosts", "net_services", "net_ports"):
        live = _get_live_targets(project_id, tool_key)
        if live:
            live = _maybe_filter(live) or []
            if key == "net_hosts":
                return jsonify({key: live, "available": True})
            elif key == "net_services":
                services = {}
                for host in live:
                    for p in host.get("ports", []):
                        if not _is_confirmed_port(p):
                            continue
                        svc = p.get("service") or "unknown"
                        services.setdefault(svc, []).append({
                            "ip": host["ip"], "port": p["port"],
                            "protocol": p.get("protocol", "tcp"),
                        })
                return jsonify({key: services, "available": True})
            elif key == "net_ports":
                return jsonify({key: {"hosts": live}, "available": True})
    return jsonify({key: None, "available": False})


def _classify_web_page(title, server, status_code):
    """Classify a web page into a human-readable description."""
    t = (title or "").lower()
    s = (server or "").lower()
    sc = status_code or 0

    if sc == 400:
        return "Bad Request (400)"
    if sc == 401:
        return "Unauthorized (401)"
    if sc == 403:
        return "Forbidden (403)"
    if sc == 404 or "404" in t:
        return "Not Found (404)"
    if sc == 405:
        return "Method Not Allowed (405)"
    if sc == 429:
        return "Too Many Requests (429)"
    if sc == 500:
        return "Internal Server Error (500)"
    if sc == 502:
        return "Bad Gateway (502)"
    if sc == 503:
        return "Service Unavailable (503)"
    if 400 <= sc < 500:
        return f"Client Error ({sc})"
    if 500 <= sc < 600:
        return f"Server Error ({sc})"
    if sc == 307:
        return "Redirect (307)"
    if sc == 308:
        return "Redirect (308)"
    if "login" in t or "sign in" in t or "log in" in t or "signin" in t:
        return "Login Page"
    if "dashboard" in t:
        return "Dashboard / Admin Panel"
    if "wordpress" in t or "wp-" in t:
        return "WordPress Site"
    if "iis" in t and "windows" in t:
        return "Default IIS Page"
    if "apache" in t and ("it works" in t or "test page" in t or "default" in t):
        return "Default Apache Page"
    if "nginx" in t and ("welcome" in t or "default" in t):
        return "Default Nginx Page"
    if "default" in t or "welcome" in t or "placeholder" in t:
        return "Default Webpage"
    if "index of" in t:
        return "Directory Listing"
    if "api" in t or "swagger" in t or "openapi" in t:
        return "API Documentation"
    if "too many requests" in t:
        return "Too Many Requests"
    if "bad domain" in t or "domain not found" in t:
        return "Bad Domain"
    if "service unavailable" in t:
        return "Service Unavailable"
    if "error" in t or "exception" in t:
        return "Error Page"
    if not title or title.strip() == "":
        if sc and 200 <= sc < 300:
            return "Web Page (no title)"
        if sc and 300 <= sc < 400:
            return f"Redirect ({sc})"
        return "Blank / Minimal Response"
    if "apache" in s:
        return "Web Page (Apache)"
    if "nginx" in s:
        return "Web Page (Nginx)"
    if "iis" in s or "microsoft" in s:
        return "Web Page (IIS)"
    return "Web Page Detected"


def _classify_web_page_by_path(url_path):
    """URL-path-based classification when title/server/status are unavailable."""
    p = (url_path or "").lower().rstrip("/")
    if not p or p == "/":
        return "Landing Page"
    if any(k in p for k in ("/login", "/signin", "/logon", "/sso", "/auth/", "/oauth")):
        return "Login Page"
    if any(k in p for k in ("/dashboard", "/home", "/landing", "/main", "/portal")):
        return "Landing Page"
    if any(k in p for k in ("/register", "/signup", "/sign-up", "/enroll")):
        return "Registration Page"
    if any(k in p for k in ("/admin", "/wp-admin", "/manage")):
        return "Admin Page"
    if any(k in p for k in ("/api", "/swagger", "/docs", "/openapi")):
        return "API Documentation"
    if any(k in p for k in ("/upload", "/import", "/attach")):
        return "File Upload Page"
    if "error" in p or "404" in p or "not-found" in p or "notfound" in p:
        return "Error Page"
    return "Interesting Page"


_RE_CURL_STATUS = re.compile(r'^Status:\s*(\d+)', re.MULTILINE)
_RE_CURL_SCHEME = re.compile(r'^URL:\s*(https?)://', re.MULTILINE)
_RE_HDR_SERVER = re.compile(r'^Server:\s*(.+)', re.MULTILINE | re.IGNORECASE)
_RE_HTML_TITLE = re.compile(r'<title[^>]*>([^<]+)</title>', re.IGNORECASE)


def _extract_web_meta_from_files(port_dir, ip_dirname, port):
    """Extract web metadata from curl output + index.html in a port dir."""
    meta = {}
    for f in port_dir.iterdir():
        if "_curl_" in f.name and f.suffix == ".txt" and not f.name.endswith(".log"):
            try:
                txt = f.read_text(errors="replace")[:8192]
            except OSError as exc:
                _intel_log.debug("curl output read: %s", exc)
                continue
            m = _RE_CURL_STATUS.search(txt)
            if m:
                meta["status_code"] = int(m.group(1))
            m = _RE_CURL_SCHEME.search(txt)
            if m:
                meta["scheme"] = m.group(1)
            hdr_section = txt
            if "--- HEADERS ---" in txt:
                after = txt.split("--- HEADERS ---", 1)[1]
                if "--- BODY" in after:
                    hdr_section = after.split("--- BODY", 1)[0]
                else:
                    hdr_section = after
            m = _RE_HDR_SERVER.search(hdr_section)
            if m:
                meta["server"] = m.group(1).strip()
            break
    idx = port_dir / "index.html"
    if idx.exists():
        try:
            html = idx.read_text(errors="replace")[:16384]
            m = _RE_HTML_TITLE.search(html)
            if m:
                meta["title"] = m.group(1).strip()
        except OSError as exc:
            _intel_log.debug("index.html read: %s", exc)
            pass
    return meta


def _scan_ss3_screenshots(project, scope_filter):
    """Walk SS3 output dirs for screenshot.png files with web metadata."""
    from config import TOOL_OUTPUT_DIRS
    results = []
    td = project.get("tool_dirs", {}).get("ss3")
    eng = project.get("engagement_dir", project.get("project_dir", ""))
    tool_dirname = TOOL_OUTPUT_DIRS.get("ss3", "scattershot")
    bases = []
    if td:
        bases.append(Path(td))
    if eng:
        ep = Path(eng)
        if not bases or ep.resolve() != bases[0].resolve():
            bases.append(ep)
    if not bases:
        return results
    candidates = []
    for base_dir in bases:
        if not base_dir.is_dir():
            continue
        for scope_label, scope_root_path in [
            ("internal", base_dir / "internal" / tool_dirname),
            ("external", base_dir / "external" / tool_dirname),
            ("internal", base_dir / "internal" / tool_dirname / "int"),
            ("external", base_dir / "external" / tool_dirname / "ext"),
            ("internal", base_dir / "int"),
            ("external", base_dir / "ext"),
        ]:
            if scope_filter and scope_filter != scope_label:
                continue
            if scope_root_path.is_dir():
                candidates.append((scope_label, scope_root_path))
        if (base_dir / "hosts").is_dir():
            lbl = scope_filter or "external"
            candidates.append((lbl, base_dir))
    seen_scopes = set()
    seen_ip_port = set()
    for scope_label, scope_root in candidates:
        if scope_label in seen_scopes:
            continue
        hosts_dir = scope_root / "hosts"
        has_hosts = hosts_dir.is_dir()
        ss_dir = scope_root / "screenshots"
        has_sidecars = ss_dir.is_dir() and any(ss_dir.glob("*.json"))
        if not has_hosts and not has_sidecars:
            continue
        seen_scopes.add(scope_label)

        # Primary: screenshots/ directory with JSON sidecars (SS3 >=1.52.0)
        if has_sidecars:
            for sidecar in sorted(ss_dir.glob("*.json")):
                png = sidecar.with_suffix(".png")
                if not png.is_file():
                    continue
                try:
                    meta = json.loads(sidecar.read_text())
                except (json.JSONDecodeError, OSError):
                    meta = {}
                ip = meta.get("ip", "")
                port = meta.get("port", 0)
                hostname = meta.get("hostname", "")
                scheme = meta.get("scheme", "https" if port == 443 else "http")
                url = meta.get("url", "")
                if not url and (hostname or ip):
                    hp = hostname or ip
                    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
                        url = f"{scheme}://{hp}/"
                    else:
                        url = f"{scheme}://{hp}:{port}/"
                try:
                    rel = str(png.relative_to(scope_root))
                except ValueError:
                    rel = png.name
                seen_ip_port.add((ip, port))
                _sc_desc = meta.get("classification") or meta.get("description", "")
                if _sc_desc:
                    _sc_desc = _sc_desc.replace("Discovery: ", "").replace("Discovery:", "").strip()
                if not _sc_desc:
                    _sc_desc = _classify_web_page(
                        meta.get("page_title") or meta.get("title", ""),
                        meta.get("server", ""),
                        meta.get("status_code"),
                    )
                results.append({
                    "url": url,
                    "ip": ip,
                    "port": port,
                    "scheme": scheme,
                    "title": meta.get("title", ""),
                    "server": meta.get("server", ""),
                    "status_code": meta.get("status_code"),
                    "description": _sc_desc or "Web Page Captured",
                    "scope": scope_label,
                    "screenshot_path": rel,
                    "tool": "ss3",
                })

        # Fallback: walk hosts/<ip>/web/<port>/screenshot.png (pre-1.52.0)
        if not has_hosts:
            continue
        web_meta = {}
        corr_path = scope_root / "correlated.json"
        if corr_path.exists():
            try:
                corr = json.loads(corr_path.read_text())
                hosts_raw = corr if isinstance(corr, list) else corr.get("hosts", [])
                if isinstance(hosts_raw, dict):
                    host_list = list(hosts_raw.values())
                else:
                    host_list = hosts_raw
                for host in host_list:
                    if not isinstance(host, dict):
                        continue
                    ip = host.get("ip", "")
                    ports_raw = host.get("ports", {})
                    if isinstance(ports_raw, dict):
                        port_objs = list(ports_raw.values())
                    else:
                        port_objs = ports_raw
                    for port_obj in port_objs:
                        if not isinstance(port_obj, dict):
                            continue
                        pnum = port_obj.get("port")
                        web = port_obj.get("web")
                        if not web:
                            for tr in port_obj.get("tool_results", []):
                                if tr.get("tool") == "http-probe":
                                    web = tr.get("data", {})
                                    break
                        if web and web.get("responds") is not False and pnum:
                            web_meta[(ip, pnum)] = web
            except (json.JSONDecodeError, OSError) as exc:
                _intel_log.debug("ss3 correlated load: %s", exc)
                pass
        try:
            rel_prefix = str(scope_root.relative_to(base_dir))
        except ValueError:
            rel_prefix = scope_root.name
        for ip_dir in sorted(hosts_dir.iterdir()):
            if not ip_dir.is_dir():
                continue
            web_dir = ip_dir / "web"
            if not web_dir.is_dir():
                continue
            ip = ip_dir.name.replace("_", ".")
            for port_dir in sorted(web_dir.iterdir()):
                if not port_dir.is_dir():
                    continue
                sc_file = port_dir / "screenshot.png"
                if not sc_file.exists():
                    continue
                port = int(port_dir.name) if port_dir.name.isdigit() else 0
                if (ip, port) in seen_ip_port:
                    continue
                wm = web_meta.get((ip, port), {})
                if not wm:
                    wm = _extract_web_meta_from_files(port_dir, ip_dir.name, port)
                scheme = wm.get("scheme", "https" if port == 443 else "http")
                title = wm.get("title", "")
                server = wm.get("server", "")
                status_code = wm.get("status_code")
                hostname = wm.get("hostname", "")
                host_part = hostname or ip
                if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
                    url = f"{scheme}://{host_part}/"
                else:
                    url = f"{scheme}://{host_part}:{port}/"
                rel = f"{rel_prefix}/hosts/{ip_dir.name}/web/{port_dir.name}/screenshot.png"
                results.append({
                    "url": url,
                    "ip": ip,
                    "port": port,
                    "scheme": scheme,
                    "title": title,
                    "server": server,
                    "status_code": status_code,
                    "description": _classify_web_page(title, server, status_code),
                    "scope": scope_label,
                    "screenshot_path": rel,
                    "tool": "ss3",
                })
    return results


def _scan_fracture_screenshots(project, scope_filter=None):
    """Get screenshots from Fracture output directories.

    scope_filter: "external", "internal", or None (all).
    Scope is determined by which scope directory the Fracture output lives in.

    Primary source: <fracture_dir>/screenshots/ directory with JSON sidecars
    (written by Fracture >=2.66.0). Falls back to findings-based PNG extraction
    for older runs.
    """
    results = []
    seen_paths = set()

    scope_dirs_map = project.get("scope_tool_dirs", {})
    fr_candidates = []
    if scope_filter:
        sd = scope_dirs_map.get(scope_filter, {}).get("fracture")
        if sd and Path(sd).is_dir():
            fr_candidates.append((scope_filter, Path(sd)))
    else:
        for sc, tools in scope_dirs_map.items():
            sd = tools.get("fracture")
            if sd and Path(sd).is_dir():
                fr_candidates.append((sc, Path(sd)))

    seen_roots = {str(p) for _, p in fr_candidates}
    fr_dir = project.get("tool_dirs", {}).get("fracture")
    if not fr_dir:
        eng = project.get("engagement_dir", project.get("project_dir", ""))
        if eng:
            fr_dir = str(Path(eng) / "fracture")
    if fr_dir and Path(fr_dir).is_dir() and fr_dir not in seen_roots:
        fr_candidates.append((scope_filter or "webapp", Path(fr_dir)))

    if not fr_candidates:
        return results

    for dir_scope, td in fr_candidates:
        ss_dir = td / "screenshots"
        if ss_dir.is_dir():
            for sidecar in sorted(ss_dir.glob("*.json")):
                png = sidecar.with_suffix(".png")
                if not png.is_file():
                    continue
                try:
                    rel = str(png.relative_to(td))
                except ValueError:
                    continue
                if rel in seen_paths:
                    continue
                seen_paths.add(rel)
                try:
                    meta = json.loads(sidecar.read_text())
                except (json.JSONDecodeError, OSError):
                    meta = {}
                ip = meta.get("ip", "")
                port = meta.get("port", 0)
                hostname = meta.get("hostname", "")
                scheme = meta.get("scheme", "https" if port == 443 else "http")
                _raw_url = meta.get("url", "")
                url = _raw_url.split("\n")[0].strip() if _raw_url else ""
                if not url and (hostname or ip):
                    hp = hostname or ip
                    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
                        url = f"{scheme}://{hp}/"
                    else:
                        url = f"{scheme}://{hp}:{port}/"
                _fr_desc = meta.get("classification") or meta.get("description", "")
                if _fr_desc:
                    _fr_desc = re.sub(
                        r'^(?:Discovery|Recon|Auth|Screenshot|Enumeration)\s*:\s*',
                        '', _fr_desc, flags=re.IGNORECASE).strip()
                    _fr_desc = _fr_desc.replace("Web Screenshot Captured", "").strip(" -—:")
                if not _fr_desc:
                    _fr_page_title = meta.get("page_title") or ""
                    _fr_sidecar_title = meta.get("title", "")
                    if _fr_sidecar_title and _fr_sidecar_title.startswith("Web Screenshot: "):
                        _fr_sidecar_title = ""
                    _fr_desc = _classify_web_page(
                        _fr_page_title or _fr_sidecar_title,
                        meta.get("server", ""),
                        meta.get("status_code"),
                    )
                    if not _fr_desc or _fr_desc == "Blank / Minimal Response":
                        _fr_url_path = ""
                        if url:
                            try:
                                _fr_url_path = urllib.parse.urlparse(url).path or "/"
                            except Exception as exc:
                                _intel_log.warning("fracture url parse: %s", exc)
                                pass
                        _fr_desc = _classify_web_page_by_path(_fr_url_path)
                _fr_page_title_display = meta.get("page_title", "")
                if not _fr_page_title_display:
                    _fr_st = meta.get("title", "")
                    if _fr_st and not _fr_st.startswith("Web Screenshot:"):
                        _fr_page_title_display = _fr_st
                results.append({
                    "url": url,
                    "ip": ip,
                    "port": port,
                    "scheme": scheme,
                    "title": _fr_page_title_display,
                    "server": meta.get("server", ""),
                    "status_code": meta.get("status_code"),
                    "description": _fr_desc or "Web Page Captured",
                    "scope": dir_scope or "webapp",
                    "screenshot_path": rel,
                    "tool": "fracture",
                })

        # Fallback: scan findings for PNG evidence (pre-2.66.0 runs)
        if not (ss_dir.is_dir() and any(ss_dir.glob("*.json"))):
            for fn in ("findings.json",):
                fp = td / fn
                if not fp.exists():
                    continue
                try:
                    data = json.loads(fp.read_text())
                    findings = data if isinstance(data, list) else data.get("findings", [])
                    for f in findings:
                        of = f.get("output_file", "")
                        if not of:
                            continue
                        for part in of.replace("[", "").replace("]", "").replace('"', "").split(","):
                            p = part.strip()
                            if not p.lower().endswith(".png"):
                                continue
                            if p in seen_paths:
                                continue
                            full = td / p
                            if not full.exists():
                                continue
                            seen_paths.add(p)
                            t = f.get("title", "Web Screenshot")
                            f_ip = f.get("ip", "")
                            f_port = f.get("port", 0)
                            f_hn = f.get("hostname", "")
                            _raw_aff = f.get("affected", "")
                            f_aff = _raw_aff.split("\n")[0].strip() if _raw_aff else ""
                            hp = f_hn or f_ip
                            sc = "https" if f_port == 443 else "http"
                            if not f_aff and hp:
                                if (sc == "https" and f_port == 443) or (sc == "http" and f_port == 80):
                                    f_aff = f"{sc}://{hp}/"
                                else:
                                    f_aff = f"{sc}://{hp}:{f_port}/"
                            desc = re.sub(
                                r'^(?:Discovery|Recon|Auth|Screenshot|Enumeration)\s*:\s*',
                                '', t, flags=re.IGNORECASE).strip()
                            desc = desc.replace("Web Screenshot Captured", "").strip(" -—:")
                            if not desc:
                                _fb_url = f_aff or ""
                                _fb_path = ""
                                if _fb_url:
                                    try:
                                        _fb_path = urllib.parse.urlparse(_fb_url).path or "/"
                                    except Exception as exc:
                                        _intel_log.warning("fracture fallback url parse: %s", exc)
                                        pass
                                desc = _classify_web_page_by_path(_fb_path) if _fb_path else "Web Page Captured"
                            results.append({
                                "url": f_aff,
                                "ip": f_ip,
                                "port": f_port,
                                "scheme": sc,
                                "title": "",
                                "server": "",
                                "status_code": None,
                                "description": desc,
                                "scope": dir_scope or "webapp",
                                "screenshot_path": p,
                                "tool": "fracture",
                            })
                except (json.JSONDecodeError, OSError) as exc:
                    _intel_log.debug("fracture findings load: %s", exc)
                    pass

    return results


@intelligence_bp.route("/api/screenshots/<project_id>")
def api_screenshots(project_id):
    """Return screenshot inventory for a scope."""
    project = require_project(project_id)
    scope = request.args.get("scope", "external").lower()
    tool = request.args.get("tool", "").lower()
    screenshots = []
    if tool == "fracture":
        screenshots = _scan_fracture_screenshots(project, scope_filter=scope)
    elif scope in ("external", "internal"):
        screenshots = _scan_ss3_screenshots(project, scope)
        screenshots.extend(_scan_fracture_screenshots(project, scope_filter=scope))
    elif scope == "webapp":
        screenshots = _scan_fracture_screenshots(project)
    else:
        screenshots = _scan_fracture_screenshots(project)
    seen = set()
    deduped = []
    for s in screenshots:
        _u = s.get("url", "")
        _parsed = urllib.parse.urlparse(_u) if _u else None
        _path = ((_parsed.path or "/").rstrip("/") or "/") if _parsed else "/"
        key = (s.get("ip", ""), s.get("port", 0), _path)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(s)

    scope_targets = set()
    for _t in project.get("scope_targets", []):
        if _t and isinstance(_t, str):
            scope_targets.add(_t.strip().lower())
    if scope_targets:
        for s in deduped:
            _ip = s.get("ip", "")
            _hn = s.get("hostname", "")
            _uh = ""
            _su = s.get("url", "")
            if _su:
                try:
                    _uh = urllib.parse.urlparse(_su).hostname or ""
                except Exception as exc:
                    _intel_log.warning("screenshot url parse: %s", exc)
                    pass
            _in_scope = any(
                h.lower() in scope_targets
                for h in (_ip, _hn, _uh) if h
            )
            s["oos"] = not _in_scope

    deduped.sort(key=lambda s: (s.get("ip", ""), s.get("port", 0)))
    return jsonify({"screenshots": deduped, "count": len(deduped)})


@intelligence_bp.route("/api/webapp-intel/<project_id>")
def api_webapp_intel(project_id):
    """Return web application intelligence data (DNS resolution, infrastructure)."""
    try:
        project = require_project(project_id)
        fr_dir = _resolve_tool_dir(project, "fracture")
        result = {"dns": None, "target_profile": None, "infrastructure": {}}
        if not fr_dir:
            return jsonify(result)
        fr_dir = Path(fr_dir)
        dns_path = fr_dir / "dns_resolution.json"
        if dns_path.exists():
            try:
                result["dns"] = json.loads(dns_path.read_text())
            except (json.JSONDecodeError, OSError) as exc:
                _intel_log.debug("dns_resolution load: %s", exc)
                pass
        tp_path = fr_dir / "target_profile.json"
        if tp_path.exists():
            try:
                result["target_profile"] = json.loads(tp_path.read_text())
            except (json.JSONDecodeError, OSError) as exc:
                _intel_log.debug("target_profile load: %s", exc)
                pass
        tp = result.get("target_profile") or {}
        dns = result.get("dns") or {}
        infra = {}
        if tp.get("waf"):
            infra["waf"] = tp["waf"]
        if tp.get("edge_security"):
            infra["edge_security"] = tp["edge_security"]
        if tp.get("cdn"):
            infra["cdn"] = tp["cdn"]
        if dns.get("load_balancer_detected"):
            infra["load_balancer"] = True
            infra["backend_ips"] = dns.get("total_unique_ips", 0)
        if tp.get("tls_enabled") is not None:
            infra["tls_enabled"] = tp["tls_enabled"]
        if tp.get("protocols"):
            infra["tls_protocols"] = tp["protocols"]
        if tp.get("cert_issuer"):
            infra["cert_issuer"] = tp["cert_issuer"]
        if tp.get("cert_expiry"):
            infra["cert_expiry"] = tp["cert_expiry"]
        if tp.get("cert_subject"):
            infra["cert_subject"] = tp["cert_subject"]
        result["infrastructure"] = infra
        return jsonify(result)
    except Exception as _wi_exc:
        import traceback as _tb
        return jsonify({
            "error": str(_wi_exc),
            "traceback": _tb.format_exc(),
            "fr_dir": str(fr_dir) if 'fr_dir' in dir() else None,
        }), 500


_SCOPE_SUBTAB_MAP = {
    "ss3": [
        ("net-hosts", "Host Map"), ("net-services", "Service Matrix"),
        ("net-software", "Software Inventory"), ("net-ports", "Port Heatmap"),
        ("net-roles", "Server Roles"),
        ("net-hostname-env", "Environment Map"),
        ("net-hostname-apps", "Application Inventory"),
        ("net-hostname-hw", "Hardware Inventory"),
        ("net-posture", "Network Posture"),
    ],
    "fracture": [
        ("fr-structure", "WebApp Structure"), ("fr-access", "WebApp Access"),
        ("fr-auth", "WebApp Auth"),
    ],
    "siphon": [
        ("si-structure", "API Structure"), ("si-access", "API Access"),
        ("si-auth", "API Auth"), ("si-api", "API Inventory"),
    ],
    "osift": [
        ("osint-domains", "Domains"), ("osint-dns", "DNS"),
        ("osint-certs", "Certificates"), ("osint-emails", "Emails"),
        ("osint-breaches", "Data Breaches"), ("osint-people", "People"),
        ("osint-phones", "Phone Numbers"), ("osint-wayback", "Wayback URLs"),
        ("osint-typosquat", "Typosquatting"),
    ],
    "trawler": [
        ("traffic-overview", "Traffic Overview"),
        ("traffic-convos", "Conversations"),
    ],
    "auger": [("db-schema", "Schema"), ("db-privs", "Privileges")],
    "bastion": [
        ("fw-rules", "FW Rules"), ("fw-zones", "FW Zones"),
        ("fw-compliance", "FW Compliance"), ("fw-config", "FW Config"),
    ],
    "forge": [
        ("cloud-resources", "Resources"), ("cloud-iam", "IAM"),
        ("cloud-services", "Services"),
    ],
    "quill": [
        ("mobile-components", "Components"), ("mobile-perms", "Permissions"),
        ("mobile-hardening", "Hardening"), ("mobile-data", "Data Flow"),
        ("mobile-traffic", "Traffic"), ("mobile-api", "API Map"),
    ],
    "isotope": [
        ("iso-properties", "Properties"), ("iso-entropy", "Entropy"),
        ("iso-contents", "Contents"), ("iso-strings", "Strings"),
        ("iso-code", "Code"), ("iso-metadata", "Metadata"),
        ("iso-binary", "Binary"), ("iso-secrets", "Secrets"),
        ("iso-ioc", "IOC Matches"),
    ],
}


def _fetch_panel_data(panel_key, project, project_id):
    spec = _PANEL_MAP.get(panel_key)
    if not spec:
        return None
    tool_key, filenames = spec
    all_tool_dirs = _resolve_tool_dirs(project, tool_key)
    if not all_tool_dirs:
        return None
    for tool_dir in all_tool_dirs:
        td = Path(tool_dir)
        if not td.is_dir():
            continue
        search_dirs = [td]
        if tool_key == "ss3":
            for scope in ("ext", "int"):
                sd = td / scope
                if sd.is_dir():
                    search_dirs.append(sd)
        if tool_key == "osift":
            for sub in ("reports", "domains"):
                sd = td / sub
                if sd.is_dir():
                    search_dirs.append(sd)
        for sd in search_dirs:
            for fn in filenames:
                fp = sd / fn
                if fp.exists():
                    try:
                        with open(fp) as f:
                            return json.load(f)
                    except (json.JSONDecodeError, OSError) as exc:
                        _intel_log.debug("panel data load: %s", exc)
                        pass
        if tool_key in ("fracture", "siphon") and filenames:
            merged = {}
            for sub in sorted(td.iterdir()):
                if not sub.is_dir() or sub.name.startswith("."):
                    continue
                for fn in filenames:
                    fp = sub / fn
                    if fp.exists():
                        try:
                            with open(fp) as f:
                                merged[sub.name] = json.load(f)
                        except (json.JSONDecodeError, OSError) as exc:
                            _intel_log.debug("panel subdir load: %s", exc)
                            pass
                        break
            if merged:
                return merged
        key = panel_key.replace("-", "_")
        aggregator = _OSIFT_AGGREGATORS.get(key)
        if aggregator and tool_key == "osift":
            data = aggregator(td)
            if data is not None:
                return data
        wifi_agg = _WIFI_AGGREGATORS.get(key)
        if wifi_agg and tool_key == "aether":
            data = wifi_agg(td)
            if data is not None:
                return data
    return None


def _filter_confirmed_ports(data):
    """Remove open|filtered / closed ports from service/host data."""
    if isinstance(data, list):
        return [e for e in data
                if not isinstance(e, dict) or _is_confirmed_port(e)]
    if isinstance(data, dict):
        for key in list(data):
            v = data[key]
            if isinstance(v, list):
                filtered = [e for e in v
                            if not isinstance(e, dict) or _is_confirmed_port(e)]
                if filtered:
                    data[key] = filtered
                else:
                    del data[key]
    return data


def _aggregate_ss3_services(project, project_id):
    """Build service matrix from SS3 correlated/hosts data (TCP + UDP)."""
    td = _resolve_tool_dir(project, "ss3")
    if not td:
        return None
    td = Path(td)
    for scope in ("ext", "int", ""):
        base = td / scope if scope else td
        for fn in ("correlated.json", "inventory/hosts.json"):
            fp = base / fn
            if not fp.exists():
                continue
            try:
                data = json.loads(fp.read_text())
            except (json.JSONDecodeError, OSError) as exc:
                _intel_log.debug("ss3 services load: %s", exc)
                continue
            hosts = data.get("hosts", data) if isinstance(data, dict) else data
            if isinstance(hosts, dict):
                host_list = [dict(v, ip=k) if isinstance(v, dict) else v
                             for k, v in hosts.items()
                             if k not in ("meta", "_") and isinstance(v, dict)]
            elif isinstance(hosts, list):
                host_list = hosts
            else:
                continue
            services = []
            seen = set()
            for h in host_list:
                if not isinstance(h, dict):
                    continue
                ip = h.get("ip", "")
                hostname = h.get("hostname", "")
                ports = h.get("ports", {})
                if isinstance(ports, dict):
                    port_items = ports.values()
                elif isinstance(ports, list):
                    port_items = ports
                else:
                    continue
                for p in port_items:
                    if not isinstance(p, dict):
                        continue
                    state = (p.get("state") or "").lower()
                    if state != "open":
                        continue
                    port = p.get("port", 0)
                    proto = p.get("protocol", "tcp")
                    svc = p.get("service", "")
                    key = (ip, port, proto)
                    if key in seen:
                        continue
                    seen.add(key)
                    services.append({
                        "ip": ip, "port": port, "protocol": proto,
                        "service": svc, "state": state,
                        "product": p.get("product", ""),
                        "version": p.get("version", ""),
                        "hostname": hostname,
                    })
            if services:
                services.sort(key=lambda s: (s["ip"], s["port"]))
                return services
    return None


def _aggregate_ss3_software(project, project_id):
    """Build software inventory from SS3 data including web technologies."""
    td = _resolve_tool_dir(project, "ss3")
    if not td:
        return None
    td = Path(td)
    software = []
    for scope in ("ext", "int", ""):
        base = td / scope if scope else td
        for fn in ("inventory/software.json", "software_inventory.json"):
            fp = base / fn
            if not fp.exists():
                continue
            try:
                data = json.loads(fp.read_text())
                items = data if isinstance(data, list) else (
                    data.get("software") or data.get("technologies") or [])
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    software.append(item)
            except (json.JSONDecodeError, OSError) as exc:
                _intel_log.debug("ss3 software load: %s", exc)
                pass
        for fn in ("correlated.json", "inventory/hosts.json"):
            fp = base / fn
            if not fp.exists():
                continue
            try:
                data = json.loads(fp.read_text())
            except (json.JSONDecodeError, OSError) as exc:
                _intel_log.debug("ss3 software hosts load: %s", exc)
                continue
            hosts = data.get("hosts", data) if isinstance(data, dict) else data
            if isinstance(hosts, dict):
                host_iter = [(k, v) for k, v in hosts.items()
                             if k not in ("meta", "_") and isinstance(v, dict)]
            elif isinstance(hosts, list):
                host_iter = [(h.get("ip", ""), h) for h in hosts
                             if isinstance(h, dict)]
            else:
                continue
            for ip, h in host_iter:
                ports = h.get("ports", {})
                port_items = ports.values() if isinstance(ports, dict) else (
                    ports if isinstance(ports, list) else [])
                for p in port_items:
                    if not isinstance(p, dict):
                        continue
                    product = p.get("product", "")
                    if not product:
                        continue
                    port = p.get("port", 0)
                    software.append({
                        "software": product,
                        "version": p.get("version", ""),
                        "ip": ip, "port": port,
                        "hostname": h.get("hostname", ""),
                        "method": "nmap service detection",
                        "os": p.get("os", ""),
                    })
    if not software:
        return None
    software = _normalize_software(software)
    software.sort(key=lambda s: (
        s.get("software", "").lower(),
        s.get("version", ""),
        s.get("ip", ""),
        int(s.get("port") or 0),
    ))
    return software


_SW_HTTPD_SUFFIX = re.compile(r'\s+httpd?$')
_SW_MULTI_SPACE = re.compile(r'\s+')


def _normalize_sw_name(name):
    n = (name or "").strip().lower()
    n = n.replace("-", " ")
    n = _SW_HTTPD_SUFFIX.sub('', n)
    n = _SW_MULTI_SPACE.sub(' ', n)
    return n


def _normalize_software(software):
    """Deduplicate software entries by (normalized name, version, ip, port).
    Hostname, detection method and OS merge newline-separated."""
    grouped = {}
    for item in software:
        name = (item.get("software") or "").strip()
        norm = _normalize_sw_name(name)
        version = (item.get("version") or "")
        if version in ("None", "none", "null"):
            version = ""
        ip = item.get("ip", "")
        port = int(item.get("port", 0) or 0)
        key = (norm, version, ip, port)
        if key not in grouped:
            grouped[key] = {
                "software": name if name[0:1].isupper() else name.title(),
                "version": version,
                "ip": ip,
                "port": port,
                "hostnames": set(),
                "methods": set(),
                "os_set": set(),
            }
        g = grouped[key]
        hostname = (item.get("hostname") or "").strip()
        if hostname:
            g["hostnames"].add(hostname)
        method = (item.get("method") or item.get("detection") or "").strip()
        if method:
            g["methods"].add(method)
        os_val = (item.get("os") or "").strip()
        if os_val:
            g["os_set"].add(os_val)
        if not g["software"][0:1].isupper() and name[0:1].isupper():
            g["software"] = name
    result = []
    for g in grouped.values():
        result.append({
            "software": g["software"],
            "version": g["version"],
            "ip": g["ip"],
            "port": str(g["port"]) if g["port"] else "",
            "hostname": "\n".join(sorted(g["hostnames"])),
            "method": "\n".join(sorted(g["methods"])),
            "os": "\n".join(sorted(g["os_set"])),
        })
    return result


def _enrich_host_findings(data, project_id, project):
    """Enrich host map data with finding counts from the findings engine."""
    try:
        fe = get_ext("findings_engine")
        if not fe:
            return data
        correlation = fe.get_host_correlation(project_id, project)
        corr_map = {h["ip"]: h for h in correlation}
    except Exception:
        return data
    if isinstance(data, list):
        for host in data:
            if not isinstance(host, dict):
                continue
            ip = host.get("ip", "")
            corr = corr_map.get(ip)
            if corr:
                host["finding_count"] = corr["total_findings"]
                host["top_risk"] = corr["max_risk"]
    elif isinstance(data, dict):
        for key, val in data.items():
            if isinstance(val, dict):
                ip = val.get("ip", key)
                corr = corr_map.get(ip)
                if corr:
                    val["finding_count"] = corr["total_findings"]
                    val["top_risk"] = corr["max_risk"]
            elif isinstance(val, list):
                for host in val:
                    if not isinstance(host, dict):
                        continue
                    ip = host.get("ip", "")
                    corr = corr_map.get(ip)
                    if corr:
                        host["finding_count"] = corr["total_findings"]
                        host["top_risk"] = corr["max_risk"]
    return data


def _data_to_rows(data):
    if data is None:
        return None, None
    payload = data
    if isinstance(data, dict):
        keys = [k for k in data if k not in ("available", "_")]
        if len(keys) == 1:
            payload = data[keys[0]]
        elif "available" in data:
            payload = {k: v for k, v in data.items() if k != "available"}
    if isinstance(payload, list) and payload and isinstance(payload[0], dict):
        all_keys = []
        for obj in payload:
            for k in obj:
                if k not in all_keys and not k.startswith("_"):
                    all_keys.append(k)
        rows = []
        for obj in payload:
            rows.append([_xlsx_val(obj.get(k)) for k in all_keys])
        return all_keys, rows
    if isinstance(payload, dict):
        nested_lists = {k: v for k, v in payload.items()
                        if isinstance(v, list) and v
                        and isinstance(v[0], dict) and not k.startswith("_")}
        if nested_lists:
            if len(nested_lists) > 1:
                combined = []
                for group_key, items in nested_lists.items():
                    for item in items:
                        row = dict(item)
                        row.setdefault("service_group", group_key)
                        combined.append(row)
                if combined:
                    return _data_to_rows(combined)
            first_key = list(nested_lists.keys())[0]
            return _data_to_rows(nested_lists[first_key])
        all_keys = [k for k in payload if not k.startswith("_")]
        return ["Key", "Value"], [[k, _xlsx_val(payload[k])] for k in all_keys]
    return None, None


def _structure_to_rows(data):
    """Convert structure_map data (per-target or flat) to XLSX rows."""
    if not isinstance(data, dict):
        return None, None
    if "paths" in data:
        headers = ["Path", "Status", "Redirect", "Auth Required", "Source"]
        rows = []
        for path in sorted(data["paths"]):
            info = data["paths"][path]
            if not isinstance(info, dict):
                continue
            rows.append([
                path,
                info.get("status", ""),
                info.get("redirect_to", ""),
                "Yes" if info.get("auth_only") else "",
                info.get("source", ""),
            ])
        return (headers, rows) if rows else (None, None)
    target_keys = sorted(k for k in data if not k.startswith("_"))
    if not target_keys:
        return None, None
    first_val = data.get(target_keys[0])
    if isinstance(first_val, dict) and "paths" in first_val:
        headers = ["Target", "Path", "Status", "Redirect", "Auth Required", "Source"]
        rows = []
        for target in target_keys:
            td = data[target]
            if not isinstance(td, dict):
                continue
            for path in sorted(td.get("paths", {})):
                info = td["paths"][path]
                if not isinstance(info, dict):
                    continue
                rows.append([
                    target, path,
                    info.get("status", ""),
                    info.get("redirect_to", ""),
                    "Yes" if info.get("auth_only") else "",
                    info.get("source", ""),
                ])
        return (headers, rows) if rows else (None, None)
    if isinstance(first_val, dict) and ("methods" in first_val or "rogue" in first_val):
        headers = ["Path", "Methods", "Rogue", "From Spec", "Auth Required"]
        rows = []
        for path in sorted(data):
            if path.startswith("_"):
                continue
            info = data[path]
            if not isinstance(info, dict):
                continue
            methods = ", ".join(sorted(info.get("methods", {}).keys()))
            rows.append([
                path, methods,
                "Yes" if info.get("rogue") else "",
                "Yes" if info.get("from_spec") else "",
                "Yes" if info.get("auth_required") else "",
            ])
        return (headers, rows) if rows else (None, None)
    return None, None


def _access_to_rows(data):
    """Convert access_matrix data (per-target or flat) to XLSX rows."""
    if not isinstance(data, dict):
        return None, None

    def _single(matrix, role_cols, target_label=None):
        items = matrix.get("endpoints") or matrix.get("paths") or []
        if not items:
            return []
        out = []
        for item in items:
            path = item.get("path") or item.get("endpoint") or ""
            row = [target_label, path] if target_label is not None else [path]
            for role in role_cols:
                val = (item.get("access") or {}).get(role)
                if val is None:
                    row.append("")
                elif isinstance(val, bool):
                    row.append("✓" if val else "✗")
                else:
                    row.append(val)
            out.append(row)
        return out

    if "roles" in data or "endpoints" in data or "paths" in data:
        roles = data.get("roles") or []
        headers = ["Path / Endpoint"] + [r if r != "unauthenticated" else "Unauthenticated" for r in roles]
        rows = _single(data, roles)
        return (headers, rows) if rows else (None, None)

    target_keys = sorted(k for k in data if not k.startswith("_"))
    if not target_keys:
        return None, None
    all_roles = []
    for tk in target_keys:
        td = data[tk]
        if isinstance(td, dict):
            for r in td.get("roles") or []:
                if r not in all_roles:
                    all_roles.append(r)
    if not all_roles:
        return None, None
    headers = ["Target", "Path / Endpoint"] + [r if r != "unauthenticated" else "Unauthenticated" for r in all_roles]
    rows = []
    for tk in target_keys:
        td = data[tk]
        if not isinstance(td, dict):
            continue
        rows.extend(_single(td, all_roles, target_label=tk))
    return (headers, rows) if rows else (None, None)


def _xlsx_val(v):
    if v is None:
        return ""
    if isinstance(v, bool):
        return "Yes" if v else "No"
    if isinstance(v, (int, float)):
        return v
    if isinstance(v, list):
        if v and isinstance(v[0], dict):
            return json.dumps(v, separators=(",", ":"))
        return ", ".join(str(x) for x in v)
    if isinstance(v, dict):
        return json.dumps(v, separators=(",", ":"))
    return str(v)


@intelligence_bp.route("/api/export-intel/<project_id>")
def api_export_intel_xlsx(project_id):
    project = require_project(project_id)
    scope_key = request.args.get("scope", "")
    scope_tools_map = project.get("scope_tools") or {}

    scope_display = {
        "external": "External", "internal": "Internal",
        "osint": "OSINT", "webapp": "Web Application",
        "api": "API", "database": "Database",
        "cloud": "Cloud Infrastructure",
        "firewall": "Firewall Config Analysis",
        "mobile": "Mobile Application",
        "file": "File Analysis",
        "endpoint": "Endpoint Security",
        "pcap": "PCAP Analysis",
        "wifi": "Wi-Fi (802.11)",
        "bluetooth": "Bluetooth (802.15.1)",
        "zigbee": "Zigbee (802.15.4)",
        "uwb": "Ultra-Wideband (UWB) (802.15.4z)",
    }

    tool_ids = []
    if scope_key:
        for sk, tids in scope_tools_map.items():
            if sk == "multi":
                continue
            dn = scope_display.get(sk, sk)
            if dn == scope_key or sk == scope_key:
                tool_ids = list(tids or [])
                break

    if not tool_ids:
        return jsonify({"error": "No tools in scope"}), 404

    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill

    wb = Workbook()
    wb.remove(wb.active)
    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill("solid", fgColor="2d3748")
    sheets_added = 0

    _sm_export = get_ext("scope_manager")

    for tid in tool_ids:
        subtabs = _SCOPE_SUBTAB_MAP.get(tid, [])
        for panel_key, sheet_name in subtabs:
            data = _fetch_panel_data(panel_key, project, project_id)
            if panel_key == "net-services":
                agg = _aggregate_ss3_services(project, project_id)
                if agg:
                    data = agg
            elif panel_key == "net-software":
                agg = _aggregate_ss3_software(project, project_id)
                if agg:
                    data = agg
            if data is None:
                continue
            if panel_key in ("net-services", "net-hosts"):
                data = _filter_confirmed_ports(data)
            if panel_key in ("net-hosts", "net-services", "net-ports"):
                if _sm_export:
                    data = _filter_excluded_intel(data, _sm_export, project)
                    data = _filter_oos_intel(data, _sm_export, project)
            if panel_key == "net-hosts":
                data = _enrich_host_findings(data, project_id, project)
            if panel_key in ("fr-structure", "si-structure"):
                headers, rows = _structure_to_rows(data)
            elif panel_key in ("fr-access", "si-access"):
                headers, rows = _access_to_rows(data)
            else:
                headers, rows = _data_to_rows(data)
            if not headers or not rows:
                continue
            safe_name = sheet_name[:31]
            ws = wb.create_sheet(title=safe_name)
            for col_idx, h in enumerate(headers, 1):
                cell = ws.cell(row=1, column=col_idx, value=h)
                cell.font = header_font
                cell.fill = header_fill
            for row_idx, row in enumerate(rows, 2):
                for col_idx, val in enumerate(row, 1):
                    ws.cell(row=row_idx, column=col_idx, value=val)
            for col_idx in range(1, len(headers) + 1):
                ws.column_dimensions[
                    ws.cell(row=1, column=col_idx).column_letter
                ].width = 20
            sheets_added += 1

    if not sheets_added:
        ws = wb.create_sheet(title="No Data")
        ws.cell(row=1, column=1, value="No intelligence data available for this scope.")

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    name = project.get("client_short", "intel")
    safe_scope = scope_key.replace(" ", "_").lower()
    return send_file(
        buf,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True,
        download_name=f"{name}_{safe_scope}_intelligence.xlsx",
    )


# ── Intelligence persistence — save to scope directory as XLSX ──────────
# Uses the same format as the XLSX export, stored per-scope in the
# engagement's scope directory.

def _save_scope_intel_xlsx(project, project_id, scope_key):
    """Build and save an intelligence XLSX for one scope into its directory."""
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill

    scope_tools_map = project.get("scope_tools") or {}
    scope_display = {
        "external": "External", "internal": "Internal",
        "osint": "OSINT", "webapp": "Web Application",
        "api": "API", "database": "Database",
        "cloud": "Cloud Infrastructure",
        "firewall": "Firewall Config Analysis",
        "mobile": "Mobile Application",
        "file": "File Analysis",
        "endpoint": "Endpoint Security",
        "pcap": "PCAP Analysis",
        "wifi": "Wi-Fi (802.11)",
        "bluetooth": "Bluetooth (802.15.1)",
        "zigbee": "Zigbee (802.15.4)",
        "uwb": "Ultra-Wideband (UWB) (802.15.4z)",
    }

    tool_ids = []
    for sk, tids in scope_tools_map.items():
        if sk == "multi":
            continue
        dn = scope_display.get(sk, sk)
        if dn == scope_key or sk == scope_key:
            tool_ids = list(tids or [])
            break

    if not tool_ids:
        return None, "No tools in scope"

    wb = Workbook()
    wb.remove(wb.active)
    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill("solid", fgColor="2d3748")
    sheets_added = 0

    _sm_export = get_ext("scope_manager")

    for tid in tool_ids:
        subtabs = _SCOPE_SUBTAB_MAP.get(tid, [])
        for panel_key, sheet_name in subtabs:
            data = _fetch_panel_data(panel_key, project, project_id)
            if panel_key == "net-services":
                agg = _aggregate_ss3_services(project, project_id)
                if agg:
                    data = agg
            elif panel_key == "net-software":
                agg = _aggregate_ss3_software(project, project_id)
                if agg:
                    data = agg
            if data is None:
                continue
            if panel_key in ("net-services", "net-hosts"):
                data = _filter_confirmed_ports(data)
            if panel_key in ("net-hosts", "net-services", "net-ports"):
                if _sm_export:
                    data = _filter_excluded_intel(data, _sm_export, project)
                    data = _filter_oos_intel(data, _sm_export, project)
            if panel_key == "net-hosts":
                data = _enrich_host_findings(data, project_id, project)
            if panel_key in ("fr-structure", "si-structure"):
                headers, rows = _structure_to_rows(data)
            elif panel_key in ("fr-access", "si-access"):
                headers, rows = _access_to_rows(data)
            else:
                headers, rows = _data_to_rows(data)
            if not headers or not rows:
                continue
            safe_name = sheet_name[:31]
            ws = wb.create_sheet(title=safe_name)
            for col_idx, h in enumerate(headers, 1):
                cell = ws.cell(row=1, column=col_idx, value=h)
                cell.font = header_font
                cell.fill = header_fill
            for row_idx, row in enumerate(rows, 2):
                for col_idx, val in enumerate(row, 1):
                    ws.cell(row=row_idx, column=col_idx, value=val)
            for col_idx in range(1, len(headers) + 1):
                ws.column_dimensions[
                    ws.cell(row=1, column=col_idx).column_letter
                ].width = 20
            sheets_added += 1

    if not sheets_added:
        return None, "No intelligence data for this scope"

    eng_dir = Path(project.get("engagement_dir", project.get("project_dir", "")))
    scope_dir = eng_dir / scope_key
    scope_dir.mkdir(parents=True, exist_ok=True)

    client_short = project.get("client_short", "intel")
    safe_scope = scope_key.replace(" ", "_").lower()
    xlsx_name = f"{client_short}_{safe_scope}_intelligence.xlsx"
    xlsx_path = scope_dir / xlsx_name

    wb.save(str(xlsx_path))
    return str(xlsx_path), None


@intelligence_bp.route("/api/save-intel/<project_id>", methods=["POST"])
def api_save_intel(project_id):
    """Save intelligence XLSX files into scope directories.

    Accepts JSON body with optional ``scope`` key. When scope is given,
    saves only that scope. When omitted, saves all active scopes.
    """
    project = require_project(project_id)
    data = request.get_json(silent=True) or {}
    scope_key = data.get("scope", "").strip()

    active_scopes = project.get("active_scopes", [])
    if scope_key:
        scopes_to_save = [scope_key]
    else:
        scopes_to_save = list(active_scopes)

    if not scopes_to_save:
        return jsonify({"error": "No scopes to save"}), 400

    results = []
    for sk in scopes_to_save:
        path, err = _save_scope_intel_xlsx(project, project_id, sk)
        if err:
            results.append({"scope": sk, "error": err})
        else:
            results.append({"scope": sk, "path": path})

    saved = [r for r in results if "path" in r]
    return jsonify({"ok": len(saved) > 0, "results": results})


@intelligence_bp.route("/api/intel/mitm-cert/<project_id>")
def api_intel_mitm_cert(project_id):
    """Return the mitmproxy CA certificate PEM from a Quill output dir."""
    project = require_project(project_id)
    all_tool_dirs = _resolve_tool_dirs(project, "quill")
    for td_str in all_tool_dirs:
        td = Path(td_str)
        if not td.is_dir():
            continue
        for sub in sorted(td.iterdir(), reverse=True):
            cert = sub / "mitm" / "mitmproxy-ca-cert.pem"
            if cert.exists():
                try:
                    pem = cert.read_text(encoding="utf-8")
                    return jsonify({"available": True, "pem": pem,
                                    "path": str(cert)})
                except OSError:
                    continue
        cert = td / "mitm" / "mitmproxy-ca-cert.pem"
        if cert.exists():
            try:
                pem = cert.read_text(encoding="utf-8")
                return jsonify({"available": True, "pem": pem,
                                "path": str(cert)})
            except OSError:
                pass
    return jsonify({"available": False, "pem": None})


@intelligence_bp.route("/api/intel/mitm-cert/<project_id>/download")
def api_intel_mitm_cert_download(project_id):
    """Download the mitmproxy CA certificate PEM file."""
    project = require_project(project_id)
    all_tool_dirs = _resolve_tool_dirs(project, "quill")
    for td_str in all_tool_dirs:
        td = Path(td_str)
        if not td.is_dir():
            continue
        for sub in sorted(td.iterdir(), reverse=True):
            cert = sub / "mitm" / "mitmproxy-ca-cert.pem"
            if cert.exists():
                return send_file(str(cert), mimetype="application/x-pem-file",
                                 as_attachment=True,
                                 download_name="mitmproxy-ca-cert.pem")
        cert = td / "mitm" / "mitmproxy-ca-cert.pem"
        if cert.exists():
            return send_file(str(cert), mimetype="application/x-pem-file",
                             as_attachment=True,
                             download_name="mitmproxy-ca-cert.pem")
    return jsonify({"error": "MITM CA cert not found"}), 404
