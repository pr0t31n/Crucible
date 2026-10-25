"""Action engine — generation rules, approval tiers, chains.

Generates action items from tool discoveries (port/service/target
findings from Scattershot3, OSift, Fracture, Siphon, etc.) and from
explicit __*_ACTION_ITEM__ protocol tokens.

Approval tiers
--------------
  auto    — queued immediately, no user confirmation
  confirm — shown in the action items panel; user approves before queuing
"""

import ipaddress
import logging
import re
from pathlib import Path

from models.action_items import (add_action_item, get_action_items_by_status,
                                 get_store as _get_ai_store)

log = logging.getLogger("crucible.action_engine")

# ── IP validation for action-item ingestion ──────────────────────────
# Filters out bogus IPs that tools (particularly OSift) mis-extract from
# text: version numbers, dates, DNS resolvers, network/broadcast addrs.

_KNOWN_DNS_RESOLVERS = frozenset({
    "1.1.1.1", "1.0.0.1", "1.0.1.1",
    "8.8.8.8", "8.8.4.4",
    "9.9.9.9", "9.9.9.10",
    "208.67.222.222", "208.67.220.220",
    "64.6.64.6", "64.6.65.6",
    "149.112.112.112",
    "185.228.168.9", "185.228.169.9",
    "77.88.8.8", "77.88.8.1",
    "4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4", "4.2.2.5", "4.2.2.6",
    "76.76.19.19", "76.223.122.150",
    "94.140.14.14", "94.140.15.15",
    "199.85.126.10", "199.85.127.10",
    "156.154.70.1", "156.154.71.1",
})

_IP_OCTET_RE = re.compile(
    r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
)


def _is_valid_target_ip(ip_str):
    """Return True if ip_str is a plausible scan-target IPv4 address.

    Rejects leading-zero octets (date/version artifacts like 07.03.16.06),
    known DNS resolvers, network/broadcast addresses, loopback, multicast,
    and reserved ranges.
    """
    if not ip_str:
        return False
    ip_str = re.sub(r'^https?://', '', ip_str).split('/')[0].split(':')[0]
    m = _IP_OCTET_RE.match(ip_str)
    if not m:
        return True  # hostname — let scope checking handle it
    raw_octets = [m.group(i) for i in range(1, 5)]
    # Leading zeros → date/version artifact (07.03.16.06, 02.06.18.4)
    if any(len(o) > 1 and o[0] == '0' for o in raw_octets):
        return False
    octets = [int(o) for o in raw_octets]
    if any(o > 255 for o in octets):
        return False
    if ip_str in _KNOWN_DNS_RESOLVERS:
        return False
    # Network addresses: x.0.0.0, x.x.0.0 (CIDR /8 and /16 bases)
    if octets[1] == 0 and octets[2] == 0 and octets[3] == 0:
        return False
    if octets[2] == 0 and octets[3] == 0:
        return False
    # Broadcast/network: x.x.x.0
    if octets[3] == 0:
        return False
    # Loopback, link-local, multicast, reserved
    if octets[0] == 127 or octets[0] == 0:
        return False
    if octets[0] >= 224:
        return False
    if octets[0] == 169 and octets[1] == 254:
        return False
    return True


_RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def _is_private_ip(ip_str):
    """Return True if ip_str is an RFC-1918 private address."""
    try:
        addr = ipaddress.ip_address(ip_str.strip())
    except (ValueError, AttributeError) as exc:
        log.debug("_is_private_ip parse failed: %s", exc)
        return False
    return any(addr in net for net in _RFC1918)


def _project_has_internal_scope(project):
    """Return True if the project's active_scopes include internal testing."""
    scopes = (project or {}).get("active_scopes", [])
    return "internal" in scopes


def _split_target(target):
    """Split a multi-value target string into individual parts.

    Handles newline, comma, and space-separated values.  Strips each
    part and drops empties, path-only fragments, and cipher names.
    """
    if not target:
        return []
    parts = re.split(r'[\n,]+', target)
    result = []
    for raw in parts:
        for p in raw.split():
            p = p.strip()
            if not p or p.startswith("/") or p.startswith("RC") \
                    or p.startswith("TLS_") or p.startswith("SSL_"):
                continue
            result.append(p)
    return result if result else [target.strip()]


# ── Category definitions ────────────────────────────────────────────────
# Each maps to a recommended tool, default priority, and approval tier.

CATEGORIES = {
    "webapp_discovered": {
        "recommended_tool": "fracture",
        "priority": "HIGH",
        "approval_tier": "confirm",
        "description": "Web application discovered — run Fracture",
    },
    "api_discovered": {
        "recommended_tool": "siphon",
        "priority": "HIGH",
        "approval_tier": "confirm",
        "description": "API endpoint/spec discovered — run Siphon",
    },
    "db_discovered": {
        "recommended_tool": "auger",
        "priority": "MEDIUM",
        "approval_tier": "confirm",
        "description": "Database service discovered — run Auger",
    },
    "auth_detected": {
        "recommended_tool": "authprobe",
        "priority": "MEDIUM",
        "approval_tier": "auto",
        "description": "Authentication mechanism detected — run AuthProbe",
    },
    "credentials_discovered": {
        "recommended_tool": None,
        "priority": "HIGH",
        "approval_tier": "auto",
        "description": "Credentials discovered — run authenticated scan",
    },
    "wireless_target": {
        "recommended_tool": "aether",
        "priority": "MEDIUM",
        "approval_tier": "confirm",
        "description": "Wireless target identified — run Aether",
    },
    "vuln_scan": {
        "recommended_tool": "nessus",
        "priority": "LOW",
        "approval_tier": "confirm",
        "description": "Host suitable for vulnerability scan",
    },
    "traffic_capture": {
        "recommended_tool": "trawler",
        "priority": "LOW",
        "approval_tier": "auto",
        "description": "Traffic capture available for analysis",
    },
    "retest_needed": {
        "recommended_tool": None,
        "priority": "HIGH",
        "approval_tier": "confirm",
        "description": "Re-test required after remediation",
    },
    "manual_validation": {
        "recommended_tool": None,
        "priority": "HIGH",
        "approval_tier": "confirm",
        "description": "Finding requires manual validation",
    },
    "exploit_available": {
        "recommended_tool": None,
        "priority": "CRITICAL",
        "approval_tier": "confirm",
        "description": "Public exploit available — validate and document",
    },
    "deeper_scan": {
        "recommended_tool": None,
        "priority": "MEDIUM",
        "approval_tier": "confirm",
        "description": "Finding warrants deeper scanning with specialized tool",
    },
    "kev_finding": {
        "recommended_tool": None,
        "priority": "CRITICAL",
        "approval_tier": "confirm",
        "description": "CISA Known Exploited Vulnerability — immediate validation required",
    },
    "oos_target": {
        "recommended_tool": "ss3",
        "priority": "MEDIUM",
        "approval_tier": "confirm",
        "description": "Out-of-scope target discovered — verify scope authorization",
    },
    "endpoint_audit": {
        "recommended_tool": "dredge",
        "priority": "MEDIUM",
        "approval_tier": "confirm",
        "description": "Windows endpoint discovered with remote access — run Dredge",
    },
    "file_analysis": {
        "recommended_tool": "isotope",
        "priority": "HIGH",
        "approval_tier": "confirm",
        "description": "Downloaded file available for deep binary analysis — run Isotope",
    },
    "scan_timeout": {
        "recommended_tool": None,
        "priority": "MEDIUM",
        "approval_tier": "confirm",
        "description": "Tool timed out — re-run with adjusted settings",
    },
}

# ── Credential discovery patterns ──────────────────────────────────────
_CREDENTIAL_PATTERNS = frozenset({
    "default credential", "default password", "default login",
    "weak password", "common password", "weak credentials",
    "brute force success", "credential brute force", "brute-force success",
    "cleartext credential", "credentials in cleartext",
    "hardcoded credential", "embedded credential",
    "authentication bypass", "login bypass",
    "password spray", "credential stuffing",
})

# Service-type → tool mapping for credentialled scans.
_CRED_SERVICE_TOOLS = {
    "http":   "fracture",
    "https":  "fracture",
    "web":    "fracture",
    "api":    "siphon",
    "mysql":  "auger",
    "postgresql": "auger",
    "mssql":  "auger",
    "oracle": "auger",
    "mongodb": "auger",
    "redis":  "auger",
    "cassandra": "auger",
    "couchdb": "auger",
    "elasticsearch": "auger",
}

# ── Service → category mapping ──────────────────────────────────────────

_WEB_SERVICES = frozenset({
    "http", "https", "http-proxy", "http-alt", "https-alt",
})

_WEB_PORTS = frozenset({
    80, 443, 8080, 8443, 8000, 8888, 8008, 8081, 8082, 8180, 8444,
    3000, 3443, 5000, 5001, 9443, 9090, 4443, 8880, 8181,
})

_DB_PORTS = {
    3306: "mysql", 5432: "postgresql", 1433: "mssql",
    1521: "oracle", 27017: "mongodb", 6379: "redis",
    9042: "cassandra", 5984: "couchdb", 5433: "postgresql",
    26257: "cockroachdb", 9200: "elasticsearch",
    3307: "mysql", 5439: "redshift",
}

_DB_SERVICES = frozenset(_DB_PORTS.values())

_API_INDICATORS = frozenset({
    "/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/",
    "swagger", "openapi",
})

_WIRELESS_SERVICES = frozenset({
    "wifi", "bluetooth", "zigbee", "uwb",
})


class ActionEngine:
    """Generate and manage action items from tool discoveries."""

    def __init__(self, scope_manager=None):
        self.scope_manager = scope_manager

    _ASN_RE = re.compile(r'^AS\d+$', re.IGNORECASE)

    def _resolve_in_scope(self, project, target="", ip="",
                          hostname=""):
        """Return True/False for scope membership.  Uses scope_manager
        when available; defaults to True when no scope data exists.

        Checks all provided identifiers — IP against CIDRs/IPs, target
        and hostname against domains/URLs.  Returns True if ANY match.
        Multi-value targets (newline/comma/space separated) are split
        and each part checked individually.
        ASN targets (e.g. AS4373) are skipped — they are not valid
        scan targets and cannot be checked against CIDRs.
        """
        if not project or not self.scope_manager:
            return True
        sm = self.scope_manager
        if ip and sm.is_ip_in_scope(project, ip):
            return True
        if target:
            parts = _split_target(target)
            for p in parts:
                if self._ASN_RE.match(p):
                    continue
                if sm.is_in_scope(project, p):
                    return True
        if hostname and sm.is_in_scope(project, hostname):
            return True
        if not ip and not target and not hostname:
            return True
        return False

    # ── Port discovery → action items ───────────────────────────────────

    def process_port_discovery(self, project_dir, port_data, source_tool,
                               project=None):
        """Generate action items from a discovered port/service.

        Parameters
        ----------
        port_data : dict
            Must contain at least ``ip`` and ``port``.  Optionally
            ``service``, ``hostname``, ``product``, ``version``,
            ``scope`` (propagated from the source tool's registered scope).
        source_tool : str
            Tool ID that discovered the port (e.g. "ss3").
        project : dict | None
            Full project dict for scope checking.
        """
        if source_tool == "ss3":
            return []

        service = (port_data.get("service") or "").lower()
        port = int(port_data.get("port", 0))
        ip = port_data.get("ip", "")
        hostname = port_data.get("hostname", "")
        product = port_data.get("product", "")
        scope = port_data.get("scope", "")
        items = []

        in_scope = True
        if self.scope_manager and project:
            in_scope = self.scope_manager.is_ip_in_scope(project, ip)
            if not in_scope and hostname:
                in_scope = self.scope_manager.is_in_scope(project, hostname)

        # Web services → Fracture
        if service in _WEB_SERVICES or port in _WEB_PORTS:
            scheme = "https" if port in (443, 8443, 9443, 4443, 3443, 8444) \
                or service == "https" else "http"
            item = add_action_item(project_dir, {
                "source_tool": source_tool,
                "recommended_tool": "fracture",
                "category": "webapp_discovered",
                "title": f"Web service on {ip}:{port}",
                "target": f"{scheme}://{ip}:{port}",
                "scope": scope,
                "priority": "HIGH",
                "approval_tier": "confirm",
                "in_scope": in_scope,
                "metadata": {
                    "ip": ip, "port": port, "hostname": hostname,
                    "service": service, "product": product,
                    "scheme": scheme,
                },
            })
            if item:
                items.append(item)

        # DB services → Auger
        if port in _DB_PORTS or service in _DB_SERVICES:
            db_type = _DB_PORTS.get(port, service)
            item = add_action_item(project_dir, {
                "source_tool": source_tool,
                "recommended_tool": "auger",
                "category": "db_discovered",
                "title": f"{db_type.upper()} on {ip}:{port}",
                "target": f"{ip}:{port}",
                "scope": scope,
                "priority": "MEDIUM",
                "approval_tier": "confirm",
                "in_scope": in_scope,
                "metadata": {
                    "ip": ip, "port": port, "hostname": hostname,
                    "db_type": db_type, "product": product,
                },
            })
            if item:
                items.append(item)

        # SSH / auth services → AuthProbe (auto)
        if service in ("ssh", "telnet") or port in (22, 23, 2222):
            item = add_action_item(project_dir, {
                "source_tool": source_tool,
                "recommended_tool": "authprobe",
                "category": "auth_detected",
                "title": f"Auth service ({service or 'ssh'}) on {ip}:{port}",
                "target": f"{ip}:{port}",
                "scope": scope,
                "priority": "MEDIUM",
                "approval_tier": "auto",
                "in_scope": in_scope,
                "metadata": {
                    "ip": ip, "port": port, "hostname": hostname,
                    "service": service,
                },
            })
            if item:
                items.append(item)

        return items

    # ── Target discovery (higher-level) ─────────────────────────────────

    def process_target_discovery(self, project_dir, target_data, source_tool,
                                  project=None):
        """Generate action items from a discovered target.

        Called when SS3/OSift discovers a web service, DB, API, etc.
        ``target_data`` should contain ``ip``, ``ports`` (list of port
        dicts), and optionally ``hostname``, ``scope``.
        """
        items = []
        ip = target_data.get("ip", "")
        hostname = target_data.get("hostname", "")
        scope = target_data.get("scope", "")
        ports = target_data.get("ports", [])

        for port_entry in ports:
            port_entry.setdefault("ip", ip)
            port_entry.setdefault("hostname", hostname)
            if scope:
                port_entry.setdefault("scope", scope)
            result = self.process_port_discovery(
                project_dir, port_entry, source_tool, project=project,
            )
            items.extend(result)

        # URL-based targets (no port list)
        urls = target_data.get("urls", [])
        for url in urls:
            item = add_action_item(project_dir, {
                "source_tool": source_tool,
                "recommended_tool": "fracture",
                "category": "webapp_discovered",
                "title": f"Web target: {url}",
                "target": url,
                "scope": scope,
                "priority": "HIGH",
                "approval_tier": "confirm",
                "in_scope": self._resolve_in_scope(project, target=url),
                "metadata": {"url": url, "hostname": hostname},
            })
            if item:
                items.append(item)

        # API spec targets
        api_specs = target_data.get("api_specs", [])
        for spec in api_specs:
            spec_url = spec if isinstance(spec, str) else spec.get("url", "")
            item = add_action_item(project_dir, {
                "source_tool": source_tool,
                "recommended_tool": "siphon",
                "category": "api_discovered",
                "title": f"API spec: {spec_url}",
                "target": spec_url,
                "scope": scope,
                "priority": "HIGH",
                "approval_tier": "confirm",
                "in_scope": self._resolve_in_scope(project, target=spec_url),
                "metadata": {"spec_url": spec_url},
            })
            if item:
                items.append(item)

        return items

    # ── API indicator detection ─────────────────────────────────────────

    def process_url_discovery(self, project_dir, url, source_tool,
                               project=None, scope=""):
        """Check if a URL looks like an API and generate Siphon item."""
        url_lower = url.lower()
        for indicator in _API_INDICATORS:
            if indicator in url_lower:
                item = add_action_item(project_dir, {
                    "source_tool": source_tool,
                    "recommended_tool": "siphon",
                    "category": "api_discovered",
                    "title": f"API discovered: {url}",
                    "target": url,
                    "scope": scope,
                    "priority": "HIGH",
                    "approval_tier": "confirm",
                    "in_scope": self._resolve_in_scope(project, target=url),
                    "metadata": {"url": url, "indicator": indicator},
                })
                return item
        return None

    # ── Wireless target ─────────────────────────────────────────────────

    def process_wireless_discovery(self, project_dir, wireless_data,
                                    source_tool, project=None):
        """Generate action item for a wireless target.

        ``wireless_data`` should contain ``ssid`` and optionally
        ``bssid``, ``channel``, ``encryption``, ``wireless_type``.
        """
        ssid = wireless_data.get("ssid", "unknown")
        wtype = wireless_data.get("wireless_type", "wifi")

        # Pick the right Aether variant
        tool_map = {
            "wifi": "aether",
            "bluetooth": "aether_b",
            "zigbee": "aether_z",
            "uwb": "aether_u",
        }
        recommended = tool_map.get(wtype, "aether")

        item = add_action_item(project_dir, {
            "source_tool": source_tool,
            "recommended_tool": recommended,
            "category": "wireless_target",
            "title": f"Wireless target: {ssid} ({wtype})",
            "target": ssid,
            "priority": "MEDIUM",
            "approval_tier": "confirm",
            "in_scope": True,
            "metadata": wireless_data,
        })
        return item

    # ── Protocol token handler ──────────────────────────────────────────

    def process_action_item_token(self, project_dir, item_data, project=None):
        """Process an __*_ACTION_ITEM__ token from a tool's stdout.

        The token payload (already JSON-parsed) is passed as
        ``item_data``.  Missing fields are defaulted from the category
        definition.

        When *project* is provided, scope-checks the item's target IP
        against the project's scope definition and sets ``in_scope``.
        """
        title_check = (item_data.get("title") or "").lower()
        if "typosquat" in title_check:
            return None

        category = item_data.get("category", "other")
        cat_defaults = CATEGORIES.get(category, {})

        item_data.setdefault("recommended_tool",
                             cat_defaults.get("recommended_tool"))
        item_data.setdefault("priority",
                             cat_defaults.get("priority", "MEDIUM"))
        item_data.setdefault("approval_tier",
                             cat_defaults.get("approval_tier", "confirm"))

        rt = item_data.get("recommended_tool")
        if rt and rt != rt.lower():
            item_data["recommended_tool"] = rt.lower()

        ip = (item_data.get("ip")
              or (item_data.get("metadata") or {}).get("ip")
              or "")
        target = item_data.get("target", "")

        # Reject bogus IPs (dates, versions, DNS resolvers, network addrs)
        check_ip = ip or target
        if check_ip and not _is_valid_target_ip(check_ip):
            log.info("Rejected action item with invalid IP %r: %s",
                     check_ip, item_data.get("title", ""))
            return None

        # Skip private IPs when project has no internal scope
        if ip and _is_private_ip(ip) and not _project_has_internal_scope(project):
            log.info("Skipped action item with internal IP %s — no internal scope",
                     ip)
            return None

        if project and self.scope_manager and item_data.get("in_scope") is None:
            sm = self.scope_manager
            hostname = (item_data.get("metadata") or {}).get(
                "hostname", "")
            if ip:
                in_s = sm.is_ip_in_scope(project, ip)
                if not in_s and target:
                    in_s = sm.is_in_scope(project, target)
                if not in_s and hostname:
                    in_s = sm.is_in_scope(project, hostname)
                item_data["in_scope"] = in_s
            elif target:
                if "," in target:
                    parts = [t.strip() for t in target.split(",") if t.strip()]
                    item_data["in_scope"] = any(
                        sm.is_in_scope(project, p) for p in parts
                    ) if parts else True
                else:
                    item_data["in_scope"] = sm.is_in_scope(
                        project, target)

            title = (item_data.get("title") or "").lower()
            if "out of scope" in title and item_data.get("in_scope") is True:
                log.info("Suppressed OOS action item for in-scope target: %s",
                         item_data.get("target", ""))
                return None

        return add_action_item(project_dir, item_data)

    # ── Traffic capture handler ─────────────────────────────────────────

    def process_pcap_discovery(self, project_dir, pcap_path, source_tool):
        """Generate action item for a traffic capture file."""
        item = add_action_item(project_dir, {
            "source_tool": source_tool,
            "recommended_tool": "trawler",
            "category": "traffic_capture",
            "title": f"Traffic capture: {Path(pcap_path).name}",
            "target": str(pcap_path),
            "priority": "LOW",
            "approval_tier": "auto",
            "in_scope": True,
            "metadata": {"pcap_path": str(pcap_path)},
        })
        return item

    # ── Retest handler ──────────────────────────────────────────────────

    def process_retest_request(self, project_dir, finding, source_tool):
        """Generate action item for re-testing a remediated finding."""
        tool = finding.get("tool", source_tool)
        title = finding.get("title", "Unknown finding")
        target = finding.get("ip", finding.get("target", ""))

        item = add_action_item(project_dir, {
            "source_tool": source_tool,
            "recommended_tool": tool,
            "category": "retest_needed",
            "title": f"Retest: {title}",
            "target": target,
            "priority": "HIGH",
            "approval_tier": "confirm",
            "in_scope": True,
            "metadata": {
                "original_finding_id": finding.get("id"),
                "original_title": title,
                "original_risk": finding.get("risk"),
            },
        })
        return item

    # ── Finding → Action Items ─────────────────────────────────────────

    _TOOL_DEEPER_MAP = {
        "fracture": {"deeper": "siphon", "manual": ["Burp Suite", "sqlmap", "nuclei"]},
        "siphon": {"deeper": "fracture", "manual": ["Postman", "curl", "jwt_tool"]},
        "ss3": {"deeper": "fracture", "manual": ["nmap scripts", "manual banner grab"]},
        "osift": {"deeper": None, "manual": ["theHarvester", "Shodan", "Censys"]},
        "aether": {"deeper": None, "manual": ["aircrack-ng", "hashcat", "hostapd-wpe"]},
        "aether_b": {"deeper": None, "manual": ["btlejack", "GATTacker", "Bettercap BLE"]},
        "aether_z": {"deeper": None, "manual": ["KillerBee", "Z-Stack sniffer"]},
        "aether_u": {"deeper": None, "manual": ["UWB sniffer"]},
        "auger": {"deeper": None, "manual": ["sqlmap", "manual queries", "DB client"]},
        "bastion": {"deeper": None, "manual": ["manual config review", "CIS benchmark"]},
        "authprobe": {"deeper": "fracture", "manual": ["hydra", "Burp Intruder"]},
        "trawler": {"deeper": None, "manual": ["Wireshark", "tshark", "NetworkMiner"]},
        "nessus": {"deeper": "fracture", "manual": ["Manual CVE validation"]},
        "forge": {"deeper": None, "manual": ["ScoutSuite", "Prowler", "CloudSploit"]},
        "quill": {"deeper": None, "manual": ["MobSF", "frida", "objection"]},
        "isotope": {"deeper": None, "manual": ["binwalk", "strings", "YARA"]},
    }

    _FINDING_TYPE_RECOMMENDATIONS = [
        {
            "patterns": ["sql injection", "sqli", "blind sql", "error-based sql",
                         "time-based sql", "union-based sql", "boolean-based sql"],
            "msf": ["auxiliary/scanner/http/sql_injection",
                    "exploit/multi/http/sql_injection"],
            "tools": ["sqlmap --url {target} --dbs", "sqlmap --url {target} --os-shell"],
            "manual": ["Confirm injection point with sleep-based payload",
                       "Attempt UNION SELECT to enumerate columns",
                       "Try stacked queries for RCE"],
            "github_search": ["sql-injection poc", "sqli bypass waf"],
        },
        {
            "patterns": ["cross-site scripting", "xss", "reflected xss",
                         "stored xss", "dom-based xss", "dom xss"],
            "msf": [],
            "tools": ["dalfox url {target}", "XSStrike -u {target}"],
            "manual": ["Inject <script>alert(1)</script> and verify execution",
                       "Test WAF bypass with encoding variations",
                       "Check for stored XSS via form submission",
                       "Verify DOM XSS with browser DevTools"],
            "github_search": ["xss payload list", "xss bypass waf"],
        },
        {
            "patterns": ["server-side template injection", "ssti",
                         "template injection"],
            "msf": [],
            "tools": ["tplmap -u {target}"],
            "manual": ["Test with {{7*7}} and ${7*7} polyglot payloads",
                       "Identify template engine (Jinja2/Twig/Freemarker/Velocity)",
                       "Attempt RCE via engine-specific payload"],
            "github_search": ["ssti rce payload", "template injection exploit"],
        },
        {
            "patterns": ["command injection", "os command injection",
                         "remote code execution", "rce", "code execution"],
            "msf": ["exploit/multi/http/apache_mod_cgi_bash_env_exec",
                    "exploit/unix/webapp/generic_exec"],
            "tools": ["commix --url {target}"],
            "manual": ["Inject ; id or | id and check response",
                       "Try out-of-band detection with curl/nslookup to collaborator",
                       "Attempt reverse shell with bash -i"],
            "github_search": ["command injection bypass", "rce exploit"],
        },
        {
            "patterns": ["server-side request forgery", "ssrf"],
            "msf": [],
            "tools": [],
            "manual": ["Test with http://127.0.0.1 and http://169.254.169.254",
                       "Try protocol smuggling (gopher://, dict://, file://)",
                       "Attempt cloud metadata access (AWS/Azure/GCP IMDSv1)"],
            "github_search": ["ssrf bypass", "ssrf cloud metadata"],
        },
        {
            "patterns": ["insecure deserialization", "deserialization",
                         "java deserialization", "pickle", "unserialize"],
            "msf": ["exploit/multi/misc/java_rmi_server",
                    "exploit/multi/http/apache_commons_text4shell"],
            "tools": ["ysoserial", "phpggc"],
            "manual": ["Generate payload with ysoserial for target framework",
                       "Test with DNS callback payload first (safe)",
                       "Identify gadget chain via error messages"],
            "github_search": ["deserialization exploit", "ysoserial payload"],
        },
        {
            "patterns": ["file upload", "unrestricted file upload",
                         "arbitrary file upload"],
            "msf": [],
            "tools": [],
            "manual": ["Upload .php/.jsp/.aspx webshell with double extension",
                       "Test content-type bypass (image/png with PHP content)",
                       "Try null byte injection in filename (file.php%00.jpg)",
                       "Check if uploaded files are served from web-accessible path"],
            "github_search": ["webshell upload bypass", "file upload exploit"],
        },
        {
            "patterns": ["path traversal", "directory traversal", "lfi",
                         "local file inclusion", "file inclusion"],
            "msf": ["auxiliary/scanner/http/files_dir",
                    "exploit/unix/webapp/php_include"],
            "tools": ["dotdotpwn -m http -h {target}"],
            "manual": ["Test ../../etc/passwd and ....//....//etc/passwd",
                       "Try null byte (%00) and encoding bypasses",
                       "Attempt log poisoning for RCE via LFI"],
            "github_search": ["lfi to rce", "path traversal bypass"],
        },
        {
            "patterns": ["idor", "insecure direct object reference",
                         "bola", "broken object level authorization"],
            "msf": [],
            "tools": ["autorize (Burp extension)"],
            "manual": ["Access resource with different user's ID/token",
                       "Enumerate object IDs sequentially",
                       "Test horizontal and vertical privilege escalation",
                       "Compare responses between privileged and unprivileged users"],
            "github_search": ["idor automation", "bola testing"],
        },
        {
            "patterns": ["default credential", "default password",
                         "weak password", "common password", "brute force"],
            "msf": ["auxiliary/scanner/ssh/ssh_login",
                    "auxiliary/scanner/http/http_login",
                    "auxiliary/scanner/ftp/ftp_login",
                    "auxiliary/scanner/smb/smb_login"],
            "tools": ["hydra -l admin -P /usr/share/wordlists/rockyou.txt {target}",
                       "medusa -h {target} -u admin -P wordlist.txt -M ssh"],
            "manual": ["Try vendor default credentials from documentation",
                       "Test admin:admin, admin:password, root:toor combinations",
                       "Check for password policy enforcement"],
            "github_search": ["default credentials database", "credential wordlist"],
        },
        {
            "patterns": ["ssl", "tls", "certificate", "weak cipher",
                         "expired cert", "self-signed", "heartbleed",
                         "poodle", "beast", "crime", "breach", "drown"],
            "msf": ["auxiliary/scanner/ssl/openssl_heartbleed",
                    "auxiliary/scanner/ssl/poodle"],
            "tools": ["testssl.sh --full {target}", "sslscan {target}",
                       "sslyze {target}"],
            "manual": ["Verify cipher suite configuration",
                       "Check certificate chain validity",
                       "Test for protocol downgrade attacks"],
            "github_search": [],
        },
        {
            "patterns": ["jwt", "json web token", "jwt bypass",
                         "jwt none algorithm"],
            "msf": [],
            "tools": ["jwt_tool -t {target} -M at",
                       "jwt_tool -t {target} -I -pc name -pv admin"],
            "manual": ["Test 'none' algorithm bypass",
                       "Try key confusion (RS256→HS256) attack",
                       "Brute force HMAC secret with jwt-cracker",
                       "Check for kid header injection"],
            "github_search": ["jwt exploit", "jwt bypass poc"],
        },
        {
            "patterns": ["open redirect", "url redirect", "unvalidated redirect"],
            "msf": [],
            "tools": [],
            "manual": ["Test with //evil.com and \\evil.com bypasses",
                       "Try URL encoding and double encoding",
                       "Chain with OAuth flows for token theft"],
            "github_search": ["open redirect bypass"],
        },
        {
            "patterns": ["csrf", "cross-site request forgery"],
            "msf": [],
            "tools": [],
            "manual": ["Generate CSRF PoC HTML form with auto-submit",
                       "Test if SameSite cookie attribute is enforced",
                       "Verify anti-CSRF token implementation"],
            "github_search": ["csrf poc generator"],
        },
        {
            "patterns": ["xxe", "xml external entity", "xml injection"],
            "msf": [],
            "tools": [],
            "manual": ["Test with <!ENTITY xxe SYSTEM 'file:///etc/passwd'>",
                       "Try out-of-band XXE with external DTD",
                       "Test blind XXE via error-based extraction"],
            "github_search": ["xxe exploit", "xxe oob payload"],
        },
        {
            "patterns": ["smb", "smbv1", "ms17-010", "eternalblue",
                         "smb signing", "null session"],
            "msf": ["exploit/windows/smb/ms17_010_eternalblue",
                    "auxiliary/scanner/smb/smb_ms17_010",
                    "auxiliary/scanner/smb/smb_login",
                    "exploit/windows/smb/psexec"],
            "tools": ["smbclient -L {target} -N", "enum4linux -a {target}",
                       "crackmapexec smb {target}"],
            "manual": ["Test null session authentication",
                       "Enumerate shares and check permissions",
                       "Check SMB signing enforcement"],
            "github_search": ["eternalblue exploit", "smb exploit"],
        },
        {
            "patterns": ["snmp", "snmp community", "snmp default"],
            "msf": ["auxiliary/scanner/snmp/snmp_login",
                    "auxiliary/scanner/snmp/snmp_enum"],
            "tools": ["snmpwalk -v2c -c public {target}",
                       "onesixtyone {target}"],
            "manual": ["Test default community strings (public/private)",
                       "Enumerate system information via SNMP"],
            "github_search": [],
        },
        {
            "patterns": ["ldap", "ldap injection", "anonymous bind",
                         "null bind"],
            "msf": ["auxiliary/gather/ldap_query",
                    "auxiliary/scanner/ldap/ldap_search"],
            "tools": ["ldapsearch -x -H ldap://{target} -b '' -s base"],
            "manual": ["Test anonymous LDAP bind",
                       "Enumerate users and groups via LDAP queries",
                       "Check for LDAP injection in login forms"],
            "github_search": ["ldap injection payload"],
        },
        {
            "patterns": ["kerberos", "as-rep roast", "kerberoast",
                         "golden ticket", "silver ticket"],
            "msf": ["auxiliary/gather/kerberos_enumusers",
                    "exploit/windows/local/kerberos_golden_ticket"],
            "tools": ["impacket-GetNPUsers", "impacket-GetUserSPNs",
                       "Rubeus kerberoast"],
            "manual": ["Attempt AS-REP roasting for accounts without preauth",
                       "Kerberoast service accounts and crack offline",
                       "Check for unconstrained delegation"],
            "github_search": ["kerberoast tool", "as-rep roast"],
        },
        {
            "patterns": ["graphql", "graphql introspection",
                         "graphql injection"],
            "msf": [],
            "tools": ["graphql-voyager", "InQL (Burp extension)",
                       "clairvoyance"],
            "manual": ["Test introspection query: {__schema{types{name}}}",
                       "Enumerate mutations and check authorization",
                       "Test for nested query DoS (batching attacks)"],
            "github_search": ["graphql exploit", "graphql introspection"],
        },
        {
            "patterns": ["crlf injection", "header injection",
                         "http response splitting"],
            "msf": [],
            "tools": ["crlfuzz -u {target}"],
            "manual": ["Inject %0d%0aSet-Cookie:evil=1 in URL parameters",
                       "Test for HTTP response splitting",
                       "Check if session fixation is possible via CRLF"],
            "github_search": ["crlf injection poc"],
        },
        {
            "patterns": ["mass assignment", "parameter pollution",
                         "auto-binding"],
            "msf": [],
            "tools": ["Arjun -u {target}"],
            "manual": ["Add admin=true or role=admin to registration/update requests",
                       "Fuzz hidden parameters with wordlist",
                       "Compare object properties in API responses"],
            "github_search": ["mass assignment exploit"],
        },
    ]

    _SELF_VALIDATED_PATTERNS = frozenset({
        "hostname mismatch", "near expiry", "expired certificate",
        "self-signed", "untrusted ca", "certificate expir",
        "weak cipher", "missing security header", "deprecated protocol",
        "insecure protocol", "non-standard web port",
        "non-standard port for", "open port",
        "hostname identified", "web page identified",
        "software version detected", "ip address identified",
        "missing caa", "missing spf", "missing dmarc", "missing dkim",
        "dmarc policy", "spf soft fail", "dnssec not enabled",
        "zone transfer", "missing caa issuewild",
        "dmarc subdomain policy", "dns: missing",
        "forward secrecy", "cipher suite", "ssl/tls vulnerability",
        "ssl/tls certificate", "ssl/tls ciphers", "ssl/tls obsolete",
        "ssl/tls session", "ssl/tls non-standard", "ssl/tls signature",
        "ssl/tls ocsp", "ssl/tls breach", "ssl/tls lucky13",
        "ssl/tls sweet32", "ssl/tls dns:", "ssl/tls cert_",
        "ssl/tls cookie_", "ssl/tls certificate information",
        "non-standard cipher", "certificate not trusted",
        "technology identified", "header data leakage",
        "software version disclosed", "unknown header",
        "server misconfiguration", "load balancer detected",
        "permissive security header", "missing secure cookie",
        "outdated copyright", "directory listing",
        "o365 tenant detected", "o365 account enumeration",
    })

    _RISK_PRIORITY = {
        "CRITICAL": "CRITICAL", "HIGH": "HIGH",
        "MEDIUM": "MEDIUM", "LOW": "LOW", "INFO": "LOW",
    }

    def _classify_finding(self, title):
        """Match a finding title against known vulnerability types.

        Returns the first matching recommendation dict or None.
        """
        title_lower = title.lower()
        for entry in self._FINDING_TYPE_RECOMMENDATIONS:
            for pattern in entry["patterns"]:
                if pattern in title_lower:
                    return entry
        return None

    def _build_recommendations(self, finding, source_tool, type_rec=None):
        """Build a full recommendations dict for a finding."""
        tool_info = self._TOOL_DEEPER_MAP.get(source_tool, {})
        target = self._finding_target(finding)

        recommendations = {
            "pr0t31n_tools": [],
            "metasploit_modules": [],
            "manual_steps": [],
            "github_pocs": [],
            "alternative_tools": list(tool_info.get("manual", [])),
        }

        if tool_info.get("deeper"):
            recommendations["pr0t31n_tools"].append(tool_info["deeper"])
        recommendations["pr0t31n_tools"].append(source_tool)

        msf_modules = finding.get("metasploit_modules", [])
        if msf_modules:
            recommendations["metasploit_modules"] = list(msf_modules)

        ss_terms = finding.get("searchsploit_terms", [])

        for ed in finding.get("exploit_details", []):
            if isinstance(ed, dict):
                url = ed.get("url", ed.get("reference", ""))
                if url and "github.com" in url:
                    recommendations["github_pocs"].append(url)

        cves = finding.get("cves", "")
        if cves:
            cve_list = [c.strip() for c in cves.split(",") if c.strip()]
            for cve in cve_list[:5]:
                recommendations["manual_steps"].append(
                    f"searchsploit {cve}")
                recommendations["manual_steps"].append(
                    f"nuclei -t cves/ -tags {cve.lower()}")

        if type_rec:
            for m in type_rec.get("msf", []):
                if m not in recommendations["metasploit_modules"]:
                    recommendations["metasploit_modules"].append(m)
            for t in type_rec.get("tools", []):
                cmd = t.replace("{target}", target)
                recommendations["manual_steps"].append(cmd)
            for step in type_rec.get("manual", []):
                recommendations["manual_steps"].append(step)
            for gs in type_rec.get("github_search", []):
                recommendations["github_pocs"].append(
                    f"github.com/search?q={gs.replace(' ', '+')}")

        if finding.get("exploitdb") and ss_terms:
            recommendations["manual_steps"].insert(0,
                f"searchsploit {ss_terms[0]}")
        if msf_modules:
            recommendations["manual_steps"].insert(0,
                f"msfconsole: use {msf_modules[0]}")

        return recommendations

    @staticmethod
    def _finding_target(finding):
        ip = finding.get("ip", "")
        if not ip:
            ip = finding.get("hostname", "") or finding.get("affected", "")
        port = finding.get("port", "")
        if ip and port and str(port) != "0":
            service = (finding.get("service") or "").lower()
            if service in ("https", "ssl/http", "ssl", "ssl/https"):
                scheme = "https"
            elif service in ("http", "http-proxy", "http-alt"):
                scheme = "http"
            else:
                scheme = None
            if scheme:
                port_s = str(port)
                if (scheme == "https" and port_s == "443") or \
                        (scheme == "http" and port_s == "80"):
                    return f"{scheme}://{ip}"
                return f"{scheme}://{ip}:{port}"
            return f"{ip}:{port}"
        return ip

    @staticmethod
    def _add_or_collect(project_dir, item_dict, collector):
        """Add an item immediately or append to a batch collector.

        When ``collector`` is a list, appends and returns the item dict.
        Otherwise calls ``add_action_item()`` which does dedup+persist.
        """
        if collector is not None:
            collector.append(item_dict)
            return item_dict
        return add_action_item(project_dir, item_dict)

    def process_finding(self, project_dir, finding, source_tool,
                        project=None, _collector=None):
        """Auto-generate action items from a security finding.

        Classifies by vulnerability type, risk, exploit flags, and KEV
        status, then attaches specific recommendations (pr0t31n tools,
        Metasploit modules, GitHub PoCs, manual validation steps).

        When ``_collector`` is a list, items are appended to it instead
        of being persisted individually via ``add_action_item()``.
        ``process_completed_findings`` uses this for batch persistence.
        """
        risk = (finding.get("risk") or "INFO").upper()
        title = finding.get("title", "")

        title_lower = title.lower()
        if "typosquat" in title_lower:
            return []

        target = self._finding_target(finding)
        ip = finding.get("ip", "")
        hostname = finding.get("hostname", "")
        scope = finding.get("scope", "")
        in_scope = self._resolve_in_scope(
            project, target=target, ip=ip, hostname=hostname)
        items = []

        # Credential findings get their own processing path
        if self._is_credential_finding(finding):
            cred_items = self.process_credential_discovery(
                project_dir, finding, source_tool, project,
                _collector=_collector)
            items.extend(cred_items)

        if not in_scope and ip:
            if not _is_valid_target_ip(ip):
                return items
            if _is_private_ip(ip) and not _project_has_internal_scope(project):
                return items
            oos_mode = (project or {}).get("oos_handling", "explicit")
            _hostname = finding.get("hostname", "")
            eligible = bool(
                oos_mode != "explicit"
                and self.scope_manager
                and self.scope_manager.is_oos_eligible(
                    project, hostname=_hostname, ip_str=ip)
            )
            tier = "auto" if eligible else "confirm"
            _oos_rec = "ss3"
            if scope in ("webapp", "fr"):
                _oos_rec = "fracture"
            elif scope in ("api", "si"):
                _oos_rec = "siphon"
            item = self._add_or_collect(project_dir, {
                "source_tool": source_tool,
                "recommended_tool": _oos_rec,
                "category": "oos_target",
                "title": f"Out of Scope IP Identified: {ip}",
                "target": ip,
                "ip": ip,
                "scope": scope,
                "priority": "HIGH" if risk in ("CRITICAL", "HIGH") and eligible
                           else "MEDIUM" if eligible else "LOW",
                "approval_tier": tier,
                "in_scope": False,
                "metadata": {
                    "finding_id": finding.get("id"),
                    "hostname": _hostname,
                    "oos_eligible": eligible,
                    "original_title": title,
                    "original_risk": risk,
                },
            }, _collector)
            if item:
                items.append(item)
            return items

        if risk in ("LOW", "INFO") and not finding.get("exploitdb") \
                and not finding.get("metasploit") and not finding.get("kev"):
            return items

        priority = self._RISK_PRIORITY.get(risk, "MEDIUM")
        type_rec = self._classify_finding(title)
        recommendations = self._build_recommendations(
            finding, source_tool, type_rec)
        cves = finding.get("cves", "")

        if finding.get("kev"):
            item = self._add_or_collect(project_dir, {
                "source_tool": source_tool,
                "recommended_tool": None,
                "category": "kev_finding",
                "title": f"KEV: {title}",
                "target": target,
                "scope": scope,
                "priority": "CRITICAL",
                "approval_tier": "confirm",
                "in_scope": in_scope,
                "metadata": {
                    "finding_id": finding.get("id"),
                    "risk": risk,
                    "cves": cves,
                    "recommendations": recommendations,
                },
            }, _collector)
            if item:
                items.append(item)

        title_lower = title.lower()
        is_self_validated = any(p in title_lower for p in self._SELF_VALIDATED_PATTERNS)

        msf_modules = finding.get("metasploit_modules", [])
        _rce_cred = any(p in title_lower for p in (
            "remote code", "code execution", "command injection", "rce",
            "credential", "password", "sensitive data", "secret",
            "authentication bypass", "default credential",
        ))
        _needs_validation = (
            msf_modules
            or (type_rec and type_rec.get("msf"))
            or _rce_cred
        )
        if not is_self_validated and _needs_validation:
            item = self._add_or_collect(project_dir, {
                "source_tool": source_tool,
                "recommended_tool": None,
                "category": "exploit_available",
                "title": f"Validate exploit: {title}",
                "target": target,
                "scope": scope,
                "priority": "CRITICAL" if risk == "CRITICAL" else "HIGH",
                "approval_tier": "confirm",
                "in_scope": in_scope,
                "metadata": {
                    "finding_id": finding.get("id"),
                    "risk": risk,
                    "vuln_type": type_rec["patterns"][0] if type_rec else None,
                    "recommendations": recommendations,
                },
            }, _collector)
            if item:
                items.append(item)
            return items

        if risk in ("CRITICAL", "HIGH") and not is_self_validated:
            if not type_rec:
                recommendations["manual_steps"].extend([
                    f"Manually verify {title} on {target}",
                    "Attempt exploitation in controlled environment",
                    "Document proof-of-concept with screenshots",
                ])
            item = self._add_or_collect(project_dir, {
                "source_tool": source_tool,
                "recommended_tool": self._TOOL_DEEPER_MAP.get(
                    source_tool, {}).get("deeper"),
                "category": "manual_validation",
                "title": f"Validate: {title}",
                "target": target,
                "scope": scope,
                "priority": priority,
                "approval_tier": "confirm",
                "in_scope": in_scope,
                "metadata": {
                    "finding_id": finding.get("id"),
                    "risk": risk,
                    "cves": cves,
                    "vuln_type": type_rec["patterns"][0] if type_rec else None,
                    "recommendations": recommendations,
                },
            }, _collector)
            if item:
                items.append(item)

        if risk == "MEDIUM" and (cves or type_rec) and not is_self_validated:
            item = self._add_or_collect(project_dir, {
                "source_tool": source_tool,
                "recommended_tool": self._TOOL_DEEPER_MAP.get(
                    source_tool, {}).get("deeper") or source_tool,
                "category": "deeper_scan",
                "title": f"Deep scan: {title}",
                "target": target,
                "scope": scope,
                "priority": "MEDIUM",
                "approval_tier": "confirm",
                "in_scope": in_scope,
                "metadata": {
                    "finding_id": finding.get("id"),
                    "risk": risk,
                    "cves": cves,
                    "vuln_type": type_rec["patterns"][0] if type_rec else None,
                    "recommendations": recommendations,
                },
            }, _collector)
            if item:
                items.append(item)

        return items

    # ── Credential discovery ─────────────────────────────────────────

    @staticmethod
    def _is_credential_finding(finding):
        """Return True if the finding indicates discovered credentials."""
        title = (finding.get("title") or "").lower()
        for pattern in _CREDENTIAL_PATTERNS:
            if pattern in title:
                return True
        if finding.get("credentials"):
            return True
        return False

    @staticmethod
    def _extract_credentials(finding):
        """Extract credentials from a finding.

        Returns a dict with username, password, and auth_method if found.
        Checks structured ``credentials`` field first, then falls back
        to regex extraction from ``output``.
        """
        creds = finding.get("credentials")
        if isinstance(creds, dict) and creds.get("username"):
            return dict(creds)

        output = finding.get("output") or ""
        if not output:
            return None

        import re
        username = None
        password = None
        for line in output.splitlines():
            line_s = line.strip()
            um = re.search(
                r'(?:user(?:name)?|login)\s*[:=]\s*["\']?(\S+?)["\']?\s*$',
                line_s, re.IGNORECASE)
            if um and not username:
                username = um.group(1)
            pm = re.search(
                r'(?:pass(?:word)?|pwd)\s*[:=]\s*["\']?(.+?)["\']?\s*$',
                line_s, re.IGNORECASE)
            if pm and not password:
                password = pm.group(1)

        if not username and not password:
            cm = re.search(r'(\S+)\s*:\s*(\S+)', output)
            if cm:
                candidate_user = cm.group(1)
                candidate_pass = cm.group(2)
                if len(candidate_user) < 64 and len(candidate_pass) < 128:
                    username = candidate_user
                    password = candidate_pass

        if username or password:
            return {"username": username or "", "password": password or ""}
        return None

    def _determine_cred_tools(self, finding, source_tool):
        """Determine which tools to recommend for a credential finding."""
        tools = []
        service = (finding.get("service") or "").lower()
        port = int(finding.get("port") or 0)

        if service in _CRED_SERVICE_TOOLS:
            tools.append(_CRED_SERVICE_TOOLS[service])
        elif port in _DB_PORTS:
            tools.append("auger")
        elif port in _WEB_PORTS or service in _WEB_SERVICES:
            tools.append("fracture")

        if source_tool == "fracture" and "fracture" not in tools:
            tools.append("fracture")
        elif source_tool == "siphon" and "siphon" not in tools:
            tools.append("siphon")
        elif source_tool in ("ss3", "authprobe", "nessus"):
            if port in _WEB_PORTS or service in _WEB_SERVICES:
                if "fracture" not in tools:
                    tools.append("fracture")
            if port in _DB_PORTS or service in _DB_SERVICES:
                if "auger" not in tools:
                    tools.append("auger")

        if not tools:
            if source_tool in ("fracture", "siphon", "auger"):
                tools.append(source_tool)
            elif port in _WEB_PORTS or service in _WEB_SERVICES:
                tools.append("fracture")

        return tools

    def process_credential_discovery(self, project_dir, finding,
                                      source_tool, project=None,
                                      _collector=None):
        """Generate action items for discovered credentials.

        Creates one action item per applicable tool, each carrying the
        credentials in metadata so auto-queue can write settings files
        and run test-connection before launching.
        """
        creds = self._extract_credentials(finding)
        if not creds:
            log.debug("Credential finding without extractable credentials: %s",
                      finding.get("title"))
            return []

        target = self._finding_target(finding)
        tools = self._determine_cred_tools(finding, source_tool)
        ip = finding.get("ip", "")
        port = finding.get("port", 0)
        hostname = finding.get("hostname", "")
        service = finding.get("service", "")
        username = creds.get("username", "")
        cred_in_scope = self._resolve_in_scope(
            project, target=target, ip=ip, hostname=hostname)
        cred_scope = finding.get("scope", "")
        items = []

        for tool in tools:
            item = self._add_or_collect(project_dir, {
                "source_tool": source_tool,
                "recommended_tool": tool,
                "category": "credentials_discovered",
                "title": f"Authenticated {tool} scan: {username}@{target}",
                "target": target,
                "scope": cred_scope,
                "priority": "HIGH",
                "approval_tier": "auto",
                "in_scope": cred_in_scope,
                "metadata": {
                    "finding_id": finding.get("id"),
                    "credentials": creds,
                    "credentialled_scan": True,
                    "ip": ip, "port": port,
                    "hostname": hostname, "service": service,
                },
            }, _collector)
            if item:
                items.append(item)
                log.info("Credential action item: %s scan as %s on %s",
                         tool, username, target)

        return items

    # ── Post-completion batch processing ───────────────────────────────

    def process_completed_findings(self, project_dir, project=None):
        """Load all findings from disk and generate missing action items.

        Called after a tool exits. Collects all candidate items into a
        list, then persists them in a single batch via the ActionItemStore.
        """
        from models.findings import load_all_findings
        from models.action_items import load_action_items

        findings = load_all_findings(project) if project else []
        existing = load_action_items(project_dir)
        existing_finding_ids = {
            ai.get("metadata", {}).get("finding_id")
            for ai in existing if ai.get("metadata", {}).get("finding_id")
        }

        collector = []

        for f in findings:
            fid = f.get("id")
            if fid and fid in existing_finding_ids:
                continue
            tool = f.get("tool", "")
            self.process_finding(project_dir, f, tool, project,
                                _collector=collector)

        self._process_osift_oos_targets(project_dir, project,
                                        _collector=collector)

        self._generate_oos_eligible_items(project_dir, findings, project,
                                          _collector=collector)

        self._process_cross_tool_o365(project_dir, findings, project,
                                      _collector=collector)

        store = _get_ai_store()
        added = store.add_items_batch(project_dir, collector)
        generated = len(added)

        if generated:
            log.info("Generated %d action items from %d findings in %s",
                     generated, len(findings), project_dir)
        return generated

    def _process_osift_oos_targets(self, project_dir, project=None,
                                    _collector=None):
        """Scan OSift targets_osint.json for out-of-scope IPs and generate
        action items.  Runs after any tool completes so OOS targets propagate
        even when OSift did not reach Phase 9.

        When oos_handling is 'separated' or 'combined', targets that are
        children of in-scope domains/IPs get auto-queued.  Unrelated
        targets (e.g. google.com) stay confirm-tier."""
        import json as _json
        td = (project or {}).get("tool_dirs", {}).get("osift", "")
        if not td:
            return 0
        oos_mode = (project or {}).get("oos_handling", "explicit")
        td = Path(td)
        for candidate in (td / "reports" / "targets_osint.json",
                          td / "targets_osint.json"):
            if not candidate.exists():
                continue
            try:
                data = _json.loads(candidate.read_text())
            except (ValueError, OSError) as exc:
                log.debug("action engine data load: %s", exc)
                continue
            generated = 0
            for ip_rec in data.get("ips", []):
                if isinstance(ip_rec, dict):
                    ip = ip_rec.get("ip", "")
                    fqdns = ip_rec.get("fqdns", [])
                    hostname = ""
                    if fqdns and isinstance(fqdns[0], dict):
                        hostname = fqdns[0].get("fqdn", "")
                    elif fqdns:
                        hostname = str(fqdns[0])
                else:
                    ip, hostname = str(ip_rec), ""
                if not ip or not _is_valid_target_ip(ip):
                    continue
                if _is_private_ip(ip) and not _project_has_internal_scope(project):
                    continue
                in_scope = bool(
                    self.scope_manager
                    and (self.scope_manager.is_ip_in_scope(project, ip)
                         or self.scope_manager.is_in_scope(project, ip))
                )
                if in_scope:
                    continue
                if ip in _KNOWN_DNS_RESOLVERS:
                    continue

                eligible = bool(
                    oos_mode != "explicit"
                    and self.scope_manager
                    and self.scope_manager.is_oos_eligible(
                        project, hostname=hostname, ip_str=ip)
                )
                tier = "auto" if eligible else "confirm"

                item = self._add_or_collect(project_dir, {
                    "source_tool": "osift",
                    "recommended_tool": "ss3",
                    "category": "oos_target",
                    "title": f"Out of Scope IP Identified: {ip}",
                    "target": ip,
                    "ip": ip,
                    "scope": "osint",
                    "priority": "MEDIUM" if eligible else "LOW",
                    "approval_tier": tier,
                    "in_scope": False,
                    "metadata": {
                        "hostname": hostname,
                        "oos_eligible": eligible,
                        "fqdns": [f.get("fqdn", str(f)) if isinstance(f, dict) else str(f)
                                  for f in (fqdns or [])[:20]],
                    },
                }, _collector)
                if item:
                    generated += 1

                if eligible and self.scope_manager:
                    for fqdn_rec in (fqdns or [])[:20]:
                        fqdn = (fqdn_rec.get("fqdn", str(fqdn_rec))
                                if isinstance(fqdn_rec, dict)
                                else str(fqdn_rec))
                        if not fqdn:
                            continue
                        if not self.scope_manager.is_oos_eligible(
                                project, hostname=fqdn):
                            continue
                        fr_item = self._add_or_collect(project_dir, {
                            "source_tool": "osift",
                            "recommended_tool": "fracture",
                            "category": "oos_target",
                            "title": f"Out of Scope Subdomain: {fqdn}",
                            "target": fqdn,
                            "ip": ip,
                            "scope": "osint",
                            "priority": "MEDIUM",
                            "approval_tier": tier,
                            "in_scope": False,
                            "metadata": {
                                "hostname": fqdn,
                                "oos_eligible": True,
                            },
                        }, _collector)
                        if fr_item:
                            generated += 1

            if generated:
                log.info("Generated %d OOS target items from OSift targets",
                         generated)
            return generated
        return 0

    # ── OOS-eligible action item generation ──────────────────────────────

    def _generate_oos_eligible_items(self, project_dir, findings, project=None,
                                     _collector=None):
        """When oos_handling is 'separated' or 'combined', auto-queue action
        items for OOS-eligible targets (children of in-scope domains/IPs).

        Targets that are NOT children of any explicitly defined scope
        (e.g. google.com referenced by an in-scope asset but not a
        subdomain/child of any in-scope domain, and whose IP isn't in
        scope) are excluded — those stay as confirm-tier items created
        by _process_osift_oos_targets."""
        oos_mode = (project or {}).get("oos_handling", "explicit")
        if oos_mode == "explicit":
            return 0
        if not self.scope_manager:
            return 0

        sm = self.scope_manager
        existing = get_action_items_by_status(project_dir, "pending")
        existing_oos_targets = {
            ai.get("target", "")
            for ai in existing
            if ai.get("category") == "oos_target"
        }

        seen = set()
        generated = 0
        for f in findings:
            if not f.get("oos"):
                continue
            ip = f.get("ip") or ""
            hostname = f.get("hostname") or ""
            target = hostname or ip
            if not target or target in seen or target in existing_oos_targets:
                continue
            if ip and _is_private_ip(ip) and not _project_has_internal_scope(project):
                continue
            seen.add(target)

            if not sm.is_oos_eligible(project, hostname=hostname, ip_str=ip):
                continue

            scope = f.get("_scope") or f.get("scope") or ""
            rec_tool = "ss3"
            if scope in ("webapp", "fr"):
                rec_tool = "fracture"
            elif scope in ("api", "si"):
                rec_tool = "siphon"

            item = self._add_or_collect(project_dir, {
                "source_tool": "crucible",
                "recommended_tool": rec_tool,
                "category": "oos_target",
                "title": f"OOS-Eligible Target: {target}",
                "target": target,
                "ip": ip,
                "scope": scope,
                "priority": "MEDIUM",
                "approval_tier": "auto",
                "in_scope": False,
                "metadata": {
                    "hostname": hostname,
                    "oos_eligible": True,
                    "oos_mode": oos_mode,
                },
            }, _collector)
            if item:
                generated += 1

        if generated:
            log.info("Generated %d OOS-eligible action items (auto-queue, mode=%s)",
                     generated, oos_mode)
        return generated

    # ── Cross-tool: SS3 O365 + OSift emails → action item ─────────────

    def _process_cross_tool_o365(self, project_dir, findings, project=None,
                                 _collector=None):
        """When SS3 found 'Discovery: O365 Tenant Detected' AND OSift found
        'Discovery: Email Address' for that domain, create an action item
        to run SS3 O365 Account Enumeration with all in-scope emails.

        Both finding sets come from the already-loaded findings list (all
        tools merged), so no filesystem spelunking is needed."""
        o365_domains = {}
        osift_emails = {}

        for f in findings:
            title = (f.get("title") or "").strip()
            tool = (f.get("tool") or "").lower()

            if title == "Discovery: O365 Tenant Detected":
                dom = (f.get("hostname") or f.get("affected") or "").strip().lower()
                if dom:
                    o365_domains[dom] = f

            _is_email = (
                title == "Discovery: Email Address"
                or (tool in ("osift", "") and (
                    title.startswith("Email:")
                    or title.startswith("Discovery: Email:")
                ))
            )
            if _is_email:
                affected = (f.get("affected") or "").strip()
                for line in affected.split("\n"):
                    addr = line.strip().lower()
                    if "@" in addr:
                        dom_part = addr.rsplit("@", 1)[1]
                        osift_emails.setdefault(dom_part, []).append(addr)
                _te = ""
                if title.startswith("Email:"):
                    _te = title[6:].strip().lower()
                elif title.startswith("Discovery: Email:"):
                    _te = title[17:].strip().lower()
                if _te and "@" in _te:
                    _dp = _te.rsplit("@", 1)[1]
                    osift_emails.setdefault(_dp, []).append(_te)

        if not o365_domains or not osift_emails:
            return 0

        scope_domains = set()
        if project:
            for sd in project.get("scope_definition", {}).get("domains", []):
                scope_domains.add(sd.lower().strip())
            for t in project.get("scope_definition", {}).get("targets", []):
                t_lower = t.lower().strip()
                if not t_lower.replace(".", "").isdigit():
                    scope_domains.add(t_lower)

        generated = 0
        for dom, o365_finding in sorted(o365_domains.items()):
            emails = osift_emails.get(dom, [])
            if not emails:
                continue
            if scope_domains:
                emails = [e for e in emails if e.rsplit("@", 1)[1] in scope_domains]
                if not emails:
                    continue

            emails = sorted(set(emails))
            item = self._add_or_collect(project_dir, {
                "source_tool": "crucible",
                "recommended_tool": "deps",
                "category": "o365_enum",
                "title": f"O365 Account Enumeration: {dom}",
                "target": dom,
                "scope": "external",
                "priority": "HIGH",
                "approval_tier": "confirm",
                "in_scope": True,
                "metadata": {
                    "source_category": "cross_tool_o365",
                    "dep_tool": "o365spray",
                    "ss3_o365_detected": True,
                    "osift_emails_available": True,
                    "harvested_email_count": len(emails),
                    "harvested_emails": emails[:200],
                    "command": f"o365spray --enum -U emails.txt --domain {dom} --output <output_dir>",
                },
            }, _collector)
            if item:
                generated += 1

        if generated:
            log.info("Generated %d cross-tool O365 enum action items", generated)
        return generated

    # ── Helpers ──────────────────────────────────────────────────────────

    def get_approval_tier(self, category):
        """Return approval tier for a category."""
        return CATEGORIES.get(category, {}).get("approval_tier", "confirm")

    def get_auto_queue_items(self, project_dir):
        """Return pending items whose approval_tier is 'auto'."""
        pending = get_action_items_by_status(project_dir, "pending")
        return [i for i in pending if i.get("approval_tier") == "auto"]

    def get_category_info(self, category):
        """Return the full category definition dict."""
        return CATEGORIES.get(category)
