#!/usr/bin/env python3
"""Crucible v2 — Penetration Test Report Generator (Template v3).
Uses Playwright/Chromium for full CSS rendering → PDF.

v3 changes:
- Scope-separated findings (External / OSINT)
- Grouped findings by type within each scope
- LOW findings get full detail cards
- INFO findings in summary table only
- Newline-separated formatting throughout
- Filtered services (confirmed open only)
- Normalized software via Crucible
- Timeline narrative per scope
- Dynamic scope-to-tool mapping from engagement data
"""

import json
import html as html_mod
import logging
import re as _re
from datetime import datetime
from pathlib import Path
from collections import Counter, defaultdict

import ipaddress as _ipaddress

from models.findings import deduplicate as crucible_deduplicate
from routes.intelligence import _normalize_software

log = logging.getLogger("crucible.report_generator")


def _parse_exclusion_networks(meta):
    """Parse scope_definition.exclusions into a list of ip_network objects."""
    scope_def = meta.get("scope_definition", {})
    exclusions = scope_def.get("exclusions", [])
    if not exclusions:
        return []
    nets = []
    for excl in exclusions:
        excl = excl.strip()
        if not excl:
            continue
        try:
            nets.append(_ipaddress.ip_network(excl, strict=False))
        except ValueError:
            try:
                nets.append(_ipaddress.ip_network(f"{excl}/32", strict=False))
            except ValueError:
                pass
    return nets


def _ip_in_exclusions(ip_str, networks):
    """Check if an IP string falls within any exclusion network."""
    ip_str = (ip_str or "").strip()
    if not ip_str:
        return False
    try:
        addr = _ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for net in networks:
        if addr in net:
            return True
    return False

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
RISK_COLORS = {
    "CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706",
    "LOW": "#059669", "INFO": "#a5b4fc",
}
RISK_BG = {
    "CRITICAL": "#fef2f2", "HIGH": "#fff7ed", "MEDIUM": "#fffbeb",
    "LOW": "#ecfdf5", "INFO": "#eef2ff",
}

TOOL_ID_ALIASES = {
    "scattershot3": "ss3",
    "osift": "osift",
    "fracture": "fracture",
    "siphon": "siphon",
}

SCOPE_LABELS = {
    "external": "External Penetration Test",
    "osint": "OSINT Reconnaissance",
    "internal": "Internal Penetration Test",
    "wireless": "Wireless Assessment",
    "web": "Web Application Assessment",
    "api": "API Security Assessment",
    "endpoint": "Endpoint Security Assessment",
}

SCOPE_SUMMARIES = {
    "external": (
        "An external penetration test simulates a real-world attack against an organization's "
        "internet-facing infrastructure from the perspective of an unauthenticated adversary "
        "with no prior knowledge of the environment. The objective is to identify vulnerabilities "
        "in publicly accessible services, including web servers, mail gateways, DNS infrastructure, "
        "VPN endpoints, and cloud-hosted resources, that could be exploited to gain unauthorized "
        "access, exfiltrate data, or disrupt operations. Testing begins with automated and manual "
        "reconnaissance to map the attack surface, followed by targeted enumeration of discovered "
        "services, vulnerability analysis using both commercial and open-source tooling, and manual "
        "exploitation attempts where safe to do so. Each finding is validated to eliminate false "
        "positives and rated according to its real-world exploitability and business impact."
    ),
    "osint": (
        "Open-Source Intelligence (OSINT) reconnaissance is the systematic collection and analysis "
        "of publicly available information about an organization, its employees, and its digital "
        "footprint. This phase operates entirely passively — no packets are sent to the target's "
        "infrastructure — yet it often reveals the most actionable intelligence for an attacker: "
        "employee names and email addresses for phishing campaigns, exposed credentials in public "
        "breach databases, subdomains and infrastructure relationships that map the real attack "
        "surface, and DNS configurations that may enable domain spoofing or unauthorized certificate "
        "issuance. Limiting an organization's public exposure is a critical defense-in-depth measure. "
        "Every piece of information discoverable through passive reconnaissance is a piece an "
        "adversary does not need to actively probe for, reducing the likelihood of detection during "
        "the early stages of a targeted attack."
    ),
    "internal": (
        "An internal penetration test evaluates the security posture of an organization's internal "
        "network from the perspective of a threat actor who has gained initial access — whether "
        "through a compromised workstation, VPN credential, or physical access to the network."
    ),
    "wireless": (
        "A wireless security assessment evaluates the configuration and resilience of the "
        "organization's wireless network infrastructure against common attack vectors including "
        "rogue access points, deauthentication attacks, and credential interception."
    ),
    "web": (
        "A web application assessment systematically evaluates the security of web-based "
        "applications against the OWASP Top 10 and other common vulnerability classes to "
        "identify weaknesses that could lead to unauthorized access or data exposure."
    ),
    "api": (
        "An API security assessment evaluates the organization's application programming "
        "interfaces against the OWASP API Security Top 10, testing for authentication bypass, "
        "authorization flaws, injection vulnerabilities, and data exposure."
    ),
    "endpoint": (
        "An endpoint security assessment evaluates the configuration and hardening posture of "
        "Windows desktops and servers against industry benchmarks including CIS Benchmarks, DISA "
        "STIGs, and Microsoft Security Baselines. Testing covers operating system configuration, "
        "Active Directory security, user and group management, firewall configuration, installed "
        "software inventory, browser security, remote management exposure, certificate management, "
        "update compliance, and indicators of compromise in event logs and running processes. Each "
        "finding is mapped to applicable compliance frameworks and rated by its real-world "
        "exploitability and impact on the organization's security posture."
    ),
}

_SCOPE_TARGET_FIELDS = {
    "external": [("network_cidrs", "IP / CIDR"), ("target_urls", "URL")],
    "internal": [("network_cidrs", "IP / CIDR")],
    "osint": [("domains", "Domain")],
    "web": [("target_urls", "URL")],
    "api": [("api_urls", "API URL"), ("api_specs", "API Spec")],
    "wireless": [("wireless_ssids", "SSID")],
    "endpoint": [("endpoint_targets", "Endpoint")],
}

# ── Report Type Registry ─────────────────────────────────
REPORT_TYPES = {
    # ── Universal (no scope gate) ─────────────────────────────
    "full":               {"label": "Full Pentest Report",                  "scope_gate": None,        "description": "Complete engagement report with all scopes, findings, and methodology"},
    "remediation":        {"label": "Remediation Prioritization Report",    "scope_gate": None,        "description": "Cross-scope remediation roadmap ranked by risk severity, exploitation likelihood, and remediation effort"},
    "compliance_matrix":  {"label": "Compliance Matrix Report",             "scope_gate": None,        "description": "All findings mapped across compliance frameworks (NIST CSF, PCI DSS, ISO 27001, SOC 2, HIPAA) with gap analysis"},
    "unified_exec":       {"label": "Unified Executive Summary",            "scope_gate": None,        "description": "Single-page executive overview spanning all scopes with risk heat map and strategic recommendations"},

    # ── External scope ────────────────────────────────────────
    "ext_vuln":           {"label": "External Vulnerability Assessment",    "scope_gate": "external",  "description": "All external findings with risk ratings, exploit availability, and remediation guidance"},
    "ext_surface":        {"label": "Attack Surface Report",                "scope_gate": "external",  "description": "Exposed services, technologies, open ports, and entry points from external reconnaissance"},
    "ext_pci":            {"label": "PCI DSS External Scan Report",         "scope_gate": "external",  "description": "External vulnerability assessment mapped to PCI DSS v4.0 requirements with ASV-style formatting"},
    "ext_firewall":       {"label": "Perimeter Firewall Assessment",        "scope_gate": "external",  "description": "Firewall rule analysis, exposed services, and network filtering gaps from external perspective"},
    "ext_exec":           {"label": "Executive Summary — External",         "scope_gate": "external",  "description": "Non-technical overview of external attack surface and risk posture for leadership"},

    # ── OSINT scope ───────────────────────────────────────────
    "osint_intel":        {"label": "OSINT Intelligence Report",            "scope_gate": "osint",     "description": "Complete passive reconnaissance findings including subdomains, DNS, infrastructure, and employee data"},
    "osint_footprint":    {"label": "Digital Footprint Report",             "scope_gate": "osint",     "description": "Organization's public-facing digital presence: domains, IP ranges, ASN relationships, and hosting"},
    "osint_email":        {"label": "Email & Credential Exposure Report",   "scope_gate": "osint",     "description": "Harvested email addresses, breach database matches, and O365/Azure tenant enumeration results"},
    "osint_dns":          {"label": "DNS Security Report",                  "scope_gate": "osint",     "description": "DNS misconfiguration findings: SPF/DKIM/DMARC gaps, zone transfers, and subdomain takeover risks"},
    "osint_exec":         {"label": "Executive Summary — OSINT",            "scope_gate": "osint",     "description": "Non-technical overview of public exposure and passive intelligence risk for leadership"},

    # ── Internal scope ────────────────────────────────────────
    "int_vuln":           {"label": "Internal Vulnerability Assessment",    "scope_gate": "internal",  "description": "All internal findings with risk ratings, lateral movement paths, and remediation guidance"},
    "int_segment":        {"label": "Network Segmentation Report",          "scope_gate": "internal",  "description": "Internal network segmentation analysis, VLAN boundaries, and lateral movement assessment"},
    "int_ad":             {"label": "Active Directory Security Report",     "scope_gate": "internal",  "description": "AD-specific findings: Kerberos weaknesses, LDAP binds, GPO misconfigurations, and privilege escalation"},
    "int_smb":            {"label": "SMB & File Share Report",              "scope_gate": "internal",  "description": "Share enumeration, permissions, null sessions, and SMBv1/signing vulnerabilities across the internal network"},
    "int_exec":           {"label": "Executive Summary — Internal",         "scope_gate": "internal",  "description": "Non-technical overview of internal network security posture and lateral movement risks for leadership"},

    # ── Wireless scope ────────────────────────────────────────
    "wire_assess":        {"label": "Wireless Security Assessment",         "scope_gate": "wireless",  "description": "Complete wireless findings across all protocols: encryption, rogue APs, deauth, and credential capture"},
    "wire_wifi":          {"label": "Wi-Fi Configuration Report",           "scope_gate": "wireless",  "description": "SSID inventory, encryption analysis, WPA assessment, guest isolation, and AP firmware findings"},
    "wire_rogue":         {"label": "Rogue Access Point Report",            "scope_gate": "wireless",  "description": "Unauthorized access points, evil twin susceptibility, and wireless intrusion detection gaps"},
    "wire_ble":           {"label": "Bluetooth / IoT Protocol Report",      "scope_gate": "wireless",  "description": "BLE device enumeration, Zigbee network mapping, UWB ranging analysis, and protocol-specific vulnerabilities"},
    "wire_exec":          {"label": "Executive Summary — Wireless",         "scope_gate": "wireless",  "description": "Non-technical overview of wireless security posture and unauthorized device risks for leadership"},

    # ── Web scope ─────────────────────────────────────────────
    "web_vuln":           {"label": "Web Application Vulnerability Report", "scope_gate": "web",       "description": "All web findings with OWASP Top 10 mapping, proof-of-concept details, and remediation guidance"},
    "web_owasp":          {"label": "OWASP Top 10 Assessment",              "scope_gate": "web",       "description": "Findings organized by OWASP Top 10:2021 categories with coverage analysis and gap assessment"},
    "web_tech":           {"label": "Web Technology Report",                "scope_gate": "web",       "description": "Detected technologies, CMS versions, JavaScript libraries, and EOL/CVE analysis across web applications"},
    "web_discovery":      {"label": "Content Discovery Report",             "scope_gate": "web",       "description": "Hidden directories, backup files, admin panels, and sensitive path enumeration across web applications"},
    "web_exec":           {"label": "Executive Summary — Web",              "scope_gate": "web",       "description": "Non-technical overview of web application security posture and critical vulnerabilities for leadership"},

    # ── API scope ─────────────────────────────────────────────
    "api_vuln":           {"label": "API Security Assessment Report",       "scope_gate": "api",       "description": "All API findings with OWASP API Top 10:2023 mapping, evidence, and remediation guidance"},
    "api_owasp":          {"label": "OWASP API Top 10 Assessment",          "scope_gate": "api",       "description": "Findings by OWASP API Security Top 10:2023 categories with coverage analysis per category"},
    "api_exec":           {"label": "Executive Summary — API",              "scope_gate": "api",       "description": "Non-technical overview of API security posture and authorization gaps for leadership"},

    # ── Endpoint scope (existing) ─────────────────────────────
    "nist":               {"label": "NIST 800-123 Assessment",              "scope_gate": "endpoint",  "description": "Guide to General Server Security compliance assessment"},
    "stig":               {"label": "DISA STIG Assessment",                 "scope_gate": "endpoint",  "description": "Defense Information Systems Agency STIG compliance assessment"},
    "cis":                {"label": "CIS Benchmark Assessment",             "scope_gate": "endpoint",  "description": "Center for Internet Security hardening benchmark assessment"},
    "disk":               {"label": "Disk & Storage Report",                "scope_gate": "endpoint",  "description": "Physical and logical disk configuration, RAID, and storage health"},
    "software":           {"label": "Software & Update Report",             "scope_gate": "endpoint",  "description": "Installed software inventory, EOL analysis, services, and update compliance"},
    "malicious":          {"label": "Malicious Activity Report",            "scope_gate": "endpoint",  "description": "Suspicious processes, persistence mechanisms, credential exposure, and event log indicators"},
    "hardware":           {"label": "Hardware Report",                      "scope_gate": "endpoint",  "description": "System hardware inventory including processors, memory, BIOS, network adapters, and peripherals"},

    # ── Cross-scope tool reports ──────────────────────────────
    "trawler":            {"label": "Network Traffic Analysis Report",      "scope_gate": None,        "description": "Protocol distribution, top talkers, malicious traffic indicators, cleartext credentials, and anomalous patterns"},
    "auger":              {"label": "Database Security Report",             "scope_gate": None,        "description": "Database authentication, privilege escalation, configuration audit, and malicious data access indicators"},
    "bastion":            {"label": "Firewall Assessment Report",           "scope_gate": None,        "description": "Firewall rule analysis, overly permissive rules, malicious forwarding, and compliance gaps"},
    "forge":              {"label": "Cloud Infrastructure Report",          "scope_gate": None,        "description": "IAM misconfigurations, storage exposure, network security groups, and malicious access patterns"},
    "cloud_pentest":      {"label": "Cloud Penetration Test Assessment",   "scope_gate": None,        "description": "Attack-surface focused cloud assessment covering IAM escalation, network exposure, data exfiltration, and detection gaps"},
    "cloud_cis":          {"label": "CIS AWS Benchmark Assessment",        "scope_gate": None,        "description": "Findings mapped to CIS Amazon Web Services Foundations Benchmark control families with gap analysis"},
    "cloud_compliance":   {"label": "Cloud Compliance Report",             "scope_gate": None,        "description": "Multi-framework regulatory compliance mapping (NIST 800-53, PCI DSS 4.0, SOC 2, ISO 27001, HITRUST, GDPR)"},
    "cloud_exec":         {"label": "Cloud Executive Summary",             "scope_gate": None,        "description": "Non-technical overview of cloud security posture, risk assessment, and strategic recommendations for leadership"},
    "quill":              {"label": "Mobile Application Report",            "scope_gate": None,        "description": "Binary analysis, API extraction, certificate pinning, data storage, and malicious indicator analysis"},
    "isotope":            {"label": "File Analysis Report",                 "scope_gate": None,        "description": "File metadata, malware indicators, embedded content, and malicious link/IP analysis"},
}


def _scope_target_rows(active_scopes, scope_def):
    rows = []
    for scope in active_scopes:
        label = SCOPE_LABELS.get(scope, scope.title())
        fields = _SCOPE_TARGET_FIELDS.get(scope, [])
        targets = []
        for field_key, field_label in fields:
            vals = scope_def.get(field_key, [])
            if vals:
                for v in vals:
                    targets.append(f"{esc(v)}")
        if not targets:
            targets = ["<em>No explicit targets defined</em>"]
        rows.append(
            f'<tr><td><strong>{esc(label)}</strong></td>'
            f'<td class="nl-cell">{"<br>".join(targets)}</td></tr>'
        )
    return "\n    ".join(rows)


# ── Merged Finding Helpers ──────────────────────────

RISK_NUMERIC = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
RISK_FROM_NUM = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "INFO"}

_CATEGORY_STRIP = {
    "Missing Security Headers": _re.compile(r'^Missing Security Header:\s*', _re.IGNORECASE),
    "SSL/TLS Vulnerabilities": _re.compile(r'^SSL/TLS\s+(?:Vulnerability(?:\s*\(Potential\))?|Forward Secrecy|Ciphers|Obsolete|Session|Non-Standard|BREACH|LUCKY13|Sweet32|OCSP|Signature):\s*', _re.IGNORECASE),
    "SSL/TLS Certificate": _re.compile(r'^SSL/TLS\s+Cert(?:ificate)?(?:\s+Information)?:?\s*', _re.IGNORECASE),
    "DNS Configuration": _re.compile(r'^DNS\s*(?:Record)?:?\s*', _re.IGNORECASE),
    "Insecure Protocol Detection": _re.compile(r'^Insecure Protocol Detected:\s*', _re.IGNORECASE),
    "Software & Version Detection": _re.compile(r'^Software Version (?:Detected|Identified|Disclosed):\s*', _re.IGNORECASE),
    "Network Exposure": _re.compile(r'^(?:Non-Standard (?:Web )?Port Detected|Open Ports? Identified):?\s*', _re.IGNORECASE),
    "Domain Intelligence": _re.compile(r'^Domain:\s*', _re.IGNORECASE),
    "Phone Number Discovery": _re.compile(r'^Phone\s*(?:Number)?:\s*', _re.IGNORECASE),
    "Email Address Discovery": _re.compile(r'^Email(?:\s*Address)?:\s*', _re.IGNORECASE),
    "Typosquatting Domains": _re.compile(r'^Typosquatting\s+Domain\s+Detected:?\s*', _re.IGNORECASE),
    "Data Leakage": _re.compile(r'^(?:Header\s+)?Data\s+Leakage:?\s*', _re.IGNORECASE),
    "IP Address Intelligence": _re.compile(r'^IP\s*Address:\s*', _re.IGNORECASE),
    "Infrastructure Discovery": _re.compile(r'^(?:Subdomain|Hostname):\s*', _re.IGNORECASE),
}

CATEGORY_DETAIL_COL = {
    "Missing Security Headers": "Missing Headers",
    "SSL/TLS Vulnerabilities": "Finding",
    "SSL/TLS Certificate": "Detail",
    "DNS Configuration": "Finding",
    "Insecure Protocol Detection": "Protocol",
    "Infrastructure Discovery": "Discovery",
    "Network Exposure": "Detail",
    "Software & Version Detection": "Software",
    "Edge Delivery and Security Stack": "Finding",
    "DNS Enumeration": "Record",
    "Email Security": "Finding",
    "Domain Intelligence": "Domain",
    "Phone Number Discovery": "Phone Number",
    "Email Address Discovery": "Email",
    "IP Address Intelligence": "IP Address",
    "WHOIS Intelligence": "Detail",
    "Physical Address Discovery": "Address",
    "Typosquatting Domains": "Domain",
    "Data Leakage": "Finding",
}


def _extract_issue(category, title):
    pat = _CATEGORY_STRIP.get(category)
    if pat:
        result = pat.sub('', title).strip()
        if result:
            if category == "Data Leakage" and result.lower() == "server":
                return "Server header"
            return result
    return title


def _highest_risk(findings):
    if not findings:
        return "INFO"
    best = max(RISK_NUMERIC.get((f.get("risk") or "INFO").upper(), 0) for f in findings)
    return RISK_FROM_NUM[best]


# ── Catalogue Loader ──────────────────────────────────
_CATALOGUES = {}

def _load_catalogues():
    if _CATALOGUES:
        return
    master_path = "/opt/pr0t31n/shared/master_findings_catalogue.json"
    fallback_paths = [
        "/opt/pr0t31n/Arbiter/findings_catalogue.json",
        "/opt/pr0t31n/Scattershot3/findings_catalogue.json",
        "/opt/pr0t31n/Fracture/findings_catalogue.json",
        "/opt/pr0t31n/OSift/findings_catalogue.json",
    ]
    loaded = False
    from pathlib import Path
    if Path(master_path).exists():
        try:
            data = json.load(open(master_path))
            entries = data.get("findings", data.get("entries", []))
            for e in entries:
                title_key = (e.get("title") or "").strip().lower()
                if title_key:
                    _CATALOGUES[title_key] = e
                for alias in e.get("aliases", []):
                    alias_key = (alias or "").strip().lower()
                    if alias_key and alias_key not in _CATALOGUES:
                        _CATALOGUES[alias_key] = e
            loaded = True
        except Exception:
            pass
    if not loaded:
        for path in fallback_paths:
            try:
                data = json.load(open(path))
                entries = data.get("findings", data.get("entries", []))
                for e in entries:
                    title_key = (e.get("title") or "").strip().lower()
                    if title_key:
                        _CATALOGUES[title_key] = e
            except Exception:
                pass


def _catalogue_lookup(title):
    _load_catalogues()
    key = (title or "").strip().lower()
    if key in _CATALOGUES:
        return _CATALOGUES[key]
    for cat_key, entry in _CATALOGUES.items():
        if key.startswith(cat_key) or cat_key.startswith(key):
            return entry
        for alias in entry.get("aliases", []):
            if (alias or "").strip().lower() == key:
                return entry
    return None


_HEADER_DESCRIPTIONS = {
    "strict-transport-security": (
        "HTTP Strict Transport Security (HSTS) instructs browsers to only communicate with "
        "the server over HTTPS, preventing protocol downgrade attacks and cookie hijacking. "
        "Without HSTS, users who type the domain without 'https://' or follow HTTP links are "
        "vulnerable to man-in-the-middle attacks that intercept or modify traffic before the "
        "redirect to HTTPS occurs."
    ),
    "content-security-policy": (
        "Content Security Policy (CSP) restricts which sources of content (scripts, styles, "
        "images, frames) the browser is allowed to load. Without CSP, an attacker who achieves "
        "any form of content injection can load arbitrary scripts from external domains, "
        "dramatically increasing the impact of cross-site scripting (XSS) vulnerabilities."
    ),
    "x-frame-options": (
        "X-Frame-Options controls whether the page can be embedded in frames or iframes on "
        "other sites. Without this header, the application is vulnerable to clickjacking "
        "attacks where a malicious site overlays invisible frames to trick users into performing "
        "unintended actions such as changing account settings or initiating transactions."
    ),
    "x-content-type-options": (
        "X-Content-Type-Options with the 'nosniff' directive prevents browsers from MIME-type "
        "sniffing responses away from the declared Content-Type. Without this header, browsers "
        "may interpret uploaded files or API responses as executable content, enabling attacks "
        "where a seemingly harmless file (e.g., an image) is executed as JavaScript."
    ),
    "x-xss-protection": (
        "X-XSS-Protection enables the browser's built-in reflected XSS filter. While modern "
        "browsers have deprecated this in favor of CSP, its absence on sites without a strong "
        "CSP leaves users of older browsers without any client-side XSS mitigation, increasing "
        "the risk of reflected cross-site scripting attacks."
    ),
    "referrer-policy": (
        "Referrer-Policy controls how much referrer information is sent with requests. Without "
        "this header, the full URL — including query parameters that may contain session tokens, "
        "search terms, or internal paths — is leaked to third-party sites when users click "
        "outbound links or load external resources."
    ),
    "permissions-policy": (
        "Permissions-Policy (formerly Feature-Policy) restricts which browser features and APIs "
        "(camera, microphone, geolocation, payment) the page and its embedded content can use. "
        "Without this header, any embedded third-party content (ads, widgets, iframes) can "
        "access sensitive device capabilities without the user's explicit consent."
    ),
    "cross-origin-opener-policy": (
        "Cross-Origin-Opener-Policy (COOP) isolates the browsing context from cross-origin "
        "documents. Without COOP, a malicious page opened via window.open() or a link retains "
        "a reference to the opener window, enabling cross-origin attacks like Spectre-based "
        "side-channel data extraction."
    ),
    "cross-origin-resource-policy": (
        "Cross-Origin-Resource-Policy (CORP) prevents other origins from loading the resource. "
        "Without CORP, sensitive resources (images, scripts, API responses) can be embedded by "
        "any third-party site, enabling data exfiltration through side-channel timing attacks."
    ),
    "cross-origin-embedder-policy": (
        "Cross-Origin-Embedder-Policy (COEP) requires all embedded resources to explicitly "
        "grant permission to be loaded. Without COEP, the page cannot enable cross-origin "
        "isolation features like SharedArrayBuffer, and embedded resources may leak data "
        "through Spectre-class side-channel vulnerabilities."
    ),
    "cache-control": (
        "Cache-Control directives instruct browsers and intermediate caches on how to store "
        "responses. Without appropriate cache restrictions, sensitive pages may be stored in "
        "browser caches, proxy caches, or CDN edge nodes, allowing unauthorized access to "
        "authenticated content after a user logs out or shares a device."
    ),
}


def _get_header_description(title):
    """Return a header-specific description for security header findings."""
    title_lower = title.lower()
    for header_name, desc in _HEADER_DESCRIPTIONS.items():
        if header_name in title_lower:
            return desc
    header_match = _re.search(r'missing security header:\s*(.+)', title, _re.IGNORECASE)
    if header_match:
        header = header_match.group(1).strip()
        return (f"The {header} HTTP security header is not configured on this service. "
                f"This header provides an additional layer of defense against common web "
                f"attacks. Its absence reduces the defense-in-depth posture of the application.")
    return ""


def _get_importance(finding, category):
    title = finding.get("title", "")
    if category == "Missing Security Headers":
        header_desc = _get_header_description(title)
        if header_desc:
            return header_desc
    cat_entry = _catalogue_lookup(title)
    if cat_entry:
        impact = (cat_entry.get("impact") or "").strip()
        if impact:
            return impact
        desc = (cat_entry.get("description") or "").strip()
        if desc:
            return desc
    desc = (finding.get("description") or "").strip()
    if desc:
        return desc
    return ""


# ── Evidence Resolver ─────────────────────────────────

def _build_risk_pie(risk_counts, size=140):
    """Build an SVG pie chart (no hole, no labels) for risk distribution."""
    import math
    levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    segments = [(r, risk_counts.get(r, 0)) for r in levels if risk_counts.get(r, 0) > 0]
    total = sum(c for _, c in segments)
    if total == 0:
        return ""

    cx, cy = size / 2, size / 2
    r = size / 2 - 4
    paths = []
    angle = -90

    for risk, count in segments:
        sweep = (count / total) * 360
        if sweep >= 359.99:
            sweep = 359.99
        start_rad = math.radians(angle)
        end_rad = math.radians(angle + sweep)

        x1 = cx + r * math.cos(start_rad)
        y1 = cy + r * math.sin(start_rad)
        x2 = cx + r * math.cos(end_rad)
        y2 = cy + r * math.sin(end_rad)
        large = 1 if sweep > 180 else 0
        color = RISK_COLORS.get(risk, "#94a3b8")

        d = (f"M {cx:.2f} {cy:.2f} L {x1:.2f} {y1:.2f} "
             f"A {r:.2f} {r:.2f} 0 {large} 1 {x2:.2f} {y2:.2f} Z")
        paths.append(f'<path d="{d}" fill="{color}" stroke="#fff" stroke-width="1.5"/>')
        angle += sweep

    return (f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" '
            f'xmlns="http://www.w3.org/2000/svg" style="display:block;">'
            f'{"".join(paths)}</svg>')


def _build_scope_bar(scope_findings, active_scopes, bar_h=140, oos_mode="explicit"):
    """Build an SVG horizontal stacked bar chart showing risk breakdown per scope."""
    SCOPE_LABELS_LOCAL = {"external": "External", "osint": "OSINT", "web": "Web App",
                          "api": "API", "wireless": "Wireless", "internal": "Internal"}
    levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    bar_rows = []
    for s in active_scopes:
        all_f = scope_findings.get(s, [])
        if not all_f:
            continue
        label = SCOPE_LABELS_LOCAL.get(s, s.title())
        if oos_mode == "separated":
            in_f = [f for f in all_f if not f.get("oos")]
            oos_f = [f for f in all_f if f.get("oos")]
            if in_f:
                bar_rows.append((label, in_f))
            if oos_f:
                bar_rows.append((f"{label} - OOS", oos_f))
        else:
            bar_rows.append((label, all_f))

    if not bar_rows:
        return ""
    max_count = max(len(fl) for _, fl in bar_rows)
    if max_count == 0:
        return ""

    bar_w = 220
    row_h = 28
    label_w = 80
    total_h = len(bar_rows) * row_h + 20
    svg_w = label_w + bar_w + 40

    parts = []
    for i, (label, fl) in enumerate(bar_rows):
        y = i * row_h + 10
        parts.append(
            f'<text x="{label_w - 6}" y="{y + row_h / 2 + 1}" text-anchor="end" '
            f'dominant-baseline="central" font-size="8" font-weight="600" '
            f'fill="#475569">{label}</text>')
        counts = Counter((f.get("risk") or "INFO").upper() for f in fl)
        x_off = label_w
        for lvl in levels:
            c = counts.get(lvl, 0)
            if c == 0:
                continue
            w = (c / max_count) * bar_w
            color = RISK_COLORS.get(lvl, "#94a3b8")
            parts.append(
                f'<rect x="{x_off:.1f}" y="{y + 4}" width="{w:.1f}" height="{row_h - 8}" '
                f'rx="3" fill="{color}"/>')
            x_off += w
        total = len(fl)
        parts.append(
            f'<text x="{x_off + 4}" y="{y + row_h / 2 + 1}" dominant-baseline="central" '
            f'font-size="7.5" font-weight="700" fill="#64748b">{total}</text>')

    return (f'<svg viewBox="0 0 {svg_w} {total_h}" width="{svg_w}" height="{total_h}" '
            f'xmlns="http://www.w3.org/2000/svg" style="display:block;">'
            f'{"".join(parts)}</svg>')


def _build_scope_table_rows(scope_findings, active_scopes, oos_mode="explicit"):
    """Build <tr> rows for the By Scope table, splitting OOS when separated."""
    rows = []
    for s in active_scopes:
        all_f = scope_findings.get(s, [])
        if oos_mode == "separated":
            in_scope_f = [f for f in all_f if not f.get("oos")]
            oos_f = [f for f in all_f if f.get("oos")]
        else:
            in_scope_f = all_f
            oos_f = []

        label = SCOPE_LABELS.get(s, s.title())
        rc = Counter((f.get("risk") or "INFO").upper() for f in in_scope_f)
        badges = " &middot; ".join(
            f'<span class="badge-sm" style="background:{RISK_COLORS[r]};">'
            f'{r} {rc[r]}</span>'
            for r in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            if rc.get(r, 0) > 0
        )
        rows.append(
            f'<tr><td><strong>{label}</strong></td>'
            f'<td style="text-align:center;">{len(in_scope_f)}</td>'
            f'<td>{badges}</td></tr>')

        if oos_f:
            oos_rc = Counter((f.get("risk") or "INFO").upper() for f in oos_f)
            oos_badges = " &middot; ".join(
                f'<span class="badge-sm" style="background:{RISK_COLORS[r]};">'
                f'{r} {oos_rc[r]}</span>'
                for r in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
                if oos_rc.get(r, 0) > 0
            )
            rows.append(
                f'<tr><td><strong>{label} - OOS</strong></td>'
                f'<td style="text-align:center;">{len(oos_f)}</td>'
                f'<td>{oos_badges}</td></tr>')
    return rows


def _apply_highlights(escaped_text, highlights):
    """Wrap highlight substrings with accent spans in already-escaped HTML text."""
    if not highlights:
        return escaped_text
    sorted_hl = sorted(set(highlights), key=len, reverse=True)
    MARKER = "\x00"
    replacements = []
    result = escaped_text
    for hl in sorted_hl:
        hl_esc = esc(hl)
        if not hl_esc or hl_esc not in result:
            continue
        placeholder = f"{MARKER}{len(replacements)}{MARKER}"
        replacements.append(f'<span class="evidence-highlight">{hl_esc}</span>')
        result = result.replace(hl_esc, placeholder)
    for i, repl in enumerate(replacements):
        result = result.replace(f"{MARKER}{i}{MARKER}", repl)
    return result


def _find_shcheck_evidence(findings, engagement_dir):
    """Find shcheck output files for security header findings."""
    if not engagement_dir:
        return None
    base = Path(engagement_dir)
    shcheck_files = list(base.rglob("shcheck_*.txt"))
    if not shcheck_files:
        return None
    for sf in shcheck_files:
        try:
            content = sf.read_text(errors="replace").strip()
            if content and len(content) > 20:
                return {"path": sf, "content": content[:600]}
        except Exception:
            continue
    return None


def _resolve_evidence(findings, engagement_dir, max_figures=5, category=""):
    figures = []

    # For security header findings, prefer shcheck output
    if category == "Missing Security Headers" and engagement_dir:
        shcheck = _find_shcheck_evidence(findings, engagement_dir)
        if shcheck:
            figures.append({
                "num": 1,
                "type": "file_output",
                "content": shcheck["content"],
                "caption": f"shcheck output — {shcheck['path'].name}",
            })
            return figures

    # Deduplicate findings by title, prefer ones with output
    by_title = {}
    for f in findings:
        title = f.get("title", "")
        key = title.lower().strip()
        has_output = bool((f.get("output") or "").strip())
        if key not in by_title or (has_output and not (by_title[key].get("output") or "").strip()):
            by_title[key] = f

    candidates = list(by_title.values())
    step = max(len(candidates) // max_figures, 1) if len(candidates) > max_figures else 1
    selected = candidates[::step][:max_figures]

    # Collect screenshots separately — deduplicate by file size, prioritize
    screenshots = []
    screenshot_sizes = set()
    MAX_SCREENSHOTS = 10
    if engagement_dir:
        for f in findings:
            output_file = f.get("output_file", "")
            if not output_file:
                continue
            file_path = _resolve_output_file(output_file, engagement_dir, f)
            if file_path and file_path.exists() and file_path.suffix == ".png":
                try:
                    fsize = file_path.stat().st_size
                    if fsize in screenshot_sizes or fsize < 1000:
                        continue
                    screenshot_sizes.add(fsize)
                    title_l = f.get("title", "").lower()
                    priority = 0
                    if "admin" in title_l: priority = 3
                    elif "login" in title_l or "auth" in title_l: priority = 2
                    elif "error" in title_l or "500" in title_l or "403" in title_l: priority = 1
                    screenshots.append((priority, file_path, f))
                except Exception:
                    pass
        screenshots.sort(key=lambda x: -x[0])
        screenshots = screenshots[:MAX_SCREENSHOTS]

    fig_num = 0
    # Insert unique screenshots first (prioritized)
    for _prio, ss_path, ss_finding in screenshots:
        if fig_num >= max_figures + MAX_SCREENSHOTS:
            break
        fig_num += 1
        loc = ""
        ip = ss_finding.get("ip", "")
        port = ss_finding.get("port", "")
        if ip:
            loc = f"{ip}:{port}" if port else ip
        figures.append({
            "num": fig_num,
            "type": "screenshot",
            "path": str(ss_path),
            "caption": f"Screenshot of {loc or ss_finding.get('title', '')}",
        })

    # Then text-based evidence (deduplicate identical content AND file paths)
    seen_content = set()
    seen_files = set()
    for f in selected:
        if fig_num >= max_figures + MAX_SCREENSHOTS:
            break

        output = (f.get("output") or "").strip()
        output_file = f.get("output_file", "")
        title = f.get("title", "")
        ip = f.get("ip", "")
        port = f.get("port", "")
        loc = f"{ip}:{port}" if ip and port else ip

        if output_file and engagement_dir:
            file_path = _resolve_output_file(output_file, engagement_dir, f)
            if file_path and file_path.exists() and file_path.suffix == ".png":
                continue  # already handled in screenshots

        if output:
            content_key = output[:200]
            if content_key in seen_content:
                continue
            seen_content.add(content_key)
            fig_num += 1
            caption = f"Tool output for {title}"
            if loc:
                caption += f" on {loc}"
            figures.append({
                "num": fig_num,
                "type": "output",
                "content": output[:4000],
                "caption": caption,
                "highlights": f.get("highlights") or [],
            })
            continue

        if output_file and engagement_dir:
            file_path = _resolve_output_file(output_file, engagement_dir, f)
            if file_path and file_path.exists():
                resolved = str(file_path.resolve())
                if resolved in seen_files:
                    continue
                seen_files.add(resolved)
                if file_path.suffix in (".txt", ".json", ".nmap", ".gnmap"):
                    try:
                        content = file_path.read_text(errors="replace")[:4000]
                        fig_num += 1
                        figures.append({
                            "num": fig_num,
                            "type": "file_output",
                            "content": content,
                            "caption": f"{file_path.name} — {category or title}",
                        })
                    except Exception:
                        pass
    return figures


def _resolve_output_file(output_file, engagement_dir, finding):
    if not output_file:
        return None
    tool = finding.get("tool", "")
    scope = finding.get("_scope", "external")
    scope_dir = "external" if scope in ("external",) else scope

    if output_file.startswith("["):
        try:
            entries = json.loads(output_file)
            for e in entries:
                fname = e.get("file") or e.get("resp") or ""
                if fname:
                    output_file = fname
                    break
        except Exception:
            pass

    if output_file.startswith("/"):
        p = Path(output_file)
        if p.exists():
            return p
        return None

    tool_dirs = {
        "scattershot3": "scattershot",
        "fracture": "fracture",
        "osift": "osift",
    }
    tool_subdir = tool_dirs.get(tool, tool)
    base = Path(engagement_dir) / scope_dir / tool_subdir
    candidate = base / output_file
    if candidate.exists():
        return candidate
    return None


def _render_figures(figures):
    if not figures:
        return ""
    fig_parts = []
    for fig in figures:
        if fig["type"] in ("output", "file_output"):
            content = esc(fig["content"])
            content = _apply_highlights(content, fig.get("highlights") or [])
            fig_parts.append(f'''
                <div class="figure">
                    <div class="evidence-box">{content}</div>
                    <div class="figure-caption">Figure {fig["num"]}: {esc(fig["caption"])}</div>
                </div>''')
        elif fig["type"] == "screenshot":
            import base64
            try:
                img_data = Path(fig["path"]).read_bytes()
                b64 = base64.b64encode(img_data).decode()
                fig_parts.append(f'''
                <div class="figure">
                    <img src="data:image/png;base64,{b64}"
                         style="max-width:100%;border:1px solid var(--slate-200);border-radius:4px;">
                    <div class="figure-caption">Figure {fig["num"]}: {esc(fig["caption"])}</div>
                </div>''')
            except Exception:
                pass
    if not fig_parts:
        return ""
    return '<div class="detail-block break-ok"><div class="label">Evidence</div>\n' + "\n".join(fig_parts) + "\n</div>"


def esc(s):
    return html_mod.escape(str(s or ""))


def nl2br(s):
    return esc(s).replace("\n", "<br>")


def _resolve_tool_dir(project, tool_key):
    td = project.get("tool_dirs", {}).get(tool_key)
    if td and Path(td).exists():
        return Path(td)
    eng_dir = project.get("engagement_dir", project.get("project_dir", ""))
    if not eng_dir:
        return None
    from models.project import TOOL_OUTPUT_DIRS
    derived = Path(eng_dir) / TOOL_OUTPUT_DIRS.get(tool_key, tool_key)
    if derived.exists():
        return derived
    return Path(td) if td else None


def _load_json(path):
    try:
        return json.loads(Path(path).read_text())
    except (json.JSONDecodeError, OSError, TypeError):
        return None


def _load_findings_for_tool(project, tool_key):
    from models.findings import load_findings_from_tool
    findings = []
    loaded = set()
    for scope_dirs in project.get("scope_tool_dirs", {}).values():
        td = scope_dirs.get(tool_key)
        if td and (tool_key, td) not in loaded and Path(td).exists():
            loaded.add((tool_key, td))
            findings.extend(load_findings_from_tool(td, tool_key))
    td = project.get("tool_dirs", {}).get(tool_key)
    if td and (tool_key, td) not in loaded and Path(td).exists():
        loaded.add((tool_key, td))
        findings.extend(load_findings_from_tool(td, tool_key))
    return findings


def _load_ss3_hosts(td):
    if not td:
        return []
    for scope in ("ext", "int", ""):
        base = td / scope if scope else td
        for fn in ("correlated.json", "inventory/hosts.json", "targets.json"):
            fp = base / fn
            data = _load_json(fp)
            if not data:
                continue
            hosts_raw = data.get("hosts", data) if isinstance(data, dict) else data
            if isinstance(hosts_raw, dict):
                hosts = []
                for ip, h in hosts_raw.items():
                    if ip in ("meta", "_") or not isinstance(h, dict):
                        continue
                    h.setdefault("ip", ip)
                    hosts.append(h)
                if hosts:
                    return hosts
            elif isinstance(hosts_raw, list) and hosts_raw:
                return hosts_raw
    return []


def _load_ss3_services(td):
    if not td:
        return {}
    for scope in ("ext", "int", ""):
        base = td / scope if scope else td
        for fn in ("correlated.json", "inventory/hosts.json"):
            fp = base / fn
            data = _load_json(fp)
            if not data:
                continue
            hosts = data.get("hosts", data) if isinstance(data, dict) else data
            if isinstance(hosts, dict):
                host_list = [dict(v, ip=k) for k, v in hosts.items()
                             if k not in ("meta", "_") and isinstance(v, dict)]
            elif isinstance(hosts, list):
                host_list = hosts
            else:
                continue
            services = {}
            for h in host_list:
                if not isinstance(h, dict):
                    continue
                ports = h.get("ports", {})
                port_items = ports.values() if isinstance(ports, dict) else (
                    ports if isinstance(ports, list) else [])
                for p in port_items:
                    if not isinstance(p, dict):
                        continue
                    svc = p.get("service", "") or "unknown"
                    entry = {
                        "ip": h.get("ip", ""), "port": p.get("port", 0),
                        "protocol": p.get("protocol", "tcp"),
                        "service": svc, "state": p.get("state", ""),
                        "product": p.get("product", ""),
                        "version": p.get("version", ""),
                    }
                    services.setdefault(svc, []).append(entry)
            if services:
                _normalize_service_protocols(services)
                return services
    return {}


_HTTPS_PORTS = {443, 8443, 2053, 2083, 2087, 2096}


def _normalize_service_protocols(services):
    for svc_name, entries in services.items():
        for e in entries:
            port = e.get("port", 0)
            svc = e.get("service", "")
            if port in _HTTPS_PORTS and svc == "http":
                e["service"] = "https"
    if "http" in services:
        moved = []
        keep = []
        for e in services["http"]:
            if e.get("service") == "https":
                moved.append(e)
            else:
                keep.append(e)
        if moved:
            services.setdefault("https", []).extend(moved)
            if keep:
                services["http"] = keep
            else:
                del services["http"]


def _load_ss3_software(td):
    if not td:
        return []
    software = []
    seen = set()
    for scope in ("ext", "int", ""):
        base = td / scope if scope else td
        for fn in ("inventory/software.json", "software_inventory.json"):
            fp = base / fn
            data = _load_json(fp)
            if not data:
                continue
            items = data if isinstance(data, list) else (
                data.get("software") or data.get("technologies") or [])
            for item in items:
                if not isinstance(item, dict):
                    continue
                key = (item.get("software", ""), item.get("ip", ""),
                       item.get("port", 0))
                if key not in seen:
                    seen.add(key)
                    software.append(item)
        for fn in ("correlated.json", "inventory/hosts.json"):
            fp = base / fn
            data = _load_json(fp)
            if not data:
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
                    for tech in p.get("technologies", []):
                        if not isinstance(tech, dict):
                            continue
                        sw_name = tech.get("name") or tech.get("software", "")
                        if not sw_name:
                            continue
                        key = (sw_name, ip, p.get("port", 0))
                        if key not in seen:
                            seen.add(key)
                            software.append({
                                "software": sw_name,
                                "version": tech.get("version", ""),
                                "ip": ip,
                                "port": p.get("port", 0),
                                "source": tech.get("source", ""),
                            })
    return software


def _load_osift_targets(td):
    if not td:
        return {}
    for candidate in (td / "reports" / "targets_osint.json",
                      td / "targets_osint.json"):
        data = _load_json(candidate)
        if data:
            return data
    return {}


def _load_osift_dns(td):
    if not td:
        return {}
    domains_dir = td / "domains"
    if not domains_dir.is_dir():
        return {}
    merged = {}
    for domain_dir in sorted(domains_dir.iterdir()):
        if not domain_dir.is_dir():
            continue
        records_dir = domain_dir / "dns" / "records"
        if not records_dir.is_dir():
            continue
        for rf in records_dir.glob("*_records.json"):
            data = _load_json(rf)
            if data and isinstance(data, dict):
                for rtype, records in data.items():
                    if isinstance(records, list):
                        merged.setdefault(rtype, []).extend(records)
                break
    return merged


def _load_osift_dns_per_domain(td):
    """Load DNS records keyed by domain name, then by record type."""
    if not td:
        return {}
    domains_dir = td / "domains"
    if not domains_dir.is_dir():
        return {}
    per_domain = {}
    for domain_dir in sorted(domains_dir.iterdir()):
        if not domain_dir.is_dir():
            continue
        domain_name = domain_dir.name
        records_dir = domain_dir / "dns" / "records"
        if not records_dir.is_dir():
            continue
        domain_records = {}
        for rf in records_dir.glob("*_records.json"):
            data = _load_json(rf)
            if data and isinstance(data, dict):
                for rtype, records in data.items():
                    if isinstance(records, list):
                        domain_records.setdefault(rtype, []).extend(records)
                break
        if domain_records:
            per_domain[domain_name] = domain_records
    return per_domain


def _load_osift_nslookup(td):
    if not td:
        return {}
    for candidate in (td / "reports" / "nslookup.json",
                      td / "nslookup.json",
                      td / "reports" / "dns_records.json",
                      td / "dns_records.json"):
        data = _load_json(candidate)
        if data:
            return data
    domains_dir = td / "domains"
    if domains_dir.is_dir():
        for domain_dir in sorted(domains_dir.iterdir()):
            if not domain_dir.is_dir():
                continue
            ns_file = domain_dir / "dns" / "nslookup" / "nslookup_summary.json"
            data = _load_json(ns_file)
            if data:
                return data
    return {}


def _load_osift_nslookup_per_domain(td):
    """Load nslookup data keyed by domain name."""
    if not td:
        return {}
    per_domain = {}
    domains_dir = td / "domains" if td else None
    if domains_dir and domains_dir.is_dir():
        for domain_dir in sorted(domains_dir.iterdir()):
            if not domain_dir.is_dir():
                continue
            ns_file = domain_dir / "dns" / "nslookup" / "nslookup_summary.json"
            data = _load_json(ns_file)
            if data:
                per_domain[domain_dir.name] = data
    return per_domain


def gather_report_data(project):
    """Build the data dict from a live Crucible v2 project."""
    ss3_td = _resolve_tool_dir(project, "ss3")
    osift_td = _resolve_tool_dir(project, "osift")

    return {
        "crucible_meta": project,
        "ss3_findings": _load_findings_for_tool(project, "ss3"),
        "fracture_findings": _load_findings_for_tool(project, "fracture"),
        "osift_findings": _load_findings_for_tool(project, "osift"),
        "ss3_hosts": _load_ss3_hosts(ss3_td),
        "ss3_services": _load_ss3_services(ss3_td),
        "ss3_software": _load_ss3_software(ss3_td),
        "osift_targets": _load_osift_targets(osift_td),
        "osift_dns": _load_osift_dns(osift_td),
        "osift_nslookup": _load_osift_nslookup(osift_td),
        "osift_dns_per_domain": _load_osift_dns_per_domain(osift_td),
        "osift_nslookup_per_domain": _load_osift_nslookup_per_domain(osift_td),
    }


def gather_endpoint_data(project):
    """Build the data dict for endpoint/Dredge-focused reports."""
    dredge_td = _resolve_tool_dir(project, "dredge")
    if not dredge_td:
        return {"crucible_meta": project}
    return {
        "endpoint_status": _load_json(dredge_td / "endpoint_status.json") or {},
        "disk_storage": _load_json(dredge_td / "disk_storage_report.json") or {},
        "hardware": _load_json(dredge_td / "hardware_report.json") or {},
        "software_inventory": _load_json(dredge_td / "software_inventory.json") or {},
        "hardening": _load_json(dredge_td / "hardening_results.json") or {},
        "network_posture": _load_json(dredge_td / "network_posture.json") or {},
        "cis_assessment": _load_json(dredge_td / "cis_assessment.json") or {},
        "nist_assessment": _load_json(dredge_td / "nist_assessment.json") or {},
        "stig_assessment": _load_json(dredge_td / "stig_assessment.json") or {},
        "dredge_findings": _load_findings_for_tool(project, "dredge"),
        "crucible_meta": project,
    }


def merge_findings(findings):
    return crucible_deduplicate(findings)


def risk_sort(f):
    return RISK_ORDER.get((f.get("risk") or "INFO").upper(), 5)


def build_scope_map(crucible_meta):
    scope_tools = crucible_meta.get("scope_tools", {})
    tool_to_scope = {}
    for scope, tools in scope_tools.items():
        for tool_id in tools:
            tool_to_scope[tool_id] = scope
    return tool_to_scope


def assign_scope(finding, tool_to_scope):
    scope = (finding.get("scope") or "").strip()
    if scope:
        return scope
    tool = finding.get("tool", "")
    tool_id = TOOL_ID_ALIASES.get(tool, tool)
    return tool_to_scope.get(tool_id, "external")


def _is_empty_typosquat(f):
    """Filter out typosquatting domain findings that have no substantive intelligence."""
    title = (f.get("title") or "").lower()
    if not title.startswith("domain:"):
        return False
    desc = (f.get("description") or "").lower()
    output = (f.get("output") or "").strip()
    if output:
        return False
    if "discovered" in desc and "relationship:" in desc:
        return True
    return False


def _should_exclude_from_report(f):
    """Filter findings that should not appear in the report."""
    title = (f.get("title") or "").lower()
    # LUCKY13 is a potential/theoretical vulnerability — not confirmed exploitable
    if "lucky13" in title:
        return True
    # Cloudflare detection is a positive finding, not a vulnerability
    if "cloudflare" in title and ("software version" in title or "detected" in title):
        return True
    # WAF blocking is a positive security control
    if "cloudflare" in title and ("blocked" in title or "waf" in title):
        return True
    # People/employee data belongs in intelligence, not report findings
    if title.startswith("employee") or "employee identified" in title:
        return True
    if "people" in title and "dork" in title:
        return True
    # Phone numbers cannot be legitimately confirmed — intelligence only
    if title.startswith("phone number:") or title.startswith("phone:"):
        return True
    # Unknown/out-of-scope email findings
    if "email" in title and "(unknown)" in title:
        return True
    # Wayback Machine findings are historical, not actionable
    if "wayback" in title or "web archive" in title:
        return True
    # Unconfirmed UDP ports — cannot be reasonably concluded to be "exposed"
    if "unconfirmed" in title and "udp" in title:
        return True
    # DNS intelligence that belongs in the intelligence section, not findings
    if title in ("subdomain identified", "ip address identified", "ip address:"):
        return True
    if title.startswith("dns record:") or title.startswith("nslookup:"):
        return True
    if "web screenshot captured" in title:
        return True
    if "no web structure identified" in title:
        return True
    return False


def categorize_finding(f):
    title = f.get("title", "").lower()
    if "security header" in title:
        return "Missing Security Headers"
    elif title.startswith("dns:") or "dns record" in title or "nslookup" in title:
        return "DNS Configuration"
    elif "ssl" in title or "tls" in title:
        if "certificate" in title or "cert" in title:
            return "SSL/TLS Certificate"
        return "SSL/TLS Vulnerabilities"
    elif "protocol" in title:
        return "Insecure Protocol Detection"
    elif "subdomain" in title or "hostname" in title:
        return "Infrastructure Discovery"
    elif "port" in title:
        return "Network Exposure"
    elif "software" in title or "version" in title:
        return "Software & Version Detection"
    elif "typosquat" in title:
        return "Typosquatting Domains"
    elif "header" in title and "leak" in title:
        return "Data Leakage"
    elif "data leak" in title or "information leak" in title or "information disclosure" in title:
        return "Data Leakage"
    elif "web" in title:
        return "Edge Delivery and Security Stack"
    elif "dmarc" in title or "spf" in title:
        return "Email Security"
    elif title.startswith("domain:"):
        return "Domain Intelligence"
    elif title.startswith("phone number:") or title.startswith("phone:"):
        return "Phone Number Discovery"
    elif title.startswith("email:") or title.startswith("email address"):
        return "Email Address Discovery"
    elif title.startswith("ip address:"):
        return "IP Address Intelligence"
    elif "whois" in title:
        return "WHOIS Intelligence"
    elif "physical address" in title:
        return "Physical Address Discovery"
    else:
        desc = f.get("description", "").lower()
        if "leak" in title or "leak" in desc or "disclosure" in desc:
            return "Data Leakage"
        return categorize_finding_fallback(f)


def categorize_finding_fallback(f):
    """For findings that don't match any specific category, derive from context."""
    tool = f.get("tool", "").lower()
    risk = (f.get("risk") or "INFO").upper()
    if tool in ("fracture", "siphon"):
        return "Edge Delivery and Security Stack"
    elif tool in ("scattershot3", "ss3"):
        return "Network Exposure"
    elif tool in ("osift",):
        return "Domain Intelligence"
    return "Edge Delivery and Security Stack" if risk in ("CRITICAL", "HIGH", "MEDIUM") else "Infrastructure Discovery"


CATEGORY_DESCRIPTIONS = {
    "Missing Security Headers": (
        "HTTP security headers provide an additional layer of defense by instructing "
        "browsers to enable built-in security mechanisms. When these headers are absent, "
        "web applications may be vulnerable to cross-site scripting (XSS), clickjacking, "
        "MIME-type confusion, and other client-side attacks. While the practical risk "
        "depends on application context and existing protections (such as a CDN/WAF), "
        "implementing these headers is a low-effort, high-value hardening measure."
    ),
    "SSL/TLS Vulnerabilities": (
        "SSL/TLS configuration issues can expose encrypted communications to downgrade "
        "attacks, protocol-level exploits, or cipher weaknesses. Proper TLS configuration "
        "ensures confidentiality and integrity of data in transit."
    ),
    "SSL/TLS Certificate": (
        "SSL/TLS certificates establish the identity of the server and enable encrypted "
        "communication. Certificate findings relate to validity, trust chain, and "
        "configuration of the deployed certificates."
    ),
    "DNS Configuration": (
        "DNS misconfigurations can enable domain takeover, certificate misissuance, or "
        "email spoofing. Proper DNS hygiene includes CAA records to restrict certificate "
        "authorities, DNSSEC to prevent cache poisoning, and appropriate TTL values."
    ),
    "Insecure Protocol Detection": (
        "Services communicating over unencrypted protocols expose data to interception "
        "and manipulation. HTTP services without TLS enforcement allow passive "
        "eavesdropping and active man-in-the-middle attacks on the network path."
    ),
    "Infrastructure Discovery": (
        "During reconnaissance, hostnames, subdomains, and infrastructure relationships "
        "were identified. While informational, these findings map the attack surface and "
        "may reveal unintended exposure of internal services or development environments."
    ),
    "Network Exposure": (
        "Open network ports represent the external attack surface. Each exposed service "
        "is a potential entry point. Non-standard ports may indicate development services, "
        "administrative interfaces, or misconfigured deployments."
    ),
    "Software & Version Detection": (
        "Identifying software and version information allows attackers to search for "
        "known vulnerabilities. Version disclosure should be minimized in production "
        "to reduce the information available for targeted attacks."
    ),
    "Edge Delivery and Security Stack": (
        "Edge delivery and security stack findings relate to the configuration, behavior, "
        "and security posture of CDNs, WAFs, content management systems, and web-facing "
        "services identified during the assessment."
    ),
    "DNS Enumeration": (
        "DNS record enumeration reveals mail servers, nameservers, SPF policies, and "
        "other infrastructure details that inform subsequent attack phases."
    ),
    "Email Security": (
        "Email authentication mechanisms (SPF, DKIM, DMARC) prevent domain spoofing "
        "and phishing. Proper configuration ensures that forged emails from the "
        "organization's domain are rejected by receiving mail servers."
    ),
    "Domain Intelligence": (
        "Typosquatting and similar domain analysis identifies registered domains that "
        "closely resemble the target organization's domain. These domains can be used "
        "for phishing campaigns, credential harvesting, or brand impersonation attacks."
    ),
    "Phone Number Discovery": (
        "Phone numbers associated with the organization were identified through open-source "
        "intelligence gathering. These can be leveraged for vishing (voice phishing), "
        "SMS phishing (smishing), or social engineering attacks against staff."
    ),
    "Email Address Discovery": (
        "Email addresses associated with the organization were identified through public "
        "sources. Discovered email addresses enable targeted phishing, credential stuffing "
        "against known services, and social engineering campaigns."
    ),
    "IP Address Intelligence": (
        "IP addresses associated with the target infrastructure were identified. These "
        "findings expand the known attack surface and may reveal hosting relationships, "
        "shared infrastructure, or geolocation information."
    ),
    "WHOIS Intelligence": (
        "WHOIS records reveal domain registration details including registrant information, "
        "registrar, nameservers, and registration dates. This information supports social "
        "engineering and infrastructure mapping."
    ),
    "Physical Address Discovery": (
        "Physical addresses associated with the organization were discovered through "
        "open-source intelligence. Location data can inform physical security assessments "
        "and support social engineering targeting."
    ),
    "Typosquatting Domains": (
        "Typosquatting domains are registered domains that closely resemble the target "
        "organization's legitimate domain through character substitution, addition, omission, "
        "or transposition. Attackers register these look-alike domains to intercept mistyped "
        "URLs, conduct phishing campaigns, harvest credentials, or impersonate the organization. "
        "Domains that actively resolve to IP addresses or have MX records configured represent "
        "a heightened risk as they can host convincing phishing pages or receive misdirected email."
    ),
    "Data Leakage": (
        "Data leakage findings identify instances where sensitive information is unintentionally "
        "exposed through HTTP response headers, error messages, server banners, or application "
        "output. Leaked information — such as internal IP addresses, software versions, framework "
        "identifiers, and server configurations — assists attackers in fingerprinting the "
        "technology stack and targeting known vulnerabilities specific to the disclosed software."
    ),
}


# ── CSS ──────────────────────────────────────────────────────

REPORT_CSS = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

@page {
    size: letter;
    margin: 0.7in 0.75in 0.9in 0.75in;
}

@page :first {
    margin: 0;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

:root {
    --slate-50: #f8fafc; --slate-100: #f1f5f9; --slate-200: #e2e8f0;
    --slate-300: #cbd5e1; --slate-400: #94a3b8; --slate-500: #64748b;
    --slate-600: #475569; --slate-700: #334155; --slate-800: #1e293b;
    --slate-900: #0f172a; --slate-950: #020617;
    --blue-50: #eff6ff; --blue-100: #dbeafe; --blue-500: #3b82f6;
    --blue-600: #2563eb; --blue-700: #1d4ed8; --blue-800: #1e40af;
    --blue-900: #1e3a5f;
    --accent: #2563eb;
    --font-sans: 'Inter', -apple-system, system-ui, sans-serif;
    --font-mono: 'JetBrains Mono', 'Fira Code', monospace;
}

body {
    font-family: var(--font-sans);
    font-size: 9.5pt;
    line-height: 1.6;
    color: var(--slate-800);
    -webkit-font-smoothing: antialiased;
}

/* ── Cover ─────────────────────────────────────────── */
.cover-page {
    width: 100%; height: 100vh;
    display: flex; flex-direction: column;
    justify-content: flex-start;
    background: #fff;
    color: var(--slate-900);
    page-break-after: always;
    padding: 0;
    position: relative;
}
.cover-stripe {
    width: 100%; height: 6px;
    background: linear-gradient(90deg, var(--accent) 0%, var(--blue-500) 60%, var(--slate-300) 100%);
}
.cover-classification {
    position: absolute; top: 24px; right: 1in;
    font-size: 7.5pt; font-weight: 700; letter-spacing: 3px;
    text-transform: uppercase; color: var(--slate-400);
}
.cover-main {
    flex: 1; display: flex; flex-direction: column;
    justify-content: center; padding: 0 1.2in;
}
.cover-accent-line {
    width: 48px; height: 3px; background: var(--accent);
    border-radius: 2px; margin-bottom: 20px;
}
.cover-client {
    font-size: 44pt; font-weight: 800; letter-spacing: -2px;
    line-height: 1.05; margin-bottom: 14px;
    color: var(--slate-900);
}
.cover-type {
    font-size: 20pt; font-weight: 600; color: var(--slate-600);
    letter-spacing: 0.5px;
}
.cover-meta-block {
    position: absolute; bottom: 1in; left: 1.2in;
    display: flex; flex-direction: column; gap: 5px;
    text-align: left;
}
.cover-meta {
    font-size: 8.5pt; color: var(--slate-500); font-weight: 400;
}
.cover-incomplete-stamp {
    position: absolute; top: 50%; left: 50%;
    transform: translate(-50%, -50%) rotate(-30deg);
    font-size: 72pt; font-weight: 900; letter-spacing: 6px;
    text-transform: uppercase; color: rgba(220, 38, 38, 0.18);
    border: 6px solid rgba(220, 38, 38, 0.18);
    padding: 10px 40px; border-radius: 12px;
    pointer-events: none; z-index: 10;
    white-space: nowrap;
}
.cover-meta strong { color: var(--slate-700); font-weight: 600; }

/* ── Page Layout ───────────────────────────────────── */
.page { page-break-before: always; }
.page:first-of-type { page-break-before: auto; }

h1 {
    font-size: 18pt; font-weight: 800; color: var(--slate-900);
    letter-spacing: -0.5px; margin: 0 0 6px 0;
    padding-bottom: 8px;
    border-bottom: 3px solid var(--accent);
}
h2 {
    font-size: 13pt; font-weight: 700; color: var(--slate-900);
    margin: 28px 0 10px 0;
    display: flex; align-items: center; gap: 10px;
}
h2::before {
    content: '';
    width: 4px; height: 20px;
    background: var(--accent); border-radius: 2px;
    flex-shrink: 0;
}
h3 {
    font-size: 10.5pt; font-weight: 600; color: var(--slate-700);
    margin: 18px 0 8px 0;
}
p { margin: 4px 0; }
.section-intro {
    color: var(--slate-600); font-size: 9.5pt;
    margin: 0 0 16px 0; line-height: 1.65;
}
code {
    font-family: var(--font-mono); font-size: 8pt;
    background: var(--slate-100); padding: 1px 5px;
    border-radius: 3px; color: var(--slate-700);
}

/* ── Stats Grid ────────────────────────────────────── */
.stats-row {
    display: flex; gap: 12px; margin: 16px 0;
}
.stat-card {
    flex: 1; text-align: center;
    background: var(--slate-50);
    border: 1px solid var(--slate-200);
    border-radius: 8px; padding: 16px 8px;
}
.stat-number {
    font-size: 28pt; font-weight: 800;
    color: var(--slate-900); line-height: 1;
    font-variant-numeric: tabular-nums;
}
.stat-label {
    font-size: 7pt; font-weight: 600; color: var(--slate-400);
    text-transform: uppercase; letter-spacing: 1px; margin-top: 4px;
}

/* ── Findings By Risk cards ────────────────────────── */
.risk-cards-row {
    display: flex; gap: 10px; margin: 14px 0;
}
.risk-card {
    flex: 1; text-align: center; padding: 12px 8px;
    border-radius: 8px; border: 1px solid var(--slate-200);
    background: var(--slate-50);
}
.risk-card-count {
    font-size: 26pt; font-weight: 800; line-height: 1;
    font-variant-numeric: tabular-nums;
}
.risk-card-label {
    font-size: 7pt; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.8px; margin-top: 4px; color: var(--slate-500);
}

/* ── Risk Distribution charts ─────────────────────── */
.risk-charts-row {
    display: flex; align-items: flex-start; gap: 24px;
    margin: 14px 0; padding: 16px 20px;
    background: var(--slate-50); border-radius: 10px;
    border: 1px solid var(--slate-200);
}
.risk-chart-col { text-align: center; flex-shrink: 0; }
.risk-chart-col h4 {
    font-size: 7.5pt; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.5px; color: var(--slate-500); margin: 0 0 8px 0;
}
.risk-chart-legend { flex: 1; display: flex; flex-direction: column; gap: 6px; justify-content: center; }
.risk-legend-row { display: flex; align-items: center; gap: 8px; }
.risk-legend-pip { width: 10px; height: 10px; border-radius: 3px; flex-shrink: 0; }
.risk-legend-name {
    font-size: 8pt; font-weight: 700; letter-spacing: 0.5px;
    text-transform: uppercase; width: 70px; color: var(--slate-700);
}
.risk-legend-count {
    font-size: 14pt; font-weight: 800; line-height: 1;
    font-variant-numeric: tabular-nums; width: 36px; text-align: right;
}
.risk-legend-label { font-size: 7.5pt; color: var(--slate-400); font-weight: 500; }

/* ── Section divider (no page break) ──────────────── */
.section-divider {
    border: none; border-top: 2px solid var(--slate-200);
    margin: 30px 0 20px 0;
    page-break-after: avoid;
}
.scope-header { page-break-after: avoid; }
.section-divider + .finding {
    page-break-before: avoid;
}

/* ── Tables ────────────────────────────────────────── */
table {
    width: 100%; border-collapse: collapse; margin: 10px 0;
    font-size: 8.5pt;
}
th {
    background: var(--slate-800); color: #fff;
    font-weight: 600; text-align: left;
    padding: 8px 10px; font-size: 7.5pt;
    text-transform: uppercase; letter-spacing: 0.5px;
}
td {
    padding: 7px 10px; border-bottom: 1px solid var(--slate-100);
    vertical-align: top; color: var(--slate-700);
    line-height: 1.5;
}
tr:nth-child(even) td { background: var(--slate-50); }
.table-light th {
    background: var(--slate-100); color: var(--slate-700);
}
td.nl-cell { white-space: pre-line; }

/* ── Finding Cards ─────────────────────────────────── */
.finding {
    border: 1px solid var(--slate-200);
    border-radius: 8px; margin: 16px 0;
    overflow: hidden;
}
.finding-head { page-break-after: avoid; }
.finding-body .detail-block { page-break-inside: avoid; }
.finding-body .detail-block.break-ok { page-break-inside: auto; }
.finding-head {
    display: flex; align-items: center; gap: 12px;
    padding: 12px 16px;
    border-bottom: 1px solid var(--slate-100);
}
.finding-head .badge {
    font-size: 7.5pt; font-weight: 700; color: #fff;
    padding: 3px 10px; border-radius: 4px;
    text-transform: uppercase; letter-spacing: 0.5px;
    white-space: nowrap;
}
.finding-head .title {
    font-size: 11pt; font-weight: 700; color: var(--slate-900);
}
.finding-body { padding: 14px 16px; }
.finding-meta {
    display: flex; gap: 20px; flex-wrap: wrap;
    font-size: 8pt; color: var(--slate-500);
    margin-bottom: 12px; padding-bottom: 10px;
    border-bottom: 1px solid var(--slate-100);
}
.finding-meta span strong { color: var(--slate-700); }
.enrichment {
    display: flex; gap: 6px; flex-wrap: wrap;
    margin-bottom: 12px;
}
.pill {
    font-size: 7pt; font-weight: 600;
    padding: 2px 8px; border-radius: 4px;
    letter-spacing: 0.3px;
}
.pill-owasp { background: var(--blue-100); color: var(--blue-800); }
.pill-nist { background: #fae8ff; color: #86198f; }
.pill-cve { background: #fee2e2; color: #991b1b; }
.detail-block { margin: 10px 0; }
.detail-block .label {
    font-size: 7.5pt; font-weight: 700; color: var(--slate-400);
    text-transform: uppercase; letter-spacing: 0.5px;
    margin-bottom: 3px;
}
.detail-block p, .detail-block ul {
    color: var(--slate-600); font-size: 9pt; line-height: 1.55;
}
.detail-block ul {
    padding-left: 16px; margin: 4px 0;
}
.detail-block li { margin: 2px 0; }
.evidence-box {
    background: var(--slate-900); color: #e2e8f0;
    font-family: var(--font-mono); font-size: 7.5pt;
    padding: 10px 14px; border-radius: 6px;
    line-height: 1.5; white-space: pre-wrap;
    word-break: break-all; margin-top: 4px;
    max-height: none; overflow: visible;
}
.evidence-highlight {
    font-weight: 700; color: #fca5a5;
    background: rgba(239, 68, 68, 0.2);
    padding: 0 3px; border-radius: 3px;
    border-bottom: 2px solid #ef4444;
}

/* ── Badges ────────────────────────────────────────── */
.badge-sm {
    display: inline-block; font-size: 7pt; font-weight: 700;
    color: #fff; padding: 1px 7px; border-radius: 3px;
    text-transform: uppercase; letter-spacing: 0.3px;
}

/* ── Narrative ─────────────────────────────────────── */
.narrative-block {
    background: linear-gradient(135deg, var(--blue-50), #f0f9ff);
    border-left: 4px solid var(--accent);
    border-radius: 0 8px 8px 0;
    padding: 16px 20px; margin: 14px 0;
    page-break-inside: avoid;
}
.narrative-block .phase-label {
    font-size: 8pt; font-weight: 700; color: var(--accent);
    text-transform: uppercase; letter-spacing: 1px;
    margin-bottom: 6px;
}
.narrative-block p {
    font-size: 9pt; color: var(--slate-700);
    line-height: 1.65; margin: 5px 0;
}

/* ── TOC ───────────────────────────────────────────── */
.toc { margin: 20px 0; }
.toc-item {
    display: flex; align-items: baseline;
    padding: 6px 0; border-bottom: 1px dotted var(--slate-200);
    font-size: 10pt;
}
.toc-num {
    font-weight: 700; color: var(--accent);
    width: 36px; flex-shrink: 0;
}
.toc-title { color: var(--slate-800); font-weight: 500; flex: 1; }
a.toc-title { text-decoration: none; }
a.toc-title:hover { color: var(--accent); }
.toc-page {
    font-size: 9pt; font-weight: 500; color: var(--slate-400);
    text-align: right; flex-shrink: 0; min-width: 24px;
    font-variant-numeric: tabular-nums;
}
.toc-dots { flex: 1; border-bottom: 1px dotted var(--slate-300); margin: 0 8px; min-width: 20px; align-self: baseline; }
.toc-sub {
    display: flex; align-items: baseline;
    padding: 4px 0 4px 20px;
    font-size: 9.5pt;
}
.toc-sub .toc-num {
    font-weight: 600; font-size: 9pt; width: 40px;
}
.toc-sub .toc-title { color: var(--slate-600); font-weight: 400; display: flex; align-items: center; gap: 6px; flex: 1; }
.toc-risk-pip {
    display: inline-block; width: 3px; height: 14px;
    border-radius: 1.5px; flex-shrink: 0;
}
.toc-risk-label {
    font-size: 7pt; font-weight: 700; letter-spacing: 0.5px;
    margin-left: auto; flex-shrink: 0; opacity: 0.85;
}

/* ── Key Observations ──────────────────────────────── */
.obs-list { list-style: none; padding: 0; margin: 10px 0; }
.obs-list li {
    position: relative; padding: 6px 0 6px 20px;
    font-size: 9pt; color: var(--slate-700); line-height: 1.55;
}
.obs-list li::before {
    content: ''; position: absolute; left: 0; top: 13px;
    width: 8px; height: 8px; border-radius: 50%;
    background: var(--accent); opacity: 0.6;
}

/* ── Scope Section Header ──────────────────────────── */
.scope-header {
    background: linear-gradient(135deg, var(--slate-800), var(--slate-900));
    color: #fff;
    padding: 16px 20px;
    border-radius: 8px;
    margin: 24px 0 16px 0;
}
.scope-header h2 {
    color: #fff; margin: 0; font-size: 14pt;
}
.scope-header h2::before { background: var(--blue-500); }
.scope-header .scope-desc {
    font-size: 8.5pt; color: rgba(255,255,255,0.6);
    margin-top: 4px;
}

/* ── Category Group ────────────────────────────────── */
.category-group {
    margin: 20px 0;
}
.category-title {
    font-size: 11pt; font-weight: 700; color: var(--slate-800);
    padding: 8px 0 4px 0;
    border-bottom: 2px solid var(--slate-200);
    margin-bottom: 8px;
}
.category-desc {
    font-size: 8.5pt; color: var(--slate-500);
    line-height: 1.6; margin-bottom: 12px;
    padding-left: 12px;
    border-left: 3px solid var(--slate-200);
}

/* ── Figures ───────────────────────────────────────── */
.figure {
    margin: 10px 0; page-break-inside: avoid;
}
.figure-caption {
    font-size: 7.5pt; font-weight: 600; color: var(--slate-500);
    font-style: italic; margin-top: 4px; text-align: center;
}
.figure img {
    display: block; margin: 0 auto;
    max-height: 200px; object-fit: contain;
}

/* ── Footer ────────────────────────────────────────── */
.page-footer {
    position: fixed; bottom: 0; left: 0; right: 0;
    display: flex; justify-content: space-between;
    padding: 8px 0.75in;
    font-size: 7pt; color: var(--slate-400);
    border-top: 1px solid var(--slate-200);
}

/* ── Endpoint Report Extras ──────────────────────────── */
.stats-row { display: flex; gap: 12px; margin: 16px 0; }
.stat-card {
    flex: 1; text-align: center;
    background: var(--slate-50); border: 1px solid var(--slate-200);
    border-radius: 8px; padding: 16px 8px;
}
.stat-number {
    font-size: 28pt; font-weight: 800; color: var(--slate-900);
    line-height: 1; font-variant-numeric: tabular-nums;
}
.stat-label {
    font-size: 7pt; font-weight: 600; color: var(--slate-400);
    text-transform: uppercase; letter-spacing: 1px; margin-top: 4px;
}
.util-bar { display: flex; align-items: center; gap: 8px; }
.util-track {
    width: 80px; height: 6px; background: var(--slate-200);
    border-radius: 3px; overflow: hidden;
}
.util-fill { height: 100%; border-radius: 3px; }
.util-pct { font-size: 8pt; font-weight: 700; min-width: 40px; }
.badge-sm {
    display: inline-block; font-size: 7pt; font-weight: 700; color: #fff;
    padding: 1px 7px; border-radius: 3px;
    text-transform: uppercase; letter-spacing: 0.3px;
}
.status-ok { background: #059669; }
.status-warn { background: #d97706; }
.status-crit { background: #dc2626; }
.status-ok, .status-warn, .status-crit {
    color: #fff; font-size: 7pt; font-weight: 700;
    padding: 2px 8px; border-radius: 3px;
}
.score-gauge {
    display: inline-flex; align-items: center; justify-content: center;
    width: 100px; height: 100px; border-radius: 50%;
    border: 8px solid var(--accent); font-size: 24pt; font-weight: 800;
    color: var(--slate-900);
}
.control-pass { color: #059669; font-weight: 600; }
.control-fail { color: #dc2626; font-weight: 600; }
.control-na { color: #94a3b8; font-weight: 500; }
"""


# ── Finding Card Builder ─────────────────────────────

def finding_card(f, idx):
    risk = (f.get("risk") or "INFO").upper()
    color = RISK_COLORS.get(risk, "#666")
    bg = RISK_BG.get(risk, "#f9fafb")
    title = esc(f.get("title", "Untitled"))
    desc = esc(f.get("description", ""))
    remed = esc(f.get("remediation", ""))
    affected = f.get("affected", "")
    ip = f.get("ip", "")
    port = f.get("port", "")
    sources = f.get("sources", "")
    owasp = f.get("owasp", "")
    nist = f.get("nist", "")
    cves = f.get("cves", "")
    output = (f.get("output") or "")[:4000]
    service = f.get("service", "")

    affected_items = [a.strip() for a in affected.split("\n") if a.strip()]
    affected_html = ""
    if affected_items:
        items = "".join(f"<li>{esc(a)}</li>" for a in affected_items[:12])
        more = f"<li><em>+{len(affected_items)-12} more</em></li>" if len(affected_items) > 12 else ""
        affected_html = f'''<div class="detail-block">
            <div class="label">Affected Locations</div>
            <ul>{items}{more}</ul></div>'''

    pills = []
    if owasp:
        pills.append(f'<span class="pill pill-owasp">{esc(owasp)}</span>')
    if nist:
        pills.append(f'<span class="pill pill-nist">NIST {esc(nist)}</span>')
    if cves:
        for cve in cves.split(",")[:3]:
            cve = cve.strip()
            if cve:
                pills.append(f'<span class="pill pill-cve">{esc(cve)}</span>')
    enrichment_html = f'<div class="enrichment">{"".join(pills)}</div>' if pills else ""

    evidence_html = ""
    if output:
        evidence_html = f'''<div class="detail-block">
            <div class="label">Evidence</div>
            <div class="evidence-box">{esc(output)}</div></div>'''

    remed_html = ""
    if remed:
        remed_lines = [r.strip() for r in remed.split("\n") if r.strip()]
        if len(remed_lines) > 1:
            remed_inner = "<ul>" + "".join(f"<li>{esc(r)}</li>" for r in remed_lines) + "</ul>"
        else:
            remed_inner = f"<p>{esc(remed)}</p>"
        remed_html = f'''<div class="detail-block">
            <div class="label">Remediation</div>
            {remed_inner}</div>'''

    host_str = ""
    if ip:
        host_str = f"{esc(ip)}:{port}" if port else esc(ip)
    elif affected_items:
        host_str = esc(affected_items[0])

    return f'''
    <div class="finding" style="border-left: 4px solid {color};">
        <div class="finding-head" style="background: {bg};">
            <span class="badge" style="background:{color};">{risk}</span>
            <span class="title">{idx}. {title}</span>
        </div>
        <div class="finding-body">
            <div class="finding-meta">
                <span><strong>Host:</strong> {host_str}</span>
                <span><strong>Service:</strong> {esc(service) if service else 'N/A'}</span>
                <span><strong>Source:</strong> {esc(sources)}</span>
            </div>
            {enrichment_html}
            <div class="detail-block">
                <div class="label">Description</div>
                <p>{desc}</p>
            </div>
            {affected_html}
            {evidence_html}
            {remed_html}
        </div>
    </div>'''


# ── Grouped Findings Builder ────────────────────────

_GLOBAL_FIG_NUM = [0]

def build_grouped_findings_section(findings, scope_label, engagement_dir=None, scope_key=""):
    if not findings:
        return f'''<p style="color:var(--slate-400);font-style:italic;padding:20px 0;">
            No findings identified in {scope_label} scope.</p>'''

    groups = defaultdict(list)
    for f in findings:
        cat = categorize_finding(f)
        groups[cat].append(f)

    sorted_groups = sorted(groups.items(),
                           key=lambda x: (-max(RISK_NUMERIC.get(
                               (i.get("risk") or "INFO").upper(), 0) for i in x[1]),
                               x[0].lower()))

    html_parts = []
    idx = 1

    for cat_name, cat_findings in sorted_groups:
        risk = _highest_risk(cat_findings)
        color = RISK_COLORS.get(risk, "#666")
        bg = RISK_BG.get(risk, "#f9fafb")
        cat_desc = CATEGORY_DESCRIPTIONS.get(cat_name, "")
        detail_col = CATEGORY_DETAIL_COL.get(cat_name, "Finding")

        # Sort findings: risk (highest first), then alphabetical
        cat_findings.sort(key=lambda f: (
            RISK_ORDER.get((f.get("risk") or "INFO").upper(), 5),
            (f.get("title") or "").lower()
        ))

        # Collect metadata
        location_issues = defaultdict(set)
        all_sources = set()
        all_remeds = []
        all_owasp = set()
        all_cves = set()

        # Deduplicate findings by title for the description list
        seen_titles = {}
        unique_findings = []

        for f in cat_findings:
            title = f.get("title", "")
            issue = _extract_issue(cat_name, title)
            risk_f = (f.get("risk") or "INFO").upper()

            title_key = title.lower().strip()
            if title_key not in seen_titles:
                seen_titles[title_key] = f
                unique_findings.append(f)
            else:
                existing = seen_titles[title_key]
                existing_risk = RISK_NUMERIC.get((existing.get("risk") or "INFO").upper(), 0)
                new_risk = RISK_NUMERIC.get(risk_f, 0)
                if new_risk > existing_risk:
                    seen_titles[title_key] = f
                    idx_in = unique_findings.index(existing)
                    unique_findings[idx_in] = f

            for s in (f.get("sources") or "").split("\n"):
                s = s.strip()
                if s:
                    all_sources.add(s)
            remed = (f.get("remediation") or "").strip()
            if remed and remed not in all_remeds:
                all_remeds.append(remed)
            owasp = (f.get("owasp") or "").strip()
            if owasp:
                all_owasp.add(owasp)
            for cve in (f.get("cves") or "").split(","):
                cve = cve.strip()
                if cve:
                    all_cves.add(cve)

            ip = f.get("ip", "")
            port = f.get("port", "")
            hostname = f.get("hostname", "")
            if cat_name == "DNS Configuration":
                loc_label = hostname or ip or "—"
                if ip and hostname:
                    loc_label = f"{hostname} — {ip}"
                locations = [loc_label]
            else:
                affected = f.get("affected", "")
                locations = [a.strip() for a in affected.split("\n") if a.strip()]
                if not locations:
                    if ip:
                        locations = [f"{ip}:{port}" if port else ip]
                    else:
                        locations = ["—"]
                else:
                    if ip or hostname:
                        base_host = hostname or ip
                        scheme = "https" if int(port or 0) in _HTTPS_PORTS else "http"
                        port_suffix = f":{port}" if port and int(port or 0) not in (80, 443) else ""
                        base_url = f"{scheme}://{base_host}{port_suffix}"
                        locations = [
                            f"{base_url}{loc}" if loc.startswith("/") and "://" not in loc else loc
                            for loc in locations
                        ]
                    elif len(locations) > 1:
                        locations = [loc for loc in locations if loc != "/"]
            # For SSL/TLS Certificate, enrich issue with cert details from output
            if cat_name == "SSL/TLS Certificate":
                output = (f.get("output") or f.get("description") or "")
                cert_lines = []
                for line in output.split("\n"):
                    line = line.strip()
                    ll = line.lower()
                    if any(ll.startswith(k) for k in ("subject:", "issuer:", "not valid", "not after",
                                                       "expires:", "serial:", "valid until")):
                        cert_lines.append(line)
                if cert_lines:
                    issue = issue + "\n    " + "\n    ".join(cert_lines[:4])
            for loc in locations:
                location_issues[loc].add(issue)

        if cat_name == "DNS Configuration" and "—" in location_issues:
            real_locs = [k for k in location_issues if k != "—"]
            if real_locs:
                primary = max(real_locs, key=lambda k: len(location_issues[k]))
                location_issues[primary].update(location_issues.pop("—"))

        sorted_locs = sorted(location_issues.keys())

        # Re-sort unique findings by risk then alpha
        unique_findings.sort(key=lambda f: (
            RISK_ORDER.get((f.get("risk") or "INFO").upper(), 5),
            (f.get("title") or "").lower()
        ))

        # Build per-finding descriptions (cap at 25 for very large groups)
        MAX_DESC_ITEMS = 25
        finding_desc_rows = []
        for uf in unique_findings[:MAX_DESC_ITEMS]:
            uf_risk = (uf.get("risk") or "INFO").upper()
            uf_color = RISK_COLORS.get(uf_risk, "#666")
            uf_title = esc(uf.get("title", ""))
            importance = _get_importance(uf, cat_name)
            uf_cves = [c.strip() for c in (uf.get("cves") or "").split(",") if c.strip()]

            desc_html = f'<span class="badge-sm" style="background:{uf_color};">{uf_risk}</span> '
            desc_html += f'<strong>{uf_title}</strong>'
            if importance:
                desc_html += f'<br><span style="color:var(--slate-600);font-size:8.5pt;">{esc(importance)}</span>'
            if uf_cves:
                cve_parts = []
                for cve in uf_cves:
                    cat_entry = _catalogue_lookup(uf.get("title", ""))
                    kev = False
                    if cat_entry:
                        kev = cat_entry.get("kev", False)
                    kev_tag = ' <span class="pill" style="background:#fee2e2;color:#991b1b;font-size:6.5pt;">KEV</span>' if kev else ""
                    cve_parts.append(f'<code>{esc(cve)}</code>{kev_tag}')
                desc_html += f'<br><span style="font-size:8pt;color:var(--slate-500);">CVE: {", ".join(cve_parts)}</span>'

            finding_desc_rows.append(
                f'<li style="margin:6px 0;line-height:1.5;">{desc_html}</li>')
        if len(unique_findings) > MAX_DESC_ITEMS:
            remaining = len(unique_findings) - MAX_DESC_ITEMS
            finding_desc_rows.append(
                f'<li style="margin:6px 0;color:var(--slate-500);font-style:italic;">'
                f'… and {remaining:,} additional findings of this type</li>')

        # Affected table (cap at 30 rows for very large groups)
        MAX_TABLE_ROWS = 30
        affected_rows = []
        for loc in sorted_locs[:MAX_TABLE_ROWS]:
            issues = sorted(location_issues[loc], key=str.lower)
            issues_html = "<br>".join(esc(i) for i in issues)
            affected_rows.append(
                f'<tr><td style="font-family:var(--font-mono);font-size:8pt;'
                f'word-break:break-all;vertical-align:top;">{esc(loc)}</td>'
                f'<td style="font-size:8pt;">{issues_html}</td></tr>')
        if len(sorted_locs) > MAX_TABLE_ROWS:
            remaining = len(sorted_locs) - MAX_TABLE_ROWS
            affected_rows.append(
                f'<tr><td colspan="2" style="font-size:8pt;color:var(--slate-500);'
                f'font-style:italic;text-align:center;">… and {remaining:,} additional locations</td></tr>')

        # Enrichment pills
        pills = []
        for ow in sorted(all_owasp):
            pills.append(f'<span class="pill pill-owasp">{esc(ow)}</span>')
        for cv in sorted(all_cves)[:5]:
            pills.append(f'<span class="pill pill-cve">{esc(cv)}</span>')
        enrichment_html = f'<div class="enrichment">{"".join(pills)}</div>' if pills else ""

        # Remediation — multiple recommendations as bulleted list
        remed_html = ""
        if all_remeds:
            remed_lines = []
            for r in all_remeds[:5]:
                for line in r.split("\n"):
                    line = line.strip()
                    if line and line not in remed_lines:
                        remed_lines.append(line)
            if len(remed_lines) > 1:
                remed_inner = "<ul>" + "".join(f"<li>{esc(r)}</li>" for r in remed_lines) + "</ul>"
            else:
                remed_inner = f"<p>{esc(remed_lines[0] if remed_lines else '')}</p>"
            remed_html = f'''<div class="detail-block">
                <div class="label">Remediation</div>
                {remed_inner}</div>'''

        # Evidence figures
        evidence_html = ""
        if engagement_dir:
            figures = _resolve_evidence(cat_findings, engagement_dir, max_figures=5, category=cat_name)
            for fig in figures:
                _GLOBAL_FIG_NUM[0] += 1
                fig["num"] = _GLOBAL_FIG_NUM[0]
            evidence_html = _render_figures(figures)

        cat_anchor = f'sec-cat-{scope_key}-{cat_name.lower().replace(" ", "-").replace("/", "-")}' if scope_key else ""
        display_title = cat_name
        html_parts.append(f'''
    <div class="finding" style="border-left: 4px solid {color};"{"" if not cat_anchor else f' id="{cat_anchor}"'}>
        <div class="finding-head" style="background: {bg};">
            <span class="badge" style="background:{color};">{risk}</span>
            <span class="title">{idx}. {esc(display_title)}</span>
        </div>
        <div class="finding-body">
            <div class="finding-meta">
                <span><strong>Locations:</strong> {len(sorted_locs)}</span>
                <span><strong>Findings:</strong> {len(unique_findings)}</span>
                <span><strong>Source:</strong> {esc(", ".join(sorted(all_sources)))}</span>
            </div>
            {enrichment_html}
            <div class="detail-block">
                <div class="label">Description</div>
                <p style="margin-bottom:8px;">{esc(cat_desc)}</p>
                <ul style="list-style:none;padding:0;margin:0;">
                    {"".join(finding_desc_rows)}
                </ul>
            </div>
            <div class="detail-block break-ok">
                <div class="label">Affected Locations</div>
                <table style="margin:4px 0;table-layout:fixed;width:100%;">
                    <tr><th style="width:35%;">Location</th><th style="width:65%;">{esc(detail_col)}</th></tr>
                    {"".join(affected_rows)}
                </table>
            </div>
            {evidence_html}
            {remed_html}
        </div>
    </div>''')
        idx += 1

    return "\n".join(html_parts)


# ── Narrative Builder ────────────────────────────────

def build_ext_narrative(client_name, subdomains, dns, hosts, services, software,
                        findings, risk_counts, rev):
    # Dynamically determine target IPs and infrastructure from data
    target_ips = set()
    for rec in dns.get("A", []):
        addr = rec.get("address", "")
        if addr:
            target_ips.add(addr)
    for h in hosts:
        hip = h.get("ip", "")
        if hip:
            target_ips.add(hip)

    # Detect CDN/WAF/hosting from reverse DNS
    hosting_hints = set()
    cdn_detected = False
    for ip_addr, fqdns in rev.items():
        for fqdn in fqdns:
            fl = fqdn.lower()
            if "cloudflare" in fl:
                hosting_hints.add("Cloudflare CDN/WAF")
                cdn_detected = True
            elif "shopify" in fl:
                hosting_hints.add("Shopify")
            elif "amazon" in fl or "aws" in fl or "ec2" in fl:
                hosting_hints.add("AWS")
            elif "azure" in fl or "microsoft" in fl:
                hosting_hints.add("Microsoft Azure")
            elif "google" in fl or "gcp" in fl:
                hosting_hints.add("Google Cloud")
            elif "akamai" in fl:
                hosting_hints.add("Akamai CDN")
                cdn_detected = True

    open_tcp_ports = set()
    for entries in services.values():
        for e in entries:
            if e.get("protocol") == "tcp" and e.get("state") == "open":
                open_tcp_ports.add(e.get("port", 0))

    header_findings = [f for f in findings if "security header" in f.get("title", "").lower()]
    ssl_findings = [f for f in findings if "ssl" in f.get("title", "").lower() or "tls" in f.get("title", "").lower()]
    crit_high = risk_counts.get("CRITICAL", 0) + risk_counts.get("HIGH", 0)
    hosting_str = ", ".join(sorted(hosting_hints)) if hosting_hints else "the hosting provider"
    ip_str = ", ".join(sorted(target_ips)[:3]) if target_ips else "the target"

    # Detect software for vulnerability context
    sw_names = set()
    for s in software:
        name = s.get("software", "").lower()
        if name:
            sw_names.add(name)

    phases = [
        ("Reconnaissance & Service Discovery",
         f'''The external assessment began with full 65,535-port TCP scanning of the target
infrastructure ({esc(ip_str)}) using nmap and masscan. This revealed
<strong>{len(open_tcp_ports)} confirmed open TCP service{"s" if len(open_tcp_ports) != 1 else ""}</strong>.
{"Reverse DNS and HTTP analysis confirmed the infrastructure is fronted by <strong>" + esc(hosting_str) + "</strong>. " if hosting_hints else ""}
{"Direct origin server access was not possible; all traffic is inspected and proxied, significantly narrowing the external attack surface." if cdn_detected else "The identified services were directly accessible for further analysis."}'''),

        ("Security Posture Analysis",
         f'''With the service map established, security header analysis and SSL/TLS
inspection were performed across all identified web ports.
{"This phase identified <strong>" + str(len(header_findings)) + " missing or misconfigured security headers</strong> across the HTTP/HTTPS services. " if header_findings else ""}
{"Headers such as <code>Strict-Transport-Security</code>, <code>Content-Security-Policy</code>, and <code>X-Frame-Options</code> were absent on several ports. Implementing these headers provides defense-in-depth against client-side attacks." if header_findings else "Security headers were properly configured across the assessed services."}
{"SSL/TLS analysis identified <strong>" + str(len(ssl_findings)) + " SSL/TLS-related findings</strong>." if ssl_findings else "SSL/TLS analysis confirmed modern cipher configuration with no legacy protocol weaknesses observed."}'''),

        ("Vulnerability Assessment",
         f'''Automated and manual vulnerability scanning was performed using nuclei,
nikto, and protocol-specific tools. {"No critical or high-severity vulnerabilities "
"were identified. " if crit_high == 0 else f"<strong>{crit_high} critical/high-severity finding{'s' if crit_high != 1 else ''}</strong> {'were' if crit_high != 1 else 'was'} identified requiring immediate attention. "}
The primary areas for improvement identified during the assessment
{"include" if header_findings or ssl_findings else "were minimal, with the overall security posture being"}
{" <strong>security header hardening</strong>" if header_findings else ""}
{"," if header_findings and ssl_findings else ""}
{" <strong>SSL/TLS configuration improvements</strong>" if ssl_findings else ""}
{"." if header_findings or ssl_findings else " strong."}'''),
    ]

    blocks = []
    for label, content in phases:
        content = " ".join(content.split())
        blocks.append(f'''<div class="narrative-block">
            <div class="phase-label">{label}</div>
            <p>{content}</p>
        </div>''')
    return "\n".join(blocks)


def build_osint_narrative(client_name, subdomains, dns, rev):
    mx_servers = [r.get("exchange", "") for r in dns.get("MX", [])]
    google_mail = any("google" in m.lower() for m in mx_servers)
    o365_mail = any("outlook" in m.lower() or "microsoft" in m.lower() for m in mx_servers)
    sub_list = [s.get("host", "") for s in subdomains]

    # Detect nameserver provider
    ns_servers = [r.get("nameserver", "") for r in dns.get("NS", [])]
    ns_provider = ""
    for ns in ns_servers:
        nsl = ns.lower()
        if "cloudflare" in nsl:
            ns_provider = "Cloudflare"
        elif "awsdns" in nsl or "amazon" in nsl:
            ns_provider = "AWS Route 53"
        elif "azure" in nsl:
            ns_provider = "Azure DNS"
        elif "google" in nsl:
            ns_provider = "Google Cloud DNS"
        elif "domaincontrol" in nsl:
            ns_provider = "GoDaddy"

    # Detect SPF/DMARC strength
    spf_val = _find_spf(dns)
    spf_strict = "-all" in spf_val
    dmarc_val = _find_dmarc(dns)
    dmarc_reject = "reject" in dmarc_val.lower() if dmarc_val else False
    dmarc_quarantine = "quarantine" in dmarc_val.lower() if dmarc_val else False

    # Detect CAA
    has_caa = bool(dns.get("CAA", []))

    mail_provider = ""
    if google_mail:
        mail_provider = "Google Workspace"
    elif o365_mail:
        mail_provider = "Microsoft 365"

    phases = [
        ("Passive Reconnaissance",
         f'''OSINT collection against <strong>{esc(client_name)}</strong> began with
multi-source subdomain enumeration and DNS analysis. Tools including subfinder,
theHarvester, dnsdumpster, and rapiddns identified <strong>{len(subdomains)} subdomain{"s" if len(subdomains) != 1 else ""}</strong>
{("including " + ", ".join(f"<code>{esc(s)}</code>" for s in sub_list[:3]) + ("" if len(sub_list) <= 3 else f" and {len(sub_list)-3} others")) if sub_list else ""}.
DNS record analysis mapped the complete infrastructure{": <strong>" + esc(ns_provider) + "</strong> nameservers" if ns_provider else ""}{" confirm edge security, WAF protection, DDoS mitigation, and TLS termination at the CDN layer" if ns_provider == "Cloudflare" else ""}.'''),

        ("Email & Identity Analysis",
         f'''{("Email infrastructure was identified as <strong>" + esc(mail_provider) + "</strong>. ") if mail_provider else ""}
{"A strict SPF policy (<code>-all</code>) is configured, which instructs receiving mail servers to reject messages that do not originate from authorized senders." if spf_strict else ("An SPF policy is configured (<code>" + esc(spf_val) + "</code>)." if spf_val and spf_val != "Not configured" else "No SPF record was identified, which may allow email spoofing.")}
{"DMARC is configured with a <code>reject</code> policy, providing strong protection against email spoofing." if dmarc_reject else ("DMARC is configured with a <code>quarantine</code> policy." if dmarc_quarantine else ("DMARC is configured but not set to reject — consider strengthening the policy." if dmarc_val else "No DMARC policy was identified, which may allow email spoofing attacks."))}
{("This combination significantly reduces the risk of phishing attacks that impersonate the <strong>" + esc(client_name) + "</strong> domain.") if (spf_strict and dmarc_reject) else ""}
{"The DNS analysis also identified a missing CAA record, which would restrict which Certificate Authorities can issue certificates for the domain — a low-effort improvement to prevent unauthorized certificate issuance." if not has_caa else ""}'''),
    ]

    blocks = []
    for label, content in phases:
        content = " ".join(content.split())
        blocks.append(f'''<div class="narrative-block">
            <div class="phase-label">{label}</div>
            <p>{content}</p>
        </div>''')
    return "\n".join(blocks)


def _find_spf(dns_data):
    for rec in dns_data.get("TXT", []):
        spf = rec.get("spf_raw", "")
        if spf:
            return spf
        text = rec.get("text", "")
        if text.startswith("v=spf1"):
            return text
    return "Not configured"


def _find_dmarc(dns_data):
    for rec in dns_data.get("DMARC", []):
        raw = rec.get("dmarc_raw", "") or rec.get("raw", "") or rec.get("text", "")
        if raw:
            return raw
    for rec in dns_data.get("TXT", []):
        text = rec.get("text", "")
        if text.startswith("v=DMARC1"):
            return text
    return ""


def _build_key_observations(scope_domains, scope_cidrs, rev, tcp_ports, dns_data, risk_counts, findings):
    obs = []
    # Infrastructure observation
    if scope_domains:
        domain_str = ", ".join(f"<strong>{esc(d)}</strong>" for d in scope_domains[:3])
        cidr_str = ", ".join(f"<strong>{esc(c)}</strong>" for c in scope_cidrs[:3]) if scope_cidrs else ""
        infra_note = f"The target domain{'s' if len(scope_domains) > 1 else ''} {domain_str}"
        if cidr_str:
            infra_note += f" resolve{'s' if len(scope_domains) == 1 else ''} to {cidr_str}"
        # Detect hosting from reverse DNS
        hosting = set()
        for fqdns in rev.values():
            for fqdn in fqdns:
                fl = fqdn.lower()
                if "cloudflare" in fl: hosting.add("Cloudflare CDN")
                elif "shopify" in fl: hosting.add("Shopify")
                elif "amazon" in fl or "aws" in fl: hosting.add("AWS")
                elif "azure" in fl: hosting.add("Azure")
                elif "google" in fl: hosting.add("Google Cloud")
        if hosting:
            infra_note += f" — indicating {', '.join(sorted(hosting))}-hosted infrastructure"
        infra_note += "."
        obs.append(f"<li>{infra_note}</li>")

    # Port observation
    if tcp_ports:
        obs.append(f"<li>{len(tcp_ports)} confirmed open TCP port{'s' if len(tcp_ports) != 1 else ''} identified across the target infrastructure.</li>")

    # Email observation
    mx_records = dns_data.get("MX", [])
    if mx_records:
        mx_providers = set()
        for r in mx_records:
            ex = (r.get("exchange") or "").lower()
            if "google" in ex: mx_providers.add("Google Workspace")
            elif "outlook" in ex or "microsoft" in ex: mx_providers.add("Microsoft 365")
        spf_val = _find_spf(dns_data)
        dmarc_val = _find_dmarc(dns_data)
        email_note = "Email infrastructure"
        if mx_providers:
            email_note += f" uses {', '.join(sorted(mx_providers))}"
        if "-all" in spf_val:
            email_note += " with a strict SPF policy (<code>-all</code>)"
        if dmarc_val and "reject" in dmarc_val.lower():
            email_note += " and DMARC configured for reject"
        email_note += "."
        obs.append(f"<li>{email_note}</li>")

    # Risk observation
    crit = risk_counts.get("CRITICAL", 0)
    high = risk_counts.get("HIGH", 0)
    if crit + high == 0:
        header_findings = [f for f in findings if "security header" in f.get("title", "").lower()]
        areas = []
        if header_findings: areas.append("security header hardening")
        ssl_findings = [f for f in findings if "ssl" in f.get("title", "").lower() or "tls" in f.get("title", "").lower()]
        if ssl_findings: areas.append("SSL/TLS configuration")
        obs.append(f'<li>No critical or high-severity vulnerabilities were identified. {"Primary areas for improvement are " + " and ".join(areas) + "." if areas else ""}</li>')
    else:
        obs.append(f"<li><strong>{crit + high} critical/high-severity finding{'s' if crit + high != 1 else ''}</strong> identified requiring remediation attention.</li>")

    return obs


# ── Main Report Builder ──────────────────────────────

def build_report(data):
    cm = data.get("crucible_meta", {})
    eng = data.get("engagement", {}).get("engagement", {})
    consultant = cm.get("consultant", {})
    client_poc = cm.get("client_poc", {})
    client_name = cm.get("client_name", "Client")
    active_scopes = cm.get("active_scopes", [])
    engagement_dir = cm.get("project_dir", "")

    _GLOBAL_FIG_NUM[0] = 0
    is_incomplete = data.get("incomplete", False)
    tool_to_scope = build_scope_map(cm)

    all_findings = []
    for f in data.get("ss3_findings", []):
        f.setdefault("tool", "scattershot3")
        all_findings.append(f)
    for f in data.get("fracture_findings", []):
        f.setdefault("tool", "fracture")
        all_findings.append(f)
    for f in data.get("osift_findings", []):
        f.setdefault("tool", "osift")
        if _is_empty_typosquat(f):
            continue
        all_findings.append(f)

    findings = merge_findings(all_findings)

    findings = [f for f in findings if not _should_exclude_from_report(f)]

    # Retroactive exclusion: filter findings for excluded IPs
    _excl_nets = _parse_exclusion_networks(cm)
    if _excl_nets:
        findings = [f for f in findings
                    if not _ip_in_exclusions(f.get("ip", ""), _excl_nets)]

    for f in findings:
        f["_scope"] = assign_scope(f, tool_to_scope)
        port = int(f.get("port") or 0)
        svc = (f.get("service") or "").strip()
        if not svc and port:
            if port in _HTTPS_PORTS:
                f["service"] = "https"
            elif port == 80:
                f["service"] = "http"

    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in findings)

    # Split findings by scope
    scope_findings = defaultdict(list)
    for f in findings:
        scope_findings[f["_scope"]].append(f)

    for scope in scope_findings:
        scope_findings[scope].sort(key=risk_sort)

    # Scope definition — tester-defined targets (authoritative)
    scope_def = cm.get("scope_definition", {})
    scope_cidrs = scope_def.get("network_cidrs", [])
    scope_domains = scope_def.get("domains", [])
    scope_urls = scope_def.get("target_urls", [])

    # Filter findings whose hostname was derived from reverse DNS of an in-scope IP
    # but the hostname itself is not an in-scope domain or subdomain.
    # When OOS handling is "separated" or "combined", keep these but flag as OOS.
    _oos_mode = cm.get("oos_handling", "explicit")
    if scope_domains:
        _scope_domain_set = set(d.lower() for d in scope_domains)
        def _hostname_in_scope(hostname):
            hostname = hostname.lower()
            if hostname in _scope_domain_set:
                return True
            for sd in _scope_domain_set:
                if hostname.endswith("." + sd):
                    return True
            return False

        filtered = []
        for f in findings:
            h = (f.get("hostname") or "").strip()
            if h and not _hostname_in_scope(h):
                ip = f.get("ip", "")
                if _oos_mode != "explicit":
                    f["oos"] = True
                    filtered.append(f)
                elif ip:
                    f["hostname"] = ""
                    filtered.append(f)
                # else: drop the finding (explicit mode, no IP fallback)
            else:
                filtered.append(f)
        findings = filtered
        scope_findings = defaultdict(list)
        for f in findings:
            scope_findings[f["_scope"]].append(f)
        for scope in scope_findings:
            scope_findings[scope].sort(key=risk_sort)
        risk_counts = Counter((f.get("risk") or "INFO").upper() for f in findings)

    # Intelligence (tool-discovered, supplementary)
    osift_targets = data.get("osift_targets", {})
    subdomains = osift_targets.get("subdomains", [])
    ips = osift_targets.get("ips", [])
    dns_data = data.get("osift_dns", {})
    nslookup = data.get("osift_nslookup", {})
    dns_per_domain = data.get("osift_dns_per_domain", {})
    nslookup_per_domain = data.get("osift_nslookup_per_domain", {})
    hosts = data.get("ss3_hosts", [])
    software_raw = data.get("ss3_software", [])
    services = data.get("ss3_services", {})

    # Retroactive exclusion: filter hosts/software/services for excluded IPs
    if _excl_nets:
        hosts = [h for h in hosts
                 if not _ip_in_exclusions(h.get("ip", ""), _excl_nets)]
        software_raw = [s for s in software_raw
                        if not _ip_in_exclusions(s.get("ip", ""), _excl_nets)]
        services = {
            svc: [e for e in entries
                  if not _ip_in_exclusions(e.get("ip", ""), _excl_nets)]
            for svc, entries in services.items()
        }
        services = {k: v for k, v in services.items() if v}

    # Normalize software via Crucible
    software = _normalize_software(software_raw)
    software.sort(key=lambda s: (s.get("software", "").lower(), s.get("ip", "")))

    # Filter services: confirmed open only
    open_services = {}
    for svc_name, entries in services.items():
        open_entries = [e for e in entries if e.get("state") == "open"]
        if open_entries:
            open_services[svc_name] = open_entries

    tcp_ports = set()
    for entries in open_services.values():
        for e in entries:
            if e.get("protocol") == "tcp":
                tcp_ports.add(e.get("port", 0))

    rev = nslookup.get("reverse_lookups", {})
    now_str = datetime.now().strftime("%B %d, %Y")
    start_date = eng.get("start_date", cm.get("start_date", ""))
    end_date = eng.get("end_date", cm.get("end_date", ""))

    # ── Section numbering ──
    # 1: Executive Summary, 2: Scope & Methodology, 3: Intelligence Summary
    # 4: Findings Overview, 5: Attack Narrative, 6+: per-scope findings, then Appendix

    narrative_section_idx = 5

    # ── Build Attack Narrative (section 5) ──
    narrative_html = f'''
<div class="page">
<h1 id="sec-narrative">{narrative_section_idx}. Attack Narrative</h1>
<p class="section-intro">
    This section presents the assessment from an attacker's perspective, describing the
    reconnaissance and analysis process as it unfolded during the engagement.
</p>
'''
    for scope in active_scopes:
        scope_label = SCOPE_LABELS.get(scope, scope.title())
        narrative_html += f'<h2 id="sec-narr-{scope}">{scope_label}</h2>'
        if scope == "external":
            narrative_html += build_ext_narrative(
                client_name, subdomains, dns_data, hosts, open_services,
                software, scope_findings.get("external", []),
                Counter((f.get("risk") or "INFO").upper() for f in scope_findings.get("external", [])),
                rev)
        elif scope == "osint":
            narrative_html += build_osint_narrative(
                client_name, subdomains, dns_data, rev)
        else:
            narrative_html += f'<p class="section-intro">No narrative available for {scope_label} scope.</p>'
    narrative_html += '</div>'

    # ── Build scope-specific finding sections (top-level, after narrative) ──
    scope_sections_html = ""
    scope_section_idx = 6
    toc_scope_items = []

    oos_mode = cm.get("oos_handling", "explicit")

    for scope in active_scopes:
        scope_label = SCOPE_LABELS.get(scope, scope.title())
        all_scope = scope_findings.get(scope, [])

        if oos_mode == "separated":
            s_findings = [f for f in all_scope if not f.get("oos")]
            oos_findings = [f for f in all_scope if f.get("oos")]
        else:
            s_findings = all_scope
            oos_findings = []

        s_risk_counts = Counter((f.get("risk") or "INFO").upper() for f in s_findings)

        toc_scope_items.append((scope_section_idx, scope_label, len(s_findings), scope))

        scope_summary = SCOPE_SUMMARIES.get(scope, "")
        scope_sections_html += f'''
<div class="page">
<h1 id="sec-scope-{scope}">{scope_section_idx}. {scope_label}</h1>
<p class="section-intro">{esc(scope_summary)}</p>
<div class="scope-header">
    <h2>{scope_label}</h2>
    <div class="scope-desc">{len(s_findings)} finding{"s" if len(s_findings) != 1 else ""} identified
        — {s_risk_counts.get("CRITICAL",0)} Critical, {s_risk_counts.get("HIGH",0)} High,
        {s_risk_counts.get("MEDIUM",0)} Medium, {s_risk_counts.get("LOW",0)} Low,
        {s_risk_counts.get("INFO",0)} Informational</div>
</div>
<hr class="section-divider">
{build_grouped_findings_section(s_findings, scope_label, engagement_dir=engagement_dir, scope_key=scope)}
</div>
'''
        scope_section_idx += 1

        if oos_findings:
            oos_label = f"{scope_label} - OOS"
            oos_key = f"{scope}_oos"
            oos_risk_counts = Counter((f.get("risk") or "INFO").upper() for f in oos_findings)
            toc_scope_items.append((scope_section_idx, oos_label, len(oos_findings), oos_key))
            scope_sections_html += f'''
<div class="page">
<h1 id="sec-scope-{oos_key}">{scope_section_idx}. {oos_label}</h1>
<p class="section-intro">The following findings were identified on targets derived from in-scope assets but not explicitly defined as in-scope. These targets share a parent domain or IP address with explicitly in-scope targets.</p>
<div class="scope-header">
    <h2>{oos_label}</h2>
    <div class="scope-desc">{len(oos_findings)} out-of-scope finding{"s" if len(oos_findings) != 1 else ""} identified
        — {oos_risk_counts.get("CRITICAL",0)} Critical, {oos_risk_counts.get("HIGH",0)} High,
        {oos_risk_counts.get("MEDIUM",0)} Medium, {oos_risk_counts.get("LOW",0)} Low,
        {oos_risk_counts.get("INFO",0)} Informational</div>
</div>
<hr class="section-divider">
{build_grouped_findings_section(oos_findings, oos_label, engagement_dir=engagement_dir, scope_key=oos_key)}
</div>
'''
            scope_section_idx += 1

    appendix_section_idx = scope_section_idx

    # Per-domain DNS sections
    def _build_dns_rows(domain_dns):
        rows = []
        for rtype in ["A", "NS", "MX", "TXT", "SOA", "DMARC"]:
            records = domain_dns.get(rtype, [])
            for rec in records[:5]:
                raw = rec.get("raw", "") or rec.get("text", "") or ""
                if rtype == "MX":
                    raw = f'{rec.get("priority","")} {rec.get("exchange","")}'.strip()
                elif rtype == "NS":
                    raw = rec.get("nameserver", raw)
                elif rtype == "A":
                    raw = rec.get("address", raw)
                rows.append(f'<tr><td><strong>{rtype}</strong></td>'
                           f'<td style="word-break:break-all;">{esc(raw)}</td></tr>')
        spf_val = _find_spf(domain_dns)
        if spf_val and spf_val != "Not configured":
            rows.append(f'<tr><td><strong>SPF</strong></td>'
                       f'<td style="word-break:break-all;">{esc(spf_val)}</td></tr>')
        return rows

    dns_sections_html = ""
    if dns_per_domain and len(dns_per_domain) > 1:
        for domain_name, domain_dns in sorted(dns_per_domain.items()):
            rows = _build_dns_rows(domain_dns)
            if rows:
                dns_sections_html += f'<h3>{esc(domain_name)}</h3>'
                dns_sections_html += f'<table><tr><th style="width:15%;">Record</th><th>Value</th></tr>{"".join(rows)}</table>'
    else:
        dns_rows = _build_dns_rows(dns_data)
        if dns_rows:
            dns_sections_html = f'<table><tr><th style="width:15%;">Record</th><th>Value</th></tr>{"".join(dns_rows)}</table>'

    # Subdomain rows (combined across domains)
    sub_rows = []
    for sub in subdomains:
        host = sub.get("host", "")
        ip_addr = sub.get("ip", "")
        srcs = ", ".join(sub.get("sources", []))
        sub_rows.append(f'<tr><td>{esc(host)}</td><td>{esc(ip_addr or "—")}</td>'
                       f'<td style="font-size:7.5pt;">{esc(srcs)}</td></tr>')

    # Reverse DNS — per-domain sections
    rev_sections_html = ""
    if dns_per_domain and len(dns_per_domain) > 1:
        for domain_name in sorted(dns_per_domain.keys()):
            ns_data = nslookup_per_domain.get(domain_name, {})
            domain_rev = ns_data.get("reverse_lookups", {})
            if domain_rev:
                rows = []
                for ip_addr, fqdns in domain_rev.items():
                    for fqdn in fqdns:
                        rows.append(f'<tr><td>{esc(ip_addr)}</td><td>{esc(fqdn)}</td></tr>')
                if rows:
                    rev_sections_html += f'<h3>{esc(domain_name)}</h3>'
                    rev_sections_html += f'<table><tr><th>IP Address</th><th>Reverse Hostname</th></tr>{"".join(rows)}</table>'
    else:
        rev_rows = []
        for ip_addr, fqdns in rev.items():
            for fqdn in fqdns:
                rev_rows.append(f'<tr><td>{esc(ip_addr)}</td><td>{esc(fqdn)}</td></tr>')
        if rev_rows:
            rev_sections_html = f'<table><tr><th>IP Address</th><th>Reverse Hostname</th></tr>{"".join(rev_rows)}</table>'

    # Email Infrastructure — per-domain sections (MX records only; SPF/DMARC in DNS)
    email_sections_html = ""
    if dns_per_domain and len(dns_per_domain) > 1:
        for domain_name, domain_dns in sorted(dns_per_domain.items()):
            mx_records = domain_dns.get("MX", [])
            if mx_records:
                mx_rows = "".join(f'<tr><td>{r.get("priority","")}</td><td>{esc(r.get("exchange",""))}</td></tr>' for r in mx_records)
                email_sections_html += f'<h3>{esc(domain_name)}</h3>'
                email_sections_html += f'<table><tr><th>Priority</th><th>Mail Server</th></tr>{mx_rows}</table>'
    else:
        mx_rows = "".join(f'<tr><td>{r.get("priority","")}</td><td>{esc(r.get("exchange",""))}</td></tr>' for r in dns_data.get("MX", []))
        email_sections_html = f'<table><tr><th>Priority</th><th>Mail Server</th></tr>{mx_rows}</table>'

    # Category table for overview
    categories = defaultdict(list)
    for f in findings:
        cat = categorize_finding(f)
        categories[cat].append(f)

    cat_rows = []
    for cat, items in sorted(categories.items(),
                              key=lambda x: min(risk_sort(i) for i in x[1])):
        highest = min((i.get("risk","INFO").upper() for i in items),
                      key=lambda r: RISK_ORDER.get(r, 5))
        color = RISK_COLORS.get(highest, "#666")
        cat_rows.append(f'<tr><td>{esc(cat)}</td><td style="text-align:center;">{len(items)}</td>'
                       f'<td><span class="badge-sm" style="background:{color};">{highest}</span></td></tr>')

    # Host table
    host_rows = []
    for h in hosts:
        hip = h.get("ip", "")
        hname = h.get("hostname", "")
        hfindings = len([f for f in findings if f.get("ip") == hip])
        _hp = h.get("ports", {})
        hports = len(_hp) if isinstance(_hp, (dict, list)) else 0
        host_rows.append(f'<tr><td>{esc(hip)}</td><td>{esc(hname)}</td>'
                        f'<td style="text-align:center;">{hfindings}</td>'
                        f'<td style="text-align:center;">{hports}</td></tr>')

    # Services table — one entry per port
    svc_rows = []
    seen_ports = set()
    for svc_name, entries in sorted(open_services.items()):
        for e in sorted(entries, key=lambda x: x.get("port", 0)):
            port = e.get("port", 0)
            proto = e.get("protocol", "tcp")
            port_key = (port, proto)
            if port_key in seen_ports:
                continue
            seen_ports.add(port_key)
            svc_rows.append(
                f'<tr><td>{port}</td>'
                f'<td>{esc(proto)}</td>'
                f'<td>{esc(svc_name)}</td>'
                f'<td>open</td></tr>'
            )
    svc_rows.sort(key=lambda r: int(r.split("<td>")[1].split("</td>")[0]) if r.split("<td>")[1].split("</td>")[0].isdigit() else 0)

    # Software table — normalized, newline-separated
    sw_rows = []
    for s in software:
        sw_rows.append(
            f'<tr><td>{esc(s.get("software",""))}</td>'
            f'<td>{esc(s.get("version","") or "—")}</td>'
            f'<td class="nl-cell">{esc(s.get("port",""))}</td>'
            f'<td class="nl-cell" style="font-size:7.5pt;">{esc(s.get("method",""))}</td></tr>'
        )

    # Identified Assets — Table 1: IP / Ports / Service / Software
    ip_asset_map = defaultdict(lambda: defaultdict(lambda: {"service": "", "software": []}))
    for svc_name, entries in open_services.items():
        for e in entries:
            ip = e.get("ip", "") or (hosts[0].get("ip", "") if hosts else "")
            port = e.get("port", 0)
            ip_asset_map[ip][port]["service"] = svc_name
    for s in software:
        sw_ip = s.get("ip", "")
        sw_port = s.get("port", "")
        sw_name = s.get("software", "")
        sw_ver = s.get("version", "")
        sw_str = f"{sw_name} {sw_ver}".strip() if sw_name else ""
        if sw_ip and sw_port and sw_str:
            for p in str(sw_port).split("\n"):
                p = p.strip()
                if p.isdigit():
                    ip_asset_map[sw_ip][int(p)]["software"].append(sw_str)

    asset_ip_rows = []
    for ip in sorted(ip_asset_map.keys()):
        ports_data = ip_asset_map[ip]
        sorted_ports = sorted(ports_data.keys())
        ports_str = "<br>".join(str(p) for p in sorted_ports)
        services_str = "<br>".join(ports_data[p]["service"] or "—" for p in sorted_ports)
        sw_str = "<br>".join(esc(", ".join(ports_data[p]["software"])) or "" for p in sorted_ports)
        asset_ip_rows.append(
            f'<tr><td>{esc(ip)}</td>'
            f'<td class="nl-cell">{ports_str}</td>'
            f'<td class="nl-cell">{services_str}</td>'
            f'<td class="nl-cell" style="font-size:7.5pt;">{sw_str if sw_str.strip() else ""}</td></tr>'
        )

    # Identified Assets — Table 2: FQDN-based (from subdomains + hosts)
    asset_fqdn_rows = []
    fqdn_seen = set()
    for sub in subdomains:
        fqdn = sub.get("host", "")
        if not fqdn or fqdn in fqdn_seen:
            continue
        fqdn_seen.add(fqdn)
        sub_ip = sub.get("ip", "")
        sub_ports = ""
        sub_svc = ""
        sub_waf = ""
        sub_lb = ""
        sub_cms = ""
        sub_ver = ""
        # Match against hosts for port/service info
        for h in hosts:
            if h.get("ip") == sub_ip or h.get("hostname") == fqdn:
                h_ports = h.get("ports", {})
                if isinstance(h_ports, dict):
                    port_nums = sorted(int(p) for p in h_ports.keys() if str(p).isdigit())
                elif isinstance(h_ports, list):
                    port_nums = sorted(h_ports)
                else:
                    port_nums = []
                sub_ports = "<br>".join(str(p) for p in port_nums[:10])
                break
        # Match against software for CMS/version
        for s in software:
            sw_name = s.get("software", "").lower()
            if s.get("ip") == sub_ip:
                if any(k in sw_name for k in ("wordpress", "drupal", "joomla", "shopify", "magento", "wix")):
                    sub_cms = s.get("software", "")
                    sub_ver = s.get("version", "") or ""
                elif "cloudflare" in sw_name:
                    sub_waf = s.get("software", "")
        asset_fqdn_rows.append(
            f'<tr><td>{esc(fqdn)}</td><td>{esc(sub_ip or "—")}</td>'
            f'<td class="nl-cell">{sub_ports or "—"}</td><td>{esc(sub_svc or "—")}</td>'
            f'<td>{esc(sub_waf or "—")}</td><td>{esc(sub_lb or "—")}</td>'
            f'<td>{esc(sub_cms or "—")}</td><td>{esc(sub_ver or "—")}</td></tr>'
        )

    # Build per-scope category lists for TOC sub-items (name, risk)
    scope_category_info = {}
    for scope in active_scopes:
        all_scope_f = scope_findings.get(scope, [])
        if _oos_mode == "separated":
            inscope_f = [f for f in all_scope_f if not f.get("oos")]
            oos_f = [f for f in all_scope_f if f.get("oos")]
        else:
            inscope_f = all_scope_f
            oos_f = []

        cats = defaultdict(list)
        for f in inscope_f:
            cats[categorize_finding(f)].append(f)
        sorted_cats = sorted(cats.items(),
                             key=lambda x: (-max(RISK_NUMERIC.get(
                                 (i.get("risk") or "INFO").upper(), 0) for i in x[1]),
                                 x[0].lower()))
        scope_category_info[scope] = [
            (name, _highest_risk(findings)) for name, findings in sorted_cats
        ]

        if oos_f:
            oos_key = f"{scope}_oos"
            oos_cats = defaultdict(list)
            for f in oos_f:
                oos_cats[categorize_finding(f)].append(f)
            oos_sorted = sorted(oos_cats.items(),
                                key=lambda x: (-max(RISK_NUMERIC.get(
                                    (i.get("risk") or "INFO").upper(), 0) for i in x[1]),
                                    x[0].lower()))
            scope_category_info[oos_key] = [
                (name, _highest_risk(findings)) for name, findings in oos_sorted
            ]

    # Count finding groupings (categories) per risk level across all scopes
    grouping_risk_counts = Counter()
    for scope in active_scopes:
        for _cat_name, cat_risk in scope_category_info.get(scope, []):
            grouping_risk_counts[cat_risk] += 1

    # Build TOC with clickable links
    def _toc_main(num, title, anchor):
        return (f'<div class="toc-item"><span class="toc-num">{num}</span>'
                f'<a href="#{anchor}" class="toc-title">{title}</a>'
                f'<span class="toc-dots"></span>'
                f'<span class="toc-page" data-toc-target="{anchor}"></span></div>')

    def _toc_sub(title, anchor=""):
        link = f'<a href="#{anchor}" class="toc-title">{title}</a>' if anchor else f'<span class="toc-title">{title}</span>'
        page_span = f'<span class="toc-dots"></span><span class="toc-page" data-toc-target="{anchor}"></span>' if anchor else ''
        return f'<div class="toc-sub"><span class="toc-num"></span>{link}{page_span}</div>'

    toc_html = f'''
    {_toc_main("1", "Scope &amp; Methodology", "sec-scope")}
    {_toc_sub("Engagement Scope", "sec-eng-scope")}
    {_toc_sub("Target Scope", "sec-target-scope")}
    {_toc_sub("Methodology", "sec-methodology")}
    {_toc_main("2", "Executive Summary", "sec-exec")}
    {_toc_sub("Findings By Risk", "sec-findings-by-risk")}
    {_toc_sub("Risk Distribution", "sec-risk-dist")}
    {_toc_sub("Key Observations", "sec-key-obs")}
    {_toc_main("3", "Intelligence Summary", "sec-intel")}
    {_toc_sub("DNS Infrastructure", "sec-dns")}
    {_toc_sub("Subdomains Discovered", "sec-subdomains")}
    {_toc_sub("Email Infrastructure", "sec-email")}
    {_toc_main("4", "Findings Overview", "sec-findings-overview")}
    {_toc_sub("By Category", "sec-by-cat")}
    {_toc_sub("By Host", "sec-by-host")}
    {_toc_sub("By Scope", "sec-by-scope")}
    {_toc_main("5", "Attack Narrative", "sec-narrative")}'''

    for scope in active_scopes:
        scope_label_toc = SCOPE_LABELS.get(scope, scope.title())
        toc_html += f'\n    {_toc_sub(scope_label_toc, f"sec-narr-{scope}")}'

    for idx, label, count, skey in toc_scope_items:
        scope_anchor = f"sec-scope-{skey}"
        toc_html += f'\n    {_toc_main(idx, f"{label} ({count} findings)", scope_anchor)}'
        cat_info = scope_category_info.get(skey, [])
        for cat_name, cat_risk in cat_info:
            cat_color = RISK_COLORS.get(cat_risk, "#94a3b8")
            cat_anchor = f"sec-cat-{skey}-{cat_name.lower().replace(' ', '-').replace('/', '-')}"
            toc_html += (f'\n    <div class="toc-sub"><span class="toc-num"></span>'
                         f'<a href="#{cat_anchor}" class="toc-title">'
                         f'<span class="toc-risk-pip" style="background:{cat_color};"></span>'
                         f'{esc(cat_name)}'
                         f'<span class="toc-risk-label" style="color:{cat_color};">{cat_risk}</span>'
                         f'</a>'
                         f'<span class="toc-dots"></span>'
                         f'<span class="toc-page" data-toc-target="{cat_anchor}"></span>'
                         f'</div>')

    toc_html += f'''
    {_toc_main(appendix_section_idx, "Appendix: Host &amp; Service Inventory", "sec-appendix")}
    {_toc_sub("Discovered Services", "sec-services")}
    {_toc_sub("Detected Software", "sec-software")}
    {_toc_sub("Identified Assets", "sec-assets")}
    {_toc_sub("Tools Used", "sec-tools")}'''

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width">
<title>{esc(client_name)} — Penetration Test Report</title>
<style>{REPORT_CSS}</style>
</head>
<body>

<!-- ═══ COVER PAGE ═══ -->
<div class="cover-page">
    <div class="cover-stripe"></div>
    <div class="cover-classification">Confidential</div>
    {'<div class="cover-incomplete-stamp">INCOMPLETE</div>' if is_incomplete else ''}
    <div class="cover-main">
        <div class="cover-accent-line"></div>
        <div class="cover-client">{esc(client_name)}</div>
        <div class="cover-type">External Penetration Test Report</div>
    </div>
    <div class="cover-meta-block">
        <div class="cover-meta"><strong>Prepared by</strong>&ensp; {esc(consultant.get("name", ""))}, {esc(consultant.get("title", ""))}</div>
        <div class="cover-meta">{esc(consultant.get("email", ""))}</div>
        <div class="cover-meta" style="margin-top:10px;">
            <strong>Engagement</strong>&ensp; {esc(start_date)} — {esc(end_date)}
        </div>
        <div class="cover-meta"><strong>Report Date</strong>&ensp; {now_str}</div>
        <div class="cover-meta"><strong>Classification</strong>&ensp; Confidential</div>
    </div>
</div>

<!-- ═══ TABLE OF CONTENTS ═══ -->
<div class="page">
<h1>Table of Contents</h1>
<div class="toc">
    {toc_html}
</div>
</div>

<!-- ═══ 1. SCOPE & METHODOLOGY ═══ -->
<div class="page">
<h1 id="sec-scope">1. Scope &amp; Methodology</h1>

<h2 id="sec-eng-scope">Engagement Scope</h2>
<table>
    <tr><th style="width:30%;">Parameter</th><th>Detail</th></tr>
    <tr><td><strong>Client</strong></td><td>{esc(client_name)}</td></tr>
    <tr><td><strong>Client POC</strong></td><td>{esc(client_poc.get("name",""))} — {esc(client_poc.get("email",""))}</td></tr>
    <tr><td><strong>Testing Type</strong></td><td class="nl-cell">{"<br>".join(SCOPE_LABELS.get(s, s.title()) for s in active_scopes)}</td></tr>
    <tr><td><strong>Active Scopes</strong></td><td>{len(active_scopes)} — {", ".join(s.title() for s in active_scopes)}</td></tr>
    <tr><td><strong>Engagement Period</strong></td><td>{esc(start_date)} — {esc(end_date)}</td></tr>
</table>

<h2 id="sec-target-scope">Target Scope</h2>
<table>
    <tr><th style="width:30%;">Scope</th><th>Targets</th></tr>
    {_scope_target_rows(active_scopes, scope_def)}
</table>

<h2 id="sec-methodology">Methodology</h2>
<table>
    <tr><th>Phase</th><th>Description</th><th>Tooling</th></tr>
    <tr><td><strong>OSINT / Passive<br>Recon</strong></td>
        <td class="nl-cell">Subdomain enumeration
DNS analysis
Email harvesting
Technology fingerprinting</td>
        <td class="nl-cell">subfinder
theHarvester
dnsx / dig
dnstwist
Custom Scripts and Tools</td></tr>
    <tr><td><strong>Active<br>Reconnaissance</strong></td>
        <td class="nl-cell">Full 65535-port TCP scan
Service identification
Banner grabbing</td>
        <td class="nl-cell">nmap
masscan
Custom Scripts and Tools</td></tr>
    <tr><td><strong>Enumeration</strong></td>
        <td class="nl-cell">Web technology detection
SSL/TLS analysis
Security header audit</td>
        <td class="nl-cell">shcheck
testssl.sh
sslscan
webanalyze / whatweb
Custom Scripts and Tools</td></tr>
    <tr><td><strong>Vulnerability<br>Analysis</strong></td>
        <td class="nl-cell">Automated vulnerability scanning
Manual verification</td>
        <td class="nl-cell">nuclei
nikto
Burp Suite
Nessus
Custom Scripts and Tools</td></tr>
</table>
</div>

<!-- ═══ 2. EXECUTIVE SUMMARY ═══ -->
<div class="page">
<h1 id="sec-exec">2. Executive Summary</h1>
<p class="section-intro">
    This report presents the findings of an external penetration test conducted against
    <strong>{esc(client_name)}</strong> infrastructure between
    <strong>{esc(start_date)}</strong> and <strong>{esc(end_date)}</strong> by
    <strong>{esc(consultant.get("name", ""))}</strong>. The assessment targeted externally-facing
    assets including web applications, network services, and DNS infrastructure associated with
    <strong>{", ".join(esc(d) for d in scope_domains)}</strong>
    ({", ".join(esc(c) for c in scope_cidrs)}). Testing was conducted across
    <strong>{len(active_scopes)} scope{"s" if len(active_scopes) != 1 else ""}</strong>:
    {", ".join(SCOPE_LABELS.get(s, s.title()) for s in active_scopes)}.
</p>

<div class="stats-row">
    <div class="stat-card">
        <div class="stat-number">{sum(grouping_risk_counts.values())}</div>
        <div class="stat-label">Total Findings</div>
    </div>
    <div class="stat-card">
        <div class="stat-number">{len(hosts)}</div>
        <div class="stat-label">Hosts Tested</div>
    </div>
    <div class="stat-card">
        <div class="stat-number">{len(tcp_ports)}</div>
        <div class="stat-label">Open TCP Ports</div>
    </div>
    <div class="stat-card">
        <div class="stat-number">{len(subdomains)}</div>
        <div class="stat-label">Subdomains</div>
    </div>
</div>

<h2 id="sec-findings-by-risk">Findings By Risk</h2>
<div class="risk-cards-row">
    {"".join(f'<div class="risk-card"><div class="risk-card-count" style="color:{RISK_COLORS[r]};">{grouping_risk_counts.get(r, 0)}</div><div class="risk-card-label">{r}</div></div>' for r in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])}
</div>

<h2 id="sec-risk-dist">Risk Distribution</h2>
<div class="risk-charts-row">
    <div class="risk-chart-col">
        <h4>By Finding Count</h4>
        {_build_risk_pie(risk_counts)}
    </div>
    <div class="risk-chart-col">
        <h4>By Scope</h4>
        {_build_scope_bar(scope_findings, active_scopes, oos_mode=_oos_mode)}
    </div>
    <div class="risk-chart-legend">
        {"".join(f'<div class="risk-legend-row"><span class="risk-legend-pip" style="background:{RISK_COLORS[r]};"></span><span class="risk-legend-name">{r}</span></div>' for r in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] if risk_counts.get(r, 0) > 0)}
    </div>
</div>

<h2 id="sec-key-obs">Key Observations</h2>
<ul class="obs-list">
    {"".join(_build_key_observations(scope_domains, scope_cidrs, rev, tcp_ports, dns_data, risk_counts, findings))}
</ul>
</div>

<!-- ═══ 3. INTELLIGENCE SUMMARY ═══ -->
<div class="page">
<h1 id="sec-intel">3. Intelligence Summary</h1>
<p class="section-intro">
    Passive reconnaissance and OSINT collection revealed the following publicly accessible
    information about {esc(client_name)}'s external footprint.
</p>

<h2 id="sec-dns">DNS Infrastructure</h2>
{dns_sections_html}

<h2 id="sec-subdomains">Subdomains Discovered</h2>
<table>
    <tr><th>Subdomain</th><th>IP Address</th><th>Sources</th></tr>
    {"".join(sub_rows)}
</table>

{"<h2>Reverse DNS</h2>" + rev_sections_html if rev_sections_html else ""}

<h2 id="sec-email">Email Infrastructure</h2>
{email_sections_html}


</div>

<!-- ═══ 4. FINDINGS OVERVIEW ═══ -->
<div class="page">
<h1 id="sec-findings-overview">4. Findings Overview</h1>
<p class="section-intro">
    A total of <strong>{len(findings)}</strong> unique findings were identified across all
    testing phases after deduplication and cross-tool merge.
</p>

<h2 id="sec-by-cat">By Category</h2>
<table>
    <tr><th>Category</th><th style="text-align:center;width:12%;">Count</th><th style="width:15%;">Highest</th></tr>
    {"".join(cat_rows)}
</table>

<h2 id="sec-by-host">By Host</h2>
<table>
    <tr><th>IP Address</th><th>Hostname</th><th style="text-align:center;">Findings</th><th style="text-align:center;">Ports</th></tr>
    {"".join(host_rows)}
</table>

<h2 id="sec-by-scope">By Scope</h2>
<table>
    <tr><th>Scope</th><th style="text-align:center;">Findings</th><th style="width:50%;">Risk Breakdown</th></tr>
    {"".join(_build_scope_table_rows(scope_findings, active_scopes, _oos_mode))}
</table>
</div>

<!-- ═══ 5. ATTACK NARRATIVE ═══ -->
{narrative_html}

<!-- ═══ 6+. SCOPE FINDINGS ═══ -->
{scope_sections_html}

<!-- ═══ APPENDIX ═══ -->
<div class="page">
<h1 id="sec-appendix">{appendix_section_idx}. Appendix: Host &amp; Service Inventory</h1>

<h2 id="sec-services">Discovered Services (Confirmed Open)</h2>
<table>
    <tr><th>Port</th><th>Protocol</th><th>Service</th><th>State</th></tr>
    {"".join(svc_rows)}
</table>

<h2 id="sec-software">Detected Software</h2>
<table>
    <tr><th>Software</th><th>Version</th><th>Port</th><th>Method</th></tr>
    {"".join(sw_rows)}
</table>

<h2 id="sec-assets">Identified Assets</h2>
<h3>By IP Address</h3>
<table>
    <tr><th>IP</th><th>Ports</th><th>Service</th><th>Software</th></tr>
    {"".join(asset_ip_rows) if asset_ip_rows else "<tr><td colspan='4' style='color:var(--slate-400);font-style:italic;'>No IP-based assets identified</td></tr>"}
</table>
<h3>By FQDN</h3>
<table style="font-size:8pt;">
    <tr><th>FQDN</th><th>IP</th><th>Ports</th><th>Service</th><th>WAF</th><th>Load Balancer</th><th>CMS</th><th>Version</th></tr>
    {"".join(asset_fqdn_rows) if asset_fqdn_rows else "<tr><td colspan='8' style='color:var(--slate-400);font-style:italic;'>No FQDN-based assets identified</td></tr>"}
</table>

<h2 id="sec-tools">Tools Used</h2>
<table>
    <tr><th>Tool</th><th>Purpose</th></tr>
    <tr><td>nmap</td><td class="nl-cell">Port scanning
Service detection
OS fingerprinting</td></tr>
    <tr><td>masscan</td><td class="nl-cell">High-speed port scanning</td></tr>
    <tr><td>testssl.sh</td><td class="nl-cell">SSL/TLS cipher analysis
Protocol analysis
Certificate inspection</td></tr>
    <tr><td>sslscan</td><td class="nl-cell">SSL/TLS configuration analysis</td></tr>
    <tr><td>shcheck</td><td class="nl-cell">HTTP security header verification</td></tr>
    <tr><td>nuclei</td><td class="nl-cell">Template-based vulnerability scanning</td></tr>
    <tr><td>nikto</td><td class="nl-cell">Web server vulnerability scanning</td></tr>
    <tr><td>subfinder</td><td class="nl-cell">Passive subdomain enumeration</td></tr>
    <tr><td>theHarvester</td><td class="nl-cell">Email and subdomain harvesting</td></tr>
    <tr><td>dnsx / dig</td><td class="nl-cell">DNS record enumeration and analysis</td></tr>
    <tr><td>dnstwist</td><td class="nl-cell">Typosquatting domain detection</td></tr>
    <tr><td>gobuster / ffuf</td><td class="nl-cell">Directory and file discovery</td></tr>
    <tr><td>webanalyze / whatweb</td><td class="nl-cell">Web technology fingerprinting</td></tr>
    <tr><td>Burp Suite</td><td class="nl-cell">Web application security testing
Manual traffic inspection</td></tr>
    <tr><td>Nessus</td><td class="nl-cell">Vulnerability scanning
Compliance auditing</td></tr>
    <tr><td>Custom Scripts and Tools</td><td class="nl-cell">Targeted enumeration
Manual verification
Evidence collection</td></tr>
</table>
</div>


</body>
</html>'''
    return html


def generate_pdf(project, incomplete=False, report_type="full"):
    """Generate a PDF report for a Crucible v2 project. Returns PDF bytes."""
    import os
    _pw_path = Path.home() / "Library" / "Caches" / "ms-playwright"
    if _pw_path.is_dir():
        os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(_pw_path))

    _BUILDERS = {
        # Endpoint
        "disk":              (gather_endpoint_data, build_disk_report),
        "hardware":          (gather_endpoint_data, build_hardware_report),
        "software":          (gather_endpoint_data, build_software_report),
        "malicious":         (gather_endpoint_data, build_malicious_report),
        "nist":              (gather_endpoint_data, build_nist_report),
        "stig":              (gather_endpoint_data, build_stig_report),
        "cis":               (gather_endpoint_data, build_cis_report),
        # External
        "ext_vuln":          (gather_external_data, build_ext_vuln_report),
        "ext_surface":       (gather_external_data, build_ext_surface_report),
        "ext_pci":           (gather_external_data, build_ext_pci_report),
        "ext_firewall":      (gather_external_data, build_ext_firewall_report),
        "ext_exec":          (gather_external_data, build_ext_exec_report),
        # OSINT
        "osint_intel":       (gather_osint_data, build_osint_intel_report),
        "osint_footprint":   (gather_osint_data, build_osint_footprint_report),
        "osint_email":       (gather_osint_data, build_osint_email_report),
        "osint_dns":         (gather_osint_data, build_osint_dns_report),
        "osint_exec":        (gather_osint_data, build_osint_exec_report),
        # Internal
        "int_vuln":          (gather_internal_data, build_int_vuln_report),
        "int_segment":       (gather_internal_data, build_int_segment_report),
        "int_ad":            (gather_internal_data, build_int_ad_report),
        "int_smb":           (gather_internal_data, build_int_smb_report),
        "int_exec":          (gather_internal_data, build_int_exec_report),
        # Wireless
        "wire_assess":       (gather_wireless_data, build_wire_assess_report),
        "wire_wifi":         (gather_wireless_data, build_wire_wifi_report),
        "wire_rogue":        (gather_wireless_data, build_wire_rogue_report),
        "wire_ble":          (gather_wireless_data, build_wire_ble_report),
        "wire_exec":         (gather_wireless_data, build_wire_exec_report),
        # Web
        "web_vuln":          (gather_web_data, build_web_vuln_report),
        "web_owasp":         (gather_web_data, build_web_owasp_report),
        "web_tech":          (gather_web_data, build_web_tech_report),
        "web_discovery":     (gather_web_data, build_web_discovery_report),
        "web_exec":          (gather_web_data, build_web_exec_report),
        # API
        "api_vuln":          (gather_api_data, build_api_vuln_report),
        "api_owasp":         (gather_api_data, build_api_owasp_report),
        "api_exec":          (gather_api_data, build_api_exec_report),
        # Cross-scope tools
        "trawler":           (gather_trawler_data, build_trawler_report),
        "auger":             (gather_auger_data, build_auger_report),
        "bastion":           (gather_bastion_data, build_bastion_report),
        "forge":             (gather_forge_data, build_forge_report),
        "cloud_pentest":     (gather_cloud_data, build_cloud_pentest_report),
        "cloud_cis":         (gather_cloud_data, build_cloud_cis_report),
        "cloud_compliance":  (gather_cloud_data, build_cloud_compliance_report),
        "cloud_exec":        (gather_cloud_data, build_cloud_exec_report),
        "quill":             (gather_quill_data, build_quill_report),
        "isotope":           (gather_isotope_data, build_isotope_report),
        # Cross-scope universal
        "remediation":       (gather_cross_scope_data, build_remediation_report),
        "compliance_matrix": (gather_cross_scope_data, build_compliance_matrix_report),
        "unified_exec":      (gather_cross_scope_data, build_unified_exec_report),
    }

    if report_type != "full" and report_type in _BUILDERS:
        gatherer, builder = _BUILDERS[report_type]
        scope_data = gatherer(project)
        if incomplete:
            scope_data["incomplete"] = True
        html = builder(scope_data)
    elif report_type == "full":
        data = gather_report_data(project)
        if incomplete:
            data["incomplete"] = True
        html = build_report(data)
    else:
        raise ValueError(f"Unknown report type: {report_type}")

    cm = project
    pdf_client = esc(cm.get("client_name", "Client"))

    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.set_content(html, wait_until="networkidle")

        page.evaluate("""() => {
            const PAGE_H = 11 * 96;    // letter height in px at 96dpi
            const TOP_M = 0.8 * 96;
            const BOT_M = 0.9 * 96;
            const CONTENT_H = PAGE_H - TOP_M - BOT_M;
            document.querySelectorAll('[data-toc-target]').forEach(span => {
                const targetId = span.getAttribute('data-toc-target');
                if (!targetId) return;
                const el = document.getElementById(targetId);
                if (!el) return;
                const top = el.getBoundingClientRect().top + window.scrollY;
                const pageNum = Math.floor(top / CONTENT_H) + 1;
                span.textContent = String(pageNum);
            });
        }""")

        header_html = '<div></div>'
        footer_html = (
            '<div style="font-size:7pt;color:#94a3b8;width:100%;display:flex;'
            'justify-content:space-between;padding:0 0.7in;font-family:sans-serif;">'
            f'<span>{pdf_client}</span>'
            '<span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>'
            '</div>'
        )
        pdf_bytes = page.pdf(
            format="Letter",
            margin={"top": "0.8in", "bottom": "0.9in", "left": "0.7in", "right": "0.7in"},
            print_background=True,
            display_header_footer=True,
            header_template=header_html,
            footer_template=footer_html,
        )
        browser.close()

    log.info("PDF report generated (%d KB, type=%s)", len(pdf_bytes) // 1024, report_type)
    return pdf_bytes


# ═══════════════════════════════════════════════════════════════
#  ENDPOINT / DREDGE REPORT BUILDERS
# ═══════════════════════════════════════════════════════════════

def _util_color(pct):
    if pct >= 90:
        return "#dc2626"
    if pct >= 75:
        return "#d97706"
    return "#059669"


def _status_badge(value, ok_values=("OK", "Enabled", "True", "Yes", "Clean", "PASS")):
    s = str(value or "")
    upper = s.upper()
    for ok in ok_values:
        if ok.upper() in upper:
            return f'<span class="status-ok">{esc(s)}</span>'
    if upper in ("CRITICAL", "FAIL", "DISABLED", "FALSE", "NO", "DIRTY"):
        return f'<span class="status-crit">{esc(s)}</span>'
    return f'<span class="status-warn">{esc(s)}</span>'


def _build_endpoint_cover(client_name, report_title, ep_data, meta, incomplete=False):
    ep = ep_data.get("endpoint_status", {})
    hostname = ep.get("hostname", "Unknown")
    os_name = ep.get("os_name", "Unknown")
    domain = ep.get("domain_name", "")
    consultant = meta.get("consultant", {})
    now_str = datetime.now().strftime("%B %d, %Y")
    start_date = meta.get("start_date", "")
    end_date = meta.get("end_date", "")
    engagement_str = f"{start_date} &mdash; {end_date}" if start_date else now_str

    return f'''
<div class="cover-page">
    <div class="cover-stripe"></div>
    <div class="cover-classification">Confidential</div>
    {'<div class="cover-incomplete-stamp">INCOMPLETE</div>' if incomplete else ''}
    <div class="cover-main">
        <div class="cover-accent-line"></div>
        <div class="cover-client">{esc(client_name)}</div>
        <div class="cover-type">{esc(report_title)}</div>
    </div>
    <div class="cover-meta-block">
        <div class="cover-meta"><strong>Target:</strong> {esc(hostname)}{(" &mdash; " + esc(domain)) if domain else ""}</div>
        <div class="cover-meta"><strong>Operating System:</strong> {esc(os_name)}</div>
        <div class="cover-meta"><strong>Prepared by</strong>&ensp; {esc(consultant.get("name", ""))}, {esc(consultant.get("title", ""))}</div>
        <div class="cover-meta"><strong>Engagement</strong>&ensp; {engagement_str}</div>
        <div class="cover-meta"><strong>Report Date</strong>&ensp; {now_str}</div>
        <div class="cover-meta"><strong>Classification</strong>&ensp; Confidential</div>
    </div>
</div>'''


def _endpoint_doc_wrap(title, client_name, body_html):
    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width">
<title>{esc(client_name)} &mdash; {esc(title)}</title>
<style>{REPORT_CSS}</style>
</head>
<body>
{body_html}
</body>
</html>'''


def _endpoint_findings_section(findings, prefix_filter=None, section_title="Related Findings"):
    if prefix_filter:
        if isinstance(prefix_filter, str):
            prefix_filter = [prefix_filter]
        filtered = [f for f in findings
                    if any((f.get("catalogue_id") or "").startswith(p) for p in prefix_filter)]
    else:
        filtered = list(findings)
    filtered.sort(key=risk_sort)
    if not filtered:
        return ""
    h = f'<h2>{esc(section_title)}</h2>'
    for idx, f in enumerate(filtered, 1):
        risk = (f.get("risk") or "INFO").upper()
        color = RISK_COLORS.get(risk, "#666")
        bg = RISK_BG.get(risk, "#f9fafb")
        title = esc(f.get("title", "Untitled"))
        desc = esc(f.get("description", ""))
        remed = esc(f.get("remediation", ""))
        output = esc((f.get("output") or "")[:2000])
        h += f'''<div class="finding" style="border-left:4px solid {color};">
  <div class="finding-head" style="background:{bg};">
    <span class="badge" style="background:{color};">{risk}</span>
    <span class="title">{idx}. {title}</span>
  </div>
  <div class="finding-body">
    <div class="detail-block"><div class="label">Description</div><p>{desc}</p></div>'''
        if output:
            h += f'''<div class="detail-block"><div class="label">Evidence</div>
    <div class="evidence-box">{output}</div></div>'''
        if remed:
            h += f'<div class="detail-block"><div class="label">Remediation</div><p>{remed}</p></div>'
        h += '</div></div>'
    return h


def _build_compliance_score_summary(assessment):
    if not assessment:
        return '<p style="color:var(--slate-400);font-style:italic;">No assessment data available.</p>'
    score = assessment.get("score_percent", 0)
    total = assessment.get("total_controls", 0)
    passed = assessment.get("pass_count", 0)
    failed = assessment.get("fail_count", 0)
    na = assessment.get("not_assessed", 0)
    rating = assessment.get("overall_rating", "Unknown")

    score_color = "#059669" if score >= 80 else "#d97706" if score >= 60 else "#dc2626"

    h = '<div class="stats-row">'
    h += f'<div class="stat-card"><div class="stat-number" style="color:{score_color}">{score:.0f}%</div><div class="stat-label">Compliance Score</div></div>'
    h += f'<div class="stat-card"><div class="stat-number">{total}</div><div class="stat-label">Total Controls</div></div>'
    h += f'<div class="stat-card"><div class="stat-number" style="color:#059669">{passed}</div><div class="stat-label">Passed</div></div>'
    h += f'<div class="stat-card"><div class="stat-number" style="color:#dc2626">{failed}</div><div class="stat-label">Failed</div></div>'
    h += f'<div class="stat-card"><div class="stat-number" style="color:#94a3b8">{na}</div><div class="stat-label">Not Assessed</div></div>'
    h += '</div>'
    h += f'<p style="margin:8px 0;font-size:9.5pt;"><strong>Overall Rating:</strong> <span style="font-weight:700;color:{score_color}">{esc(rating)}</span></p>'
    return h


def _build_compliance_categories(assessment):
    cats = assessment.get("categories", [])
    if not cats:
        return ""
    h = ""
    for cat in cats:
        cat_name = cat.get("name", cat.get("id", "Unknown"))
        cat_pass = cat.get("pass_count", 0)
        cat_fail = cat.get("fail_count", 0)
        cat_na = cat.get("not_assessed", 0)
        h += f'<h2>{esc(cat_name)}</h2>'
        h += f'<p class="section-intro">Passed: <strong style="color:#059669">{cat_pass}</strong> &bull; Failed: <strong style="color:#dc2626">{cat_fail}</strong> &bull; Not Assessed: <strong style="color:#94a3b8">{cat_na}</strong></p>'
        controls = cat.get("controls", [])
        if controls:
            h += '<table><tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Current Value</th><th>Expected Value</th></tr>'
            for c in controls:
                status = (c.get("status") or "NOT_ASSESSED").upper()
                if status == "PASS":
                    status_html = '<span class="control-pass">PASS</span>'
                elif status == "FAIL":
                    status_html = '<span class="control-fail">FAIL</span>'
                else:
                    status_html = '<span class="control-na">NOT ASSESSED</span>'
                sev = esc(c.get("severity", ""))
                h += f'<tr><td><code>{esc(c.get("id", ""))}</code></td><td>{esc(c.get("title", ""))}</td><td>{sev}</td><td>{status_html}</td><td><code>{esc(str(c.get("current_value", "")))}</code></td><td><code>{esc(str(c.get("expected_value", "")))}</code></td></tr>'
            h += '</table>'
    return h


def _build_compliance_failures(assessment):
    cats = assessment.get("categories", [])
    failures = []
    for cat in cats:
        for c in cat.get("controls", []):
            if (c.get("status") or "").upper() == "FAIL":
                failures.append((cat.get("name", ""), c))
    if not failures:
        return '<p style="color:#059669;font-weight:600;">No failed controls detected.</p>'
    h = '<h2>Failed Controls &mdash; Prioritized Remediation</h2>'
    h += '<table><tr><th>Category</th><th>Control ID</th><th>Title</th><th>Severity</th><th>Remediation</th></tr>'
    for cat_name, c in failures:
        h += f'<tr><td>{esc(cat_name)}</td><td><code>{esc(c.get("id", ""))}</code></td><td>{esc(c.get("title", ""))}</td><td>{esc(c.get("severity", ""))}</td><td>{esc(c.get("remediation", ""))}</td></tr>'
    h += '</table>'
    return h


def _build_compliance_report(data, framework_key, report_title, background_paragraphs,
                             applicability_text):
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    assessment = data.get(f"{framework_key}_assessment", {})
    findings = data.get("dredge_findings", [])

    cover = _build_endpoint_cover(client_name, report_title, data, meta, incomplete)

    body = cover
    body += '<div class="page"><h1>Executive Summary</h1>'
    body += _build_compliance_score_summary(assessment)
    body += '</div>'

    body += '<div class="page"><h1>Framework Background</h1>'
    for para in background_paragraphs:
        body += f'<p class="section-intro">{para}</p>'
    body += f'<h2>Applicability</h2><p class="section-intro">{applicability_text}</p>'
    body += '</div>'

    body += '<div class="page"><h1>Assessment Results by Category</h1>'
    body += _build_compliance_categories(assessment)
    body += '</div>'

    body += '<div class="page"><h1>Remediation Priorities</h1>'
    body += _build_compliance_failures(assessment)
    body += '</div>'

    findings_html = _endpoint_findings_section(findings, prefix_filter=["DR-CMP", "DR-HDN", "DR-SYS"],
                                                section_title="Related Security Findings")
    if findings_html:
        body += f'<div class="page">{findings_html}</div>'

    return _endpoint_doc_wrap(report_title, client_name, body)


# ── Individual Report Builders ───────────────────────────

def build_disk_report(data):
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    ep = data.get("endpoint_status", {})
    disk = data.get("disk_storage", {})
    hw = data.get("hardware", {})
    findings = data.get("dredge_findings", [])

    hostname = ep.get("hostname", "Unknown")
    os_name = ep.get("os_name", "Unknown")
    domain = ep.get("domain_name", "")

    phys = disk.get("physical_disks", [])
    logs = disk.get("logical_disks", [])
    parts = disk.get("partitions", [])
    vols = disk.get("volumes", [])
    pools = disk.get("storage_spaces", {}).get("pools", [])
    raid_summary = disk.get("raid_summary", [])
    controllers = disk.get("controllers", [])
    hw_raid = disk.get("hardware_raid")

    bb = hw.get("baseboard", {})
    bios = hw.get("bios", {})
    procs = hw.get("processors", [])
    mem = hw.get("memory", {})

    total_cap = sum(d.get("size_gb", 0) for d in phys)
    local_drives = [d for d in logs if d.get("type", "") not in ("Network", "CD-ROM")]
    net_drives = [d for d in logs if d.get("type") == "Network"]

    cover = _build_endpoint_cover(client_name, "Disk & Storage Assessment", data, meta, incomplete)
    body = cover

    # Exec Summary
    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'<p class="section-intro">This report documents the disk storage configuration and health assessment of <strong>{esc(hostname)}</strong>'
    if domain:
        body += f' in the <strong>{esc(domain)}</strong> domain'
    body += f', running {esc(os_name)}. Data was collected using Dredge endpoint collection.</p>'
    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(phys)}</div><div class="stat-label">Physical Disks</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{total_cap:,.0f} GB</div><div class="stat-label">Total Raw Capacity</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(local_drives)}</div><div class="stat-label">Local Drives</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(net_drives)}</div><div class="stat-label">Network Drives</div></div>'
    body += '</div>'

    findings_html = _endpoint_findings_section(findings,
        prefix_filter=["DR-DISK"], section_title="Key Findings")
    if findings_html:
        body += findings_html
    body += '</div>'

    # Physical Disk Inventory
    if phys:
        body += '<div class="page"><h1>Physical Disk Inventory</h1>'
        body += f'<p class="section-intro">{esc(hostname)} contains {len(phys)} physical disk(s).</p>'
        body += '<table><tr><th>Device</th><th>Model</th><th>Interface</th><th>Media</th><th>Capacity</th><th>Serial</th><th>Status</th></tr>'
        for d in phys:
            device = d.get("device", "")
            st = _status_badge(d.get("status", "Unknown"))
            body += f'<tr><td>{esc(device)}</td><td>{esc(d.get("model", ""))}</td><td>{esc(d.get("interface", ""))}</td><td>{esc(d.get("media", ""))}</td><td>{d.get("size_gb", 0):,.1f} GB</td><td style="font-family:var(--font-mono);font-size:7.5pt">{esc(d.get("serial", ""))}</td><td>{st}</td></tr>'
        body += '</table>'

    # Hardware Platform
    body += '<h2>Hardware Platform</h2>'
    body += '<table><tr><th>Component</th><th>Detail</th></tr>'
    if bb:
        body += f'<tr><td>Baseboard</td><td>{esc(bb.get("manufacturer", ""))} {esc(bb.get("product", ""))}</td></tr>'
    if bios:
        body += f'<tr><td>BIOS</td><td>{esc(bios.get("name", ""))} (SMBIOS {esc(bios.get("smbios_version", ""))})</td></tr>'
    if procs:
        proc_name = procs[0].get("name", "Unknown").strip()
        body += f'<tr><td>Processors</td><td>{len(procs)}x {esc(proc_name)}</td></tr>'
    if mem:
        mods = mem.get("modules", [])
        mod_desc = ""
        if mods:
            mod_desc = f' ({len(mods)}x {mods[0].get("capacity_gb", 0):.0f} GB)'
        body += f'<tr><td>Memory</td><td>{mem.get("total_gb", 0):.0f} GB{mod_desc}</td></tr>'
        body += f'<tr><td>ECC</td><td>{_status_badge("Enabled" if mem.get("ecc") else "Not Detected")}</td></tr>'
    body += '</table></div>'

    # RAID Configuration
    if hw_raid or controllers or raid_summary:
        body += '<div class="page"><h1>RAID Configuration</h1>'
        if controllers:
            body += '<table><tr><th>Controller</th><th>Manufacturer</th><th>Status</th></tr>'
            for c in controllers:
                body += f'<tr><td>{esc(c.get("name", ""))}</td><td>{esc(c.get("manufacturer", ""))}</td><td>{_status_badge(c.get("status", ""))}</td></tr>'
            body += '</table>'
        if raid_summary:
            body += '<h2>RAID Summary</h2><table><tr><th>Array</th><th>Level</th><th>Status</th><th>Disks</th><th>Capacity</th></tr>'
            for r in raid_summary:
                body += f'<tr><td>{esc(r.get("name", ""))}</td><td>{esc(r.get("level", ""))}</td><td>{_status_badge(r.get("status", ""))}</td><td>{r.get("disk_count", "")}</td><td>{r.get("size_gb", 0):,.1f} GB</td></tr>'
            body += '</table>'
        body += '</div>'

    # Logical Disk Layout
    if logs:
        body += '<div class="page"><h1>Logical Disk Layout</h1>'
        body += f'<p class="section-intro">{len(logs)} logical drive(s) visible to the operating system.</p>'
        body += '<table><tr><th>Drive</th><th>Type</th><th>Filesystem</th><th>Label</th><th>Capacity</th><th>Free</th><th>Utilization</th></tr>'
        for d in logs:
            dtype = d.get("type", "Fixed")
            if dtype == "CD-ROM":
                body += f'<tr><td><strong>{esc(d.get("drive", ""))}</strong></td><td>CD-ROM</td><td colspan="5" style="color:var(--slate-400)">&mdash;</td></tr>'
                continue
            size = d.get("size_gb", 0)
            free = d.get("free_gb", 0)
            pfree = d.get("percent_free", 100)
            used_pct = 100.0 - pfree if size > 0 else 0
            uc = _util_color(used_pct)
            body += f'<tr><td><strong>{esc(d.get("drive", ""))}</strong></td><td>{esc(dtype)}</td><td>{esc(d.get("filesystem", ""))}</td><td>{esc(d.get("volume", "") or "&mdash;")}</td><td>{size:,.1f} GB</td><td>{free:,.1f} GB</td>'
            body += f'<td><div class="util-bar"><div class="util-track"><div class="util-fill" style="width:{used_pct:.1f}%;background:{uc}"></div></div><span class="util-pct" style="color:{uc}">{used_pct:.1f}%</span></div></td></tr>'
        body += '</table></div>'

    # Partition Table
    if parts:
        body += '<div class="page"><h1>Partition Table</h1>'
        body += f'<p class="section-intro">{len(parts)} partition(s) across {len(phys)} physical disk(s).</p>'
        body += '<table><tr><th>Partition</th><th>Disk Index</th><th>Size</th><th>Type</th><th>Boot</th></tr>'
        for p in sorted(parts, key=lambda x: (x.get("disk_index", 0), x.get("partition_index", 0))):
            boot = _status_badge("Boot") if p.get("boot_partition") else "&mdash;"
            body += f'<tr><td>{esc(p.get("device", ""))}</td><td>{p.get("disk_index", "")}</td><td>{p.get("size_gb", 0):,.1f} GB</td><td>{esc(p.get("type", ""))}</td><td>{boot}</td></tr>'
        body += '</table></div>'

    # Volume Configuration
    if vols:
        body += '<div class="page"><h1>Volume Configuration</h1>'
        body += f'<p class="section-intro">{len(vols)} volume(s) registered with the Windows Volume Manager.</p>'
        body += '<table><tr><th>Drive</th><th>Label</th><th>FS</th><th>Capacity</th><th>Free</th><th>Serial</th><th>Dirty Bit</th></tr>'
        for v in vols:
            dl = v.get("drive_letter") or "<em>(none)</em>"
            dirty = _status_badge("Dirty" if v.get("dirty") else "Clean")
            if not v.get("filesystem"):
                dirty = "&mdash;"
            body += f'<tr><td><strong>{dl}</strong></td><td>{esc(v.get("label") or "&mdash;")}</td><td>{esc(v.get("filesystem") or "&mdash;")}</td><td>{v.get("capacity_gb", 0):,.1f} GB</td><td>{v.get("free_gb", 0):,.1f} GB</td><td style="font-family:var(--font-mono);font-size:7.5pt">{esc(v.get("serial", ""))}</td><td>{dirty}</td></tr>'
        body += '</table></div>'

    return _endpoint_doc_wrap("Disk & Storage Assessment", client_name, body)


def build_hardware_report(data):
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    ep = data.get("endpoint_status", {})
    hw = data.get("hardware", {})
    findings = data.get("dredge_findings", [])

    hostname = ep.get("hostname", "Unknown")
    os_name = ep.get("os_name", "Unknown")
    domain = ep.get("domain_name", "")

    bb = hw.get("baseboard", {})
    bios = hw.get("bios", {})
    procs = hw.get("processors", [])
    mem = hw.get("memory", {})
    gpus = hw.get("gpu_adapters", [])
    nics = hw.get("network_adapters", [])
    usbs = hw.get("usb_devices", [])

    cover = _build_endpoint_cover(client_name, "Hardware Inventory Report", data, meta, incomplete)
    body = cover

    # Exec Summary
    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'<p class="section-intro">This report documents the hardware inventory of <strong>{esc(hostname)}</strong>, running {esc(os_name)}.</p>'
    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(procs)}</div><div class="stat-label">Processors</div></div>'
    core_count = sum(p.get("cores", 0) for p in procs)
    body += f'<div class="stat-card"><div class="stat-number">{core_count}</div><div class="stat-label">Total Cores</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{mem.get("total_gb", 0):.0f} GB</div><div class="stat-label">Total RAM</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(nics)}</div><div class="stat-label">Network Adapters</div></div>'
    body += '</div></div>'

    # System Overview
    body += '<div class="page"><h1>System Overview</h1>'
    body += '<table><tr><th>Parameter</th><th>Value</th></tr>'
    body += f'<tr><td>Hostname</td><td><strong>{esc(hostname)}</strong></td></tr>'
    body += f'<tr><td>Operating System</td><td>{esc(os_name)}</td></tr>'
    if domain:
        body += f'<tr><td>Domain</td><td>{esc(domain)}</td></tr>'
    body += f'<tr><td>Domain Role</td><td>{esc(ep.get("domain_role", ""))}</td></tr>'
    body += f'<tr><td>Uptime</td><td>{ep.get("uptime_days", "N/A")} days</td></tr>'
    body += f'<tr><td>Secure Boot</td><td>{_status_badge("Enabled" if ep.get("secure_boot") else "Not Supported")}</td></tr>'
    tpm = ep.get("tpm", {})
    body += f'<tr><td>TPM</td><td>{_status_badge("Present" if tpm.get("present") else "Not Detected")}</td></tr>'
    body += '</table></div>'

    # Baseboard / BIOS
    body += '<div class="page"><h1>Baseboard &amp; Firmware</h1>'
    body += '<table><tr><th>Component</th><th>Detail</th></tr>'
    body += f'<tr><td>Manufacturer</td><td>{esc(bb.get("manufacturer", ""))}</td></tr>'
    body += f'<tr><td>Product</td><td>{esc(bb.get("product", ""))}</td></tr>'
    body += f'<tr><td>Version</td><td>{esc(bb.get("version", ""))}</td></tr>'
    body += f'<tr><td>Serial</td><td style="font-family:var(--font-mono)">{esc(bb.get("serial", ""))}</td></tr>'
    body += f'<tr><td>BIOS</td><td>{esc(bios.get("name", ""))}</td></tr>'
    body += f'<tr><td>BIOS Version</td><td>{esc(bios.get("version", ""))}</td></tr>'
    body += f'<tr><td>SMBIOS Version</td><td>{esc(bios.get("smbios_version", ""))}</td></tr>'
    body += f'<tr><td>Release Date</td><td>{esc(bios.get("release_date", ""))}</td></tr>'
    body += '</table></div>'

    # Processors
    if procs:
        body += '<div class="page"><h1>Processors</h1>'
        body += '<table><tr><th>#</th><th>Name</th><th>Cores</th><th>Logical</th><th>Max Clock (MHz)</th></tr>'
        for i, p in enumerate(procs):
            body += f'<tr><td>{i}</td><td>{esc(p.get("name", "").strip())}</td><td>{p.get("cores", "")}</td><td>{p.get("logical_processors", "")}</td><td>{p.get("max_clock_mhz", "")}</td></tr>'
        body += '</table></div>'

    # Memory
    body += '<div class="page"><h1>Memory</h1>'
    body += '<table><tr><th>Parameter</th><th>Value</th></tr>'
    body += f'<tr><td>Total RAM</td><td>{mem.get("total_gb", 0):.0f} GB</td></tr>'
    body += f'<tr><td>Slots Populated</td><td>{mem.get("slot_count", 0)}</td></tr>'
    body += f'<tr><td>ECC</td><td>{_status_badge("Enabled" if mem.get("ecc") else "Not Detected")}</td></tr>'
    body += '</table>'
    mods = mem.get("modules", [])
    if mods:
        body += '<h2>Memory Modules</h2>'
        body += '<table><tr><th>Slot</th><th>Capacity</th><th>Speed</th><th>Type</th><th>Manufacturer</th></tr>'
        for i, m in enumerate(mods):
            body += f'<tr><td>{i}</td><td>{m.get("capacity_gb", 0):.0f} GB</td><td>{m.get("speed_mhz", "")} MHz</td><td>{esc(m.get("type", ""))}</td><td>{esc(m.get("manufacturer", ""))}</td></tr>'
        body += '</table>'
    body += '</div>'

    # GPU Adapters
    if gpus:
        body += '<div class="page"><h1>GPU Adapters</h1>'
        body += '<table><tr><th>Name</th><th>Driver Version</th><th>Status</th></tr>'
        for g in gpus:
            body += f'<tr><td>{esc(g.get("name", ""))}</td><td>{esc(g.get("driver_version", ""))}</td><td>{_status_badge(g.get("status", ""))}</td></tr>'
        body += '</table></div>'

    # Network Adapters
    if nics:
        body += '<div class="page"><h1>Network Adapters</h1>'
        body += '<table><tr><th>Name</th><th>MAC Address</th><th>Speed (Mbps)</th><th>Type</th><th>Manufacturer</th></tr>'
        for n in nics:
            body += f'<tr><td>{esc(n.get("name", ""))}</td><td style="font-family:var(--font-mono);font-size:7.5pt">{esc(n.get("mac", ""))}</td><td>{n.get("speed_mbps", "")}</td><td>{esc(n.get("type", ""))}</td><td>{esc(n.get("manufacturer", ""))}</td></tr>'
        body += '</table></div>'

    # USB Devices
    if usbs:
        body += '<div class="page"><h1>USB Devices</h1>'
        body += '<table><tr><th>Name</th><th>Manufacturer</th></tr>'
        for u in usbs:
            body += f'<tr><td>{esc(u.get("name", ""))}</td><td>{esc(u.get("manufacturer", ""))}</td></tr>'
        body += '</table></div>'

    findings_html = _endpoint_findings_section(findings, prefix_filter=["DR-HW"],
                                                section_title="Hardware-Related Findings")
    if findings_html:
        body += f'<div class="page">{findings_html}</div>'

    return _endpoint_doc_wrap("Hardware Inventory Report", client_name, body)


def build_software_report(data):
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    ep = data.get("endpoint_status", {})
    sw = data.get("software_inventory", {})
    findings = data.get("dredge_findings", [])

    hostname = ep.get("hostname", "Unknown")
    software_list = sw.get("software", [])
    services = sw.get("services", [])
    tasks = sw.get("notable_tasks", [])
    svc_summary = sw.get("services_summary", {})

    cover = _build_endpoint_cover(client_name, "Software & Update Report", data, meta, incomplete)
    body = cover

    # Exec Summary
    auto_start = sum(1 for s in services if (s.get("start_type") or "").lower() in ("auto", "automatic"))
    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'<p class="section-intro">Software and service inventory for <strong>{esc(hostname)}</strong>.</p>'
    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{sw.get("software_count", len(software_list))}</div><div class="stat-label">Installed Software</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{svc_summary.get("total", len(services))}</div><div class="stat-label">Total Services</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{svc_summary.get("running", 0)}</div><div class="stat-label">Running Services</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{auto_start}</div><div class="stat-label">Auto-Start</div></div>'
    body += '</div>'

    findings_html = _endpoint_findings_section(findings,
        prefix_filter=["DR-SFT", "DR-SYS"], section_title="Key Findings")
    if findings_html:
        body += findings_html
    body += '</div>'

    # Installed Software
    if software_list:
        sorted_sw = sorted(software_list, key=lambda x: (x.get("name") or "").lower())
        body += '<div class="page"><h1>Installed Software</h1>'
        body += f'<p class="section-intro">{len(sorted_sw)} software package(s) detected.</p>'
        body += '<table><tr><th>Name</th><th>Version</th><th>Publisher</th><th>Install Date</th></tr>'
        for s in sorted_sw:
            body += f'<tr><td>{esc(s.get("name", ""))}</td><td>{esc(s.get("version", ""))}</td><td>{esc(s.get("publisher", ""))}</td><td>{esc(s.get("install_date", ""))}</td></tr>'
        body += '</table></div>'

    # Services
    if services:
        body += '<div class="page"><h1>Services Inventory</h1>'
        body += f'<p class="section-intro">{len(services)} service(s) enumerated.</p>'
        body += '<table><tr><th>Name</th><th>Display Name</th><th>State</th><th>Start Type</th><th>Account</th></tr>'
        for s in services:
            state = (s.get("state") or s.get("status") or "").capitalize()
            state_html = f'<span class="status-ok">{esc(state)}</span>' if state.lower() == "running" else esc(state)
            body += f'<tr><td style="font-family:var(--font-mono);font-size:7.5pt">{esc(s.get("name", ""))}</td><td>{esc(s.get("display_name", ""))}</td><td>{state_html}</td><td>{esc(s.get("start_type", ""))}</td><td>{esc(s.get("account", s.get("logon_as", "")))}</td></tr>'
        body += '</table></div>'

    # Scheduled Tasks
    if tasks:
        body += '<div class="page"><h1>Scheduled Tasks</h1>'
        body += f'<p class="section-intro">{len(tasks)} notable scheduled task(s).</p>'
        body += '<table><tr><th>Task Name</th><th>Run As</th><th>Command</th><th>Status</th></tr>'
        for t in tasks:
            body += f'<tr><td>{esc(t.get("task_name", ""))}</td><td>{esc(t.get("run_as", ""))}</td><td style="font-family:var(--font-mono);font-size:7.5pt;word-break:break-all">{esc(t.get("command", ""))}</td><td>{esc(t.get("status", ""))}</td></tr>'
        body += '</table></div>'

    return _endpoint_doc_wrap("Software & Update Report", client_name, body)


def build_malicious_report(data):
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    ep = data.get("endpoint_status", {})
    findings = data.get("dredge_findings", [])
    hardening = data.get("hardening", {})

    hostname = ep.get("hostname", "Unknown")

    proc_findings = [f for f in findings if (f.get("catalogue_id") or "").startswith("DR-PROC")]
    pers_findings = [f for f in findings if (f.get("catalogue_id") or "").startswith("DR-PERS")]
    cred_findings = [f for f in findings if (f.get("catalogue_id") or "").startswith("DR-CRED")]
    evt_findings = [f for f in findings if (f.get("catalogue_id") or "").startswith("DR-EVT")]
    hdn_mal_ids = ("DR-HDN-008", "DR-HDN-009", "DR-HDN-010", "DR-HDN-011", "DR-HDN-012",
                   "DR-HDN-022", "DR-HDN-023")
    hdn_findings = [f for f in findings if (f.get("catalogue_id") or "") in hdn_mal_ids]
    all_mal = proc_findings + pers_findings + cred_findings + evt_findings + hdn_findings

    cover = _build_endpoint_cover(client_name, "Malicious Activity Report", data, meta, incomplete)
    body = cover

    # Exec Summary
    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in all_mal)
    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'<p class="section-intro">Malicious activity indicator analysis for <strong>{esc(hostname)}</strong>. This report examines suspicious processes, persistence mechanisms, credential exposure, event log anomalies, and hardening gaps that could facilitate unauthorized access.</p>'
    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#dc2626">{risk_counts.get("CRITICAL", 0)}</div><div class="stat-label">Critical</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#ea580c">{risk_counts.get("HIGH", 0)}</div><div class="stat-label">High</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#d97706">{risk_counts.get("MEDIUM", 0)}</div><div class="stat-label">Medium</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#059669">{risk_counts.get("LOW", 0) + risk_counts.get("INFO", 0)}</div><div class="stat-label">Low / Info</div></div>'
    body += '</div></div>'

    # Suspicious Processes
    if proc_findings:
        body += '<div class="page">'
        body += _endpoint_findings_section(proc_findings, section_title="Suspicious Processes")
        body += '</div>'

    # Persistence Mechanisms
    if pers_findings:
        body += '<div class="page">'
        body += _endpoint_findings_section(pers_findings, section_title="Persistence Mechanisms")
        body += '</div>'

    # Credential Exposure
    if cred_findings:
        body += '<div class="page">'
        body += _endpoint_findings_section(cred_findings, section_title="Credential Exposure")
        body += '</div>'

    # Event Log Analysis
    if evt_findings:
        body += '<div class="page">'
        body += _endpoint_findings_section(evt_findings, section_title="Event Log Analysis")
        body += '</div>'

    # Hardening Gaps
    if hdn_findings:
        body += '<div class="page">'
        body += _endpoint_findings_section(hdn_findings, section_title="Hardening Gaps Facilitating Malicious Activity")
        body += '</div>'

    if not all_mal:
        body += '<div class="page"><h1>Analysis Results</h1>'
        body += '<p style="color:#059669;font-weight:600;font-size:12pt;padding:40px 0;text-align:center;">No malicious activity indicators detected.</p></div>'

    # Recommendations
    body += '<div class="page"><h1>Recommendations</h1>'
    body += '<p class="section-intro">Based on the analysis above, the following actions are recommended:</p>'
    body += '<table><tr><th>Priority</th><th>Recommendation</th></tr>'
    recs = [
        ("Critical", "Investigate and remediate any confirmed malicious processes immediately."),
        ("High", "Remove unauthorized persistence mechanisms and review all scheduled tasks."),
        ("High", "Rotate credentials for any exposed accounts, especially domain-level accounts."),
        ("Medium", "Enable LSA Protection and Credential Guard to protect credential material."),
        ("Medium", "Enable advanced audit logging and configure a SIEM to monitor for anomalous activity."),
        ("Low", "Implement application whitelisting to prevent unauthorized executable execution."),
    ]
    for pri, rec in recs:
        color = RISK_COLORS.get(pri.upper(), "#666")
        body += f'<tr><td><span class="badge-sm" style="background:{color}">{esc(pri)}</span></td><td>{esc(rec)}</td></tr>'
    body += '</table></div>'

    return _endpoint_doc_wrap("Malicious Activity Report", client_name, body)


def build_nist_report(data):
    return _build_compliance_report(
        data,
        framework_key="nist",
        report_title="NIST 800-123 Assessment",
        background_paragraphs=[
            "NIST Special Publication 800-123, <em>Guide to General Server Security</em>, published by the "
            "National Institute of Standards and Technology (NIST), provides recommendations for securing "
            "server operating systems. It addresses the security of server software, the underlying OS, and "
            "the network infrastructure that supports them. This publication is part of the NIST 800-series "
            "that forms the foundation of federal cybersecurity policy under the Federal Information "
            "Security Modernization Act (FISMA).",

            "Key areas include operating system hardening, user and access management, file system security, "
            "logging and monitoring, application security, and maintenance of server software. Compliance "
            "with NIST 800-123 reduces the attack surface and strengthens the overall security posture of "
            "server infrastructure.",
        ],
        applicability_text=(
            "NIST 800-123 applies to all federal agencies and their contractors that operate, manage, or "
            "maintain servers in any capacity. Private-sector organizations also benefit from its guidance "
            "as a best-practice baseline for server hardening. Organizations subject to FISMA, FedRAMP, "
            "or CMMC requirements may reference this publication as part of their compliance programs."
        ),
    )


def build_stig_report(data):
    return _build_compliance_report(
        data,
        framework_key="stig",
        report_title="DISA STIG Assessment",
        background_paragraphs=[
            "The Defense Information Systems Agency (DISA) Security Technical Implementation Guides "
            "(STIGs) are the configuration standards for Department of Defense (DoD) information systems. "
            "STIGs provide detailed technical guidance for locking down systems that might otherwise be "
            "vulnerable to cyberattack. Compliance with applicable STIGs is mandatory for all DoD "
            "information systems and is verified through the Risk Management Framework (RMF) accreditation "
            "process.",

            "STIG severity categories define the urgency of remediation: <strong>CAT I</strong> findings "
            "represent the highest risk with the potential for direct and immediate loss of confidentiality, "
            "integrity, or availability. <strong>CAT II</strong> findings have the potential for significant "
            "security impact. <strong>CAT III</strong> findings represent lower-risk items that could degrade "
            "security measures.",

            "STIG compliance is required for all systems connected to the DoD Information Network (DoDIN), "
            "including systems operated by contractors and partner organizations. Many private-sector "
            "organizations also adopt STIG benchmarks as a rigorous hardening baseline that exceeds most "
            "commercial security frameworks.",
        ],
        applicability_text=(
            "DISA STIGs apply to all DoD information systems, Defense Industrial Base (DIB) contractor "
            "systems that process Controlled Unclassified Information (CUI), and any system requiring an "
            "Authority to Operate (ATO) under the RMF. Organizations outside the DoD ecosystem frequently "
            "adopt STIGs as a high-assurance hardening baseline."
        ),
    )


def build_cis_report(data):
    return _build_compliance_report(
        data,
        framework_key="cis",
        report_title="CIS Benchmark Assessment",
        background_paragraphs=[
            "The Center for Internet Security (CIS) Benchmarks are consensus-based security configuration "
            "guides developed by a global community of cybersecurity professionals. Each benchmark provides "
            "prescriptive, prioritized guidance for establishing a secure configuration posture for "
            "technology platforms. CIS Benchmarks are recognized by multiple regulatory frameworks including "
            "PCI DSS, HIPAA, and FedRAMP as acceptable hardening baselines.",

            "CIS Benchmarks define two implementation levels: <strong>Level 1</strong> provides a practical "
            "security baseline that can be implemented broadly without significant performance impact. "
            "<strong>Level 2</strong> extends Level 1 with additional security controls intended for "
            "environments requiring heightened security, which may have a greater impact on system usability "
            "or performance.",

            "Organizations of any size and sector can adopt CIS Benchmarks. They are particularly valuable "
            "for organizations subject to compliance requirements (PCI DSS, HIPAA, SOC 2, ISO 27001) as "
            "CIS mappings to these frameworks simplify cross-compliance demonstration.",
        ],
        applicability_text=(
            "CIS Benchmarks are vendor-neutral and applicable to any organization seeking to improve its "
            "security posture. They are especially relevant to organizations pursuing PCI DSS compliance, "
            "HIPAA security requirements, SOC 2 Type II attestation, ISO 27001 certification, or FedRAMP "
            "authorization. CIS also maintains the CIS Controls framework, which maps directly to these "
            "benchmarks for a comprehensive defense-in-depth strategy."
        ),
    )

# ═══════════════════════════════════════════════════════════════════════
#  SCOPE REPORT BUILDERS — External, OSINT, Internal, Wireless,
#  Web, API, Cross-Scope Tool, and Universal reports
# ═══════════════════════════════════════════════════════════════════════

# ── Scope-report shared helpers ──────────────────────────────────────

def _build_scope_cover(client_name, report_title, meta, scope_label="",
                       target_lines=None, incomplete=False):
    consultant = meta.get("consultant", {})
    now_str = datetime.now().strftime("%B %d, %Y")
    start_date = meta.get("start_date", "")
    end_date = meta.get("end_date", "")
    engagement_str = f"{start_date} &mdash; {end_date}" if start_date else now_str

    meta_rows = []
    if scope_label:
        meta_rows.append(f'<div class="cover-meta"><strong>Scope:</strong> {esc(scope_label)}</div>')
    if target_lines:
        for line in target_lines[:4]:
            meta_rows.append(f'<div class="cover-meta"><strong>Target:</strong> {esc(line)}</div>')
    meta_rows.append(
        f'<div class="cover-meta"><strong>Prepared by</strong>&ensp; '
        f'{esc(consultant.get("name", ""))}, {esc(consultant.get("title", ""))}</div>')
    meta_rows.append(f'<div class="cover-meta"><strong>Engagement</strong>&ensp; {engagement_str}</div>')
    meta_rows.append(f'<div class="cover-meta"><strong>Report Date</strong>&ensp; {now_str}</div>')
    meta_rows.append('<div class="cover-meta"><strong>Classification</strong>&ensp; Confidential</div>')

    return f'''
<div class="cover-page">
    <div class="cover-stripe"></div>
    <div class="cover-classification">Confidential</div>
    {'<div class="cover-incomplete-stamp">INCOMPLETE</div>' if incomplete else ''}
    <div class="cover-main">
        <div class="cover-accent-line"></div>
        <div class="cover-client">{esc(client_name)}</div>
        <div class="cover-type">{esc(report_title)}</div>
    </div>
    <div class="cover-meta-block">
        {"".join(meta_rows)}
    </div>
</div>'''


def _risk_cards_html(risk_counts):
    h = '<div class="risk-cards-row">'
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        color = RISK_COLORS.get(level, "#666")
        count = risk_counts.get(level, 0)
        h += (f'<div class="risk-card">'
              f'<div class="risk-card-count" style="color:{color}">{count}</div>'
              f'<div class="risk-card-label">{level}</div></div>')
    h += '</div>'
    return h


def _scope_target_lines(meta, scope):
    scope_def = meta.get("scope_definition", {})
    lines = []
    if scope in ("external", "internal"):
        for cidr in scope_def.get("network_cidrs", [])[:4]:
            lines.append(cidr)
    for domain in scope_def.get("domains", [])[:4]:
        lines.append(domain)
    for url in scope_def.get("target_urls", [])[:4]:
        lines.append(url)
    return lines


def _findings_section_full(findings, section_title="Detailed Findings"):
    if not findings:
        return '<p style="color:var(--slate-400);font-style:italic;">No findings identified.</p>'
    findings = sorted(findings, key=risk_sort)
    h = f'<h2>{esc(section_title)}</h2>'
    for idx, f in enumerate(findings, 1):
        h += finding_card(f, idx)
    return h


def _remediation_summary(findings):
    remeds = defaultdict(list)
    for f in findings:
        r = (f.get("remediation") or "").strip()
        risk = (f.get("risk") or "INFO").upper()
        if r:
            remeds[risk].append(r)
    if not remeds:
        return ""
    h = '<h2>Remediation Summary</h2>'
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        items = remeds.get(level, [])
        if not items:
            continue
        color = RISK_COLORS.get(level, "#666")
        h += f'<h3 style="color:{color}">{level} Severity</h3><ul>'
        seen = set()
        for r in items:
            key = r[:120].lower()
            if key not in seen:
                seen.add(key)
                h += f'<li>{esc(r)}</li>'
        h += '</ul>'
    return h


def _exec_risk_heatmap(risk_counts, total):
    if total == 0:
        return '<p style="color:var(--slate-400);font-style:italic;">No findings to display.</p>'
    h = '<div style="display:flex;gap:2px;height:28px;border-radius:6px;overflow:hidden;margin:14px 0;">'
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = risk_counts.get(level, 0)
        if count == 0:
            continue
        pct = count / total * 100
        color = RISK_COLORS.get(level, "#666")
        h += (f'<div style="flex:{pct};background:{color};display:flex;align-items:center;'
              f'justify-content:center;color:#fff;font-size:7pt;font-weight:700;'
              f'min-width:24px;" title="{level}: {count}">{count}</div>')
    h += '</div>'
    return h


def _findings_cards(findings, max_count=None):
    """Render full finding cards with badge, desc, evidence, remediation."""
    if max_count:
        findings = findings[:max_count]
    h = ""
    for idx, f in enumerate(sorted(findings, key=risk_sort), 1):
        risk = (f.get("risk") or "INFO").upper()
        color = RISK_COLORS.get(risk, "#666")
        bg = RISK_BG.get(risk, "#f9fafb")
        title = esc(f.get("title", "Untitled"))
        desc = esc(f.get("description", ""))
        remed = esc(f.get("remediation", ""))
        output = esc((f.get("output") or "")[:2000])
        ip = esc(f.get("ip", ""))
        port = f.get("port", "")
        target = f"{ip}:{port}" if ip and port else ip

        h += f'''<div class="finding" style="border-left:4px solid {color};">
  <div class="finding-head" style="background:{bg};">
    <span class="badge" style="background:{color};">{risk}</span>
    <span class="title">{idx}. {title}</span>
    {f'<span style="float:right;font-size:7.5pt;color:var(--slate-400)">{target}</span>' if target else ''}
  </div>
  <div class="finding-body">
    <div class="detail-block"><div class="label">Description</div><p>{desc}</p></div>'''
        if output:
            h += f'''<div class="detail-block"><div class="label">Evidence</div>
    <div class="evidence-box">{output}</div></div>'''
        if remed:
            h += f'<div class="detail-block"><div class="label">Remediation</div><p>{remed}</p></div>'
        h += '</div></div>\n'
    return h


def _all_internal_findings(data):
    """Merge all internal-scope findings from all tool sources."""
    all_f = []
    for key in ("ss3_findings", "deps_findings", "nuclei_findings",
                "nessus_findings", "authprobe_findings", "auger_findings",
                "bastion_findings", "trawler_findings"):
        for f in data.get(key, []):
            all_f.append(f)
    return all_f


def _all_wireless_findings(data):
    """Merge all wireless-scope findings from all Aether tools."""
    all_f = []
    for key in ("aether_findings", "aether_b_findings",
                "aether_z_findings", "aether_u_findings"):
        for f in data.get(key, []):
            all_f.append(f)
    return all_f


def _filter_by_title_patterns(findings, patterns):
    """Return findings whose title matches any pattern (case-insensitive)."""
    patterns_lower = [p.lower() for p in patterns]
    result = []
    for f in findings:
        title_l = (f.get("title") or "").lower()
        if any(p in title_l for p in patterns_lower):
            result.append(f)
    return result


def _filter_by_tool(findings, tool_name):
    """Return findings whose tool field matches."""
    return [f for f in findings if (f.get("tool") or "").lower() == tool_name.lower()]


def _top_findings(findings, count=5):
    """Return the top N findings by risk severity."""
    sorted_f = sorted(findings, key=risk_sort)
    return sorted_f[:count]


def _host_inventory_table(hosts):
    """Render an internal host inventory table from SS3 hosts data."""
    if not hosts:
        return '<p style="color:var(--slate-400);font-style:italic;">No host inventory available.</p>'
    h = '<table><tr><th>IP Address</th><th>Hostname</th><th>OS</th><th>Open Ports</th></tr>'
    for host in hosts[:100]:
        ip = esc(host.get("ip", ""))
        hostname = esc(host.get("hostname", "") or host.get("hostnames", [""])[0] if isinstance(host.get("hostnames"), list) else host.get("hostname", ""))
        os_name = esc(host.get("os", "") or host.get("os_match", ""))
        ports = host.get("ports", {})
        if isinstance(ports, dict):
            port_list = sorted(int(p) for p in ports.keys() if str(p).isdigit())
        elif isinstance(ports, list):
            port_list = sorted(int(p.get("port", 0)) for p in ports if isinstance(p, dict))
        else:
            port_list = []
        port_str = ", ".join(str(p) for p in port_list[:15])
        if len(port_list) > 15:
            port_str += f" (+{len(port_list) - 15} more)"
        h += f'<tr><td><code>{ip}</code></td><td>{hostname}</td><td>{os_name}</td><td style="font-size:8pt">{port_str}</td></tr>'
    h += '</table>'
    if len(hosts) > 100:
        h += f'<p style="font-size:8pt;color:var(--slate-400);">Showing 100 of {len(hosts)} hosts.</p>'
    return h


def _subnet_analysis(hosts):
    """Group hosts by /24 subnet and show counts."""
    subnets = Counter()
    for host in hosts:
        ip = host.get("ip", "")
        parts = ip.split(".")
        if len(parts) == 4:
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            subnets[subnet] += 1
    if not subnets:
        return ""
    h = '<table><tr><th>Subnet</th><th>Hosts Discovered</th></tr>'
    for subnet, count in subnets.most_common(30):
        h += f'<tr><td><code>{esc(subnet)}</code></td><td style="text-align:center">{count}</td></tr>'
    h += '</table>'
    return h


def _map_pci_req(finding):
    title = (finding.get("title") or "").lower()
    for keyword, req in _PCI_FINDING_MAP.items():
        if keyword in title:
            return req
    return "6.1 / 11.2"


# ── OWASP classification constants ──────────────────────────────────


_OWASP_WEB_2021 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable & Outdated Components",
    "A07": "Identification & Authentication Failures",
    "A08": "Software & Data Integrity Failures",
    "A09": "Security Logging & Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}


_OWASP_WEB_KEYWORDS = {
    "A01": ["access control", "authorization", "idor", "privilege escalation",
            "forced browsing", "cors misconfiguration", "directory traversal"],
    "A02": ["tls", "ssl", "certificate", "cipher", "cleartext", "hsts",
            "cryptograph", "weak encryption", "plaintext", "pfs"],
    "A03": ["injection", "sqli", "xss", "cross-site scripting", "command injection",
            "ldap injection", "xpath", "template injection", "ssti", "nosql"],
    "A04": ["insecure design", "business logic", "race condition", "enumeration"],
    "A05": ["misconfiguration", "default credential", "debug", "verbose error",
            "directory listing", "server header", "information disclosure",
            "stack trace", "backup file", "security header"],
    "A06": ["outdated", "eol", "end of life", "cve-", "vulnerable version",
            "known vulnerability", "component", "library", "framework version"],
    "A07": ["authentication", "brute force", "session", "credential", "password",
            "login", "jwt", "token", "mfa", "2fa", "otp"],
    "A08": ["integrity", "deserialization", "unsigned", "supply chain",
            "ci/cd", "auto-update"],
    "A09": ["logging", "monitoring", "audit", "log"],
    "A10": ["ssrf", "server-side request"],
}


_OWASP_API_2023 = {
    "API1": "Broken Object Level Authorization",
    "API2": "Broken Authentication",
    "API3": "Broken Object Property Level Authorization",
    "API4": "Unrestricted Resource Consumption",
    "API5": "Broken Function Level Authorization",
    "API6": "Unrestricted Access to Sensitive Business Flows",
    "API7": "Server Side Request Forgery",
    "API8": "Security Misconfiguration",
    "API9": "Improper Inventory Management",
    "API10": "Unsafe Consumption of APIs",
}


_OWASP_API_KEYWORDS = {
    "API1": ["bola", "idor", "object level", "horizontal privilege",
             "insecure direct object"],
    "API2": ["authentication", "broken auth", "jwt", "token", "api key",
             "credential", "session", "oauth"],
    "API3": ["mass assignment", "excessive data", "property level",
             "response filtering"],
    "API4": ["rate limit", "resource consumption", "dos", "pagination",
             "unbounded", "throttl"],
    "API5": ["function level", "admin endpoint", "privilege escalation",
             "vertical privilege", "rbac"],
    "API6": ["business flow", "business logic", "abuse", "scraping",
             "automated threat"],
    "API7": ["ssrf", "server-side request"],
    "API8": ["misconfiguration", "cors", "verbose error", "debug",
             "default", "security header", "tls", "ssl"],
    "API9": ["inventory", "shadow api", "deprecated", "undocumented",
             "rogue endpoint", "api version"],
    "API10": ["third-party", "upstream", "downstream", "consumption",
              "external api", "integration"],
}


def _classify_owasp_web(finding):
    title = (finding.get("title") or "").lower()
    desc = (finding.get("description") or "").lower()
    owasp = (finding.get("owasp") or "").upper()
    text = title + " " + desc

    if owasp:
        for code in _OWASP_WEB_2021:
            if code in owasp:
                return code

    for code, keywords in _OWASP_WEB_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            return code
    return None


def _classify_owasp_api(finding):
    title = (finding.get("title") or "").lower()
    desc = (finding.get("description") or "").lower()
    owasp_api = (finding.get("owasp_api") or "").upper()
    text = title + " " + desc

    if owasp_api:
        for code in _OWASP_API_2023:
            if code in owasp_api:
                return code

    for code, keywords in _OWASP_API_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            return code
    return None


def _malicious_indicators_section(findings):
    patterns = ["malicious", "malware", "phishing", "c2", "command and control",
                "backdoor", "suspicious", "trojan", "ransomware", "botnet",
                "exfiltration", "data leak", "unauthorized forward",
                "credential harvest", "keylog"]
    mal_f = []
    for f in findings:
        text = ((f.get("title") or "") + " " + (f.get("description") or "")).lower()
        if any(p in text for p in patterns):
            mal_f.append(f)
    if not mal_f:
        return ""
    mal_f.sort(key=risk_sort)
    h = '<div class="page"><h1>Malicious Indicators</h1>'
    h += '<p class="section-intro">Findings associated with potentially malicious activity, '
    h += 'including malicious IPs, links, traffic patterns, data forwarding, or credential theft indicators.</p>'
    for idx, f in enumerate(mal_f, 1):
        h += finding_card(f, idx)
    h += '</div>'
    return h


# ═══════════════════════════════════════════════════════════════════════
#  DATA GATHERERS
# ═══════════════════════════════════════════════════════════════════════

def gather_external_data(project):
    ss3_td = _resolve_tool_dir(project, "ss3")
    osift_td = _resolve_tool_dir(project, "osift")

    all_findings = []
    for f in _load_findings_for_tool(project, "ss3"):
        f.setdefault("tool", "scattershot3")
        all_findings.append(f)
    for f in _load_findings_for_tool(project, "fracture"):
        f.setdefault("tool", "fracture")
        all_findings.append(f)
    for f in _load_findings_for_tool(project, "osift"):
        f.setdefault("tool", "osift")
        if not _is_empty_typosquat(f):
            all_findings.append(f)

    findings = merge_findings(all_findings)
    findings = [f for f in findings if not _should_exclude_from_report(f)]

    return {
        "crucible_meta": project,
        "findings": findings,
        "ss3_hosts": _load_ss3_hosts(ss3_td),
        "ss3_services": _load_ss3_services(ss3_td),
        "ss3_software": _load_ss3_software(ss3_td),
        "osift_targets": _load_osift_targets(osift_td),
        "osift_dns": _load_osift_dns(osift_td),
        "osift_nslookup": _load_osift_nslookup(osift_td),
    }


def gather_osint_data(project):
    osift_td = _resolve_tool_dir(project, "osift")

    osift_findings = []
    for f in _load_findings_for_tool(project, "osift"):
        f.setdefault("tool", "osift")
        if not _is_empty_typosquat(f):
            osift_findings.append(f)

    findings = merge_findings(osift_findings)
    findings = [f for f in findings if not _should_exclude_from_report(f)]

    return {
        "crucible_meta": project,
        "findings": findings,
        "osift_targets": _load_osift_targets(osift_td),
        "osift_dns": _load_osift_dns(osift_td),
        "osift_nslookup": _load_osift_nslookup(osift_td),
        "osift_dns_per_domain": _load_osift_dns_per_domain(osift_td),
        "osift_nslookup_per_domain": _load_osift_nslookup_per_domain(osift_td),
    }


def gather_internal_data(project):
    """Build the data dict for internal-scope reports."""
    ss3_td = _resolve_tool_dir(project, "ss3")

    all_ss3 = _load_findings_for_tool(project, "ss3")
    all_deps = _load_findings_for_tool(project, "deps")
    all_nuclei = _load_findings_for_tool(project, "nuclei")
    all_nessus = _load_findings_for_tool(project, "nessus")
    all_authprobe = _load_findings_for_tool(project, "authprobe")

    def _is_internal(f):
        s = (f.get("scope") or "").lower()
        if s == "internal":
            return True
        if not s:
            ip = f.get("ip", "")
            if ip and (ip.startswith("10.") or ip.startswith("192.168.") or
                       ip.startswith("172.16.") or ip.startswith("172.17.") or
                       ip.startswith("172.18.") or ip.startswith("172.19.") or
                       ip.startswith("172.2") or ip.startswith("172.30.") or
                       ip.startswith("172.31.")):
                return True
        return False

    ss3_findings = [f for f in all_ss3 if _is_internal(f)]
    deps_findings = [f for f in all_deps if _is_internal(f)]
    nuclei_findings = [f for f in all_nuclei if _is_internal(f)]
    nessus_findings = [f for f in all_nessus if _is_internal(f)]
    authprobe_findings = [f for f in all_authprobe if _is_internal(f)]

    return {
        "ss3_findings": ss3_findings,
        "deps_findings": deps_findings,
        "nuclei_findings": nuclei_findings,
        "nessus_findings": nessus_findings,
        "authprobe_findings": authprobe_findings,
        "auger_findings": _load_findings_for_tool(project, "auger"),
        "bastion_findings": _load_findings_for_tool(project, "bastion"),
        "trawler_findings": _load_findings_for_tool(project, "trawler"),
        "ss3_hosts": _load_ss3_hosts(ss3_td),
        "ss3_services": _load_ss3_services(ss3_td),
        "ss3_software": _load_ss3_software(ss3_td),
        "crucible_meta": project,
    }


def gather_wireless_data(project):
    """Build the data dict for wireless-scope reports."""
    return {
        "aether_findings": _load_findings_for_tool(project, "aether"),
        "aether_b_findings": _load_findings_for_tool(project, "aether_b"),
        "aether_z_findings": _load_findings_for_tool(project, "aether_z"),
        "aether_u_findings": _load_findings_for_tool(project, "aether_u"),
        "crucible_meta": project,
    }


def gather_web_data(project):
    fr_findings = _load_findings_for_tool(project, "fracture")
    for f in fr_findings:
        f.setdefault("tool", "fracture")
    nuclei_findings = _load_findings_for_tool(project, "nuclei")
    for f in nuclei_findings:
        f.setdefault("tool", "nuclei")
    deps_findings = _load_findings_for_tool(project, "deps")
    for f in deps_findings:
        f.setdefault("tool", "deps")

    all_findings = merge_findings(fr_findings + nuclei_findings + deps_findings)

    return {
        "crucible_meta": project,
        "findings": all_findings,
        "fr_findings": fr_findings,
        "nuclei_findings": nuclei_findings,
        "deps_findings": deps_findings,
    }


def gather_api_data(project):
    si_findings = _load_findings_for_tool(project, "siphon")
    for f in si_findings:
        f.setdefault("tool", "siphon")
    nuclei_findings = _load_findings_for_tool(project, "nuclei")
    for f in nuclei_findings:
        f.setdefault("tool", "nuclei")
    deps_findings = _load_findings_for_tool(project, "deps")
    for f in deps_findings:
        f.setdefault("tool", "deps")

    all_findings = merge_findings(si_findings + nuclei_findings + deps_findings)

    si_td = _resolve_tool_dir(project, "siphon")
    api_inventory = []
    if si_td:
        inv = _load_json(si_td / "api_inventory.json")
        if isinstance(inv, list):
            api_inventory = inv
        elif isinstance(inv, dict):
            api_inventory = inv.get("endpoints", inv.get("inventory", []))

    return {
        "crucible_meta": project,
        "findings": all_findings,
        "si_findings": si_findings,
        "nuclei_findings": nuclei_findings,
        "deps_findings": deps_findings,
        "api_inventory": api_inventory,
    }


def gather_trawler_data(project):
    return {
        "trawler_findings": _load_findings_for_tool(project, "trawler"),
        "crucible_meta": project,
    }


def gather_auger_data(project):
    return {
        "auger_findings": _load_findings_for_tool(project, "auger"),
        "crucible_meta": project,
    }


def gather_bastion_data(project):
    return {
        "bastion_findings": _load_findings_for_tool(project, "bastion"),
        "crucible_meta": project,
    }


def gather_forge_data(project):
    return {
        "forge_findings": _load_findings_for_tool(project, "forge"),
        "crucible_meta": project,
    }


def gather_quill_data(project):
    return {
        "quill_findings": _load_findings_for_tool(project, "quill"),
        "crucible_meta": project,
    }


def gather_isotope_data(project):
    return {
        "isotope_findings": _load_findings_for_tool(project, "isotope"),
        "crucible_meta": project,
    }


def gather_cross_scope_data(project):
    all_findings = []
    for tool_key in ("ss3", "fracture", "siphon", "osift", "nuclei", "nessus",
                     "deps", "authprobe", "aether", "aether_b", "aether_z",
                     "aether_u", "dredge", "trawler", "auger", "bastion",
                     "forge", "quill", "isotope", "gearbox"):
        for f in _load_findings_for_tool(project, tool_key):
            f.setdefault("tool", tool_key)
            all_findings.append(f)

    findings = merge_findings(all_findings)

    return {
        "crucible_meta": project,
        "findings": findings,
        "all_findings_raw": all_findings,
    }


# ═══════════════════════════════════════════════════════════════════════
#  EXTERNAL SCOPE BUILDERS
# ═══════════════════════════════════════════════════════════════════════

def build_ext_vuln_report(data):
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = data.get("findings", [])
    targets = _scope_target_lines(meta, "external")

    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in findings)
    total = len(findings)

    cover = _build_scope_cover(client_name, "External Vulnerability Assessment",
                               meta, "External Penetration Test", targets, incomplete)
    body = cover

    # Executive Summary
    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'<p class="section-intro">{SCOPE_SUMMARIES.get("external", "")}</p>'
    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{total}</div><div class="stat-label">Total Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#dc2626">{risk_counts.get("CRITICAL", 0)}</div><div class="stat-label">Critical</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#ea580c">{risk_counts.get("HIGH", 0)}</div><div class="stat-label">High</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#d97706">{risk_counts.get("MEDIUM", 0)}</div><div class="stat-label">Medium</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#059669">{risk_counts.get("LOW", 0) + risk_counts.get("INFO", 0)}</div><div class="stat-label">Low / Info</div></div>'
    body += '</div>'

    # Risk Distribution
    body += '<h2>Risk Distribution</h2>'
    body += _risk_cards_html(risk_counts)
    body += '</div>'

    # Detailed Findings
    if findings:
        body += '<div class="page">'
        body += _findings_section_full(findings, "Detailed Findings")
        body += '</div>'

    # Remediation Summary
    remed_html = _remediation_summary(findings)
    if remed_html:
        body += f'<div class="page"><h1>Remediation Priorities</h1>{remed_html}</div>'

    return _endpoint_doc_wrap("External Vulnerability Assessment", client_name, body)


def build_ext_surface_report(data):
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    hosts = data.get("ss3_hosts", [])
    services = data.get("ss3_services", {})
    software_raw = data.get("ss3_software", [])
    dns_data = data.get("osift_dns", {})
    nslookup = data.get("osift_nslookup", {})
    targets = _scope_target_lines(meta, "external")

    software = _normalize_software(software_raw)

    open_services = {}
    for svc_name, entries in services.items():
        open_entries = [e for e in entries if e.get("state") == "open"]
        if open_entries:
            open_services[svc_name] = open_entries

    tcp_ports = set()
    for entries in open_services.values():
        for e in entries:
            if e.get("protocol") == "tcp":
                tcp_ports.add(e.get("port", 0))

    cover = _build_scope_cover(client_name, "Attack Surface Report",
                               meta, "External Penetration Test", targets, incomplete)
    body = cover

    # Executive Summary
    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'<p class="section-intro">This report details the externally visible attack surface of <strong>{esc(client_name)}</strong>, including open ports, exposed services, detected technologies, and DNS infrastructure.</p>'
    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(hosts)}</div><div class="stat-label">Hosts Discovered</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(tcp_ports)}</div><div class="stat-label">Open TCP Ports</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(open_services)}</div><div class="stat-label">Unique Services</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(software)}</div><div class="stat-label">Technologies Detected</div></div>'
    body += '</div></div>'

    # Open Ports Inventory
    if tcp_ports:
        body += '<div class="page"><h1>Open Ports Inventory</h1>'
        body += '<table><tr><th>Host</th><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Version</th></tr>'
        rows = []
        for svc_name, entries in sorted(open_services.items()):
            for e in entries:
                rows.append(e)
        rows.sort(key=lambda e: (e.get("ip", ""), e.get("port", 0)))
        for e in rows[:200]:
            body += (f'<tr><td><code>{esc(e.get("ip", ""))}</code></td>'
                     f'<td>{e.get("port", "")}</td>'
                     f'<td>{esc(e.get("protocol", "tcp"))}</td>'
                     f'<td>{esc(e.get("service", ""))}</td>'
                     f'<td>{esc(e.get("product", ""))}</td>'
                     f'<td>{esc(e.get("version", ""))}</td></tr>')
        if len(rows) > 200:
            body += f'<tr><td colspan="6" style="text-align:center;color:var(--slate-400);font-style:italic;">… and {len(rows)-200} additional entries</td></tr>'
        body += '</table></div>'

    # Exposed Services
    if open_services:
        body += '<div class="page"><h1>Exposed Services</h1>'
        body += f'<p class="section-intro">{len(open_services)} unique service types were identified across the external attack surface.</p>'
        body += '<table><tr><th>Service</th><th>Instances</th><th>Ports</th></tr>'
        for svc_name in sorted(open_services.keys()):
            entries = open_services[svc_name]
            ports = sorted(set(e.get("port", 0) for e in entries))
            ports_str = ", ".join(str(p) for p in ports[:10])
            if len(ports) > 10:
                ports_str += f" (+{len(ports)-10})"
            body += f'<tr><td><strong>{esc(svc_name)}</strong></td><td>{len(entries)}</td><td><code>{esc(ports_str)}</code></td></tr>'
        body += '</table></div>'

    # Detected Technologies
    if software:
        body += '<div class="page"><h1>Detected Technologies</h1>'
        body += '<table><tr><th>Technology</th><th>Version</th><th>Host</th><th>Port</th></tr>'
        for s in software[:150]:
            body += (f'<tr><td>{esc(s.get("software", ""))}</td>'
                     f'<td>{esc(s.get("version", ""))}</td>'
                     f'<td><code>{esc(s.get("ip", ""))}</code></td>'
                     f'<td>{s.get("port", "")}</td></tr>')
        if len(software) > 150:
            body += f'<tr><td colspan="4" style="text-align:center;color:var(--slate-400);font-style:italic;">… and {len(software)-150} additional entries</td></tr>'
        body += '</table></div>'

    # DNS Infrastructure
    a_records = dns_data.get("A", [])
    ns_records = dns_data.get("NS", [])
    mx_records = dns_data.get("MX", [])
    if a_records or ns_records or mx_records:
        body += '<div class="page"><h1>DNS Infrastructure</h1>'
        if ns_records:
            body += '<h2>Nameservers</h2><table><tr><th>Nameserver</th></tr>'
            for r in ns_records:
                body += f'<tr><td><code>{esc(r.get("nameserver", r.get("host", "")))}</code></td></tr>'
            body += '</table>'
        if mx_records:
            body += '<h2>Mail Exchangers</h2><table><tr><th>Exchange</th><th>Priority</th></tr>'
            for r in sorted(mx_records, key=lambda x: x.get("priority", 99)):
                body += f'<tr><td><code>{esc(r.get("exchange", ""))}</code></td><td>{r.get("priority", "")}</td></tr>'
            body += '</table>'
        if a_records:
            body += '<h2>A Records</h2><table><tr><th>Host</th><th>Address</th></tr>'
            for r in a_records[:50]:
                body += f'<tr><td>{esc(r.get("host", r.get("name", "")))}</td><td><code>{esc(r.get("address", r.get("ip", "")))}</code></td></tr>'
            body += '</table>'
        body += '</div>'

    return _endpoint_doc_wrap("Attack Surface Report", client_name, body)


def build_ext_pci_report(data):
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = data.get("findings", [])
    targets = _scope_target_lines(meta, "external")

    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in findings)
    crit_high = risk_counts.get("CRITICAL", 0) + risk_counts.get("HIGH", 0)
    pci_pass = crit_high == 0

    cover = _build_scope_cover(client_name, "PCI DSS External Scan Report",
                               meta, "PCI DSS v4.0 Compliance", targets, incomplete)
    body = cover

    # Executive Summary
    body += '<div class="page"><h1>Executive Summary</h1>'
    body += '<p class="section-intro">This report maps the external vulnerability assessment results to the Payment Card Industry Data Security Standard (PCI DSS) v4.0 requirements. Findings are evaluated against the ASV Program Guide criteria to determine compliance status.</p>'

    pass_color = "#059669" if pci_pass else "#dc2626"
    pass_label = "PASS" if pci_pass else "FAIL"
    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number" style="color:{pass_color}">{pass_label}</div><div class="stat-label">Overall Status</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(findings)}</div><div class="stat-label">Total Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#dc2626">{crit_high}</div><div class="stat-label">Critical / High</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#d97706">{risk_counts.get("MEDIUM", 0)}</div><div class="stat-label">Medium</div></div>'
    body += '</div>'

    if not pci_pass:
        body += '<div class="narrative-block"><div class="phase-label">Compliance Note</div>'
        body += f'<p>The scan identified <strong>{crit_high} critical or high severity finding{"s" if crit_high != 1 else ""}</strong> which constitute automatic PCI DSS ASV scan failures. These must be remediated and the scan re-run before achieving a passing result.</p></div>'
    body += '</div>'

    # PCI Requirements Mapping
    body += '<div class="page"><h1>PCI DSS v4.0 Requirements Mapping</h1>'
    body += '<table><tr><th>#</th><th>Finding</th><th>Risk</th><th>PCI Requirement</th><th>Status</th></tr>'
    for idx, f in enumerate(sorted(findings, key=risk_sort), 1):
        risk = (f.get("risk") or "INFO").upper()
        color = RISK_COLORS.get(risk, "#666")
        pci_req = f.get("pci_dss_4", [])
        pci_str = ", ".join(pci_req) if isinstance(pci_req, list) and pci_req else _map_pci_req(f)
        status = "FAIL" if risk in ("CRITICAL", "HIGH") else "REVIEW"
        status_color = "#dc2626" if status == "FAIL" else "#d97706"
        body += (f'<tr><td>{idx}</td>'
                 f'<td>{esc(f.get("title", "Untitled"))}</td>'
                 f'<td><span class="badge-sm" style="background:{color}">{risk}</span></td>'
                 f'<td><code>{esc(pci_str)}</code></td>'
                 f'<td style="color:{status_color};font-weight:700;">{status}</td></tr>')
    body += '</table></div>'

    # Recommendations
    body += '<div class="page"><h1>Recommendations</h1>'
    body += '<div class="narrative-block"><div class="phase-label">Priority Actions</div>'
    body += '<p>The following actions are recommended to achieve PCI DSS compliance:</p></div>'
    body += '<ul class="obs-list">'
    if risk_counts.get("CRITICAL", 0):
        body += '<li>Immediately remediate all <strong>Critical</strong> severity findings — these represent active exploitation risk and automatic ASV scan failure.</li>'
    if risk_counts.get("HIGH", 0):
        body += '<li>Remediate all <strong>High</strong> severity findings — these trigger automatic ASV scan failure under PCI DSS v4.0.</li>'
    if risk_counts.get("MEDIUM", 0):
        body += '<li>Address <strong>Medium</strong> severity findings to reduce overall risk exposure and improve compliance posture.</li>'
    body += '<li>Re-run the external ASV scan after remediation to confirm passing status.</li>'
    body += '<li>Document any findings accepted as false positives with supporting evidence for the QSA.</li>'
    body += '</ul></div>'

    return _endpoint_doc_wrap("PCI DSS External Scan Report", client_name, body)


def build_ext_firewall_report(data):
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = data.get("findings", [])
    hosts = data.get("ss3_hosts", [])
    services = data.get("ss3_services", {})
    targets = _scope_target_lines(meta, "external")

    open_services = {}
    for svc_name, entries in services.items():
        open_entries = [e for e in entries if e.get("state") == "open"]
        if open_entries:
            open_services[svc_name] = open_entries

    tcp_ports = set()
    all_port_entries = []
    for entries in open_services.values():
        for e in entries:
            if e.get("protocol") == "tcp":
                tcp_ports.add(e.get("port", 0))
                all_port_entries.append(e)

    header_findings = [f for f in findings if "security header" in (f.get("title") or "").lower()]
    firewall_findings = [f for f in findings
                         if any(kw in (f.get("title") or "").lower()
                                for kw in ("firewall", "filter", "acl", "ingress", "egress", "port"))]

    cover = _build_scope_cover(client_name, "Perimeter Firewall Assessment",
                               meta, "External Penetration Test", targets, incomplete)
    body = cover

    # Executive Summary
    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'<p class="section-intro">This report evaluates the perimeter firewall and network filtering posture of <strong>{esc(client_name)}</strong> based on external reconnaissance and vulnerability assessment results. The assessment identifies exposed services, evaluates filtering effectiveness, and provides recommendations for improving perimeter security.</p>'
    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(tcp_ports)}</div><div class="stat-label">Open TCP Ports</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(open_services)}</div><div class="stat-label">Exposed Services</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(header_findings)}</div><div class="stat-label">Header Issues</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(hosts)}</div><div class="stat-label">Hosts Assessed</div></div>'
    body += '</div></div>'

    # Exposed Services Analysis
    body += '<div class="page"><h1>Exposed Services Analysis</h1>'
    body += '<p class="section-intro">The following services are externally reachable through the perimeter firewall. Each exposed service represents a potential attack vector.</p>'
    if all_port_entries:
        body += '<table><tr><th>Host</th><th>Port</th><th>Service</th><th>Product</th><th>Risk</th></tr>'
        all_port_entries.sort(key=lambda e: (e.get("ip", ""), e.get("port", 0)))
        web_ports = {80, 443, 8080, 8443, 2053, 2083, 2087, 2096}
        for e in all_port_entries[:100]:
            port = e.get("port", 0)
            svc = e.get("service", "")
            risk_lvl = "Expected" if port in web_ports else "Review"
            risk_color = "#059669" if risk_lvl == "Expected" else "#d97706"
            body += (f'<tr><td><code>{esc(e.get("ip", ""))}</code></td>'
                     f'<td>{port}</td>'
                     f'<td>{esc(svc)}</td>'
                     f'<td>{esc(e.get("product", ""))}</td>'
                     f'<td style="color:{risk_color};font-weight:600;">{risk_lvl}</td></tr>')
        body += '</table>'
    else:
        body += '<p style="color:var(--slate-400);font-style:italic;">No open services detected — perimeter filtering appears comprehensive.</p>'
    body += '</div>'

    # Security Header Analysis
    if header_findings:
        body += '<div class="page"><h1>Security Header Analysis</h1>'
        body += '<p class="section-intro">Web services were evaluated for the presence of recommended security headers. Missing headers weaken the browser-side security posture and may indicate incomplete web application firewall configuration.</p>'
        body += _findings_section_full(header_findings, "Missing Security Headers")
        body += '</div>'

    # Firewall-specific findings
    if firewall_findings:
        body += '<div class="page"><h1>Firewall-Related Findings</h1>'
        body += _findings_section_full(firewall_findings, "Network Filtering Issues")
        body += '</div>'

    # Recommendations
    body += '<div class="page"><h1>Recommendations</h1>'
    body += '<ul class="obs-list">'
    non_web_ports = tcp_ports - {80, 443, 8080, 8443}
    if non_web_ports:
        ports_str = ", ".join(str(p) for p in sorted(non_web_ports)[:10])
        body += f'<li>Review non-standard exposed ports ({ports_str}) and restrict access where possible through firewall rules.</li>'
    if header_findings:
        body += f'<li>Implement missing security headers on {len(header_findings)} identified web services to strengthen browser-side protections.</li>'
    body += '<li>Implement egress filtering to prevent data exfiltration through non-essential outbound ports.</li>'
    body += '<li>Deploy a web application firewall (WAF) for all internet-facing web applications.</li>'
    body += '<li>Conduct regular firewall rule reviews to identify and remove overly permissive rules.</li>'
    body += '</ul></div>'

    return _endpoint_doc_wrap("Perimeter Firewall Assessment", client_name, body)


def build_ext_exec_report(data):
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = data.get("findings", [])
    hosts = data.get("ss3_hosts", [])
    services = data.get("ss3_services", {})
    targets = _scope_target_lines(meta, "external")

    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in findings)
    total = len(findings)

    tcp_ports = set()
    for entries in services.values():
        for e in entries:
            if e.get("protocol") == "tcp" and e.get("state") == "open":
                tcp_ports.add(e.get("port", 0))

    crit = risk_counts.get("CRITICAL", 0)
    high = risk_counts.get("HIGH", 0)

    cover = _build_scope_cover(client_name, "Executive Summary — External",
                               meta, "External Penetration Test", targets, incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Overview</h1>'
    body += f'<p class="section-intro">This executive summary presents the key findings from the external penetration test of <strong>{esc(client_name)}</strong>. The assessment evaluated {len(hosts)} host{"s" if len(hosts) != 1 else ""} with {len(tcp_ports)} externally accessible service port{"s" if len(tcp_ports) != 1 else ""}.</p>'

    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{total}</div><div class="stat-label">Total Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(hosts)}</div><div class="stat-label">Hosts Assessed</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(tcp_ports)}</div><div class="stat-label">Open Ports</div></div>'
    body += '</div>'

    # Risk Heat Map
    body += '<h2>Risk Distribution</h2>'
    body += _exec_risk_heatmap(risk_counts, total)
    body += _risk_cards_html(risk_counts)

    # Key Observations
    body += '<h2>Key Observations</h2><ul class="obs-list">'
    if crit + high == 0:
        body += f'<li>No critical or high-severity vulnerabilities were identified across the external attack surface. The overall security posture is <strong>strong</strong>.</li>'
    else:
        body += f'<li><strong>{crit + high} critical/high-severity finding{"s" if crit + high != 1 else ""}</strong> require{"s" if crit + high == 1 else ""} immediate remediation attention.</li>'
    body += f'<li>The external attack surface consists of {len(hosts)} host{"s" if len(hosts) != 1 else ""} exposing {len(tcp_ports)} TCP port{"s" if len(tcp_ports) != 1 else ""}.</li>'

    header_count = sum(1 for f in findings if "security header" in (f.get("title") or "").lower())
    ssl_count = sum(1 for f in findings if any(kw in (f.get("title") or "").lower() for kw in ("ssl", "tls", "cipher", "certificate")))
    if header_count:
        body += f'<li>{header_count} security header misconfiguration{"s" if header_count != 1 else ""} should be addressed to strengthen browser-side protections.</li>'
    if ssl_count:
        body += f'<li>{ssl_count} SSL/TLS configuration finding{"s" if ssl_count != 1 else ""} should be remediated to improve transport security.</li>'
    body += '</ul>'

    # Strategic Recommendations
    body += '<h2>Strategic Recommendations</h2>'
    body += '<div class="narrative-block"><div class="phase-label">Priority Actions</div><p>'
    if crit + high > 0:
        body += f'Immediately address the {crit + high} critical/high-severity findings. '
    body += 'Implement missing security headers across all web services. '
    body += 'Review exposed non-essential services and restrict through firewall rules. '
    body += 'Establish a regular external vulnerability scanning cadence to maintain security posture.'
    body += '</p></div></div>'

    return _endpoint_doc_wrap("Executive Summary — External", client_name, body)


# ═══════════════════════════════════════════════════════════════════════
#  OSINT SCOPE BUILDERS
# ═══════════════════════════════════════════════════════════════════════

def build_osint_intel_report(data):
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = data.get("findings", [])
    osift_targets = data.get("osift_targets", {})
    dns_data = data.get("osift_dns", {})
    nslookup = data.get("osift_nslookup", {})
    targets = _scope_target_lines(meta, "osint")

    subdomains = osift_targets.get("subdomains", [])
    ips = osift_targets.get("ips", [])
    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in findings)
    total = len(findings)

    cover = _build_scope_cover(client_name, "OSINT Intelligence Report",
                               meta, "OSINT Reconnaissance", targets, incomplete)
    body = cover

    # Executive Summary
    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'<p class="section-intro">{SCOPE_SUMMARIES.get("osint", "")}</p>'
    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(subdomains)}</div><div class="stat-label">Subdomains</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(ips)}</div><div class="stat-label">IP Addresses</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{total}</div><div class="stat-label">Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#dc2626">{risk_counts.get("CRITICAL", 0) + risk_counts.get("HIGH", 0)}</div><div class="stat-label">Critical / High</div></div>'
    body += '</div></div>'

    # Subdomain Discovery
    if subdomains:
        body += '<div class="page"><h1>Subdomain Discovery</h1>'
        body += f'<p class="section-intro">{len(subdomains)} subdomain{"s" if len(subdomains) != 1 else ""} {"were" if len(subdomains) != 1 else "was"} identified through passive reconnaissance sources.</p>'
        body += '<table><tr><th>#</th><th>Subdomain</th><th>Source</th></tr>'
        for idx, sub in enumerate(subdomains[:200], 1):
            host = sub.get("host", sub) if isinstance(sub, dict) else str(sub)
            source = sub.get("source", "") if isinstance(sub, dict) else ""
            body += f'<tr><td>{idx}</td><td><code>{esc(host)}</code></td><td>{esc(source)}</td></tr>'
        if len(subdomains) > 200:
            body += f'<tr><td colspan="3" style="text-align:center;color:var(--slate-400);font-style:italic;">… and {len(subdomains)-200} additional subdomains</td></tr>'
        body += '</table></div>'

    # DNS Infrastructure
    ns_records = dns_data.get("NS", [])
    mx_records = dns_data.get("MX", [])
    a_records = dns_data.get("A", [])
    txt_records = dns_data.get("TXT", [])
    if ns_records or mx_records or a_records:
        body += '<div class="page"><h1>DNS Infrastructure</h1>'
        if ns_records:
            body += '<h2>Nameservers</h2><table><tr><th>Nameserver</th></tr>'
            for r in ns_records:
                body += f'<tr><td><code>{esc(r.get("nameserver", r.get("host", "")))}</code></td></tr>'
            body += '</table>'
        if a_records:
            body += '<h2>A Records</h2><table><tr><th>Host</th><th>Address</th></tr>'
            for r in a_records[:80]:
                body += f'<tr><td>{esc(r.get("host", r.get("name", "")))}</td><td><code>{esc(r.get("address", r.get("ip", "")))}</code></td></tr>'
            body += '</table>'
        if mx_records:
            body += '<h2>Mail Exchangers</h2><table><tr><th>Exchange</th><th>Priority</th></tr>'
            for r in sorted(mx_records, key=lambda x: x.get("priority", 99)):
                body += f'<tr><td><code>{esc(r.get("exchange", ""))}</code></td><td>{r.get("priority", "")}</td></tr>'
            body += '</table>'
        body += '</div>'

    # IP Ranges
    if ips:
        body += '<div class="page"><h1>IP Address Intelligence</h1>'
        body += '<table><tr><th>#</th><th>IP Address</th><th>Source</th></tr>'
        for idx, ip_entry in enumerate(ips[:100], 1):
            ip_addr = ip_entry.get("ip", ip_entry) if isinstance(ip_entry, dict) else str(ip_entry)
            source = ip_entry.get("source", "") if isinstance(ip_entry, dict) else ""
            body += f'<tr><td>{idx}</td><td><code>{esc(ip_addr)}</code></td><td>{esc(source)}</td></tr>'
        body += '</table></div>'

    # Email Infrastructure
    spf_val = _find_spf(dns_data)
    dmarc_val = _find_dmarc(dns_data)
    body += '<div class="page"><h1>Email Infrastructure</h1>'
    body += '<table class="table-light"><tr><th>Component</th><th>Status</th><th>Value</th></tr>'
    body += f'<tr><td><strong>SPF Record</strong></td><td>{"✓ Configured" if spf_val != "Not configured" else "✗ Missing"}</td><td><code>{esc(spf_val[:120])}</code></td></tr>'
    body += f'<tr><td><strong>DMARC Record</strong></td><td>{"✓ Configured" if dmarc_val else "✗ Missing"}</td><td><code>{esc(dmarc_val[:120]) if dmarc_val else "Not configured"}</code></td></tr>'
    if mx_records:
        mx_str = ", ".join(r.get("exchange", "") for r in mx_records[:5])
        body += f'<tr><td><strong>Mail Exchangers</strong></td><td>✓ Configured</td><td><code>{esc(mx_str)}</code></td></tr>'
    body += '</table></div>'

    # OSINT Findings
    if findings:
        body += '<div class="page">'
        body += _findings_section_full(findings, "OSINT Findings")
        body += '</div>'

    return _endpoint_doc_wrap("OSINT Intelligence Report", client_name, body)


def build_osint_footprint_report(data):
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    osift_targets = data.get("osift_targets", {})
    dns_data = data.get("osift_dns", {})
    nslookup = data.get("osift_nslookup", {})
    targets = _scope_target_lines(meta, "osint")

    subdomains = osift_targets.get("subdomains", [])
    ips = osift_targets.get("ips", [])
    rev = nslookup.get("reverse_lookups", {})

    # Detect hosting/CDN
    hosting_providers = set()
    for fqdns in rev.values():
        for fqdn in (fqdns if isinstance(fqdns, list) else [fqdns]):
            fl = str(fqdn).lower()
            if "cloudflare" in fl:
                hosting_providers.add("Cloudflare")
            elif "amazon" in fl or "aws" in fl or "ec2" in fl:
                hosting_providers.add("AWS")
            elif "azure" in fl or "microsoft" in fl:
                hosting_providers.add("Microsoft Azure")
            elif "google" in fl or "gcp" in fl:
                hosting_providers.add("Google Cloud")
            elif "akamai" in fl:
                hosting_providers.add("Akamai")
            elif "shopify" in fl:
                hosting_providers.add("Shopify")
            elif "fastly" in fl:
                hosting_providers.add("Fastly")

    cover = _build_scope_cover(client_name, "Digital Footprint Report",
                               meta, "OSINT Reconnaissance", targets, incomplete)
    body = cover

    # Executive Summary
    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'<p class="section-intro">This report documents the public-facing digital footprint of <strong>{esc(client_name)}</strong>, including domains, IP address ranges, hosting infrastructure, and CDN relationships discovered through passive reconnaissance.</p>'
    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(subdomains)}</div><div class="stat-label">Subdomains</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(ips)}</div><div class="stat-label">IP Addresses</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(hosting_providers)}</div><div class="stat-label">Hosting Providers</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(rev)}</div><div class="stat-label">Reverse DNS Entries</div></div>'
    body += '</div></div>'

    # Domain Inventory
    if subdomains:
        body += '<div class="page"><h1>Domain Inventory</h1>'
        body += '<table><tr><th>#</th><th>Subdomain</th><th>Source</th></tr>'
        for idx, sub in enumerate(subdomains[:200], 1):
            host = sub.get("host", sub) if isinstance(sub, dict) else str(sub)
            source = sub.get("source", "") if isinstance(sub, dict) else ""
            body += f'<tr><td>{idx}</td><td><code>{esc(host)}</code></td><td>{esc(source)}</td></tr>'
        if len(subdomains) > 200:
            body += f'<tr><td colspan="3" style="text-align:center;color:var(--slate-400);">… and {len(subdomains)-200} more</td></tr>'
        body += '</table></div>'

    # IP Range Mapping
    if ips:
        body += '<div class="page"><h1>IP Address Mapping</h1>'
        body += '<table><tr><th>IP Address</th><th>Reverse DNS</th></tr>'
        for ip_entry in ips[:100]:
            ip_addr = ip_entry.get("ip", ip_entry) if isinstance(ip_entry, dict) else str(ip_entry)
            rev_entries = rev.get(ip_addr, [])
            rev_str = ", ".join(str(r) for r in rev_entries) if isinstance(rev_entries, list) else str(rev_entries)
            body += f'<tr><td><code>{esc(ip_addr)}</code></td><td>{esc(rev_str)}</td></tr>'
        body += '</table></div>'

    # Hosting Providers
    if hosting_providers:
        body += '<div class="page"><h1>Hosting & CDN Providers</h1>'
        body += '<p class="section-intro">The following hosting and content delivery providers were identified through reverse DNS analysis of the discovered IP addresses.</p>'
        body += '<table><tr><th>Provider</th><th>Detection Method</th></tr>'
        for provider in sorted(hosting_providers):
            body += f'<tr><td><strong>{esc(provider)}</strong></td><td>Reverse DNS Pattern Match</td></tr>'
        body += '</table></div>'

    # Reverse DNS
    if rev:
        body += '<div class="page"><h1>Reverse DNS Analysis</h1>'
        body += '<table><tr><th>IP Address</th><th>Reverse Hostname(s)</th></tr>'
        for ip_addr, fqdns in sorted(rev.items())[:100]:
            fqdn_list = fqdns if isinstance(fqdns, list) else [fqdns]
            body += f'<tr><td><code>{esc(ip_addr)}</code></td><td>{esc(", ".join(str(f) for f in fqdn_list))}</td></tr>'
        body += '</table></div>'

    return _endpoint_doc_wrap("Digital Footprint Report", client_name, body)


def build_osint_email_report(data):
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = data.get("findings", [])
    osift_targets = data.get("osift_targets", {})
    dns_data = data.get("osift_dns", {})
    targets = _scope_target_lines(meta, "osint")

    emails = osift_targets.get("emails", [])
    mx_records = dns_data.get("MX", [])
    spf_val = _find_spf(dns_data)
    dmarc_val = _find_dmarc(dns_data)

    email_findings = [f for f in findings
                      if any(kw in (f.get("title") or "").lower()
                             for kw in ("email", "spf", "dkim", "dmarc", "credential", "breach", "o365", "tenant"))]

    # Detect mail provider
    mail_provider = ""
    for r in mx_records:
        ex = (r.get("exchange") or "").lower()
        if "google" in ex:
            mail_provider = "Google Workspace"
            break
        elif "outlook" in ex or "microsoft" in ex:
            mail_provider = "Microsoft 365"
            break

    cover = _build_scope_cover(client_name, "Email & Credential Exposure Report",
                               meta, "OSINT Reconnaissance", targets, incomplete)
    body = cover

    # Executive Summary
    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'<p class="section-intro">This report evaluates the email security posture and credential exposure risk of <strong>{esc(client_name)}</strong> based on passive intelligence collection.</p>'
    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(emails)}</div><div class="stat-label">Emails Harvested</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(email_findings)}</div><div class="stat-label">Email Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{"✓" if spf_val != "Not configured" else "✗"}</div><div class="stat-label">SPF Record</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{"✓" if dmarc_val else "✗"}</div><div class="stat-label">DMARC Policy</div></div>'
    body += '</div></div>'

    # SPF / DKIM / DMARC Analysis
    body += '<div class="page"><h1>Email Authentication Analysis</h1>'
    body += '<h2>SPF (Sender Policy Framework)</h2>'
    if spf_val and spf_val != "Not configured":
        spf_strict = "-all" in spf_val
        body += f'<p class="section-intro">SPF record detected: <code>{esc(spf_val)}</code></p>'
        if spf_strict:
            body += '<p style="color:#059669;font-weight:600;">✓ Strict enforcement (-all) — unauthorized senders will be rejected.</p>'
        elif "~all" in spf_val:
            body += '<p style="color:#d97706;font-weight:600;">⚠ Soft fail (~all) — unauthorized senders are flagged but not rejected. Consider upgrading to -all.</p>'
        else:
            body += '<p style="color:#dc2626;font-weight:600;">✗ Weak enforcement — SPF record lacks strict rejection. Spoofing risk exists.</p>'
    else:
        body += '<p style="color:#dc2626;font-weight:600;">✗ No SPF record detected — email spoofing is possible.</p>'

    body += '<h2>DMARC (Domain-based Message Authentication)</h2>'
    if dmarc_val:
        body += f'<p class="section-intro">DMARC record detected: <code>{esc(dmarc_val[:200])}</code></p>'
        if "reject" in dmarc_val.lower():
            body += '<p style="color:#059669;font-weight:600;">✓ Policy set to reject — strong anti-spoofing protection.</p>'
        elif "quarantine" in dmarc_val.lower():
            body += '<p style="color:#d97706;font-weight:600;">⚠ Policy set to quarantine — consider upgrading to reject for maximum protection.</p>'
        else:
            body += '<p style="color:#dc2626;font-weight:600;">✗ Policy set to none — DMARC is monitoring only with no enforcement.</p>'
    else:
        body += '<p style="color:#dc2626;font-weight:600;">✗ No DMARC record detected — domain spoofing protection is absent.</p>'

    if mail_provider:
        body += f'<h2>Email Provider</h2><p class="section-intro">Mail infrastructure identified as <strong>{esc(mail_provider)}</strong>.</p>'
    body += '</div>'

    # Harvested Emails
    if emails:
        body += '<div class="page"><h1>Harvested Email Addresses</h1>'
        body += f'<p class="section-intro">{len(emails)} email address{"es" if len(emails) != 1 else ""} {"were" if len(emails) != 1 else "was"} discovered through passive reconnaissance. These addresses may be used for targeted phishing campaigns or credential stuffing attacks.</p>'
        body += '<table><tr><th>#</th><th>Email Address</th><th>Source</th></tr>'
        for idx, em in enumerate(emails[:200], 1):
            addr = em.get("email", em) if isinstance(em, dict) else str(em)
            source = em.get("source", "") if isinstance(em, dict) else ""
            body += f'<tr><td>{idx}</td><td><code>{esc(addr)}</code></td><td>{esc(source)}</td></tr>'
        if len(emails) > 200:
            body += f'<tr><td colspan="3" style="text-align:center;color:var(--slate-400);">… and {len(emails)-200} more</td></tr>'
        body += '</table></div>'

    # Findings
    if email_findings:
        body += '<div class="page">'
        body += _findings_section_full(email_findings, "Email Security Findings")
        body += '</div>'

    # Recommendations
    body += '<div class="page"><h1>Recommendations</h1><ul class="obs-list">'
    if spf_val == "Not configured":
        body += '<li>Implement an SPF record with strict enforcement (<code>-all</code>) to prevent email spoofing.</li>'
    elif "~all" in spf_val:
        body += '<li>Upgrade SPF policy from soft fail (<code>~all</code>) to hard fail (<code>-all</code>).</li>'
    if not dmarc_val:
        body += '<li>Implement a DMARC policy with <code>p=reject</code> to prevent domain spoofing.</li>'
    elif "none" in dmarc_val.lower():
        body += '<li>Upgrade DMARC policy from <code>p=none</code> to <code>p=reject</code> for active enforcement.</li>'
    if emails:
        body += f'<li>Review the {len(emails)} harvested email addresses and implement email address obfuscation on public-facing web properties.</li>'
    body += '<li>Monitor public breach databases for organizational credentials using a continuous monitoring service.</li>'
    body += '<li>Implement phishing-resistant multi-factor authentication for all user accounts.</li>'
    body += '</ul></div>'

    return _endpoint_doc_wrap("Email & Credential Exposure Report", client_name, body)


def build_osint_dns_report(data):
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = data.get("findings", [])
    dns_data = data.get("osift_dns", {})
    dns_per_domain = data.get("osift_dns_per_domain", {})
    targets = _scope_target_lines(meta, "osint")

    spf_val = _find_spf(dns_data)
    dmarc_val = _find_dmarc(dns_data)
    caa_records = dns_data.get("CAA", [])
    ns_records = dns_data.get("NS", [])
    txt_records = dns_data.get("TXT", [])

    dns_findings = [f for f in findings
                    if any(kw in (f.get("title") or "").lower()
                           for kw in ("dns", "spf", "dkim", "dmarc", "zone transfer", "subdomain takeover",
                                      "caa", "dnssec", "nameserver"))]

    cover = _build_scope_cover(client_name, "DNS Security Report",
                               meta, "OSINT Reconnaissance", targets, incomplete)
    body = cover

    # Executive Summary
    issue_count = 0
    if spf_val == "Not configured":
        issue_count += 1
    if not dmarc_val:
        issue_count += 1
    if not caa_records:
        issue_count += 1
    issue_count += len(dns_findings)

    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'<p class="section-intro">This report evaluates the DNS security configuration of <strong>{esc(client_name)}</strong>, covering email authentication (SPF, DKIM, DMARC), certificate authority authorization (CAA), DNSSEC status, and zone transfer protections.</p>'
    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{issue_count}</div><div class="stat-label">Issues Identified</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(ns_records)}</div><div class="stat-label">Nameservers</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(dns_per_domain)}</div><div class="stat-label">Domains Analyzed</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(txt_records)}</div><div class="stat-label">TXT Records</div></div>'
    body += '</div></div>'

    # DNS Security Assessment Table
    body += '<div class="page"><h1>DNS Security Assessment</h1>'
    body += '<table><tr><th>Control</th><th>Status</th><th>Details</th></tr>'

    # SPF
    spf_ok = spf_val != "Not configured" and "-all" in spf_val
    spf_status = "✓ Strong" if spf_ok else ("⚠ Weak" if spf_val != "Not configured" else "✗ Missing")
    spf_color = "#059669" if spf_ok else ("#d97706" if spf_val != "Not configured" else "#dc2626")
    body += f'<tr><td><strong>SPF</strong></td><td style="color:{spf_color};font-weight:600;">{spf_status}</td><td><code>{esc(spf_val[:100])}</code></td></tr>'

    # DMARC
    dmarc_reject = dmarc_val and "reject" in dmarc_val.lower()
    dmarc_ok = bool(dmarc_reject)
    dmarc_status = "✓ Reject" if dmarc_ok else ("⚠ Weak" if dmarc_val else "✗ Missing")
    dmarc_color = "#059669" if dmarc_ok else ("#d97706" if dmarc_val else "#dc2626")
    body += f'<tr><td><strong>DMARC</strong></td><td style="color:{dmarc_color};font-weight:600;">{dmarc_status}</td><td><code>{esc((dmarc_val or "Not configured")[:100])}</code></td></tr>'

    # CAA
    caa_ok = bool(caa_records)
    caa_status = "✓ Present" if caa_ok else "✗ Missing"
    caa_color = "#059669" if caa_ok else "#dc2626"
    caa_detail = ", ".join(r.get("value", r.get("text", "")) for r in caa_records[:3]) if caa_records else "No CAA records"
    body += f'<tr><td><strong>CAA</strong></td><td style="color:{caa_color};font-weight:600;">{caa_status}</td><td><code>{esc(caa_detail[:100])}</code></td></tr>'

    body += '</table>'

    # SPF Detailed Analysis
    body += '<h2>SPF Analysis</h2>'
    if spf_val and spf_val != "Not configured":
        body += f'<p class="section-intro">SPF record: <code>{esc(spf_val)}</code></p>'
        if "-all" in spf_val:
            body += '<p style="color:#059669;">The SPF record uses a hard fail mechanism, which instructs receiving servers to reject emails from unauthorized senders.</p>'
        elif "~all" in spf_val:
            body += '<p style="color:#d97706;">The SPF record uses a soft fail mechanism. While unauthorized emails are flagged, they may still be delivered. Upgrade to <code>-all</code> for strict enforcement.</p>'
        elif "?all" in spf_val:
            body += '<p style="color:#dc2626;">The SPF record uses a neutral mechanism (?all), providing no meaningful protection. Upgrade to <code>-all</code>.</p>'
    else:
        body += '<p style="color:#dc2626;">No SPF record was detected. This allows any server to send email claiming to be from this domain.</p>'

    # DMARC Detailed Analysis
    body += '<h2>DMARC Analysis</h2>'
    if dmarc_val:
        body += f'<p class="section-intro">DMARC record: <code>{esc(dmarc_val[:200])}</code></p>'
        if "reject" in dmarc_val.lower():
            body += '<p style="color:#059669;">DMARC policy is set to reject, providing maximum protection against domain spoofing.</p>'
        elif "quarantine" in dmarc_val.lower():
            body += '<p style="color:#d97706;">DMARC policy is set to quarantine. Consider upgrading to reject for maximum protection.</p>'
        else:
            body += '<p style="color:#dc2626;">DMARC policy is set to none (monitoring only). This provides no active protection against spoofing.</p>'
    else:
        body += '<p style="color:#dc2626;">No DMARC policy was detected. The domain is unprotected against email spoofing attacks.</p>'

    # CAA Analysis
    body += '<h2>CAA Record Analysis</h2>'
    if caa_records:
        body += '<p style="color:#059669;">CAA records restrict which Certificate Authorities can issue certificates for the domain:</p>'
        body += '<table><tr><th>Flag</th><th>Tag</th><th>Value</th></tr>'
        for r in caa_records:
            body += f'<tr><td>{r.get("flag", "")}</td><td>{esc(r.get("tag", ""))}</td><td><code>{esc(r.get("value", r.get("text", "")))}</code></td></tr>'
        body += '</table>'
    else:
        body += '<p style="color:#dc2626;">No CAA records are configured. Any Certificate Authority can issue certificates for this domain, increasing the risk of unauthorized certificate issuance.</p>'
    body += '</div>'

    # DNS Findings
    if dns_findings:
        body += '<div class="page">'
        body += _findings_section_full(dns_findings, "DNS Security Findings")
        body += '</div>'

    # Recommendations
    body += '<div class="page"><h1>Recommendations</h1><ul class="obs-list">'
    if spf_val == "Not configured":
        body += '<li>Implement SPF record with <code>v=spf1 ... -all</code> to authenticate outbound email.</li>'
    elif "-all" not in spf_val:
        body += '<li>Strengthen SPF enforcement from soft fail to hard fail (<code>-all</code>).</li>'
    if not dmarc_val:
        body += '<li>Implement DMARC policy: <code>v=DMARC1; p=reject; rua=mailto:dmarc@domain</code></li>'
    elif "reject" not in dmarc_val.lower():
        body += '<li>Upgrade DMARC policy to <code>p=reject</code> for maximum spoofing protection.</li>'
    if not caa_records:
        body += '<li>Add CAA records to restrict certificate issuance to authorized CAs only.</li>'
    body += '<li>Enable DNSSEC to protect against DNS cache poisoning and response tampering.</li>'
    body += '<li>Ensure zone transfers are restricted to authorized secondary nameservers only.</li>'
    body += '</ul></div>'

    return _endpoint_doc_wrap("DNS Security Report", client_name, body)


def build_osint_exec_report(data):
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = data.get("findings", [])
    osift_targets = data.get("osift_targets", {})
    dns_data = data.get("osift_dns", {})
    targets = _scope_target_lines(meta, "osint")

    subdomains = osift_targets.get("subdomains", [])
    ips = osift_targets.get("ips", [])
    emails = osift_targets.get("emails", [])
    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in findings)
    total = len(findings)
    crit_high = risk_counts.get("CRITICAL", 0) + risk_counts.get("HIGH", 0)

    spf_val = _find_spf(dns_data)
    dmarc_val = _find_dmarc(dns_data)

    cover = _build_scope_cover(client_name, "Executive Summary — OSINT",
                               meta, "OSINT Reconnaissance", targets, incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Overview</h1>'
    body += f'<p class="section-intro">This executive summary presents the key findings from passive intelligence collection against <strong>{esc(client_name)}</strong>. All data was gathered through publicly available sources without sending traffic to the organization\'s infrastructure.</p>'

    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(subdomains)}</div><div class="stat-label">Subdomains</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(ips)}</div><div class="stat-label">IP Addresses</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(emails)}</div><div class="stat-label">Emails Found</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{total}</div><div class="stat-label">Findings</div></div>'
    body += '</div>'

    # Risk Distribution
    if findings:
        body += '<h2>Risk Distribution</h2>'
        body += _exec_risk_heatmap(risk_counts, total)

    # Key Observations
    body += '<h2>Key Observations</h2><ul class="obs-list">'
    body += f'<li>{len(subdomains)} subdomain{"s" if len(subdomains) != 1 else ""} discovered through passive reconnaissance, defining the public attack surface.</li>'
    if emails:
        body += f'<li>{len(emails)} email address{"es" if len(emails) != 1 else ""} harvested from public sources — potential phishing targets.</li>'
    if spf_val != "Not configured" and "-all" in spf_val and dmarc_val and "reject" in dmarc_val.lower():
        body += '<li>Email authentication (SPF + DMARC) is properly configured with strict enforcement — <strong>strong anti-spoofing posture</strong>.</li>'
    elif spf_val == "Not configured" or not dmarc_val:
        missing = []
        if spf_val == "Not configured":
            missing.append("SPF")
        if not dmarc_val:
            missing.append("DMARC")
        body += f'<li>Missing email authentication records ({", ".join(missing)}) increase the risk of domain spoofing and phishing attacks.</li>'
    else:
        body += '<li>Email authentication records are present but may benefit from stricter enforcement policies.</li>'
    if crit_high > 0:
        body += f'<li><strong>{crit_high} critical/high-severity finding{"s" if crit_high != 1 else ""}</strong> identified requiring attention.</li>'
    body += '</ul>'

    # Strategic Recommendations
    body += '<h2>Strategic Recommendations</h2>'
    body += '<div class="narrative-block"><div class="phase-label">Priority Actions</div><p>'
    body += 'Minimize the organization\'s public digital footprint by removing unnecessary DNS records and subdomains. '
    body += 'Strengthen email authentication with strict SPF (-all) and DMARC (p=reject) policies. '
    if emails:
        body += 'Implement email address obfuscation on public web properties. '
    body += 'Establish continuous monitoring for credential breaches and unauthorized certificate issuance.'
    body += '</p></div></div>'

    return _endpoint_doc_wrap("Executive Summary — OSINT", client_name, body)


# ═══════════════════════════════════════════════════════════════════════
#  INTERNAL SCOPE BUILDERS
# ═══════════════════════════════════════════════════════════════════════

def build_int_vuln_report(data):
    """Internal Vulnerability Assessment — full finding report."""
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)

    findings = _all_internal_findings(data)
    findings.sort(key=risk_sort)
    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in findings)
    total = len(findings)

    cover = _build_scope_cover(client_name, "Internal Vulnerability Assessment", meta, incomplete=incomplete)
    body = cover

    # ── Executive Summary ──
    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
This report presents the findings from an internal penetration test conducted
against {esc(client_name)}'s internal network infrastructure. The assessment
simulates the perspective of a threat actor who has gained initial access to the
internal network — through a compromised workstation, VPN credential, or physical
access — and evaluates the potential for lateral movement, privilege escalation,
and access to sensitive resources.</p>'''

    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{total}</div><div class="stat-label">Total Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#dc2626">{risk_counts.get("CRITICAL", 0)}</div><div class="stat-label">Critical</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#ea580c">{risk_counts.get("HIGH", 0)}</div><div class="stat-label">High</div></div>'
    hosts = data.get("ss3_hosts", [])
    body += f'<div class="stat-card"><div class="stat-number">{len(hosts)}</div><div class="stat-label">Hosts Discovered</div></div>'
    body += '</div>'

    body += _risk_cards_html(risk_counts)

    pie = _build_risk_pie(risk_counts)
    if pie:
        body += '<div class="risk-charts-row">'
        body += f'<div class="risk-chart-col"><h4>Risk Distribution</h4>{pie}</div>'
        body += '</div>'
    body += '</div>'

    # ── Methodology ──
    body += '''<div class="page"><h1>Methodology</h1>
<p class="section-intro">The internal penetration test followed a structured methodology
aligned with the Penetration Testing Execution Standard (PTES):</p>
<table>
    <tr><th>Phase</th><th>Description</th><th>Tooling</th></tr>
    <tr><td><strong>Network Discovery</strong></td>
        <td>Host discovery, port scanning, service enumeration across internal subnets</td>
        <td>Scattershot3, Nmap, Masscan</td></tr>
    <tr><td><strong>Service Enumeration</strong></td>
        <td>Detailed service fingerprinting, version detection, banner grabbing</td>
        <td>Scattershot3, Nmap NSE, ssh-audit</td></tr>
    <tr><td><strong>Vulnerability Analysis</strong></td>
        <td>Automated and manual vulnerability identification against discovered services</td>
        <td>Nuclei, Nessus, testssl, sslscan</td></tr>
    <tr><td><strong>AD Enumeration</strong></td>
        <td>Active Directory reconnaissance, Kerberos testing, LDAP enumeration</td>
        <td>kerbrute, ldapsearch, crackmapexec, rpcclient</td></tr>
    <tr><td><strong>SMB / Share Analysis</strong></td>
        <td>SMB enumeration, share discovery, permission analysis</td>
        <td>enum4linux, smbmap, smbclient</td></tr>
    <tr><td><strong>Credential Testing</strong></td>
        <td>Default credential checks, brute-force validation, SNMP community strings</td>
        <td>Hydra, snmpwalk, Responder</td></tr>
    <tr><td><strong>Exploitation</strong></td>
        <td>Controlled exploitation of confirmed vulnerabilities with evidence capture</td>
        <td>Manual, Metasploit, sqlmap</td></tr>
</table></div>'''

    # ── Host Inventory ──
    if hosts:
        body += '<div class="page"><h1>Internal Host Inventory</h1>'
        body += f'<p class="section-intro">{len(hosts)} host(s) discovered during internal network scanning.</p>'
        body += _host_inventory_table(hosts)
        subnet_html = _subnet_analysis(hosts)
        if subnet_html:
            body += '<h2>Subnet Distribution</h2>'
            body += subnet_html
        body += '</div>'

    # ── Detailed Findings ──
    if findings:
        body += '<div class="page"><h1>Detailed Findings</h1>'
        body += f'<p class="section-intro">{total} finding(s) identified during internal testing, '
        body += 'sorted by risk severity. Each finding includes a description, supporting evidence, '
        body += 'and remediation guidance.</p>'
        body += _findings_cards(findings)
        body += '</div>'

    return _endpoint_doc_wrap("Internal Vulnerability Assessment", client_name, body)


def build_int_segment_report(data):
    """Network Segmentation Report — internal segmentation analysis."""
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    hosts = data.get("ss3_hosts", [])
    bastion_f = data.get("bastion_findings", [])
    trawler_f = data.get("trawler_findings", [])
    all_f = _all_internal_findings(data)

    segment_patterns = [
        "segmentation", "vlan", "inter-vlan", "network isolation",
        "firewall rule", "access control list", "acl", "zone boundary",
        "lateral movement", "broadcast domain",
    ]
    segment_findings = _filter_by_title_patterns(all_f, segment_patterns)
    segment_findings.sort(key=risk_sort)

    cover = _build_scope_cover(client_name, "Network Segmentation Report", meta, incomplete=incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
This report evaluates the internal network segmentation posture of {esc(client_name)}'s
environment. Effective network segmentation is a critical defense-in-depth control that
limits lateral movement, contains breaches, and reduces the blast radius of a successful
compromise. This assessment examines VLAN boundaries, inter-zone access controls, firewall
rule effectiveness, and the ability of an attacker on one segment to reach sensitive resources
on another.</p>'''
    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(hosts)}</div><div class="stat-label">Hosts Discovered</div></div>'
    subnets = set()
    for h in hosts:
        ip = h.get("ip", "")
        parts = ip.split(".")
        if len(parts) == 4:
            subnets.add(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")
    body += f'<div class="stat-card"><div class="stat-number">{len(subnets)}</div><div class="stat-label">Subnets Identified</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(bastion_f)}</div><div class="stat-label">Firewall Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(segment_findings)}</div><div class="stat-label">Segmentation Findings</div></div>'
    body += '</div></div>'

    # ── Subnet Distribution ──
    if hosts:
        body += '<div class="page"><h1>Internal Network Topology</h1>'
        body += f'<p class="section-intro">Hosts were discovered across {len(subnets)} subnet(s). '
        body += 'The following table shows the distribution of discovered hosts per subnet.</p>'
        body += _subnet_analysis(hosts)
        body += '</div>'

    # ── Bastion / Firewall Findings ──
    if bastion_f:
        body += '<div class="page"><h1>Firewall &amp; Access Control Findings</h1>'
        body += '<p class="section-intro">Findings from Bastion firewall configuration audit that impact network segmentation.</p>'
        body += _findings_cards(bastion_f)
        body += '</div>'

    # ── Trawler Traffic Analysis ──
    if trawler_f:
        body += '<div class="page"><h1>Traffic Analysis</h1>'
        body += '<p class="section-intro">Findings from Trawler network traffic analysis, including inter-segment communication patterns and protocol distribution.</p>'
        body += _findings_cards(trawler_f)
        body += '</div>'

    # ── Segmentation-Specific Findings ──
    if segment_findings:
        body += '<div class="page"><h1>Segmentation Gap Findings</h1>'
        body += '<p class="section-intro">Findings specifically related to network segmentation weaknesses.</p>'
        body += _findings_cards(segment_findings)
        body += '</div>'

    # ── Recommendations ──
    body += '''<div class="page"><h1>Recommendations</h1>
<p class="section-intro">The following recommendations address the segmentation weaknesses
identified during this assessment:</p>
<table>
    <tr><th>Priority</th><th>Recommendation</th><th>Impact</th></tr>
    <tr><td><span class="badge" style="background:#dc2626">HIGH</span></td>
        <td>Implement micro-segmentation between sensitive asset tiers (databases, domain controllers, management networks)</td>
        <td>Prevents lateral movement from compromised workstations to critical infrastructure</td></tr>
    <tr><td><span class="badge" style="background:#dc2626">HIGH</span></td>
        <td>Deploy and enforce inter-VLAN firewall rules with explicit deny-all default</td>
        <td>Limits attacker ability to traverse network boundaries</td></tr>
    <tr><td><span class="badge" style="background:#ea580c">MEDIUM</span></td>
        <td>Implement network access control (NAC) to prevent unauthorized device connection</td>
        <td>Reduces rogue device and rogue VLAN hop risk</td></tr>
    <tr><td><span class="badge" style="background:#ea580c">MEDIUM</span></td>
        <td>Enable DHCP snooping, dynamic ARP inspection, and IP source guard on access switches</td>
        <td>Mitigates ARP spoofing, DHCP starvation, and IP spoofing attacks</td></tr>
    <tr><td><span class="badge" style="background:#d97706">LOW</span></td>
        <td>Monitor inter-VLAN traffic with IDS/IPS for anomalous lateral movement patterns</td>
        <td>Provides detection capability for segmentation bypass attempts</td></tr>
</table></div>'''

    return _endpoint_doc_wrap("Network Segmentation Report", client_name, body)


def build_int_ad_report(data):
    """Active Directory Security Report — AD-focused findings and analysis."""
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    all_f = _all_internal_findings(data)

    ad_patterns = [
        "kerberos", "kerberoast", "as-rep", "asrep", "ldap", "anonymous bind",
        "null bind", "gpo", "group policy", "ntlm", "relay", "smb signing",
        "password policy", "domain controller", "active directory", "ad cs",
        "certificate authority", "golden ticket", "silver ticket", "dcsync",
        "pass-the-hash", "pass-the-ticket", "overpass-the-hash",
        "unconstrained delegation", "constrained delegation",
        "resource-based constrained delegation", "rbcd", "shadow credentials",
        "admincount", "domain admin", "enterprise admin", "spn",
    ]
    ad_findings = _filter_by_title_patterns(all_f, ad_patterns)
    ad_findings.sort(key=risk_sort)

    deps_ad_tools = ["kerbrute", "ldapsearch", "crackmapexec", "rpcclient",
                     "bloodhound", "responder"]
    deps_findings = []
    for tool in deps_ad_tools:
        deps_findings.extend(_filter_by_tool(all_f, tool))
    deps_unique = []
    seen = set()
    for f in deps_findings:
        key = (f.get("title", ""), f.get("ip", ""), f.get("port", ""))
        if key not in seen:
            seen.add(key)
            deps_unique.append(f)
    deps_unique.sort(key=risk_sort)

    combined = []
    seen_titles = set()
    for f in ad_findings + deps_unique:
        key = (f.get("title", ""), f.get("ip", ""), f.get("port", ""))
        if key not in seen_titles:
            seen_titles.add(key)
            combined.append(f)
    combined.sort(key=risk_sort)

    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in combined)

    # MITRE ATT&CK mapping for AD
    _AD_MITRE = {
        "kerberoast": ("T1558.003", "Credential Access", "Kerberoasting"),
        "as-rep": ("T1558.004", "Credential Access", "AS-REP Roasting"),
        "asrep": ("T1558.004", "Credential Access", "AS-REP Roasting"),
        "golden ticket": ("T1558.001", "Credential Access", "Golden Ticket"),
        "silver ticket": ("T1558.002", "Credential Access", "Silver Ticket"),
        "dcsync": ("T1003.006", "Credential Access", "DCSync"),
        "pass-the-hash": ("T1550.002", "Lateral Movement", "Pass the Hash"),
        "pass-the-ticket": ("T1550.003", "Lateral Movement", "Pass the Ticket"),
        "ntlm relay": ("T1557.001", "Credential Access", "LLMNR/NBT-NS Poisoning"),
        "relay": ("T1557.001", "Credential Access", "LLMNR/NBT-NS Poisoning"),
        "smb signing": ("T1557.001", "Credential Access", "NTLM Relay via SMB"),
        "delegation": ("T1134.001", "Privilege Escalation", "Token Impersonation"),
        "gpo": ("T1484.001", "Defense Evasion", "Group Policy Modification"),
        "group policy": ("T1484.001", "Defense Evasion", "Group Policy Modification"),
        "domain admin": ("T1078.002", "Privilege Escalation", "Domain Accounts"),
        "password policy": ("T1110", "Credential Access", "Brute Force"),
        "ldap": ("T1087.002", "Discovery", "Domain Account Enumeration"),
        "anonymous bind": ("T1087.002", "Discovery", "LDAP Anonymous Bind"),
        "spn": ("T1558.003", "Credential Access", "SPN Enumeration"),
    }

    cover = _build_scope_cover(client_name, "Active Directory Security Report", meta, incomplete=incomplete)
    body = cover

    # ── Exec Summary ──
    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
This report presents Active Directory security findings discovered during the internal
penetration test of {esc(client_name)}'s environment. Active Directory is the backbone
of identity and access management in Windows environments — weaknesses here can enable
an attacker to escalate from a single compromised account to full domain compromise.
Testing covered Kerberos authentication weaknesses, LDAP configuration, group policy
security, credential exposure, trust relationships, and privilege escalation paths.</p>'''
    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(combined)}</div><div class="stat-label">AD Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#dc2626">{risk_counts.get("CRITICAL", 0)}</div><div class="stat-label">Critical</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#ea580c">{risk_counts.get("HIGH", 0)}</div><div class="stat-label">High</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(deps_unique)}</div><div class="stat-label">Deps Enrichment</div></div>'
    body += '</div>'
    body += _risk_cards_html(risk_counts)
    body += '</div>'

    # ── MITRE ATT&CK Mapping ──
    mapped = []
    for f in combined:
        title_l = (f.get("title") or "").lower()
        for pattern, (tech_id, tactic, name) in _AD_MITRE.items():
            if pattern in title_l:
                mapped.append((tech_id, tactic, name, f.get("title", ""), (f.get("risk") or "INFO").upper()))
                break

    if mapped:
        body += '<div class="page"><h1>MITRE ATT&amp;CK Mapping</h1>'
        body += '<p class="section-intro">AD findings mapped to the MITRE ATT&amp;CK framework for threat intelligence correlation.</p>'
        body += '<table><tr><th>Technique ID</th><th>Tactic</th><th>Technique</th><th>Finding</th><th>Risk</th></tr>'
        seen_tech = set()
        for tech_id, tactic, name, title, risk in mapped:
            if tech_id in seen_tech:
                continue
            seen_tech.add(tech_id)
            color = RISK_COLORS.get(risk, "#666")
            body += f'<tr><td><code>{esc(tech_id)}</code></td><td>{esc(tactic)}</td><td>{esc(name)}</td><td style="font-size:8pt">{esc(title)}</td><td><span class="badge" style="background:{color};">{risk}</span></td></tr>'
        body += '</table></div>'

    # ── Deps Enrichment ──
    if deps_unique:
        body += '<div class="page"><h1>Dependency Tool Enrichment</h1>'
        body += '<p class="section-intro">Additional findings from action-item-driven dependency tools (kerbrute, ldapsearch, crackmapexec, rpcclient, Responder) that provide deeper validation of AD weaknesses.</p>'
        body += _findings_cards(deps_unique)
        body += '</div>'

    # ── Detailed AD Findings ──
    if combined:
        body += '<div class="page"><h1>Detailed Findings</h1>'
        body += _findings_cards(combined)
        body += '</div>'

    # ── Recommendations ──
    body += '''<div class="page"><h1>AD Hardening Recommendations</h1>
<p class="section-intro">The following recommendations address the Active Directory
security weaknesses identified during this assessment:</p>
<table>
    <tr><th>Priority</th><th>Recommendation</th><th>Mitigates</th></tr>
    <tr><td><span class="badge" style="background:#dc2626">CRITICAL</span></td>
        <td>Require SMB signing on all domain-joined systems and domain controllers</td>
        <td>NTLM relay attacks, man-in-the-middle</td></tr>
    <tr><td><span class="badge" style="background:#dc2626">CRITICAL</span></td>
        <td>Disable NTLM authentication where possible; enforce Kerberos with AES encryption</td>
        <td>Pass-the-hash, NTLM downgrade, relay</td></tr>
    <tr><td><span class="badge" style="background:#dc2626">CRITICAL</span></td>
        <td>Disable unconstrained Kerberos delegation on all non-DC accounts and systems</td>
        <td>Kerberos delegation abuse, privilege escalation</td></tr>
    <tr><td><span class="badge" style="background:#ea580c">HIGH</span></td>
        <td>Enforce a minimum 14-character password policy with complexity requirements for all domain accounts</td>
        <td>Password spraying, brute force, AS-REP roasting</td></tr>
    <tr><td><span class="badge" style="background:#ea580c">HIGH</span></td>
        <td>Implement tiered administration (Tier 0/1/2) to prevent privilege escalation paths</td>
        <td>Lateral movement, credential theft, domain compromise</td></tr>
    <tr><td><span class="badge" style="background:#ea580c">HIGH</span></td>
        <td>Remove unnecessary SPNs from service accounts; use Group Managed Service Accounts (gMSA)</td>
        <td>Kerberoasting</td></tr>
    <tr><td><span class="badge" style="background:#d97706">MEDIUM</span></td>
        <td>Disable anonymous LDAP binds and restrict LDAP queries to authenticated principals</td>
        <td>AD enumeration, information disclosure</td></tr>
    <tr><td><span class="badge" style="background:#d97706">MEDIUM</span></td>
        <td>Enable LDAP signing and channel binding on all domain controllers</td>
        <td>LDAP relay, man-in-the-middle</td></tr>
</table></div>'''

    return _endpoint_doc_wrap("Active Directory Security Report", client_name, body)


def build_int_smb_report(data):
    """SMB & File Share Report — SMB-specific findings and share analysis."""
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    all_f = _all_internal_findings(data)

    smb_patterns = [
        "smb", "smbv1", "null session", "eternalblue", "ms17-010",
        "share", "netbios", "file share", "cifs", "smb signing",
        "anonymous access", "writable share", "readable share",
        "ipc$", "admin$", "c$", "smbmap", "smbclient",
    ]
    smb_findings = _filter_by_title_patterns(all_f, smb_patterns)
    smb_findings.sort(key=risk_sort)

    smb_tools = ["enum4linux", "smbmap", "smbclient", "crackmapexec"]
    deps_findings = []
    for tool in smb_tools:
        deps_findings.extend(_filter_by_tool(all_f, tool))
    deps_unique = []
    seen = set()
    for f in deps_findings:
        key = (f.get("title", ""), f.get("ip", ""), f.get("port", ""))
        if key not in seen:
            seen.add(key)
            deps_unique.append(f)
    deps_unique.sort(key=risk_sort)

    combined = []
    seen_titles = set()
    for f in smb_findings + deps_unique:
        key = (f.get("title", ""), f.get("ip", ""), f.get("port", ""))
        if key not in seen_titles:
            seen_titles.add(key)
            combined.append(f)
    combined.sort(key=risk_sort)

    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in combined)
    signing_findings = _filter_by_title_patterns(combined, ["smb signing", "message signing"])
    null_session_findings = _filter_by_title_patterns(combined, ["null session", "anonymous"])

    cover = _build_scope_cover(client_name, "SMB & File Share Report", meta, incomplete=incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
This report details SMB (Server Message Block) and file share security findings
across {esc(client_name)}'s internal network. SMB is a critical file-sharing protocol
in Windows environments and a primary target for attackers seeking lateral movement
and data exfiltration. This assessment covers SMB version security, signing configuration,
share enumeration, permission analysis, and null session access.</p>'''
    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(combined)}</div><div class="stat-label">SMB Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#dc2626">{risk_counts.get("CRITICAL", 0) + risk_counts.get("HIGH", 0)}</div><div class="stat-label">Critical/High</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(signing_findings)}</div><div class="stat-label">Signing Issues</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(null_session_findings)}</div><div class="stat-label">Null Sessions</div></div>'
    body += '</div>'
    body += _risk_cards_html(risk_counts)
    body += '</div>'

    # ── SMB Signing Analysis ──
    if signing_findings:
        body += '<div class="page"><h1>SMB Signing Analysis</h1>'
        body += '''<p class="section-intro">SMB signing ensures the integrity of SMB
communication by cryptographically signing each message. When SMB signing is not
required, attackers can perform NTLM relay attacks to impersonate users and gain
unauthorized access to network resources.</p>'''
        body += _findings_cards(signing_findings)
        body += '</div>'

    # ── Null Session / Anonymous Access ──
    if null_session_findings:
        body += '<div class="page"><h1>Null Session &amp; Anonymous Access</h1>'
        body += '''<p class="section-intro">Null sessions allow unauthenticated connections
to SMB shares and the IPC$ pipe, enabling attackers to enumerate users, groups, shares,
and domain information without any credentials.</p>'''
        body += _findings_cards(null_session_findings)
        body += '</div>'

    # ── Deps Enrichment ──
    if deps_unique:
        body += '<div class="page"><h1>Share Enumeration Results</h1>'
        body += '<p class="section-intro">Detailed share enumeration from dependency tools (enum4linux, smbmap, smbclient, crackmapexec).</p>'
        body += _findings_cards(deps_unique)
        body += '</div>'

    # ── All SMB Findings ──
    remaining = [f for f in combined
                 if f not in signing_findings and f not in null_session_findings and f not in deps_unique]
    if remaining:
        body += '<div class="page"><h1>Additional SMB Findings</h1>'
        body += _findings_cards(remaining)
        body += '</div>'

    # ── Recommendations ──
    body += '''<div class="page"><h1>SMB Hardening Recommendations</h1>
<table>
    <tr><th>Priority</th><th>Recommendation</th><th>Mitigates</th></tr>
    <tr><td><span class="badge" style="background:#dc2626">CRITICAL</span></td>
        <td>Disable SMBv1 on all systems (server and client components)</td>
        <td>EternalBlue (MS17-010), SMBv1 protocol weaknesses</td></tr>
    <tr><td><span class="badge" style="background:#dc2626">CRITICAL</span></td>
        <td>Require SMB signing on all systems via Group Policy</td>
        <td>NTLM relay attacks, man-in-the-middle</td></tr>
    <tr><td><span class="badge" style="background:#ea580c">HIGH</span></td>
        <td>Restrict null session access by setting RestrictAnonymous=1 and RestrictAnonymousSAM=1</td>
        <td>Unauthenticated enumeration, information disclosure</td></tr>
    <tr><td><span class="badge" style="background:#ea580c">HIGH</span></td>
        <td>Review and restrict share permissions — remove Everyone and Authenticated Users from sensitive shares</td>
        <td>Data exposure, unauthorized access</td></tr>
    <tr><td><span class="badge" style="background:#d97706">MEDIUM</span></td>
        <td>Enable SMB encryption (SMBv3) for sensitive file shares</td>
        <td>Network sniffing, credential interception</td></tr>
    <tr><td><span class="badge" style="background:#d97706">MEDIUM</span></td>
        <td>Audit administrative shares (C$, ADMIN$, IPC$) and disable where not operationally required</td>
        <td>Lateral movement via administrative shares</td></tr>
</table></div>'''

    return _endpoint_doc_wrap("SMB & File Share Report", client_name, body)


def build_int_exec_report(data):
    """Executive Summary — Internal (single-page overview)."""
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = _all_internal_findings(data)
    findings.sort(key=risk_sort)
    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in findings)
    hosts = data.get("ss3_hosts", [])
    top = _top_findings(findings, 5)

    cover = _build_scope_cover(client_name, "Executive Summary — Internal Penetration Test", meta, incomplete=incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
{esc(client_name)} engaged the assessor to perform an internal penetration test of its
network infrastructure. This executive summary provides a high-level overview of the
assessment results for leadership and stakeholders.</p>'''

    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(findings)}</div><div class="stat-label">Total Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#dc2626">{risk_counts.get("CRITICAL", 0)}</div><div class="stat-label">Critical</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#ea580c">{risk_counts.get("HIGH", 0)}</div><div class="stat-label">High</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(hosts)}</div><div class="stat-label">Hosts</div></div>'
    body += '</div>'

    body += _risk_cards_html(risk_counts)

    pie = _build_risk_pie(risk_counts)
    if pie:
        body += '<div class="risk-charts-row">'
        body += f'<div class="risk-chart-col"><h4>Risk Distribution</h4>{pie}</div>'
        body += '</div>'

    if top:
        body += '<h2>Top Findings</h2>'
        body += '<table><tr><th>Risk</th><th>Finding</th><th>Target</th></tr>'
        for f in top:
            risk = (f.get("risk") or "INFO").upper()
            color = RISK_COLORS.get(risk, "#666")
            ip = esc(f.get("ip", ""))
            port = f.get("port", "")
            target = f"{ip}:{port}" if ip and port else ip
            body += f'<tr><td><span class="badge" style="background:{color};">{risk}</span></td><td>{esc(f.get("title", ""))}</td><td><code>{target}</code></td></tr>'
        body += '</table>'

    body += '<h2>Key Recommendations</h2>'
    body += '''<ol style="font-size:9pt;line-height:1.7;padding-left:18px;">
<li>Remediate all Critical and High findings within 30 days</li>
<li>Enforce SMB signing and disable SMBv1 across the entire domain</li>
<li>Implement network segmentation to limit lateral movement</li>
<li>Harden Active Directory configuration (Kerberos, LDAP signing, password policy)</li>
<li>Establish a vulnerability management program with quarterly internal scanning</li>
</ol>'''
    body += '</div>'

    return _endpoint_doc_wrap("Executive Summary — Internal", client_name, body)


# ═══════════════════════════════════════════════════════════════════════
#  WIRELESS SCOPE BUILDERS
# ═══════════════════════════════════════════════════════════════════════

def build_wire_assess_report(data):
    """Full Wireless Security Assessment — all protocols combined."""
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = _all_wireless_findings(data)
    findings.sort(key=risk_sort)
    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in findings)

    wifi_f = data.get("aether_findings", [])
    ble_f = data.get("aether_b_findings", [])
    zigbee_f = data.get("aether_z_findings", [])
    uwb_f = data.get("aether_u_findings", [])

    ssids = set()
    for f in wifi_f:
        ssid = f.get("ssid") or ""
        if not ssid:
            title = f.get("title", "")
            if "ssid" in title.lower():
                parts = title.split(":")
                if len(parts) > 1:
                    ssid = parts[-1].strip().strip('"').strip("'")
        if ssid:
            ssids.add(ssid)

    enc_types = set()
    for f in wifi_f:
        for enc in ("WPA3", "WPA2", "WPA", "WEP", "Open", "OWE"):
            if enc.lower() in (f.get("title", "") + " " + f.get("description", "")).lower():
                enc_types.add(enc)

    cover = _build_scope_cover(client_name, "Wireless Security Assessment", meta, incomplete=incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
This report presents the complete wireless security assessment of {esc(client_name)}'s
environment, covering Wi-Fi (IEEE 802.11), Bluetooth Low Energy (BLE), Zigbee (IEEE 802.15.4),
and Ultra-Wideband (UWB) protocols. Testing was conducted using the Aether family of wireless
security tools with dedicated hardware interfaces for each protocol.</p>'''
    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(findings)}</div><div class="stat-label">Total Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(ssids)}</div><div class="stat-label">SSIDs Detected</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(enc_types)}</div><div class="stat-label">Encryption Types</div></div>'
    protocols_active = sum(1 for x in [wifi_f, ble_f, zigbee_f, uwb_f] if x)
    body += f'<div class="stat-card"><div class="stat-number">{protocols_active}</div><div class="stat-label">Protocols Tested</div></div>'
    body += '</div>'
    body += _risk_cards_html(risk_counts)

    pie = _build_risk_pie(risk_counts)
    if pie:
        body += '<div class="risk-charts-row">'
        body += f'<div class="risk-chart-col"><h4>Risk Distribution</h4>{pie}</div>'
        body += '</div>'
    body += '</div>'

    # ── Wi-Fi Section ──
    if wifi_f:
        sorted_wifi = sorted(wifi_f, key=risk_sort)
        body += '<div class="page"><h1>Wi-Fi (IEEE 802.11) Findings</h1>'
        body += f'<p class="section-intro">{len(wifi_f)} finding(s) from Wi-Fi security analysis via Aether.</p>'
        if ssids:
            body += '<h2>SSID Inventory</h2>'
            body += '<table><tr><th>SSID</th></tr>'
            for ssid in sorted(ssids):
                body += f'<tr><td>{esc(ssid)}</td></tr>'
            body += '</table>'
        body += '<h2>Findings</h2>'
        body += _findings_cards(sorted_wifi)
        body += '</div>'

    # ── Bluetooth Section ──
    if ble_f:
        sorted_ble = sorted(ble_f, key=risk_sort)
        body += '<div class="page"><h1>Bluetooth (BLE) Findings</h1>'
        body += f'<p class="section-intro">{len(ble_f)} finding(s) from Bluetooth security analysis via Aether-B.</p>'
        body += _findings_cards(sorted_ble)
        body += '</div>'

    # ── Zigbee Section ──
    if zigbee_f:
        sorted_zigbee = sorted(zigbee_f, key=risk_sort)
        body += '<div class="page"><h1>Zigbee (IEEE 802.15.4) Findings</h1>'
        body += f'<p class="section-intro">{len(zigbee_f)} finding(s) from Zigbee protocol analysis via Aether-Z.</p>'
        body += _findings_cards(sorted_zigbee)
        body += '</div>'

    # ── UWB Section ──
    if uwb_f:
        sorted_uwb = sorted(uwb_f, key=risk_sort)
        body += '<div class="page"><h1>Ultra-Wideband (UWB) Findings</h1>'
        body += f'<p class="section-intro">{len(uwb_f)} finding(s) from UWB security analysis via Aether-U.</p>'
        body += _findings_cards(sorted_uwb)
        body += '</div>'

    return _endpoint_doc_wrap("Wireless Security Assessment", client_name, body)


def build_wire_wifi_report(data):
    """Wi-Fi Configuration Report — Wi-Fi-specific configuration analysis."""
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    wifi_f = sorted(data.get("aether_findings", []), key=risk_sort)
    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in wifi_f)

    ssids = set()
    ssid_details = {}
    for f in wifi_f:
        ssid = f.get("ssid") or ""
        if not ssid:
            title = f.get("title", "")
            if "ssid" in title.lower():
                parts = title.split(":")
                if len(parts) > 1:
                    ssid = parts[-1].strip().strip('"').strip("'")
        if ssid:
            ssids.add(ssid)
            if ssid not in ssid_details:
                ssid_details[ssid] = {"findings": [], "bssid": f.get("bssid", "")}
            ssid_details[ssid]["findings"].append(f)

    enc_patterns = {
        "WPA3": ["wpa3", "sae"],
        "WPA2": ["wpa2", "wpa2-psk", "wpa2-enterprise"],
        "WPA": ["wpa ", "wpa-psk", "tkip"],
        "WEP": ["wep"],
        "Open": ["open network", "unencrypted", "no encryption"],
    }
    enc_found = {}
    for enc, patterns in enc_patterns.items():
        for f in wifi_f:
            text = (f.get("title", "") + " " + f.get("description", "")).lower()
            if any(p in text for p in patterns):
                enc_found[enc] = enc_found.get(enc, 0) + 1

    isolation_findings = _filter_by_title_patterns(wifi_f, [
        "client isolation", "guest", "ap isolation", "private vlan",
        "station isolation",
    ])
    config_findings = _filter_by_title_patterns(wifi_f, [
        "firmware", "management", "wps", "admin", "default password",
        "configuration", "web interface",
    ])

    cover = _build_scope_cover(client_name, "Wi-Fi Configuration Report", meta, incomplete=incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
This report evaluates the Wi-Fi configuration and security posture of {esc(client_name)}'s
wireless infrastructure. The assessment covers SSID inventory, encryption standards,
guest network isolation, access point configuration, and client isolation controls.</p>'''
    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(wifi_f)}</div><div class="stat-label">Wi-Fi Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(ssids)}</div><div class="stat-label">SSIDs Detected</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(enc_found)}</div><div class="stat-label">Encryption Types</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#dc2626">{risk_counts.get("CRITICAL", 0) + risk_counts.get("HIGH", 0)}</div><div class="stat-label">Critical/High</div></div>'
    body += '</div>'
    body += _risk_cards_html(risk_counts)
    body += '</div>'

    # ── SSID Inventory ──
    if ssid_details:
        body += '<div class="page"><h1>SSID Inventory</h1>'
        body += f'<p class="section-intro">{len(ssids)} SSID(s) detected during wireless scanning.</p>'
        body += '<table><tr><th>SSID</th><th>BSSID</th><th>Findings</th><th>Highest Risk</th></tr>'
        for ssid in sorted(ssid_details.keys()):
            det = ssid_details[ssid]
            f_list = det["findings"]
            worst = "INFO"
            for f in f_list:
                r = (f.get("risk") or "INFO").upper()
                if RISK_ORDER.get(r, 5) < RISK_ORDER.get(worst, 5):
                    worst = r
            color = RISK_COLORS.get(worst, "#666")
            body += f'<tr><td><strong>{esc(ssid)}</strong></td><td><code>{esc(det["bssid"])}</code></td><td style="text-align:center">{len(f_list)}</td><td><span class="badge" style="background:{color};">{worst}</span></td></tr>'
        body += '</table></div>'

    # ── Encryption Analysis ──
    if enc_found:
        body += '<div class="page"><h1>Encryption Analysis</h1>'
        body += '<p class="section-intro">Encryption standards detected across the wireless environment.</p>'
        body += '<table><tr><th>Standard</th><th>Occurrences</th><th>Assessment</th></tr>'
        enc_assess = {
            "WPA3": ("Recommended — strongest available standard", "#059669"),
            "WPA2": ("Acceptable — ensure AES-CCMP, not TKIP", "#d97706"),
            "WPA": ("Deprecated — vulnerable to TKIP attacks", "#ea580c"),
            "WEP": ("Critical — trivially crackable, must be removed", "#dc2626"),
            "Open": ("Critical — no encryption, all traffic visible", "#dc2626"),
        }
        for enc, count in enc_found.items():
            assess_text, assess_color = enc_assess.get(enc, ("Unknown", "#666"))
            body += f'<tr><td><strong>{esc(enc)}</strong></td><td style="text-align:center">{count}</td><td style="color:{assess_color};font-weight:600">{assess_text}</td></tr>'
        body += '</table></div>'

    # ── Client Isolation ──
    if isolation_findings:
        body += '<div class="page"><h1>Client Isolation &amp; Guest Network</h1>'
        body += '<p class="section-intro">Findings related to client isolation and guest network segmentation.</p>'
        body += _findings_cards(isolation_findings)
        body += '</div>'

    # ── AP Configuration ──
    if config_findings:
        body += '<div class="page"><h1>Access Point Configuration</h1>'
        body += '<p class="section-intro">Findings related to access point firmware, management interfaces, and configuration weaknesses.</p>'
        body += _findings_cards(config_findings)
        body += '</div>'

    # ── All Findings ──
    remaining = [f for f in wifi_f
                 if f not in isolation_findings and f not in config_findings]
    if remaining:
        body += '<div class="page"><h1>Additional Wi-Fi Findings</h1>'
        body += _findings_cards(remaining)
        body += '</div>'

    return _endpoint_doc_wrap("Wi-Fi Configuration Report", client_name, body)


def build_wire_rogue_report(data):
    """Rogue Access Point Report — unauthorized AP detection analysis."""
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    wifi_f = data.get("aether_findings", [])

    rogue_patterns = [
        "rogue", "unauthorized", "evil twin", "deauth", "deauthentication",
        "karma", "fake ap", "unknown ap", "unmanaged", "unregistered",
        "spoofed", "impersonation",
    ]
    rogue_findings = _filter_by_title_patterns(wifi_f, rogue_patterns)
    rogue_findings.sort(key=risk_sort)

    deauth_findings = _filter_by_title_patterns(wifi_f, ["deauth", "disassoc"])
    all_rogues = list({id(f): f for f in rogue_findings + deauth_findings}.values())
    all_rogues.sort(key=risk_sort)

    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in all_rogues)

    cover = _build_scope_cover(client_name, "Rogue Access Point Report", meta, incomplete=incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
This report details the rogue access point analysis conducted during the wireless
assessment of {esc(client_name)}'s environment. Rogue access points — whether malicious
(evil twin) or unintentional (employee hotspots, unconfigured APs) — pose a significant
risk by bypassing network security controls and providing unauthorized entry points into
the corporate network. This assessment evaluates the presence of unauthorized APs,
susceptibility to evil twin attacks, and the effectiveness of wireless intrusion detection
systems (WIDS/WIPS).</p>'''
    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(all_rogues)}</div><div class="stat-label">Rogue/Deauth Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#dc2626">{risk_counts.get("CRITICAL", 0) + risk_counts.get("HIGH", 0)}</div><div class="stat-label">Critical/High</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(rogue_findings)}</div><div class="stat-label">Rogue APs</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(deauth_findings)}</div><div class="stat-label">Deauth Issues</div></div>'
    body += '</div>'
    body += _risk_cards_html(risk_counts)
    body += '</div>'

    if all_rogues:
        body += '<div class="page"><h1>Detailed Findings</h1>'
        body += _findings_cards(all_rogues)
        body += '</div>'

    # ── WIDS/WIPS Assessment ──
    body += '''<div class="page"><h1>WIDS/WIPS Gap Analysis</h1>
<p class="section-intro">A Wireless Intrusion Detection/Prevention System (WIDS/WIPS) is
essential for detecting and responding to rogue access points in real time.</p>
<table>
    <tr><th>Control</th><th>Expected</th><th>Assessment</th></tr>
    <tr><td>Rogue AP Detection</td><td>WIDS actively monitors for unauthorized access points</td>
        <td>Evaluate whether rogue APs detected during testing were also flagged by existing WIDS</td></tr>
    <tr><td>Evil Twin Detection</td><td>WIDS detects SSID impersonation attempts</td>
        <td>Test whether WIDS alerts on AP broadcasting legitimate corporate SSIDs from unauthorized hardware</td></tr>
    <tr><td>Deauthentication Detection</td><td>WIDS detects deauthentication flood attacks</td>
        <td>Evaluate whether deauth frames trigger WIDS alerts</td></tr>
    <tr><td>Automated Containment</td><td>WIPS automatically contains detected rogue APs</td>
        <td>Assess whether WIPS can auto-contain via counter-deauth or VLAN quarantine</td></tr>
    <tr><td>Alerting &amp; Response</td><td>Security team receives real-time alerts for rogue activity</td>
        <td>Verify alert integration with SIEM/SOC</td></tr>
</table></div>'''

    # ── Recommendations ──
    body += '''<div class="page"><h1>Recommendations</h1>
<table>
    <tr><th>Priority</th><th>Recommendation</th></tr>
    <tr><td><span class="badge" style="background:#dc2626">HIGH</span></td>
        <td>Deploy a WIDS/WIPS solution with rogue AP detection, evil twin identification, and automated containment</td></tr>
    <tr><td><span class="badge" style="background:#dc2626">HIGH</span></td>
        <td>Enable 802.11w (Management Frame Protection) on all enterprise SSIDs to prevent deauthentication attacks</td></tr>
    <tr><td><span class="badge" style="background:#ea580c">MEDIUM</span></td>
        <td>Conduct regular wireless sweeps of all physical locations to identify unauthorized APs and personal hotspots</td></tr>
    <tr><td><span class="badge" style="background:#ea580c">MEDIUM</span></td>
        <td>Implement NAC (802.1X) on wired switch ports in common areas to prevent rogue AP connectivity</td></tr>
    <tr><td><span class="badge" style="background:#d97706">LOW</span></td>
        <td>Establish a wireless security policy prohibiting personal hotspots and unauthorized APs on corporate premises</td></tr>
</table></div>'''

    return _endpoint_doc_wrap("Rogue Access Point Report", client_name, body)


def build_wire_ble_report(data):
    """Bluetooth / IoT Protocol Report — BLE, Zigbee, UWB findings."""
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    ble_f = sorted(data.get("aether_b_findings", []), key=risk_sort)
    zigbee_f = sorted(data.get("aether_z_findings", []), key=risk_sort)
    uwb_f = sorted(data.get("aether_u_findings", []), key=risk_sort)
    all_f = ble_f + zigbee_f + uwb_f
    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in all_f)

    cover = _build_scope_cover(client_name, "Bluetooth / IoT Protocol Report", meta, incomplete=incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
This report presents findings from non-Wi-Fi wireless protocol testing across
{esc(client_name)}'s environment, covering Bluetooth Low Energy (BLE), Zigbee
(IEEE 802.15.4), and Ultra-Wideband (UWB). These protocols are increasingly used
in IoT devices, building automation, access control, and asset tracking systems.
Security weaknesses in these protocols can enable device impersonation, data
interception, and unauthorized access to connected systems.</p>'''
    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(all_f)}</div><div class="stat-label">Total Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(ble_f)}</div><div class="stat-label">Bluetooth</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(zigbee_f)}</div><div class="stat-label">Zigbee</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(uwb_f)}</div><div class="stat-label">UWB</div></div>'
    body += '</div>'
    body += _risk_cards_html(risk_counts)
    body += '</div>'

    # ── Bluetooth Section ──
    if ble_f:
        body += '<div class="page"><h1>Bluetooth Low Energy (BLE)</h1>'
        body += f'''<p class="section-intro">{len(ble_f)} finding(s) from Bluetooth security
analysis via Aether-B. BLE is widely used in medical devices, access control badges,
fitness trackers, and IoT sensors. Testing covers device enumeration, pairing security,
GATT service exposure, and data interception.</p>'''
        body += _findings_cards(ble_f)
        body += '</div>'

    # ── Zigbee Section ──
    if zigbee_f:
        body += '<div class="page"><h1>Zigbee (IEEE 802.15.4)</h1>'
        body += f'''<p class="section-intro">{len(zigbee_f)} finding(s) from Zigbee protocol
analysis via Aether-Z. Zigbee is used in building automation, smart lighting, HVAC
controls, and industrial sensors. Testing covers network key extraction, replay attacks,
and device impersonation.</p>'''
        body += _findings_cards(zigbee_f)
        body += '</div>'

    # ── UWB Section ──
    if uwb_f:
        body += '<div class="page"><h1>Ultra-Wideband (UWB)</h1>'
        body += f'''<p class="section-intro">{len(uwb_f)} finding(s) from UWB security
analysis via Aether-U. UWB is used for precise ranging and positioning in access control,
asset tracking, and automotive keyless entry. Testing covers relay attacks, distance
manipulation, and protocol-level weaknesses.</p>'''
        body += _findings_cards(uwb_f)
        body += '</div>'

    if not all_f:
        body += '<div class="page"><h1>Assessment Results</h1>'
        body += '<p class="section-intro">No BLE, Zigbee, or UWB findings were identified during this assessment. This may indicate that these protocols are not in use within the tested environment, or that the protocols in use are properly secured.</p>'
        body += '</div>'

    return _endpoint_doc_wrap("Bluetooth / IoT Protocol Report", client_name, body)


def build_wire_exec_report(data):
    """Executive Summary — Wireless (single-page overview)."""
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = _all_wireless_findings(data)
    findings.sort(key=risk_sort)
    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in findings)
    top = _top_findings(findings, 5)

    protocols_tested = []
    if data.get("aether_findings"):
        protocols_tested.append("Wi-Fi")
    if data.get("aether_b_findings"):
        protocols_tested.append("Bluetooth")
    if data.get("aether_z_findings"):
        protocols_tested.append("Zigbee")
    if data.get("aether_u_findings"):
        protocols_tested.append("UWB")

    cover = _build_scope_cover(client_name, "Executive Summary — Wireless Assessment", meta, incomplete=incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
{esc(client_name)} engaged the assessor to perform a wireless security assessment of
its environment. This executive summary provides a high-level overview of the
assessment results for leadership and stakeholders. Testing covered
{", ".join(protocols_tested) if protocols_tested else "wireless"} protocol(s).</p>'''

    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(findings)}</div><div class="stat-label">Total Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#dc2626">{risk_counts.get("CRITICAL", 0)}</div><div class="stat-label">Critical</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#ea580c">{risk_counts.get("HIGH", 0)}</div><div class="stat-label">High</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(protocols_tested)}</div><div class="stat-label">Protocols</div></div>'
    body += '</div>'
    body += _risk_cards_html(risk_counts)

    pie = _build_risk_pie(risk_counts)
    if pie:
        body += '<div class="risk-charts-row">'
        body += f'<div class="risk-chart-col"><h4>Risk Distribution</h4>{pie}</div>'
        body += '</div>'

    if top:
        body += '<h2>Top Findings</h2>'
        body += '<table><tr><th>Risk</th><th>Finding</th><th>Protocol</th></tr>'
        for f in top:
            risk = (f.get("risk") or "INFO").upper()
            color = RISK_COLORS.get(risk, "#666")
            tool = (f.get("tool") or "").lower()
            proto = "Wi-Fi"
            if "aether_b" in tool or "bluetooth" in tool:
                proto = "Bluetooth"
            elif "aether_z" in tool or "zigbee" in tool:
                proto = "Zigbee"
            elif "aether_u" in tool or "uwb" in tool:
                proto = "UWB"
            body += f'<tr><td><span class="badge" style="background:{color};">{risk}</span></td><td>{esc(f.get("title", ""))}</td><td>{proto}</td></tr>'
        body += '</table>'

    body += '<h2>Key Recommendations</h2>'
    body += '''<ol style="font-size:9pt;line-height:1.7;padding-left:18px;">
<li>Remediate all Critical and High wireless findings within 30 days</li>
<li>Upgrade all SSIDs to WPA3-Enterprise or WPA2-Enterprise with AES-CCMP minimum</li>
<li>Deploy WIDS/WIPS with rogue AP detection and automated containment</li>
<li>Enable 802.11w (Management Frame Protection) on all enterprise SSIDs</li>
<li>Inventory all IoT devices using BLE, Zigbee, and UWB and ensure firmware is current</li>
</ol>'''
    body += '</div>'

    return _endpoint_doc_wrap("Executive Summary — Wireless", client_name, body)


# ═══════════════════════════════════════════════════════════════════════
#  WEB SCOPE BUILDERS
# ═══════════════════════════════════════════════════════════════════════

def build_web_vuln_report(data):
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = sorted(data.get("findings", []), key=risk_sort)
    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in findings)
    total = len(findings)
    targets = _scope_target_lines(meta, "web")

    cover = _build_scope_cover(client_name, "Web Application Vulnerability Report",
                               meta, "Web Application", targets, incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
This report presents the findings from a web application penetration test conducted
against {esc(client_name)}'s web applications. The assessment identifies vulnerabilities
across the OWASP Top 10:2021 categories, evaluates input validation, authentication
mechanisms, session management, and server configuration security.</p>'''

    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{total}</div><div class="stat-label">Total Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#dc2626">{risk_counts.get("CRITICAL", 0)}</div><div class="stat-label">Critical</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#ea580c">{risk_counts.get("HIGH", 0)}</div><div class="stat-label">High</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#d97706">{risk_counts.get("MEDIUM", 0)}</div><div class="stat-label">Medium</div></div>'
    body += '</div>'
    body += _risk_cards_html(risk_counts)

    pie = _build_risk_pie(risk_counts)
    if pie:
        body += '<div class="risk-charts-row">'
        body += f'<div class="risk-chart-col"><h4>Risk Distribution</h4>{pie}</div>'
        body += '</div>'
    body += '</div>'

    body += '''<div class="page"><h1>Methodology</h1>
<p class="section-intro">The web application assessment followed OWASP Testing Guide v4.2
methodology and the Penetration Testing Execution Standard (PTES):</p>
<table>
    <tr><th>Phase</th><th>Description</th><th>Tooling</th></tr>
    <tr><td><strong>Reconnaissance</strong></td>
        <td>Technology fingerprinting, CMS detection, JavaScript library enumeration</td>
        <td>Fracture, whatweb, Wappalyzer, webanalyze</td></tr>
    <tr><td><strong>Content Discovery</strong></td>
        <td>Hidden directories, backup files, admin panels, API endpoints</td>
        <td>Fracture (gobuster/ffuf), Nuclei</td></tr>
    <tr><td><strong>Vulnerability Scanning</strong></td>
        <td>Automated vulnerability identification across OWASP categories</td>
        <td>Nuclei, Nikto, Fracture</td></tr>
    <tr><td><strong>Authentication Testing</strong></td>
        <td>Login mechanisms, session tokens, password policy, MFA bypass</td>
        <td>Fracture, Hydra, manual</td></tr>
    <tr><td><strong>Injection Testing</strong></td>
        <td>SQL injection, XSS, SSTI, command injection, LDAP injection</td>
        <td>sqlmap, Fracture, manual</td></tr>
    <tr><td><strong>TLS/SSL Analysis</strong></td>
        <td>Certificate validation, cipher suite analysis, protocol support</td>
        <td>testssl.sh, sslscan, shcheck</td></tr>
    <tr><td><strong>Manual Exploitation</strong></td>
        <td>Controlled exploitation with evidence capture</td>
        <td>Manual, Burp Suite, curl</td></tr>
</table></div>'''

    if findings:
        body += '<div class="page"><h1>Detailed Findings</h1>'
        body += f'<p class="section-intro">{total} vulnerability(ies) identified, sorted by risk severity.</p>'
        body += _findings_section_full(findings)
        body += _remediation_summary(findings)
        body += '</div>'

    return _endpoint_doc_wrap("Web Application Vulnerability Report", client_name, body)


def build_web_owasp_report(data):
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = sorted(data.get("findings", []), key=risk_sort)
    targets = _scope_target_lines(meta, "web")

    categorized = defaultdict(list)
    uncategorized = []
    for f in findings:
        cat = _classify_owasp_web(f)
        if cat:
            categorized[cat].append(f)
        else:
            uncategorized.append(f)

    cover = _build_scope_cover(client_name, "OWASP Top 10 Assessment",
                               meta, "Web Application", targets, incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
This report maps findings from the web application penetration test of
{esc(client_name)}'s applications against the OWASP Top 10:2021 framework.
Each category is assessed for presence, severity, and coverage to identify
both confirmed vulnerabilities and testing gaps.</p>'''

    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(findings)}</div><div class="stat-label">Total Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(categorized)}/10</div><div class="stat-label">Categories Hit</div></div>'
    cats_with_crit = sum(1 for cat_f in categorized.values()
                        if any((f.get("risk") or "").upper() in ("CRITICAL", "HIGH") for f in cat_f))
    body += f'<div class="stat-card"><div class="stat-number" style="color:#dc2626">{cats_with_crit}</div><div class="stat-label">Critical/High Cats</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{10 - len(categorized)}</div><div class="stat-label">No Findings</div></div>'
    body += '</div>'

    body += '<h2>Coverage Matrix</h2>'
    body += '<table><tr><th>OWASP Category</th><th>Findings</th><th>Highest Risk</th><th>Status</th></tr>'
    for code in sorted(_OWASP_WEB_2021.keys()):
        cat_findings = categorized.get(code, [])
        count = len(cat_findings)
        if count:
            worst = "INFO"
            for f in cat_findings:
                r = (f.get("risk") or "INFO").upper()
                if RISK_ORDER.get(r, 5) < RISK_ORDER.get(worst, 5):
                    worst = r
            color = RISK_COLORS.get(worst, "#666")
            status = f'<span class="badge" style="background:{color};">{worst}</span>'
        else:
            status = '<span style="color:#059669;font-weight:600;">No findings</span>'
        body += f'<tr><td><strong>{code}:</strong> {esc(_OWASP_WEB_2021[code])}</td><td style="text-align:center">{count}</td><td style="text-align:center">{status}</td><td></td></tr>'
    body += '</table></div>'

    for code in sorted(_OWASP_WEB_2021.keys()):
        cat_findings = categorized.get(code, [])
        if not cat_findings:
            continue
        cat_findings.sort(key=risk_sort)
        risk_counts = Counter((f.get("risk") or "INFO").upper() for f in cat_findings)

        body += f'<div class="page"><h1>{code}: {esc(_OWASP_WEB_2021[code])}</h1>'
        body += _risk_cards_html(risk_counts)
        for idx, f in enumerate(cat_findings, 1):
            body += finding_card(f, idx)
        body += '</div>'

    if uncategorized:
        body += '<div class="page"><h1>Uncategorized Findings</h1>'
        body += '<p class="section-intro">Findings not mapped to an OWASP Top 10 category.</p>'
        for idx, f in enumerate(uncategorized, 1):
            body += finding_card(f, idx)
        body += '</div>'

    return _endpoint_doc_wrap("OWASP Top 10 Assessment", client_name, body)


def build_web_tech_report(data):
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = data.get("findings", [])
    targets = _scope_target_lines(meta, "web")

    tech_patterns = ["technology", "version", "framework", "cms", "wordpress",
                     "drupal", "joomla", "angular", "react", "jquery", "bootstrap",
                     "apache", "nginx", "iis", "tomcat", "php", "asp.net",
                     "node.js", "express", "django", "flask", "spring",
                     "server header", "x-powered-by", "webanalyze", "whatweb",
                     "wappalyzer", "eol", "end of life", "outdated"]
    tech_findings = []
    other_findings = []
    for f in findings:
        text = ((f.get("title") or "") + " " + (f.get("description") or "")).lower()
        if any(p in text for p in tech_patterns):
            tech_findings.append(f)
        else:
            other_findings.append(f)
    tech_findings.sort(key=risk_sort)

    eol_findings = [f for f in tech_findings
                    if any(kw in ((f.get("title") or "") + " " + (f.get("description") or "")).lower()
                           for kw in ("eol", "end of life", "outdated", "unsupported", "deprecated"))]

    cover = _build_scope_cover(client_name, "Web Technology Report",
                               meta, "Web Application", targets, incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
This report catalogs the technologies, frameworks, CMS platforms, and libraries detected
across {esc(client_name)}'s web applications. Technology fingerprinting reveals the attack
surface and identifies outdated or end-of-life components that may contain known
vulnerabilities.</p>'''
    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(tech_findings)}</div><div class="stat-label">Tech Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(eol_findings)}</div><div class="stat-label">EOL / Outdated</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(findings)}</div><div class="stat-label">Total Findings</div></div>'
    body += '</div></div>'

    if eol_findings:
        body += '<div class="page"><h1>End-of-Life &amp; Outdated Components</h1>'
        body += '''<p class="section-intro">Components that have reached end-of-life or are
running outdated versions with known CVEs. These represent an immediate patching priority.</p>'''
        for idx, f in enumerate(eol_findings, 1):
            body += finding_card(f, idx)
        body += '</div>'

    remaining_tech = [f for f in tech_findings if f not in eol_findings]
    if remaining_tech:
        body += '<div class="page"><h1>Technology Fingerprinting Findings</h1>'
        body += '<p class="section-intro">Technologies and frameworks detected during web reconnaissance.</p>'
        for idx, f in enumerate(remaining_tech, 1):
            body += finding_card(f, idx)
        body += '</div>'

    return _endpoint_doc_wrap("Web Technology Report", client_name, body)


def build_web_discovery_report(data):
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = data.get("findings", [])
    targets = _scope_target_lines(meta, "web")

    discovery_patterns = ["directory", "hidden", "backup", "admin panel",
                          "admin interface", "sensitive path", "robots.txt",
                          "sitemap", ".git", ".svn", ".env", "phpinfo",
                          "web.config", "config file", "gobuster", "ffuf",
                          "content discovery", "path traversal", "lfi",
                          "debug endpoint", "status page", "health check",
                          "api documentation", "swagger", "graphql"]
    disc_findings = []
    for f in findings:
        text = ((f.get("title") or "") + " " + (f.get("description") or "")).lower()
        if any(p in text for p in discovery_patterns):
            disc_findings.append(f)
    disc_findings.sort(key=risk_sort)
    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in disc_findings)

    sensitive_patterns = [".env", ".git", "backup", "config", "phpinfo",
                          "web.config", "database", "credential"]
    sensitive_f = [f for f in disc_findings
                   if any(p in ((f.get("title") or "") + " " + (f.get("description") or "")).lower()
                          for p in sensitive_patterns)]

    cover = _build_scope_cover(client_name, "Content Discovery Report",
                               meta, "Web Application", targets, incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
This report details the results of content discovery and hidden path enumeration
against {esc(client_name)}'s web applications. Content discovery reveals resources
not linked from the application's normal navigation — including backup files, admin
interfaces, configuration files, and debug endpoints — that may expose sensitive data
or provide an attacker with additional entry points.</p>'''
    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(disc_findings)}</div><div class="stat-label">Discovery Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(sensitive_f)}</div><div class="stat-label">Sensitive Files</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#dc2626">{risk_counts.get("CRITICAL", 0) + risk_counts.get("HIGH", 0)}</div><div class="stat-label">Critical/High</div></div>'
    body += '</div>'
    body += _risk_cards_html(risk_counts)
    body += '</div>'

    if sensitive_f:
        body += '<div class="page"><h1>Sensitive File Exposure</h1>'
        body += '''<p class="section-intro">Files containing sensitive configuration data,
credentials, source code, or database connection strings exposed via web server.</p>'''
        for idx, f in enumerate(sensitive_f, 1):
            body += finding_card(f, idx)
        body += '</div>'

    remaining = [f for f in disc_findings if f not in sensitive_f]
    if remaining:
        body += '<div class="page"><h1>Directory &amp; Path Findings</h1>'
        body += '<p class="section-intro">Additional hidden directories, admin panels, and discoverable paths.</p>'
        for idx, f in enumerate(remaining, 1):
            body += finding_card(f, idx)
        body += '</div>'

    return _endpoint_doc_wrap("Content Discovery Report", client_name, body)


def build_web_exec_report(data):
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = sorted(data.get("findings", []), key=risk_sort)
    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in findings)
    total = len(findings)
    top = findings[:5]

    cover = _build_scope_cover(client_name, "Executive Summary — Web Application Assessment",
                               meta, "Web Application", None, incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
{esc(client_name)} engaged the assessor to perform a web application penetration test.
This executive summary provides a high-level overview of the assessment results for
leadership and stakeholders.</p>'''

    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{total}</div><div class="stat-label">Total Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#dc2626">{risk_counts.get("CRITICAL", 0)}</div><div class="stat-label">Critical</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#ea580c">{risk_counts.get("HIGH", 0)}</div><div class="stat-label">High</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#d97706">{risk_counts.get("MEDIUM", 0)}</div><div class="stat-label">Medium</div></div>'
    body += '</div>'
    body += _risk_cards_html(risk_counts)

    pie = _build_risk_pie(risk_counts)
    if pie:
        body += '<div class="risk-charts-row">'
        body += f'<div class="risk-chart-col"><h4>Risk Distribution</h4>{pie}</div>'
        body += '</div>'
    body += _exec_risk_heatmap(risk_counts, total)

    if top:
        body += '<h2>Top Findings</h2>'
        body += '<table><tr><th>Risk</th><th>Finding</th><th>Target</th></tr>'
        for f in top:
            risk = (f.get("risk") or "INFO").upper()
            color = RISK_COLORS.get(risk, "#666")
            ip = esc(f.get("ip", ""))
            port = f.get("port", "")
            target = f"{ip}:{port}" if ip and port else ip
            body += f'<tr><td><span class="badge" style="background:{color};">{risk}</span></td><td>{esc(f.get("title", ""))}</td><td><code>{target}</code></td></tr>'
        body += '</table>'

    body += '<h2>Key Recommendations</h2>'
    body += '''<ol style="font-size:9pt;line-height:1.7;padding-left:18px;">
<li>Remediate all Critical and High findings within 30 days</li>
<li>Implement input validation and output encoding across all application entry points</li>
<li>Enforce HTTPS with HSTS and strong cipher suites on all web applications</li>
<li>Implement security headers (CSP, X-Frame-Options, X-Content-Type-Options)</li>
<li>Update all components to current supported versions and establish a patching cadence</li>
</ol>'''
    body += '</div>'

    return _endpoint_doc_wrap("Executive Summary — Web", client_name, body)


# ═══════════════════════════════════════════════════════════════════════
#  API SCOPE BUILDERS
# ═══════════════════════════════════════════════════════════════════════

def build_api_vuln_report(data):
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = sorted(data.get("findings", []), key=risk_sort)
    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in findings)
    total = len(findings)
    api_inventory = data.get("api_inventory", [])
    targets = _scope_target_lines(meta, "api")

    rogue_findings = [f for f in findings
                      if (f.get("is_rogue_endpoint") or
                          "rogue" in (f.get("title") or "").lower() or
                          "undocumented" in (f.get("title") or "").lower())]

    cover = _build_scope_cover(client_name, "API Security Assessment Report",
                               meta, "API Security", targets, incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
This report presents findings from an API penetration test of {esc(client_name)}'s
API infrastructure. The assessment evaluates authentication, authorization, input
validation, rate limiting, and data exposure across REST, GraphQL, and SOAP endpoints
against the OWASP API Security Top 10:2023 framework.</p>'''
    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{total}</div><div class="stat-label">Total Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#dc2626">{risk_counts.get("CRITICAL", 0)}</div><div class="stat-label">Critical</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(api_inventory)}</div><div class="stat-label">Endpoints Tested</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(rogue_findings)}</div><div class="stat-label">Rogue/Shadow</div></div>'
    body += '</div>'
    body += _risk_cards_html(risk_counts)

    pie = _build_risk_pie(risk_counts)
    if pie:
        body += '<div class="risk-charts-row">'
        body += f'<div class="risk-chart-col"><h4>Risk Distribution</h4>{pie}</div>'
        body += '</div>'
    body += '</div>'

    body += '''<div class="page"><h1>Methodology</h1>
<p class="section-intro">The API assessment followed a structured approach combining
automated scanning with manual exploitation:</p>
<table>
    <tr><th>Phase</th><th>Description</th><th>Tooling</th></tr>
    <tr><td><strong>API Discovery</strong></td>
        <td>Endpoint enumeration from specs (OpenAPI/Swagger), crawling, and traffic analysis</td>
        <td>Siphon, Nuclei</td></tr>
    <tr><td><strong>Authentication Testing</strong></td>
        <td>Token validation, JWT analysis, API key security, OAuth flow testing</td>
        <td>Siphon, manual</td></tr>
    <tr><td><strong>Authorization Testing</strong></td>
        <td>BOLA/IDOR, BFLA, mass assignment, horizontal/vertical privilege escalation</td>
        <td>Siphon, manual</td></tr>
    <tr><td><strong>Input Validation</strong></td>
        <td>Injection testing (SQL, NoSQL, command), parameter tampering, type confusion</td>
        <td>Siphon, sqlmap, Nuclei</td></tr>
    <tr><td><strong>Rate Limiting</strong></td>
        <td>Resource consumption testing, pagination abuse, DoS resilience</td>
        <td>Siphon</td></tr>
    <tr><td><strong>Data Exposure</strong></td>
        <td>Excessive data in responses, sensitive field exposure, verbose errors</td>
        <td>Siphon, manual</td></tr>
</table></div>'''

    if api_inventory:
        body += '<div class="page"><h1>API Endpoint Inventory</h1>'
        body += f'<p class="section-intro">{len(api_inventory)} endpoint(s) identified during API enumeration.</p>'
        body += '<table><tr><th>Method</th><th>Endpoint</th><th>Source</th></tr>'
        for ep in api_inventory[:80]:
            method = esc(ep.get("method", ep.get("api_method", "GET")))
            path = esc(ep.get("path", ep.get("api_endpoint_path", ep.get("endpoint", ""))))
            source = "Spec" if ep.get("api_from_spec") or ep.get("from_spec") else "Discovered"
            is_rogue = ep.get("is_rogue_endpoint") or ep.get("rogue")
            if is_rogue:
                source = '<span style="color:#dc2626;font-weight:700;">Rogue</span>'
            body += f'<tr><td><code>{method}</code></td><td><code>{path}</code></td><td>{source}</td></tr>'
        body += '</table>'
        if len(api_inventory) > 80:
            body += f'<p style="font-size:8pt;color:var(--slate-400);">Showing 80 of {len(api_inventory)} endpoints.</p>'
        body += '</div>'

    if rogue_findings:
        body += '<div class="page"><h1>Rogue &amp; Shadow API Endpoints</h1>'
        body += '''<p class="section-intro">Endpoints discovered that are not documented in
the API specification. These "shadow" APIs bypass governance and may lack proper security controls.</p>'''
        for idx, f in enumerate(rogue_findings, 1):
            body += finding_card(f, idx)
        body += '</div>'

    if findings:
        body += '<div class="page"><h1>Detailed Findings</h1>'
        body += _findings_section_full(findings)
        body += _remediation_summary(findings)
        body += '</div>'

    body += _malicious_indicators_section(findings)

    return _endpoint_doc_wrap("API Security Assessment Report", client_name, body)


def build_api_owasp_report(data):
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = sorted(data.get("findings", []), key=risk_sort)
    targets = _scope_target_lines(meta, "api")

    categorized = defaultdict(list)
    uncategorized = []
    for f in findings:
        cat = _classify_owasp_api(f)
        if cat:
            categorized[cat].append(f)
        else:
            uncategorized.append(f)

    cover = _build_scope_cover(client_name, "OWASP API Top 10 Assessment",
                               meta, "API Security", targets, incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
This report maps API security findings from the assessment of {esc(client_name)}'s
APIs against the OWASP API Security Top 10:2023 framework. Each category is evaluated
for the presence of confirmed vulnerabilities and testing coverage.</p>'''

    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(findings)}</div><div class="stat-label">Total Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(categorized)}/10</div><div class="stat-label">Categories Hit</div></div>'
    cats_with_crit = sum(1 for cat_f in categorized.values()
                        if any((f.get("risk") or "").upper() in ("CRITICAL", "HIGH") for f in cat_f))
    body += f'<div class="stat-card"><div class="stat-number" style="color:#dc2626">{cats_with_crit}</div><div class="stat-label">Critical/High Cats</div></div>'
    body += '</div>'

    body += '<h2>Coverage Matrix</h2>'
    body += '<table><tr><th>OWASP API Category</th><th>Findings</th><th>Highest Risk</th></tr>'
    for code in sorted(_OWASP_API_2023.keys(), key=lambda c: int(c.replace("API", ""))):
        cat_findings = categorized.get(code, [])
        count = len(cat_findings)
        if count:
            worst = "INFO"
            for f in cat_findings:
                r = (f.get("risk") or "INFO").upper()
                if RISK_ORDER.get(r, 5) < RISK_ORDER.get(worst, 5):
                    worst = r
            color = RISK_COLORS.get(worst, "#666")
            status = f'<span class="badge" style="background:{color};">{worst}</span>'
        else:
            status = '<span style="color:#059669;font-weight:600;">No findings</span>'
        body += f'<tr><td><strong>{code}:</strong> {esc(_OWASP_API_2023[code])}</td><td style="text-align:center">{count}</td><td style="text-align:center">{status}</td></tr>'
    body += '</table></div>'

    for code in sorted(_OWASP_API_2023.keys(), key=lambda c: int(c.replace("API", ""))):
        cat_findings = categorized.get(code, [])
        if not cat_findings:
            continue
        cat_findings.sort(key=risk_sort)
        risk_counts = Counter((f.get("risk") or "INFO").upper() for f in cat_findings)

        body += f'<div class="page"><h1>{code}: {esc(_OWASP_API_2023[code])}</h1>'
        body += _risk_cards_html(risk_counts)
        for idx, f in enumerate(cat_findings, 1):
            body += finding_card(f, idx)
        body += '</div>'

    if uncategorized:
        body += '<div class="page"><h1>Uncategorized API Findings</h1>'
        body += '<p class="section-intro">Findings not mapped to an OWASP API Top 10 category.</p>'
        for idx, f in enumerate(uncategorized, 1):
            body += finding_card(f, idx)
        body += '</div>'

    return _endpoint_doc_wrap("OWASP API Top 10 Assessment", client_name, body)


def build_api_exec_report(data):
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = sorted(data.get("findings", []), key=risk_sort)
    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in findings)
    total = len(findings)
    top = findings[:5]
    api_inventory = data.get("api_inventory", [])

    cover = _build_scope_cover(client_name, "Executive Summary — API Security Assessment",
                               meta, "API Security", None, incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
{esc(client_name)} engaged the assessor to perform an API security assessment. This
executive summary provides a high-level overview for leadership and stakeholders.</p>'''

    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{total}</div><div class="stat-label">Total Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#dc2626">{risk_counts.get("CRITICAL", 0)}</div><div class="stat-label">Critical</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#ea580c">{risk_counts.get("HIGH", 0)}</div><div class="stat-label">High</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(api_inventory)}</div><div class="stat-label">Endpoints</div></div>'
    body += '</div>'
    body += _risk_cards_html(risk_counts)

    pie = _build_risk_pie(risk_counts)
    if pie:
        body += '<div class="risk-charts-row">'
        body += f'<div class="risk-chart-col"><h4>Risk Distribution</h4>{pie}</div>'
        body += '</div>'
    body += _exec_risk_heatmap(risk_counts, total)

    if top:
        body += '<h2>Top Findings</h2>'
        body += '<table><tr><th>Risk</th><th>Finding</th><th>Target</th></tr>'
        for f in top:
            risk = (f.get("risk") or "INFO").upper()
            color = RISK_COLORS.get(risk, "#666")
            ip = esc(f.get("ip", ""))
            port = f.get("port", "")
            target = f"{ip}:{port}" if ip and port else ip
            body += f'<tr><td><span class="badge" style="background:{color};">{risk}</span></td><td>{esc(f.get("title", ""))}</td><td><code>{target}</code></td></tr>'
        body += '</table>'

    body += '<h2>Key Recommendations</h2>'
    body += '''<ol style="font-size:9pt;line-height:1.7;padding-left:18px;">
<li>Remediate all Critical and High API findings within 30 days</li>
<li>Implement proper object-level authorization (BOLA protection) on all endpoints</li>
<li>Enforce rate limiting and pagination bounds on all API endpoints</li>
<li>Remove or secure all undocumented/shadow API endpoints</li>
<li>Implement API gateway with centralized authentication, logging, and throttling</li>
</ol>'''
    body += '</div>'

    return _endpoint_doc_wrap("Executive Summary — API", client_name, body)


# ═══════════════════════════════════════════════════════════════════════
#  CROSS-SCOPE TOOL BUILDERS
# ═══════════════════════════════════════════════════════════════════════

def build_trawler_report(data):
    """Network Traffic Analysis Report — Trawler findings with security focus."""
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = sorted(data.get("trawler_findings", []), key=risk_sort)
    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in findings)

    malicious_patterns = [
        "malicious", "c2", "command and control", "beacon", "exfiltration",
        "dns tunnel", "covert channel", "suspicious", "blacklist",
        "threat intel", "ioc", "indicator", "botnet", "tor exit",
        "known bad", "abuse", "phishing", "malware",
    ]
    traffic_patterns = [
        "cleartext", "unencrypted", "plain text", "ftp", "telnet",
        "http ", "snmp v1", "snmpv1", "community string",
        "credential", "password", "authentication",
    ]
    forwarding_patterns = [
        "forwarding", "redirect", "relay", "proxy", "tunnel",
        "pivot", "port forward", "socks", "reverse shell",
        "nat", "arp spoof", "arp poison", "mitm", "man-in-the-middle",
        "ip forward", "routing", "gateway",
    ]

    malicious_findings = _filter_by_title_patterns(findings, malicious_patterns)
    traffic_findings = _filter_by_title_patterns(findings, traffic_patterns)
    forwarding_findings = _filter_by_title_patterns(findings, forwarding_patterns)

    cover = _build_scope_cover(client_name, "Network Traffic Analysis Report", meta, incomplete=incomplete)
    body = cover

    # ── Exec Summary ──
    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
This report presents the network traffic analysis findings from the Trawler deep packet
inspection engine. Trawler analyzes captured network traffic (pcap) to identify security
threats including malicious communications, cleartext credential exposure, protocol
anomalies, suspicious traffic patterns, covert channels, and unauthorized forwarding
or tunneling activity across {esc(client_name)}'s network infrastructure.</p>'''
    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(findings)}</div><div class="stat-label">Total Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#dc2626">{len(malicious_findings)}</div><div class="stat-label">Malicious Activity</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#ea580c">{len(traffic_findings)}</div><div class="stat-label">Cleartext/Creds</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#d97706">{len(forwarding_findings)}</div><div class="stat-label">Forwarding/Tunnel</div></div>'
    body += '</div>'
    body += _risk_cards_html(risk_counts)

    pie = _build_risk_pie(risk_counts)
    if pie:
        body += '<div class="risk-charts-row">'
        body += f'<div class="risk-chart-col"><h4>Risk Distribution</h4>{pie}</div>'
        body += '</div>'
    body += '</div>'

    # ── Malicious Activity ──
    if malicious_findings:
        body += '<div class="page"><h1>Malicious Traffic &amp; Threat Intelligence</h1>'
        body += '''<p class="section-intro">Findings involving communication with known malicious
IPs, command-and-control (C2) beacon patterns, DNS tunneling, data exfiltration indicators,
botnet traffic, and matches against threat intelligence feeds. These findings represent
the highest-priority items requiring immediate investigation and incident response.</p>'''
        body += _findings_cards(malicious_findings)
        body += '</div>'

    # ── Cleartext & Credential Exposure ──
    if traffic_findings:
        body += '<div class="page"><h1>Cleartext &amp; Credential Exposure</h1>'
        body += '''<p class="section-intro">Findings involving unencrypted protocols transmitting
sensitive data, including cleartext credentials (FTP, Telnet, HTTP Basic Auth, SNMPv1
community strings), unencrypted email (POP3/IMAP without TLS), and other plaintext
protocols that expose data to network-level interception.</p>'''
        body += _findings_cards(traffic_findings)
        body += '</div>'

    # ── Forwarding & Tunneling ──
    if forwarding_findings:
        body += '<div class="page"><h1>Forwarding, Tunneling &amp; Pivoting</h1>'
        body += '''<p class="section-intro">Findings involving unauthorized traffic forwarding,
tunneling, SOCKS proxying, port forwarding, ARP spoofing/poisoning, man-in-the-middle
activity, suspicious NAT traversal, reverse shells, and other indicators of network-layer
pivoting or traffic redirection that could facilitate lateral movement or data exfiltration.</p>'''
        body += _findings_cards(forwarding_findings)
        body += '</div>'

    # ── Remaining Findings ──
    seen = set(id(f) for f in malicious_findings + traffic_findings + forwarding_findings)
    remaining = [f for f in findings if id(f) not in seen]
    if remaining:
        body += '<div class="page"><h1>Additional Traffic Findings</h1>'
        body += '<p class="section-intro">Additional traffic analysis findings including protocol anomalies, misconfigurations, and informational observations.</p>'
        body += _findings_cards(remaining)
        body += '</div>'

    # ── Recommendations ──
    body += '''<div class="page"><h1>Traffic Security Recommendations</h1>
<table>
    <tr><th>Priority</th><th>Recommendation</th><th>Mitigates</th></tr>
    <tr><td><span class="badge" style="background:#dc2626">CRITICAL</span></td>
        <td>Investigate all malicious IP communications immediately — isolate affected hosts, perform forensic analysis, and check for persistence mechanisms</td>
        <td>Active compromise, C2 communication, data exfiltration</td></tr>
    <tr><td><span class="badge" style="background:#dc2626">CRITICAL</span></td>
        <td>Replace all cleartext protocols (FTP, Telnet, HTTP, SNMPv1/v2c) with encrypted alternatives (SFTP, SSH, HTTPS, SNMPv3)</td>
        <td>Credential theft, data interception, man-in-the-middle</td></tr>
    <tr><td><span class="badge" style="background:#ea580c">HIGH</span></td>
        <td>Block unauthorized tunneling protocols at the firewall — SSH tunnels, SOCKS proxies, DNS-over-HTTPS from non-approved resolvers</td>
        <td>Covert channels, data exfiltration, security control bypass</td></tr>
    <tr><td><span class="badge" style="background:#ea580c">HIGH</span></td>
        <td>Deploy network-level threat intelligence integration (Suricata/Snort with ET Pro, Zeek with Intel Framework) for continuous C2/malicious IP detection</td>
        <td>Undetected malicious communication</td></tr>
    <tr><td><span class="badge" style="background:#d97706">MEDIUM</span></td>
        <td>Enable ARP inspection, DHCP snooping, and port security on switch infrastructure to prevent ARP spoofing and MITM attacks</td>
        <td>ARP poisoning, traffic interception, rogue device injection</td></tr>
    <tr><td><span class="badge" style="background:#d97706">MEDIUM</span></td>
        <td>Implement network segmentation with explicit deny-all inter-VLAN rules to limit scope of traffic capture from a compromised segment</td>
        <td>Lateral traffic visibility, broadcast domain attacks</td></tr>
</table></div>'''

    return _endpoint_doc_wrap("Network Traffic Analysis Report", client_name, body)


def build_auger_report(data):
    """Database Security Report — Auger findings with data security focus."""
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = sorted(data.get("auger_findings", []), key=risk_sort)
    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in findings)

    auth_patterns = [
        "default credential", "weak password", "anonymous", "no password",
        "blank password", "root login", "sa account", "default account",
        "authentication bypass", "brute force", "credential",
    ]
    config_patterns = [
        "remote access", "listener", "configuration", "privilege",
        "permission", "role", "grant", "stored procedure", "xp_cmdshell",
        "linked server", "trust", "encryption at rest", "tde",
        "transparent data", "audit", "logging",
    ]
    injection_patterns = [
        "injection", "sqli", "sql injection", "stacked queries",
        "blind", "union", "time-based", "error-based",
        "command execution", "code execution",
    ]
    data_exposure_patterns = [
        "data exposure", "sensitive data", "pii", "phi", "credit card",
        "social security", "cleartext", "unencrypted", "backup",
        "dump", "exfiltration", "data leak",
    ]

    auth_findings = _filter_by_title_patterns(findings, auth_patterns)
    config_findings = _filter_by_title_patterns(findings, config_patterns)
    injection_findings = _filter_by_title_patterns(findings, injection_patterns)
    exposure_findings = _filter_by_title_patterns(findings, data_exposure_patterns)

    db_types = set()
    for f in findings:
        svc = (f.get("service") or "").lower()
        title = (f.get("title") or "").lower()
        for db in ("mysql", "postgresql", "postgres", "mssql", "sql server",
                    "oracle", "mongodb", "redis", "cassandra", "couchdb",
                    "elasticsearch", "mariadb", "sqlite"):
            if db in svc or db in title:
                db_types.add(db.title())

    cover = _build_scope_cover(client_name, "Database Security Report", meta, incomplete=incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
This report presents database security findings from the Auger database assessment
engine across {esc(client_name)}'s environment. Databases are primary targets for
attackers seeking to exfiltrate sensitive data, establish persistence, or escalate
privileges. This assessment covers authentication weaknesses, misconfigurations,
SQL injection vulnerabilities, data exposure risks, and compliance gaps across
{len(db_types) if db_types else "all detected"} database platform(s).</p>'''
    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(findings)}</div><div class="stat-label">Total Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#dc2626">{len(auth_findings)}</div><div class="stat-label">Auth Issues</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#ea580c">{len(injection_findings)}</div><div class="stat-label">Injection</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(db_types)}</div><div class="stat-label">DB Platforms</div></div>'
    body += '</div>'
    body += _risk_cards_html(risk_counts)

    pie = _build_risk_pie(risk_counts)
    if pie:
        body += '<div class="risk-charts-row">'
        body += f'<div class="risk-chart-col"><h4>Risk Distribution</h4>{pie}</div>'
        body += '</div>'
    body += '</div>'

    # ── DB Platform Inventory ──
    if db_types:
        body += '<div class="page"><h1>Database Platform Inventory</h1>'
        body += '<p class="section-intro">Database platforms identified during the assessment.</p>'
        body += '<table><tr><th>Platform</th><th>Related Findings</th></tr>'
        for db in sorted(db_types):
            count = sum(1 for f in findings if db.lower() in ((f.get("service") or "") + " " + (f.get("title") or "")).lower())
            body += f'<tr><td><strong>{esc(db)}</strong></td><td style="text-align:center">{count}</td></tr>'
        body += '</table></div>'

    # ── Authentication ──
    if auth_findings:
        body += '<div class="page"><h1>Authentication &amp; Credential Findings</h1>'
        body += '''<p class="section-intro">Findings related to database authentication
weaknesses including default credentials, blank passwords, anonymous access, and
brute-forceable accounts that could allow unauthorized database access.</p>'''
        body += _findings_cards(auth_findings)
        body += '</div>'

    # ── SQL Injection ──
    if injection_findings:
        body += '<div class="page"><h1>SQL Injection &amp; Code Execution</h1>'
        body += '''<p class="section-intro">Findings related to SQL injection vulnerabilities,
stored procedure abuse, and code execution paths through database interfaces. These
represent direct data compromise and potential server-level access vectors.</p>'''
        body += _findings_cards(injection_findings)
        body += '</div>'

    # ── Data Exposure ──
    if exposure_findings:
        body += '<div class="page"><h1>Sensitive Data Exposure</h1>'
        body += '''<p class="section-intro">Findings related to sensitive data stored without
adequate protection — including PII, PHI, payment card data, and other regulated information
found in cleartext, unencrypted backups, or exposed through misconfigured access controls.</p>'''
        body += _findings_cards(exposure_findings)
        body += '</div>'

    # ── Configuration ──
    if config_findings:
        body += '<div class="page"><h1>Configuration &amp; Hardening</h1>'
        body += '<p class="section-intro">Database configuration weaknesses, excessive privileges, disabled audit logging, and missing encryption controls.</p>'
        body += _findings_cards(config_findings)
        body += '</div>'

    # ── Remaining ──
    seen = set(id(f) for f in auth_findings + injection_findings + exposure_findings + config_findings)
    remaining = [f for f in findings if id(f) not in seen]
    if remaining:
        body += '<div class="page"><h1>Additional Database Findings</h1>'
        body += _findings_cards(remaining)
        body += '</div>'

    # ── Recommendations ──
    body += '''<div class="page"><h1>Database Security Recommendations</h1>
<table>
    <tr><th>Priority</th><th>Recommendation</th><th>Mitigates</th></tr>
    <tr><td><span class="badge" style="background:#dc2626">CRITICAL</span></td>
        <td>Immediately rotate all default and weak database credentials; disable SA/root remote access</td>
        <td>Unauthorized access, credential-based compromise</td></tr>
    <tr><td><span class="badge" style="background:#dc2626">CRITICAL</span></td>
        <td>Remediate all SQL injection findings with parameterized queries and input validation</td>
        <td>Data exfiltration, command execution, privilege escalation</td></tr>
    <tr><td><span class="badge" style="background:#ea580c">HIGH</span></td>
        <td>Enable Transparent Data Encryption (TDE) and encrypted connections for all production databases</td>
        <td>Data-at-rest and data-in-transit exposure</td></tr>
    <tr><td><span class="badge" style="background:#ea580c">HIGH</span></td>
        <td>Implement least-privilege access model — remove excessive GRANTs, disable xp_cmdshell/linked servers where unused</td>
        <td>Privilege escalation, lateral movement through DB links</td></tr>
    <tr><td><span class="badge" style="background:#d97706">MEDIUM</span></td>
        <td>Enable database audit logging (queries, logins, schema changes) and forward to SIEM</td>
        <td>Undetected data access, compliance gaps</td></tr>
    <tr><td><span class="badge" style="background:#d97706">MEDIUM</span></td>
        <td>Restrict database listener to required interfaces only; do not bind to 0.0.0.0</td>
        <td>Unauthorized network access to database services</td></tr>
</table></div>'''

    return _endpoint_doc_wrap("Database Security Report", client_name, body)


def build_bastion_report(data):
    """Firewall & Configuration Audit Report — Bastion findings."""
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = sorted(data.get("bastion_findings", []), key=risk_sort)
    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in findings)

    rule_patterns = [
        "firewall rule", "acl", "access control", "any any", "allow all",
        "overly permissive", "broad rule", "wildcard", "0.0.0.0",
        "default allow", "implicit deny", "rule order",
    ]
    mgmt_patterns = [
        "management", "admin", "console", "snmp", "ssh",
        "telnet", "http management", "firmware", "update",
        "default password", "credential",
    ]
    vpn_patterns = [
        "vpn", "ipsec", "ike", "ssl vpn", "tunnel", "split tunnel",
        "remote access", "radius", "tacacs", "two-factor", "mfa",
    ]
    logging_patterns = [
        "logging", "syslog", "audit", "log", "monitoring",
        "alert", "notification", "event",
    ]
    malicious_patterns = [
        "malicious", "block", "deny", "blacklist", "geo-block",
        "threat feed", "ip reputation", "botnet", "c2",
        "exfiltration", "egress filter",
    ]

    rule_findings = _filter_by_title_patterns(findings, rule_patterns)
    mgmt_findings = _filter_by_title_patterns(findings, mgmt_patterns)
    vpn_findings = _filter_by_title_patterns(findings, vpn_patterns)
    logging_findings = _filter_by_title_patterns(findings, logging_patterns)
    malicious_findings = _filter_by_title_patterns(findings, malicious_patterns)

    cover = _build_scope_cover(client_name, "Firewall & Configuration Audit Report", meta, incomplete=incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
This report presents the firewall and network device configuration audit results from
the Bastion security assessment engine across {esc(client_name)}'s infrastructure.
The audit evaluates firewall rule effectiveness, management interface security, VPN
configuration, logging adequacy, and the ability to detect and block malicious traffic
including known-bad IPs, C2 communication, and unauthorized data exfiltration.</p>'''
    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(findings)}</div><div class="stat-label">Total Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#dc2626">{len(rule_findings)}</div><div class="stat-label">Rule Issues</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#ea580c">{len(mgmt_findings)}</div><div class="stat-label">Mgmt Issues</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(vpn_findings)}</div><div class="stat-label">VPN Issues</div></div>'
    body += '</div>'
    body += _risk_cards_html(risk_counts)

    pie = _build_risk_pie(risk_counts)
    if pie:
        body += '<div class="risk-charts-row">'
        body += f'<div class="risk-chart-col"><h4>Risk Distribution</h4>{pie}</div>'
        body += '</div>'
    body += '</div>'

    # ── Firewall Rules ──
    if rule_findings:
        body += '<div class="page"><h1>Firewall Rule Analysis</h1>'
        body += '''<p class="section-intro">Findings from firewall rule-base analysis,
including overly permissive rules, any/any rules, missing egress filtering,
misconfigured ACLs, and rule ordering issues that could allow unauthorized traffic.</p>'''
        body += _findings_cards(rule_findings)
        body += '</div>'

    # ── Malicious Traffic Controls ──
    if malicious_findings:
        body += '<div class="page"><h1>Malicious Traffic Controls</h1>'
        body += '''<p class="section-intro">Assessment of the firewall's ability to detect and
block malicious traffic, including IP reputation feeds, geo-blocking, botnet/C2 blocking,
egress filtering for data exfiltration prevention, and threat intelligence integration.</p>'''
        body += _findings_cards(malicious_findings)
        body += '</div>'

    # ── Management Interface ──
    if mgmt_findings:
        body += '<div class="page"><h1>Management Interface Security</h1>'
        body += '''<p class="section-intro">Findings related to firewall and network device
management interfaces, including admin console exposure, default credentials, insecure
management protocols (Telnet, HTTP), and firmware update status.</p>'''
        body += _findings_cards(mgmt_findings)
        body += '</div>'

    # ── VPN ──
    if vpn_findings:
        body += '<div class="page"><h1>VPN Configuration</h1>'
        body += '''<p class="section-intro">Findings related to VPN configuration including
IPSec/IKE settings, SSL VPN hardening, split tunneling, MFA enforcement, and
remote access policy compliance.</p>'''
        body += _findings_cards(vpn_findings)
        body += '</div>'

    # ── Logging ──
    if logging_findings:
        body += '<div class="page"><h1>Logging &amp; Monitoring</h1>'
        body += '''<p class="section-intro">Assessment of firewall logging configuration,
syslog forwarding, event alerting, and audit trail completeness for forensic readiness
and compliance requirements.</p>'''
        body += _findings_cards(logging_findings)
        body += '</div>'

    # ── Remaining ──
    seen = set(id(f) for f in rule_findings + mgmt_findings + vpn_findings + logging_findings + malicious_findings)
    remaining = [f for f in findings if id(f) not in seen]
    if remaining:
        body += '<div class="page"><h1>Additional Findings</h1>'
        body += _findings_cards(remaining)
        body += '</div>'

    # ── Recommendations ──
    body += '''<div class="page"><h1>Firewall Hardening Recommendations</h1>
<table>
    <tr><th>Priority</th><th>Recommendation</th><th>Mitigates</th></tr>
    <tr><td><span class="badge" style="background:#dc2626">CRITICAL</span></td>
        <td>Remove all any/any permit rules; implement explicit least-privilege rules with specific source, destination, and service</td>
        <td>Unauthorized access, lateral movement, security control bypass</td></tr>
    <tr><td><span class="badge" style="background:#dc2626">CRITICAL</span></td>
        <td>Enable egress filtering to block unauthorized outbound protocols and known-malicious IP ranges; integrate threat intelligence feeds</td>
        <td>Data exfiltration, C2 communication, malicious outbound traffic</td></tr>
    <tr><td><span class="badge" style="background:#ea580c">HIGH</span></td>
        <td>Restrict management interfaces to dedicated management VLAN; disable HTTP/Telnet management; require MFA for admin access</td>
        <td>Admin console compromise, credential theft</td></tr>
    <tr><td><span class="badge" style="background:#ea580c">HIGH</span></td>
        <td>Enforce strong VPN authentication (certificate + MFA); disable split tunneling for full-tunnel corporate VPN profiles</td>
        <td>VPN credential abuse, split-tunnel data leakage</td></tr>
    <tr><td><span class="badge" style="background:#d97706">MEDIUM</span></td>
        <td>Forward all firewall logs to SIEM with real-time correlation rules for blocked traffic spikes and admin access events</td>
        <td>Undetected attacks, incomplete forensic trail</td></tr>
    <tr><td><span class="badge" style="background:#d97706">MEDIUM</span></td>
        <td>Conduct quarterly firewall rule review to remove stale, duplicate, and shadowed rules</td>
        <td>Rule-base bloat, misconfigurations from stale entries</td></tr>
</table></div>'''

    return _endpoint_doc_wrap("Firewall & Configuration Audit Report", client_name, body)


def build_forge_report(data):
    """Cloud Configuration Security Report — Forge findings."""
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = sorted(data.get("forge_findings", []), key=risk_sort)
    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in findings)

    iam_patterns = [
        "iam", "role", "policy", "permission", "privilege", "access key",
        "mfa", "root account", "service account", "cross-account",
        "assume role", "excessive permission", "wildcard", "admin",
    ]
    storage_patterns = [
        "s3", "bucket", "blob", "storage", "public access",
        "encryption", "versioning", "lifecycle", "acl",
        "container", "object storage",
    ]
    network_patterns = [
        "security group", "nacl", "vpc", "subnet", "public ip",
        "internet gateway", "nat", "peering", "endpoint", "firewall",
        "0.0.0.0/0", "ingress", "egress",
    ]
    logging_patterns = [
        "cloudtrail", "cloudwatch", "flow log", "access log",
        "audit log", "monitoring", "alert", "guard duty", "detective",
    ]
    malicious_patterns = [
        "malicious", "exposed", "public", "leak", "exfiltration",
        "data transfer", "cross-region", "suspicious", "anomalous",
    ]

    iam_findings = _filter_by_title_patterns(findings, iam_patterns)
    storage_findings = _filter_by_title_patterns(findings, storage_patterns)
    network_findings = _filter_by_title_patterns(findings, network_patterns)
    logging_findings = _filter_by_title_patterns(findings, logging_patterns)
    malicious_findings = _filter_by_title_patterns(findings, malicious_patterns)

    cover = _build_scope_cover(client_name, "Cloud Configuration Security Report", meta, incomplete=incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
This report presents cloud infrastructure security findings from the Forge cloud
configuration assessment engine across {esc(client_name)}'s cloud environment.
The assessment evaluates IAM policies, storage security, network configuration,
logging adequacy, and controls for preventing malicious data exfiltration,
unauthorized access, and misconfiguration-driven exposure.</p>'''
    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(findings)}</div><div class="stat-label">Total Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#dc2626">{len(iam_findings)}</div><div class="stat-label">IAM Issues</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#ea580c">{len(storage_findings)}</div><div class="stat-label">Storage Issues</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(network_findings)}</div><div class="stat-label">Network Issues</div></div>'
    body += '</div>'
    body += _risk_cards_html(risk_counts)

    pie = _build_risk_pie(risk_counts)
    if pie:
        body += '<div class="risk-charts-row">'
        body += f'<div class="risk-chart-col"><h4>Risk Distribution</h4>{pie}</div>'
        body += '</div>'
    body += '</div>'

    if iam_findings:
        body += '<div class="page"><h1>Identity &amp; Access Management (IAM)</h1>'
        body += '''<p class="section-intro">IAM policy and role findings including excessive
permissions, missing MFA, exposed access keys, overly broad wildcard policies, and
root account usage that could enable unauthorized access or privilege escalation.</p>'''
        body += _findings_cards(iam_findings)
        body += '</div>'

    if storage_findings:
        body += '<div class="page"><h1>Storage Security</h1>'
        body += '''<p class="section-intro">Cloud storage findings including publicly accessible
buckets/containers, missing encryption, permissive ACLs, disabled versioning, and
configuration gaps that could lead to sensitive data exposure or malicious data
exfiltration.</p>'''
        body += _findings_cards(storage_findings)
        body += '</div>'

    if network_findings:
        body += '<div class="page"><h1>Network Configuration</h1>'
        body += '''<p class="section-intro">Cloud network findings including overly permissive
security groups, public-facing resources, missing network segmentation, and
configuration gaps that expose cloud resources to unauthorized access.</p>'''
        body += _findings_cards(network_findings)
        body += '</div>'

    if malicious_findings:
        body += '<div class="page"><h1>Data Exposure &amp; Exfiltration Risks</h1>'
        body += '''<p class="section-intro">Findings related to data exposure, suspicious
cross-region transfers, publicly accessible resources, and configuration gaps that
could facilitate malicious data exfiltration or unauthorized data access.</p>'''
        body += _findings_cards(malicious_findings)
        body += '</div>'

    if logging_findings:
        body += '<div class="page"><h1>Logging &amp; Monitoring</h1>'
        body += '<p class="section-intro">Cloud logging and monitoring findings including CloudTrail/flow log gaps, missing alerts, and detection blind spots.</p>'
        body += _findings_cards(logging_findings)
        body += '</div>'

    seen = set(id(f) for f in iam_findings + storage_findings + network_findings + logging_findings + malicious_findings)
    remaining = [f for f in findings if id(f) not in seen]
    if remaining:
        body += '<div class="page"><h1>Additional Cloud Findings</h1>'
        body += _findings_cards(remaining)
        body += '</div>'

    body += '''<div class="page"><h1>Cloud Security Recommendations</h1>
<table>
    <tr><th>Priority</th><th>Recommendation</th><th>Mitigates</th></tr>
    <tr><td><span class="badge" style="background:#dc2626">CRITICAL</span></td>
        <td>Enforce least-privilege IAM — remove wildcard (*) actions and unused permissions; require MFA for all human users</td>
        <td>Privilege escalation, unauthorized access, account compromise</td></tr>
    <tr><td><span class="badge" style="background:#dc2626">CRITICAL</span></td>
        <td>Block all public access to storage buckets/containers unless explicitly required; enable default encryption</td>
        <td>Data exposure, accidental public leak, regulatory violation</td></tr>
    <tr><td><span class="badge" style="background:#ea580c">HIGH</span></td>
        <td>Restrict security group ingress to specific CIDR ranges; remove 0.0.0.0/0 rules except for public-facing load balancers</td>
        <td>Unauthorized network access, reconnaissance, exploitation</td></tr>
    <tr><td><span class="badge" style="background:#ea580c">HIGH</span></td>
        <td>Enable CloudTrail (all regions, all event types), VPC flow logs, and S3 access logging; forward to SIEM</td>
        <td>Undetected attacks, missing forensic trail</td></tr>
    <tr><td><span class="badge" style="background:#d97706">MEDIUM</span></td>
        <td>Implement data exfiltration controls — VPC endpoints, S3 bucket policies restricting cross-account copy, GuardDuty anomaly detection</td>
        <td>Malicious data exfiltration via cloud APIs</td></tr>
</table></div>'''

    return _endpoint_doc_wrap("Cloud Configuration Security Report", client_name, body)


# ── Cloud Assessment Reports ─────────────────────────────────────────────────
# Cloud pentest, CIS benchmark, compliance, and executive summary reports


def gather_cloud_data(project):
    """Enhanced cloud gatherer — loads findings + intelligence files."""
    findings = _load_findings_for_tool(project, "forge")
    cloud_inventory = []
    iam_matrix = []
    service_dashboard = []
    for scope_dirs in project.get("scope_tool_dirs", {}).values():
        td = scope_dirs.get("forge")
        if td:
            td = Path(td)
            if td.exists():
                cloud_inventory = _load_json(td / "cloud_inventory.json") or cloud_inventory
                iam_matrix = _load_json(td / "iam_matrix.json") or iam_matrix
                service_dashboard = _load_json(td / "service_dashboard.json") or service_dashboard
    td = project.get("tool_dirs", {}).get("forge")
    if td:
        td = Path(td)
        if td.exists():
            cloud_inventory = _load_json(td / "cloud_inventory.json") or cloud_inventory
            iam_matrix = _load_json(td / "iam_matrix.json") or iam_matrix
            service_dashboard = _load_json(td / "service_dashboard.json") or service_dashboard
    return {
        "forge_findings": findings,
        "cloud_inventory": cloud_inventory if isinstance(cloud_inventory, list) else [],
        "iam_matrix": iam_matrix if isinstance(iam_matrix, list) else [],
        "service_dashboard": service_dashboard if isinstance(service_dashboard, list) else [],
        "crucible_meta": project,
    }


def _cloud_service_table(service_dashboard):
    if not service_dashboard:
        return ""
    h = '<h2>AWS Service Risk Summary</h2>'
    h += '<table><tr><th>Service</th><th>Resources</th><th>Findings</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Status</th></tr>'
    for svc in sorted(service_dashboard, key=lambda s: (s.get("critical", 0) + s.get("high", 0) * 0.5), reverse=True):
        name = esc(svc.get("service", ""))
        resources = svc.get("resources", 0)
        findings = svc.get("findings", 0)
        if findings == 0:
            continue
        crit = svc.get("critical", 0)
        high = svc.get("high", 0)
        med = svc.get("medium", 0)
        low = svc.get("low", 0)
        status = esc(svc.get("status", ""))
        h += f'<tr><td><strong>{name}</strong></td><td style="text-align:center">{resources}</td>'
        h += f'<td style="text-align:center;font-weight:700">{findings}</td>'
        h += f'<td style="text-align:center;color:#dc2626;font-weight:700">{crit if crit else "-"}</td>'
        h += f'<td style="text-align:center;color:#ea580c;font-weight:700">{high if high else "-"}</td>'
        h += f'<td style="text-align:center;color:#d97706;">{med if med else "-"}</td>'
        h += f'<td style="text-align:center;color:#65a30d;">{low if low else "-"}</td>'
        h += f'<td style="font-size:8pt">{status}</td></tr>'
    h += '</table>'
    return h


def _cloud_iam_table(iam_matrix):
    if not iam_matrix:
        return ""
    h = '<h2>IAM User Analysis</h2>'
    h += '<table><tr><th>User</th><th>MFA</th><th>Access Keys</th><th>Last Login</th><th>Policies</th><th>Risk</th></tr>'
    for user in sorted(iam_matrix, key=lambda u: RISK_ORDER.get((u.get("risk") or "INFO").upper(), 5)):
        name = esc(user.get("user", ""))
        mfa = user.get("mfa_active", "")
        mfa_icon = '<span style="color:#16a34a">&#10003;</span>' if mfa in ("true", True) else '<span style="color:#dc2626">&#10007;</span>'
        keys = user.get("active_keys", user.get("access_keys", 0))
        last = esc((user.get("last_login") or "Never")[:10])
        policies = esc((user.get("policies") or "")[:80])
        risk = (user.get("risk") or "INFO").upper()
        color = RISK_COLORS.get(risk, "#666")
        h += f'<tr><td><code>{name}</code></td><td style="text-align:center">{mfa_icon}</td>'
        h += f'<td style="text-align:center">{keys}</td><td style="font-size:8pt">{last}</td>'
        h += f'<td style="font-size:7.5pt">{policies}</td>'
        h += f'<td><span class="badge" style="background:{color}">{risk}</span></td></tr>'
    h += '</table>'
    return h


def build_cloud_pentest_report(data):
    """Cloud Penetration Test Assessment — attack-surface focused."""
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = sorted(data.get("forge_findings", []), key=risk_sort)
    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in findings)
    service_dashboard = data.get("service_dashboard", [])
    iam_matrix = data.get("iam_matrix", [])
    cloud_inventory = data.get("cloud_inventory", [])

    iam_patterns = [
        "iam", "role", "policy", "permission", "privilege", "access key",
        "mfa", "root account", "service account", "cross-account",
        "assume role", "excessive permission", "wildcard", "admin",
        "credential", "password", "console access",
    ]
    network_patterns = [
        "security group", "nacl", "vpc", "subnet", "public ip",
        "internet gateway", "nat", "peering", "endpoint", "firewall",
        "0.0.0.0/0", "ingress", "egress", "load balancer", "cloudfront",
        "waf", "route table", "elastic ip",
    ]
    storage_patterns = [
        "s3", "bucket", "blob", "storage", "public access",
        "encryption", "versioning", "lifecycle", "acl",
        "object storage", "block public", "kms", "key management",
        "efs", "dynamodb",
    ]
    secrets_patterns = [
        "secret", "key management", "kms", "rotation", "access key",
        "credential", "password policy", "secrets manager", "ssm parameter",
        "certificate", "acm", "hardcoded",
    ]
    detection_patterns = [
        "cloudtrail", "cloudwatch", "flow log", "access log",
        "audit log", "monitoring", "alert", "guardduty", "guard duty",
        "detective", "security hub", "config", "inspector",
        "log", "event",
    ]
    exfil_patterns = [
        "malicious", "exposed", "public", "leak", "exfiltration",
        "data transfer", "cross-region", "suspicious", "anomalous",
        "unrestricted", "open to internet",
    ]

    iam_findings = _filter_by_title_patterns(findings, iam_patterns)
    network_findings = _filter_by_title_patterns(findings, network_patterns)
    storage_findings = _filter_by_title_patterns(findings, storage_patterns)
    secrets_findings = _filter_by_title_patterns(findings, secrets_patterns)
    detection_findings = _filter_by_title_patterns(findings, detection_patterns)
    exfil_findings = _filter_by_title_patterns(findings, exfil_patterns)

    cover = _build_scope_cover(client_name, "Cloud Penetration Test Assessment",
                               meta, "Cloud Infrastructure", None, incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
the assessor performed a cloud infrastructure penetration test of {esc(client_name)}'s
AWS environment. This assessment evaluated the cloud environment from an attacker's
perspective, identifying misconfiguration-driven attack vectors across identity management,
network exposure, data storage, secrets handling, and detection capability gaps that
could be exploited to gain unauthorized access, escalate privileges, exfiltrate data,
or maintain persistent access.</p>'''

    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(findings)}</div><div class="stat-label">Total Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#dc2626">{risk_counts.get("CRITICAL", 0)}</div><div class="stat-label">Critical</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#ea580c">{risk_counts.get("HIGH", 0)}</div><div class="stat-label">High</div></div>'
    svc_count = len([s for s in service_dashboard if s.get("findings", 0) > 0])
    body += f'<div class="stat-card"><div class="stat-number">{svc_count}</div><div class="stat-label">Services Affected</div></div>'
    body += '</div>'
    body += _risk_cards_html(risk_counts)

    pie = _build_risk_pie(risk_counts)
    if pie:
        body += '<div class="risk-charts-row">'
        body += f'<div class="risk-chart-col"><h4>Risk Distribution</h4>{pie}</div>'
        body += '</div>'
    body += _exec_risk_heatmap(risk_counts, len(findings))
    body += '</div>'

    if service_dashboard or cloud_inventory:
        body += '<div class="page"><h1>Attack Surface Overview</h1>'
        body += f'''<p class="section-intro">The following AWS services were assessed and
found to contain security findings. Resource counts and risk breakdowns provide
the attack surface scope for each service.</p>'''
        body += _cloud_service_table(service_dashboard)
        if cloud_inventory:
            regions = set(r.get("region", "unknown") for r in cloud_inventory)
            body += f'<p style="margin-top:12px;font-size:9pt;color:var(--slate-500);">'
            body += f'<strong>Regions observed:</strong> {", ".join(sorted(regions))}'
            body += f' &bull; <strong>Inventoried resources:</strong> {len(cloud_inventory)}</p>'
        body += '</div>'

    if iam_findings:
        body += '<div class="page"><h1>IAM &amp; Privilege Escalation</h1>'
        body += f'''<p class="section-intro">Identity and Access Management findings represent
the highest-impact attack surface in any cloud environment. An attacker who compromises
a misconfigured IAM principal can escalate privileges, pivot across accounts, access
production data, and establish persistent backdoor access. {len(iam_findings)} finding(s)
were identified in this category.</p>'''
        body += _cloud_iam_table(iam_matrix)
        body += _findings_cards(iam_findings)
        body += '</div>'

    if network_findings:
        body += '<div class="page"><h1>Network Security &amp; Exposure</h1>'
        body += f'''<p class="section-intro">Cloud network misconfigurations expose internal
services to the internet, enable lateral movement between VPCs, and bypass security
controls. Overly permissive security groups and missing network segmentation are the
primary attack vectors. {len(network_findings)} finding(s) were identified.</p>'''
        body += _findings_cards(network_findings)
        body += '</div>'

    if storage_findings:
        body += '<div class="page"><h1>Data Protection &amp; Storage Security</h1>'
        body += f'''<p class="section-intro">Cloud storage services (S3, EFS, DynamoDB) are
a primary target for data exfiltration. Publicly accessible buckets, missing encryption,
and overly permissive ACLs allow attackers to access, modify, or exfiltrate sensitive data.
{len(storage_findings)} finding(s) were identified.</p>'''
        body += _findings_cards(storage_findings)
        body += '</div>'

    if secrets_findings:
        body += '<div class="page"><h1>Secrets &amp; Key Management</h1>'
        body += f'''<p class="section-intro">Credential and key management weaknesses enable
attackers to obtain long-lived access tokens, decrypt protected data, or leverage
exposed secrets for lateral movement. {len(secrets_findings)} finding(s) were identified.</p>'''
        body += _findings_cards(secrets_findings)
        body += '</div>'

    if detection_findings:
        body += '<div class="page"><h1>Detection &amp; Monitoring Gaps</h1>'
        body += f'''<p class="section-intro">From a penetration testing perspective, gaps in
logging and monitoring are exploitable — they allow an attacker to operate undetected.
Missing CloudTrail coverage, disabled GuardDuty, and absent flow logs create blind spots
where reconnaissance, privilege escalation, and data exfiltration go unnoticed.
{len(detection_findings)} finding(s) were identified.</p>'''
        body += _findings_cards(detection_findings)
        body += '</div>'

    if exfil_findings:
        body += '<div class="page"><h1>Data Exfiltration &amp; Malicious Access</h1>'
        body += f'''<p class="section-intro">Configuration gaps that facilitate or fail to
prevent malicious data exfiltration via cloud APIs, cross-region transfers, and
publicly accessible resources. {len(exfil_findings)} finding(s) were identified.</p>'''
        body += _findings_cards(exfil_findings)
        body += '</div>'

    seen = set(id(f) for f in iam_findings + network_findings + storage_findings +
               secrets_findings + detection_findings + exfil_findings)
    remaining = [f for f in findings if id(f) not in seen]
    if remaining:
        body += '<div class="page"><h1>Additional Findings</h1>'
        body += _findings_cards(remaining)
        body += '</div>'

    crit_high = [f for f in findings if (f.get("risk") or "INFO").upper() in ("CRITICAL", "HIGH")]
    med = [f for f in findings if (f.get("risk") or "INFO").upper() == "MEDIUM"]
    body += '<div class="page"><h1>Remediation Roadmap</h1>'
    body += f'''<p class="section-intro">Prioritized remediation plan based on exploitability and
business impact. Immediate items should be addressed within 7 days; short-term within 30 days;
medium-term within 90 days.</p>'''
    body += '<table><tr><th>Timeline</th><th>Priority</th><th>Action</th><th>Findings Addressed</th></tr>'
    body += f'''<tr><td><strong>Immediate</strong><br>(0–7 days)</td>
        <td><span class="badge" style="background:#dc2626">CRITICAL</span></td>
        <td>Enforce MFA on all IAM users; disable unused access keys; block public S3 access; restrict 0.0.0.0/0 security group rules</td>
        <td style="text-align:center">{len(crit_high)}</td></tr>'''
    body += f'''<tr><td><strong>Short-term</strong><br>(7–30 days)</td>
        <td><span class="badge" style="background:#ea580c">HIGH</span></td>
        <td>Enable CloudTrail in all regions; enable GuardDuty; implement least-privilege IAM policies; enable default encryption on all storage</td>
        <td style="text-align:center">{len(med)}</td></tr>'''
    body += f'''<tr><td><strong>Medium-term</strong><br>(30–90 days)</td>
        <td><span class="badge" style="background:#d97706">MEDIUM</span></td>
        <td>Implement VPC flow logging; configure CloudWatch alarms for critical events; establish automated secret rotation; deploy AWS Config rules</td>
        <td style="text-align:center">{len(findings) - len(crit_high) - len(med)}</td></tr>'''
    body += '</table></div>'

    return _endpoint_doc_wrap("Cloud Penetration Test Assessment", client_name, body)


def build_cloud_cis_report(data):
    """CIS AWS Foundations Benchmark Assessment."""
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = sorted(data.get("forge_findings", []), key=risk_sort)
    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in findings)

    CIS_SECTIONS = {
        "1. Identity and Access Management": {
            "patterns": [
                "iam", "root account", "mfa", "access key", "password policy",
                "credential", "service account", "console access", "role",
                "policy", "permission", "privilege", "cross-account", "assume role",
                "wildcard", "admin",
            ],
            "description": "Controls ensuring proper identity management, authentication, and least-privilege access.",
        },
        "2. Storage": {
            "patterns": [
                "s3", "bucket", "public access", "encryption", "versioning",
                "lifecycle", "acl", "block public", "object lock", "efs",
                "dynamodb", "backup", "storage",
            ],
            "description": "Controls for securing cloud storage services including S3, EFS, and DynamoDB.",
        },
        "3. Logging": {
            "patterns": [
                "cloudtrail", "access log", "audit log", "s3 access logging",
                "flow log", "trail", "log validation", "log file",
            ],
            "description": "Controls ensuring comprehensive audit trail and activity logging across all services.",
        },
        "4. Monitoring": {
            "patterns": [
                "cloudwatch", "alarm", "metric", "alert", "monitoring",
                "guardduty", "guard duty", "security hub", "config",
                "detective", "inspector", "event",
            ],
            "description": "Controls for real-time detection, alerting, and continuous monitoring of cloud resources.",
        },
        "5. Networking": {
            "patterns": [
                "security group", "nacl", "vpc", "subnet", "public ip",
                "internet gateway", "nat", "peering", "endpoint", "firewall",
                "0.0.0.0/0", "ingress", "egress", "route", "elastic ip",
                "load balancer", "cloudfront", "waf",
            ],
            "description": "Controls for network segmentation, traffic filtering, and restricting access to cloud resources.",
        },
        "6. Key Management": {
            "patterns": [
                "kms", "key management", "key rotation", "secrets manager",
                "ssm parameter", "acm", "certificate", "cmk", "encryption key",
            ],
            "description": "Controls for managing cryptographic keys and secrets used to protect data.",
        },
    }

    section_findings = {}
    section_risk_counts = {}
    for section, cfg in CIS_SECTIONS.items():
        sf = _filter_by_title_patterns(findings, cfg["patterns"])
        section_findings[section] = sf
        section_risk_counts[section] = Counter((f.get("risk") or "INFO").upper() for f in sf)

    cover = _build_scope_cover(client_name, "CIS AWS Foundations Benchmark Assessment",
                               meta, "Cloud Infrastructure", None, incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
This report maps {esc(client_name)}'s cloud infrastructure findings against the
CIS Amazon Web Services Foundations Benchmark. The CIS Benchmark provides a
prescriptive set of security configuration recommendations for AWS environments,
organized by control family. Each finding is mapped to the most relevant CIS
section to identify gaps in compliance and prioritize hardening efforts.</p>'''

    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(findings)}</div><div class="stat-label">Total Findings</div></div>'
    sections_with_findings = sum(1 for sf in section_findings.values() if sf)
    body += f'<div class="stat-card"><div class="stat-number">{sections_with_findings}/{len(CIS_SECTIONS)}</div><div class="stat-label">Sections Impacted</div></div>'
    mapped_ids = set(id(f) for sf in section_findings.values() for f in sf)
    body += f'<div class="stat-card"><div class="stat-number">{len(mapped_ids)}</div><div class="stat-label">Mapped Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(findings) - len(mapped_ids)}</div><div class="stat-label">Unmapped</div></div>'
    body += '</div>'
    body += _risk_cards_html(risk_counts)
    body += '</div>'

    body += '<div class="page"><h1>CIS Section Summary</h1>'
    body += '<table><tr><th>CIS Section</th><th>Findings</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Status</th></tr>'
    for section in CIS_SECTIONS:
        sf = section_findings[section]
        rc = section_risk_counts[section]
        count = len(sf)
        if count == 0:
            body += f'<tr><td>{esc(section)}</td><td style="text-align:center;color:var(--slate-400)">0</td>'
            body += '<td></td><td></td><td></td><td></td>'
            body += '<td><span style="color:#16a34a;font-weight:700">&#10003; Pass</span></td></tr>'
            continue
        worst = "INFO"
        for r in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if rc.get(r, 0) > 0:
                worst = r
                break
        status_color = RISK_COLORS.get(worst, "#666")
        body += f'<tr><td><strong>{esc(section)}</strong></td>'
        body += f'<td style="text-align:center;font-weight:700">{count}</td>'
        for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            c = rc.get(lvl, 0)
            color = RISK_COLORS.get(lvl, "#666")
            body += f'<td style="text-align:center;color:{color};font-weight:700">{c if c else "-"}</td>'
        body += f'<td><span style="color:{status_color};font-weight:700">&#10007; Fail</span></td></tr>'
    body += '</table></div>'

    for section, cfg in CIS_SECTIONS.items():
        sf = section_findings[section]
        if not sf:
            continue
        body += f'<div class="page"><h1>{esc(section)}</h1>'
        body += f'<p class="section-intro">{esc(cfg["description"])} {len(sf)} finding(s) identified.</p>'
        body += _findings_cards(sf)
        body += '</div>'

    unmapped = [f for f in findings if id(f) not in mapped_ids]
    if unmapped:
        body += '<div class="page"><h1>Findings Outside CIS Benchmark Scope</h1>'
        body += f'<p class="section-intro">{len(unmapped)} finding(s) do not map directly to CIS AWS Foundations Benchmark controls but remain relevant to the overall cloud security posture.</p>'
        body += _findings_cards(unmapped)
        body += '</div>'

    empty_sections = [s for s in CIS_SECTIONS if not section_findings[s]]
    body += '<div class="page"><h1>CIS Benchmark Gap Analysis</h1>'
    if empty_sections:
        body += f'''<p class="section-intro">The following CIS sections had no findings mapped.
This may indicate either strong compliance in those areas or limited assessment
coverage. A dedicated CIS benchmark scan (e.g., Prowler, ScoutSuite) is recommended
for full control-level coverage.</p>'''
        body += '<table><tr><th>CIS Section</th><th>Status</th><th>Recommendation</th></tr>'
        for section in empty_sections:
            body += f'<tr><td>{esc(section)}</td>'
            body += '<td><span style="color:#16a34a;font-weight:700">No Findings</span></td>'
            body += '<td style="font-size:8pt">Verify with dedicated CIS benchmark tooling for full control-level coverage</td></tr>'
        body += '</table>'
    else:
        body += '<p class="section-intro">All CIS sections had findings mapped. Review each section for specific control gaps.</p>'
    body += '</div>'

    return _endpoint_doc_wrap("CIS AWS Foundations Benchmark Assessment", client_name, body)


def build_cloud_compliance_report(data):
    """Cloud Regulatory Compliance Report — multi-framework gap analysis."""
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = sorted(data.get("forge_findings", []), key=risk_sort)
    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in findings)

    frameworks = {
        "NIST 800-53": {
            "field": "nist_800_53",
            "description": "NIST Special Publication 800-53 provides a catalog of security and privacy controls for federal information systems. These controls are widely adopted as a baseline for cloud security governance.",
        },
        "NIST CSF 2.0": {
            "field": "nist_csf2",
            "description": "The NIST Cybersecurity Framework 2.0 provides outcome-based guidance organized around Govern, Identify, Protect, Detect, Respond, and Recover functions.",
        },
        "NIST 800-171": {
            "field": "nist_800_171",
            "description": "NIST SP 800-171 protects Controlled Unclassified Information (CUI) in non-federal systems, commonly required for government contractors.",
        },
        "PCI DSS 4.0": {
            "field": "pci_dss_4",
            "description": "The Payment Card Industry Data Security Standard v4.0 establishes requirements for organizations that store, process, or transmit cardholder data.",
        },
        "ISO 27001": {
            "field": "iso_27001",
            "description": "ISO/IEC 27001 specifies requirements for establishing, implementing, and continually improving an information security management system (ISMS).",
        },
        "ISO 27002": {
            "field": "iso_27002",
            "description": "ISO/IEC 27002 provides implementation guidance for information security controls referenced by ISO 27001.",
        },
        "SOC 2": {
            "field": "soc2",
            "description": "SOC 2 Trust Services Criteria cover security, availability, processing integrity, confidentiality, and privacy for service organizations.",
        },
        "HITRUST CSF": {
            "field": "hitrust",
            "description": "The HITRUST Common Security Framework integrates healthcare-specific regulatory requirements (HIPAA) with industry standards.",
        },
        "GDPR": {
            "field": "gdpr",
            "description": "The General Data Protection Regulation governs data protection and privacy for individuals within the European Union.",
        },
    }

    framework_findings = {}
    for fw_label, fw_cfg in frameworks.items():
        field = fw_cfg["field"]
        mapped = [f for f in findings if f.get(field)]
        framework_findings[fw_label] = mapped

    cover = _build_scope_cover(client_name, "Cloud Regulatory Compliance Report",
                               meta, "Cloud Infrastructure", None, incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
This report maps cloud infrastructure security findings from {esc(client_name)}'s
AWS environment against major regulatory and compliance frameworks. This cross-reference
enables compliance, legal, and governance teams to understand the regulatory impact of
identified cloud misconfigurations and prioritize remediation to satisfy audit requirements.</p>'''

    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(findings)}</div><div class="stat-label">Total Findings</div></div>'
    fw_with_hits = sum(1 for v in framework_findings.values() if v)
    body += f'<div class="stat-card"><div class="stat-number">{fw_with_hits}/{len(frameworks)}</div><div class="stat-label">Frameworks Impacted</div></div>'
    mapped_ids = set(id(f) for fw_f in framework_findings.values() for f in fw_f)
    body += f'<div class="stat-card"><div class="stat-number">{len(mapped_ids)}</div><div class="stat-label">Mapped Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(findings) - len(mapped_ids)}</div><div class="stat-label">Unmapped</div></div>'
    body += '</div>'
    body += _risk_cards_html(risk_counts)
    body += '</div>'

    body += '<div class="page"><h1>Framework Coverage Matrix</h1>'
    body += '<p class="section-intro">Summary of findings mapped to each compliance framework. Frameworks with zero mappings indicate findings have not yet been enriched with that framework\'s control references.</p>'
    body += '<table><tr><th>Framework</th><th>Findings</th><th>Critical</th><th>High</th><th>Medium</th><th>Controls Hit</th></tr>'
    for fw_label, fw_cfg in frameworks.items():
        fw_f = framework_findings[fw_label]
        field = fw_cfg["field"]
        if not fw_f:
            body += f'<tr><td>{esc(fw_label)}</td><td style="text-align:center;color:var(--slate-400)">0</td><td></td><td></td><td></td><td style="text-align:center;color:var(--slate-400)">-</td></tr>'
            continue
        rc = Counter((f.get("risk") or "INFO").upper() for f in fw_f)
        controls = set()
        for f in fw_f:
            ctrls = f.get(field, [])
            if isinstance(ctrls, str):
                ctrls = [c.strip() for c in ctrls.split(",") if c.strip()]
            controls.update(ctrls)
        body += f'<tr><td><strong>{esc(fw_label)}</strong></td>'
        body += f'<td style="text-align:center;font-weight:700">{len(fw_f)}</td>'
        for lvl in ("CRITICAL", "HIGH", "MEDIUM"):
            c = rc.get(lvl, 0)
            color = RISK_COLORS.get(lvl, "#666")
            body += f'<td style="text-align:center;color:{color};font-weight:700">{c if c else "-"}</td>'
        body += f'<td style="text-align:center">{len(controls)}</td></tr>'
    body += '</table></div>'

    for fw_label, fw_cfg in frameworks.items():
        fw_f = framework_findings[fw_label]
        field = fw_cfg["field"]
        if not fw_f:
            continue
        fw_f_sorted = sorted(fw_f, key=risk_sort)
        control_groups = defaultdict(list)
        for f in fw_f_sorted:
            ctrls = f.get(field, [])
            if isinstance(ctrls, str):
                ctrls = [c.strip() for c in ctrls.split(",") if c.strip()]
            for ctrl in ctrls:
                control_groups[ctrl].append(f)

        body += f'<div class="page"><h1>{esc(fw_label)} Gap Analysis</h1>'
        body += f'<p class="section-intro">{esc(fw_cfg["description"])}</p>'
        body += f'<p style="margin-bottom:10px;"><strong>{len(fw_f)}</strong> finding(s) mapped to <strong>{len(control_groups)}</strong> control(s).</p>'
        body += '<table><tr><th>Control</th><th>Findings</th><th>Highest Risk</th><th>Representative Finding</th></tr>'
        for ctrl in sorted(control_groups.keys()):
            ctrl_f = control_groups[ctrl]
            worst = "INFO"
            for f in ctrl_f:
                r = (f.get("risk") or "INFO").upper()
                if RISK_ORDER.get(r, 5) < RISK_ORDER.get(worst, 5):
                    worst = r
            color = RISK_COLORS.get(worst, "#666")
            rep_title = esc((ctrl_f[0].get("title", ""))[:60])
            body += f'<tr><td><code>{esc(ctrl)}</code></td>'
            body += f'<td style="text-align:center">{len(ctrl_f)}</td>'
            body += f'<td><span class="badge" style="background:{color}">{worst}</span></td>'
            body += f'<td style="font-size:8pt">{rep_title}</td></tr>'
        body += '</table></div>'

    # ── OWASP Cloud-Native Application Security Top 10 ──
    CNAS_CATEGORIES = {
        "CNAS-1: Insecure Cloud, Container, or Orchestration Configuration": {
            "patterns": [
                "s3", "bucket", "public access", "security group", "nacl", "vpc",
                "encryption", "versioning", "acl", "block public", "0.0.0.0/0",
                "ingress", "egress", "misconfigur", "default", "permissive",
                "unrestricted", "open to internet", "iam", "policy", "role",
                "cloudfront", "waf", "kms", "efs", "dynamodb", "sns", "sqs",
                "lambda", "ecs", "rds", "ec2",
            ],
            "description": "Insecure defaults, overly permissive configurations, and missing security controls across cloud services, containers, and orchestration platforms.",
        },
        "CNAS-3: Improper Authentication and Authorization": {
            "patterns": [
                "mfa", "root account", "access key", "password policy",
                "credential", "console access", "privilege", "permission",
                "wildcard", "admin", "cross-account", "assume role",
                "service account", "excessive",
            ],
            "description": "Weak authentication mechanisms, missing MFA, overly broad IAM policies, and improper authorization boundaries.",
        },
        "CNAS-5: Insecure Secrets Management": {
            "patterns": [
                "secret", "key management", "kms", "rotation", "access key",
                "credential", "password", "secrets manager", "ssm parameter",
                "certificate", "acm", "hardcoded", "plaintext", "exposed key",
            ],
            "description": "Secrets stored insecurely, missing rotation, exposed credentials, and inadequate key management practices.",
        },
        "CNAS-6: Over-Permissive or Insecure Network Policies": {
            "patterns": [
                "security group", "nacl", "vpc", "subnet", "public ip",
                "internet gateway", "nat", "peering", "firewall",
                "0.0.0.0/0", "ingress", "egress", "route", "elastic ip",
                "load balancer", "cloudfront", "endpoint",
            ],
            "description": "Network segmentation failures, overly permissive firewall rules, and missing network-level access controls.",
        },
        "CNAS-10: Ineffective Logging and Monitoring": {
            "patterns": [
                "cloudtrail", "cloudwatch", "flow log", "access log",
                "audit log", "monitoring", "alert", "guardduty", "guard duty",
                "detective", "security hub", "config", "inspector",
                "log", "event",
            ],
            "description": "Gaps in audit logging, missing threat detection services, and insufficient monitoring that allow attacks to go undetected.",
        },
    }
    CNAS_NA = {
        "CNAS-2: Injection Flaws": "Application-layer vulnerability — not assessed by cloud infrastructure audit.",
        "CNAS-4: CI/CD Pipeline Vulnerabilities": "Build/deploy pipeline security — not assessed by cloud infrastructure audit.",
        "CNAS-7: Using Components with Known Vulnerabilities": "Software composition analysis — not assessed by cloud infrastructure audit.",
        "CNAS-8: Improper Assets Management": "Partial overlap with resource inventory; dedicated assessment recommended.",
        "CNAS-9: Inadequate Compute Resource Quota Limits": "Resource quota/DoS protection — not currently assessed by Forge.",
    }

    cnas_section_findings = {}
    for cat, cfg in CNAS_CATEGORIES.items():
        cnas_section_findings[cat] = _filter_by_title_patterns(findings, cfg["patterns"])

    cnas_mapped_ids = set(id(f) for sf in cnas_section_findings.values() for f in sf)
    cnas_total_mapped = len(cnas_mapped_ids)

    body += '<div class="page"><h1>OWASP Cloud-Native Application Security Top 10</h1>'
    body += f'''<p class="section-intro">The OWASP Cloud-Native Application Security (CNAS)
Top 10 identifies the most critical security risks in cloud-native environments.
{cnas_total_mapped} finding(s) map to {sum(1 for sf in cnas_section_findings.values() if sf)}
of the {len(CNAS_CATEGORIES)} applicable CNAS categories. {len(CNAS_NA)} categories are
outside the scope of a cloud infrastructure configuration audit.</p>'''

    body += '<table><tr><th>CNAS Category</th><th>Findings</th><th>Highest Risk</th><th>Status</th></tr>'
    for cat in CNAS_CATEGORIES:
        sf = cnas_section_findings[cat]
        if not sf:
            body += f'<tr><td>{esc(cat)}</td><td style="text-align:center;color:var(--slate-400)">0</td><td></td>'
            body += '<td style="font-size:8pt;color:var(--slate-400)">No findings mapped</td></tr>'
            continue
        rc = Counter((f.get("risk") or "INFO").upper() for f in sf)
        worst = "INFO"
        for r in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if rc.get(r, 0) > 0:
                worst = r
                break
        color = RISK_COLORS.get(worst, "#666")
        body += f'<tr><td><strong>{esc(cat)}</strong></td>'
        body += f'<td style="text-align:center;font-weight:700">{len(sf)}</td>'
        body += f'<td><span class="badge" style="background:{color}">{worst}</span></td>'
        body += f'<td><span style="color:{color};font-weight:700">&#10007; Fail</span></td></tr>'
    for cat, reason in CNAS_NA.items():
        body += f'<tr><td style="color:var(--slate-400)">{esc(cat)}</td>'
        body += '<td style="text-align:center;color:var(--slate-400)">—</td><td></td>'
        body += f'<td style="font-size:7.5pt;color:var(--slate-400)">{esc(reason)}</td></tr>'
    body += '</table></div>'

    for cat, cfg in CNAS_CATEGORIES.items():
        sf = cnas_section_findings[cat]
        if not sf:
            continue
        body += f'<div class="page"><h2>{esc(cat)}</h2>'
        body += f'<p class="section-intro">{esc(cfg["description"])} {len(sf)} finding(s) identified.</p>'
        body += _findings_cards(sf)
        body += '</div>'

    # ── Enrichment Note ──
    unenriched = len(findings) - len(mapped_ids)
    if unenriched > 0:
        body += '<div class="page"><h1>Enrichment Coverage Note</h1>'
        body += f'''<p class="section-intro">
{unenriched} of {len(findings)} finding(s) have not been mapped to any compliance
framework. This typically indicates the findings have not yet been processed through
catalogue-based compliance enrichment. Running the Arbiter enrichment pipeline against
these findings will populate NIST, PCI DSS, ISO 27001, SOC 2, and other framework
mappings for more complete compliance coverage.</p>'''
        body += '<p>Findings without compliance mappings are still included in the pentest and CIS benchmark reports.</p>'
        body += '</div>'

    return _endpoint_doc_wrap("Cloud Regulatory Compliance Report", client_name, body)


def build_cloud_exec_report(data):
    """Cloud Executive Summary — non-technical leadership overview."""
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = sorted(data.get("forge_findings", []), key=risk_sort)
    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in findings)
    service_dashboard = data.get("service_dashboard", [])
    iam_matrix = data.get("iam_matrix", [])

    cover = _build_scope_cover(client_name, "Cloud Security Executive Summary",
                               meta, "Cloud Infrastructure", None, incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Overview</h1>'
    crit = risk_counts.get("CRITICAL", 0)
    high = risk_counts.get("HIGH", 0)
    med = risk_counts.get("MEDIUM", 0)
    total = len(findings)
    svc_affected = len([s for s in service_dashboard if s.get("findings", 0) > 0])
    users_no_mfa = sum(1 for u in iam_matrix if u.get("mfa_active") in ("false", False))

    body += f'''<p class="section-intro">
the assessor performed a cloud infrastructure security assessment of {esc(client_name)}'s
Amazon Web Services (AWS) environment. The assessment identified <strong>{total}
finding(s)</strong> across <strong>{svc_affected} AWS service(s)</strong>, including
<strong style="color:#dc2626">{crit} critical</strong> and
<strong style="color:#ea580c">{high} high</strong> severity issues that require
immediate attention.</p>'''

    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{total}</div><div class="stat-label">Total Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#dc2626">{crit}</div><div class="stat-label">Critical</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#ea580c">{high}</div><div class="stat-label">High</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{svc_affected}</div><div class="stat-label">Services Affected</div></div>'
    body += '</div>'
    body += _risk_cards_html(risk_counts)

    pie = _build_risk_pie(risk_counts)
    if pie:
        body += '<div class="risk-charts-row">'
        body += f'<div class="risk-chart-col"><h4>Risk Distribution</h4>{pie}</div>'
        body += '</div>'
    body += _exec_risk_heatmap(risk_counts, total)
    body += '</div>'

    body += '<div class="page"><h1>Risk Posture Assessment</h1>'
    if crit > 0:
        posture = "Critical"
        posture_color = "#dc2626"
        posture_text = f'''{esc(client_name)}'s cloud environment is at <strong>critical risk</strong>.
{crit} critical finding(s) present immediate exploitation opportunities that could result
in unauthorized access to production data, account compromise, or complete environment takeover.'''
    elif high > 3:
        posture = "High"
        posture_color = "#ea580c"
        posture_text = f'''{esc(client_name)}'s cloud environment has a <strong>high risk</strong>
posture. {high} high-severity finding(s) represent significant attack surface that could
be exploited for data access, privilege escalation, or lateral movement.'''
    elif high > 0:
        posture = "Moderate"
        posture_color = "#d97706"
        posture_text = f'''{esc(client_name)}'s cloud environment has a <strong>moderate risk</strong>
posture. While no critical issues were found, {high} high-severity finding(s) warrant
prompt remediation to reduce the attack surface.'''
    else:
        posture = "Low"
        posture_color = "#16a34a"
        posture_text = f'''{esc(client_name)}'s cloud environment demonstrates a <strong>low risk</strong>
posture with primarily medium and low severity findings. Continue maintaining security
hygiene and address remaining findings on a standard remediation schedule.'''

    body += f'''<div style="background:{posture_color}15;border:2px solid {posture_color};
border-radius:8px;padding:16px 20px;margin-bottom:16px;">
<div style="font-size:11pt;font-weight:700;color:{posture_color};margin-bottom:6px;">
Overall Risk: {posture}</div>
<p style="font-size:9pt;margin:0;">{posture_text}</p></div>'''
    body += '</div>'

    if service_dashboard:
        body += '<div class="page"><h1>AWS Service Impact</h1>'
        body += '<p class="section-intro">Distribution of findings across AWS services in the assessed environment.</p>'
        body += '<table><tr><th>AWS Service</th><th>Resources</th><th>Findings</th><th>Highest Severity</th></tr>'
        for svc in sorted(service_dashboard, key=lambda s: s.get("findings", 0), reverse=True):
            if svc.get("findings", 0) == 0:
                continue
            name = esc(svc.get("service", ""))
            resources = svc.get("resources", 0)
            svc_findings = svc.get("findings", 0)
            if svc.get("critical", 0) > 0:
                worst = "CRITICAL"
            elif svc.get("high", 0) > 0:
                worst = "HIGH"
            elif svc.get("medium", 0) > 0:
                worst = "MEDIUM"
            elif svc.get("low", 0) > 0:
                worst = "LOW"
            else:
                worst = "INFO"
            color = RISK_COLORS.get(worst, "#666")
            body += f'<tr><td><strong>{name}</strong></td>'
            body += f'<td style="text-align:center">{resources}</td>'
            body += f'<td style="text-align:center;font-weight:700">{svc_findings}</td>'
            body += f'<td><span class="badge" style="background:{color}">{worst}</span></td></tr>'
        body += '</table></div>'

    top = findings[:10]
    if top:
        body += '<div class="page"><h1>Top Findings</h1>'
        body += '<p class="section-intro">The most severe findings from the cloud assessment, ranked by risk.</p>'
        body += '<table><tr><th>#</th><th>Risk</th><th>Finding</th><th>Service</th></tr>'
        for idx, f in enumerate(top, 1):
            risk = (f.get("risk") or "INFO").upper()
            color = RISK_COLORS.get(risk, "#666")
            title = esc(f.get("title", ""))
            svc = ""
            for s in ("S3", "IAM", "EC2", "RDS", "KMS", "Lambda", "VPC", "CloudTrail",
                       "CloudWatch", "GuardDuty", "Security Hub", "CloudFront", "SNS",
                       "SQS", "EFS", "ACM", "Secrets Manager", "OpenSearch", "DynamoDB", "ECS"):
                if s.lower() in title.lower():
                    svc = s
                    break
            body += f'<tr><td>{idx}</td><td><span class="badge" style="background:{color}">{risk}</span></td>'
            body += f'<td style="font-size:8pt">{title}</td>'
            body += f'<td style="font-size:8pt">{esc(svc)}</td></tr>'
        body += '</table></div>'

    body += '<div class="page"><h1>Strategic Recommendations</h1>'
    body += f'''<p class="section-intro">Based on the cloud security assessment of {esc(client_name)}'s
AWS environment, the assessor recommends the following strategic actions.</p>'''
    body += '''<table>
    <tr><th>Priority</th><th>Recommendation</th><th>Business Impact</th></tr>
    <tr><td><span class="badge" style="background:#dc2626">IMMEDIATE</span></td>
        <td>Enforce multi-factor authentication on all IAM users and restrict root account usage</td>
        <td>Prevents account compromise and unauthorized access to production resources</td></tr>
    <tr><td><span class="badge" style="background:#dc2626">IMMEDIATE</span></td>
        <td>Block public access to all S3 buckets and enable default encryption</td>
        <td>Prevents data exposure, regulatory violations, and reputational damage</td></tr>
    <tr><td><span class="badge" style="background:#ea580c">HIGH</span></td>
        <td>Implement comprehensive logging (CloudTrail, VPC Flow Logs, S3 Access Logs)</td>
        <td>Enables incident detection, forensic investigation, and compliance audit trails</td></tr>
    <tr><td><span class="badge" style="background:#ea580c">HIGH</span></td>
        <td>Review and restrict security group rules — eliminate 0.0.0.0/0 ingress</td>
        <td>Reduces external attack surface and prevents unauthorized network access</td></tr>
    <tr><td><span class="badge" style="background:#d97706">MEDIUM</span></td>
        <td>Enable GuardDuty, Security Hub, and AWS Config for continuous monitoring</td>
        <td>Provides automated threat detection and continuous compliance monitoring</td></tr>
    <tr><td><span class="badge" style="background:#d97706">MEDIUM</span></td>
        <td>Implement least-privilege IAM policies with automated access reviews</td>
        <td>Minimizes blast radius of credential compromise and satisfies compliance requirements</td></tr>
</table></div>'''

    return _endpoint_doc_wrap("Cloud Security Executive Summary", client_name, body)


def build_quill_report(data):
    """Mobile Application Security Report — Quill findings."""
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = sorted(data.get("quill_findings", []), key=risk_sort)
    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in findings)

    storage_patterns = [
        "insecure storage", "shared preference", "sqlite", "realm",
        "keychain", "keystore", "plaintext", "cleartext", "hardcoded",
        "embedded", "api key", "secret", "token", "credential",
        "certificate pinning", "pin", "backup",
    ]
    network_patterns = [
        "ssl", "tls", "certificate", "http ", "cleartext traffic",
        "network security config", "ats", "transport security",
        "proxy", "interceptable", "man-in-the-middle", "mitm",
    ]
    code_patterns = [
        "obfuscation", "root detection", "jailbreak", "tamper",
        "debug", "reverse engineer", "decompil", "binary protection",
        "code injection", "hook", "frida", "magisk",
    ]
    data_leak_patterns = [
        "clipboard", "screenshot", "log", "analytics", "tracking",
        "third-party", "sdk", "webview", "deep link", "intent",
        "broadcast", "content provider", "exported",
    ]
    malicious_patterns = [
        "malicious", "malware", "trojan", "backdoor", "suspicious",
        "obfuscated url", "c2", "exfiltration", "data leak",
        "tracking", "fingerprint",
    ]

    storage_findings = _filter_by_title_patterns(findings, storage_patterns)
    network_findings = _filter_by_title_patterns(findings, network_patterns)
    code_findings = _filter_by_title_patterns(findings, code_patterns)
    leak_findings = _filter_by_title_patterns(findings, data_leak_patterns)
    malicious_findings = _filter_by_title_patterns(findings, malicious_patterns)

    cover = _build_scope_cover(client_name, "Mobile Application Security Report", meta, incomplete=incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
This report presents mobile application security findings from the Quill mobile
assessment engine for {esc(client_name)}'s mobile application(s). The assessment
covers data storage security, network communication, binary protections, data
leakage vectors, and indicators of malicious behavior including suspicious URLs,
data exfiltration paths, and unauthorized tracking.</p>'''
    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(findings)}</div><div class="stat-label">Total Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#dc2626">{len(storage_findings)}</div><div class="stat-label">Storage Issues</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#ea580c">{len(network_findings)}</div><div class="stat-label">Network Issues</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(code_findings)}</div><div class="stat-label">Binary Issues</div></div>'
    body += '</div>'
    body += _risk_cards_html(risk_counts)

    pie = _build_risk_pie(risk_counts)
    if pie:
        body += '<div class="risk-charts-row">'
        body += f'<div class="risk-chart-col"><h4>Risk Distribution</h4>{pie}</div>'
        body += '</div>'
    body += '</div>'

    if storage_findings:
        body += '<div class="page"><h1>Insecure Data Storage</h1>'
        body += '''<p class="section-intro">Findings related to insecure data storage including
plaintext credentials, hardcoded secrets, insecure SharedPreferences/Keychain usage,
embedded API keys, and backup exposure that could allow data extraction from the device.</p>'''
        body += _findings_cards(storage_findings)
        body += '</div>'

    if network_findings:
        body += '<div class="page"><h1>Network Communication Security</h1>'
        body += '''<p class="section-intro">Findings related to insecure network communication
including missing certificate pinning, cleartext HTTP traffic, weak TLS configuration,
and susceptibility to man-in-the-middle attacks that could intercept sensitive data.</p>'''
        body += _findings_cards(network_findings)
        body += '</div>'

    if malicious_findings:
        body += '<div class="page"><h1>Malicious Indicators &amp; Data Exfiltration</h1>'
        body += '''<p class="section-intro">Findings indicating potential malicious behavior
within the application including suspicious URLs, unauthorized tracking/fingerprinting,
obfuscated communication channels, and data exfiltration paths.</p>'''
        body += _findings_cards(malicious_findings)
        body += '</div>'

    if code_findings:
        body += '<div class="page"><h1>Binary &amp; Code Protections</h1>'
        body += '''<p class="section-intro">Findings related to application binary protections
including missing obfuscation, absent root/jailbreak detection, debug mode enabled, and
insufficient tamper detection that increase reverse engineering risk.</p>'''
        body += _findings_cards(code_findings)
        body += '</div>'

    if leak_findings:
        body += '<div class="page"><h1>Data Leakage Vectors</h1>'
        body += '''<p class="section-intro">Findings related to data leakage through clipboard,
screenshots, logs, exported components, WebViews, deep links, and third-party SDKs.</p>'''
        body += _findings_cards(leak_findings)
        body += '</div>'

    seen = set(id(f) for f in storage_findings + network_findings + code_findings + leak_findings + malicious_findings)
    remaining = [f for f in findings if id(f) not in seen]
    if remaining:
        body += '<div class="page"><h1>Additional Mobile Findings</h1>'
        body += _findings_cards(remaining)
        body += '</div>'

    body += '''<div class="page"><h1>Mobile Security Recommendations</h1>
<table>
    <tr><th>Priority</th><th>Recommendation</th><th>Mitigates</th></tr>
    <tr><td><span class="badge" style="background:#dc2626">CRITICAL</span></td>
        <td>Remove all hardcoded credentials, API keys, and secrets; use platform secure storage (Keychain/Keystore) with hardware-backed keys</td>
        <td>Credential extraction, API abuse, account compromise</td></tr>
    <tr><td><span class="badge" style="background:#dc2626">CRITICAL</span></td>
        <td>Implement certificate pinning for all API endpoints; enforce TLS 1.2+ with strong cipher suites</td>
        <td>Man-in-the-middle, traffic interception, credential theft</td></tr>
    <tr><td><span class="badge" style="background:#ea580c">HIGH</span></td>
        <td>Enable code obfuscation (ProGuard/R8 for Android, Swift compilation flags for iOS) and implement tamper detection</td>
        <td>Reverse engineering, code modification, cloned apps</td></tr>
    <tr><td><span class="badge" style="background:#ea580c">HIGH</span></td>
        <td>Audit all third-party SDKs for data collection scope; remove unnecessary tracking and analytics libraries</td>
        <td>Unauthorized data collection, privacy violations, malicious SDK behavior</td></tr>
    <tr><td><span class="badge" style="background:#d97706">MEDIUM</span></td>
        <td>Disable clipboard copy for sensitive fields; prevent screenshots on sensitive screens; sanitize log output</td>
        <td>Data leakage through side channels</td></tr>
</table></div>'''

    return _endpoint_doc_wrap("Mobile Application Security Report", client_name, body)


def build_isotope_report(data):
    """File & Artifact Analysis Report — Isotope findings."""
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = sorted(data.get("isotope_findings", []), key=risk_sort)
    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in findings)

    malware_patterns = [
        "malware", "malicious", "virus", "trojan", "backdoor",
        "ransomware", "dropper", "payload", "exploit", "shellcode",
        "obfuscated", "packed", "suspicious binary", "yara",
    ]
    metadata_patterns = [
        "metadata", "exif", "author", "comment", "hidden",
        "embedded", "macro", "vba", "ole", "rtf",
        "pdf javascript", "openxml",
    ]
    credential_patterns = [
        "credential", "password", "key", "token", "secret",
        "certificate", "private key", "ssh key", "api key",
        "connection string", "config",
    ]
    link_patterns = [
        "url", "link", "phishing", "malicious link", "redirect",
        "domain", "callback", "c2", "beacon", "external reference",
    ]

    malware_findings = _filter_by_title_patterns(findings, malware_patterns)
    metadata_findings = _filter_by_title_patterns(findings, metadata_patterns)
    credential_findings = _filter_by_title_patterns(findings, credential_patterns)
    link_findings = _filter_by_title_patterns(findings, link_patterns)

    cover = _build_scope_cover(client_name, "File & Artifact Analysis Report", meta, incomplete=incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
This report presents the file and artifact analysis findings from the Isotope file
analysis engine across {esc(client_name)}'s environment. Isotope examines files for
malicious content, embedded credentials, suspicious metadata, malicious links and
URLs, hidden macros, and other indicators that represent security risks including
data exfiltration channels, command-and-control callbacks, and phishing indicators.</p>'''
    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{len(findings)}</div><div class="stat-label">Total Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#dc2626">{len(malware_findings)}</div><div class="stat-label">Malware/Suspicious</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#ea580c">{len(credential_findings)}</div><div class="stat-label">Credentials</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(link_findings)}</div><div class="stat-label">Malicious Links</div></div>'
    body += '</div>'
    body += _risk_cards_html(risk_counts)

    pie = _build_risk_pie(risk_counts)
    if pie:
        body += '<div class="risk-charts-row">'
        body += f'<div class="risk-chart-col"><h4>Risk Distribution</h4>{pie}</div>'
        body += '</div>'
    body += '</div>'

    if malware_findings:
        body += '<div class="page"><h1>Malicious File Detection</h1>'
        body += '''<p class="section-intro">Files identified as potentially malicious through
signature matching (YARA rules), behavioral analysis, and structural anomaly detection.
These findings include malware, trojans, backdoors, exploit payloads, obfuscated/packed
binaries, and suspicious executables requiring immediate quarantine and investigation.</p>'''
        body += _findings_cards(malware_findings)
        body += '</div>'

    if link_findings:
        body += '<div class="page"><h1>Malicious Links &amp; URLs</h1>'
        body += '''<p class="section-intro">Malicious or suspicious URLs, links, and external
references found within analyzed files. These include phishing URLs, command-and-control
callback addresses, redirect chains, and domains associated with malicious activity.</p>'''
        body += _findings_cards(link_findings)
        body += '</div>'

    if credential_findings:
        body += '<div class="page"><h1>Embedded Credentials &amp; Secrets</h1>'
        body += '''<p class="section-intro">Credentials, secrets, API keys, certificates, and
connection strings found embedded within files. These represent immediate exposure risks
as the credentials may provide unauthorized access to systems and services.</p>'''
        body += _findings_cards(credential_findings)
        body += '</div>'

    if metadata_findings:
        body += '<div class="page"><h1>Metadata &amp; Hidden Content</h1>'
        body += '''<p class="section-intro">Findings from file metadata analysis including
hidden comments, embedded macros (VBA/OLE), suspicious PDF JavaScript, EXIF data leakage,
and other metadata that could expose internal information or contain malicious payloads.</p>'''
        body += _findings_cards(metadata_findings)
        body += '</div>'

    seen = set(id(f) for f in malware_findings + metadata_findings + credential_findings + link_findings)
    remaining = [f for f in findings if id(f) not in seen]
    if remaining:
        body += '<div class="page"><h1>Additional File Analysis Findings</h1>'
        body += _findings_cards(remaining)
        body += '</div>'

    body += '''<div class="page"><h1>File Security Recommendations</h1>
<table>
    <tr><th>Priority</th><th>Recommendation</th><th>Mitigates</th></tr>
    <tr><td><span class="badge" style="background:#dc2626">CRITICAL</span></td>
        <td>Quarantine and forensically analyze all files flagged as malicious; check for persistence and lateral spread</td>
        <td>Active malware, backdoors, ransomware</td></tr>
    <tr><td><span class="badge" style="background:#dc2626">CRITICAL</span></td>
        <td>Immediately rotate all credentials found embedded in files; revoke exposed API keys and certificates</td>
        <td>Unauthorized access via exposed credentials</td></tr>
    <tr><td><span class="badge" style="background:#ea580c">HIGH</span></td>
        <td>Block access to all identified malicious URLs/domains at the proxy/firewall level; add to threat intelligence blocklist</td>
        <td>Phishing, C2 callbacks, malicious redirects</td></tr>
    <tr><td><span class="badge" style="background:#ea580c">HIGH</span></td>
        <td>Disable Office macros by default via Group Policy; enable only for digitally signed macros from trusted publishers</td>
        <td>Macro-based malware delivery, VBA exploits</td></tr>
    <tr><td><span class="badge" style="background:#d97706">MEDIUM</span></td>
        <td>Implement file metadata stripping on outbound documents to prevent information leakage through EXIF, comments, and author fields</td>
        <td>Internal information disclosure, social engineering</td></tr>
    <tr><td><span class="badge" style="background:#d97706">MEDIUM</span></td>
        <td>Deploy endpoint detection (EDR) with YARA rule scanning and behavioral analysis for real-time file threat detection</td>
        <td>Undetected malware, zero-day file exploits</td></tr>
</table></div>'''

    return _endpoint_doc_wrap("File & Artifact Analysis Report", client_name, body)


# ═══════════════════════════════════════════════════════════════════════
#  UNIVERSAL / CROSS-SCOPE BUILDERS
# ═══════════════════════════════════════════════════════════════════════

def build_remediation_report(data):
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = sorted(data.get("findings", []), key=risk_sort)
    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in findings)
    total = len(findings)

    cover = _build_scope_cover(client_name, "Remediation Prioritization Report",
                               meta, "All Scopes", None, incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
This report provides a prioritized remediation roadmap for all findings identified
across all scopes of the {esc(client_name)} penetration test engagement. Findings are
ranked by risk severity, exploitation likelihood, and estimated remediation effort
to help security and engineering teams allocate resources effectively.</p>'''

    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{total}</div><div class="stat-label">Total Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#dc2626">{risk_counts.get("CRITICAL", 0)}</div><div class="stat-label">Critical</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#ea580c">{risk_counts.get("HIGH", 0)}</div><div class="stat-label">High</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#d97706">{risk_counts.get("MEDIUM", 0)}</div><div class="stat-label">Medium</div></div>'
    body += '</div>'
    body += _risk_cards_html(risk_counts)
    body += _exec_risk_heatmap(risk_counts, total)
    body += '</div>'

    effort_buckets = {"Easy": [], "Moderate": [], "Significant": [], "Major": [], "Unknown": []}
    for f in findings:
        effort = (f.get("remediation_effort") or "").strip()
        if effort in effort_buckets:
            effort_buckets[effort].append(f)
        else:
            effort_buckets["Unknown"].append(f)

    body += '<div class="page"><h1>Remediation Effort Matrix</h1>'
    body += '''<p class="section-intro">Findings grouped by estimated remediation effort,
within each group sorted by risk severity. Prioritize Critical+Easy items first (quick wins),
then Critical+Moderate, then High+Easy, and so on.</p>'''
    body += '<table><tr><th>Effort</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th><th>Total</th></tr>'
    for effort in ("Easy", "Moderate", "Significant", "Major", "Unknown"):
        bucket = effort_buckets[effort]
        if not bucket:
            continue
        rc = Counter((f.get("risk") or "INFO").upper() for f in bucket)
        body += f'<tr><td><strong>{effort}</strong></td>'
        for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            c = rc.get(lvl, 0)
            body += f'<td style="text-align:center">{c if c else "-"}</td>'
        body += f'<td style="text-align:center;font-weight:700;">{len(bucket)}</td></tr>'
    body += '</table></div>'

    for priority_label, risk_levels in [("Immediate (0-30 days)", ["CRITICAL"]),
                                         ("Short-Term (30-90 days)", ["HIGH"]),
                                         ("Medium-Term (90-180 days)", ["MEDIUM"]),
                                         ("Long-Term / Informational", ["LOW", "INFO"])]:
        priority_f = [f for f in findings if (f.get("risk") or "INFO").upper() in risk_levels]
        if not priority_f:
            continue
        body += f'<div class="page"><h1>{esc(priority_label)}</h1>'
        body += f'<p class="section-intro">{len(priority_f)} finding(s) in this priority tier.</p>'
        body += '<table><tr><th>#</th><th>Risk</th><th>Finding</th><th>Target</th><th>Effort</th><th>Remediation</th></tr>'
        for idx, f in enumerate(priority_f, 1):
            risk = (f.get("risk") or "INFO").upper()
            color = RISK_COLORS.get(risk, "#666")
            ip = esc(f.get("ip", ""))
            port = f.get("port", "")
            target = f"{ip}:{port}" if ip and port else ip
            effort = esc(f.get("remediation_effort", ""))
            remed = esc((f.get("remediation") or "")[:200])
            body += f'<tr><td>{idx}</td><td><span class="badge" style="background:{color};">{risk}</span></td>'
            body += f'<td style="font-size:8pt;">{esc(f.get("title", ""))}</td>'
            body += f'<td><code style="font-size:7pt;">{target}</code></td>'
            body += f'<td style="font-size:8pt;">{effort}</td>'
            body += f'<td style="font-size:7.5pt;">{remed}</td></tr>'
        body += '</table></div>'

    return _endpoint_doc_wrap("Remediation Prioritization Report", client_name, body)


def build_compliance_matrix_report(data):
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = sorted(data.get("findings", []), key=risk_sort)
    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in findings)
    total = len(findings)

    frameworks = {
        "NIST CSF 2.0": "nist_csf2",
        "NIST 800-53": "nist_800_53",
        "NIST 800-171": "nist_800_171",
        "PCI DSS 4.0": "pci_dss_4",
        "ISO 27001": "iso_27001",
        "ISO 27002": "iso_27002",
        "SOC 2": "soc2",
        "HITRUST": "hitrust",
        "GDPR": "gdpr",
    }

    framework_findings = {}
    for fw_label, field in frameworks.items():
        mapped = [f for f in findings if f.get(field)]
        framework_findings[fw_label] = mapped

    cover = _build_scope_cover(client_name, "Compliance Matrix Report",
                               meta, "All Scopes", None, incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
This report maps all penetration test findings from the {esc(client_name)} engagement
across major compliance and regulatory frameworks. This cross-reference enables compliance
teams to understand the regulatory impact of identified vulnerabilities and prioritize
remediation efforts by framework requirement.</p>'''

    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{total}</div><div class="stat-label">Total Findings</div></div>'
    fw_with_hits = sum(1 for v in framework_findings.values() if v)
    body += f'<div class="stat-card"><div class="stat-number">{fw_with_hits}/{len(frameworks)}</div><div class="stat-label">Frameworks Impacted</div></div>'
    mapped_count = len(set(id(f) for fw_f in framework_findings.values() for f in fw_f))
    body += f'<div class="stat-card"><div class="stat-number">{mapped_count}</div><div class="stat-label">Mapped Findings</div></div>'
    unmapped = total - mapped_count
    body += f'<div class="stat-card"><div class="stat-number">{unmapped}</div><div class="stat-label">Unmapped</div></div>'
    body += '</div></div>'

    body += '<div class="page"><h1>Framework Coverage Matrix</h1>'
    body += '<table><tr><th>Framework</th><th>Findings</th><th>Critical</th><th>High</th><th>Medium</th></tr>'
    for fw_label in frameworks:
        fw_f = framework_findings[fw_label]
        if not fw_f:
            body += f'<tr><td>{esc(fw_label)}</td><td style="text-align:center;color:var(--slate-400);">0</td><td></td><td></td><td></td></tr>'
            continue
        rc = Counter((f.get("risk") or "INFO").upper() for f in fw_f)
        body += f'<tr><td><strong>{esc(fw_label)}</strong></td>'
        body += f'<td style="text-align:center;font-weight:700;">{len(fw_f)}</td>'
        for lvl in ("CRITICAL", "HIGH", "MEDIUM"):
            c = rc.get(lvl, 0)
            color = RISK_COLORS.get(lvl, "#666")
            if c:
                body += f'<td style="text-align:center;color:{color};font-weight:700;">{c}</td>'
            else:
                body += '<td style="text-align:center;color:var(--slate-400);">-</td>'
        body += '</tr>'
    body += '</table></div>'

    for fw_label, field in frameworks.items():
        fw_f = framework_findings[fw_label]
        if not fw_f:
            continue
        fw_f.sort(key=risk_sort)
        control_groups = defaultdict(list)
        for f in fw_f:
            controls = f.get(field, [])
            if isinstance(controls, str):
                controls = [c.strip() for c in controls.split(",") if c.strip()]
            for ctrl in controls:
                control_groups[ctrl].append(f)

        body += f'<div class="page"><h1>{esc(fw_label)} Gap Analysis</h1>'
        body += f'<p class="section-intro">{len(fw_f)} finding(s) mapped to {len(control_groups)} {esc(fw_label)} control(s).</p>'
        body += '<table><tr><th>Control</th><th>Findings</th><th>Highest Risk</th></tr>'
        for ctrl in sorted(control_groups.keys()):
            ctrl_f = control_groups[ctrl]
            worst = "INFO"
            for f in ctrl_f:
                r = (f.get("risk") or "INFO").upper()
                if RISK_ORDER.get(r, 5) < RISK_ORDER.get(worst, 5):
                    worst = r
            color = RISK_COLORS.get(worst, "#666")
            body += f'<tr><td><code>{esc(ctrl)}</code></td><td style="text-align:center">{len(ctrl_f)}</td><td><span class="badge" style="background:{color};">{worst}</span></td></tr>'
        body += '</table></div>'

    return _endpoint_doc_wrap("Compliance Matrix Report", client_name, body)


def build_unified_exec_report(data):
    meta = data.get("crucible_meta", {})
    client_name = meta.get("client_name", "Client")
    incomplete = data.get("incomplete", False)
    findings = sorted(data.get("findings", []), key=risk_sort)
    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in findings)
    total = len(findings)
    active_scopes = meta.get("active_scopes", [])

    tool_counts = Counter((f.get("tool") or "unknown").lower() for f in findings)
    scope_counts = Counter()
    for f in findings:
        s = (f.get("scope") or "").lower()
        if s:
            scope_counts[s] += 1

    cover = _build_scope_cover(client_name, "Unified Executive Summary",
                               meta, "All Scopes", None, incomplete)
    body = cover

    body += '<div class="page"><h1>Executive Summary</h1>'
    body += f'''<p class="section-intro">
{esc(client_name)} engaged the assessor to perform a comprehensive security assessment
spanning {len(active_scopes)} scope(s): {", ".join(esc(s.title()) for s in active_scopes) if active_scopes else "multiple domains"}.
This executive summary consolidates findings from all assessment domains into a unified
risk picture for leadership and board-level stakeholders.</p>'''

    body += '<div class="stats-row">'
    body += f'<div class="stat-card"><div class="stat-number">{total}</div><div class="stat-label">Total Findings</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#dc2626">{risk_counts.get("CRITICAL", 0)}</div><div class="stat-label">Critical</div></div>'
    body += f'<div class="stat-card"><div class="stat-number" style="color:#ea580c">{risk_counts.get("HIGH", 0)}</div><div class="stat-label">High</div></div>'
    body += f'<div class="stat-card"><div class="stat-number">{len(active_scopes)}</div><div class="stat-label">Scopes Tested</div></div>'
    body += '</div>'
    body += _risk_cards_html(risk_counts)

    pie = _build_risk_pie(risk_counts)
    if pie:
        body += '<div class="risk-charts-row">'
        body += f'<div class="risk-chart-col"><h4>Overall Risk Distribution</h4>{pie}</div>'
        body += '</div>'
    body += _exec_risk_heatmap(risk_counts, total)
    body += '</div>'

    if scope_counts:
        body += '<div class="page"><h1>Findings by Scope</h1>'
        body += '<p class="section-intro">Distribution of findings across assessment domains.</p>'
        body += '<table><tr><th>Scope</th><th>Findings</th><th>Critical</th><th>High</th></tr>'
        for scope_name, count in scope_counts.most_common():
            scope_f = [f for f in findings if (f.get("scope") or "").lower() == scope_name]
            sc_rc = Counter((f.get("risk") or "INFO").upper() for f in scope_f)
            body += f'<tr><td><strong>{esc(scope_name.title())}</strong></td>'
            body += f'<td style="text-align:center">{count}</td>'
            crit = sc_rc.get("CRITICAL", 0)
            high = sc_rc.get("HIGH", 0)
            body += f'<td style="text-align:center;color:#dc2626;font-weight:700;">{crit if crit else "-"}</td>'
            body += f'<td style="text-align:center;color:#ea580c;font-weight:700;">{high if high else "-"}</td>'
            body += '</tr>'
        body += '</table></div>'

    if tool_counts:
        body += '<div class="page"><h1>Tool Coverage</h1>'
        body += '<p class="section-intro">Findings contributed by each assessment tool.</p>'
        body += '<table><tr><th>Tool</th><th>Findings</th></tr>'
        for tool_name, count in tool_counts.most_common(15):
            body += f'<tr><td>{esc(tool_name)}</td><td style="text-align:center">{count}</td></tr>'
        body += '</table></div>'

    top = findings[:10]
    if top:
        body += '<div class="page"><h1>Top 10 Critical Findings</h1>'
        body += '<p class="section-intro">The most severe findings across all assessment scopes.</p>'
        body += '<table><tr><th>#</th><th>Risk</th><th>Finding</th><th>Scope</th><th>Target</th></tr>'
        for idx, f in enumerate(top, 1):
            risk = (f.get("risk") or "INFO").upper()
            color = RISK_COLORS.get(risk, "#666")
            scope = esc((f.get("scope") or f.get("tool") or "").title())
            ip = esc(f.get("ip", ""))
            port = f.get("port", "")
            target = f"{ip}:{port}" if ip and port else ip
            body += f'<tr><td>{idx}</td><td><span class="badge" style="background:{color};">{risk}</span></td>'
            body += f'<td style="font-size:8pt;">{esc(f.get("title", ""))}</td>'
            body += f'<td style="font-size:8pt;">{scope}</td>'
            body += f'<td><code style="font-size:7pt;">{target}</code></td></tr>'
        body += '</table></div>'

    body += '<div class="page"><h1>Strategic Recommendations</h1>'
    body += f'''<p class="section-intro">Based on the comprehensive assessment of {esc(client_name)}'s
security posture, the following strategic recommendations are provided:</p>'''
    body += '''<table>
    <tr><th>Priority</th><th>Recommendation</th><th>Impact</th></tr>
    <tr><td><span class="badge" style="background:#dc2626">IMMEDIATE</span></td>
        <td>Remediate all Critical findings within 30 days</td>
        <td>Eliminates highest-risk attack paths across all domains</td></tr>
    <tr><td><span class="badge" style="background:#dc2626">IMMEDIATE</span></td>
        <td>Establish an emergency patch management process for externally-facing systems</td>
        <td>Reduces external attack surface window</td></tr>
    <tr><td><span class="badge" style="background:#ea580c">SHORT-TERM</span></td>
        <td>Implement network segmentation and micro-segmentation between critical tiers</td>
        <td>Limits blast radius of any future breach</td></tr>
    <tr><td><span class="badge" style="background:#ea580c">SHORT-TERM</span></td>
        <td>Harden Active Directory: enforce SMB signing, Kerberos AES, tiered admin</td>
        <td>Prevents domain-wide compromise from single credential theft</td></tr>
    <tr><td><span class="badge" style="background:#d97706">MEDIUM-TERM</span></td>
        <td>Deploy centralized logging (SIEM) with correlation rules for attack indicators</td>
        <td>Enables detection and response for attacks that bypass preventive controls</td></tr>
    <tr><td><span class="badge" style="background:#d97706">MEDIUM-TERM</span></td>
        <td>Establish a vulnerability management program with quarterly internal and external scanning</td>
        <td>Continuous posture monitoring between annual assessments</td></tr>
</table></div>'''

    return _endpoint_doc_wrap("Unified Executive Summary", client_name, body)


