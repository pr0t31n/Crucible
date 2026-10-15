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
    "full":      {"label": "Full Pentest Report",        "scope_gate": None,       "description": "Complete engagement report with all scopes, findings, and methodology"},
    "nist":      {"label": "NIST 800-123 Assessment",    "scope_gate": "endpoint", "description": "Guide to General Server Security compliance assessment"},
    "stig":      {"label": "DISA STIG Assessment",       "scope_gate": "endpoint", "description": "Defense Information Systems Agency STIG compliance assessment"},
    "cis":       {"label": "CIS Benchmark Assessment",   "scope_gate": "endpoint", "description": "Center for Internet Security hardening benchmark assessment"},
    "disk":      {"label": "Disk & Storage Report",      "scope_gate": "endpoint", "description": "Physical and logical disk configuration, RAID, and storage health"},
    "software":  {"label": "Software & Update Report",   "scope_gate": "endpoint", "description": "Installed software inventory, EOL analysis, services, and update compliance"},
    "malicious": {"label": "Malicious Activity Report",  "scope_gate": "endpoint", "description": "Suspicious processes, persistence mechanisms, credential exposure, and event log indicators"},
    "hardware":  {"label": "Hardware Report",            "scope_gate": "endpoint", "description": "System hardware inventory including processors, memory, BIOS, network adapters, and peripherals"},
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

    _EP_BUILDERS = {
        "disk": build_disk_report,
        "hardware": build_hardware_report,
        "software": build_software_report,
        "malicious": build_malicious_report,
        "nist": build_nist_report,
        "stig": build_stig_report,
        "cis": build_cis_report,
    }

    if report_type != "full" and report_type in _EP_BUILDERS:
        ep_data = gather_endpoint_data(project)
        if incomplete:
            ep_data["incomplete"] = True
        html = _EP_BUILDERS[report_type](ep_data)
    else:
        data = gather_report_data(project)
        if incomplete:
            data["incomplete"] = True
        html = build_report(data)

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
