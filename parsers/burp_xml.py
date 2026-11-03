"""Enhanced Burp Suite XML parser with 162-entry title normalization.

Supports both streaming parse (via existing importer) and wizard-mode
preview/commit for the 3-step import wizard.
"""

import re
import hashlib
import logging
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

log = logging.getLogger("crucible.parsers.burp_xml")

_RE_HTML_TAG = re.compile(r"<[^>]+>")
_RE_URL = re.compile(r"https?://([^/\s:]+)(?::(\d+))?")

_SEVERITY_MAP = {
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "information": "INFO",
    "info": "INFO",
}

# ── Title normalization map (162 entries) ─────────────────────
BURP_TITLE_MAP = {
    # Tier 1: Confirmed from user export
    "Client-side JSON injection (DOM-based)":                   "Cross-Site Scripting (XSS) — DOM-Based",
    "Possible DOM-based Cross-site scripting":                  "Cross-Site Scripting (XSS) — DOM-Based",
    "Content Sniffing not disabled":                            "Missing X-Content-Type-Options Header",
    "Content security policy: allows clickjacking":             "Clickjacking Vulnerability",
    "Content security policy: allows untrusted script execution": "Insecure Content-Security-Policy (Unsafe-Inline Allowed)",
    "Content security policy: allowlisted script resources":    "Permissive Security Header: Content-Security-Policy",
    "Content security policy: allows untrusted style execution":"Permissive Security Header: Content-Security-Policy",
    "Cross-domain Referer leakage":                             "Missing Referrer-Policy Header",
    "Frameable response (potential Clickjacking)":              "Missing X-Frame-Options Header",
    "Request vulnerable to Cross-site Request Forgery":         "Cross-Site Request Forgery (CSRF)",
    "Robots.txt file":                                          "Robots.txt Discloses Hidden Paths",
    "Session token in URL":                                     "Session Token in URL",
    "Software Version Numbers Revealed":                        "Software Version Disclosed",
    "[Vulners] Software detected":                              "Software Version Disclosed",
    "Strict Transport Security Misconfiguration":               "HTTP Strict Transport Security (HSTS) Not Enforced",
    "Strict transport security not enforced":                   "HTTP Strict Transport Security (HSTS) Not Enforced",
    "Browser cross-site scripting filter misconfiguration":     "Missing Security Header: X-XSS-Protection",
    "Email addresses disclosed":                                "Sensitive Data Exposure — PII in Response",
    "Redirection from HTTP to HTTPS":                           "Web — HTTP Exposed (No HTTPS Redirect)",
    "Cross-domain script include":                              "Cross-Domain Script Include",
    "HTML does not specify charset":                            "Missing HTML Charset Declaration",

    # Tier 2: Pre-mapped from Burp Scanner catalogue — Injection
    "SQL injection":                                            "SQL Injection",
    "SQL injection (second order)":                             "SQL Injection",
    "Client-side SQL injection (DOM-based)":                    "SQL Injection",
    "OS command injection":                                     "Command Injection (OS Command Injection)",
    "LDAP injection":                                           "LDAP Injection",
    "XPath injection":                                          "XPath Injection",
    "XML external entity injection":                            "XML External Entity (XXE) Injection",
    "XML injection":                                            "XML External Entity (XXE) Injection",
    "Server-side template injection":                           "Server-Side Template Injection (SSTI)",
    "Client-side template injection":                           "Cross-Site Scripting (XSS) — DOM-Based",
    "NoSQL injection":                                          "NoSQL Injection",
    "HTTP header injection":                                    "Inadequate Input Validation — HTTP Header Injection",
    "HTTP response header injection":                           "CRLF Injection",
    "SSI injection":                                            "Server-Side Include (SSI) Injection",
    "XML entity expansion":                                     "XML External Entity (XXE) Injection",
    "SQL statement in request parameter":                       "SQL Injection",
    "File path manipulation":                                   "Path Traversal / Local File Inclusion",

    # XSS
    "Cross-site scripting (reflected)":                         "Cross-Site Scripting (XSS) — Reflected",
    "Cross-site scripting (stored)":                            "Cross-Site Scripting (XSS) — Stored",
    "Cross-site scripting (DOM-based reflected)":               "Cross-Site Scripting (XSS) — DOM-Based",
    "Cross-site scripting (DOM-based stored)":                  "Cross-Site Scripting (XSS) — DOM-Based",
    "Link manipulation (DOM-based)":                            "Cross-Site Scripting (XSS) — DOM-Based",
    "Link manipulation (reflected)":                            "Cross-Site Scripting (XSS) — Reflected",
    "Link manipulation (stored)":                               "Cross-Site Scripting (XSS) — Stored",
    "Ajax request header manipulation (DOM-based)":             "Cross-Site Scripting (XSS) — DOM-Based",
    "Document domain manipulation (DOM-based)":                 "Cross-Site Scripting (XSS) — DOM-Based",
    "DOM data manipulation (DOM-based)":                        "Cross-Site Scripting (XSS) — DOM-Based",
    "HTML storage manipulation (DOM-based)":                    "Cross-Site Scripting (XSS) — DOM-Based",
    "HTML web message manipulation (DOM-based)":                "Cross-Site Scripting (XSS) — DOM-Based",
    "Local file path manipulation (DOM-based)":                 "Path Traversal / Local File Inclusion",

    # Access Control / SSRF
    "Cross-site request forgery":                               "Cross-Site Request Forgery (CSRF)",
    "Cross-domain POST":                                        "Cross-Site Request Forgery (CSRF)",
    "File path traversal":                                      "Path Traversal / Local File Inclusion",
    "Directory listing":                                        "Directory Listing Enabled",
    "Server-side request forgery (SSRF)":                       "Server-Side Request Forgery (SSRF)",
    "External service interaction (HTTP)":                      "Server-Side Request Forgery (SSRF)",
    "External service interaction (DNS)":                       "Server-Side Request Forgery (SSRF)",
    "Out-of-band resource load (HTTP)":                         "Server-Side Request Forgery (SSRF)",

    # Redirects
    "Open redirection (reflected)":                             "Open Redirect",
    "Open redirection (stored)":                                "Open Redirect",
    "Open redirection (DOM-based)":                             "Open Redirect",
    "Long redirection response":                                "Open Redirect",

    # Request Smuggling
    "HTTP request smuggling":                                   "HTTP Request Smuggling",
    "HTTP/2 request smuggling via CRLF injection":              "HTTP Request Smuggling",
    "HTTP/2 queue poisoning via request cancellation":          "HTTP Request Smuggling",
    "Client-side desync":                                       "HTTP Request Smuggling — CL.0 Client-Side Desync",
    "Browser-powered request smuggling":                        "HTTP Request Smuggling",

    # Serialization / Prototype
    "Serialized object in HTTP message":                        "Insecure Deserialization",
    "Client-side prototype pollution":                          "Potential Client-Side Prototype Pollution",
    "Server-side prototype pollution":                          "Server-Side Prototype Pollution",
    "Insecure deserialization":                                 "Insecure Deserialization",
    "Java deserialization":                                     "Java Deserialization via Gadget Chains",

    # CORS / Cross-Origin
    "Cross-origin resource sharing: arbitrary origin trusted":  "CORS Misconfiguration — Arbitrary Origin Reflected",
    "Cross-origin resource sharing: unencrypted origin trusted":"CORS Misconfiguration — Arbitrary Origin Reflected",
    "Cross-origin resource sharing: all subdomains trusted":    "CORS Misconfiguration — Arbitrary Origin Reflected",
    "Cross-origin resource sharing: excessive trust":           "CORS Misconfiguration Allowing Credential Leakage",
    "WebSocket hijacking (cross-site)":                         "WebSocket Missing Origin Validation",
    "Cross-site WebSocket hijacking":                           "WebSocket Missing Origin Validation",
    "Flash cross-domain policy":                                "CORS Misconfiguration — Arbitrary Origin Reflected",
    "Silverlight cross-domain policy":                          "CORS Misconfiguration — Arbitrary Origin Reflected",

    # Authentication / Session
    "Password field with autocomplete enabled":                 "Password Field With Autocomplete Enabled",
    "Login page password field with autocomplete enabled":      "Password Field With Autocomplete Enabled",
    "Cleartext submission of password":                         "Password Field With Autocomplete Enabled",
    "Password returned in later response":                      "Sensitive Data Exposure — PII in Response",
    "Password submitted using GET method":                      "Session Token in URL",
    "Password returned in URL query string":                    "Sensitive Data in GET Request Parameters",
    "Password value set in cookie":                             "Sensitive Data Exposure — PII in Response",
    "Session fixation":                                         "Session Fixation",
    "Username enumeration":                                     "Application Responses Identify Valid Accounts",
    "Race condition":                                           "Business Logic Flaw — Race Condition",

    # Cookies
    "TLS cookie without secure flag set":                       "Session Cookie Missing Secure Flag",
    "SSL cookie without secure flag set":                       "Session Cookie Missing Secure Flag",
    "Cookie without HttpOnly flag set":                         "Session Cookie Missing HttpOnly Flag",
    "Cookie manipulation (DOM-based)":                          "Session Cookie Missing Secure Flag",
    "Cookie scoped to parent domain":                           "Overly Broad Cookie Domain Scope",
    "Duplicate cookies set":                                    "Overly Broad Cookie Domain Scope",
    "Cookie without SameSite attribute set":                    "Session Cookie Missing SameSite Attribute",

    # TLS / Crypto
    "Unencrypted communications":                               "HTTP Strict Transport Security (HSTS) Not Enforced",
    "HSTS missing from HTTPS server":                           "HTTP Strict Transport Security (HSTS) Not Enforced",

    # Information Disclosure
    "Information disclosure in error message":                   "Application Error Message Disclosure",
    "Information disclosure in redirect":                        "Application Error Message Disclosure",
    "Private IP addresses disclosed":                           "Information Disclosure: Internal IP in HTTP Response",
    "Credit card numbers disclosed":                            "Sensitive Data Exposure — PII in Response",
    "Social security numbers disclosed":                        "Sensitive Data Exposure — PII in Response",
    "Input returned in response (reflected)":                   "Cross-Site Scripting (XSS) — Reflected",
    "Input returned in response (stored)":                      "Cross-Site Scripting (XSS) — Stored",
    "Cacheable HTTPS response":                                 "Missing Cache-Control on Sensitive Page",
    "Spoofable client IP address":                              "Rate Limit Bypass via X-Forwarded-For Header",
    "Private key disclosed":                                    "Sensitive File Exposed — Private Key",
    "Database connection string disclosed":                     "Verbose Error Messages — Stack Trace Disclosed",
    "Source code disclosure (file extension)":                   "Application Error Message Disclosure",
    "Source code disclosure":                                    "Application Error Message Disclosure",
    "Stack trace disclosed":                                    "Verbose Error Messages — Stack Trace Disclosed",

    # JavaScript / Client-Side
    "Vulnerable JavaScript dependency":                         "Vulnerable Component: {pname} {version}",
    "JavaScript/CSS dependency served from untrusted domain":   "Cross-Domain Script Include",
    "Path-relative style sheet import":                         "Missing Subresource Integrity",
    "React Server Components RCE (React2Shell)":                "Command Injection (OS Command Injection)",
    "Denial of service (DOM-based)":                            "Potential Client-Side Prototype Pollution",

    # Server Configuration
    "ASP.NET tracing enabled":                                  "Information Disclosure: Debug/Trace Headers",
    "ASP.NET debugging enabled":                                "Information Disclosure: Debug/Trace Headers",
    "ASP.NET ViewState without MAC enabled":                    "Insecure Deserialization — Serialized Object Accepted",
    "HTTP TRACE method is enabled":                             "HTTP Methods: Unsafe Methods Enabled",
    "TRACE method is enabled":                                  "HTTP Methods: Unsafe Methods Enabled",
    "Request URL override":                                     "Information Disclosure: Internal IP in HTTP Response",
    "Content type incorrectly stated":                          "Content-Type Confusion",
    "Content type is not specified":                            "Content-Type Confusion",
    "Multiple content types specified":                         "Content-Type Confusion",
    "HTML uses unrecognized charset":                           "Missing HTML Charset Declaration",
    "Backup file":                                              "Backup File Discovered",
    "Suspicious input transformation (reflected)":              "Cross-Site Scripting (XSS) — Reflected",
    "Suspicious input transformation (stored)":                 "Cross-Site Scripting (XSS) — Stored",
    "Base64-encoded data in parameter":                         "Application Error Message Disclosure",
    "File upload functionality":                                "Unrestricted File Upload — Executable File",
    "PHP info page":                                            "PHP Info Page Exposed",
    "Mixed content":                                            "Mixed Content on Authenticated Page",

    # GraphQL
    "GraphQL introspection enabled":                            "GraphQL Introspection Enabled",
    "GraphQL suggestions enabled":                              "GraphQL Introspection Enabled",
    "GraphQL batching enabled":                                 "GraphQL Batch Query Attack",

    # JWT
    "JWT none algorithm supported":                             "JWT Algorithm Confusion (None Algorithm)",
    "JWT signature not verified":                               "JWT Signature Not Verified",
    "JWT algorithm confusion":                                  "JWT Algorithm Confusion (None Algorithm)",

    # Web Cache
    "Web cache poisoning":                                      "Web Cache Poisoning",
    "Web cache deception":                                      "Web Cache Deception",

    # CSP variants (Burp 2024+)
    "Content security policy: allows form hijacking":           "Insecure Content-Security-Policy (Unsafe-Inline Allowed)",
    "Content security policy: incorrect syntax":                "Permissive Security Header: Content-Security-Policy",
    "Content security policy: wildcard directive":              "Permissive Security Header: Content-Security-Policy",
    "Content security policy: missing policy":                  "Missing Content-Security-Policy Header",

    # Additional DOM-based sinks
    "Form action hijacking (DOM-based)":                        "Cross-Site Request Forgery (CSRF)",
    "WebSocket URL poisoning (DOM-based)":                      "WebSocket Missing Origin Validation",
    "Client-side XPath injection (DOM-based)":                  "XPath Injection",

    # Additional discovery/config
    "OpenAPI definition file found":                            "Swagger/OpenAPI Documentation Exposed",
    "Email header injection":                                   "Email Header Injection",
    "SMTP header injection":                                    "Email Header Injection",
    "Client-side HTTP parameter pollution":                     "HTTP Parameter Pollution (Reflected)",
    "Referer-dependent response":                               "Missing Referrer-Policy Header",

    # Code Injection (additional)
    "Server-side JavaScript code injection":                    "Remote Code Execution via Code Injection",
    "Ruby code injection":                                      "Remote Code Execution via Code Injection",
    "Perl code injection":                                      "Remote Code Execution via Code Injection",
    "PHP code injection":                                       "Remote Code Execution via Code Injection",
    "Python code injection":                                    "Remote Code Execution via Code Injection",
    "ASP code injection":                                       "Remote Code Execution via Code Injection",
    "Expression language injection":                            "Remote Code Execution via Code Injection",
    "Unidentified code injection":                              "Remote Code Execution via Code Injection",
}

_BURP_TITLE_MAP_LOWER = {k.lower(): v for k, v in BURP_TITLE_MAP.items()}


# ── TLS sub-parser ────────────────────────────────────────────
_TLS_RULES = [
    (re.compile(r"expired", re.I),                   "Expired TLS Certificate Detected"),
    (re.compile(r"self[- ]signed", re.I),            "Self-Signed TLS Certificate"),
    (re.compile(r"untrusted|chain", re.I),           "TLS Certificate Self-Signed"),
    (re.compile(r"weak.?signature|SHA-1|MD5", re.I), "TLS Certificate Uses Weak Signature Algorithm (MD5/SHA-1)"),
    (re.compile(r"wildcard", re.I),                  "Wildcard TLS Certificate"),
    (re.compile(r"mismatch|hostname", re.I),         "TLS Certificate Hostname Mismatch"),
]


def _normalize_tls_title(issue_detail):
    for rx, title in _TLS_RULES:
        if rx.search(issue_detail or ""):
            return title
    return "TLS Certificate Issue"


def _strip_html(text):
    if not text:
        return ""
    return _RE_HTML_TAG.sub("", text).strip()


def _el_text(el, tag):
    child = el.find(tag)
    if child is not None and child.text:
        return child.text.strip()
    return ""


def normalize_title(burp_name, issue_detail=""):
    if not burp_name:
        return burp_name
    lower = burp_name.lower().strip()
    if lower.startswith("tls certificate") or lower.startswith("ssl certificate"):
        return _normalize_tls_title(issue_detail)
    mapped = _BURP_TITLE_MAP_LOWER.get(lower)
    if mapped:
        return mapped
    return burp_name


def _parse_host(issue):
    host_el = issue.find("host")
    ip = ""
    hostname = ""
    port = 0
    host_url = ""
    if host_el is not None:
        ip = host_el.get("ip", "")
        host_url = (host_el.text or "").strip()
        m = _RE_URL.search(host_url)
        if m:
            hostname = m.group(1)
            p = m.group(2)
            if p:
                port = int(p)
            elif host_url.startswith("https"):
                port = 443
            else:
                port = 80
        if not ip and hostname:
            ip = hostname
    return ip, hostname, port, host_url


def _parse_issue(issue):
    name = _el_text(issue, "name")
    if not name:
        return None

    severity = _el_text(issue, "severity").lower()
    if severity == "false positive":
        return None
    risk = _SEVERITY_MAP.get(severity, "INFO")

    ip, hostname, port, host_url = _parse_host(issue)
    path = _el_text(issue, "path")
    issue_type = _el_text(issue, "type")
    serial = _el_text(issue, "serialNumber")

    bg = _strip_html(_el_text(issue, "issueBackground"))
    detail = _strip_html(_el_text(issue, "issueDetail"))
    desc = f"{bg}\n\n{detail}".strip() if bg and detail else (bg or detail or name)

    rem_bg = _strip_html(_el_text(issue, "remediationBackground"))
    rem_detail = _strip_html(_el_text(issue, "remediationDetail"))
    remediation = f"{rem_bg}\n\n{rem_detail}".strip() if rem_bg and rem_detail else (rem_bg or rem_detail or f"Review and remediate: {name}")

    confidence = _el_text(issue, "confidence")
    references = _strip_html(_el_text(issue, "references"))
    location = _el_text(issue, "location")

    normalized = normalize_title(name, detail or bg)
    cat_id = f"BURP-{issue_type}" if issue_type else ""

    affected = host_url
    if path:
        affected = f"{host_url}{path}"

    output_parts = []
    if location:
        output_parts.append(f"Location: {location}")
    if confidence:
        output_parts.append(f"Confidence: {confidence}")

    rr = issue.find("requestresponse")
    if rr is not None:
        req_el = rr.find("request")
        if req_el is not None and req_el.text:
            output_parts.append(f"Request (truncated):\n{req_el.text[:500]}")
        resp_el = rr.find("response")
        if resp_el is not None and resp_el.text:
            output_parts.append(f"Response (truncated):\n{resp_el.text[:500]}")

    dedup_key = f"{normalized}|{host_url}|{port}|{path}"

    return {
        "burp_name": name,
        "title": normalized,
        "risk": risk,
        "ip": ip,
        "port": port,
        "hostname": hostname,
        "host_url": host_url,
        "path": path or "",
        "affected": affected,
        "description": desc[:4096],
        "remediation": remediation[:4096],
        "output": "\n".join(output_parts)[:4096],
        "sources": references or "burp",
        "confidence": confidence or "",
        "catalogue_id": cat_id,
        "issue_type": issue_type or "",
        "serial": serial or "",
        "dedup_key": dedup_key,
        "service": "https" if port == 443 else "http",
    }


def parse_xml(file_path):
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except (ET.ParseError, OSError) as exc:
        log.error("Burp XML parse error: %s", exc)
        return []

    if root.tag != "issues":
        log.warning("Unexpected root element: %s (expected <issues>)", root.tag)

    results = []
    for issue in root.iter("issue"):
        parsed = _parse_issue(issue)
        if parsed:
            results.append(parsed)
    return results


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def build_preview(parsed_issues, project, selected_scope=None):
    hosts = {}
    for p in parsed_issues:
        key = p["host_url"] or p["ip"]
        if key not in hosts:
            hosts[key] = {"host": key, "ip": p["ip"], "hostname": p["hostname"], "count": 0}
        hosts[key]["count"] += 1

    scope_targets = _get_scope_targets(project)

    applicable_scopes = []
    for s in ("external", "internal", "webapp", "api"):
        st = project.get("scope_tool_dirs", {})
        sd = project.get("scope_definition", {})
        if st.get(s) or sd.get(s) or sd.get(f"{s}_targets"):
            applicable_scopes.append(s)

    if not applicable_scopes:
        applicable_scopes = ["webapp"]

    for h in hosts.values():
        h["in_scope"] = _host_in_scope(h, scope_targets, selected_scope or (applicable_scopes[0] if len(applicable_scopes) == 1 else None))

    deduped = {}
    for p in parsed_issues:
        dk = p["dedup_key"]
        if dk not in deduped:
            deduped[dk] = {**p, "dup_count": 1}
        else:
            deduped[dk]["dup_count"] += 1

    return {
        "hosts": sorted(hosts.values(), key=lambda h: (-h["count"], h["host"])),
        "findings": sorted(deduped.values(), key=lambda f: (
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(f["risk"], 5),
            f["title"],
        )),
        "applicable_scopes": applicable_scopes,
        "scope_targets": scope_targets,
    }


_SCOPE_TARGET_KEY = {
    "webapp": ("target_urls", "domains"),
    "api": ("api_urls", "domains"),
    "external": ("network_cidrs", "domains"),
    "internal": ("network_cidrs", "domains"),
}


def _get_scope_targets(project):
    sd = project.get("scope_definition", {})
    result = {}
    for scope, (primary, secondary) in _SCOPE_TARGET_KEY.items():
        targets = sd.get(primary, [])
        domains = sd.get(secondary, [])
        if isinstance(targets, str):
            targets = [t.strip() for t in targets.split(",") if t.strip()]
        if isinstance(domains, str):
            domains = [d.strip() for d in domains.split(",") if d.strip()]
        result[scope] = {"targets": targets, "domains": domains}
    return result


def _host_in_scope(host_info, scope_targets, scope):
    if not scope:
        return False
    st = scope_targets.get(scope, {})
    targets = st.get("targets", [])
    domains = st.get("domains", [])

    h = (host_info.get("host") or "").lower()
    ip = host_info.get("ip") or ""
    hostname = (host_info.get("hostname") or "").lower()

    for t in targets:
        tl = t.lower().rstrip("/")
        m = _RE_URL.search(tl)
        if m and m.group(1) == hostname:
            return True
        if tl == ip or tl == hostname or tl == h:
            return True

    for d in domains:
        dl = d.lower().lstrip("*.")
        if hostname.endswith(dl) or h.endswith(dl):
            return True

    return False


def build_findings(parsed_issues, selected_scope, selected_hosts, selected_dedup_keys):
    host_set = set(h.lower() for h in selected_hosts)
    key_set = set(selected_dedup_keys)

    findings = []
    seen_keys = set()
    now = datetime.now(timezone.utc).isoformat()

    for p in parsed_issues:
        host_key = (p["host_url"] or p["ip"]).lower()
        if host_key not in host_set:
            continue
        dk = p["dedup_key"]
        if dk not in key_set:
            continue
        if dk in seen_keys:
            continue
        seen_keys.add(dk)

        findings.append({
            "id": uuid.uuid4().hex,
            "tool": "burp",
            "title": p["title"],
            "datetime": now,
            "ip": p["ip"],
            "port": p["port"],
            "hostname": p["hostname"],
            "risk": p["risk"],
            "command": "burp (imported)",
            "description": p["description"],
            "output": p["output"],
            "cves": "",
            "sources": p["sources"],
            "service": p["service"],
            "output_file": "",
            "affected": p["affected"],
            "exploitdb": False,
            "metasploit": False,
            "exploit_details": [],
            "remediation": p["remediation"],
            "scope": selected_scope,
            "catalogue_id": p["catalogue_id"],
            "confidence": p["confidence"],
            "imported": True,
        })

    return findings
