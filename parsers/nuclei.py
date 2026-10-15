"""Crucible v2 — Nuclei JSONL import parser.

Replicates the exact finding title normalisation from Fracture's
_normalize_nuclei() so imported nuclei output produces identical findings
to when Fracture invokes nuclei natively.
"""

import datetime
import json
import re
import urllib.parse
import uuid
from pathlib import Path

from parsers.base import BaseParser

# ── Severity map (matches Fracture) ─────────────────────────────────────────
_NUCLEI_SEVERITY_MAP = {
    "critical": "CRITICAL", "high": "HIGH",
    "medium": "MEDIUM", "low": "LOW", "info": "INFO",
}

# ── Normalization table ─────────────────────────────────────────────────────
# (regex, title, risk, owasp, nist, remediation)
# Matches Fracture _NUCLEI_NORM exactly.
_NUCLEI_NORM = [
    (r"^missing-x-frame-options$|x-frame-options",
     "Missing Security Header: X-Frame-Options", None,
     "A05:2025 Security Misconfiguration", "SC-8",
     "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' response header."),
    (r"^missing-csp$|content-security-policy|csp-missing",
     "Missing Security Header: Content-Security-Policy", None,
     "A05:2025 Security Misconfiguration", "SC-8",
     "Implement a Content-Security-Policy header."),
    (r"^missing-hsts$|strict-transport-security|hsts-missing",
     "Missing Security Header: Strict-Transport-Security", None,
     "A05:2025 Security Misconfiguration", "SC-8",
     "Add Strict-Transport-Security header with appropriate max-age."),
    (r"^missing-x-content-type-options$|x-content-type-options",
     "Missing Security Header: X-Content-Type-Options", None,
     "A05:2025 Security Misconfiguration", "SC-8",
     "Add 'X-Content-Type-Options: nosniff' response header."),
    (r"^permissions-policy$|^missing-permissions-policy$|feature-policy",
     "Missing Security Header: Permissions-Policy", None,
     "A05:2025 Security Misconfiguration", "SC-8",
     "Implement a Permissions-Policy header."),
    (r"^referrer-policy$|^missing-referrer-policy$",
     "Missing Security Header: Referrer-Policy", None,
     "A05:2025 Security Misconfiguration", "SC-8",
     "Add a Referrer-Policy header."),
    (r"expired-ssl|ssl-cert-expired",
     "SSL/TLS Certificate: Expired", "HIGH",
     "A02:2025 Cryptographic Failures", "SC-17",
     "Renew the SSL/TLS certificate."),
    (r"self-signed-ssl|self-signed-cert",
     "SSL/TLS Certificate: Self-Signed", "MEDIUM",
     "A02:2025 Cryptographic Failures", "SC-17",
     "Replace self-signed certificate with one from a trusted CA."),
    (r"mismatched-ssl|ssl-hostname-mismatch|ssl-cert-mismatch",
     "SSL/TLS Certificate: Hostname Mismatch", "HIGH",
     "A02:2025 Cryptographic Failures", "SC-17",
     "Ensure the certificate CN/SAN matches the hostname."),
    (r"tls-version|deprecated-tls|ssl-deprecated|sslv[23]|tlsv1[.-]0|tlsv1[.-]1",
     "SSL/TLS Vulnerability: Deprecated Protocol Version", None,
     "A02:2025 Cryptographic Failures", "SC-8",
     "Disable deprecated TLS/SSL protocols; require TLS 1.2+."),
    (r"weak-cipher|obsolete-cipher|sweet32|rc4|des-cbc|null-cipher|insecure-cipher-suite",
     "SSL/TLS Ciphers: Obsolete Ciphers", None,
     "A02:2025 Cryptographic Failures", "SC-8",
     "Disable weak and obsolete cipher suites; use modern TLS 1.2/1.3 with AEAD ciphers."),
    (r"revoked-ssl",
     "SSL/TLS Certificate: Revoked", "HIGH",
     "A02:2025 Cryptographic Failures", "SC-17",
     "Replace the revoked certificate with a new one from a trusted CA."),
    (r"untrusted-root-certificate",
     "SSL/TLS Certificate: Untrusted Root", "LOW",
     "A02:2025 Cryptographic Failures", "SC-17",
     "Replace the certificate with one issued by a publicly trusted CA."),
    (r"wildcard-tls",
     "SSL/TLS Certificate: Wildcard", "INFO",
     "A02:2025 Cryptographic Failures", "SC-17",
     "Consider using per-subdomain certificates to limit exposure."),
    (r"heartbleed",
     "Heartbleed (CVE-2014-0160) Vulnerability Detected", "CRITICAL",
     "A06:2025 Vulnerable and Outdated Components", "SI-2",
     "Patch OpenSSL to a version not affected by Heartbleed."),
    (r"^tech-detect$|^wappalyzer-",
     "Technology Identified", "INFO",
     "A05:2025 Security Misconfiguration", "CM-7",
     "Review exposed technology stack for known vulnerabilities."),
    (r"^waf-detect$|^waf-",
     "WAF / Edge Security Platform Active", "INFO",
     "A05:2025 Security Misconfiguration", "CM-7",
     "WAF/CDN detected — informational."),
    (r"server-header|apache-version|nginx-version|iis-version",
     "Information Disclosure: Server Header", "LOW",
     "A05:2025 Security Misconfiguration", "SI-11",
     "Suppress or generalise the Server header."),
    (r"x-powered-by",
     "Information Disclosure: X-Powered-By Header", "LOW",
     "A05:2025 Security Misconfiguration", "SI-11",
     "Remove the X-Powered-By header."),
    (r"aspnet-version",
     "Information Disclosure: X-AspNet-Version Header", "LOW",
     "A05:2025 Security Misconfiguration", "SI-11",
     "Remove the X-AspNet-Version header via web.config."),
    (r"^exposed-panels?/|admin-panel|phpmyadmin|adminer|grafana-default|jenkins",
     "Admin Panel Exposed", "HIGH",
     "A05:2025 Security Misconfiguration", "AC-3",
     "Restrict admin interfaces by IP allowlist or VPN."),
    (r"git-config|git-head|\.git",
     "Sensitive Path Accessible: /.git", "CRITICAL",
     "A05:2025 Security Misconfiguration", "CM-7",
     "Block public access to .git directories."),
    (r"env-file|\.env\b|dotenv",
     "Sensitive Path Accessible: /.env", "CRITICAL",
     "A05:2025 Security Misconfiguration", "CM-7",
     "Block public access to .env files."),
    (r"phpinfo",
     "Sensitive File Exposed: phpinfo()", "HIGH",
     "A05:2025 Security Misconfiguration", "CM-7",
     "Remove phpinfo() files from production servers."),
    (r"robots\.txt",
     "Information Disclosure: Sensitive Path in robots.txt", "INFO",
     "A05:2025 Security Misconfiguration", "CM-7",
     "Review robots.txt for sensitive path disclosure."),
    (r"backup-file|\.bak|\.old|\.orig",
     "Sensitive File Exposed", "HIGH",
     "A05:2025 Security Misconfiguration", "CM-7",
     "Remove backup files from production web roots."),
    (r"swagger|openapi|api-doc",
     "Sensitive Path Accessible: /swagger", "MEDIUM",
     "A05:2025 Security Misconfiguration", "CM-7",
     "Restrict API documentation endpoints to internal networks."),
    (r"directory-listing|dir-listing|apache-dir",
     "Directory Listing Enabled", "MEDIUM",
     "A01:2025 Broken Access Control", "CM-7",
     "Disable directory listing on the web server."),
    (r"put-method|delete-method|options-method|http-method",
     "HTTP Methods: Unsafe Methods Enabled", "MEDIUM",
     "A05:2025 Security Misconfiguration", "CM-7",
     "Disable unnecessary HTTP methods; review and restrict allowed methods to only those required."),
    (r"cookies-without-httponly|cookie-httponly|httponly-cookie",
     "Missing Secure Cookie Attribute: HttpOnly", "MEDIUM",
     "A05:2025 Security Misconfiguration", "SC-23",
     "Set the HttpOnly flag on all session and sensitive cookies."),
    (r"cookies-without-secure|cookie-secure|secure-cookie|cookie-without-secure",
     "Missing Secure Cookie Attribute: Secure", "MEDIUM",
     "A05:2025 Security Misconfiguration", "SC-23",
     "Set the Secure flag on all cookies transmitted over HTTPS."),
    (r"missing-cookie-samesite|samesite|cookie-samesite",
     "Missing Secure Cookie Attribute: SameSite", "LOW",
     "A05:2025 Security Misconfiguration", "SC-23",
     "Set the SameSite attribute on session cookies."),
    (r"weak-hsts-detect",
     "Permissive Security Header: Strict-Transport-Security", "MEDIUM",
     "A05:2025 Security Misconfiguration", "SC-8",
     "Set Strict-Transport-Security with max-age of at least 31536000."),
    (r"weak-csp-detect",
     "Permissive Security Header: Content-Security-Policy", "LOW",
     "A05:2025 Security Misconfiguration", "SI-10",
     "Tighten the Content-Security-Policy: remove unsafe-inline/unsafe-eval."),
    (r"xss-deprecated-header",
     "Permissive Security Header: X-XSS-Protection", "LOW",
     "A05:2025 Security Misconfiguration", "SI-10",
     "Remove the deprecated X-XSS-Protection header; use CSP instead."),
    (r"cors-misconfig|cors-check",
     "CORS Misconfiguration Allowing Credential Leakage", "HIGH",
     "A01:2025 Broken Access Control", "AC-4",
     "Review CORS configuration; do not reflect arbitrary origins with credentials."),
    (r"^http-trace$|cross-site-tracing-xss|trace-method",
     "HTTP Methods: Unsafe Methods Enabled", "MEDIUM",
     "A05:2025 Security Misconfiguration", "CM-7",
     "Disable unnecessary HTTP methods; review and restrict allowed methods to only those required."),
    (r"aspx-debug-mode|werkzeug-debugger|django-debug|laravel-debug",
     "Debug Mode Enabled / Developer Console Exposed", "MEDIUM",
     "A05:2025 Security Misconfiguration", "CM-7",
     "Disable debug/developer mode in production environments."),
    (r"trace-axd-detect",
     "Sensitive Path Accessible: /trace.axd", "HIGH",
     "A05:2025 Security Misconfiguration", "CM-7",
     "Disable trace.axd in production via web.config."),
    (r"iis-shortname",
     "Information Disclosure: IIS Short File/Directory Disclosure", "LOW",
     "A05:2025 Security Misconfiguration", "CM-7",
     "Disable 8.3 filename generation via `fsutil behavior set disable8dot3 1` and restart IIS."),
    (r"crypto-address-detect",
     "Exposed Cryptocurrency Wallet Address", "INFO",
     "A09:2025 Security Logging and Monitoring Failures", "AU-6",
     "Review detected patterns to confirm they are actual wallet addresses and not false positives from hash-like strings."),
    (r"old-copyright",
     "Outdated Copyright Notice Detected", "INFO",
     "A05:2025 Security Misconfiguration", "CM-7",
     "Update copyright dates to reflect current year; outdated dates suggest unmaintained code."),
    (r"ssl-issuer\b",
     "SSL/TLS Certificate: Issuer Information", "INFO",
     "A02:2025 Cryptographic Failures", "SC-17",
     "Informational — review certificate authority trust chain."),
    (r"ssl-dns-names\b",
     "SSL/TLS Certificate: Subject Alternative Names", "INFO",
     "A02:2025 Cryptographic Failures", "SC-17",
     "Review SAN entries for unexpected hostnames or overly broad wildcard coverage."),
    (r"wildcard-tls\b|wildcard-cert",
     "SSL/TLS Certificate: Wildcard", "INFO",
     "A02:2025 Cryptographic Failures", "SC-17",
     "Limit wildcard certificates to specific services; prefer per-service certificates."),
    (r"tls-version\b|deprecated-tls",
     "SSL/TLS Vulnerability: Deprecated Protocol Version", "INFO",
     "A02:2025 Cryptographic Failures", "SC-8",
     "Disable TLS 1.0 and 1.1; enforce TLS 1.2+ with modern cipher suites."),
    (r"CVE-2017-9248|CVE-2019-18935|CVE-2017-11317|CVE-2017-11357",
     "Telerik UI File Upload / Remote Code Execution (CVE-2017-9248)", "HIGH",
     "A06:2025 Vulnerable and Outdated Components", "SI-2",
     "Upgrade Telerik UI to the latest patched version; restrict access to DialogHandler.aspx and WebResource.axd."),
    (r"telerik-dialoghandler|telerik-fileupload|telerik",
     "Telerik UI Component Detected", "MEDIUM",
     "A06:2025 Vulnerable and Outdated Components", "SI-2",
     "Review the Telerik UI version for known vulnerabilities and apply patches."),
    (r"reflected-xss|xss-reflected|cross-site-scripting",
     "Reflected Cross-Site Scripting (XSS)", "HIGH",
     "A03:2025 Injection", "SI-10",
     "Implement input validation and output encoding."),
    (r"stored-xss",
     "Stored Cross-Site Scripting (XSS)", "HIGH",
     "A03:2025 Injection", "SI-10",
     "Implement input validation and output encoding."),
    (r"dom-xss|dom-based",
     "DOM-Based Cross-Site Scripting (XSS)", "MEDIUM",
     "A03:2025 Injection", "SI-10",
     "Implement input validation and output encoding."),
    (r"sqli|sql-injection",
     "SQL Injection (Error-Based)", "HIGH",
     "A03:2025 Injection", "SI-10",
     "Use parameterised queries; never concatenate user input into SQL."),
    (r"ssti|template-injection",
     "Server-Side Template Injection (SSTI)", "CRITICAL",
     "A03:2025 Injection", "SI-10",
     "Do not pass user input to template engines without sanitisation."),
    (r"command-injection|os-command|\brce\b",
     "OS Command Injection", "CRITICAL",
     "A03:2025 Injection", "SI-10",
     "Do not pass user input to OS commands; use safe APIs."),
    (r"lfi|local-file-inclusion|path-traversal|file-inclusion",
     "Path Traversal / Local File Inclusion", "HIGH",
     "A01:2025 Broken Access Control", "AC-3",
     "Validate and sanitise file path parameters."),
    (r"ssrf|server-side-request",
     "Server-Side Request Forgery (SSRF)", "HIGH",
     "A10:2025 Server-Side Request Forgery", "AC-4",
     "Validate and restrict outbound requests from the application."),
    (r"open-redirect",
     "Open Redirect", "MEDIUM",
     "A01:2025 Broken Access Control", "CM-7",
     "Validate redirect destinations against an allowlist."),
    (r"crlf-injection|crlf",
     "CRLF Injection", "MEDIUM",
     "A03:2025 Injection", "SI-10",
     "Sanitise user input in HTTP headers; reject CRLF characters."),
    (r"xxe|xml-external|xml-entity",
     "XML External Entity (XXE) Injection", "HIGH",
     "A03:2025 Injection", "SI-10",
     "Disable external entity processing in XML parsers."),
    (r"csrf",
     "Cross-Site Request Forgery (CSRF) — Missing Token", "MEDIUM",
     "A01:2025 Broken Access Control", "SC-23",
     "Implement anti-CSRF tokens on state-changing forms."),
    (r"stacktrace|stack-trace|debug|verbose-error|error-page",
     "Verbose Error Messages — Stack Trace Disclosed", "MEDIUM",
     "A05:2025 Security Misconfiguration", "SI-11",
     "Implement custom error pages; disable verbose errors in production."),
    (r"wordpress-detect|wp-detect",
     "CMS Detected: WordPress", "INFO",
     "A05:2025 Security Misconfiguration", "CM-7",
     "Ensure WordPress core, themes, and plugins are kept up to date."),
    (r"wordpress-xmlrpc|xmlrpc",
     "WordPress XML-RPC Multicall Brute-Force Vector", "HIGH",
     "A07:2025 Identification and Authentication Failures", "AC-7",
     "Disable or restrict XML-RPC access."),
    (r"wp-config|wordpress-config",
     "WordPress wp-config.php Source Code Exposed", "CRITICAL",
     "A05:2025 Security Misconfiguration", "CM-7",
     "Block public access to wp-config.php."),
    (r"wordpress-user|wp-user-enum",
     "WordPress Users Exposed via REST API", "MEDIUM",
     "A01:2025 Broken Access Control", "AC-3",
     "Disable the WordPress REST API users endpoint or restrict access."),
    (r"drupal-user-enum",
     "__SUPPRESS__", None, None, None, None),
    (r"wp-cron",
     "WordPress wp-cron.php Publicly Accessible", "LOW",
     "A05:2025 Security Misconfiguration", "CM-7",
     "Restrict access to wp-cron.php."),
    (r"wp-debug-log",
     "WordPress Debug Log Exposed", "HIGH",
     "A05:2025 Security Misconfiguration", "CM-7",
     "Disable WP_DEBUG_LOG in production."),
    (r"default-login|default-cred|default-password",
     "Weak or Default Credentials Accepted", "CRITICAL",
     "A07:2025 Identification and Authentication Failures", "IA-5",
     "Change default credentials immediately."),
    (r"subdomain-takeover|cname-takeover",
     "Subdomain Takeover — Dangling CNAME", "CRITICAL",
     "A05:2025 Security Misconfiguration", "CM-7",
     "Remove dangling DNS records or reclaim the underlying service."),
    (r"graphql-introspection",
     "GraphQL Introspection Enabled", "MEDIUM",
     "A05:2025 Security Misconfiguration", "CM-7",
     "Disable GraphQL introspection in production."),
    (r"graphql-field-suggestion",
     "GraphQL Field Suggestions Enabled", "LOW",
     "A05:2025 Security Misconfiguration", "CM-7",
     "Disable GraphQL field suggestions in production."),
    # Catch-all CVE pattern
    (r"^CVE-\d{4}-\d+",
     None, None, None, None, None),
]
_NUCLEI_NORM_COMPILED = [
    (re.compile(p, re.IGNORECASE), t, r, o, n, rm)
    for p, t, r, o, n, rm in _NUCLEI_NORM
]

# ── Dynamic title regexes ───────────────────────────────────────────────────
_NUCLEI_DYN_TECH = re.compile(r"^tech-detect$|^wappalyzer-", re.IGNORECASE)
_NUCLEI_DYN_WAF = re.compile(r"^waf-detect$|^waf-", re.IGNORECASE)
_NUCLEI_DYN_PANEL = re.compile(
    r"admin-panel|phpmyadmin|adminer|grafana-default|jenkins"
    r"|-panel-detect$|-login-detect$|-panel$",
    re.IGNORECASE)

# ── Header matcher for http-missing-security-headers template ───────────────
_NUCLEI_HDR_MATCHER = {
    "strict-transport-security":        ("Strict-Transport-Security", "MEDIUM"),
    "content-security-policy":          ("Content-Security-Policy", "MEDIUM"),
    "permissions-policy":               ("Permissions-Policy", "LOW"),
    "x-frame-options":                  ("X-Frame-Options", "MEDIUM"),
    "x-content-type-options":           ("X-Content-Type-Options", "MEDIUM"),
    "x-permitted-cross-domain-policies": ("X-Permitted-Cross-Domain-Policies", "LOW"),
    "referrer-policy":                  ("Referrer-Policy", "LOW"),
    "clear-site-data":                  ("Clear-Site-Data", "LOW"),
    "cross-origin-embedder-policy":     ("Cross-Origin-Embedder-Policy", "LOW"),
    "cross-origin-opener-policy":       ("Cross-Origin-Opener-Policy", "LOW"),
    "cross-origin-resource-policy":     ("Cross-Origin-Resource-Policy", "LOW"),
    "missing-content-type":             ("Content-Type", "LOW"),
    "content-type-charset-specification": ("Content-Type Charset", "LOW"),
}


def _enrich_nuclei_output(raw_output, item):
    _tid = item.get("template-id", "")
    _matched = item.get("matched-at", "")
    _matcher = item.get("matcher-name", "")
    _sev = (item.get("info", {}).get("severity") or "info").upper()

    if raw_output and not raw_output.startswith("Template:"):
        parts = []
        if _matched:
            parts.append(f"Matched at: {_matched}")
        parts.append(str(raw_output)[:2000])
        return "\n".join(parts)

    parts = []
    if _matched:
        parts.append(f"Matched at: {_matched}")
    parts.append(f"Template: {_tid}")
    if _matcher:
        parts.append(f"Matcher: {_matcher}")
    parts.append(f"Severity: {_sev}")

    _curl = item.get("curl-command", "")
    _response = item.get("response", "")
    _matched_line = item.get("matched-line", "")
    _host = item.get("host", "")

    if _matched_line and _matched_line != raw_output:
        parts.append("")
        parts.append("Matched line:")
        parts.append(str(_matched_line)[:500])
    elif _response:
        parts.append("")
        parts.append("Response excerpt:")
        _resp_str = str(_response)
        _body_start = _resp_str.find("\r\n\r\n")
        if _body_start > 0:
            parts.append(_resp_str[_body_start + 4:][:500])
        else:
            parts.append(_resp_str[:500])

    if _curl:
        parts.append("")
        parts.append(f"Reproduce: {str(_curl)[:300]}")

    if _host and _host != _matched:
        parts.append(f"Host: {_host}")

    return "\n".join(parts)


def _normalize_nuclei(item):
    _info = item.get("info", {})
    _tid = item.get("template-id", "")
    _matcher = item.get("matcher-name", "")
    _name = _info.get("name", "Nuclei Finding")
    _sev = _NUCLEI_SEVERITY_MAP.get(_info.get("severity", "info"), "INFO")
    _desc = _info.get("description", "")
    _cves = ",".join(_info.get("classification", {}).get("cve-id", []) or [])

    _cls = _info.get("classification", {})
    _v11 = {}
    _n_cvss = _cls.get("cvss-score")
    if _n_cvss is not None:
        try:
            _v11["cvss_score"] = round(float(_n_cvss), 1)
        except (ValueError, TypeError):
            pass
    _n_cvss_vec = _cls.get("cvss-metrics", "")
    if _n_cvss_vec:
        _v11["cvss_vector"] = str(_n_cvss_vec)
    _n_cwe = _cls.get("cwe-id") or []
    if _n_cwe:
        _v11["cwe"] = [str(c) for c in _n_cwe if c]

    _matched = item.get("matched-at", "")
    _output_raw = item.get("extracted-results", item.get("matched-line", ""))
    if isinstance(_output_raw, list):
        _output_raw = "\n".join(_output_raw)
    _output = _enrich_nuclei_output(_output_raw, item)

    # Priority 1: http-missing-security-headers with named matchers
    if _tid == "http-missing-security-headers" and _matcher:
        _hdr = _NUCLEI_HDR_MATCHER.get(_matcher)
        if _hdr:
            _hdr_display, _hdr_risk = _hdr
            return {
                "title": f"Missing Security Header: {_hdr_display}",
                "risk": _hdr_risk,
                "description": _desc or f"The {_hdr_display} HTTP security header is not present.",
                "output": str(_output)[:2000] if _output else f"Template: {_tid}:{_matcher}",
                "owasp": "A05:2025 Security Misconfiguration", "nist": "SI-11",
                "remediation": f"Add the {_hdr_display} header to all HTTP responses.",
                "cves": _cves, **_v11,
            }

    # Priority 2: Dynamic titles from template category
    if _NUCLEI_DYN_TECH.search(_tid):
        return {
            "title": f"Technology Identified: {_name}", "risk": "INFO",
            "description": _desc or f"{_name} detected by nuclei ({_tid}).",
            "output": str(_output)[:2000] if _output else f"Template: {_tid}",
            "owasp": "A05:2025 Security Misconfiguration", "nist": "CM-7",
            "remediation": "Review exposed technology stack for known vulnerabilities.",
            "cves": _cves, **_v11,
        }
    if _NUCLEI_DYN_WAF.search(_tid):
        _waf_name_upper = _name.upper()
        _is_lb = any(lb.upper() in _waf_name_upper for lb in (
            "F5", "BIG-IP", "HAProxy", "Nginx LB", "AWS ELB", "Azure LB",
            "Citrix NetScaler", "Envoy",
        ))
        if _is_lb:
            return {
                "title": f"Load Balancer Detected: {_name}", "risk": "INFO",
                "description": (
                    _desc or f"A load balancer ({_name}) was identified in front of the target. "
                    "The load balancer distributes traffic but does NOT perform application-layer "
                    "inspection or WAF-style blocking."
                ),
                "output": str(_output)[:2000] if _output else f"Template: {_tid}",
                "owasp": "A05:2025 Security Misconfiguration", "nist": "SC-7",
                "remediation": (
                    "Ensure load balancer cookies do not leak internal infrastructure details. "
                    "Review session affinity configuration. Do not confuse load balancing with "
                    "WAF protection."
                ),
                "cves": _cves, **_v11,
            }
        return {
            "title": f"WAF / Edge Security Platform Active: {_name}", "risk": "INFO",
            "description": _desc or f"{_name} detected by nuclei ({_tid}).",
            "output": str(_output)[:2000] if _output else f"Template: {_tid}",
            "owasp": "A05:2025 Security Misconfiguration", "nist": "CM-7",
            "remediation": "WAF/CDN detected — informational.",
            "cves": _cves, **_v11,
        }
    if _NUCLEI_DYN_PANEL.search(_tid):
        _panel_path = ""
        try:
            _panel_path = urllib.parse.urlparse(_matched).path or ""
        except Exception:
            pass
        _panel_title = f"Admin Panel Exposed: {_panel_path}" if _panel_path else f"Admin Panel Exposed: {_name}"
        return {
            "title": _panel_title, "risk": "HIGH",
            "description": _desc or f"{_name} detected by nuclei ({_tid}).",
            "output": str(_output)[:2000] if _output else f"Template: {_tid}",
            "owasp": "A05:2025 Security Misconfiguration", "nist": "AC-3",
            "remediation": "Restrict admin interfaces by IP allowlist or VPN.",
            "cves": _cves, **_v11,
        }

    # Priority 3: Table-driven regex
    _nuc_search_fields = [_tid]
    if _matcher:
        _nuc_search_fields.append(_matcher)
    _nuc_search_fields.append(_name)
    for _rx, _title, _risk, _owasp, _nist, _remed in _NUCLEI_NORM_COMPILED:
        if any(_rx.search(f) for f in _nuc_search_fields):
            if _title is None:
                break
            if _title == "__SUPPRESS__":
                return {}
            return {
                "title": _title, "risk": _risk or _sev,
                "description": _desc or f"{_name} ({_tid})",
                "output": str(_output)[:2000] if _output else f"Template: {_tid}",
                "owasp": _owasp, "nist": _nist,
                "remediation": _remed, "cves": _cves, **_v11,
            }

    # Priority 4: Template-path directory category
    _tpath = item.get("template-path", "")
    if _tpath:
        _tp_parts = _tpath.replace("\\", "/").split("/")
        if "exposed-panels" in _tp_parts:
            _ep_path = ""
            try:
                _ep_path = urllib.parse.urlparse(_matched).path or ""
            except Exception:
                pass
            _clean = _name
            for _sfx in (" - Detect", " - Detection", " - Exposure",
                         " Panel - Detect", " Login Panel - Detect",
                         " Login - Detect", " Panel Detect"):
                if _clean.endswith(_sfx):
                    _clean = _clean[:-len(_sfx)].strip()
                    break
            _ep_title = f"Admin Panel Exposed: {_ep_path}" if _ep_path else f"Admin Panel Exposed: {_clean}"
            return {
                "title": _ep_title, "risk": _sev or "MEDIUM",
                "description": _desc or f"{_name} ({_tid})",
                "output": str(_output)[:2000] if _output else f"Template: {_tid}",
                "owasp": "A01:2025 Broken Access Control", "nist": "CM-7",
                "remediation": "Restrict access to administrative panels.",
                "cves": _cves, **_v11,
            }
        if "technologies" in _tp_parts:
            _clean = _name
            for _sfx in (" - Detect", " - Detection", " - Tech Detect",
                         " - Discovery"):
                if _clean.endswith(_sfx):
                    _clean = _clean[:-len(_sfx)].strip()
                    break
            return {
                "title": f"Technology Identified: {_clean}", "risk": _sev or "INFO",
                "description": _desc or f"{_name} ({_tid})",
                "output": str(_output)[:2000] if _output else f"Template: {_tid}",
                "owasp": "A06:2025 Vulnerable and Outdated Components", "nist": "SI-2",
                "remediation": "Keep identified components up to date.",
                "cves": _cves, **_v11,
            }
        if "default-logins" in _tp_parts:
            return {
                "title": f"Default Credentials: {_name}", "risk": _sev or "HIGH",
                "description": _desc or f"{_name} ({_tid})",
                "output": str(_output)[:2000] if _output else f"Template: {_tid}",
                "owasp": "A07:2025 Identification and Authentication Failures", "nist": "IA-5",
                "remediation": "Change default credentials immediately.",
                "cves": _cves, **_v11,
            }
        if "exposures" in _tp_parts:
            _ep_path = ""
            try:
                _ep_path = urllib.parse.urlparse(_matched).path or ""
            except Exception:
                pass
            return {
                "title": f"Sensitive Path Accessible: {_ep_path}" if _ep_path else f"Sensitive Path Accessible: {_name}",
                "risk": _sev or "MEDIUM",
                "description": _desc or f"{_name} ({_tid})",
                "output": str(_output)[:2000] if _output else f"Template: {_tid}",
                "owasp": "A01:2025 Broken Access Control", "nist": "AC-3",
                "remediation": "Restrict access to the exposed resource.",
                "cves": _cves, **_v11,
            }
        if "cves" in _tp_parts or "vulnerabilities" in _tp_parts:
            return {
                "title": f"Vulnerable Component: {_name}", "risk": _sev,
                "description": _desc or f"{_name} ({_tid})",
                "output": str(_output)[:2000] if _output else f"Template: {_tid}",
                "owasp": "A06:2025 Vulnerable and Outdated Components", "nist": "SI-2",
                "remediation": "Apply vendor patches and update affected components.",
                "cves": _cves, **_v11,
            }
        if "misconfiguration" in _tp_parts:
            return {
                "title": f"Server Misconfiguration: {_name}", "risk": _sev,
                "description": _desc or f"{_name} ({_tid})",
                "output": str(_output)[:2000] if _output else f"Template: {_tid}",
                "owasp": "A05:2025 Security Misconfiguration", "nist": "CM-6",
                "remediation": "Review and correct the identified misconfiguration.",
                "cves": _cves, **_v11,
            }

    # Fallback
    return {
        "title": _name, "risk": _sev,
        "description": _desc or f"Nuclei template {_tid} matched.",
        "output": str(_output)[:2000] if _output else f"Template: {_tid}",
        "owasp": "A06:2025 Vulnerable and Outdated Components", "nist": "SI-2",
        "remediation": "Apply vendor patches and update affected components.",
        "cves": _cves, **_v11,
    }


def _extract_target_from_item(item):
    targets = set()
    host = item.get("host", "")
    if host:
        try:
            parsed = urllib.parse.urlparse(host)
            h = parsed.hostname or host
            targets.add(h)
        except Exception:
            targets.add(host)
    matched = item.get("matched-at", "")
    if matched:
        try:
            parsed = urllib.parse.urlparse(matched)
            h = parsed.hostname
            if h:
                targets.add(h)
        except Exception:
            pass
    ip = item.get("ip", "")
    if ip:
        targets.add(ip)
    return targets


class NucleiParser(BaseParser):
    TOOL_ID = "nuclei"
    TOOL_NAME = "Nuclei"
    SUPPORTED_FORMATS = ["jsonl", "json"]

    def parse(self):
        self.emit("log", f"Parsing Nuclei JSONL: {self.file_path.name}")
        count = 0
        skipped = 0
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            self.emit("log", f"ERROR: Failed to read file: {exc}")
            return

        for line_no, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                self.emit("log", f"WARN: Skipping malformed JSON at line {line_no}")
                continue

            if not isinstance(item, dict):
                continue

            normalized = _normalize_nuclei(item)
            if not normalized or not normalized.get("title"):
                skipped += 1
                continue

            _matched = item.get("matched-at", "")
            _host = item.get("host", "")
            ip = item.get("ip", "")
            hostname = ""
            port = 0

            if _matched:
                try:
                    parsed = urllib.parse.urlparse(_matched)
                    hostname = parsed.hostname or ""
                    if parsed.port:
                        port = parsed.port
                    elif parsed.scheme == "https":
                        port = 443
                    elif parsed.scheme == "http":
                        port = 80
                except Exception:
                    pass
            elif _host:
                try:
                    parsed = urllib.parse.urlparse(_host)
                    hostname = parsed.hostname or _host
                    if parsed.port:
                        port = parsed.port
                except Exception:
                    hostname = _host

            if not ip and hostname:
                ip = hostname

            _tid = item.get("template-id", "")

            finding = {
                "id":               str(uuid.uuid4()),
                "tool":             "nuclei",
                "title":            normalized["title"],
                "datetime":         item.get("timestamp", datetime.datetime.now().isoformat()),
                "ip":               ip,
                "port":             port,
                "hostname":         hostname,
                "risk":             normalized.get("risk", "INFO"),
                "command":          f"nuclei -t {_tid}",
                "description":      normalized.get("description", ""),
                "output":           normalized.get("output", "")[:4096],
                "output_file":      "",
                "cves":             normalized.get("cves", ""),
                "sources":          "nuclei",
                "service":          "",
                "affected":         f"{ip}:{port}" if port else ip,
                "remediation":      normalized.get("remediation", ""),
                "owasp":            normalized.get("owasp", ""),
                "nist":             normalized.get("nist", ""),
                "exploitdb":        False,
                "metasploit":       False,
                "exploit_details":  [],
            }
            if "cvss_score" in normalized:
                finding["cvss_score"] = normalized["cvss_score"]
            if "cvss_vector" in normalized:
                finding["cvss_vector"] = normalized["cvss_vector"]
            if "cwe" in normalized:
                finding["cwe"] = normalized["cwe"]

            yield ("finding", finding)
            count += 1

        self.emit("log", f"Parsed {count} findings from Nuclei JSONL ({skipped} suppressed)")

    def extract_targets(self):
        targets = set()
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                    if isinstance(item, dict):
                        targets.update(_extract_target_from_item(item))
                except json.JSONDecodeError:
                    continue
        except Exception:
            pass
        return targets
