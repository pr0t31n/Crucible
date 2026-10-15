"""Parsers for web scanning tools (WPScan, ffuf, gobuster, feroxbuster, nikto).
Finding titles match SS3/Fracture conventions exactly."""

import json
import re
from datetime import datetime, timezone
from urllib.parse import urlparse
from parsers.base import BaseParser

_RE_GOBUSTER = re.compile(r'(/\S+)\s+\(Status:\s*(\d+)\)')
_RE_FEROX = re.compile(r'^(\d{3})\s+\w+\s+.*?(https?://\S+)', re.M)
_RE_URL = re.compile(r'https?://([^/:]+)(?::(\d+))?')
_RE_IP = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')


def _url_to_host_port(url):
    try:
        p = urlparse(url)
        host = p.hostname or ""
        port = p.port or (443 if p.scheme == "https" else 80)
        return host, int(port)
    except Exception:
        return "", 80


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _finding(title, ip, port, risk, desc, sources, affected, output,
             service="", remediation="", output_file="",
             cves="", owasp="", nist=""):
    return {
        "title": title, "datetime": _now_iso(), "ip": ip,
        "port": int(port) if port else 0, "hostname": "",
        "risk": risk, "command": f"{sources} (imported)",
        "description": desc, "output": output[:4096],
        "cves": cves, "sources": sources, "service": service,
        "output_file": output_file, "affected": affected,
        "exploitdb": False, "metasploit": False,
        "exploit_details": [], "remediation": remediation,
    }


_NIKTO_NORM = [
    (re.compile(r"X-Frame-Options header", re.I),
     "Missing Security Header: X-Frame-Options", "MEDIUM"),
    (re.compile(r"X-Content-Type-Options header", re.I),
     "Missing Security Header: X-Content-Type-Options", "MEDIUM"),
    (re.compile(r"Strict-Transport-Security|HSTS", re.I),
     "Missing Security Header: Strict-Transport-Security", "MEDIUM"),
    (re.compile(r"Content-Security-Policy|CSP header", re.I),
     "Missing Security Header: Content-Security-Policy", "MEDIUM"),
    (re.compile(r"X-XSS-Protection header", re.I),
     "Missing Security Header: X-XSS-Protection", "MEDIUM"),
    (re.compile(r"[Rr]etrieved\s+server\s+header|server.*header.*version", re.I),
     "Information Disclosure: Server Header", "LOW"),
    (re.compile(r"X-Powered-By", re.I),
     "Information Disclosure: X-Powered-By Header", "LOW"),
    (re.compile(r"SSL cert.*expir|certificate.*expir", re.I),
     "SSL/TLS Certificate: Expired", "HIGH"),
    (re.compile(r"self.signed cert|self-signed", re.I),
     "SSL/TLS Certificate: Self-Signed", "MEDIUM"),
    (re.compile(r"SSLv[23]|TLSv1\.0|TLSv1\.1|deprecated.*(?:SSL|TLS)", re.I),
     "SSL/TLS Vulnerability: Deprecated Protocol Version", "MEDIUM"),
    (re.compile(r"directory.*listing|indexing.*enabled|Index of /", re.I),
     "Directory Listing Enabled", "MEDIUM"),
    (re.compile(r"OPTIONS.*method|Public HTTP Method|Allowed HTTP Method", re.I),
     "HTTP Methods: Unsafe Methods Enabled", "MEDIUM"),
    (re.compile(r"TRACE.*method|TRACK.*method", re.I),
     "HTTP Methods: Unsafe Methods Enabled", "MEDIUM"),
    (re.compile(r"PUT.*method|DELETE.*method|WebDAV", re.I),
     "HTTP Methods: Unsafe Methods Enabled", "MEDIUM"),
    (re.compile(r"phpinfo|phpMyAdmin", re.I),
     "Information Disclosure: PHP Configuration Exposed", "MEDIUM"),
    (re.compile(r"default (web)?page|default.*install", re.I),
     "Default Web Page / Installation Present", "LOW"),
]


class WPScanParser(BaseParser):
    TOOL_ID = "wpscan"
    TOOL_NAME = "WPScan"
    SUPPORTED_FORMATS = ["json"]

    def parse(self):
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
            data = json.loads(text)
        except (OSError, json.JSONDecodeError) as exc:
            self.emit("log", f"Failed to parse WPScan JSON: {exc}")
            return

        if not isinstance(data, dict):
            return

        of = str(self.file_path)
        target_url = data.get("target_url", "")
        ip, port = _url_to_host_port(target_url)

        if ip:
            yield ("target", {"ip": ip, "port": port, "hostname": ip})

        ver_info = data.get("version", {})
        if isinstance(ver_info, dict):
            ver_num = ver_info.get("number", "")
            for vuln in ver_info.get("vulnerabilities", []):
                title = vuln.get("title", "Unknown WordPress Core Vulnerability")
                cves = self._extract_cves(vuln)
                self.emit("log", f"WPScan core vuln: {title}")
                yield ("finding", _finding(
                    title=f"WordPress Core Vulnerability: {title[:80]}",
                    ip=ip, port=port, risk="CRITICAL",
                    desc=f"WordPress {ver_num} at {target_url} has a known core vulnerability: {title}",
                    sources="wpscan", affected=target_url,
                    output=f"Version: {ver_num}\nVulnerability: {title}",
                    output_file=of, cves=cves,
                    owasp="A06:2025 Vulnerable and Outdated Components",
                    remediation="Update WordPress to the latest version.",
                ))

        plugins = data.get("plugins") or {}
        if isinstance(plugins, dict):
            for slug, plugin in plugins.items():
                if not isinstance(plugin, dict):
                    continue
                for vuln in plugin.get("vulnerabilities", []):
                    title = vuln.get("title", "Unknown Plugin Vulnerability")
                    cves = self._extract_cves(vuln)
                    self.emit("log", f"WPScan plugin vuln: {title}")
                    yield ("finding", _finding(
                        title=f"WordPress Plugin Vulnerability: {title[:65]} ({slug})",
                        ip=ip, port=port, risk="HIGH",
                        desc=f"WordPress plugin '{slug}' has a vulnerability: {title}",
                        sources="wpscan", affected=target_url,
                        output=f"Plugin: {slug}\nVulnerability: {title}\nFixed in: {vuln.get('fixed_in', 'N/A')}",
                        output_file=of, cves=cves,
                        owasp="A06:2025 Vulnerable and Outdated Components",
                        remediation=f"Update or remove the '{slug}' plugin.",
                    ))

        themes = {}
        main_theme = data.get("main_theme")
        if isinstance(main_theme, dict):
            tslug = main_theme.get("slug", "main_theme")
            themes[tslug] = main_theme
        themes.update(data.get("themes") or {})
        for slug, theme in themes.items():
            if not isinstance(theme, dict):
                continue
            for vuln in theme.get("vulnerabilities", []):
                title = vuln.get("title", "Unknown Theme Vulnerability")
                cves = self._extract_cves(vuln)
                self.emit("log", f"WPScan theme vuln: {title}")
                yield ("finding", _finding(
                    title=f"WordPress Theme Vulnerability: {title[:70]} ({slug})",
                    ip=ip, port=port, risk="HIGH",
                    desc=f"WordPress theme '{slug}' has a vulnerability: {title}",
                    sources="wpscan", affected=target_url,
                    output=f"Theme: {slug}\nVulnerability: {title}\nFixed in: {vuln.get('fixed_in', 'N/A')}",
                    output_file=of, cves=cves,
                    owasp="A06:2025 Vulnerable and Outdated Components",
                    remediation=f"Update or remove the '{slug}' theme.",
                ))

        users = data.get("users", {})
        if isinstance(users, dict) and users:
            user_list = sorted(users.keys())
            self.emit("log", f"WPScan users: {len(user_list)} found")
            yield ("finding", _finding(
                title="WordPress User Enumeration",
                ip=ip, port=port, risk="MEDIUM",
                desc=f"WPScan enumerated {len(user_list)} WordPress user(s) at {target_url}.",
                sources="wpscan", affected=target_url,
                output=f"Users: {', '.join(user_list[:20])}",
                output_file=of,
                owasp="A01:2025 Broken Access Control",
                remediation="Disable user enumeration by blocking /?author=N and REST API user endpoints.",
            ))

    @staticmethod
    def _extract_cves(vuln):
        refs = vuln.get("references", {})
        if not isinstance(refs, dict):
            return ""
        cves = []
        for cve in refs.get("cve", []):
            s = str(cve)
            cves.append(f"CVE-{s}" if not s.startswith("CVE-") else s)
        return ",".join(cves)

    def extract_targets(self):
        targets = set()
        try:
            data = json.loads(self.file_path.read_text(encoding="utf-8", errors="replace"))
            url = data.get("target_url", "")
            h, _ = _url_to_host_port(url)
            if h:
                targets.add(h)
        except (OSError, json.JSONDecodeError):
            pass
        return targets


class FfufParser(BaseParser):
    TOOL_ID = "ffuf"
    TOOL_NAME = "ffuf"
    SUPPORTED_FORMATS = ["json"]

    def parse(self):
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
            data = json.loads(text)
        except (OSError, json.JSONDecodeError) as exc:
            self.emit("log", f"Failed to parse ffuf JSON: {exc}")
            return

        if not isinstance(data, dict):
            return

        of = str(self.file_path)
        cmd_line = data.get("commandline", "")
        results = data.get("results", [])
        self.emit("log", f"ffuf: {len(results)} results")

        ip, port = "", 80
        m = _RE_URL.search(cmd_line)
        if m:
            ip = m.group(1)
            port = int(m.group(2)) if m.group(2) else 80

        if ip:
            yield ("target", {"ip": ip, "port": port, "hostname": ip})

        for r in results:
            if not isinstance(r, dict):
                continue
            status = r.get("status", 0)
            if status in (404, 405):
                continue
            url = r.get("url", "")
            length = r.get("length", 0)
            inp = r.get("input", {})
            fuzz_word = inp.get("FUZZ", "") if isinstance(inp, dict) else str(inp)

            self.emit("log", f"ffuf: {url} [{status}]")
            yield ("finding", _finding(
                title="Discovery: Web Page",
                ip=ip, port=port, risk="INFO",
                desc=f"Content discovered at {url} (HTTP {status}, {length} bytes).",
                sources="ffuf", affected=url,
                output=f"URL: {url}\nStatus: {status}\nLength: {length}\nFUZZ: {fuzz_word}",
                output_file=of,
                remediation="Review discovered content for sensitive information exposure.",
            ))

    def extract_targets(self):
        targets = set()
        try:
            data = json.loads(self.file_path.read_text(encoding="utf-8", errors="replace"))
            m = _RE_URL.search(data.get("commandline", ""))
            if m:
                targets.add(m.group(1))
        except (OSError, json.JSONDecodeError):
            pass
        return targets


class GobusterParser(BaseParser):
    TOOL_ID = "gobuster"
    TOOL_NAME = "gobuster"
    SUPPORTED_FORMATS = ["txt"]

    def parse(self):
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        of = str(self.file_path)
        base_url = ""
        m = _RE_URL.search(text[:2048])
        if m:
            base_url = m.group(0) if "://" in text[:2048] else ""
        ip, port = _url_to_host_port(base_url) if base_url else ("", 80)

        if ip:
            yield ("target", {"ip": ip, "port": port, "hostname": ip})

        seen = set()
        for line in text.splitlines():
            m = _RE_GOBUSTER.search(line)
            if not m:
                continue
            path = m.group(1)
            status = int(m.group(2))
            if path in seen or status in (401, 403, 404, 405):
                continue
            seen.add(path)

            found_url = base_url.rstrip("/") + path if base_url else path
            self.emit("log", f"gobuster: {path} [{status}]")
            yield ("finding", _finding(
                title="Discovery: Web Page",
                ip=ip, port=port, risk="INFO",
                desc=f"A web page was identified at {found_url} (HTTP {status}).",
                sources="gobuster", affected=found_url,
                output=line.strip(),
                output_file=of,
                remediation="Review discovered content for sensitive information exposure.",
            ))

    def extract_targets(self):
        targets = set()
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return targets
        for m in _RE_URL.finditer(text[:4096]):
            targets.add(m.group(1))
        return targets


class FeroxbusterParser(BaseParser):
    TOOL_ID = "feroxbuster"
    TOOL_NAME = "feroxbuster"
    SUPPORTED_FORMATS = ["txt"]

    def parse(self):
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        of = str(self.file_path)
        ip, port = "", 80
        m = _RE_URL.search(text[:4096])
        if m:
            ip = m.group(1)
            port = int(m.group(2)) if m.group(2) else 80

        if ip:
            yield ("target", {"ip": ip, "port": port, "hostname": ip})

        seen = set()
        for line in text.splitlines():
            m = _RE_FEROX.match(line.strip())
            if not m:
                continue
            status = int(m.group(1))
            url = m.group(2)
            if status in (404, 405) or url in seen:
                continue
            seen.add(url)

            h, p = _url_to_host_port(url)
            self.emit("log", f"feroxbuster: {url} [{status}]")
            yield ("finding", _finding(
                title="Discovery: Web Page",
                ip=h or ip, port=p or port, risk="INFO",
                desc=f"Content discovered at {url} (HTTP {status}).",
                sources="feroxbuster", affected=url,
                output=line.strip()[:500],
                output_file=of,
                remediation="Review discovered content for sensitive information exposure.",
            ))

    def extract_targets(self):
        targets = set()
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return targets
        for m in _RE_URL.finditer(text):
            targets.add(m.group(1))
        return targets


class NiktoParser(BaseParser):
    TOOL_ID = "nikto"
    TOOL_NAME = "Nikto"
    SUPPORTED_FORMATS = ["txt", "csv"]

    def parse(self):
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        of = str(self.file_path)
        ip = ""
        port = 0

        m = re.search(r'Target IP:\s*(\S+)', text)
        if m:
            ip = m.group(1)
        m = re.search(r'Target Port:\s*(\d+)', text)
        if m:
            port = int(m.group(1))

        if ip:
            yield ("target", {"ip": ip, "port": port, "hostname": ip})

        re_item = re.compile(r'^\+\s+(?:OSVDB-(\d+):?\s*)?(.+)', re.M)
        seen = set()
        for m in re_item.finditer(text):
            osvdb = m.group(1) or ""
            msg = m.group(2).strip()
            if not msg or msg in seen:
                continue
            if msg.startswith("Target") or msg.startswith("Start") or msg.startswith("End"):
                continue
            seen.add(msg)

            title, risk = self._normalize(msg)

            self.emit("log", f"Nikto: {title}")
            yield ("finding", _finding(
                title=title,
                ip=ip, port=port, risk=risk,
                desc=msg,
                sources="nikto", affected=f"{ip}:{port}" if ip else "unknown",
                output=f"{'OSVDB-' + osvdb + ': ' if osvdb else ''}{msg}",
                output_file=of,
                owasp="A05:2025 Security Misconfiguration",
                remediation="Address the identified misconfiguration or vulnerability.",
            ))

    @staticmethod
    def _normalize(msg):
        for pattern, title, risk in _NIKTO_NORM:
            if pattern.search(msg):
                return title, risk
        first_sentence = msg.split(".")[0].strip() if msg else "Unknown finding"
        return first_sentence[:120], "INFO"

    def extract_targets(self):
        targets = set()
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return targets
        m = re.search(r'Target IP:\s*(\S+)', text)
        if m:
            targets.add(m.group(1))
        m = re.search(r'Target Hostname:\s*(\S+)', text)
        if m:
            targets.add(m.group(1))
        return targets
