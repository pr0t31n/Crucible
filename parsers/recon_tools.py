"""Parsers for recon tools (shcheck, Shodan CLI, webanalyze)."""

import json
import re
from datetime import datetime, timezone
from parsers.base import BaseParser

_RE_SHCHECK_MISS_V1 = re.compile(r'^\[!\]\s+Missing\s+security\s+header:\s+(\S+)', re.I)
_RE_SHCHECK_MISS_V2 = re.compile(
    r'^\[!\]\s+(?:The\s+)?[Hh]eader\s+[\'"]?([A-Za-z0-9_-]+)[\'"]?\s+is\s+missing')
_RE_URL = re.compile(r'https?://([^/\s:]+)(?::(\d+))?')
_RE_IP = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
_RE_SHODAN_IP = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$', re.M)
_RE_SHODAN_PORTS = re.compile(r'Ports:\s*(.+)', re.I)
_RE_SHODAN_VULNS = re.compile(r'Vulnerabilities:\s*(.+)', re.I)
_RE_CVE = re.compile(r'CVE-\d{4}-\d{4,}')

_DEPRECATED_HEADERS = frozenset({"Expect-CT", "Public-Key-Pins"})
_HSTS = "Strict-Transport-Security"


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _finding(title, ip, port, risk, desc, sources, affected, output,
             service="", remediation="", output_file="",
             cves="", exploitdb=False, metasploit=False):
    return {
        "title": title, "datetime": _now_iso(), "ip": ip,
        "port": int(port) if port else 0, "hostname": "",
        "risk": risk, "command": f"{sources} (imported)",
        "description": desc, "output": output[:4096],
        "cves": cves, "sources": sources, "service": service,
        "output_file": output_file, "affected": affected,
        "exploitdb": exploitdb, "metasploit": metasploit,
        "exploit_details": [], "remediation": remediation,
    }


class ShcheckParser(BaseParser):
    TOOL_ID = "shcheck"
    TOOL_NAME = "shcheck"
    SUPPORTED_FORMATS = ["json", "txt"]

    def parse(self):
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        of = str(self.file_path)
        url = ""
        ip = ""
        port = 0

        stripped = text.strip()
        if stripped.startswith("{"):
            yield from self._parse_json(stripped, of)
        else:
            yield from self._parse_text(text, of)

    def _parse_json(self, text, of):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            yield from self._parse_text(text, of)
            return

        if not isinstance(data, dict):
            return

        missing_headers = []
        url = ""

        if "missing" in data:
            missing_headers = data.get("missing") or []
            for k in data:
                m = _RE_URL.search(k)
                if m:
                    url = k
                    break
        else:
            for key, val in data.items():
                if isinstance(val, dict) and "missing" in val:
                    url = key
                    mh = val.get("missing")
                    if isinstance(mh, list):
                        missing_headers.extend(mh)

        ip, port = self._extract_ip_port(url)

        seen = set()
        for header_name in missing_headers:
            header_name = str(header_name).strip()
            if not header_name or header_name in seen or header_name in _DEPRECATED_HEADERS:
                continue
            seen.add(header_name)
            risk = "MEDIUM" if header_name == _HSTS else "LOW"
            self.emit("log", f"Missing header: {header_name}")
            yield ("finding", _finding(
                title=f"Missing Security Header: {header_name}",
                ip=ip, port=port, risk=risk,
                desc=f"The web service is missing the '{header_name}' "
                     "HTTP security response header.",
                sources="shcheck", affected=url or ip or "unknown",
                output=f"Missing header: {header_name}\nURL: {url}",
                output_file=of,
                remediation=f"Add the '{header_name}' header to all HTTP responses.",
            ))

    def _parse_text(self, text, of):
        ip = ""
        port = 0
        url = ""
        m = _RE_URL.search(text)
        if m:
            url = m.group(0)
            ip, port = self._extract_ip_port(url)

        seen = set()
        for line in text.splitlines():
            line = line.strip()
            header_name = None
            m = _RE_SHCHECK_MISS_V1.match(line)
            if m:
                header_name = m.group(1)
            if not header_name:
                m = _RE_SHCHECK_MISS_V2.match(line)
                if m:
                    header_name = m.group(1)
            if not header_name or header_name in seen or header_name in _DEPRECATED_HEADERS:
                continue
            seen.add(header_name)
            risk = "MEDIUM" if header_name == _HSTS else "LOW"
            self.emit("log", f"Missing header: {header_name}")
            yield ("finding", _finding(
                title=f"Missing Security Header: {header_name}",
                ip=ip, port=port, risk=risk,
                desc=f"The web service is missing the '{header_name}' "
                     "HTTP security response header.",
                sources="shcheck", affected=url or ip or "unknown",
                output=f"Missing header: {header_name}\nSource: {line[:200]}",
                output_file=of,
                remediation=f"Add the '{header_name}' header to all HTTP responses.",
            ))

    @staticmethod
    def _extract_ip_port(url):
        if not url:
            return "", 0
        m = _RE_URL.search(url)
        if not m:
            return "", 0
        host = m.group(1)
        port_str = m.group(2)
        if port_str:
            port = int(port_str)
        elif url.startswith("https"):
            port = 443
        else:
            port = 80
        return host, port

    def extract_targets(self):
        targets = set()
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return targets
        for m in _RE_URL.finditer(text):
            targets.add(m.group(1))
        for m in _RE_IP.finditer(text):
            targets.add(m.group(1))
        return targets


class ShodanParser(BaseParser):
    TOOL_ID = "shodan"
    TOOL_NAME = "Shodan CLI"
    SUPPORTED_FORMATS = ["txt"]

    def parse(self):
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        of = str(self.file_path)

        ip = ""
        m = _RE_SHODAN_IP.search(text)
        if m:
            ip = m.group(1)

        m = _RE_SHODAN_PORTS.search(text)
        if m:
            ports_raw = m.group(1)
            for ps in ports_raw.split(","):
                ps = ps.strip()
                if ps.isdigit():
                    yield ("port", {"ip": ip, "port": int(ps), "service": "", "source": "shodan"})

        m = _RE_SHODAN_VULNS.search(text)
        if m:
            vulns_raw = m.group(1)
            for cve in _RE_CVE.findall(vulns_raw):
                self.emit("log", f"Shodan vulnerability: {cve} on {ip}")
                yield ("finding", _finding(
                    title=f"Shodan: {cve}",
                    ip=ip, port=0, risk="HIGH",
                    desc=f"Shodan reports vulnerability {cve} on {ip}. "
                         "This finding is based on Shodan's passive scanning data "
                         "and may require manual verification.",
                    sources="shodan", affected=ip,
                    output=f"CVE: {cve}\nHost: {ip}",
                    output_file=of, cves=cve,
                    remediation=f"Investigate and remediate {cve} on {ip}.",
                ))

    def extract_targets(self):
        targets = set()
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return targets
        for m in _RE_IP.finditer(text):
            targets.add(m.group(1))
        return targets


class WebanalyzeParser(BaseParser):
    TOOL_ID = "webanalyze"
    TOOL_NAME = "webanalyze"
    SUPPORTED_FORMATS = ["txt"]

    def parse(self):
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        of = str(self.file_path)
        current_url = ""
        current_ip = ""
        current_port = 0
        in_target = False

        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if stripped.startswith("http") and "error" not in stripped.lower():
                current_url = stripped
                m = _RE_URL.search(stripped)
                if m:
                    current_ip = m.group(1)
                    p = m.group(2)
                    if p:
                        current_port = int(p)
                    elif stripped.startswith("https"):
                        current_port = 443
                    else:
                        current_port = 80
                in_target = True
                continue

            if not in_target:
                continue

            tech = stripped.lstrip("- ").strip()
            if not tech or tech == "<no results>":
                continue
            if tech.lower().startswith("hsts"):
                continue

            parts = [t.strip() for t in tech.split(",", 1)]
            sw_name = parts[0]
            sw_ver_raw = parts[1] if len(parts) > 1 else ""
            sw_ver = sw_ver_raw if sw_ver_raw and not sw_ver_raw.startswith("(") else ""

            ver_str = f" {sw_ver}" if sw_ver else ""
            self.emit("log", f"Technology: {sw_name}{ver_str} on {current_ip}:{current_port}")
            yield ("finding", _finding(
                title=f"Software Version Detected: {sw_name}",
                ip=current_ip, port=current_port, risk="INFO",
                desc=f"Technology '{sw_name}'{(' version ' + sw_ver) if sw_ver else ''} "
                     f"detected on {current_url or current_ip}.",
                sources="webanalyze", affected=current_url or f"{current_ip}:{current_port}",
                output=f"Technology: {sw_name}\nVersion: {sw_ver or 'unknown'}\nURL: {current_url}",
                output_file=of,
                remediation="Ensure detected software is up to date and unnecessary version "
                            "information is not exposed in HTTP headers.",
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
