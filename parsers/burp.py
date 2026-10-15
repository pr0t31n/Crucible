"""Parser for Burp Suite XML export files."""

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from parsers.base import BaseParser

_RE_HTML_TAG = re.compile(r'<[^>]+>')
_RE_URL = re.compile(r'https?://([^/\s:]+)(?::(\d+))?')

_SEVERITY_MAP = {
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "information": "INFO",
    "info": "INFO",
}


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _strip_html(text):
    if not text:
        return ""
    return _RE_HTML_TAG.sub("", text).strip()


def _el_text(el, tag):
    child = el.find(tag)
    if child is not None and child.text:
        return child.text.strip()
    return ""


class BurpParser(BaseParser):
    TOOL_ID = "burp"
    TOOL_NAME = "Burp Suite"
    SUPPORTED_FORMATS = ["xml"]

    def parse(self):
        of = str(self.file_path)
        try:
            tree = ET.parse(self.file_path)
            root = tree.getroot()
        except (ET.ParseError, OSError) as exc:
            self.emit("log", f"Burp XML parse error: {exc}")
            return

        for issue in root.iter("issue"):
            name = _el_text(issue, "name")
            if not name:
                continue

            severity = _el_text(issue, "severity").lower()
            if severity == "false positive":
                continue
            risk = _SEVERITY_MAP.get(severity, "INFO")

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

            path = _el_text(issue, "path")
            location = _el_text(issue, "location")

            bg = _strip_html(_el_text(issue, "issueBackground"))
            detail = _strip_html(_el_text(issue, "issueDetail"))
            desc = bg
            if detail:
                desc = f"{bg}\n\n{detail}" if bg else detail
            if not desc:
                desc = name

            rem_bg = _strip_html(_el_text(issue, "remediationBackground"))
            rem_detail = _strip_html(_el_text(issue, "remediationDetail"))
            remediation = rem_bg
            if rem_detail:
                remediation = f"{rem_bg}\n\n{rem_detail}" if rem_bg else rem_detail
            if not remediation:
                remediation = f"Review and remediate: {name}"

            confidence = _el_text(issue, "confidence")

            output_parts = []
            if location:
                output_parts.append(f"Location: {location}")
            if confidence:
                output_parts.append(f"Confidence: {confidence}")

            rr = issue.find("requestresponse")
            if rr is not None:
                req_el = rr.find("request")
                if req_el is not None and req_el.text:
                    req_text = req_el.text[:500]
                    output_parts.append(f"Request (truncated):\n{req_text}")
                resp_el = rr.find("response")
                if resp_el is not None and resp_el.text:
                    resp_text = resp_el.text[:500]
                    output_parts.append(f"Response (truncated):\n{resp_text}")

            affected = host_url
            if path:
                affected = f"{host_url}{path}"

            self.emit("log", f"Burp issue: {name} ({risk}) on {ip}:{port}")
            yield ("finding", {
                "title": name,
                "datetime": _now_iso(),
                "ip": ip,
                "port": port,
                "hostname": hostname,
                "risk": risk,
                "command": "burp (imported)",
                "description": desc[:4096],
                "output": "\n".join(output_parts)[:4096],
                "cves": "",
                "sources": "burp",
                "service": "https" if port == 443 else "http",
                "output_file": of,
                "affected": affected,
                "exploitdb": False,
                "metasploit": False,
                "exploit_details": [],
                "remediation": remediation[:4096],
            })

    def extract_targets(self):
        targets = set()
        try:
            for event, el in ET.iterparse(self.file_path, events=("end",)):
                if el.tag == "host":
                    ip = el.get("ip", "")
                    if ip:
                        targets.add(ip)
                    text = (el.text or "").strip()
                    m = _RE_URL.search(text)
                    if m:
                        targets.add(m.group(1))
                    el.clear()
        except (ET.ParseError, OSError):
            pass
        return targets
