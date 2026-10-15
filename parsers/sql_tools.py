"""Parsers for SQL injection, exploit lookup, and Metasploit tools."""

import json
import re
from datetime import datetime, timezone
from parsers.base import BaseParser

_RE_SQLI_VULN = re.compile(
    r'(?:Parameter.*is (?:vulnerable|injectable)|'
    r'sqlmap identified the following injection point|'
    r'\bis vulnerable\b)', re.I)
_RE_SQLI_PARAM = re.compile(r'Parameter:\s*(\S+)\s*\((\w+)\)', re.I)
_RE_SQLI_URL = re.compile(r'(?:URL|Target URL|target url):\s*(\S+)', re.I)
_RE_URL_EXTRACT = re.compile(r'https?://[^\s"\'<>]+')
_RE_IP = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
_RE_MSF_MODULE = re.compile(r'^\s*\d+\s+((?:exploit|auxiliary|post)/\S+)')


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _finding(title, ip, port, risk, desc, sources, affected, output,
             service="", remediation="", output_file="",
             cves="", exploitdb=False, metasploit=False,
             owasp="", nist=""):
    f = {
        "title": title, "datetime": _now_iso(), "ip": ip,
        "port": int(port) if port else 0, "hostname": "",
        "risk": risk, "command": f"{sources} (imported)",
        "description": desc, "output": output[:4096],
        "cves": cves, "sources": sources, "service": service,
        "output_file": output_file, "affected": affected,
        "exploitdb": exploitdb, "metasploit": metasploit,
        "exploit_details": [], "remediation": remediation,
    }
    if owasp:
        f["owasp"] = owasp
    if nist:
        f["nist"] = nist
    return f


class SqlmapParser(BaseParser):
    TOOL_ID = "sqlmap"
    TOOL_NAME = "sqlmap"
    SUPPORTED_FORMATS = ["txt"]

    def parse(self):
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        of = str(self.file_path)

        if not _RE_SQLI_VULN.search(text):
            self.emit("log", "sqlmap: no confirmed injections found")
            return

        negative = re.search(
            r'do not appear to be injectable|'
            r'does not seem to be injectable|'
            r'all tested parameters .* not .* injectable',
            text, re.I)
        if negative:
            self.emit("log", "sqlmap: negative verdict found alongside positive — skipping")
            return

        url = ""
        m = _RE_SQLI_URL.search(text)
        if m:
            url = m.group(1)
        if not url:
            urls = _RE_URL_EXTRACT.findall(text)
            if urls:
                url = urls[0]

        params = []
        for pm in _RE_SQLI_PARAM.finditer(text):
            params.append(f"{pm.group(1)} ({pm.group(2)})")

        ip = ""
        if url:
            import urllib.parse as _up
            try:
                ip = _up.urlparse(url).hostname or ""
            except Exception:
                pass

        trigger = "\n".join(
            l for l in text.splitlines()
            if re.search(r'is vulnerable|Type:.*injection|Payload:|injection point',
                         l, re.I)
        )[:1500]

        self.emit("log", f"sqlmap confirmed injection at {url or 'unknown URL'}")
        yield ("finding", _finding(
            title="SQL Injection Confirmed by sqlmap",
            ip=ip, port=0, risk="CRITICAL",
            desc="User-controlled input is incorporated into SQL queries without "
                 "parameterisation, allowing an attacker to read, modify, or delete "
                 "database contents.",
            sources="sqlmap", affected=url or ip,
            output=f"URL: {url}\nParameters: {', '.join(params) if params else 'see output'}\n"
                   f"sqlmap trigger lines:\n{trigger}",
            output_file=of,
            owasp="A03:2025 Injection", nist="SI-10",
            remediation="Replace all dynamic SQL string construction with parameterised "
                        "queries or prepared statements and suppress database error output "
                        "in production responses.",
        ))

    def extract_targets(self):
        targets = set()
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return targets
        for url in _RE_URL_EXTRACT.findall(text):
            import urllib.parse as _up
            try:
                h = _up.urlparse(url).hostname
                if h:
                    targets.add(h)
            except Exception:
                pass
        for m in _RE_IP.finditer(text):
            targets.add(m.group(1))
        return targets


class SearchsploitParser(BaseParser):
    TOOL_ID = "searchsploit"
    TOOL_NAME = "searchsploit"
    SUPPORTED_FORMATS = ["json"]

    def parse(self):
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
            data = json.loads(text)
        except (OSError, json.JSONDecodeError):
            return

        of = str(self.file_path)
        exploits = (data.get("RESULTS_EXPLOIT", [])
                    + data.get("RESULTS_SHELLCODE", []))

        if not exploits:
            self.emit("log", "searchsploit: no exploits found")
            return

        search_term = data.get("SEARCH", "")
        if not search_term:
            titles = [e.get("Title", "") for e in exploits[:3]]
            common = []
            for t in titles:
                parts = t.split()[:2]
                if parts:
                    common.append(" ".join(parts))
            search_term = common[0] if common else "unknown"

        titles_list = [e.get("Title", "") for e in exploits[:5]]
        edb_ids = [str(e.get("EDB-ID", "")) for e in exploits[:5] if e.get("EDB-ID")]

        self.emit("log", f"searchsploit: {len(exploits)} exploit(s) for '{search_term}'")
        yield ("finding", _finding(
            title=f"Public Exploit Available: {search_term}",
            ip="", port=0, risk="HIGH",
            desc=f"{len(exploits)} public exploit(s) found in ExploitDB for "
                 f"'{search_term}'. Review and patch before exposure.",
            sources="searchsploit", affected=search_term,
            output="\n".join(f"- {t}" for t in titles_list),
            output_file=of, exploitdb=True,
            owasp="A06:2025 Vulnerable and Outdated Components", nist="SI-2",
            remediation=f"Update or patch {search_term} to address known vulnerabilities.",
            cves=",".join(edb_ids[:5]) if edb_ids else "",
        ))

    def extract_targets(self):
        return set()


class MsfSearchParser(BaseParser):
    TOOL_ID = "metasploit"
    TOOL_NAME = "Metasploit Search"
    SUPPORTED_FORMATS = ["txt"]

    def parse(self):
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        of = str(self.file_path)
        seen = set()

        for line in text.splitlines():
            m = _RE_MSF_MODULE.search(line)
            if not m:
                continue
            module_path = m.group(1)
            if module_path in seen:
                continue
            seen.add(module_path)

            parts = module_path.split("/")
            module_name = parts[-1] if parts else module_path
            module_type = parts[0] if parts else "unknown"

            self.emit("log", f"Metasploit module: {module_path}")
            yield ("finding", _finding(
                title=f"Metasploit Module Available: {module_name}",
                ip="", port=0, risk="INFO",
                desc=f"Metasploit {module_type} module '{module_path}' is available "
                     "for potential exploitation of this target.",
                sources="metasploit", affected=module_path,
                output=f"Module: {module_path}\nType: {module_type}\nSource: {line.strip()[:200]}",
                output_file=of, metasploit=True,
                remediation="Verify whether the target is vulnerable to this module and patch accordingly.",
            ))

    def extract_targets(self):
        return set()
