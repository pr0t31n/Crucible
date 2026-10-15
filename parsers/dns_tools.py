"""DNS/subdomain tool parsers — amass, subfinder, dnsx.
Yields intel items for subdomain discovery; targets for resolved IPs."""

import json
import re
from datetime import datetime, timezone
from parsers.base import BaseParser

_RE_FQDN = re.compile(r'^[a-z0-9]([a-z0-9.\-]*[a-z0-9])?\.[a-z]{2,}$', re.I)


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _finding(title, ip, port, risk, desc, sources, affected, output,
             output_file="", remediation=""):
    return {
        "title": title, "datetime": _now_iso(), "ip": ip,
        "port": int(port) if port else 0, "hostname": "",
        "risk": risk, "command": f"{sources} (imported)",
        "description": desc, "output": output[:4096],
        "cves": "", "sources": sources, "service": "dns",
        "output_file": output_file, "affected": affected,
        "exploitdb": False, "metasploit": False,
        "exploit_details": [], "remediation": remediation,
    }


class AmassParser(BaseParser):
    TOOL_ID = "amass"
    TOOL_NAME = "amass"
    SUPPORTED_FORMATS = ["txt"]

    def parse(self):
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        of = str(self.file_path)
        domains = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if _RE_FQDN.match(line):
                domains.add(line.lower())
                yield ("intel", {"type": "subdomain", "value": line.lower()})

        if domains:
            sample = sorted(domains)[:20]
            self.emit("log", f"amass: {len(domains)} subdomain(s)")
            yield ("finding", _finding(
                title="Subdomain Enumeration Results",
                ip="", port=0, risk="INFO",
                desc=f"{len(domains)} subdomain(s) discovered via amass.",
                sources="amass", affected="multiple",
                output="\n".join(sample) +
                       (f"\n... and {len(domains) - 20} more" if len(domains) > 20 else ""),
                output_file=of,
                remediation="Review discovered subdomains for unauthorized or forgotten assets.",
            ))

    def extract_targets(self):
        targets = set()
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                line = line.strip()
                if _RE_FQDN.match(line):
                    targets.add(line.lower())
        except OSError:
            pass
        return targets


class SubfinderParser(BaseParser):
    TOOL_ID = "subfinder"
    TOOL_NAME = "subfinder"
    SUPPORTED_FORMATS = ["txt"]

    def parse(self):
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        of = str(self.file_path)
        domains = set()
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if _RE_FQDN.match(line):
                domains.add(line.lower())
                yield ("intel", {"type": "subdomain", "value": line.lower()})

        if domains:
            sample = sorted(domains)[:20]
            self.emit("log", f"subfinder: {len(domains)} subdomain(s)")
            yield ("finding", _finding(
                title="Subdomain Enumeration Results",
                ip="", port=0, risk="INFO",
                desc=f"{len(domains)} subdomain(s) discovered via subfinder.",
                sources="subfinder", affected="multiple",
                output="\n".join(sample) +
                       (f"\n... and {len(domains) - 20} more" if len(domains) > 20 else ""),
                output_file=of,
                remediation="Review discovered subdomains for unauthorized or forgotten assets.",
            ))

    def extract_targets(self):
        targets = set()
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                line = line.strip()
                if _RE_FQDN.match(line):
                    targets.add(line.lower())
        except OSError:
            pass
        return targets


class DnsxParser(BaseParser):
    TOOL_ID = "dnsx"
    TOOL_NAME = "dnsx"
    SUPPORTED_FORMATS = ["jsonl", "json"]

    def parse(self):
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        count = 0
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            host = obj.get("host", "")
            a_records = obj.get("a", [])
            cname_records = obj.get("cname", [])

            if host:
                yield ("intel", {"type": "dns", "host": host,
                                 "a": a_records, "cname": cname_records})
                count += 1

            for a_ip in (a_records or []):
                yield ("target", {"ip": a_ip, "hostname": host})

        self.emit("log", f"dnsx: {count} record(s)")

    def extract_targets(self):
        targets = set()
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    h = obj.get("host", "")
                    if h:
                        targets.add(h)
                    for a in obj.get("a", []):
                        targets.add(a)
                except json.JSONDecodeError:
                    continue
        except OSError:
            pass
        return targets
