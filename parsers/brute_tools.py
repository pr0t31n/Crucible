"""Parsers for brute-force and credential-capture tools (Hydra, Responder)."""

import re
from datetime import datetime, timezone
from parsers.base import BaseParser

_RE_HYDRA_CRED = re.compile(
    r'host:\s*(\S+).*?login:\s*(\S+)\s+password:\s*(\S+)', re.I)
_RE_HYDRA_SIDECAR = re.compile(
    r'\[(\d+)\]\[(\S+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)')
_RE_HYDRA_PORT = re.compile(r'\[(\d+)\]\[')

_RE_RESP_NTLMV2 = re.compile(
    r'(?P<user>\S+?)::(?P<domain>\S+?):(?P<challenge>[0-9a-fA-F]{16}):'
    r'(?P<r1>[0-9a-fA-F]{32}):(?P<r2>[0-9a-fA-F]+)')
_RE_RESP_NTLMV1 = re.compile(
    r'(?P<user>\S+?)::(?P<domain>\S+?):(?P<lm>[0-9a-fA-F]{48}):'
    r'(?P<nt>[0-9a-fA-F]{48}):(?P<chal>[0-9a-fA-F]{16})')
_RE_RESP_CLEAR = re.compile(
    r'[Cc]leartext.*?:\s*(\S+)')
_RE_RESP_IP = re.compile(
    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
_RE_IP = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')


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


class HydraParser(BaseParser):
    TOOL_ID = "hydra"
    TOOL_NAME = "Hydra"
    SUPPORTED_FORMATS = ["txt"]

    def parse(self):
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        seen = set()
        of = str(self.file_path)

        for line in text.splitlines():
            m = _RE_HYDRA_SIDECAR.search(line)
            if m:
                port, svc, host, user, pwd = m.groups()
                key = (host, port, user, pwd)
                if key in seen:
                    continue
                seen.add(key)
                self.emit("log", f"Hydra credential: {user}:{pwd} @ {host}:{port}")
                yield ("finding", _finding(
                    title="Brute Force: Web Server Permits Weak/Default Passwords",
                    ip=host, port=port, risk="CRITICAL",
                    desc=f"Hydra confirmed {user}:{pwd} for {svc.upper()} on {host}:{port}.",
                    sources="hydra", affected=f"{host}:{port}",
                    output=f"Service: {svc}\nUsername: {user}\nPassword: {pwd}\nSource: {line.strip()}",
                    service=svc, output_file=of,
                    remediation="Enforce strong passwords, implement account lockout policies, and disable default credentials.",
                ))
                continue

            m = _RE_HYDRA_CRED.search(line)
            if m:
                host, user, pwd = m.groups()
                pm = _RE_HYDRA_PORT.search(line)
                port = pm.group(1) if pm else "0"
                key = (host, port, user, pwd)
                if key in seen:
                    continue
                seen.add(key)
                self.emit("log", f"Hydra credential: {user}:{pwd} @ {host}:{port}")
                yield ("finding", _finding(
                    title="Brute Force: Web Server Permits Weak/Default Passwords",
                    ip=host, port=port, risk="CRITICAL",
                    desc=f"Hydra confirmed {user}:{pwd} on {host}:{port}.",
                    sources="hydra", affected=f"{host}:{port}",
                    output=f"Username: {user}\nPassword: {pwd}\nSource: {line.strip()}",
                    output_file=of,
                    remediation="Enforce strong passwords, implement account lockout policies, and disable default credentials.",
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


class ResponderParser(BaseParser):
    TOOL_ID = "responder"
    TOOL_NAME = "Responder"
    SUPPORTED_FORMATS = ["txt"]

    def parse(self):
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        of = str(self.file_path)
        seen_hashes = set()

        fname_ip = ""
        m = _RE_RESP_IP.search(self.file_path.name)
        if m:
            fname_ip = m.group(1)

        for line in text.splitlines():
            ls = line.strip()
            if not ls:
                continue

            m = _RE_RESP_NTLMV2.search(ls)
            if m:
                user = m.group("user")
                domain = m.group("domain")
                h = f"{user}::{domain}:{m.group('challenge')}:{m.group('r1')}:{m.group('r2')}"
                if h in seen_hashes:
                    continue
                seen_hashes.add(h)
                self.emit("log", f"NTLMv2 hash: {user}::{domain}")
                yield ("finding", _finding(
                    title="NTLM Hash Captured via Responder",
                    ip=fname_ip, port=0, risk="HIGH",
                    desc=f"Responder captured NTLMv2 hash for {user}::{domain}. "
                         "The hash can be cracked offline to recover the plaintext password.",
                    sources="responder", affected=f"{user}::{domain}",
                    output=f"Type: NTLMv2\nUser: {user}\nDomain: {domain}\nHash: {h[:80]}...",
                    output_file=of,
                    remediation="Disable LLMNR, NBT-NS, and mDNS on all network segments. "
                                "Enforce SMB signing and use Kerberos authentication.",
                ))
                continue

            m = _RE_RESP_NTLMV1.search(ls)
            if m:
                user = m.group("user")
                domain = m.group("domain")
                h = f"{user}::{domain}:{m.group('lm')}:{m.group('nt')}:{m.group('chal')}"
                if h in seen_hashes:
                    continue
                seen_hashes.add(h)
                self.emit("log", f"NTLMv1 hash: {user}::{domain}")
                yield ("finding", _finding(
                    title="NTLM Hash Captured via Responder",
                    ip=fname_ip, port=0, risk="HIGH",
                    desc=f"Responder captured NTLMv1 hash for {user}::{domain}. "
                         "NTLMv1 hashes are significantly easier to crack than NTLMv2.",
                    sources="responder", affected=f"{user}::{domain}",
                    output=f"Type: NTLMv1\nUser: {user}\nDomain: {domain}\nHash: {h[:80]}...",
                    output_file=of,
                    remediation="Disable LLMNR, NBT-NS, and mDNS. Enforce NTLMv2 minimum "
                                "and migrate to Kerberos authentication.",
                ))
                continue

            m = _RE_RESP_CLEAR.search(ls)
            if m:
                cred = m.group(1)
                key = f"clear:{cred}"
                if key in seen_hashes:
                    continue
                seen_hashes.add(key)
                self.emit("log", f"Cleartext credential captured")
                yield ("finding", _finding(
                    title="Cleartext Credential Captured via Responder",
                    ip=fname_ip, port=0, risk="CRITICAL",
                    desc="Responder captured a cleartext credential transmitted over the network. "
                         "Protocols transmitting credentials in cleartext are vulnerable to interception.",
                    sources="responder", affected=fname_ip or "network",
                    output=f"Cleartext credential captured\nSource: {ls[:200]}",
                    output_file=of,
                    remediation="Disable cleartext authentication protocols (FTP, HTTP Basic over non-TLS, "
                                "Telnet). Enforce encrypted alternatives.",
                ))

    def extract_targets(self):
        targets = set()
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return targets
        for m in _RE_IP.finditer(text):
            targets.add(m.group(1))
        m = _RE_RESP_IP.search(self.file_path.name)
        if m:
            targets.add(m.group(1))
        return targets
