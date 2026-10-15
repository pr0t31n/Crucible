"""SMB tool parsers — smbmap, enum4linux.
Finding titles match SS3 conventions exactly."""

import re
from datetime import datetime, timezone
from parsers.base import BaseParser

_RE_SMBMAP_SHARE = re.compile(
    r'^\s*(\S+)\s+(READ|WRITE|NO ACCESS|READ, WRITE|READ ONLY)\s+(.*)$')
_RE_ENUM4_SHARE = re.compile(r'^\s*(\S+)\s+Disk\s+(.*?)$')
_RE_ENUM4_USER = re.compile(r'user:\[([^\]]+)\]')
_RE_IP = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _finding(title, ip, port, risk, desc, sources, affected, output,
             output_file="", remediation=""):
    return {
        "title": title, "datetime": _now_iso(), "ip": ip,
        "port": int(port) if port else 0, "hostname": "",
        "risk": risk, "command": f"{sources} (imported)",
        "description": desc, "output": output[:4096],
        "cves": "", "sources": sources, "service": "smb",
        "output_file": output_file, "affected": affected,
        "exploitdb": False, "metasploit": False,
        "exploit_details": [], "remediation": remediation,
    }


class SmbmapParser(BaseParser):
    TOOL_ID = "smbmap"
    TOOL_NAME = "smbmap"
    SUPPORTED_FORMATS = ["txt"]

    def parse(self):
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        of = str(self.file_path)
        ip_match = _RE_IP.search(text)
        ip = ip_match.group(1) if ip_match else ""

        if ip:
            yield ("target", {"ip": ip, "hostname": ""})

        null_session = False
        if re.search(r'Authentication\s*error|STATUS_ACCESS_DENIED', text, re.I):
            pass
        elif re.search(r'\bNO ACCESS\b.*\bNO ACCESS\b.*\bNO ACCESS\b', text):
            pass
        else:
            null_session = any(
                _RE_SMBMAP_SHARE.match(l) for l in text.splitlines()
            )

        if null_session and ("guest" in text.lower() or
                             re.search(r'^\s*\S+\s+READ', text, re.M)):
            self.emit("log", f"SMB null session on {ip}")
            yield ("finding", _finding(
                title="SMB Null Session Permitted",
                ip=ip, port=445, risk="HIGH",
                desc=f"SMB null session access is permitted on {ip}, "
                     "allowing anonymous enumeration of shares.",
                sources="smbmap", affected=f"{ip}:445",
                output_file=of,
                output="Null/guest session returned share listing.",
                remediation="Disable anonymous/guest SMB access and require authentication.",
            ))

        for line in text.splitlines():
            m = _RE_SMBMAP_SHARE.match(line)
            if not m:
                continue
            share = m.group(1)
            perm = m.group(2).strip()
            comment = m.group(3).strip()

            if share in ("IPC$",):
                continue

            if "WRITE" in perm:
                self.emit("log", f"Writable share: \\\\{ip}\\{share}")
                yield ("finding", _finding(
                    title="SMB Share Identified with WRITE Permissions",
                    ip=ip, port=445, risk="HIGH",
                    desc=f"SMB share '\\\\{ip}\\{share}' permits write access. "
                         "An attacker could plant malicious files or modify existing data.",
                    sources="smbmap", affected=f"\\\\{ip}\\{share}",
                    output=f"Share: {share}\nPermissions: {perm}\nComment: {comment}",
                    output_file=of,
                    remediation="Restrict write access to authorized users and review share permissions.",
                ))
            elif "READ" in perm:
                self.emit("log", f"Readable share: \\\\{ip}\\{share}")
                yield ("finding", _finding(
                    title=f"SMB Share Read Access: {share}",
                    ip=ip, port=445, risk="MEDIUM",
                    desc=f"SMB share '\\\\{ip}\\{share}' permits read access.",
                    sources="smbmap", affected=f"\\\\{ip}\\{share}",
                    output=f"Share: {share}\nPermissions: {perm}\nComment: {comment}",
                    output_file=of,
                    remediation="Restrict share access to authorized users only.",
                ))
            else:
                self.emit("log", f"Share enumerated: \\\\{ip}\\{share}")
                yield ("finding", _finding(
                    title=f"SMB Share Enumerated: \\\\{ip}\\{share}",
                    ip=ip, port=445, risk="INFO",
                    desc=f"SMB share '\\\\{ip}\\{share}' was enumerated (access: {perm}).",
                    sources="smbmap", affected=f"\\\\{ip}\\{share}",
                    output=f"Share: {share}\nPermissions: {perm}\nComment: {comment}",
                    output_file=of,
                ))

        if "ADMIN!!!" in text:
            yield ("finding", _finding(
                title="SMB Administrative Access Confirmed",
                ip=ip, port=445, risk="CRITICAL",
                desc="Administrative access to SMB shares confirmed.",
                sources="smbmap", affected=f"{ip}:445",
                output="ADMIN!!! flag detected in smbmap output.",
                output_file=of,
                remediation="Remove administrative SMB access for non-privileged accounts.",
            ))

    def extract_targets(self):
        targets = set()
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
            for m in _RE_IP.finditer(text):
                targets.add(m.group(1))
        except OSError:
            pass
        return targets


class Enum4linuxParser(BaseParser):
    TOOL_ID = "enum4linux"
    TOOL_NAME = "enum4linux"
    SUPPORTED_FORMATS = ["txt"]

    def parse(self):
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        of = str(self.file_path)
        ip_match = re.search(
            r'Target\s*[.:]\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', text, re.I)
        if not ip_match:
            ip_match = _RE_IP.search(text)
        ip = ip_match.group(1) if ip_match else ""

        if ip:
            yield ("target", {"ip": ip, "hostname": ""})

        if re.search(r'null session', text, re.I) and re.search(r'allowed|success', text, re.I):
            self.emit("log", f"SMB null session on {ip}")
            yield ("finding", _finding(
                title="SMB Null Session Permitted",
                ip=ip, port=445, risk="HIGH",
                desc=f"SMB null session access is permitted on {ip}, "
                     "allowing anonymous enumeration of shares, users, and groups.",
                sources="enum4linux", affected=f"{ip}:445",
                output_file=of, output="Null session detected by enum4linux.",
                remediation="Disable anonymous/guest SMB access and require authentication.",
            ))

        users = set()
        for m in _RE_ENUM4_USER.finditer(text):
            users.add(m.group(1))

        if users:
            self.emit("log", f"enum4linux: {len(users)} users enumerated")
            yield ("finding", _finding(
                title="SMB Users Enumerated",
                ip=ip, port=445, risk="MEDIUM",
                desc=f"{len(users)} user(s) enumerated via enum4linux on {ip}.",
                sources="enum4linux", affected=f"{ip}:445",
                output="\n".join(sorted(users)[:50]),
                output_file=of,
                remediation="Restrict anonymous enumeration of domain/local users.",
            ))

        for line in text.splitlines():
            m = _RE_ENUM4_SHARE.match(line)
            if not m:
                continue
            share = m.group(1)
            if share in ("IPC$",):
                continue
            self.emit("log", f"Share enumerated: \\\\{ip}\\{share}")
            yield ("finding", _finding(
                title=f"SMB Share Enumerated: \\\\{ip}\\{share}",
                ip=ip, port=445, risk="INFO",
                desc=f"SMB share '\\\\{ip}\\{share}' was discovered via enum4linux.",
                sources="enum4linux", affected=f"\\\\{ip}\\{share}",
                output=line.strip(),
                output_file=of,
            ))

        if "password policy" in text.lower():
            pp_lines = []
            in_pp = False
            for line in text.splitlines():
                if "password policy" in line.lower():
                    in_pp = True
                elif in_pp and line.startswith("==="):
                    break
                if in_pp:
                    pp_lines.append(line)
            if pp_lines:
                yield ("finding", _finding(
                    title="SMB Password Policy Retrieved",
                    ip=ip, port=445, risk="INFO",
                    desc="Domain/local password policy extracted via enum4linux.",
                    sources="enum4linux", affected=f"{ip}:445",
                    output="\n".join(pp_lines)[:4096],
                    output_file=of,
                ))

    def extract_targets(self):
        targets = set()
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
            for m in _RE_IP.finditer(text):
                targets.add(m.group(1))
        except OSError:
            pass
        return targets
