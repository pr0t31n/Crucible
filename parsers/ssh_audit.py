"""ssh-audit import parser — JSON output format."""

import json
import re
from datetime import datetime
from parsers.base import BaseParser

_RE_IP_PORT = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3}).*?(\d+)')
_RE_IP_FNAME = re.compile(r'(\d{1,3}[_.](?:\d{1,3}[_.]){2}\d{1,3})')


def _base_finding(ip, port, hostname):
    return {
        "ip": ip, "port": int(port) if port else 22,
        "hostname": hostname or "", "command": "imported",
        "output": "", "cves": "", "sources": "ssh-audit",
        "service": "ssh", "output_file": "",
        "affected": f"{ip}:{port}" if port else ip,
        "datetime": datetime.now().isoformat(),
        "exploitdb": False, "metasploit": False, "exploit_details": [],
    }


class SshAuditParser(BaseParser):
    TOOL_ID = "ssh-audit"
    TOOL_NAME = "ssh-audit"
    SUPPORTED_FORMATS = ["json"]

    def extract_targets(self):
        targets = set()
        try:
            data = json.loads(self.file_path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            return targets
        if isinstance(data, dict):
            banner = data.get("banner") or {}
            if isinstance(banner, dict):
                raw = banner.get("raw", "")
                m = _RE_IP_PORT.search(raw)
                if m:
                    targets.add(m.group(1))
        fname = self.file_path.stem
        m = _RE_IP_FNAME.search(fname)
        if m:
            targets.add(m.group(1).replace("_", "."))
        return targets

    def parse(self):
        try:
            raw = self.file_path.read_text(encoding="utf-8", errors="replace")
            data = json.loads(raw)
        except (json.JSONDecodeError, OSError) as exc:
            self.emit("log", f"Failed to parse ssh-audit JSON: {exc}")
            return

        if not isinstance(data, dict):
            self.emit("log", "ssh-audit JSON is not a dict")
            return

        ip = ""
        port = 22
        hostname = ""

        fname = self.file_path.stem
        m = _RE_IP_FNAME.search(fname)
        if m:
            ip = m.group(1).replace("_", ".")
        port_m = re.search(r'_(\d+)_', fname)
        if port_m:
            try:
                port = int(port_m.group(1))
            except ValueError:
                pass

        if ip:
            yield ("target", {"ip": ip, "port": port, "hostname": hostname})
            yield ("port", {"ip": ip, "port": port, "service": "ssh", "protocol": "tcp"})

        banner_block = data.get("banner") or {}
        if isinstance(banner_block, dict):
            software = (banner_block.get("software") or "").strip()
            if software:
                self.emit("log", f"SSH server: {software}")

        # CVEs
        cves_block = data.get("cves") or []
        if isinstance(cves_block, list):
            for cve in cves_block:
                if not isinstance(cve, dict):
                    continue
                cve_id = (cve.get("name") or "").strip()
                if not cve_id:
                    continue
                cvss = cve.get("cvssv2") or cve.get("cvssv3") or ""
                descr = (cve.get("description") or "").strip()
                try:
                    cvss_f = float(cvss)
                except (TypeError, ValueError):
                    cvss_f = 0.0
                if cvss_f >= 9.0:
                    risk = "CRITICAL"
                elif cvss_f >= 7.0:
                    risk = "HIGH"
                elif cvss_f >= 4.0:
                    risk = "MEDIUM"
                elif cvss_f > 0:
                    risk = "LOW"
                else:
                    risk = "MEDIUM"

                f = _base_finding(ip, port, hostname)
                f["title"] = f"SSH Vulnerability: {cve_id}"
                f["risk"] = risk
                f["cves"] = cve_id
                f["description"] = (
                    f"ssh-audit matched the SSH server banner against its CVE "
                    f"database and identified {cve_id} (CVSS {cvss or 'n/a'}). "
                    f"{descr}"
                ).strip()
                f["output"] = f"CVE: {cve_id}\nCVSS: {cvss}\nDescription: {descr}"
                yield ("finding", f)

        # Recommendations
        recs = data.get("recommendations") or {}
        sev_buckets = {}
        if isinstance(recs, dict):
            for sev_key in ("critical", "warning", "informational"):
                blk = recs.get(sev_key) or {}
                if not isinstance(blk, dict):
                    continue
                for action_key in ("del", "chg", "add"):
                    action_blk = blk.get(action_key) or {}
                    if not isinstance(action_blk, dict):
                        continue
                    for algo_kind, algo_list in action_blk.items():
                        if not isinstance(algo_list, list):
                            continue
                        for algo in algo_list:
                            algo_name = (
                                algo if isinstance(algo, str)
                                else (algo.get("name") if isinstance(algo, dict) else "")
                            )
                            if not algo_name:
                                continue
                            sev_buckets.setdefault(sev_key, []).append(
                                f"[{action_key.upper()} {algo_kind}] {algo_name}"
                            )

        sev_to_risk = {
            "critical": "HIGH",
            "warning": "MEDIUM",
            "informational": "INFO",
        }
        for sev_key, items in sev_buckets.items():
            risk = sev_to_risk.get(sev_key, "MEDIUM")
            title = (
                "SSH Vulnerability: Weak/Deprecated Cryptographic Algorithms"
                if sev_key in ("critical", "warning")
                else "SSH Algorithm Hardening Recommendations"
            )
            f = _base_finding(ip, port, hostname)
            f["title"] = title
            f["risk"] = risk
            f["description"] = (
                f"ssh-audit recommends action on {len(items)} "
                f"{sev_key}-severity SSH algorithm setting(s). Remove "
                f"deprecated algorithms from sshd_config to prevent "
                f"downgrade attacks."
            )
            f["output"] = (
                f"Severity: {sev_key}\n"
                f"Total recommendations: {len(items)}\n"
                + "\n".join(items)
            )
            yield ("finding", f)

        # Per-algorithm fail/warn flags
        per_algo_findings = {}
        for algo_kind in ("kex", "key", "enc", "mac"):
            algo_list = data.get(algo_kind) or []
            if not isinstance(algo_list, list):
                continue
            for algo in algo_list:
                if not isinstance(algo, dict):
                    continue
                name = (algo.get("algorithm") or algo.get("name") or "").strip()
                notes = algo.get("notes") or {}
                for sev_key, label in (("fail", "fail"), ("warn", "warn")):
                    sev_notes = notes.get(sev_key) if isinstance(notes, dict) else None
                    if sev_notes and name:
                        detail = (
                            "; ".join(sev_notes)
                            if isinstance(sev_notes, list)
                            else str(sev_notes)
                        )
                        per_algo_findings.setdefault(label, []).append(
                            f"[{algo_kind}] {name} — {detail}"
                        )

        for sev_key, items in per_algo_findings.items():
            risk = "HIGH" if sev_key == "fail" else "MEDIUM"
            f = _base_finding(ip, port, hostname)
            f["title"] = "SSH Vulnerability: Weak/Deprecated Cryptographic Algorithms"
            f["risk"] = risk
            f["description"] = (
                f"ssh-audit flagged {len(items)} SSH algorithm(s) as "
                f"'{sev_key}'. Each entry identifies the algorithm "
                f"family, name, and rationale."
            )
            f["output"] = (
                f"Severity: {sev_key}\n"
                f"Total flagged: {len(items)}\n"
                + "\n".join(items)
            )
            yield ("finding", f)
