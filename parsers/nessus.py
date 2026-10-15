"""Crucible v2 — Nessus XML/CSV import parser.

Replicates the exact finding title normalisation and field mapping from
routes/nessus.py so imported .nessus files produce identical findings to
the native Nessus tab.
"""

import csv
import datetime
import io
import json
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

from parsers.base import BaseParser

# ── Title normalisation map ─────────────────────────────────────────────────
# Mirrors routes/nessus.py _NESSUS_TITLE_MAP exactly.
_NESSUS_TITLE_MAP = {
    "HSTS Missing From HTTPS Server (RFC 6797)":
        "Missing Security Header: Strict-Transport-Security",
    "HSTS Missing From HTTPS Server":
        "Missing Security Header: Strict-Transport-Security",
    "HTTP Strict Transport Security (HSTS) Not Enforced":
        "Missing Security Header: Strict-Transport-Security",
    "Web Application Potentially Vulnerable to Clickjacking":
        "Missing Security Header: X-Frame-Options",
    "Missing X-Frame-Options Header":
        "Missing Security Header: X-Frame-Options",
    "X-Content-Type-Options Header Missing":
        "Missing Security Header: X-Content-Type-Options",
    "Missing Content-Security-Policy Header":
        "Missing Security Header: Content-Security-Policy",
    "Missing or Permissive X-Frame-Options HTTP Response Header":
        "Missing Security Header: X-Frame-Options",
    "SSL Certificate Cannot Be Trusted":
        "SSL/TLS Certificate: Untrusted",
    "SSL Self-Signed Certificate":
        "SSL/TLS Certificate: Self-Signed",
    "SSL Certificate Expiry":
        "SSL/TLS Certificate: Expired",
    "SSL Certificate with Wrong Hostname":
        "SSL/TLS Certificate: Hostname Mismatch",
    "SSL Medium Strength Cipher Suites Supported (SWEET32)":
        "SSL/TLS Vulnerability: SWEET32",
    "SSL/TLS Diffie-Hellman Modulus <= 1024 Bits (Logjam)":
        "SSL/TLS Vulnerability: LOGJAM",
    "SSL DROWN Attack Vulnerability (Decrypting RSA with Obsolete and Weakened eNcryption)":
        "SSL/TLS Vulnerability: DROWN",
    "SSL Version 2 and 3 Protocol Detection":
        "Deprecated Protocol Enabled: SSLv2/SSLv3",
    "TLS Version 1.0 Protocol Detection":
        "Deprecated Protocol Enabled: TLSv1.0",
    "TLS Version 1.1 Protocol Deprecated":
        "Deprecated Protocol Enabled: TLSv1.1",
    "TLS Version 1.1 Protocol Detection":
        "Deprecated Protocol Enabled: TLSv1.1",
    "SSL RC4 Cipher Suites Supported (Bar Mitzvah)":
        "SSL/TLS Ciphers: Obsolete Cipher — RC4",
    "SSL Weak Cipher Suites Supported":
        "SSL/TLS Ciphers: Weak Cipher Suites",
    "SSL Certificate Chain Contains RSA Keys Less Than 2048 bits":
        "SSL/TLS Certificate: Short Key Length",
    "SSL Certificate Signed Using Weak Hashing Algorithm":
        "SSL/TLS Certificate: Weak Signature Algorithm",
    "Web Server HTTP Header Internal IP Disclosure":
        "Information Disclosure: Internal IP in HTTP Response",
    # ── LDAP ──
    "LDAP Server Detection":
        "Discovery: LDAP Service",
    "LDAP NULL BASE Search Access":
        "LDAP: Anonymous Bind",
    "Microsoft Windows LDAP Signing Not Required":
        "LDAP: Signing Not Required",
    "LDAP Server Allows Cleartext Authentication":
        "LDAP: Cleartext Authentication Permitted",
    # ── RPC ──
    "RPC portmapper (TCP)":
        "RPC: Portmapper Exposed",
    "DCE Services Enumeration":
        "RPC: DCE Services Enumeration",
    "Microsoft Windows SMB : DCE-RPC Services Enumerable":
        "RPC: DCE Services Enumeration",
    # ── NTP ──
    "NTP Server Detection":
        "Discovery: NTP Service",
    "NTP monlist Command Enabled":
        "NTP: Monlist Amplification (CVE-2013-5211)",
    "NTP Mode 6 Queries Enabled":
        "NTP: Mode 6 Queries Enabled",
}
_NESSUS_TITLE_MAP_LOWER = {k.lower(): v for k, v in _NESSUS_TITLE_MAP.items()}

RISK_MAP = {"4": "CRITICAL", "3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}


def _normalize_title(title):
    mapped = _NESSUS_TITLE_MAP_LOWER.get((title or "").strip().lower())
    return mapped if mapped else title


class NessusParser(BaseParser):
    TOOL_ID = "nessus"
    TOOL_NAME = "Nessus"
    SUPPORTED_FORMATS = ["xml", "csv"]

    def parse(self):
        suffix = self.file_path.suffix.lower()
        if suffix in (".nessus", ".xml"):
            yield from self._parse_xml()
        elif suffix == ".csv":
            yield from self._parse_csv()
        else:
            yield from self._parse_xml()

    def extract_targets(self):
        targets = set()
        suffix = self.file_path.suffix.lower()
        try:
            if suffix == ".csv":
                with open(self.file_path, "r", encoding="utf-8", errors="replace") as fh:
                    reader = csv.DictReader(fh)
                    for row in reader:
                        host = (row.get("Host") or row.get("IP Address") or "").strip()
                        if host:
                            targets.add(host)
            else:
                tree = ET.parse(str(self.file_path))
                root = tree.getroot()
                for host in root.iter("ReportHost"):
                    name = host.get("name", "")
                    if name:
                        targets.add(name)
                    for tag in host.iter("tag"):
                        if tag.get("name") == "host-ip" and tag.text:
                            targets.add(tag.text.strip())
                        elif tag.get("name") == "host-fqdn" and tag.text:
                            targets.add(tag.text.strip())
        except Exception:
            pass
        return targets

    def _parse_xml(self):
        self.emit("log", f"Parsing Nessus XML: {self.file_path.name}")
        count = 0
        try:
            tree = ET.parse(str(self.file_path))
            root = tree.getroot()
        except Exception as exc:
            self.emit("log", f"ERROR: Failed to parse XML: {exc}")
            return

        for host in root.iter("ReportHost"):
            ip = host.get("name", "")
            hostname = ""
            for tag in host.iter("tag"):
                tag_name = tag.get("name", "")
                if tag_name == "host-ip" and tag.text:
                    ip = tag.text.strip()
                elif tag_name == "host-fqdn" and tag.text:
                    hostname = tag.text.strip()

            for item in host.iter("ReportItem"):
                sev = item.get("severity", "0")
                if sev == "0":
                    continue
                risk = RISK_MAP.get(sev, "INFO")
                port = int(item.get("port", "0"))
                plugin_id = item.get("pluginID", "")
                title = _normalize_title(item.get("pluginName", "Unknown"))
                desc = (item.findtext("description") or "").strip()
                solution = (item.findtext("solution") or "").strip()
                output = (item.findtext("plugin_output") or "").strip()
                synopsis = (item.findtext("synopsis") or "").strip()
                service = item.get("svc_name", "")
                protocol = item.get("protocol", "tcp")

                cves = []
                for cve_el in item.iter("cve"):
                    if cve_el.text:
                        cves.append(cve_el.text.strip())

                cvss_score = None
                cvss_vec = ""
                for tag_name in ("cvss3_base_score", "cvss_base_score"):
                    val = item.findtext(tag_name)
                    if val:
                        try:
                            cvss_score = float(val)
                        except ValueError:
                            pass
                        break
                for tag_name in ("cvss3_vector", "cvss_vector"):
                    val = item.findtext(tag_name)
                    if val:
                        cvss_vec = val
                        break

                _has_exploit = (item.findtext("exploit_available") or "").lower() == "true"
                _has_msf = (item.findtext("exploit_framework_metasploit") or "").lower() == "true"
                _msf_name = (item.findtext("metasploit_name") or "").strip()
                _ease = (item.findtext("exploitability_ease") or "").strip()

                _has_edb = False
                _edb_ids = []
                _github_urls = []
                _see_also = []
                for xr in item.iter("xref"):
                    if xr.text and xr.text.startswith("EDB-ID:"):
                        _has_edb = True
                        _edb_ids.append(xr.text)
                for sa in item.iter("see_also"):
                    if sa.text:
                        for _url in sa.text.strip().splitlines():
                            _url = _url.strip()
                            if _url:
                                _see_also.append(_url)
                                if "github.com" in _url.lower():
                                    _github_urls.append(_url)

                _exploit_details = []
                if _has_msf and _msf_name:
                    _exploit_details.append({"type": "metasploit", "name": _msf_name})
                for _eid in _edb_ids:
                    _exploit_details.append({"type": "exploitdb", "id": _eid})
                for _gu in _github_urls:
                    _exploit_details.append({"type": "github", "url": _gu})

                finding = {
                    "id":               str(uuid.uuid4()),
                    "tool":             "nessus",
                    "title":            title,
                    "datetime":         datetime.datetime.now().isoformat(),
                    "ip":               ip,
                    "port":             port,
                    "hostname":         hostname,
                    "risk":             risk,
                    "command":          f"Nessus Plugin {plugin_id}",
                    "description":      desc or synopsis,
                    "output":           output[:4096],
                    "output_file":      "",
                    "cves":             ",".join(cves),
                    "sources":          "nessus",
                    "service":          f"{service}/{protocol}" if service else protocol,
                    "affected":         f"{ip}:{port}",
                    "remediation":      solution,
                    "exploitdb":        _has_edb or _has_exploit,
                    "metasploit":       _has_msf,
                    "exploit_details":  _exploit_details,
                    "nessus_plugin_id": int(plugin_id) if plugin_id.isdigit() else None,
                    "nessus_plugin_name": item.get("pluginName", ""),
                    "cvss_score":       cvss_score,
                    "cvss_vector":      cvss_vec,
                    "see_also":         _see_also,
                    "exploitability_ease": _ease,
                }
                yield ("finding", finding)
                count += 1

        self.emit("log", f"Parsed {count} findings from Nessus XML")

    def _parse_csv(self):
        self.emit("log", f"Parsing Nessus CSV: {self.file_path.name}")
        count = 0
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
            reader = csv.DictReader(io.StringIO(text))
        except Exception as exc:
            self.emit("log", f"ERROR: Failed to read CSV: {exc}")
            return

        for row in reader:
            risk_raw = (row.get("Risk") or "").strip().upper()
            if not risk_raw or risk_raw == "NONE":
                continue
            if risk_raw not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                continue

            ip = (row.get("Host") or row.get("IP Address") or "").strip()
            port = 0
            try:
                port = int(row.get("Port", "0"))
            except (ValueError, TypeError):
                pass
            plugin_id = (row.get("Plugin ID") or row.get("Plugin") or "").strip()
            title = _normalize_title(
                row.get("Name") or row.get("Plugin Name") or "Unknown"
            )
            desc = (row.get("Description") or row.get("Synopsis") or "").strip()
            solution = (row.get("Solution") or "").strip()
            output = (row.get("Plugin Output") or "").strip()
            protocol = (row.get("Protocol") or "tcp").strip()
            cves = (row.get("CVE") or "").strip()

            cvss_score = None
            for col in ("CVSS v3.0 Base Score", "CVSS v2.0 Base Score", "CVSS"):
                val = (row.get(col) or "").strip()
                if val:
                    try:
                        cvss_score = float(val)
                    except ValueError:
                        pass
                    break

            finding = {
                "id":               str(uuid.uuid4()),
                "tool":             "nessus",
                "title":            title,
                "datetime":         datetime.datetime.now().isoformat(),
                "ip":               ip,
                "port":             port,
                "hostname":         "",
                "risk":             risk_raw,
                "command":          f"Nessus Plugin {plugin_id}",
                "description":      desc,
                "output":           output[:4096],
                "output_file":      "",
                "cves":             cves,
                "sources":          "nessus",
                "service":          protocol,
                "affected":         f"{ip}:{port}",
                "remediation":      solution,
                "exploitdb":        False,
                "metasploit":       False,
                "exploit_details":  [],
                "nessus_plugin_id": int(plugin_id) if plugin_id.isdigit() else None,
                "nessus_plugin_name": row.get("Name") or row.get("Plugin Name") or "",
                "cvss_score":       cvss_score,
                "cvss_vector":      "",
                "see_also":         [],
                "exploitability_ease": "",
            }
            yield ("finding", finding)
            count += 1

        self.emit("log", f"Parsed {count} findings from Nessus CSV")


NessusXmlParser = NessusParser
NessusCsvParser = NessusParser
