"""testssl.sh import parsers — JSON and text output formats."""

import json
import re
from datetime import datetime
from parsers.base import BaseParser

_RE_IP_PORT = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})[:/](\d+)')
_RE_WEAK_SSL = re.compile(r'SSLv[23]', re.I)
_RE_WEAK_TLS = re.compile(
    r"TLSv1(?:\.0|\.1|(?!\.[23]))\b|TLS\s+1(?:\.[01]|\s|$)(?!\.[23])",
    re.I,
)
_RE_TS_PROTO = re.compile(
    r"(SSLv[23]|TLS\s+[\d.]+)\s+(offered|not offered)(.*)", re.I
)
_RE_TS_VULN = re.compile(
    r"(Heartbleed|ROBOT|BEAST|POODLE|CRIME|BREACH|DROWN|LOGJAM|"
    r"FREAK|Sweet32|LUCKY13|RC4|TICKETBLEED|GOLDENDOODLE|"
    r"0-RTT|RACCOON|Zombie POODLE|Sleeping POODLE|POODLE.*TLS)\s+(.*)",
    re.I,
)
_RE_TS_CIPHER_CAT = re.compile(
    r"^\s*(NULL ciphers?|Anonymous.*Ciphers?|Export ciphers?|LOW[:\s].*|"
    r"Triple DES.*|Obsoleted CBC.*)\s+(not offered|offered)(.*)",
    re.I,
)
_RE_TS_SUBJECT = re.compile(r"subject\s*[:/]\s*(.+)", re.I)
_RE_TS_ISSUER = re.compile(r"issuer\s*[:/]\s*(.+)", re.I)
_RE_TS_EXPIRY = re.compile(r"expires\s*[:/]\s*(.+)", re.I)

_TESTSSL_RISK_MAP = {
    "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
    "LOW": "LOW", "WARN": "INFO", "INFO": "INFO", "OK": "INFO",
}

_TESTSSL_PROTO_IDS = {
    "SSLv2": "SSLv2", "SSLv3": "SSLv3",
    "TLS1": "TLSv1.0", "TLS1_1": "TLSv1.1",
}

_TS_SKIP_IDS = frozenset({
    "overall_grade", "cert_revocation", "security_headers",
    "FS_TLS12_sig_algs", "TLS1_2", "TLS1_3",
})

_TESTSSL_CVES = {
    "heartbleed": "CVE-2014-0160", "ROBOT": "CVE-2017-13099",
    "DROWN": "CVE-2016-0800", "POODLE": "CVE-2014-3566",
    "BEAST": "CVE-2011-3389", "CCS": "CVE-2014-0224",
    "LUCKY13": "CVE-2013-0169", "FREAK": "CVE-2015-0204",
    "LOGJAM": "CVE-2015-4000", "SWEET32": "CVE-2016-2183",
    "ticketbleed": "CVE-2016-9244",
}

_TESTSSL_DESCS = {
    "Heartbleed": "OpenSSL Heartbleed (CVE-2014-0160): the server leaks up to 64 KB of process memory per request.",
    "ROBOT": "ROBOT (CVE-2017-13099): RSA PKCS#1 v1.5 padding oracle allows passive decryption of past TLS sessions.",
    "DROWN": "DROWN (CVE-2016-0800): SSLv2 support allows decryption of modern TLS sessions via cross-protocol attack.",
    "POODLE": "POODLE (CVE-2014-3566): CBC padding oracle in SSLv3/TLS allows plaintext recovery via MITM.",
    "BEAST": "BEAST (CVE-2011-3389): CBC cipher suite attack against TLS 1.0 enables plaintext recovery via MITM.",
    "CCS": "OpenSSL CCS Injection (CVE-2014-0224): MITM attacker can force weak keys, enabling session decryption.",
    "LUCKY13": "LUCKY13 (CVE-2013-0169): timing side-channel in CBC-mode decryption allows plaintext recovery.",
    "FREAK": "FREAK (CVE-2015-0204): server accepts RSA_EXPORT cipher suites, enabling downgrade to 512-bit RSA.",
    "LOGJAM": "LOGJAM (CVE-2015-4000): server accepts DHE_EXPORT with 512-bit DH, enabling downgrade attack.",
    "SWEET32": "SWEET32 (CVE-2016-2183): 64-bit block ciphers vulnerable to birthday attacks after ~32 GB.",
    "ticketbleed": "Ticketbleed (CVE-2016-9244): F5 TLS session ticket implementation leaks uninitialized memory.",
}


def _proto_risk(proto_name):
    if re.search(r'SSLv2', proto_name, re.I):
        return "HIGH"
    if re.search(r'SSLv3', proto_name, re.I):
        return "MEDIUM"
    return "LOW"


def _norm_proto(raw):
    raw = raw.strip()
    if re.match(r'TLS\s+1\.0', raw, re.I):
        return "TLSv1.0"
    if re.match(r'TLS\s+1\.1', raw, re.I):
        return "TLSv1.1"
    if re.match(r'TLS\s+1$', raw, re.I):
        return "TLSv1.0"
    return raw.replace(" ", "")


def _base_finding(ip, port, hostname):
    return {
        "ip": ip, "port": int(port) if port else 443,
        "hostname": hostname or "", "command": "imported",
        "output": "", "cves": "", "sources": "testssl",
        "service": "ssl/tls", "output_file": "",
        "affected": f"{ip}:{port}" if port else ip,
        "datetime": datetime.now().isoformat(),
        "exploitdb": False, "metasploit": False, "exploit_details": [],
    }


class TestsslJsonParser(BaseParser):
    TOOL_ID = "testssl"
    TOOL_NAME = "testssl-json"
    SUPPORTED_FORMATS = ["json"]

    def extract_targets(self):
        targets = set()
        try:
            data = json.loads(self.file_path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            return targets
        findings = self._get_findings(data)
        for f in findings[:100]:
            ip = f.get("ip", "").strip().rstrip("/")
            if ip and not ip.startswith("::"):
                targets.add(ip)
        return targets

    def _get_findings(self, data):
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            if data.get("findings"):
                return data["findings"]
            sr = data.get("scanResult", [])
            if sr and isinstance(sr[0], dict):
                return sr[0].get("Finding", sr[0].get("findings", []))
        return []

    def parse(self):
        try:
            raw = self.file_path.read_text(encoding="utf-8", errors="replace")
            data = json.loads(raw)
        except (json.JSONDecodeError, OSError) as exc:
            self.emit("log", f"Failed to parse testssl JSON: {exc}")
            return

        findings = self._get_findings(data)
        self.emit("log", f"testssl JSON: {len(findings)} entries")

        ip = ""
        port = 443
        hostname = ""
        for f in findings[:5]:
            fip = (f.get("ip") or "").strip().rstrip("/")
            if fip and not fip.startswith("::"):
                ip = fip
                break
        for f in findings[:5]:
            fp = f.get("port")
            if fp:
                try:
                    port = int(str(fp).strip().split("/")[0])
                except (ValueError, IndexError):
                    pass
                break
        fqdn = (findings[0].get("fqdn") or findings[0].get("hostname") or "") if findings else ""
        if fqdn:
            hostname = fqdn.strip().rstrip("/")

        if ip:
            yield ("target", {"ip": ip, "port": port, "hostname": hostname})
            yield ("port", {"ip": ip, "port": port, "service": "ssl/tls", "protocol": "tcp"})

        for entry in findings:
            try:
                yield from self._process_entry(entry, ip, port, hostname)
            except Exception:
                pass

    def _process_entry(self, entry, ip, port, hostname):
        fid = entry.get("id", "")
        sev = (entry.get("severity") or "INFO").upper()
        risk = _TESTSSL_RISK_MAP.get(sev, "INFO")
        finding_text = entry.get("finding") or ""
        finding_lo = finding_text.lower()
        cve_inline = ",".join(re.findall(r'CVE-\d{4}-\d+', finding_text))

        if fid in _TESTSSL_PROTO_IDS:
            if "not offered" in finding_lo:
                return
            proto_name = _TESTSSL_PROTO_IDS[fid]
            f = _base_finding(ip, port, hostname)
            f["title"] = f"Deprecated Protocol Enabled: {proto_name}"
            f["risk"] = _proto_risk(proto_name)
            f["description"] = f"testssl: {proto_name} is enabled on {ip}:{port}"
            f["cves"] = _TESTSSL_CVES.get(fid, "")
            if cve_inline:
                all_cves = set(c for c in (f["cves"] + "," + cve_inline).split(",") if c.strip())
                f["cves"] = ",".join(sorted(all_cves))
            f["output"] = finding_text
            yield ("finding", f)
            return

        cve = _TESTSSL_CVES.get(fid, "")
        if cve_inline:
            all_cves = set(c for c in (cve + "," + cve_inline).split(",") if c.strip())
            cve = ",".join(sorted(all_cves))

        if fid in _TS_SKIP_IDS or fid.startswith("cipher-"):
            return

        if "self-signed" in finding_lo or "self signed" in finding_lo:
            f = _base_finding(ip, port, hostname)
            f["title"] = "SSL/TLS Certificate: Self-Signed"
            f["risk"] = "MEDIUM"
            f["description"] = "The server presented a self-signed TLS certificate."
            f["output"] = finding_text
            f["cves"] = cve
            yield ("finding", f)
            return

        if "chain incomplete" in finding_lo:
            f = _base_finding(ip, port, hostname)
            f["title"] = "SSL/TLS Certificate: Chain Incomplete"
            f["risk"] = "LOW"
            f["description"] = "The TLS certificate chain is incomplete."
            f["output"] = finding_text
            f["cves"] = cve
            yield ("finding", f)
            return

        if "potentially vulnerable" in finding_lo:
            f = _base_finding(ip, port, hostname)
            f["title"] = f"SSL/TLS Vulnerability (Potential): {fid}"
            f["risk"] = "INFO"
            f["description"] = f"testssl flagged {fid} as potentially vulnerable."
            f["output"] = finding_text
            f["cves"] = cve
            yield ("finding", f)
            return

        if fid.startswith("cipher_order"):
            if "not" in finding_lo:
                f = _base_finding(ip, port, hostname)
                f["title"] = "SSL/TLS Ciphers: No Cipher Order Configured"
                f["risk"] = "LOW"
                f["description"] = "The server does not enforce cipher order."
                f["output"] = finding_text
                f["cves"] = cve
                yield ("finding", f)
            return

        if fid.lower() == "cert_extlifespan":
            if sev in ("OK", "INFO"):
                return
            f = _base_finding(ip, port, hostname)
            f["title"] = "SSL/TLS Certificate: Long Duration"
            f["risk"] = "MEDIUM"
            f["description"] = "The TLS certificate has an extended lifespan."
            f["output"] = finding_text
            f["cves"] = cve
            yield ("finding", f)
            return

        if fid in ("cert_commonName_wo_SNI", "cert_commonName"):
            if sev in ("OK", "INFO"):
                return
            f = _base_finding(ip, port, hostname)
            f["title"] = "SSL/TLS Certificate: Hostname Mismatch"
            f["risk"] = "MEDIUM"
            f["description"] = "Certificate common name does not match the hostname."
            f["output"] = finding_text
            f["cves"] = cve
            yield ("finding", f)
            return

        if fid == "cert_trust":
            if sev in ("OK", "INFO"):
                return
            f = _base_finding(ip, port, hostname)
            f["title"] = "SSL/TLS Certificate: Not Trusted"
            f["risk"] = "MEDIUM"
            f["description"] = "The TLS certificate is not trusted."
            f["output"] = finding_text
            f["cves"] = cve
            yield ("finding", f)
            return

        if fid == "cert_subjectAltName":
            f = _base_finding(ip, port, hostname)
            if sev in ("OK", "INFO"):
                f["title"] = "SSL/TLS Certificate: Subject Alternative Names"
                f["risk"] = "INFO"
                f["description"] = "TLS certificate SAN entries."
            else:
                f["title"] = "SSL/TLS Certificate: Missing SAN"
                f["risk"] = "LOW"
                f["description"] = "The TLS certificate is missing Subject Alternative Names."
            f["output"] = finding_text
            f["cves"] = cve
            yield ("finding", f)
            return

        if fid.startswith("hsts"):
            if "offered" in finding_lo and "not offered" not in finding_lo:
                return
            f = _base_finding(ip, port, hostname)
            f["title"] = "Missing Security Headers"
            f["risk"] = "LOW"
            f["description"] = "Strict Transport Security header not detected."
            f["affected"] = "Strict Transport Security"
            f["output"] = finding_text
            f["cves"] = cve
            yield ("finding", f)
            return

        if fid == "cert_keySize":
            f = _base_finding(ip, port, hostname)
            f["title"] = "SSL/TLS Certificate: Weak Encryption Method"
            f["risk"] = "LOW"
            f["description"] = "The TLS certificate uses a weak key size."
            f["output"] = finding_text
            f["cves"] = cve
            yield ("finding", f)
            return

        if fid == "cipherlist_OBSOLETED":
            if "not offered" in finding_lo:
                return
            obs_ciphers = list(dict.fromkeys(
                re.findall(r'\b([A-Z][A-Z0-9_-]{4,})\b', finding_text)
            ))
            f = _base_finding(ip, port, hostname)
            f["title"] = "SSL/TLS Ciphers: Obsolete Ciphers"
            f["risk"] = "MEDIUM"
            f["owasp"] = "A02:2025 Cryptographic Failures"
            f["nist"] = "SC-8"
            f["remediation"] = "Disable weak and obsolete cipher suites; use modern TLS 1.2/1.3 with AEAD ciphers."
            if obs_ciphers:
                f["description"] = f"Obsolete cipher suites offered: {', '.join(obs_ciphers)}"
                f["output"] = f"Obsolete ciphers: {', '.join(obs_ciphers)}\ntestssl finding: {finding_text}"
            else:
                f["description"] = "Obsolete ciphers detected but could not enumerate individual suites."
                f["output"] = finding_text
            f["cves"] = cve
            yield ("finding", f)
            return

        if risk not in ("INFO",) or sev not in ("OK", "INFO"):
            f = _base_finding(ip, port, hostname)
            f["title"] = f"SSL/TLS Finding: {fid}" if fid else "SSL/TLS Finding"
            f["risk"] = risk
            f["description"] = finding_text[:500] if finding_text else f"testssl finding: {fid}"
            f["output"] = finding_text
            f["cves"] = cve
            yield ("finding", f)


class TestsslTextParser(BaseParser):
    TOOL_ID = "testssl"
    TOOL_NAME = "testssl-text"
    SUPPORTED_FORMATS = ["txt"]

    def extract_targets(self):
        targets = set()
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return targets
        for m in _RE_IP_PORT.finditer(text[:4096]):
            targets.add(m.group(1))
        return targets

    def parse(self):
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            self.emit("log", f"Failed to read testssl text: {exc}")
            return

        lines = text.splitlines()
        self.emit("log", f"testssl text: {len(lines)} lines")

        ip = ""
        port = 443
        hostname = ""
        for line in lines[:30]:
            m = _RE_IP_PORT.search(line)
            if m:
                ip = m.group(1)
                port = int(m.group(2))
                break

        if ip:
            yield ("target", {"ip": ip, "port": port, "hostname": hostname})
            yield ("port", {"ip": ip, "port": port, "service": "ssl/tls", "protocol": "tcp"})

        cert_subject = ""
        cert_issuer = ""
        cert_expiry = ""

        for line in lines:
            line_s = line.strip()
            if not line_s:
                continue

            m = _RE_TS_PROTO.match(line_s)
            if m:
                proto_raw = m.group(1)
                status = m.group(2).lower()
                if status == "offered":
                    normalized = _norm_proto(proto_raw)
                    if _RE_WEAK_SSL.search(proto_raw) or _RE_WEAK_TLS.search(proto_raw):
                        f = _base_finding(ip, port, hostname)
                        f["title"] = f"Deprecated Protocol Enabled: {normalized}"
                        f["risk"] = _proto_risk(normalized)
                        f["description"] = f"testssl: {normalized} is enabled on {ip}:{port}"
                        f["output"] = line_s
                        yield ("finding", f)
                continue

            m = _RE_TS_VULN.match(line_s)
            if m:
                name = m.group(1)
                detail = m.group(2)
                if re.search(r'\bVULNERABLE\b', detail, re.I):
                    is_potential = "potentially" in detail.lower() or "potential" in detail.lower()
                    if is_potential:
                        title = f"SSL/TLS Vulnerability (Potential): {name}"
                        risk = "INFO"
                    else:
                        title = f"SSL/TLS Vulnerability: {name}"
                        name_u = name.upper()
                        if name_u in ("HEARTBLEED", "ROBOT", "DROWN", "POODLE"):
                            risk = "CRITICAL"
                        elif name_u in ("LUCKY13",):
                            risk = "MEDIUM"
                        elif name_u in ("SWEET32",):
                            risk = "MEDIUM"
                        else:
                            risk = "HIGH"
                    f = _base_finding(ip, port, hostname)
                    f["title"] = title
                    f["risk"] = risk
                    f["description"] = _TESTSSL_DESCS.get(
                        name, f"testssl detected {name} on this TLS endpoint.")
                    f["cves"] = _TESTSSL_CVES.get(name.lower(), _TESTSSL_CVES.get(name, ""))
                    f["output"] = line_s
                    yield ("finding", f)
                continue

            m = _RE_TS_CIPHER_CAT.match(line_s)
            if m:
                cat = m.group(1).strip()
                status = m.group(2).lower()
                if status == "offered":
                    f = _base_finding(ip, port, hostname)
                    f["title"] = "Weak Cipher Identified"
                    f["risk"] = "HIGH" if "null" in cat.lower() or "export" in cat.lower() else "MEDIUM"
                    f["description"] = f"Weak cipher category offered: {cat}"
                    f["output"] = line_s
                    yield ("finding", f)
                continue

            m = _RE_TS_SUBJECT.search(line_s)
            if m and not cert_subject:
                cert_subject = m.group(1).strip()
            m = _RE_TS_ISSUER.search(line_s)
            if m and not cert_issuer:
                cert_issuer = m.group(1).strip()
            m = _RE_TS_EXPIRY.search(line_s)
            if m and not cert_expiry:
                cert_expiry = m.group(1).strip()

        if cert_subject or cert_issuer or cert_expiry:
            f = _base_finding(ip, port, hostname)
            f["title"] = "SSL/TLS Certificate Information"
            f["risk"] = "INFO"
            f["description"] = f"TLS certificate details for {ip}:{port}."
            parts = []
            if cert_subject:
                parts.append(f"Subject: {cert_subject}")
            if cert_issuer:
                parts.append(f"Issuer: {cert_issuer}")
            if cert_expiry:
                parts.append(f"Expires: {cert_expiry}")
            f["output"] = "\n".join(parts)
            yield ("finding", f)
