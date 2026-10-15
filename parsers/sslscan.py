"""sslscan import parsers — XML and text output formats."""

import re
from datetime import datetime
from parsers.base import BaseParser

try:
    import xml.etree.ElementTree as ET
except ImportError:
    ET = None

_RE_SS_PROTO = re.compile(r"(SSLv[23]|TLSv[\d.]+)\s+(enabled|disabled)", re.I)
_RE_SS_CIPHER = re.compile(r"Accepted\s+(\S+)\s+(\d+)\s+bits\s+(\S+)", re.I)
_RE_SS_SUBJECT = re.compile(r"Subject:\s+(.+)")
_RE_SS_ISSUER = re.compile(r"Issuer:\s+(.+)")
_RE_SS_EXPIRY = re.compile(r"Not valid after:\s+(.+)", re.I)
_RE_SS_SELF = re.compile(r"self[- ]signed", re.I)
_RE_SS_HB = re.compile(r"heartbleed.*?(vulnerable|not vulnerable|safe)", re.I)
_RE_WEAK_CIPHER = re.compile(r"RC4|DES|EXPORT|NULL|anon|MD5|3DES", re.I)
_RE_WEAK_SSL = re.compile(r"SSLv[23]", re.I)
_RE_WEAK_TLS = re.compile(
    r"TLSv1(?:\.0|\.1|(?!\.[23]))\b", re.I
)
_RE_IP_PORT = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})[:/](\d+)')


def _proto_risk(proto_name):
    if re.search(r'SSLv2', proto_name, re.I):
        return "HIGH"
    if re.search(r'SSLv3', proto_name, re.I):
        return "MEDIUM"
    return "LOW"


def _base_finding(ip, port, hostname):
    return {
        "ip": ip, "port": int(port) if port else 443,
        "hostname": hostname or "", "command": "imported",
        "output": "", "cves": "", "sources": "sslscan",
        "service": "ssl/tls", "output_file": "",
        "affected": f"{ip}:{port}" if port else ip,
        "datetime": datetime.now().isoformat(),
        "exploitdb": False, "metasploit": False, "exploit_details": [],
    }


class SslscanXmlParser(BaseParser):
    TOOL_ID = "sslscan"
    TOOL_NAME = "sslscan-xml"
    SUPPORTED_FORMATS = ["xml"]

    def extract_targets(self):
        targets = set()
        if not ET:
            return targets
        try:
            tree = ET.parse(str(self.file_path))
            root = tree.getroot()
            for st in root.findall(".//ssltest"):
                host = st.get("host", "")
                if host:
                    targets.add(host)
        except Exception:
            pass
        return targets

    def parse(self):
        if not ET:
            self.emit("log", "xml.etree not available")
            return
        try:
            tree = ET.parse(str(self.file_path))
            root = tree.getroot()
        except Exception as exc:
            self.emit("log", f"Failed to parse sslscan XML: {exc}")
            return

        for ssltest in root.findall(".//ssltest"):
            ip = ssltest.get("host", "")
            port_s = ssltest.get("port", "443")
            try:
                port = int(port_s)
            except ValueError:
                port = 443
            hostname = ssltest.get("sniName", "") or ""

            self.emit("log", f"sslscan XML: {ip}:{port}")
            yield ("target", {"ip": ip, "port": port, "hostname": hostname})
            yield ("port", {"ip": ip, "port": port, "service": "ssl/tls", "protocol": "tcp"})

            # Heartbleed
            for hb_el in ssltest.findall(".//heartbleed"):
                if hb_el.get("vulnerable", "0") == "1":
                    f = _base_finding(ip, port, hostname)
                    f["title"] = "Heartbleed (CVE-2014-0160) Vulnerability Detected"
                    f["risk"] = "CRITICAL"
                    f["cves"] = "CVE-2014-0160"
                    f["description"] = "sslscan: Heartbleed (CVE-2014-0160) detected — remote memory disclosure possible"
                    f["output"] = "Heartbleed status: vulnerable"
                    yield ("finding", f)
                    break

            # Protocols
            cipher_protos = set()
            for cipher_el in ssltest.findall(".//cipher"):
                if cipher_el.get("status", "").lower() == "accepted":
                    cipher_protos.add(cipher_el.get("sslversion", "").lower())

            for proto_el in ssltest.findall(".//protocol"):
                ptype = proto_el.get("type", "").lower()
                pver = proto_el.get("version", "")
                enabled = proto_el.get("enabled", "0") == "1"
                if ptype == "ssl":
                    pname = f"SSLv{pver.replace('.', '')}"
                elif ptype == "tls":
                    pname = f"TLSv{pver}"
                else:
                    continue
                if enabled and (_RE_WEAK_SSL.search(pname) or _RE_WEAK_TLS.search(pname)):
                    if cipher_protos and pname.lower() not in cipher_protos:
                        continue
                    f = _base_finding(ip, port, hostname)
                    f["title"] = f"Deprecated Protocol Enabled: {pname}"
                    f["risk"] = _proto_risk(pname)
                    f["description"] = f"sslscan: {pname} is enabled on {ip}:{port}"
                    f["output"] = f"Protocol: {pname}\nStatus: enabled"
                    yield ("finding", f)

            # Ciphers
            for cipher_el in ssltest.findall(".//cipher"):
                if cipher_el.get("status", "").lower() != "accepted":
                    continue
                cipher_name = cipher_el.get("cipher", "")
                bits_s = cipher_el.get("bits", "128")
                try:
                    bits = int(bits_s)
                except ValueError:
                    bits = 128
                is_weak = _RE_WEAK_CIPHER.search(cipher_name) or bits < 128
                if is_weak:
                    f = _base_finding(ip, port, hostname)
                    f["title"] = f"Weak Cipher Accepted: {cipher_name}"
                    f["risk"] = "HIGH"
                    f["description"] = f"Weak cipher suite {cipher_name} ({bits} bits) is accepted."
                    f["output"] = f"Cipher: {cipher_name}\nBits: {bits}"
                    yield ("finding", f)

            # Certificate
            cert_subject = ""
            cert_issuer = ""
            cert_expiry = ""
            self_signed = False
            pk_type = ""
            pk_bits = 0

            for cert_el in ssltest.findall(".//certificate"):
                if not cert_subject:
                    subj_el = cert_el.find("subject")
                    if subj_el is not None and subj_el.text:
                        cert_subject = subj_el.text.strip()
                if not cert_issuer:
                    iss_el = cert_el.find("issuer")
                    if iss_el is not None and iss_el.text:
                        cert_issuer = iss_el.text.strip()
                if not cert_expiry:
                    exp_el = cert_el.find("not-valid-after")
                    if exp_el is not None and exp_el.text:
                        cert_expiry = exp_el.text.strip()
                ss = cert_el.get("self-signed", cert_el.get("self_signed", ""))
                if ss and ss.lower() in ("true", "1", "yes"):
                    self_signed = True
                pt = cert_el.get("pk-type", "")
                pb = cert_el.get("pk-bits", "")
                if pt and pb:
                    pk_type = pt
                    try:
                        pk_bits = int(pb)
                    except ValueError:
                        pass

            if self_signed:
                f = _base_finding(ip, port, hostname)
                f["title"] = "SSL/TLS Certificate: Self-Signed"
                f["risk"] = "MEDIUM"
                f["description"] = "The server presented a self-signed TLS certificate."
                f["output"] = f"Subject: {cert_subject}\nIssuer: {cert_issuer}\nStatus: self-signed"
                yield ("finding", f)

            if pk_type and pk_bits:
                weak_key = (pk_type.upper() == "RSA" and pk_bits < 4096) or \
                           (pk_type.upper() in ("EC", "ECDSA") and pk_bits < 256)
                if weak_key:
                    f = _base_finding(ip, port, hostname)
                    f["title"] = "SSL/TLS Certificate: Weak Encryption Method"
                    f["risk"] = "LOW"
                    f["description"] = f"TLS certificate uses {pk_type} {pk_bits} bits."
                    f["output"] = f"{pk_type} {pk_bits} bits"
                    yield ("finding", f)

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
                    parts.append(f"Not Valid After: {cert_expiry}")
                f["output"] = "\n".join(parts)
                yield ("finding", f)


class SslscanTextParser(BaseParser):
    TOOL_ID = "sslscan"
    TOOL_NAME = "sslscan-text"
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
            self.emit("log", f"Failed to read sslscan text: {exc}")
            return

        lines = text.splitlines()
        self.emit("log", f"sslscan text: {len(lines)} lines")

        ip = ""
        port = 443
        hostname = ""
        for line in lines[:20]:
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
        cert_self_signed = False
        heartbleed_done = False

        for line in lines:
            line_s = line.strip()
            if not line_s:
                continue

            m = _RE_SS_PROTO.match(line_s)
            if m:
                proto = m.group(1)
                status = m.group(2).lower()
                if status == "enabled" and (_RE_WEAK_SSL.search(proto) or _RE_WEAK_TLS.search(proto)):
                    f = _base_finding(ip, port, hostname)
                    f["title"] = f"Deprecated Protocol Enabled: {proto}"
                    f["risk"] = _proto_risk(proto)
                    f["description"] = f"sslscan: {proto} is enabled on {ip}:{port}"
                    f["output"] = f"Protocol: {proto}\nStatus: enabled"
                    yield ("finding", f)
                continue

            m = _RE_SS_CIPHER.match(line_s)
            if m:
                cipher_name = m.group(3)
                try:
                    bits = int(m.group(2))
                except ValueError:
                    bits = 128
                if _RE_WEAK_CIPHER.search(cipher_name) or bits < 128:
                    f = _base_finding(ip, port, hostname)
                    f["title"] = f"Weak Cipher Accepted: {cipher_name}"
                    f["risk"] = "HIGH"
                    f["description"] = f"Weak cipher suite {cipher_name} ({bits} bits) is accepted."
                    f["output"] = f"Cipher: {cipher_name}\nBits: {bits}"
                    yield ("finding", f)
                continue

            if not heartbleed_done:
                m = _RE_SS_HB.search(line_s)
                if m:
                    heartbleed_done = True
                    if m.group(1).lower() == "vulnerable":
                        f = _base_finding(ip, port, hostname)
                        f["title"] = "Heartbleed (CVE-2014-0160) Vulnerability Detected"
                        f["risk"] = "CRITICAL"
                        f["cves"] = "CVE-2014-0160"
                        f["description"] = "sslscan: Heartbleed detected — remote memory disclosure possible"
                        f["output"] = f"Heartbleed status: {m.group(1)}"
                        yield ("finding", f)
                    continue

            if _RE_SS_SELF.search(line_s):
                cert_self_signed = True

            m = _RE_SS_SUBJECT.search(line_s)
            if m and not cert_subject:
                cert_subject = m.group(1).strip()
            m = _RE_SS_ISSUER.search(line_s)
            if m and not cert_issuer:
                cert_issuer = m.group(1).strip()
            m = _RE_SS_EXPIRY.search(line_s)
            if m and not cert_expiry:
                cert_expiry = m.group(1).strip()

        if cert_self_signed:
            f = _base_finding(ip, port, hostname)
            f["title"] = "SSL/TLS Certificate: Self-Signed"
            f["risk"] = "MEDIUM"
            f["description"] = "The server presented a self-signed TLS certificate."
            f["output"] = f"Subject: {cert_subject}\nIssuer: {cert_issuer}\nStatus: self-signed"
            yield ("finding", f)

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
                parts.append(f"Not Valid After: {cert_expiry}")
            f["output"] = "\n".join(parts)
            yield ("finding", f)
