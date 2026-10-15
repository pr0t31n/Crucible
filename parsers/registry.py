"""Parser registry — content-based fingerprinting and parser dispatch."""

import json
import re
import logging

log = logging.getLogger("crucible.parsers.registry")

# ── Compiled fingerprint regexes ────────────────────────────────────────
_RE_GOBUSTER = re.compile(r'(/\S+)\s+\(Status:\s*\d+\)')
_RE_FEROXBUSTER = re.compile(r'^\d{3}\s+\w+\s+.*?https?://')
_RE_ENUM4 = re.compile(r'={3,}\s*\w+.*={3,}')
_RE_HYDRA = re.compile(r'host:\s*\S+.*?login:\s*\S+\s+password:')
_RE_RESPONDER = re.compile(r'\w+::\w+:')
_RE_MSF = re.compile(r'^\s*\d+\s+(exploit|auxiliary|post)/')
_RE_FQDN = re.compile(r'^[a-z0-9]([a-z0-9.\-]*[a-z0-9])?\.[a-z]{2,}$', re.I)
_RE_TESTSSL = re.compile(r'(SSLv[23]|TLS\s*1[._][0-3])\s.*(offered|not offered)', re.I)
_RE_SSLSCAN = re.compile(r'(SSLv[23]|TLSv[\d.]+)\s+(enabled|disabled)', re.I)

# Pcap magic bytes
_PCAP_LE = b'\xd4\xc3\xb2\xa1'
_PCAP_BE = b'\xa1\xb2\xc3\xd4'
_PCAPNG = b'\x0a\x0d\x0d\x0a'


class ParserRegistry:
    """Content-based fingerprinting and parser dispatch."""

    def __init__(self):
        self._parsers = {}
        self._fingerprints = []
        self._tool_meta = {}
        self._register_all()

    def register(self, tool_name, tool_id, formats, fingerprint_fn,
                 module_path, class_name):
        self._parsers[tool_name] = {
            "tool_id": tool_id,
            "formats": formats,
            "module": module_path,
            "class": class_name,
        }
        self._fingerprints.append((tool_name, fingerprint_fn))
        self._tool_meta[tool_name] = {
            "name": tool_name, "tool_id": tool_id, "formats": formats,
        }

    def identify(self, file_path):
        """Identify tool from file content.
        Returns (tool_name, parser_class) or None."""
        try:
            with open(file_path, "rb") as f:
                chunk = f.read(8192)
        except OSError:
            return None
        if not chunk:
            return None

        text = chunk.decode("utf-8", errors="replace")
        first_lines = text.splitlines()[:50]

        for tool_name, fp_fn in self._fingerprints:
            try:
                if fp_fn(chunk, first_lines):
                    cls = self._load_class(tool_name)
                    if cls:
                        return (tool_name, cls)
            except Exception:
                pass
        return None

    def get_parser(self, tool_name):
        """Get parser class by tool name."""
        if tool_name not in self._parsers:
            low = tool_name.lower()
            for k in self._parsers:
                if k.lower() == low:
                    tool_name = k
                    break
        return self._load_class(tool_name)

    def get_tool_id(self, tool_name):
        info = self._parsers.get(tool_name)
        return info["tool_id"] if info else None

    def list_tools(self):
        """Return list of {name, tool_id, formats} for UI dropdown."""
        return sorted(self._tool_meta.values(), key=lambda t: t["name"])

    def _load_class(self, tool_name):
        info = self._parsers.get(tool_name)
        if not info:
            return None
        try:
            import importlib
            mod = importlib.import_module(info["module"])
            return getattr(mod, info["class"])
        except (ImportError, AttributeError) as exc:
            log.warning("Failed to load parser %s.%s: %s",
                        info["module"], info["class"], exc)
            return None

    # ── Registration ────────────────────────────────────────────────────

    def _register_all(self):
        P = "parsers"

        # Binary — highest priority
        self.register("pcap", "pcap", ["pcap", "pcapng", "cap"],
                      self._fp_pcap_magic, f"{P}.network_tools", "PcapParser")

        # XML
        self.register("nmap", "nmap", ["xml"],
                      self._fp_nmap_xml, f"{P}.nmap", "NmapParser")
        self.register("nessus", "nessus", ["nessus", "xml"],
                      self._fp_nessus_xml, f"{P}.nessus", "NessusParser")
        self.register("burp", "burp", ["xml"],
                      self._fp_burp_xml, f"{P}.burp", "BurpParser")
        self.register("sslscan-xml", "sslscan", ["xml"],
                      self._fp_sslscan_xml, f"{P}.sslscan", "SslscanXmlParser")

        # JSON
        self.register("testssl-json", "testssl", ["json"],
                      self._fp_testssl_json, f"{P}.testssl", "TestsslJsonParser")
        self.register("ssh-audit", "ssh-audit", ["json"],
                      self._fp_ssh_audit_json, f"{P}.ssh_audit", "SshAuditParser")
        self.register("shcheck-json", "shcheck", ["json"],
                      self._fp_shcheck_json, f"{P}.recon_tools", "ShcheckParser")
        self.register("wpscan", "wpscan", ["json"],
                      self._fp_wpscan_json, f"{P}.web_scanners", "WPScanParser")
        self.register("searchsploit-json", "searchsploit", ["json"],
                      self._fp_searchsploit_json, f"{P}.sql_tools",
                      "SearchsploitParser")
        self.register("ffuf", "ffuf", ["json"],
                      self._fp_ffuf_json, f"{P}.web_scanners", "FfufParser")

        # JSONL
        self.register("nuclei", "nuclei", ["jsonl", "json"],
                      self._fp_nuclei_jsonl, f"{P}.nuclei", "NucleiParser")
        self.register("dnsx", "dnsx", ["jsonl", "json"],
                      self._fp_dnsx_jsonl, f"{P}.dns_tools", "DnsxParser")

        # CSV
        self.register("nessus-csv", "nessus", ["csv"],
                      self._fp_nessus_csv, f"{P}.nessus", "NessusParser")

        # Text — order matters: specific patterns before generic
        self.register("nikto", "nikto", ["txt", "csv"],
                      self._fp_nikto_text, f"{P}.web_scanners", "NiktoParser")
        self.register("sslscan-text", "sslscan", ["txt"],
                      self._fp_sslscan_text, f"{P}.sslscan", "SslscanTextParser")
        self.register("testssl-text", "testssl", ["txt"],
                      self._fp_testssl_text, f"{P}.testssl", "TestsslTextParser")
        self.register("gobuster", "gobuster", ["txt"],
                      self._fp_gobuster_text, f"{P}.web_scanners",
                      "GobusterParser")
        self.register("feroxbuster", "feroxbuster", ["txt"],
                      self._fp_feroxbuster_text, f"{P}.web_scanners",
                      "FeroxbusterParser")
        self.register("smbmap", "smbmap", ["txt"],
                      self._fp_smbmap_text, f"{P}.smb_tools", "SmbmapParser")
        self.register("enum4linux", "enum4linux", ["txt"],
                      self._fp_enum4linux_text, f"{P}.smb_tools",
                      "Enum4linuxParser")
        self.register("hydra", "hydra", ["txt"],
                      self._fp_hydra_text, f"{P}.brute_tools", "HydraParser")
        self.register("responder", "responder", ["txt"],
                      self._fp_responder_text, f"{P}.brute_tools",
                      "ResponderParser")
        self.register("sqlmap", "sqlmap", ["txt"],
                      self._fp_sqlmap_text, f"{P}.sql_tools", "SqlmapParser")
        self.register("metasploit", "metasploit", ["txt"],
                      self._fp_msf_text, f"{P}.sql_tools", "MsfSearchParser")
        self.register("shodan", "shodan", ["txt"],
                      self._fp_shodan_text, f"{P}.recon_tools", "ShodanParser")

        # DNS / subdomain tools — generic one-per-line last
        self.register("amass", "amass", ["txt"],
                      self._fp_amass_text, f"{P}.dns_tools", "AmassParser")
        # subfinder uses same parser class as amass
        self.register("subfinder", "subfinder", ["txt"],
                      self._fp_subfinder_text, f"{P}.dns_tools",
                      "SubfinderParser")

    # ── Fingerprint functions ───────────────────────────────────────────

    @staticmethod
    def _fp_pcap_magic(chunk, first_lines):
        return (chunk[:4] in (_PCAP_LE, _PCAP_BE) or
                chunk[:4] == _PCAPNG)

    @staticmethod
    def _fp_nmap_xml(chunk, first_lines):
        return b'<nmaprun' in chunk

    @staticmethod
    def _fp_nessus_xml(chunk, first_lines):
        return b'NessusClientData' in chunk

    @staticmethod
    def _fp_burp_xml(chunk, first_lines):
        return b'<issues' in chunk and b'<issue>' in chunk

    @staticmethod
    def _fp_sslscan_xml(chunk, first_lines):
        return b'<document' in chunk and b'<ssltest' in chunk

    @staticmethod
    def _fp_testssl_json(chunk, first_lines):
        if not first_lines:
            return False
        line = first_lines[0].strip()
        if not line or line[0] not in '{[':
            return False
        try:
            obj = json.loads(chunk.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False
        if isinstance(obj, list):
            if obj and isinstance(obj[0], dict):
                return "id" in obj[0] and "severity" in obj[0]
            return False
        if isinstance(obj, dict):
            if "findings" in obj or "scanResult" in obj:
                return True
        return False

    @staticmethod
    def _fp_ssh_audit_json(chunk, first_lines):
        if not first_lines:
            return False
        line = first_lines[0].strip()
        if not line or line[0] != '{':
            return False
        try:
            obj = json.loads(chunk.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False
        return isinstance(obj, dict) and "banner" in obj and "kex" in obj

    @staticmethod
    def _fp_shcheck_json(chunk, first_lines):
        if not first_lines:
            return False
        line = first_lines[0].strip()
        if not line or line[0] != '{':
            return False
        try:
            obj = json.loads(chunk.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False
        if isinstance(obj, dict):
            if "missing" in obj:
                return True
            for v in obj.values():
                if isinstance(v, dict) and "missing" in v:
                    return True
        return False

    @staticmethod
    def _fp_wpscan_json(chunk, first_lines):
        if not first_lines:
            return False
        line = first_lines[0].strip()
        if not line or line[0] != '{':
            return False
        try:
            obj = json.loads(chunk.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False
        return (isinstance(obj, dict) and
                ("version" in obj or "main_theme" in obj) and
                ("plugins" in obj or "themes" in obj))

    @staticmethod
    def _fp_searchsploit_json(chunk, first_lines):
        if not first_lines:
            return False
        line = first_lines[0].strip()
        if not line or line[0] != '{':
            return False
        try:
            obj = json.loads(chunk.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False
        return isinstance(obj, dict) and "RESULTS_EXPLOIT" in obj

    @staticmethod
    def _fp_ffuf_json(chunk, first_lines):
        if not first_lines:
            return False
        line = first_lines[0].strip()
        if not line or line[0] != '{':
            return False
        try:
            obj = json.loads(chunk.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False
        if isinstance(obj, dict) and "results" in obj:
            results = obj["results"]
            if isinstance(results, list) and results:
                return "input" in results[0]
        return False

    @staticmethod
    def _fp_nuclei_jsonl(chunk, first_lines):
        if not first_lines:
            return False
        line = first_lines[0].strip()
        if not line or line[0] != '{':
            return False
        try:
            obj = json.loads(line)
            return "template-id" in obj and "info" in obj
        except (json.JSONDecodeError, ValueError):
            return False

    @staticmethod
    def _fp_dnsx_jsonl(chunk, first_lines):
        if not first_lines:
            return False
        line = first_lines[0].strip()
        if not line or line[0] != '{':
            return False
        try:
            obj = json.loads(line)
            return ("host" in obj and
                    ("a" in obj or "aaaa" in obj or "cname" in obj))
        except (json.JSONDecodeError, ValueError):
            return False

    @staticmethod
    def _fp_nessus_csv(chunk, first_lines):
        if not first_lines:
            return False
        hdr = first_lines[0].lower()
        return "plugin id" in hdr and "risk" in hdr and "host" in hdr

    @staticmethod
    def _fp_gobuster_text(chunk, first_lines):
        for line in first_lines[:20]:
            if _RE_GOBUSTER.search(line):
                return True
        return False

    @staticmethod
    def _fp_feroxbuster_text(chunk, first_lines):
        for line in first_lines[:20]:
            if _RE_FEROXBUSTER.search(line):
                return True
        return False

    @staticmethod
    def _fp_smbmap_text(chunk, first_lines):
        if b'ADMIN!!!' in chunk:
            return True
        text50 = "\n".join(first_lines[:50])
        return "Disk" in text50 and "Permissions" in text50

    @staticmethod
    def _fp_enum4linux_text(chunk, first_lines):
        if b'enum4linux' in chunk:
            return True
        for line in first_lines[:30]:
            if _RE_ENUM4.search(line):
                return True
        return False

    @staticmethod
    def _fp_hydra_text(chunk, first_lines):
        for line in first_lines:
            if _RE_HYDRA.search(line):
                return True
        return False

    @staticmethod
    def _fp_responder_text(chunk, first_lines):
        for line in first_lines[:30]:
            if _RE_RESPONDER.search(line) and line.count(':') >= 3:
                return True
        return False

    @staticmethod
    def _fp_sqlmap_text(chunk, first_lines):
        return (b'sqlmap' in chunk and
                (b'is vulnerable' in chunk or
                 b'injection point' in chunk))

    @staticmethod
    def _fp_msf_text(chunk, first_lines):
        for line in first_lines[:30]:
            if _RE_MSF.search(line):
                return True
        return False

    @staticmethod
    def _fp_amass_text(chunk, first_lines):
        non_empty = [l.strip() for l in first_lines[:15] if l.strip()]
        if len(non_empty) < 3:
            return False
        fqdn_count = sum(1 for l in non_empty[:10] if _RE_FQDN.match(l))
        return fqdn_count >= len(non_empty[:10]) * 0.8

    @staticmethod
    def _fp_subfinder_text(chunk, first_lines):
        non_empty = [l.strip() for l in first_lines[:15] if l.strip()]
        if len(non_empty) < 3:
            return False
        fqdn_count = sum(1 for l in non_empty[:10] if _RE_FQDN.match(l))
        return fqdn_count >= len(non_empty[:10]) * 0.8

    @staticmethod
    def _fp_shodan_text(chunk, first_lines):
        return b'Ports:' in chunk

    @staticmethod
    def _fp_testssl_text(chunk, first_lines):
        for line in first_lines[:40]:
            if _RE_TESTSSL.search(line):
                return True
        return False

    @staticmethod
    def _fp_sslscan_text(chunk, first_lines):
        for line in first_lines[:40]:
            if _RE_SSLSCAN.search(line):
                return True
        return False

    @staticmethod
    def _fp_nikto_text(chunk, first_lines):
        return (b'Nikto' in chunk or
                b'+ Target IP:' in chunk or
                b'OSVDB-' in chunk)

    @staticmethod
    def _fp_wpscan_text(chunk, first_lines):
        return (b'WPScan' in chunk or
                (b'WordPress' in chunk and b'[+]' in chunk))
