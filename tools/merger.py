"""Crucible v2 Engagement Merger — standalone tool.

Scans a folder for Crucible v2 exports, legacy exports, and Nessus
files, then merges everything into a single unified Crucible v2 engagement.
"""

import csv
import io
import ipaddress
import json
import re
import shutil
import sys
import uuid
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

_APP_DIR = Path(__file__).resolve().parent.parent
if str(_APP_DIR) not in sys.path:
    sys.path.insert(0, str(_APP_DIR))

from config import CLIENTS_BASE, TOOL_OUTPUT_DIRS

_TOOL_NATIVE_SCOPE = {
    "ss3": "external", "osift": "osint", "trawler": "pcap",
    "fracture": "webapp", "siphon": "api", "auger": "database",
    "bastion": "firewall", "forge": "cloud", "quill": "mobile",
    "isotope": "file", "aether": "wifi", "aether_b": "bluetooth",
    "aether_z": "zigbee", "aether_u": "uwb", "authprobe": "external",
    "nessus": "external",
}

_TOOL_KEY_MAP = {
    "ss": "ss3", "os": "osift", "tr": "trawler",
    "au": "auger", "fr": "fracture", "si": "siphon",
    "scattershot3": "ss3", "scattershot": "ss3",
}

_RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

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
        "SSL/TLS Vulnerability: SSLv2/SSLv3 is Deprecated",
    "TLS Version 1.0 Protocol Detection":
        "SSL/TLS Vulnerability: TLSv1.0 is Deprecated",
    "TLS Version 1.1 Protocol Deprecated":
        "SSL/TLS Vulnerability: TLSv1.1 is Deprecated",
    "TLS Version 1.1 Deprecated Protocol":
        "SSL/TLS Vulnerability: TLSv1.1 is Deprecated",
    "TLS Version 1.1 Protocol Detection":
        "SSL/TLS Vulnerability: TLSv1.1 is Deprecated",
    "SSL RC4 Cipher Suites Supported (Bar Mitzvah)":
        "SSL/TLS Ciphers: Obsolete Cipher — RC4",
    "SSL Weak Cipher Suites Supported":
        "SSL/TLS Ciphers: Weak Cipher Suites",
    "SSL Certificate Chain Contains RSA Keys Less Than 2048 bits":
        "SSL/TLS Certificate: Short Key Length",
    "SSL Certificate Signed Using Weak Hashing Algorithm":
        "SSL/TLS Certificate: Weak Signature Algorithm",
    "MS17-010: Security Update for Microsoft Windows SMB Server (4013389) (ETERNALBLUE) (ETERNALCHAMPION) (ETERNALROMANCE) (ETERNALSYNERGY) (WannaCry) (EternalRocks) (Petya) (uncredentialed check)":
        "RCE: MS17-010 (EternalBlue)(EternalRomance)(WannaCry)",
    "SSL Anonymous Cipher Suites Supported":
        "SSL/TLS Ciphers: Anonymous Cipher Suites",
    "SSH Terrapin Prefix Truncation Weakness (CVE-2023-48795)":
        "SSH Vulnerability: Terrapin",
    "SSH Server CBC Mode Ciphers Enabled":
        "SSH Vulnerability: CBC Mode Ciphers Enabled",
    "SSH Weak Key Exchange Algorithms Enabled":
        "SSH Vulnerability: Weak Key Exchange",
    "Microsoft SQL Server Unsupported Version Detection (remote check)":
        "EOL Software: Microsoft SQL Server",
    "Unsupported Windows OS (remote)":
        "EOL Operating System: Windows OS (remote)",
    "SMB Signing not required":
        "SMB Vulnerability: SMB Signing Not Required",
    "SMB Signing Disabled":
        "SMB Vulnerability: SMB Signing Not Enabled",
}
_NESSUS_TITLE_MAP_LOWER = {k.lower(): v for k, v in _NESSUS_TITLE_MAP.items()}

_WELL_KNOWN_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 587: "submission", 593: "http-rpc-epmap",
    636: "ldaps", 993: "imaps", 995: "pop3s",
    1433: "ms-sql", 1434: "ms-sql-m", 1515: "ifor-protocol",
    1521: "oracle", 2049: "nfs", 3268: "ldap-gc", 3269: "ldap-gc-ssl",
    3306: "mysql", 3389: "ms-wbt-server", 5060: "sip", 5432: "postgresql",
    5500: "vnc", 5900: "vnc", 5985: "wsman", 5986: "wsmans",
    6379: "redis", 8080: "http-proxy", 8443: "https-alt", 8834: "nessus",
    9200: "elasticsearch", 9443: "tungsten-https",
    9593: "cics-websvc", 9594: "msgsys",
    27017: "mongodb", 47001: "winrm",
}

_RFC1918_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def _is_rfc1918(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return any(addr in net for net in _RFC1918_NETS)
    except ValueError:
        return False


_NESSUS_SCANNER_PLUGINS = {
    11219, 19506, 10287, 11936, 54615, 45590, 209654, 12053,
    86420, 35716, 110723, 117886, 66334, 22964, 10736, 10107,
    24260, 11002, 10884, 20870, 11011, 10940, 10267, 48204,
    181418, 50845, 122364, 25221, 10150, 277650, 277654, 298387,
    156899, 70544, 25220, 121010, 136318, 138330, 84821, 39520,
    64814,
}

_NESSUS_RISK_MAP = {
    "4": "CRITICAL", "3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO",
    "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
    "low": "LOW", "none": "INFO", "info": "INFO", "informational": "INFO",
}

_INTEL_FILES = [
    "structure_map.json", "access_matrix.json", "authentication_status.json",
    "target_profile.json", "api_map.json", "api_inventory.json",
    "access_points.json", "software_inventory.json", "hosts_inventory.json",
    "services_inventory.json", "dns_records.json", "firewall_rules.json",
    "zone_map.json", "policy_compliance.json", "config_summary.json",
    "cloud_inventory.json", "iam_matrix.json", "service_dashboard.json",
    "component_map.json", "permission_matrix.json", "binary_hardening.json",
    "data_flow.json", "traffic.json", "conversations.json", "db_schema.json",
    "db_privileges.json", "db_inventory.json", "properties.json",
    "entropy.json", "contents.json", "strings.json", "code_analysis.json",
    "metadata.json", "binary_analysis.json", "secrets.json", "ioc_matches.json",
    "port_matrix.json", "correlated.json", "targets.json", "results.json",
    "targets_osint.json", "domains.json", "certificates.json",
    "dehashed_results.json", "breach_results.json",
]

_FINDINGS_FILENAMES = (
    "findings.json", "findings_crucible.json", "findings_vantage.json", "findings_report.json",  # vantage: legacy compat
)


class MergeSource:
    __slots__ = ("type", "path", "meta", "scopes", "temp_dir", "label")

    def __init__(self, type_, path, meta=None, scopes=None, temp_dir=None):
        self.type = type_
        self.path = Path(path)
        self.meta = meta or {}
        self.scopes = scopes or {}
        self.temp_dir = temp_dir
        name = self.meta.get("name") or self.meta.get("client_short") or self.path.stem
        self.label = f"{self.type}:{name}"


class EngagementMerger:

    def __init__(self, search_folder, output_name=None, clients_base=None,
                 callback=None):
        self.search_folder = Path(search_folder)
        self.output_name = output_name
        self.clients_base = Path(clients_base) if clients_base else CLIENTS_BASE
        self._cb = callback or (lambda msg: None)
        self._temp_dirs = []

    def _log(self, msg):
        self._cb(msg)

    # ── Scanning ────────────────────────────────────────────────

    def scan(self):
        sources = []
        folder = self.search_folder
        if not folder.is_dir():
            self._log(f"ERROR: {folder} is not a directory")
            return sources

        self._log(f"Scanning {folder} ...")

        for fp in sorted(folder.rglob("*")):
            if fp.is_file():
                low = fp.name.lower()
                if low.endswith(".zip"):
                    src = self._probe_zip(fp)
                    if src:
                        sources.append(src)
                elif low.endswith(".nessus"):
                    sources.append(MergeSource("nessus_xml", fp))
                    self._log(f"  Found Nessus XML: {fp.name}")
                elif low.endswith(".csv"):
                    if self._is_nessus_csv(fp):
                        sources.append(MergeSource("nessus_csv", fp))
                        self._log(f"  Found Nessus CSV: {fp.name}")
            elif fp.is_dir():
                if (fp / "crucible_meta.json").is_file():
                    src = self._probe_crucible_dir(fp)
                    if src:
                        sources.append(src)
                elif (fp / "project_meta.json").is_file():
                    if not (fp / "crucible_meta.json").is_file():
                        src = self._probe_legacy_dir(fp)
                        if src:
                            sources.append(src)

        self._log(f"Found {len(sources)} source(s)")
        return sources

    def _probe_zip(self, zip_path):
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                names = zf.namelist()
                crucible_metas = [n for n in names if n.endswith("crucible_meta.json")]
                legacy_metas = [n for n in names if n.endswith("project_meta.json")]

                if crucible_metas:
                    crucible_metas.sort(key=lambda x: x.count("/"))
                    meta = json.loads(zf.read(crucible_metas[0]))
                    self._log(f"  Found Crucible v2 ZIP: {zip_path.name}")
                    return MergeSource("crucible_v2_zip", zip_path, meta)
                elif legacy_metas:
                    legacy_metas.sort(key=lambda x: x.count("/"))
                    meta = json.loads(zf.read(legacy_metas[0]))
                    self._log(f"  Found legacy ZIP: {zip_path.name}")
                    return MergeSource("legacy_zip", zip_path, meta)
        except (zipfile.BadZipFile, json.JSONDecodeError, KeyError):
            pass
        return None

    def _probe_crucible_dir(self, dir_path):
        try:
            meta = json.loads((dir_path / "crucible_meta.json").read_text())
            self._log(f"  Found Crucible v2 dir: {dir_path.name}")
            return MergeSource("crucible_v2_dir", dir_path, meta)
        except (json.JSONDecodeError, OSError):
            return None

    def _probe_legacy_dir(self, dir_path):
        try:
            meta = json.loads((dir_path / "project_meta.json").read_text())
            self._log(f"  Found legacy dir: {dir_path.name}")
            return MergeSource("legacy_dir", dir_path, meta)
        except (json.JSONDecodeError, OSError):
            return None

    def _is_nessus_csv(self, csv_path):
        try:
            with open(csv_path, "r", errors="replace") as f:
                header = f.readline().strip().lower()
                return "plugin id" in header and ("risk" in header or "severity" in header)
        except OSError:
            return False

    # ── Extraction ──────────────────────────────────────────────

    def _extract_source(self, source):
        if source.type.endswith("_zip"):
            import tempfile
            td = Path(tempfile.mkdtemp(prefix="crucible_merge_"))
            self._temp_dirs.append(td)
            with zipfile.ZipFile(source.path, "r") as zf:
                for name in zf.namelist():
                    if ".." in name or name.startswith("/"):
                        continue
                    zf.extract(name, td)
            source.temp_dir = td

            if source.type == "crucible_v2_zip":
                metas = list(td.rglob("crucible_meta.json"))
                if metas:
                    metas.sort(key=lambda p: len(p.parts))
                    source.path = metas[0].parent
            elif source.type == "legacy_zip":
                metas = list(td.rglob("project_meta.json"))
                if metas:
                    metas.sort(key=lambda p: len(p.parts))
                    source.path = metas[0].parent

    def _map_source_scopes(self, source):
        if source.type.startswith("crucible_v2"):
            return self._map_crucible_scopes(source)
        elif source.type.startswith("legacy"):
            return self._map_legacy_scopes(source)
        return {}

    def _map_crucible_scopes(self, source):
        scopes = {}
        root = source.path
        meta = source.meta

        scope_tool_dirs = meta.get("scope_tool_dirs", {})
        if scope_tool_dirs:
            for scope_key, tool_map in scope_tool_dirs.items():
                scopes[scope_key] = {}
                for tool_id, td_str in tool_map.items():
                    td = Path(td_str)
                    if not td.is_absolute() or not td.exists():
                        rel = root / scope_key / TOOL_OUTPUT_DIRS.get(tool_id, tool_id)
                        if rel.exists():
                            td = rel
                    if td.exists():
                        scopes[scope_key][tool_id] = td
        else:
            for child in sorted(root.iterdir()):
                if child.is_dir() and child.name not in ("__pycache__",):
                    scope_meta = child / "scope_meta.json"
                    if scope_meta.exists():
                        scope_key = child.name
                        scopes[scope_key] = {}
                        for tool_child in sorted(child.iterdir()):
                            if tool_child.is_dir():
                                tool_id = self._dirname_to_tool_id(tool_child.name)
                                if tool_id:
                                    scopes[scope_key][tool_id] = tool_child

        source.scopes = scopes
        return scopes

    def _map_legacy_scopes(self, source):
        scopes = {}
        root = source.path
        meta = source.meta
        tool_key = (meta.get("tool") or "").lower()
        tool_id = _TOOL_KEY_MAP.get(tool_key, tool_key)
        if not tool_id:
            for child in sorted(root.iterdir()):
                if child.is_dir():
                    tid = self._dirname_to_tool_id(child.name)
                    if tid:
                        scope = _TOOL_NATIVE_SCOPE.get(tid, "external")
                        scopes.setdefault(scope, {})[tid] = child
            if not scopes:
                scopes["external"] = {"unknown": root}
        else:
            int_dir = root / "int"
            ext_dir = root / "ext"
            if int_dir.is_dir():
                scope = "internal"
            elif ext_dir.is_dir():
                scope = "external"
            else:
                scope = _TOOL_NATIVE_SCOPE.get(tool_id, "external")
            scopes[scope] = {tool_id: root}

            os_dir = meta.get("os_output_dir")
            if os_dir and Path(os_dir).exists():
                scopes.setdefault("osint", {})["osift"] = Path(os_dir)
            tr_dir = meta.get("tr_output_dir")
            if tr_dir and Path(tr_dir).exists():
                scopes.setdefault("pcap", {})["trawler"] = Path(tr_dir)
            au_dir = meta.get("au_output_dir")
            if au_dir and Path(au_dir).exists():
                scopes.setdefault("database", {})["auger"] = Path(au_dir)

        source.scopes = scopes
        return scopes

    def _dirname_to_tool_id(self, dirname):
        rev = {v: k for k, v in TOOL_OUTPUT_DIRS.items()}
        if dirname in rev:
            return rev[dirname]
        if dirname in TOOL_OUTPUT_DIRS:
            return dirname
        return _TOOL_KEY_MAP.get(dirname.lower())

    # ── Scope & target detection ──────────────────────────────

    def _detect_nessus_scope(self, nessus_sources):
        sample_ips = set()
        for src in nessus_sources[:2]:
            if src.type == "nessus_csv":
                try:
                    with open(src.path, "r", errors="replace") as f:
                        reader = csv.DictReader(f)
                        for i, row in enumerate(reader):
                            if i >= 200:
                                break
                            ip = (row.get("Host") or row.get("IP Address") or "").strip()
                            if ip:
                                sample_ips.add(ip)
                except OSError:
                    pass
            elif src.type == "nessus_xml":
                try:
                    tree = ET.parse(str(src.path))
                    for host in tree.getroot().iter("ReportHost"):
                        hp = host.find("HostProperties")
                        if hp is not None:
                            for tag in hp.iter("tag"):
                                if tag.get("name") == "host-ip" and tag.text:
                                    sample_ips.add(tag.text.strip())
                except ET.ParseError:
                    pass
        if sample_ips and all(_is_rfc1918(ip) for ip in sample_ips):
            self._log("  Nessus targets are RFC1918 → internal scope")
            return "internal"
        return "external"

    def _should_reclassify_as_internal(self, sources, nessus_sources):
        all_ips = set()
        for src in sources:
            if src.type.startswith("nessus"):
                continue
            for scope_key, tool_map in src.scopes.items():
                if scope_key != "external":
                    continue
                for _tid, td in tool_map.items():
                    if not td.exists() or not td.is_dir():
                        continue
                    for fn in _FINDINGS_FILENAMES:
                        fp = td / fn
                        if not fp.exists():
                            for sub in sorted(td.iterdir()):
                                if sub.is_dir():
                                    fp = sub / fn
                                    if fp.exists():
                                        break
                            else:
                                continue
                        try:
                            data = json.loads(fp.read_text())
                            findings = data if isinstance(data, list) else data.get("findings", [])
                            for f in findings[:100]:
                                ip = (f.get("ip") or "").strip()
                                if ip:
                                    all_ips.add(ip)
                        except (json.JSONDecodeError, OSError):
                            pass
                        break

        if not all_ips:
            return False
        return all(_is_rfc1918(ip) for ip in all_ips)

    def _import_targets(self, sources, nessus_sources):
        targets_by_scope = {}
        search_dir = self.search_folder

        for fp in sorted(search_dir.iterdir()):
            if not fp.is_file():
                continue
            low = fp.name.lower()
            if low == "targets.txt" or low.endswith("_targets.txt"):
                try:
                    for line in fp.read_text().splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            scope = "internal" if self._target_is_internal(line) else "external"
                            targets_by_scope.setdefault(scope, set()).add(line)
                except OSError:
                    pass
            elif low.endswith(".gnmap"):
                try:
                    for line in fp.read_text().splitlines():
                        if line.startswith("Host:"):
                            parts = line.split()
                            if len(parts) >= 2:
                                ip = parts[1].strip()
                                scope = "internal" if _is_rfc1918(ip) else "external"
                                targets_by_scope.setdefault(scope, set()).add(ip)
                except OSError:
                    pass

        for src in nessus_sources:
            if src.type == "nessus_csv":
                try:
                    with open(src.path, "r", errors="replace") as f:
                        reader = csv.DictReader(f)
                        seen = set()
                        for row in reader:
                            ip = (row.get("Host") or row.get("IP Address") or "").strip()
                            if ip and ip not in seen:
                                seen.add(ip)
                                scope = "internal" if _is_rfc1918(ip) else "external"
                                targets_by_scope.setdefault(scope, set()).add(ip)
                except OSError:
                    pass
            elif src.type == "nessus_xml":
                try:
                    tree = ET.parse(str(src.path))
                    for host in tree.getroot().iter("ReportHost"):
                        hp = host.find("HostProperties")
                        if hp is not None:
                            for tag in hp.iter("tag"):
                                if tag.get("name") == "host-ip" and tag.text:
                                    ip = tag.text.strip()
                                    scope = "internal" if _is_rfc1918(ip) else "external"
                                    targets_by_scope.setdefault(scope, set()).add(ip)
                except ET.ParseError:
                    pass

        result = {}
        for scope_key, addrs in targets_by_scope.items():
            result[scope_key] = sorted(addrs)
            self._log(f"  Imported {len(addrs)} targets for {scope_key} scope")
        return result

    @staticmethod
    def _target_is_internal(target_str):
        target_str = target_str.strip()
        if "/" in target_str:
            try:
                net = ipaddress.ip_network(target_str, strict=False)
                return net.is_private
            except ValueError:
                return False
        return _is_rfc1918(target_str)

    # ── Merging ─────────────────────────────────────────────────

    def merge(self, sources):
        if not sources:
            self._log("ERROR: No sources to merge")
            return None

        self._log("Extracting ZIP sources...")
        for src in sources:
            if src.type.endswith("_zip"):
                self._extract_source(src)

        self._log("Mapping source scopes...")
        for src in sources:
            if not src.type.startswith("nessus"):
                self._map_source_scopes(src)

        eng_dir = self._create_engagement(sources)
        if not eng_dir:
            return None

        all_scopes = {}
        for src in sources:
            for scope_key, tool_map in src.scopes.items():
                for tool_id in tool_map:
                    all_scopes.setdefault(scope_key, set()).add(tool_id)

        nessus_sources = [s for s in sources if s.type.startswith("nessus")]
        if nessus_sources:
            nessus_scope = self._detect_nessus_scope(nessus_sources)
            all_scopes.setdefault(nessus_scope, set()).add("nessus")

        if "external" in all_scopes and self._should_reclassify_as_internal(sources, nessus_sources):
            all_scopes["internal"] = all_scopes.pop("external")
            self._log("  Reclassified scope: external → internal (RFC1918 IPs detected)")

        imported_targets = self._import_targets(sources, nessus_sources)

        for scope_key, tool_ids in sorted(all_scopes.items()):
            scope_dir = eng_dir / scope_key
            scope_dir.mkdir(parents=True, exist_ok=True)
            scope_targets = imported_targets.get(scope_key, [])
            self._write_scope_meta(scope_dir, scope_key, scope_targets)

            for tool_id in sorted(tool_ids):
                tool_dirname = TOOL_OUTPUT_DIRS.get(tool_id, tool_id)
                dst_tool_dir = scope_dir / tool_dirname
                dst_tool_dir.mkdir(parents=True, exist_ok=True)

                if tool_id == "nessus":
                    self._merge_nessus(nessus_sources, dst_tool_dir)
                    continue

                src_dirs = []
                for src in sources:
                    if src.type.startswith("nessus"):
                        continue
                    td = src.scopes.get(scope_key, {}).get(tool_id)
                    if td and td.exists():
                        src_dirs.append((src, td))

                if src_dirs:
                    self._merge_tool_output(src_dirs, dst_tool_dir, tool_id,
                                            eng_dir)

        self._update_engagement_meta(eng_dir, all_scopes, imported_targets)
        self._write_provenance(eng_dir, sources)

        self._enrich_merged_findings(eng_dir, all_scopes)
        self._build_targets_json(eng_dir, all_scopes)
        if nessus_sources:
            self._update_nessus_action_items(eng_dir)
            self._build_nessus_software_inventory(eng_dir, all_scopes)

        self._log(f"Merge complete: {eng_dir}")
        self.cleanup()
        return eng_dir

    def _enrich_merged_findings(self, eng_dir, all_scopes):
        self._log("Running enrichment pass...")
        enriched_total = 0
        for scope_key, tool_ids in all_scopes.items():
            for tool_id in tool_ids:
                tool_dirname = TOOL_OUTPUT_DIRS.get(tool_id, tool_id)
                fp = eng_dir / scope_key / tool_dirname / "findings.json"
                if not fp.exists():
                    continue
                try:
                    data = json.loads(fp.read_text())
                    findings = data if isinstance(data, list) else data.get("findings", [])
                except (json.JSONDecodeError, OSError):
                    continue
                changed = False
                for f in findings:
                    if not f.get("id"):
                        f["id"] = str(uuid.uuid4())
                        changed = True
                    if not f.get("tool"):
                        f["tool"] = tool_id
                        changed = True
                    if not f.get("scope"):
                        f["scope"] = scope_key
                        changed = True
                    risk = (f.get("risk") or "INFO").upper()
                    if risk != f.get("risk"):
                        f["risk"] = risk
                        changed = True
                    desc = f.get("description") or ""
                    if not desc and f.get("output"):
                        f["description"] = f["output"][:500]
                        changed = True
                    if changed:
                        enriched_total += 1
                if changed:
                    with open(fp, "w") as fh:
                        json.dump(findings, fh, indent=2)

        if enriched_total:
            self._log(f"  Enriched {enriched_total} findings")

    def _create_engagement(self, sources):
        now = datetime.now()
        ts = now.strftime("%Y%m%d_%H%M%S")
        year = str(now.year)

        client_shorts = []
        _cs_seen = set()
        client_names = []
        eng_names = []
        for src in sources:
            cs = src.meta.get("client_short", "")
            if cs and cs.lower() not in _cs_seen:
                _cs_seen.add(cs.lower())
                client_shorts.append(cs)
            cn = src.meta.get("client_name", "")
            if cn and cn not in client_names:
                client_names.append(cn)
            en = src.meta.get("name", "")
            if en and en not in eng_names:
                eng_names.append(en)

        if self.output_name:
            eng_name = self.output_name
        elif eng_names:
            eng_name = f"Merged: {', '.join(eng_names[:3])}"
            if len(eng_names) > 3:
                eng_name += f" (+{len(eng_names) - 3} more)"
        else:
            eng_name = f"Merged Engagement {ts}"

        client_short = "merged"
        if client_shorts:
            if len(client_shorts) == 1:
                client_short = client_shorts[0]
            else:
                client_short = "merged_" + "_".join(client_shorts[:3])

        client_short = re.sub(r"[^\w\-]", "_", client_short).strip("._")

        engagement_id = f"{client_short}_{ts}"
        eng_dir = self.clients_base / client_short / year / engagement_id
        eng_dir.mkdir(parents=True, exist_ok=True)

        pid = str(uuid.uuid4())
        meta = {
            "id": pid,
            "name": eng_name,
            "client_name": ", ".join(client_names) if client_names else "",
            "client_short": client_short,
            "year": year,
            "created": now.isoformat(),
            "scope": "multi",
            "active_scopes": [],
            "tools": [],
            "tool_dirs": {},
            "scope_tools": {},
            "scope_tool_dirs": {},
            "scope_definition": {},
            "engagement_id": engagement_id,
            "engagement_dir": str(eng_dir),
            "layout_version": "2.0",
            "project_dir": str(eng_dir),
            "merged": True,
            "merged_at": now.isoformat(),
            "source_count": len(sources),
        }

        with open(eng_dir / "crucible_meta.json", "w") as f:
            json.dump(meta, f, indent=2)

        self._log(f"Created engagement: {eng_dir}")
        return eng_dir

    def _update_engagement_meta(self, eng_dir, all_scopes, imported_targets=None):
        meta_path = eng_dir / "crucible_meta.json"
        meta = json.loads(meta_path.read_text())

        active_scopes = sorted(all_scopes.keys())
        meta["active_scopes"] = active_scopes
        meta["scope"] = active_scopes[0] if len(active_scopes) == 1 else "multi"

        all_tools = set()
        scope_tools = {}
        scope_tool_dirs = {}
        tool_dirs = {}

        for scope_key, tool_ids in all_scopes.items():
            scope_tools[scope_key] = sorted(tool_ids)
            scope_tool_dirs[scope_key] = {}
            for tid in tool_ids:
                td_name = TOOL_OUTPUT_DIRS.get(tid, tid)
                td_path = str(eng_dir / scope_key / td_name)
                scope_tool_dirs[scope_key][tid] = td_path
                if tid not in tool_dirs:
                    tool_dirs[tid] = td_path
                all_tools.add(tid)

        meta["tools"] = sorted(all_tools)
        meta["scope_tools"] = scope_tools
        meta["scope_tool_dirs"] = scope_tool_dirs
        meta["tool_dirs"] = tool_dirs

        if imported_targets:
            scope_def = {}
            for scope_key, targets in imported_targets.items():
                scope_def[scope_key] = {
                    "targets": targets,
                    "cidrs": [t for t in targets if "/" in t],
                    "ips": [t for t in targets if "/" not in t],
                }
            meta["scope_definition"] = scope_def

        with open(meta_path, "w") as f:
            json.dump(meta, f, indent=2)

    def _write_scope_meta(self, scope_dir, scope_key, targets=None):
        meta = {
            "schema_version": "2.0",
            "scope_key": scope_key,
            "scope_display": scope_key.replace("_", " ").title(),
            "targets": targets or [],
            "tools": {},
        }
        with open(scope_dir / "scope_meta.json", "w") as f:
            json.dump(meta, f, indent=2)

    # ── Tool output merging ─────────────────────────────────────

    def _merge_tool_output(self, src_dirs, dst_dir, tool_id, eng_dir):
        self._log(f"  Merging {tool_id} ({len(src_dirs)} source(s))...")

        for src, src_dir in src_dirs:
            self._copy_evidence(src_dir, dst_dir, src)

        all_findings = []
        for src, src_dir in src_dirs:
            findings = self._load_findings(src_dir)
            for f in findings:
                self._remap_output_path(f, src_dir, dst_dir)
                if not f.get("_provenance"):
                    f["_provenance"] = src.label
            all_findings.extend(findings)

        if all_findings:
            deduped = self._deduplicate(all_findings)
            with open(dst_dir / "findings.json", "w") as f:
                json.dump(deduped, f, indent=2)
            self._log(f"    {len(all_findings)} findings → {len(deduped)} after dedup")

        self._merge_intel(src_dirs, dst_dir)

    _EVIDENCE_SKIP_NAMES = {
        "findings.json", "findings_crucible.json", "findings_vantage.json", "findings_report.json",  # vantage: legacy compat
        "falsePositives.json", "falsePositives.csv",
        "false_positives.json", "false_positives.csv",
        "project_meta.json", "crucible_meta.json", "scope_meta.json",
    }

    def _copy_evidence(self, src_dir, dst_dir, source):
        skip = set(self._EVIDENCE_SKIP_NAMES)
        skip.update(_INTEL_FILES)

        for item in sorted(src_dir.iterdir()):
            dst = dst_dir / item.name
            if item.is_file():
                if item.name in skip:
                    continue
                if item.name == "meta.json":
                    continue
                if not dst.exists():
                    shutil.copy2(item, dst)
                elif item.name.endswith((".log", ".txt")):
                    stem = item.stem
                    suffix = item.suffix
                    tag = re.sub(r"[^\w]", "_", source.label)[:30]
                    dst = dst_dir / f"{stem}_{tag}{suffix}"
                    shutil.copy2(item, dst)
            elif item.is_dir() and item.name != "__pycache__":
                if dst.exists():
                    for sub in item.rglob("*"):
                        if sub.is_file():
                            if sub.name in skip:
                                continue
                            rel = sub.relative_to(item)
                            sub_dst = dst / rel
                            sub_dst.parent.mkdir(parents=True, exist_ok=True)
                            if not sub_dst.exists():
                                shutil.copy2(sub, sub_dst)
                else:
                    shutil.copytree(
                        item, dst, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns(*self._EVIDENCE_SKIP_NAMES),
                    )

    def _load_findings(self, tool_dir):
        for fn in _FINDINGS_FILENAMES:
            fp = tool_dir / fn
            if fp.exists():
                try:
                    data = json.loads(fp.read_text())
                    if isinstance(data, list):
                        return data
                    if isinstance(data, dict) and "findings" in data:
                        return data["findings"]
                except (json.JSONDecodeError, OSError):
                    pass

        all_f = []
        for sub in sorted(tool_dir.iterdir()):
            if sub.is_dir():
                for fn in _FINDINGS_FILENAMES:
                    fp = sub / fn
                    if fp.exists():
                        try:
                            data = json.loads(fp.read_text())
                            items = data if isinstance(data, list) else data.get("findings", [])
                            for f in items:
                                of = f.get("output_file") or ""
                                if of and not of.startswith("/"):
                                    lines = of.split("\n")
                                    prefixed = []
                                    for line in lines:
                                        line = line.strip()
                                        if line and not line.startswith("/"):
                                            line = f"{sub.name}/{line}"
                                        prefixed.append(line)
                                    f["output_file"] = "\n".join(prefixed)
                            all_f.extend(items)
                        except (json.JSONDecodeError, OSError):
                            pass
                        break
        return all_f

    def _remap_output_path(self, finding, old_base, new_base):
        of = finding.get("output_file") or ""
        if not of:
            return
        old_str = str(old_base)
        new_str = str(new_base)
        lines = of.split("\n")
        remapped = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith(old_str):
                line = new_str + line[len(old_str):]
            elif not line.startswith("/"):
                pass
            remapped.append(line)
        finding["output_file"] = "\n".join(remapped)

    # ── Intelligence merging ────────────────────────────────────

    def _merge_intel(self, src_dirs, dst_dir):
        for fname in _INTEL_FILES:
            src_data = []
            for _src, sd in src_dirs:
                candidates = [sd / fname]
                if "/" not in fname:
                    candidates.append(sd / "reports" / fname)
                    candidates.append(sd / "inventory" / fname)
                    for sub in ("int", "ext", "internal", "external"):
                        sub_dir = sd / sub
                        if sub_dir.is_dir():
                            candidates.append(sub_dir / fname)
                            candidates.append(sub_dir / "reports" / fname)
                            candidates.append(sub_dir / "inventory" / fname)
                for fp in candidates:
                    if fp.exists():
                        try:
                            data = json.loads(fp.read_text())
                            src_data.append(data)
                        except (json.JSONDecodeError, OSError):
                            pass
                        break

            if not src_data:
                continue

            merged = self._merge_json_data(src_data)
            if merged is not None:
                dst_path = dst_dir / fname
                dst_path.parent.mkdir(parents=True, exist_ok=True)
                with open(dst_path, "w") as f:
                    json.dump(merged, f, indent=2)

    def _merge_json_data(self, data_list):
        if not data_list:
            return None
        if len(data_list) == 1:
            return data_list[0]

        if all(isinstance(d, list) for d in data_list):
            merged = []
            seen = set()
            for arr in data_list:
                for item in arr:
                    key = json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item)
                    if key not in seen:
                        seen.add(key)
                        merged.append(item)
            return merged

        if all(isinstance(d, dict) for d in data_list):
            merged = {}
            for d in data_list:
                for k, v in d.items():
                    if k not in merged:
                        merged[k] = v
                    elif isinstance(merged[k], list) and isinstance(v, list):
                        existing = {json.dumps(x, sort_keys=True) if isinstance(x, dict) else str(x) for x in merged[k]}
                        for item in v:
                            key = json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item)
                            if key not in existing:
                                existing.add(key)
                                merged[k].append(item)
                    elif isinstance(merged[k], dict) and isinstance(v, dict):
                        merged[k] = self._merge_json_data([merged[k], v])
            return merged

        return data_list[0]

    # ── Finding dedup (self-contained, mirrors models/findings.py) ──

    _TITLE_NORM = [
        (re.compile(r'TLS\s*v?\s*1[\s_.]?0', re.I), 'TLSv1.0'),
        (re.compile(r'TLS\s*v?\s*1[\s_.]?1', re.I), 'TLSv1.1'),
        (re.compile(r'TLS\s*v?\s*1[\s_.]?2', re.I), 'TLSv1.2'),
        (re.compile(r'TLS\s*v?\s*1[\s_.]?3', re.I), 'TLSv1.3'),
        (re.compile(r'SSLv?[\s_]?2(?:\.0)?', re.I), 'SSLv2'),
        (re.compile(r'SSLv?[\s_]?3(?:\.0)?', re.I), 'SSLv3'),
        (re.compile(r'\((\d+)\s*bits?\)', re.I), r'(\1 bit)'),
        (re.compile(r'^/[^:]*:\s+'), ''),
    ]

    _GLOBAL_MERGE_PREFIXES = (
        "missing security header:", "interesting endpoint discovered",
        "authenticated interesting endpoint", "api endpoint identified",
        "non-login form detected", "login page identified",
        "missing secure cookie attribute:", "misconfigured secure cookie attribute:",
        "web files downloaded", "web screenshot captured",
        "session cookie missing", "directory listing enabled",
        "http trace method enabled", "http methods",
        "sensitive paths disclosed in robots.txt", "verbose error messages",
        "cors misconfiguration", "admin panel exposed",
        "ssl/tls certificate:", "ssl/tls ciphers:", "ssl/tls vulnerability:",
        "technology identified:", "open ports identified",
        "software version detected:", "software version identified",
        "subdomain identified", "email address identified",
        "discovery: subdomain", "discovery: ip address",
        "discovery: email address", "discovery: hostname",
        "discovery: open ports", "discovery: web page",
        "discovery: login page", "discovery: unconfirmed udp ports",
        "discovery: apache tomcat",
        "dns: ",
    )

    def _norm_title(self, title):
        t = (title or "").strip()
        for pat, repl in self._TITLE_NORM:
            t = pat.sub(repl, t)
        return t.lower()

    def _is_global(self, ntitle):
        return any(ntitle.startswith(p) for p in self._GLOBAL_MERGE_PREFIXES)

    def _dedup_key(self, f):
        nt = self._norm_title(f.get("title") or f.get("detail") or "")
        gl = self._is_global(nt)
        tool = (f.get("tool") or "").split(":")[0]
        return (
            nt, tool,
            "" if gl else (f.get("ip") or "").strip(),
            "0" if gl else str(f.get("port") or "0"),
            (f.get("scope") or f.get("_scope") or "").lower(),
            "" if gl else (f.get("hostname") or "").strip().lower(),
        )

    def _deduplicate(self, findings):
        seen = {}
        result = []
        for f in findings:
            key = self._dedup_key(f)
            if key in seen:
                self._merge_finding(seen[key], f)
            else:
                seen[key] = f
                result.append(f)
        return sorted(result, key=lambda f: _RISK_ORDER.get(
            (f.get("risk") or "INFO").upper(), 4))

    def _merge_finding(self, target, source):
        for field in ("affected", "sources", "cves"):
            sv = source.get(field) or ""
            tv = target.get(field) or ""
            if isinstance(sv, list):
                sv = "\n".join(sv)
            if isinstance(tv, list):
                tv = "\n".join(tv)
            t_set = set(tv.split("\n")) if tv else set()
            s_set = set(sv.split("\n")) if sv else set()
            merged = sorted((t_set | s_set) - {""})
            if merged:
                target[field] = "\n".join(merged)

        for field in ("output", "command"):
            sv = source.get(field) or ""
            tv = target.get(field) or ""
            if sv and sv not in tv:
                target[field] = f"{tv}\n{sv}".strip()

        s_of = source.get("output_file") or ""
        t_of = target.get("output_file") or ""
        if s_of and s_of != t_of:
            if t_of:
                existing = set(t_of.split("\n"))
                new_paths = [p for p in s_of.split("\n") if p and p not in existing]
                if new_paths:
                    target["output_file"] = t_of + "\n" + "\n".join(new_paths)
            else:
                target["output_file"] = s_of

        for field in ("exploitdb", "metasploit", "kev"):
            if source.get(field):
                target[field] = True

        sr = _RISK_ORDER.get((source.get("risk") or "INFO").upper(), 4)
        tr = _RISK_ORDER.get((target.get("risk") or "INFO").upper(), 4)
        if sr < tr:
            target["risk"] = source["risk"]

        prov_t = target.get("_provenance") or ""
        prov_s = source.get("_provenance") or ""
        if prov_s and prov_s not in prov_t:
            target["_provenance"] = f"{prov_t}, {prov_s}".strip(", ")

    # ── Nessus merging ──────────────────────────────────────────

    def _merge_nessus(self, nessus_sources, dst_dir):
        self._log(f"  Merging {len(nessus_sources)} Nessus source(s)...")

        originals_dir = dst_dir / "originals"
        originals_dir.mkdir(exist_ok=True)
        for src in nessus_sources:
            shutil.copy2(src.path, originals_dir / src.path.name)

        all_findings = []
        for src in nessus_sources:
            ref = f"originals/{src.path.name}"
            if src.type == "nessus_xml":
                parsed = self._parse_nessus_xml(src.path)
                for f in parsed:
                    f["output_file"] = ref
                all_findings.extend(parsed)
            elif src.type == "nessus_csv":
                parsed = self._parse_nessus_csv(src.path)
                for f in parsed:
                    f["output_file"] = ref
                all_findings.extend(parsed)

        deduped = self._dedup_nessus(all_findings)
        self._log(f"    {len(all_findings)} Nessus findings → {len(deduped)} after dedup")

        with open(dst_dir / "findings.json", "w") as f:
            json.dump(deduped, f, indent=2)

        self._write_nessus_csv(deduped, dst_dir / "findings.csv")

    def _parse_nessus_xml(self, nessus_path):
        findings = []
        try:
            tree = ET.parse(str(nessus_path))
            root = tree.getroot()
        except ET.ParseError:
            self._log(f"    WARN: Could not parse {nessus_path.name}")
            return findings

        for report in root.iter("Report"):
            for host_elem in report.iter("ReportHost"):
                host_name = host_elem.get("name", "")
                props = {}
                hp = host_elem.find("HostProperties")
                if hp is not None:
                    for tag in hp.iter("tag"):
                        props[tag.get("name", "")] = (tag.text or "").strip()

                host_ip = props.get("host-ip", host_name)
                host_fqdn = props.get("host-fqdn", "")

                for item in host_elem.iter("ReportItem"):
                    plugin_id = item.get("pluginID", "0")
                    if plugin_id == "0":
                        continue
                    pid_int = int(plugin_id)
                    if pid_int in _NESSUS_SCANNER_PLUGINS:
                        continue

                    severity = item.get("severity", "0")
                    if severity == "0":
                        continue
                    risk = _NESSUS_RISK_MAP.get(severity, "INFO")
                    port = int(item.get("port", "0"))
                    protocol = item.get("protocol", "tcp")
                    svc_name = item.get("svc_name", "")
                    plugin_name = item.get("pluginName", "")

                    title = _NESSUS_TITLE_MAP_LOWER.get(
                        plugin_name.strip().lower(), plugin_name)

                    desc = self._xml_text(item, "description")
                    synopsis = self._xml_text(item, "synopsis")
                    solution = self._xml_text(item, "solution")
                    output = self._xml_text(item, "plugin_output")
                    cvss = self._xml_text(item, "cvss3_base_score") or self._xml_text(item, "cvss_base_score")
                    cvss_vec = self._xml_text(item, "cvss3_vector") or self._xml_text(item, "cvss_vector")

                    cves = []
                    for cve_elem in item.iter("cve"):
                        if cve_elem.text:
                            cves.append(cve_elem.text.strip())

                    has_exploit = (self._xml_text(item, "exploit_available") or "").lower() == "true"
                    has_msf = (self._xml_text(item, "exploit_framework_metasploit") or "").lower() == "true"
                    msf_name = self._xml_text(item, "metasploit_name")
                    ease = self._xml_text(item, "exploitability_ease")

                    has_edb = False
                    exploit_details = []
                    see_also = []
                    for xr in item.iter("xref"):
                        if xr.text and xr.text.startswith("EDB-ID:"):
                            has_edb = True
                            exploit_details.append({"type": "exploitdb", "id": xr.text})
                    for sa in item.iter("see_also"):
                        if sa.text:
                            for url in sa.text.strip().splitlines():
                                url = url.strip()
                                if url:
                                    see_also.append(url)
                                    if "github.com" in url.lower():
                                        exploit_details.append({"type": "github", "url": url})
                    if has_msf and msf_name:
                        exploit_details.insert(0, {"type": "metasploit", "name": msf_name})

                    svc_label = f"{svc_name}/{protocol}" if svc_name else protocol

                    finding = {
                        "id": str(uuid.uuid4()),
                        "title": title,
                        "tool": "nessus",
                        "datetime": datetime.now().isoformat(),
                        "ip": host_ip,
                        "port": port,
                        "hostname": host_fqdn,
                        "risk": risk,
                        "description": desc or synopsis or "",
                        "output": (output or "")[:4096],
                        "command": f"Nessus Plugin {plugin_id}",
                        "cves": ", ".join(cves),
                        "sources": "Nessus",
                        "nessus_source_file": nessus_path.name,
                        "affected": f"{host_ip}:{port}" if port else host_ip,
                        "remediation": solution or "",
                        "service": svc_label,
                        "exploitdb": has_edb or has_exploit,
                        "metasploit": has_msf,
                        "exploit_details": exploit_details,
                        "output_file": "",
                        "nessus_plugin_id": pid_int,
                        "nessus_plugin_name": plugin_name,
                        "protocol": protocol,
                        "exploitability_ease": ease,
                    }
                    if cvss:
                        try:
                            finding["cvss_score"] = float(cvss)
                        except ValueError:
                            pass
                    if cvss_vec:
                        finding["cvss_vector"] = cvss_vec
                    if see_also:
                        finding["see_also"] = see_also

                    findings.append(finding)

        return findings

    def _xml_text(self, elem, tag):
        child = elem.find(tag)
        if child is not None and child.text:
            return child.text.strip()
        return ""

    def _parse_nessus_csv(self, csv_path):
        findings = []
        try:
            with open(csv_path, "r", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    plugin_id = row.get("Plugin ID", row.get("Plugin", "0"))
                    if not plugin_id or plugin_id == "0":
                        continue
                    try:
                        pid_int = int(plugin_id)
                        if pid_int in _NESSUS_SCANNER_PLUGINS:
                            continue
                    except ValueError:
                        pid_int = 0

                    risk_val = row.get("Risk", row.get("Severity", "None"))
                    if risk_val.lower() in ("none", "info", "informational"):
                        continue
                    risk = _NESSUS_RISK_MAP.get(risk_val.lower(), "INFO")
                    host = row.get("Host", row.get("IP Address", ""))
                    port = int(row.get("Port", "0") or "0")
                    protocol = row.get("Protocol", "tcp")
                    name = row.get("Name", row.get("Plugin Name", ""))
                    title = _NESSUS_TITLE_MAP_LOWER.get(
                        name.strip().lower(), name)
                    desc = row.get("Description", "")
                    synopsis = row.get("Synopsis", "")
                    solution = row.get("Solution", "")
                    output = row.get("Plugin Output", "")
                    cve = row.get("CVE", "")

                    cvss_str = row.get("CVSS v3.0 Base Score",
                                       row.get("CVSS v2.0 Base Score",
                                               row.get("CVSS", "")))

                    finding = {
                        "id": str(uuid.uuid4()),
                        "title": title,
                        "tool": "nessus",
                        "datetime": datetime.now().isoformat(),
                        "ip": host,
                        "port": port,
                        "hostname": "",
                        "risk": risk,
                        "description": desc or synopsis or "",
                        "output": (output or "")[:4096],
                        "command": f"Nessus Plugin {plugin_id}",
                        "cves": cve,
                        "sources": "Nessus",
                        "nessus_source_file": csv_path.name,
                        "affected": f"{host}:{port}" if port else host,
                        "remediation": solution or "",
                        "service": "",
                        "exploitdb": False,
                        "metasploit": False,
                        "exploit_details": [],
                        "output_file": "",
                        "nessus_plugin_id": pid_int,
                        "nessus_plugin_name": name,
                        "protocol": protocol,
                    }
                    if cvss_str:
                        try:
                            finding["cvss_score"] = float(cvss_str)
                        except ValueError:
                            pass

                    findings.append(finding)
        except (OSError, csv.Error) as exc:
            self._log(f"    WARN: CSV parse error {csv_path.name}: {exc}")

        return findings

    def _dedup_nessus(self, findings):
        seen = {}
        result = []
        for f in findings:
            pid = f.get("nessus_plugin_id", 0)
            ip = (f.get("ip") or "").strip()
            port = str(f.get("port") or "0")
            proto = (f.get("protocol") or "tcp").lower()
            key = (pid, ip, port, proto)

            if key in seen:
                existing = seen[key]
                s_out = f.get("output") or ""
                e_out = existing.get("output") or ""
                if s_out and s_out not in e_out:
                    existing["output"] = f"{e_out}\n{s_out}".strip()
                s_src = f.get("sources") or ""
                e_src = existing.get("sources") or ""
                if s_src and s_src not in e_src:
                    existing["sources"] = f"{e_src}\n{s_src}".strip()
                s_nsf = f.get("nessus_source_file") or ""
                e_nsf = existing.get("nessus_source_file") or ""
                if s_nsf and s_nsf not in e_nsf:
                    existing["nessus_source_file"] = f"{e_nsf}, {s_nsf}".strip(", ")
                s_of = f.get("output_file") or ""
                e_of = existing.get("output_file") or ""
                if s_of and s_of not in e_of:
                    existing["output_file"] = f"{e_of}\n{s_of}".strip()
            else:
                seen[key] = f
                result.append(f)

        return sorted(result, key=lambda f: _RISK_ORDER.get(
            (f.get("risk") or "INFO").upper(), 4))

    def _write_nessus_csv(self, findings, csv_path):
        if not findings:
            return
        fields = [
            "nessus_plugin_id", "title", "risk", "cvss_score", "ip", "port",
            "protocol", "hostname", "cves", "description", "remediation",
            "output", "sources",
        ]
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for finding in findings:
                writer.writerow(finding)

    # ── Action items ───────────────────────────────────────────

    def _update_nessus_action_items(self, eng_dir):
        """Mark Nessus action items as complete since scans were imported."""
        try:
            from models.action_items import load_action_items, save_action_items
            items = load_action_items(str(eng_dir))
            changed = 0
            now = datetime.now().isoformat()
            for item in items:
                rt = (item.get("recommended_tool") or "").lower()
                if rt == "nessus" and item.get("status") == "pending":
                    item["status"] = "complete"
                    item["completed_at"] = now
                    item["updated"] = now
                    changed += 1
            if changed:
                save_action_items(str(eng_dir), items)
                self._log(f"  Marked {changed} Nessus action item(s) complete")
        except Exception as exc:
            self._log(f"  WARN: Could not update action items: {exc}")

    # ── Nessus software inventory ──────────────────────────────

    _NESSUS_SW_TITLE_MAP = {
        r"OpenSSH":                "OpenSSH",
        r"Apache Log4j":           "Apache Log4j",
        r"Apache HTTP":            "Apache HTTP Server",
        r"Microsoft IIS":          "Microsoft IIS",
        r"Microsoft SQL Server":   "Microsoft SQL Server",
        r"jQuery":                 "jQuery",
        r"PHP":                    "PHP",
        r"nginx":                  "nginx",
        r"Tomcat":                 "Apache Tomcat",
        r"RDP":                    "Remote Desktop Protocol",
        r"SMB":                    "SMB",
        r"SSL":                    "SSL/TLS",
        r"TLS":                    "SSL/TLS",
        r"Active Management":      "Intel AMT",
    }

    @staticmethod
    def _extract_sw_from_output(output, title):
        """Extract (software, version) from Nessus plugin_output field.
        Looks for 'Installed version : X.Y' and 'Version source : ...' patterns."""
        results = []
        if not output:
            return results
        ver_m = re.findall(
            r"Installed\s+version\s*:\s*(\S+)", output, re.IGNORECASE
        )
        prod_m = re.findall(
            r"Installed\s+product\s*:\s*(.+?)(?:\n|$)", output, re.IGNORECASE
        )
        src_m = re.search(
            r"Version\s+source\s*:\s*(\S+.*?)(?:\n|$)", output, re.IGNORECASE
        )
        if ver_m:
            sw_name = ""
            if prod_m:
                sw_name = prod_m[0].strip()
            if not sw_name and src_m:
                src_str = src_m.group(1).strip()
                sm = re.match(r"SSH-[\d.]+-(\S+)", src_str)
                if sm:
                    sw_name = sm.group(1).split("_")[0]
            if not sw_name:
                for frag, name in EngagementMerger._NESSUS_SW_TITLE_MAP.items():
                    if frag.lower() in title.lower():
                        sw_name = name
                        break
            if not sw_name:
                sw_name = title.split("<")[0].split("(")[0].strip()[:60]
            for v in ver_m:
                results.append((sw_name, v.strip()))
        elif src_m:
            src_str = src_m.group(1).strip()
            sm = re.match(r"SSH-[\d.]+-(\S+?)_(\d[\d.p]*)", src_str)
            if sm:
                results.append((sm.group(1), sm.group(2)))
        return results

    def _build_nessus_software_inventory(self, eng_dir, all_scopes):
        """Extract software versions from Nessus plugin_output into software_inventory.json."""
        for scope_key, tool_ids in all_scopes.items():
            if "nessus" not in tool_ids:
                continue
            nessus_dir = eng_dir / scope_key / TOOL_OUTPUT_DIRS.get("nessus", "nessus")
            fp = nessus_dir / "findings.json"
            if not fp.exists():
                continue
            try:
                data = json.loads(fp.read_text())
                findings = data if isinstance(data, list) else data.get("findings", [])
            except (json.JSONDecodeError, OSError):
                continue

            inv_map = {}
            for f in findings:
                output = f.get("output") or f.get("plugin_output") or ""
                title = f.get("title") or ""
                ip = f.get("ip") or ""
                port = f.get("port", 0)
                hostname = f.get("hostname") or ""
                plugin_id = str(f.get("nessus_plugin_id") or "")
                pairs = self._extract_sw_from_output(output, title)
                for sw_name, version in pairs:
                    key = (sw_name.lower(), ip, port)
                    if key in inv_map:
                        existing = inv_map[key]
                        if plugin_id and plugin_id not in existing["method"]:
                            existing["method"] += f"\n{plugin_id}"
                    else:
                        inv_map[key] = {
                            "software": sw_name,
                            "version": version,
                            "os": None,
                            "ip": ip,
                            "port": port,
                            "hostname": hostname,
                            "method": f"Nessus Plugin {plugin_id}" if plugin_id else "Nessus",
                            "datetime": f.get("datetime", ""),
                        }

            inventory = list(inv_map.values())
            if inventory:
                inv_path = nessus_dir / "software_inventory.json"
                with open(inv_path, "w") as fh:
                    json.dump(inventory, fh, indent=2)
                ss3_dir = eng_dir / scope_key / TOOL_OUTPUT_DIRS.get("ss3", "scattershot")
                if ss3_dir.is_dir():
                    ss3_inv = ss3_dir / "software_inventory.json"
                    existing = []
                    if ss3_inv.exists():
                        try:
                            existing = json.loads(ss3_inv.read_text())
                        except (json.JSONDecodeError, OSError):
                            pass
                    existing_keys = {(e.get("software", "").lower(),
                                     e.get("ip"), e.get("port"))
                                    for e in existing}
                    added = 0
                    for entry in inventory:
                        k = (entry["software"].lower(), entry["ip"], entry["port"])
                        if k not in existing_keys:
                            existing.append(entry)
                            existing_keys.add(k)
                            added += 1
                    if added:
                        with open(ss3_inv, "w") as fh:
                            json.dump(existing, fh, indent=2)
                self._log(f"  Nessus software inventory: {len(inventory)} entries")

    # ── Target synthesis ──────────────────────────────────────

    def _build_targets_json(self, eng_dir, all_scopes):
        """Synthesize targets.json from merged findings so the overview cards
        show Live IPs / Open Ports / Services."""
        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        for scope_key, tool_ids in all_scopes.items():
            hosts = {}
            for tool_id in tool_ids:
                tool_dirname = TOOL_OUTPUT_DIRS.get(tool_id, tool_id)
                fp = eng_dir / scope_key / tool_dirname / "findings.json"
                if not fp.exists():
                    continue
                try:
                    data = json.loads(fp.read_text())
                    findings = data if isinstance(data, list) else data.get("findings", [])
                except (json.JSONDecodeError, OSError):
                    continue
                for f in findings:
                    ip = (f.get("ip") or "").strip()
                    if not ip:
                        continue
                    if ip not in hosts:
                        hosts[ip] = {
                            "ip": ip,
                            "hostname": "",
                            "os": "",
                            "ports": [],
                            "scope": scope_key,
                            "status": "up",
                            "risk": "INFO",
                            "tools": [],
                            "_port_set": set(),
                            "_tool_set": set(),
                            "_risk_rank": 4,
                        }
                    h = hosts[ip]
                    hn = (f.get("hostname") or "").strip()
                    if hn and not h["hostname"]:
                        h["hostname"] = hn
                    fr = (f.get("risk") or "INFO").upper()
                    fr_rank = risk_order.get(fr, 4)
                    if fr_rank < h["_risk_rank"]:
                        h["_risk_rank"] = fr_rank
                        h["risk"] = fr
                    t = f.get("tool") or tool_id
                    if t not in h["_tool_set"]:
                        h["_tool_set"].add(t)
                        h["tools"].append(t)
                    port = f.get("port", 0)
                    if isinstance(port, str):
                        try:
                            port = int(port)
                        except ValueError:
                            port = 0
                    if port and port not in h["_port_set"]:
                        h["_port_set"].add(port)
                        svc = (f.get("service") or "").strip()
                        if svc:
                            svc = svc.split("/")[0].strip()
                        if not svc or svc in ("", "?"):
                            svc = _WELL_KNOWN_PORTS.get(port, "")
                        proto = (f.get("protocol") or "tcp").strip()
                        h["ports"].append({
                            "port": port,
                            "service": svc,
                            "protocol": proto,
                            "state": "open",
                        })
                    elif port and port in h["_port_set"]:
                        svc = (f.get("service") or "").strip()
                        if svc:
                            svc = svc.split("/")[0].strip()
                            for p in h["ports"]:
                                if p["port"] == port and not p["service"]:
                                    p["service"] = svc
                                    break

            if not hosts:
                continue

            for h in hosts.values():
                del h["_port_set"]
                del h["_tool_set"]
                del h["_risk_rank"]
                for p in h["ports"]:
                    if not p["service"]:
                        p["service"] = _WELL_KNOWN_PORTS.get(p["port"], "")

            target_list = sorted(hosts.values(), key=lambda h: h["ip"])

            ss3_dir = eng_dir / scope_key / TOOL_OUTPUT_DIRS.get("ss3", "scattershot")
            if ss3_dir.is_dir():
                for subdir_name in ("int", "ext", "internal", "external"):
                    sd = ss3_dir / subdir_name
                    if sd.is_dir():
                        with open(sd / "targets.json", "w") as fh:
                            json.dump(target_list, fh, indent=2)
                        self._log(f"  Built targets.json: {len(target_list)} hosts "
                                  f"in {scope_key}/{subdir_name}")
                        break
                else:
                    with open(ss3_dir / "targets.json", "w") as fh:
                        json.dump(target_list, fh, indent=2)
                    self._log(f"  Built targets.json: {len(target_list)} hosts "
                              f"in {scope_key}/scattershot")
            else:
                nessus_dir = eng_dir / scope_key / TOOL_OUTPUT_DIRS.get("nessus", "nessus")
                if nessus_dir.is_dir():
                    with open(nessus_dir / "targets.json", "w") as fh:
                        json.dump(target_list, fh, indent=2)
                    self._log(f"  Built targets.json: {len(target_list)} hosts "
                              f"in {scope_key}/nessus")

    # ── Provenance ──────────────────────────────────────────────

    def _write_provenance(self, eng_dir, sources):
        provenance = {
            "merged_at": datetime.now().isoformat(),
            "merger_version": "1.0.0",
            "sources": [],
        }
        for src in sources:
            entry = {
                "type": src.type,
                "path": str(src.path),
                "label": src.label,
                "scopes": {k: list(v.keys()) for k, v in src.scopes.items()},
            }
            if src.meta:
                entry["meta"] = {
                    "name": src.meta.get("name", ""),
                    "client_short": src.meta.get("client_short", ""),
                    "client_name": src.meta.get("client_name", ""),
                    "id": src.meta.get("id", ""),
                    "created": src.meta.get("created", ""),
                }
            provenance["sources"].append(entry)

        with open(eng_dir / "merger_provenance.json", "w") as f:
            json.dump(provenance, f, indent=2)

    # ── Cleanup ─────────────────────────────────────────────────

    def cleanup(self):
        for td in self._temp_dirs:
            shutil.rmtree(td, ignore_errors=True)
        self._temp_dirs.clear()


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Crucible v2 Engagement Merger")
    parser.add_argument("folder", help="Folder to scan for sources")
    parser.add_argument("-n", "--name", help="Name for merged engagement")
    parser.add_argument("-b", "--base", help="Clients base directory")
    args = parser.parse_args()

    def log(msg):
        print(msg)

    merger = EngagementMerger(args.folder, output_name=args.name,
                              clients_base=args.base, callback=log)
    sources = merger.scan()
    if not sources:
        print("No mergeable sources found.")
        sys.exit(1)

    print(f"\nSources to merge:")
    for i, src in enumerate(sources, 1):
        print(f"  {i}. [{src.type}] {src.path.name}")

    eng_dir = merger.merge(sources)
    if eng_dir:
        print(f"\nMerged engagement at: {eng_dir}")
    else:
        print("\nMerge failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
