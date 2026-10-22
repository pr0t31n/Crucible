"""Findings model -- loading, dedup, merge, FP management."""

import re
import json
import csv
import hashlib
import threading
from pathlib import Path
from datetime import datetime

from config import TOOL_OUTPUT_DIRS

_findings_lock = threading.Lock()


# ── Loading ──────────────────────────────────────────────────

def load_findings_from_tool(tool_output_dir, tool_id):
    """Load findings from a single tool's output directory.
    Delegates to the tool's adapter.load_findings()."""
    from adapters import get_adapter
    adapter = get_adapter(tool_id)
    if not adapter:
        return []
    td = Path(tool_output_dir) if tool_output_dir else None
    if not td or not td.exists():
        return []
    return adapter.load_findings(str(td.parent), str(td))


_FINDINGS_FILENAMES = (
    "findings.json", "findings_vantage.json", "findings_report.json",
)


def _has_findings_content(dirpath):
    """Check whether *dirpath* contains findings (root or one subdir level)."""
    p = Path(dirpath)
    for fn in _FINDINGS_FILENAMES:
        if (p / fn).exists():
            return True
    try:
        for sub in p.iterdir():
            if sub.is_dir():
                for fn in _FINDINGS_FILENAMES:
                    if (sub / fn).exists():
                        return True
    except OSError:
        pass
    return False


def _resolve_tool_dir(project, tool_id):
    td = project.get("tool_dirs", {}).get(tool_id)
    if td and Path(td).exists() and _has_findings_content(td):
        return td
    eng_dir = project.get("engagement_dir", project.get("project_dir", ""))
    if not eng_dir:
        return td
    derived = str(Path(eng_dir) / TOOL_OUTPUT_DIRS.get(tool_id, tool_id))
    if Path(derived).exists() and _has_findings_content(derived):
        return derived
    if td and Path(td).exists():
        return td
    return td


def _build_ip_fqdn_map(project):
    """Build IP→set[FQDN] reverse map from OSift's targets_osint.json."""
    ip_to_fqdns = {}
    osift_dir = _resolve_tool_dir(project, "osift")
    if not osift_dir:
        return ip_to_fqdns
    for candidate in (Path(osift_dir) / "reports" / "targets_osint.json",
                      Path(osift_dir) / "targets_osint.json"):
        if candidate.exists():
            try:
                data = json.loads(candidate.read_text())
                for sub in (data.get("subdomains") or []):
                    host = (sub.get("host") or "").strip()
                    if not host:
                        continue
                    for ip in (sub.get("ips") or []):
                        if ip:
                            ip_to_fqdns.setdefault(ip, set()).add(host)
                    single_ip = (sub.get("ip") or "").strip()
                    if single_ip:
                        ip_to_fqdns.setdefault(single_ip, set()).add(host)
                for ip_rec in (data.get("ips") or []):
                    ip = (ip_rec.get("ip") or "").strip()
                    if not ip:
                        continue
                    for fqdn_rec in (ip_rec.get("fqdns") or []):
                        fqdn = fqdn_rec.get("fqdn") if isinstance(fqdn_rec, dict) else str(fqdn_rec)
                        if fqdn:
                            ip_to_fqdns.setdefault(ip, set()).add(fqdn.strip())
                break
            except (json.JSONDecodeError, OSError):
                pass
    return ip_to_fqdns


def load_all_findings(project):
    """Load and merge findings from all tools in a project.
    Returns deduplicated, sorted list."""
    all_findings = []
    tool_ids = set(project.get("tool_dirs", {}).keys())
    tool_ids.update(project.get("tools", []))
    loaded = set()
    for tool_id in tool_ids:
        for scope_dirs in project.get("scope_tool_dirs", {}).values():
            td = scope_dirs.get(tool_id)
            if td and (tool_id, td) not in loaded and Path(td).exists():
                loaded.add((tool_id, td))
                all_findings.extend(load_findings_from_tool(td, tool_id))
        td = _resolve_tool_dir(project, tool_id)
        if td and (tool_id, td) not in loaded:
            loaded.add((tool_id, td))
            all_findings.extend(load_findings_from_tool(td, tool_id))

    _excl_raw = project.get("scope_definition", {}).get("exclusions", [])
    if _excl_raw:
        import ipaddress as _ipa
        _excl_addrs = set()
        _excl_nets = []
        for _ex in _excl_raw:
            if not _ex:
                continue
            _ex = _ex.strip()
            try:
                _net = _ipa.ip_network(_ex, strict=False)
                if _net.prefixlen == _net.max_prefixlen:
                    _excl_addrs.add(str(_net.network_address))
                else:
                    _excl_nets.append(_net)
            except ValueError:
                _excl_addrs.add(_ex)
        def _ip_excluded(ip_str):
            if not ip_str:
                return False
            if ip_str in _excl_addrs:
                return True
            try:
                _a = _ipa.ip_address(ip_str)
                return any(_a in _n for _n in _excl_nets)
            except ValueError:
                return ip_str in _excl_addrs
        all_findings = [f for f in all_findings
                        if not _ip_excluded(f.get("ip", ""))]

    ip_fqdn_map = _build_ip_fqdn_map(project)
    return deduplicate(all_findings, ip_fqdn_map=ip_fqdn_map)


# ── Title Normalization (from Vantage) ──────────────────────

_TITLE_RENAMES = [
    # Full-title rewrites (must come before generic TLS normalizers)
    (re.compile(r'^TLS Version 1\.1 Deprecated Protocol$', re.IGNORECASE), 'SSL/TLS Vulnerability: TLSv1.1 is Deprecated'),
    (re.compile(r'^TLS Version 1\.0 Deprecated Protocol$', re.IGNORECASE), 'SSL/TLS Vulnerability: TLSv1.0 is Deprecated'),
    (re.compile(r'^Deprecated Protocol Enabled:\s*TLS\s*v?\s*1[\s.]0$', re.IGNORECASE), 'SSL/TLS Vulnerability: TLSv1.0 is Deprecated'),
    (re.compile(r'^Deprecated Protocol Enabled:\s*TLS\s*v?\s*1[\s.]1$', re.IGNORECASE), 'SSL/TLS Vulnerability: TLSv1.1 is Deprecated'),
    (re.compile(r'^Deprecated Protocol Enabled:\s*SSLv2/SSLv3$', re.IGNORECASE), 'SSL/TLS Vulnerability: SSLv2/SSLv3 is Deprecated'),
    (re.compile(r'^SSL/TLS: TLSv1\.3 Not Supported$', re.IGNORECASE), 'SSL/TLS Vulnerability: TLSv1.3 Not Supported'),
    (re.compile(r'^SSL/TLS Certificate Information$', re.IGNORECASE), 'Discovery: SSL/TLS Certificate'),
    (re.compile(r'^Unconfirmed UDP Ports.*', re.IGNORECASE), 'Discovery: UDP Ports [UNCONFIRMED]'),
    (re.compile(r'^Web Page Identified$', re.IGNORECASE), 'Discovery: Web Page Identified'),
    (re.compile(r'^Hostname Identified$', re.IGNORECASE), 'Discovery: Hostname Identified'),
    (re.compile(r'^Open Ports Identified$', re.IGNORECASE), 'Discovery: Open Ports'),
    (re.compile(r'^Default Webpage Detected:.*', re.IGNORECASE), 'Discovery: Default Webpage'),
    (re.compile(r'^Non-Standard Web Port Detected$', re.IGNORECASE), 'Discovery: Non-standard Web Port'),
    (re.compile(r'^Non-Standard Port for (.+)', re.IGNORECASE), r'Discovery: Non-Standard Port for \1'),
    (re.compile(r'^Microsoft SQL Server Unsupported Version Detection.*', re.IGNORECASE), 'EOL Software: Microsoft SQL Server'),
    (re.compile(r'^Unsupported (.+OS.*)$', re.IGNORECASE), r'EOL Operating System: \1'),
    (re.compile(r'^SMB Signing not required$', re.IGNORECASE), 'SMB Vulnerability: SMB Signing Not Required'),
    (re.compile(r'^SMB Signing not enabled$', re.IGNORECASE), 'SMB Vulnerability: SMB Signing Not Enabled'),
    (re.compile(r'^SMB Version 1 \(SMBv1\) Enabled$', re.IGNORECASE), 'SMB Vulnerability: SMBv1 Enabled'),
    (re.compile(r'^SMBv1 Enabled$', re.IGNORECASE), 'SMB Vulnerability: SMBv1 Enabled'),
    (re.compile(r'^Enumeration: O365 Tenant Detected$', re.IGNORECASE), 'Discovery: O365 Tenant Detected'),
    (re.compile(r'^Enumeration: O365 Account Validation$', re.IGNORECASE), 'Enumeration: O365 Account Enumeration'),
    (re.compile(r'^WinRM Service Exposed$', re.IGNORECASE), 'Discovery: WinRM Service'),
    (re.compile(r'^WinRM Over Cleartext HTTP$', re.IGNORECASE), 'Insecure Protocol Detected: WinRM (Cleartext)'),
    # Cross-tool title normalization
    (re.compile(r'^Improper Error Handling\b.*', re.IGNORECASE), 'Information Disclosure: Verbose Server Error Messages'),
    (re.compile(r'^Verbose Error Messages\b.*', re.IGNORECASE), 'Information Disclosure: Verbose Server Error Messages'),
    (re.compile(r'^Server banner changed\b.*', re.IGNORECASE), 'Discovery: Load Balancer Identified'),
    (re.compile(r'^Password Field With Autocomplete Enabled$', re.IGNORECASE), 'Web Misconfiguration: Password Autocomplete Enabled'),
    (re.compile(r'^Web Server HTTP Header Internal IP Disclosure$', re.IGNORECASE), 'Information Disclosure: Internal IP in HTTP Response'),
    (re.compile(r'^Non-Standard Cipher Suites Accepted$', re.IGNORECASE), 'SSL/TLS Ciphers: Non-Standard Cipher Suites'),
    (re.compile(r'^OS Version Detected:\s*SSDP/UPnP$', re.IGNORECASE), 'Software Version Detected: SSDP/UPnP'),
    (re.compile(r'^UPnP/SSDP Service Responding$', re.IGNORECASE), 'Discovery: UPnP/SSDP Service'),
    (re.compile(r'^Software Version Disclosed:\s*(.+)', re.IGNORECASE), r'Software Version Detected: \1'),
    (re.compile(r'^Retrieved access-control-allow-origin header.*', re.IGNORECASE), 'Permissive Security Header: Access-Control-Allow-Origin'),
    (re.compile(r'^CORS Misconfiguration Allowing Credential Leakage$', re.IGNORECASE), 'Permissive Security Header: Cross-Origin Resource Sharing'),
    (re.compile(r'^Missing Security Headers$', re.IGNORECASE), 'Missing Security Header: Strict-Transport-Security'),
    # Nuclei/OSINT title normalization
    (re.compile(r'^ACME DNS Challenge\s*[-—]\s*Detect$', re.IGNORECASE), 'DNS Information: ACME Challenge'),
    (re.compile(r'^DNS SaaS Service Detection$', re.IGNORECASE), 'DNS Information: SaaS Service'),
    (re.compile(r'^SOA Record Service\s*[-—]\s*Detection$', re.IGNORECASE), 'DNS Information: SOA Record Service'),
    (re.compile(r'^Wayback Machine CDX returned \d+.*', re.IGNORECASE), 'Discovery: Historical URLs Identified'),
    (re.compile(r'^Unnecessary/Outdated Website Available$', re.IGNORECASE), 'Discovery: Legacy Web Application'),
    (re.compile(r'^Outdated or Unnecessary Website Detected$', re.IGNORECASE), 'Discovery: Legacy Web Application'),
    (re.compile(r'^SSL/TLS Vulnerability \[UNCONFIRMED\]:\s*LOGJAM$', re.IGNORECASE), 'SSL/TLS Vulnerability (Potential): LOGJAM'),
    (re.compile(r'^SSL Anonymous Cipher Suites Supported$', re.IGNORECASE), 'SSL/TLS Ciphers: Anonymous Cipher Suites'),
    (re.compile(r'^Weak Cipher Identified$', re.IGNORECASE), 'SSL/TLS Ciphers: Weak Cipher'),
    (re.compile(r'^IP Forwarding Enabled$', re.IGNORECASE), 'Network Misconfiguration: IP Forwarding Enabled'),
    (re.compile(r'^ICMP Timestamp (?:Re(?:ply|sponse)|Request Remote Date Disclosure).*', re.IGNORECASE), 'Network Misconfiguration: ICMP Timestamp'),
    (re.compile(r'^TCP Timestamp Re(?:ply|sponse).*', re.IGNORECASE), 'Network Misconfiguration: TCP Timestamp'),
    (re.compile(r'^SSH Terrapin Prefix Truncation Weakness.*', re.IGNORECASE), 'SSH Vulnerability: Terrapin'),
    (re.compile(r'^SSH Server CBC Mode Ciphers Enabled$', re.IGNORECASE), 'SSH Vulnerability: CBC Mode Ciphers Enabled'),
    (re.compile(r'^SSH Weak Key Exchange Algorithms Enabled$', re.IGNORECASE), 'SSH Vulnerability: Weak Key Exchange'),
    (re.compile(r'^SSH Algorithm Hardening Recommendations$', re.IGNORECASE), 'SSH Configuration: Algorithm Hardening'),
    # ── LDAP ──────────────────────────────────────────────────────────────
    (re.compile(r'^LDAP Anonymous Bind Permitted\b.*', re.IGNORECASE), 'LDAP: Anonymous Bind'),
    (re.compile(r'^LDAP NULL BASE Search Access$', re.IGNORECASE), 'LDAP: Anonymous Bind'),
    (re.compile(r'^LDAP Server Detection$', re.IGNORECASE), 'Discovery: LDAP Service'),
    (re.compile(r'^LDAP Service Publicly Resolvable$', re.IGNORECASE), 'Discovery: LDAP Service Publicly Resolvable'),
    (re.compile(r'^Microsoft Windows LDAP Signing Not Required$', re.IGNORECASE), 'LDAP: Signing Not Required'),
    (re.compile(r'^LDAP Server Allows Cleartext Authentication$', re.IGNORECASE), 'LDAP: Cleartext Authentication Permitted'),
    (re.compile(r'^Enumeration: LDAP Anonymous Enumeration\b.*', re.IGNORECASE), 'LDAP: Anonymous Enumeration'),
    (re.compile(r'^Enumeration: LDAP Domain Users$', re.IGNORECASE), 'LDAP: Domain User Enumeration'),
    # ── enum4linux / SMB enumeration ────────────────────────────────────
    (re.compile(r'^Domain\s*/\s*Workgroup Name Identified$', re.IGNORECASE), 'Discovery: Domain / Workgroup Name'),
    (re.compile(r'^Domain SID Identified$', re.IGNORECASE), 'Discovery: Domain SID'),
    (re.compile(r'^Domain/Local Users Enumerated$', re.IGNORECASE), 'Enumeration: Domain/Local Users'),
    (re.compile(r'^Administrators Group Members Identified$', re.IGNORECASE), 'Enumeration: Administrators Group Members'),
    (re.compile(r'^SMB Shares Enumerated$', re.IGNORECASE), 'Enumeration: SMB Shares'),
    (re.compile(r'^RID Cycling Successful$', re.IGNORECASE), 'Enumeration: RID Cycling'),
    # ── Management interface discovery (was Info Disclosure: … Exposed) ──
    (re.compile(r'^Information Disclosure: VMware ESXi Management Interface Exposed$', re.IGNORECASE), 'Discovery: VMware ESXi Management Interface'),
    (re.compile(r'^Information Disclosure: Jenkins CI/CD Server Exposed$', re.IGNORECASE), 'Discovery: Jenkins CI/CD Server'),
    (re.compile(r'^Information Disclosure: System Management Console \(Cockpit\) Exposed$', re.IGNORECASE), 'Discovery: System Management Console (Cockpit)'),
    (re.compile(r'^Information Disclosure: Oracle EM Agent Exposed$', re.IGNORECASE), 'Discovery: Oracle EM Agent'),
    (re.compile(r'^Information Disclosure: License Server Exposed \(Sentinel\)$', re.IGNORECASE), 'Discovery: License Server (Sentinel)'),
    (re.compile(r'^Information Disclosure: Sentinel License Server$', re.IGNORECASE), 'Discovery: License Server (Sentinel)'),
    # ── Login page title normalization ──
    (re.compile(r'^Login Page Identified$', re.IGNORECASE), 'Discovery: Login Page'),
    # ── testssl cert finding normalization ──
    (re.compile(r'^SSL/TLS Vulnerability: cert_signatureAlgorithm$', re.IGNORECASE), 'SSL/TLS Certificate: Weak Signature Algorithm'),
    (re.compile(r'^SSL/TLS Vulnerability: intermediate_cert_expiration(?:\s*<#\d+>)?$', re.IGNORECASE), 'SSL/TLS Certificate: Intermediate Certificate Expired'),
    (re.compile(r'^SSL/TLS Vulnerability: intermediate_cert_notAfter(?:\s*<#\d+>)?$', re.IGNORECASE), 'SSL/TLS Certificate: Intermediate Certificate Expired'),
    # ── RPC ──────────────────────────────────────────────────────────────
    (re.compile(r'^RPC Null Session Permitted$', re.IGNORECASE), 'RPC: Null Session Permitted'),
    (re.compile(r'^RPC portmapper \(TCP\)$', re.IGNORECASE), 'RPC: Portmapper Exposed'),
    (re.compile(r'^DCE Services Enumeration$', re.IGNORECASE), 'RPC: DCE Services Enumeration'),
    (re.compile(r'^Microsoft Windows SMB\s*:\s*DCE-RPC Services Enumerable$', re.IGNORECASE), 'RPC: DCE Services Enumeration'),
    (re.compile(r'^gRPC Server Reflection Exposed$', re.IGNORECASE), 'gRPC: Server Reflection Exposed'),
    (re.compile(r'^Insecure gRPC Transport\b.*', re.IGNORECASE), 'gRPC: Insecure Transport (No TLS)'),
    # ── NTP ──────────────────────────────────────────────────────────────
    (re.compile(r'^NTP monlist Permitted\b.*', re.IGNORECASE), 'NTP: Monlist Amplification (CVE-2013-5211)'),
    (re.compile(r'^NTP Server Detection$', re.IGNORECASE), 'Discovery: NTP Service'),
    (re.compile(r'^NTP monlist Command Enabled$', re.IGNORECASE), 'NTP: Monlist Amplification (CVE-2013-5211)'),
    (re.compile(r'^NTP Mode 6 Queries Enabled$', re.IGNORECASE), 'NTP: Mode 6 Queries Enabled'),
    (re.compile(r'^NTP Daemon Multiple Vulnerabilities\b.*', re.IGNORECASE), 'NTP: Multiple Vulnerabilities'),
    # ── DNS ─────────────────────────────────────────────────────────────
    (re.compile(r'^DNS Recursion Enabled$', re.IGNORECASE), 'DNS Vulnerability: Recursion Enabled'),
    (re.compile(r'^DNS Server Version Disclosed via CHAOS Query$', re.IGNORECASE), 'Information Disclosure: DNS Server Version Disclosure'),
    (re.compile(r'^DNS Server Version Disclosed$', re.IGNORECASE), 'Information Disclosure: DNS Server Version Disclosure'),
    (re.compile(r'^DNS Zone Transfer Permitted.*', re.IGNORECASE), 'DNS Vulnerability: Zone Transfer Permitted (AXFR)'),
    # Remap legacy DNS: prefix entries from prior renames
    (re.compile(r'^DNS: Recursion Enabled$', re.IGNORECASE), 'DNS Vulnerability: Recursion Enabled'),
    (re.compile(r'^DNS: Zone Transfer Permitted.*', re.IGNORECASE), 'DNS Vulnerability: Zone Transfer Permitted (AXFR)'),
    (re.compile(r'^DNS: Server Version Disclosed\b.*', re.IGNORECASE), 'Information Disclosure: DNS Server Version Disclosure'),
    (re.compile(r'^PTR Detected$', re.IGNORECASE), 'DNS Information: PTR Record Detected'),
    # Catch-all: remaining DNS: → DNS Information:
    (re.compile(r'^DNS: (.+)$'), r'DNS Information: \1'),
    # ── RDP ──────────────────────────────────────────────────────────────
    (re.compile(r'^RDP Accepts Native Encryption\b.*', re.IGNORECASE), 'RDP: Native Encryption Downgrade'),
    (re.compile(r'^RDP FIPS Encryption Not Enforced$', re.IGNORECASE), 'RDP: FIPS Encryption Not Enforced'),
    (re.compile(r'^RDP Low Encryption Level$', re.IGNORECASE), 'RDP: Low Encryption Level'),
    (re.compile(r'^RDP NLA Not Enforced\b.*', re.IGNORECASE), 'RDP: NLA Not Enforced'),
    (re.compile(r'^RDP NLA Not Supported$', re.IGNORECASE), 'RDP: NLA Not Supported'),
    (re.compile(r'^RDP No TLS or NLA\b.*', re.IGNORECASE), 'RDP: No TLS or NLA (MitM)'),
    (re.compile(r'^RDP Null Encryption Accepted$', re.IGNORECASE), 'RDP: Null Encryption'),
    (re.compile(r'^RDP Weak Encryption Methods Supported$', re.IGNORECASE), 'RDP: Weak Encryption'),
    (re.compile(r'^RDP Weak or No Encryption Configured$', re.IGNORECASE), 'RDP: Weak or No Encryption'),
    (re.compile(r'^MS12-020 RDP Vulnerability Detected$', re.IGNORECASE), 'RDP: MS12-020 Vulnerability'),
    # ── FTP ──────────────────────────────────────────────────────────────
    (re.compile(r'^FTP Anonymous Login Permitted$', re.IGNORECASE), 'FTP: Anonymous Login Permitted'),
    (re.compile(r'^FTP Brute Force Protection Not Detected$', re.IGNORECASE), 'FTP: Brute Force Protection Not Detected'),
    (re.compile(r'^FTP Default Credentials Accepted$', re.IGNORECASE), 'FTP: Default Credentials'),
    # ── IKE ──────────────────────────────────────────────────────────────
    (re.compile(r'^IKE Aggressive Mode Enabled$', re.IGNORECASE), 'IKE: Aggressive Mode Enabled'),
    (re.compile(r'^IKE VPN:\s*Weak Cryptographic Parameters$', re.IGNORECASE), 'IKE: Weak Cryptographic Parameters'),
    (re.compile(r'^IKE/ISAKMP VPN Endpoint Detected$', re.IGNORECASE), 'Discovery: IKE/VPN Endpoint'),
    # ── SSL/TLS (bare titles) ────────────────────────────────────────────
    (re.compile(r'^TLS Certificate Hostname Mismatch$', re.IGNORECASE), 'SSL/TLS Certificate: Hostname Mismatch'),
    (re.compile(r'^CBC Mode Cipher Suites Accepted$', re.IGNORECASE), 'SSL/TLS Ciphers: CBC Mode Cipher Suites'),
    (re.compile(r'^Expired TLS Certificate Detected$', re.IGNORECASE), 'SSL/TLS Certificate: Expired'),
    (re.compile(r'^Self-Signed TLS Certificate$', re.IGNORECASE), 'SSL/TLS Certificate: Self-Signed'),
    (re.compile(r'^Revoked TLS Certificate Detected$', re.IGNORECASE), 'SSL/TLS Certificate: Revoked'),
    (re.compile(r'^TLS Version Identified$', re.IGNORECASE), 'Discovery: TLS Version'),
    (re.compile(r'^HSTS Not Preload-Ready$', re.IGNORECASE), 'Permissive Security Header: HSTS Not Preload-Ready'),
    # ── Unauthenticated Access ───────────────────────────────────────────
    (re.compile(r'^Cassandra\s+(?:Native Protocol |Unauthenticated ).*(?:Access|Authentication).*', re.IGNORECASE), 'Unauthenticated Access: Cassandra'),
    (re.compile(r'^(?:Unauthenticated )?CouchDB\s+(?:Unauthenticated )?.*(?:Access|Listing).*', re.IGNORECASE), 'Unauthenticated Access: CouchDB'),
    (re.compile(r'^MongoDB Unauthenticated Access$', re.IGNORECASE), 'Unauthenticated Access: MongoDB'),
    (re.compile(r'^Unauthenticated Docker API\b.*', re.IGNORECASE), 'Unauthenticated Access: Docker API'),
    (re.compile(r'^Grafana (?:API )?(?:Accessible Without Authentication|Unauthenticated.*Access)$', re.IGNORECASE), 'Unauthenticated Access: Grafana'),
    (re.compile(r'^Grafana Default Credentials\b.*', re.IGNORECASE), 'Unauthenticated Access: Grafana (Default Credentials)'),
    (re.compile(r'^(?:Unauthenticated )?Kibana\s+(?:API )?(?:Accessible Without Authentication|Unauthenticated.*Access)$', re.IGNORECASE), 'Unauthenticated Access: Kibana'),
    (re.compile(r'^Java RMI Registry Exposed$', re.IGNORECASE), 'Unauthenticated Access: Java RMI Registry'),
    (re.compile(r'^PostgreSQL Trust Authentication\b.*', re.IGNORECASE), 'Unauthenticated Access: PostgreSQL'),
    (re.compile(r'^MySQL Unauthenticated Access\b.*', re.IGNORECASE), 'Unauthenticated Access: MySQL'),
    # ── SMTP / SNMP / TFTP / IPMI ────────────────────────────────────────
    (re.compile(r'^SMTP Open Mail Relay Detected$', re.IGNORECASE), 'SMTP: Open Mail Relay'),
    (re.compile(r'^SNMP Default Community String Accepted$', re.IGNORECASE), 'SNMP: Default Community String'),
    (re.compile(r'^TFTP Service Accessible\b.*', re.IGNORECASE), 'TFTP: Files Retrievable'),
    (re.compile(r'^TFTP Service Detected$', re.IGNORECASE), 'Discovery: TFTP Service'),
    (re.compile(r'^IPMI 2\.0 Cipher Suite 0$', re.IGNORECASE), 'IPMI: Cipher Suite 0'),
    # ── Protocol / service detection ─────────────────────────────────────
    (re.compile(r'^Telnet Service Exposed\b.*', re.IGNORECASE), 'Insecure Protocol Detected: Telnet'),
    (re.compile(r'^AMQP Service Detected$', re.IGNORECASE), 'Discovery: AMQP Service'),
    (re.compile(r'^Non-Standard Web Port Detected$', re.IGNORECASE), 'Discovery: Non-Standard Web Port'),
    (re.compile(r'^Unconfirmed UDP Ports\b.*', re.IGNORECASE), 'Discovery: Unconfirmed UDP Ports'),
    # ── Exposed files / pages ────────────────────────────────────────────
    (re.compile(r'^PHP Info Page Exposed$', re.IGNORECASE), 'Sensitive File Exposed: phpinfo()'),
    (re.compile(r'^(?:Exposed \.git Repository|Git Repository Exposed via Web)$', re.IGNORECASE), 'Sensitive File Exposed: .git Repository'),
    (re.compile(r'^Application Structure Disclosed via sitemap\.xml$', re.IGNORECASE), 'Sensitive File Exposed: sitemap.xml'),
    # ── OSINT / Recon ─────────────────────────────────────────────────────
    (re.compile(r'^Typosquatting Domain Detected$', re.IGNORECASE), 'Discovery: Typosquatting Domain'),
    (re.compile(r'^Suspicious Typosquatting Domain:\s*(.+)', re.IGNORECASE), r'Discovery: Typosquatting Domain: \1'),
    (re.compile(r'^Email Naming Convention Identified$', re.IGNORECASE), 'Discovery: Email Naming Convention'),
    # ── Nikto ────────────────────────────────────────────────────────────
    (re.compile(r'^An ASP page that allows attackers to upload files\b.*', re.IGNORECASE), 'Sensitive File Exposed: ASP Upload Page'),
    (re.compile(r'^Database SQL found\b.*', re.IGNORECASE), 'Sensitive File Exposed: Database File'),
    (re.compile(r'^Database SQL\?\s*$', re.IGNORECASE), 'Sensitive File Exposed: Database File'),
    (re.compile(r'^Encryption key exposed\b.*', re.IGNORECASE), 'Sensitive File Exposed: Encryption Key'),
    (re.compile(r'^LocalWEB2000 users\b.*', re.IGNORECASE), 'Information Disclosure: User List'),
    (re.compile(r'^May be FactoSystem CMS\b.*', re.IGNORECASE), 'Software Identified: FactoSystem CMS'),
    (re.compile(r'^Possible debug directory/program found\b.*', re.IGNORECASE), 'Debug Endpoint Exposed: Debug Directory'),
    (re.compile(r'^This may be User Online version\b.*', re.IGNORECASE), 'Software Identified: User Online'),
    (re.compile(r'^VP-ASP shopping cart admin\b.*', re.IGNORECASE), 'Discovery: Admin Panel'),
    (re.compile(r'^XMB Magic Lantern forum\b.*', re.IGNORECASE), 'Software Identified: XMB Magic Lantern'),
    (re.compile(r'^web-erp\b.*', re.IGNORECASE), 'Software Identified: web-erp'),
    (re.compile(r'^Shopping cart config file\b.*', re.IGNORECASE), 'Sensitive File Exposed: Shopping Cart Config'),
    (re.compile(r'^Log File Publicly Accessible\b.*', re.IGNORECASE), 'Sensitive File Exposed: Log File'),
    # ── Business Logic ──────────────────────────────────────────────────
    (re.compile(r'^Business Logic\s*[-—]\s*(.+)$', re.IGNORECASE), r'Business Logic: \1'),
    # ── Debug / error ────────────────────────────────────────────────────
    (re.compile(r'^Debug (?:Mode Enabled|/ Developer Console Exposed)\b.*', re.IGNORECASE), 'Debug Endpoint Exposed: Developer Console'),
    # ── Misc ─────────────────────────────────────────────────────────────
    (re.compile(r'^Bearer Token Transmitted in URL\b.*', re.IGNORECASE), 'Information Disclosure: Bearer Token in URL'),
    # ── Authentication ──────────────────────────────────────────────────
    (re.compile(r'^Weak or Default Credentials Accepted$', re.IGNORECASE), 'Authentication: Weak or Default Credentials'),
    (re.compile(r'^Authentication Bypass via SQL Injection$', re.IGNORECASE), 'Authentication: SQL Injection Bypass'),
    (re.compile(r'^Password Reset Token Exposed in URL$', re.IGNORECASE), 'Authentication: Password Reset Token in URL'),
    (re.compile(r'^Timing Attack\s*[-—]\s*Non-Constant-Time Authentication$', re.IGNORECASE), 'Authentication: Timing Attack'),
    (re.compile(r'^Unicode Normalization Bypass in Authentication$', re.IGNORECASE), 'Authentication: Unicode Normalization Bypass'),
    (re.compile(r'^Auth Bypass Confirmed\s*[-—]\s*Credential Extraction$', re.IGNORECASE), 'Authentication: Bypass (Credential Extraction)'),
    (re.compile(r'^Credential Validation\s*[-—]\s*Default Creds Confirmed$', re.IGNORECASE), 'Authentication: Default Credentials Confirmed'),
    (re.compile(r'^OAuth Missing State Parameter\b.*', re.IGNORECASE), 'Authentication: OAuth Missing State Parameter'),
    (re.compile(r'^OAuth redirect_uri Open Redirect\b.*', re.IGNORECASE), 'Authentication: OAuth Open Redirect'),
    (re.compile(r'^OAuth Scope Escalation\b.*', re.IGNORECASE), 'Authentication: OAuth Scope Escalation'),
    (re.compile(r'^MFA Bypass\s*[-—]\s*Direct Navigation$', re.IGNORECASE), 'Authentication: MFA Bypass (Direct Navigation)'),
    (re.compile(r'^MFA Missing Rate Limiting on OTP$', re.IGNORECASE), 'Authentication: MFA Missing Rate Limiting'),
    (re.compile(r'^Missing Rate Limiting\s*/\s*Brute-Force Protection$', re.IGNORECASE), 'Authentication: Missing Rate Limiting'),
    (re.compile(r'^Insufficient Auth Failure Logging\s*/\s*No Brute-Force Detection$', re.IGNORECASE), 'Authentication: Insufficient Failure Logging / No Brute-Force Detection'),
    (re.compile(r'^Multi-Factor Authentication Detected$', re.IGNORECASE), 'Authentication: Multi-Factor Authentication Detected'),
    (re.compile(r'^JSON API Accepts Form Content-Type \(CSRF\)$', re.IGNORECASE), 'Authentication: CSRF via Content-Type Confusion'),
    (re.compile(r'^CSRF Token Leaked via URL\b.*', re.IGNORECASE), 'Authentication: CSRF Token Leaked in URL'),
    (re.compile(r'^CSRF Token Not Required\b.*', re.IGNORECASE), 'Authentication: CSRF Token Not Required'),
    (re.compile(r'^CSRF Token Not Validated\b.*', re.IGNORECASE), 'Authentication: CSRF Token Not Validated'),
    (re.compile(r'^Cross-Site Request Forgery \(CSRF\)\b.*', re.IGNORECASE), 'Authentication: CSRF Token Missing'),
    (re.compile(r'^Information Disclosure: OAuth Token via URL$', re.IGNORECASE), 'Authentication: OAuth Token in URL'),
    # ── Authorization ───────────────────────────────────────────────────
    (re.compile(r'^Broken Object Level Authorization \(IDOR\s*/\s*BOLA\)$', re.IGNORECASE), 'Authorization: IDOR (BOLA)'),
    (re.compile(r'^Authorization Gaps\s*[-—]\s*Unauthenticated Access to Restricted Paths$', re.IGNORECASE), 'Authorization: Unauthenticated Access to Restricted Paths'),
    (re.compile(r'^Cross-User Data Leakage \(IDOR\)$', re.IGNORECASE), 'Authorization: Cross-User Data Leakage (IDOR)'),
    (re.compile(r'^API Endpoint Returns Same Data for All Users$', re.IGNORECASE), 'Authorization: Missing User-Level Access Control'),
    (re.compile(r'^Missing Authentication Enforcement$', re.IGNORECASE), 'Authorization: Missing Authentication Enforcement'),
    (re.compile(r'^(?:Broken Access Control:\s*)?Unauthenticated Access to Protected Path$', re.IGNORECASE), 'Broken Access Control: Unauthenticated Access to Protected Path'),
    # ── GraphQL ─────────────────────────────────────────────────────────
    (re.compile(r'^(?:Enumeration: )?GraphQL Introspection Enabled$', re.IGNORECASE), 'GraphQL: Introspection Enabled'),
    (re.compile(r'^GraphQL Batch Query Attack\b.*', re.IGNORECASE), 'GraphQL: Batch Query Attack'),
    (re.compile(r'^GraphQL Field Suggestions Enabled$', re.IGNORECASE), 'GraphQL: Field Suggestions Enabled'),
    (re.compile(r'^GraphQL Field Name Suggestions Enabled$', re.IGNORECASE), 'GraphQL: Field Suggestions Enabled'),
    (re.compile(r'^GraphQL Alias-Based (?:Batching|Rate Limit Bypass)$', re.IGNORECASE), 'GraphQL: Alias-Based Batching'),
    (re.compile(r'^GraphQL Circular Fragment Accepted$', re.IGNORECASE), 'GraphQL: Circular Fragment Accepted'),
    (re.compile(r'^GraphQL Field Duplication Not Limited$', re.IGNORECASE), 'GraphQL: Field Duplication Not Limited'),
    (re.compile(r'^GraphQL Query Depth Attack$', re.IGNORECASE), 'GraphQL: Query Depth Attack'),
    (re.compile(r'^GraphQL Error Response Leaks Internal Details$', re.IGNORECASE), 'GraphQL: Error Response Information Disclosure'),
    (re.compile(r'^GraphQL Debug Extensions Exposed$', re.IGNORECASE), 'GraphQL: Debug Extensions Exposed'),
    (re.compile(r'^GraphQL Batching Enabled Without Limit$', re.IGNORECASE), 'GraphQL: Batching Without Limit'),
    (re.compile(r'^GraphQL Fragment Sprawl\b.*', re.IGNORECASE), 'GraphQL: Fragment Sprawl'),
    (re.compile(r'^GraphQL Directive Abuse\b.*', re.IGNORECASE), 'GraphQL: Directive Abuse'),
    (re.compile(r'^GraphQL Subscription Endpoint Detected$', re.IGNORECASE), 'Discovery: GraphQL Subscription Endpoint'),
    (re.compile(r'^GraphQL Endpoint Detected\b.*', re.IGNORECASE), 'Discovery: GraphQL Endpoint'),
    # ── WebSocket ───────────────────────────────────────────────────────
    (re.compile(r'^WebSocket Endpoint Missing Authentication$', re.IGNORECASE), 'WebSocket: Missing Authentication'),
    (re.compile(r'^WebSocket Missing Origin Validation$', re.IGNORECASE), 'WebSocket: Missing Origin Validation'),
    (re.compile(r'^WebSocket Message Injection \(XSS\)$', re.IGNORECASE), 'WebSocket: Message Injection (XSS)'),
    (re.compile(r'^Insecure WebSocket Transport \(Unencrypted ws://\)$', re.IGNORECASE), 'WebSocket: Insecure Transport (Unencrypted)'),
    (re.compile(r'^WebSocket Handshake Accepts Arbitrary Origin\b.*', re.IGNORECASE), 'WebSocket: Arbitrary Origin Accepted'),
    # ── JWT ─────────────────────────────────────────────────────────────
    (re.compile(r'^JWT (?:Vulnerability:\s*)?(?:None|\'none\') Algorithm\b.*(?:Bypass|Accepted)?$', re.IGNORECASE), 'JWT: None Algorithm Bypass'),
    (re.compile(r'^JWT None-Alg\b.*', re.IGNORECASE), 'JWT: None Algorithm Bypass'),
    (re.compile(r'^JWT None Algorithm Authentication Bypass$', re.IGNORECASE), 'JWT: None Algorithm Bypass'),
    (re.compile(r'^JWT (?:Vulnerability:\s*)?Missing Expiry Claim\b.*', re.IGNORECASE), 'JWT: Missing Expiry Claim'),
    (re.compile(r'^JWT (?:Vulnerability:\s*)?Missing Issued-At Claim$', re.IGNORECASE), 'JWT: Missing Issued-At Claim'),
    (re.compile(r'^JWT (?:Vulnerability:\s*)?Contains jku Header$', re.IGNORECASE), 'JWT: jku Header Present'),
    (re.compile(r'^JWT\s*[-—]\s*jku/x5u Header Injection\b.*', re.IGNORECASE), 'JWT: jku/x5u Header Injection'),
    (re.compile(r'^JWT (?:Vulnerability:\s*)?kid Header (?:Path )?Traversal$', re.IGNORECASE), 'JWT: kid Path Traversal'),
    (re.compile(r'^JWT\s*[-—]\s*kid Header SQL Injection$', re.IGNORECASE), 'JWT: kid SQL Injection'),
    (re.compile(r'^JWT (?:Vulnerability:\s*)?Uses Insecure Algorithm$', re.IGNORECASE), 'JWT: Insecure Algorithm'),
    (re.compile(r'^JWT (?:Vulnerability:\s*)?Uses Symmetric Algorithm\b.*', re.IGNORECASE), 'JWT: Symmetric Algorithm'),
    (re.compile(r'^JWT (?:Vulnerability:\s*)?HMAC Secret (?:Cracked|Brute-Force Recovered)\b.*', re.IGNORECASE), 'JWT: HMAC Secret Cracked'),
    (re.compile(r'^Weak JWT Secret\b.*', re.IGNORECASE), 'JWT: Weak Secret'),
    (re.compile(r'^JWT Secret Reuse\b.*', re.IGNORECASE), 'JWT: Secret Reuse'),
    (re.compile(r'^JWT (?:Vulnerability:\s*)?Algorithm Confusion\b.*', re.IGNORECASE), 'JWT: Algorithm Confusion'),
    (re.compile(r'^JWT\s*[-—]\s*Scope/Claim Manipulation\b.*', re.IGNORECASE), 'JWT: Scope/Claim Manipulation'),
    (re.compile(r'^JWT (?:Vulnerability:\s*)?Token Not Invalidated\b.*', re.IGNORECASE), 'JWT: Token Not Invalidated After Logout'),
    (re.compile(r'^JWT Token Contains Personally Identifiable\b.*', re.IGNORECASE), 'JWT: PII in Token'),
    (re.compile(r'^JWT Vulnerability Confirmed\b.*', re.IGNORECASE), 'JWT: Vulnerability Confirmed'),
    (re.compile(r'^JWT Vulnerability:\s*(.+)$', re.IGNORECASE), r'JWT: \1'),
    # ── CORS alignment ──────────────────────────────────────────────────
    (re.compile(r'^(?:Security Misconfiguration\s*/\s*)?CORS Wildcard with Credentials$', re.IGNORECASE), 'Permissive Security Header: CORS Wildcard with Credentials'),
    (re.compile(r'^CORS Allows Null Origin$', re.IGNORECASE), 'Permissive Security Header: CORS Null Origin Accepted'),
    # ── Additional Information Disclosure ────────────────────────────────
    (re.compile(r'^Unhandled Application Exception Disclosed$', re.IGNORECASE), 'Information Disclosure: Unhandled Application Exception'),
    (re.compile(r'^Sensitive Data Exposed in HTML Comments$', re.IGNORECASE), 'Information Disclosure: Sensitive Data in HTML Comments'),
    (re.compile(r'^Cloud Storage Bucket URL Exposed$', re.IGNORECASE), 'Information Disclosure: Cloud Storage Bucket URL'),
    (re.compile(r'^Inline Source Map in JavaScript Bundle$', re.IGNORECASE), 'Information Disclosure: Inline Source Map'),
    # ── Additional Enumeration ───────────────────────────────────────────
    (re.compile(r'^ASP\.NET Handler Endpoints Discovered$', re.IGNORECASE), 'Enumeration: ASP.NET Handler Endpoints'),
    (re.compile(r'^SPA Routes Extracted from JavaScript Bundle$', re.IGNORECASE), 'Enumeration: SPA Routes Extracted'),
    # ── Additional Sensitive File ────────────────────────────────────────
    (re.compile(r'^Log File Publicly Accessible$', re.IGNORECASE), 'Sensitive File Exposed: Log File'),
    (re.compile(r'^Terraform State File Exposed$', re.IGNORECASE), 'Sensitive File Exposed: Terraform State'),
    (re.compile(r'^JavaScript Source Map Exposed$', re.IGNORECASE), 'Sensitive File Exposed: JavaScript Source Map'),
    (re.compile(r'^Plaintext Credentials in Web File$', re.IGNORECASE), 'Sensitive File Exposed: Plaintext Credentials'),
    (re.compile(r'^Sensitive File Exposed$', re.IGNORECASE), 'Sensitive File Exposed: Default File'),
    # ── Additional Discovery ─────────────────────────────────────────────
    (re.compile(r'^API Layer Detected\b.*', re.IGNORECASE), 'Discovery: API Layer Detected'),
    (re.compile(r'^Authenticated API Layer Detected\b.*', re.IGNORECASE), 'Discovery: Authenticated API Layer Detected'),
    (re.compile(r'^API Endpoint Identified\b.*', re.IGNORECASE), 'Discovery: API Endpoint Identified'),
    (re.compile(r'^JetDirect\s*/\s*PJL Printer Accessible$', re.IGNORECASE), 'Discovery: JetDirect / PJL Printer'),
    (re.compile(r'^File Upload Endpoint Detected$', re.IGNORECASE), 'Discovery: File Upload Endpoint'),
    (re.compile(r'^Interesting Endpoint Discovered$', re.IGNORECASE), 'Discovery: Interesting Endpoint'),
    (re.compile(r'^Login Page Identified$', re.IGNORECASE), 'Discovery: Login Page'),
    (re.compile(r'^OAuth 2$', re.IGNORECASE), 'Discovery: OAuth 2.0 Endpoint'),
    (re.compile(r'^Single Page Application Detected$', re.IGNORECASE), 'Discovery: Single Page Application'),
    (re.compile(r'^Web Screenshot:\s*.+', re.IGNORECASE), 'Discovery: Web Screenshot Captured'),
    # ── Debug / Metrics ──────────────────────────────────────────────────
    (re.compile(r'^Exposed Metrics Endpoint\b.*', re.IGNORECASE), 'Debug Endpoint Exposed: Metrics Endpoint'),
    # ── Injection ────────────────────────────────────────────────────────
    (re.compile(r'^NoSQL Injection$', re.IGNORECASE), 'Injection: NoSQL Injection'),
    (re.compile(r'^Server-Side Template Injection \(SSTI\)\s*[-—]\s*SSTImap Confirmed$', re.IGNORECASE), 'Injection: SSTI — SSTImap Confirmed'),
    (re.compile(r'^HTTP Parameter Pollution \(HPP\)$', re.IGNORECASE), 'Injection: HTTP Parameter Pollution (HPP)'),
    (re.compile(r'^HTTP Parameter Pollution \(Reflected\)$', re.IGNORECASE), 'Injection: HTTP Parameter Pollution (Reflected)'),
    (re.compile(r'^Mass Assignment\s*/\s*Privilege Escalation via Parameter Binding$', re.IGNORECASE), 'Injection: Mass Assignment (Privilege Escalation)'),
    # Out of Date Software: prefix the full title (preserves version-specific detail)
    (re.compile(r'^(OpenSSH\b.*)$', re.IGNORECASE), r'Out of Date Software: \1'),
    (re.compile(r'^(Apache Log4j\b.*)$', re.IGNORECASE), r'Out of Date Software: \1'),
    (re.compile(r'^(urllib3\b.*)$', re.IGNORECASE), r'Out of Date Software: \1'),
    # General out-of-date catch-alls (prefix full title)
    (re.compile(r'^(?!(?:Out of Date Software|EOL Software|EOL Operating System|Discovery|SSL/TLS|SSH Vulnerability|SSH Configuration|Missing Security Header|Insecure Protocol Detected|Information Disclosure|Software Version Detected|Software Identified|Web Misconfiguration|Permissive Security Header|Network Misconfiguration|SMB Vulnerability|DNS|Enumeration|LDAP|RPC|gRPC|NTP|RDP|FTP|IKE|Unauthenticated Access|SMTP|SNMP|TFTP|IPMI|Sensitive File Exposed|Debug Endpoint Exposed|Authentication|Authorization|GraphQL|WebSocket|JWT|Injection|Business Logic):)(.+Multiple Vulnerabilities.*)$', re.IGNORECASE), r'Out of Date Software: \1'),
    (re.compile(r'^(?!(?:Out of Date Software|EOL Software|EOL Operating System|Discovery|SSL/TLS|SSH Vulnerability|SSH Configuration|Missing Security Header|Insecure Protocol Detected|Information Disclosure|Software Version Detected|Software Identified|Web Misconfiguration|Permissive Security Header|Network Misconfiguration|SMB Vulnerability|DNS|Enumeration|LDAP|RPC|gRPC|NTP|RDP|FTP|IKE|Unauthenticated Access|SMTP|SNMP|TFTP|IPMI|Sensitive File Exposed|Debug Endpoint Exposed|Authentication|Authorization|GraphQL|WebSocket|JWT|Injection|Business Logic):)(.+<\s*\d[\d.]+.*)$', re.IGNORECASE), r'Out of Date Software: \1'),
    # TLS version format normalization (display-level)
    (re.compile(r'TLS\s+1[\s.]0', re.IGNORECASE), 'TLSv1.0'),
    (re.compile(r'TLS\s+1[\s.]1', re.IGNORECASE), 'TLSv1.1'),
    (re.compile(r'TLS\s+1[\s.]2', re.IGNORECASE), 'TLSv1.2'),
    (re.compile(r'TLS\s+1[\s.]3', re.IGNORECASE), 'TLSv1.3'),
]

_TITLE_NORM_SUBS = _TITLE_RENAMES + [
    (re.compile(r'TLS\s*v?\s*1[\s_.]?0', re.IGNORECASE), 'TLSv1.0'),
    (re.compile(r'TLS\s*v?\s*1[\s_.]?1', re.IGNORECASE), 'TLSv1.1'),
    (re.compile(r'TLS\s*v?\s*1[\s_.]?2', re.IGNORECASE), 'TLSv1.2'),
    (re.compile(r'TLS\s*v?\s*1[\s_.]?3', re.IGNORECASE), 'TLSv1.3'),
    (re.compile(r'SSLv?[\s_]?2(?:\.0)?', re.IGNORECASE), 'SSLv2'),
    (re.compile(r'SSLv?[\s_]?3(?:\.0)?', re.IGNORECASE), 'SSLv3'),
    (re.compile(r'\((\d+)\s*bits?\)', re.IGNORECASE), r'(\1 bit)'),
    (re.compile(r'^/[^:]*:\s+'), ''),
    (re.compile(r'\s*<hostCert#\d+>'), ''),
    (re.compile(r'^(Typosquatting Domain Detected):?\s+.*', re.IGNORECASE), r'\1'),
]


def _apply_title_renames(title):
    """Apply display-level title renames without lowercasing."""
    t = (title or "").strip()
    for pat, repl in _TITLE_RENAMES:
        t = pat.sub(repl, t)
    return t


def _normalize_title(title):
    t = (title or "").strip()
    for pat, repl in _TITLE_NORM_SUBS:
        t = pat.sub(repl, t)
    return t.lower()


def _is_nessus(finding):
    tool = (finding.get("tool") or "").split(":")[0].lower()
    return tool == "nessus"


# ── Dedup / Merge ────────────────────────────────────────────

_CATALOGUE_RISK = {
    "ssl/tls vulnerability: sweet32": "MEDIUM",
}

_RE_UNABLE_TO_CONNECT = re.compile(r'^Unable to connect to\b', re.IGNORECASE)


def deduplicate(findings, ip_fqdn_map=None):
    """Deduplicate findings by (normalized_title, tool, scope).
    pr0t31n tool findings processed first.  Nessus merges into existing
    pr0t31n findings when the same (title, scope) exists; otherwise Nessus
    findings merge with each other.  IP/port/hostname always fold into
    affected.

    When *ip_fqdn_map* (IP→set[FQDN]) is provided, enrich each finding's
    hostname from OSift DNS data so engagement-level dedup collapses
    findings on the same FQDN behind different IPs."""
    ip_fqdn_map = ip_fqdn_map or {}
    pr0t31n = []
    nessus = []
    for f in findings:
        if _RE_UNABLE_TO_CONNECT.search(f.get("title") or ""):
            continue
        orig = f.get("title") or ""
        f["title"] = _apply_title_renames(orig)
        if f["title"] != orig:
            f["_original_title"] = orig
        if ip_fqdn_map and f.get("ip") and not f.get("hostname"):
            fqdns = ip_fqdn_map.get(f["ip"])
            if fqdns:
                f["hostname"] = sorted(fqdns)[0]
        aff = (f.get("affected") or "").strip()
        if aff:
            f["affected"] = _prefix_relative_affected(
                aff, f.get("hostname"), f.get("ip"),
                str(f.get("port") or "0"),
            )
        if _is_nessus(f):
            nessus.append(f)
        else:
            pr0t31n.append(f)

    seen = {}
    result = []
    ts_index = {}

    for f in pr0t31n:
        key = _dedup_key(f)
        if key in seen:
            _merge_finding(seen[key], f)
        else:
            seen[key] = f
            result.append(f)
            ts = (key[0], key[2], key[3])
            if ts not in ts_index:
                ts_index[ts] = key

    for f in nessus:
        ntitle = _normalize_title(f.get("title") or "")
        scope = (f.get("scope") or f.get("_scope") or "").lower()
        oos = "oos" if f.get("oos") else ""
        ts = (ntitle, scope, oos)
        if ts in ts_index:
            _merge_finding(seen[ts_index[ts]], f, nessus_secondary=True)
        else:
            nk = (ntitle, "nessus", scope, oos)
            if nk in seen:
                _merge_finding(seen[nk], f)
            else:
                seen[nk] = f
                result.append(f)

    for f in result:
        if not f.get("id"):
            key = _dedup_key(f)
            f["id"] = hashlib.sha256(
                "\x00".join(key).encode("utf-8", errors="replace")
            ).hexdigest()[:16]
        ntitle = _normalize_title(f.get("title") or "")
        if ntitle in _CATALOGUE_RISK:
            f["risk"] = _CATALOGUE_RISK[ntitle]
    return sorted(result, key=lambda f: _risk_sort_key(f.get("risk", "INFO")))


def _aff_has_url(aff_set, loc):
    """Check if aff_set already contains a URL form of ip:port loc."""
    for entry in aff_set:
        if "://" in entry and loc in entry:
            return True
    return False


def _prefix_relative_affected(affected_str, hostname, ip, port):
    """Prefix bare relative paths (starting with /) with the host's base URL
    so '/' becomes 'https://columbushosp.org/' in multi-target scans."""
    if not affected_str:
        return affected_str
    host = (hostname or "").strip() or (ip or "").strip()
    if not host:
        return affected_str
    try:
        port_num = int(port) if port else 0
    except (ValueError, TypeError):
        port_num = 0
    if port_num == 443 or port_num == 0:
        base = "https://" + host
    elif port_num == 80:
        base = "http://" + host
    else:
        base = "https://" + host + ":" + str(port_num)
    parts = affected_str.split("\n")
    changed = False
    result = []
    for p in parts:
        ps = p.strip()
        if not ps:
            continue
        if ps.startswith("/"):
            result.append(base + ps)
            changed = True
        else:
            result.append(ps)
    return "\n".join(result) if changed else affected_str


def _dedup_affected_set(aff_set):
    """Collapse redundant target identifiers. When a URL form like
    https://host/ exists, bare 'host' and 'host:443' are redundant."""
    if len(aff_set) <= 1:
        return aff_set
    result = set(aff_set)
    to_remove = set()
    url_hosts = set()
    for e in result:
        if "://" not in e:
            continue
        try:
            after = e.split("://", 1)[1]
            hp = after.split("/", 1)[0]
            h = hp.rsplit(":", 1)[0] if ":" in hp else hp
            url_hosts.add(h)
            url_hosts.add(hp)
            if e.startswith("https://") and ":" not in hp:
                url_hosts.add(h + ":443")
            elif e.startswith("http://") and ":" not in hp:
                url_hosts.add(h + ":80")
        except Exception:
            pass
    for e in list(result):
        if "://" in e:
            continue
        if e in url_hosts:
            to_remove.add(e)
    for e in list(result - to_remove):
        if "://" in e or ":" not in e:
            continue
        parts = e.rsplit(":", 1)
        try:
            int(parts[1])
            if parts[0] in (result - to_remove):
                to_remove.add(parts[0])
        except ValueError:
            pass
    return result - to_remove


def _dedup_key(finding):
    ntitle = _normalize_title(
        finding.get("title") or finding.get("detail") or ""
    )
    tool = (finding.get("tool") or "").split(":")[0].lower()
    scope = (finding.get("scope") or finding.get("_scope") or "").lower()
    oos = "oos" if finding.get("oos") else ""
    return (ntitle, tool, scope, oos)


_CROSS_ENRICH_FIELDS = (
    "cvss_score", "cvss_vector", "cwe", "description", "impact",
    "remediation", "nessus_plugin_id", "nessus_plugin_name",
    "mitre_attack", "owasp", "owasp_api",
    "nist_csf2", "nist_800_53", "nist_800_171",
    "pci_dss_4", "iso_27001", "iso_27002",
    "soc2", "hitrust", "gdpr",
)


def _is_empty(v):
    if v is None:
        return True
    if isinstance(v, str):
        return v.strip() == ""
    if isinstance(v, list):
        return len(v) == 0
    return False


def _union_merge(target, source, field):
    """Union-merge a newline-separated string field."""
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


def _try_parse_json_array(val):
    """Return parsed list if val is a JSON array string, else None."""
    s = val.strip()
    if s.startswith("["):
        try:
            parsed = json.loads(s)
            if isinstance(parsed, list):
                return parsed
        except (json.JSONDecodeError, ValueError):
            pass
    return None


def _plain_to_json_entries(val):
    """Wrap plain newline-delimited paths as [{file: path}, ...]."""
    return [{"file": p} for p in val.split("\n") if p.strip()]


def _evidence_entry_key(entry):
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        return (entry.get("req") or "", entry.get("resp") or "",
                entry.get("file") or "", entry.get("url") or "")
    return str(entry)


def _merge_finding(target, source, nessus_secondary=False):
    """Merge source into target.  IP/port/hostname always fold into affected.
    When nessus_secondary, target risk is authoritative (pr0t31n > Nessus)."""
    t_tool = target.get("tool") or target.get("_tool") or ""
    s_tool = source.get("tool") or source.get("_tool") or ""
    st = list(target.get("source_tools") or [])
    if t_tool and t_tool not in st:
        st.append(t_tool)
    if s_tool and s_tool not in st:
        st.append(s_tool)
    if len(st) > 1 or (st and st[0] != t_tool):
        target["source_tools"] = st

    _union_merge(target, source, "affected")
    _union_merge(target, source, "sources")
    _union_merge(target, source, "cves")

    for field in ("output", "command"):
        sv = source.get(field) or ""
        tv = target.get(field) or ""
        if sv and sv not in tv:
            target[field] = f"{tv}\n{sv}".strip()

    s_of = source.get("output_file") or ""
    t_of = target.get("output_file") or ""
    if s_of and s_of != t_of:
        if t_of:
            t_json = _try_parse_json_array(t_of)
            s_json = _try_parse_json_array(s_of)
            if t_json is not None or s_json is not None:
                t_list = t_json if t_json is not None else _plain_to_json_entries(t_of)
                s_list = s_json if s_json is not None else _plain_to_json_entries(s_of)
                seen_keys = set()
                for e in t_list:
                    seen_keys.add(_evidence_entry_key(e))
                merged = list(t_list)
                for e in s_list:
                    k = _evidence_entry_key(e)
                    if k not in seen_keys:
                        merged.append(e)
                        seen_keys.add(k)
                target["output_file"] = json.dumps(merged)
            else:
                existing = set(t_of.split("\n"))
                new_paths = [p for p in s_of.split("\n") if p and p not in existing]
                if new_paths:
                    target["output_file"] = t_of + "\n" + "\n".join(new_paths)
        else:
            target["output_file"] = s_of

    for field in ("exploit_details",):
        sl = source.get(field, [])
        tl = target.get(field, [])
        if isinstance(sl, list) and isinstance(tl, list):
            target[field] = tl + [x for x in sl if x not in tl]

    if "oos" in source and "oos" not in target:
        target["oos"] = source["oos"]

    for field in ("exploitdb", "metasploit", "kev"):
        if source.get(field):
            target[field] = True

    if not nessus_secondary:
        if _risk_sort_key(source.get("risk", "INFO")) < _risk_sort_key(target.get("risk", "INFO")):
            target["risk"] = source["risk"]

    if nessus_secondary:
        for field in _CROSS_ENRICH_FIELDS:
            sv = source.get(field)
            if _is_empty(sv):
                continue
            if _is_empty(target.get(field)):
                target[field] = sv

    t_aff = (target.get("affected") or "").strip()
    aff_set = set(t_aff.split("\n")) if t_aff else set()
    changed = False
    s_ip = (source.get("ip") or "").strip()
    s_port = str(source.get("port") or "0")
    if s_ip:
        s_loc = s_ip + ":" + s_port if s_port != "0" else s_ip
        if s_loc not in aff_set and not _aff_has_url(aff_set, s_loc):
            aff_set.add(s_loc)
            changed = True
    s_host = (source.get("hostname") or "").strip()
    if s_host and s_host not in aff_set:
        aff_set.add(s_host)
        changed = True
    t_ip = (target.get("ip") or "").strip()
    t_port = str(target.get("port") or "0")
    if t_ip:
        t_loc = t_ip + ":" + t_port if t_port != "0" else t_ip
        if t_loc not in aff_set and not _aff_has_url(aff_set, t_loc):
            aff_set.add(t_loc)
            changed = True
    t_host = (target.get("hostname") or "").strip()
    if t_host and t_host not in aff_set:
        aff_set.add(t_host)
        changed = True
    aff_set = _dedup_affected_set(aff_set - {""})
    target["affected"] = "\n".join(sorted(aff_set))
    if s_ip or s_host:
        target["ip"] = ""
        target["hostname"] = ""
        target["port"] = 0


def _risk_sort_key(risk):
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(
        risk.upper() if isinstance(risk, str) else "INFO", 5
    )


# ── False Positive Management ────────────────────────────────

def load_false_positives(project_dir):
    """Load FP list from project dir.
    Prefers falsePositives.json, falls back to false_positives.json."""
    pd = Path(project_dir)
    fp_file = pd / "falsePositives.json"
    if not fp_file.exists():
        fp_file = pd / "false_positives.json"
    if not fp_file.exists():
        return []
    with open(fp_file) as f:
        return json.load(f)


def _preserve_fp_evidence(project_dir, finding):
    """Copy evidence files referenced by a finding to falsePositive_evidence/."""
    import shutil
    pd = Path(project_dir)
    fid = finding.get("id", "")
    raw = finding.get("output_file", "")
    if not raw or not fid:
        return
    paths = []
    if raw.lstrip().startswith("["):
        try:
            for item in json.loads(raw):
                if isinstance(item, dict):
                    for v in item.values():
                        if isinstance(v, str) and v:
                            paths.append(v)
                elif isinstance(item, str):
                    paths.append(item)
        except (json.JSONDecodeError, TypeError):
            pass
    if not paths:
        for sep in ("\n", ","):
            if sep in raw:
                paths = [p.strip() for p in raw.split(sep) if p.strip()]
                break
        if not paths:
            paths = [raw.strip()]
    dest = pd / "falsePositive_evidence" / fid
    copied = 0
    for p in paths:
        src = pd / p if not p.startswith("/") else Path(p)
        if src.is_file():
            rel = src.relative_to(pd) if str(src).startswith(str(pd)) else Path(src.name)
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(src, target)
                copied += 1
            except OSError:
                pass
    if copied:
        finding["_fp_evidence_dir"] = str(dest.relative_to(pd))


def mark_false_positive(project_dir, finding, findings_list):
    """Move a finding from findings to falsePositives.
    Also writes falsePositives.csv mirror.
    Returns the updated findings list (finding removed)."""
    with _findings_lock:
        pd = Path(project_dir)
        fps = load_false_positives(project_dir)
        _preserve_fp_evidence(project_dir, finding)
        finding["fp_marked_at"] = datetime.now().isoformat()
        fps.append(finding)
        with open(pd / "falsePositives.json", "w") as f:
            json.dump(fps, f, indent=2)
        _write_fp_csv(pd, fps)
        fid = finding.get("id", "")
        return [f for f in findings_list if f.get("id") != fid]


def mark_partial_fp(project_dir, finding, findings_list, affected_locations):
    """Mark specific affected locations within a merged finding as FP.

    Splits the finding: each selected location gets its own individual
    FP entry (with full details/evidence) so they can be recovered
    independently.  The original finding keeps the remaining locations.
    If ALL locations are selected, behaves like a full mark_false_positive().

    Returns (updated_findings_list, fp_entries_list).
    """
    import copy

    all_affected = [a.strip() for a in (finding.get("affected") or "").split("\n")
                    if a.strip()]
    selected = set(a.strip() for a in affected_locations if a.strip())
    remaining = [a for a in all_affected if a not in selected]

    if not remaining:
        return mark_false_positive(project_dir, finding, findings_list), finding

    with _findings_lock:
        pd = Path(project_dir)
        now = datetime.now().isoformat()
        parent_id = finding.get("id", "")

        fps = load_false_positives(project_dir)
        fp_entries = []
        for loc in sorted(selected):
            fp_entry = copy.deepcopy(finding)
            fp_entry["affected"] = loc
            fp_entry["fp_marked_at"] = now
            fp_entry["_partial_fp"] = True
            fp_entry["_parent_finding_id"] = parent_id
            loc_hash = hashlib.md5(loc.encode()).hexdigest()[:8]
            fp_entry["id"] = parent_id + "_pfp_" + loc_hash
            _preserve_fp_evidence(project_dir, fp_entry)
            fps.append(fp_entry)
            fp_entries.append(fp_entry)

        with open(pd / "falsePositives.json", "w") as f:
            json.dump(fps, f, indent=2)
        _write_fp_csv(pd, fps)

        finding["affected"] = "\n".join(remaining)
        _persist_partial_fp_update(project_dir, finding.get("id", ""),
                                   finding["affected"])

        return list(findings_list), fp_entries


def _persist_partial_fp_update(project_dir, finding_id, new_affected):
    """Update the affected field in on-disk findings.json files after partial FP."""
    if not finding_id:
        return
    pd = Path(project_dir)
    for fj in pd.rglob("findings.json"):
        try:
            data = json.loads(fj.read_text())
            items = data if isinstance(data, list) else data.get("findings", [])
            changed = False
            for f in items:
                if f.get("id") == finding_id:
                    f["affected"] = new_affected
                    changed = True
            if changed:
                if isinstance(data, list):
                    fj.write_text(json.dumps(data, indent=2, default=str))
                else:
                    data["findings"] = items
                    fj.write_text(json.dumps(data, indent=2, default=str))
        except (json.JSONDecodeError, OSError):
            continue


def recover_false_positive(project_dir, finding_id):
    """Move a finding back from FP to active.
    Returns the recovered finding or None."""
    with _findings_lock:
        pd = Path(project_dir)
        fps = load_false_positives(project_dir)
        recovered = None
        remaining = []
        for fp in fps:
            if fp.get("id") == finding_id:
                recovered = fp
                recovered.pop("fp_marked_at", None)
            else:
                remaining.append(fp)
        if recovered:
            with open(pd / "falsePositives.json", "w") as f:
                json.dump(remaining, f, indent=2)
            _write_fp_csv(pd, remaining)
        return recovered


def _write_fp_csv(project_dir, fps):
    if not fps:
        csv_path = Path(project_dir) / "falsePositives.csv"
        if csv_path.exists():
            csv_path.unlink()
        return
    pd = Path(project_dir)
    fieldnames = ["id", "title", "risk", "ip", "port", "hostname", "tool",
                  "description", "remediation", "fp_marked_at"]
    with open(pd / "falsePositives.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(fps)


# ── Risk Override + Accept/Unaccept + Notes ──────────────────

_OVERRIDES_FILE = "risk_overrides.json"


def _overrides_path(project):
    pd = project.get("project_dir", "")
    return Path(pd) / _OVERRIDES_FILE if pd else None


def load_risk_overrides(project):
    """Load saved risk overrides — {title: {risk, reason, original_risk}}."""
    fp = _overrides_path(project)
    if not fp or not fp.exists():
        return {}
    try:
        with open(fp) as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_risk_override(project, title, new_risk, reason="", original_risk=""):
    """Persist a risk override to the project-level overrides file."""
    fp = _overrides_path(project)
    if not fp:
        return
    overrides = load_risk_overrides(project)
    overrides[title] = {
        "risk": new_risk.upper(),
        "reason": reason,
        "original_risk": original_risk,
        "datetime": datetime.now().isoformat(),
    }
    try:
        with open(fp, "w") as fh:
            json.dump(overrides, fh, indent=2)
    except Exception:
        pass


def remove_risk_override(project, title):
    """Remove a saved risk override (e.g. when resetting to original)."""
    fp = _overrides_path(project)
    if not fp or not fp.exists():
        return
    overrides = load_risk_overrides(project)
    if title in overrides:
        del overrides[title]
        try:
            with open(fp, "w") as fh:
                json.dump(overrides, fh, indent=2)
        except Exception:
            pass


def apply_risk_overrides(findings_list, project):
    """Apply saved risk overrides to a findings list (by title match)."""
    overrides = load_risk_overrides(project)
    if not overrides:
        return findings_list
    for f in findings_list:
        title = f.get("title") or ""
        if title in overrides:
            ov = overrides[title]
            f["original_risk"] = ov.get("original_risk") or f.get("risk", "INFO")
            f["risk"] = ov["risk"]
            if ov.get("reason"):
                f["risk_override_reason"] = ov["reason"]
    return findings_list


def override_risk(findings_list, finding_id, new_risk, reason=""):
    """Override a finding's risk level. Returns updated list."""
    for f in findings_list:
        if f.get("id") == finding_id:
            f["original_risk"] = f.get("risk", "INFO")
            f["risk"] = new_risk.upper()
            f["risk_override_reason"] = reason
            break
    return findings_list


def persist_risk_override(findings_list, finding_id, new_risk, project,
                          reason=""):
    """Write a risk override to the project-level overrides file AND
    back to the source findings file(s) (best-effort — the tool may
    overwrite them, but the overrides file survives)."""
    target = None
    for f in findings_list:
        if f.get("id") == finding_id:
            target = f
            break
    if not target:
        return
    title = target.get("title") or ""
    if not title:
        return
    original = target.get("original_risk") or target.get("risk", "INFO")
    save_risk_override(project, title, new_risk, reason=reason,
                       original_risk=original)
    source_files = set()
    _all_tdirs = list(project.get("tool_dirs", {}).values())
    for scope_dirs in project.get("scope_tool_dirs", {}).values():
        _all_tdirs.extend(scope_dirs.values())
    for td in _all_tdirs:
        td_path = Path(td)
        if not td_path.is_dir():
            continue
        for fn in ("findings.json", "findings_vantage.json",
                   "findings_report.json"):
            fp = td_path / fn
            if fp.exists():
                source_files.add(str(fp))
        try:
            for sub in td_path.iterdir():
                if sub.is_dir():
                    fp = sub / "findings.json"
                    if fp.exists():
                        source_files.add(str(fp))
        except OSError:
            pass
    nr = new_risk.upper()
    for sf_path in source_files:
        try:
            fp = Path(sf_path)
            with open(fp) as fh:
                data = json.load(fh)
            items = data if isinstance(data, list) else data.get("findings", [])
            changed = False
            for item in items:
                if (item.get("title") or "") == title:
                    if item.get("risk") != nr:
                        item["original_risk"] = item.get("risk", "INFO")
                        item["risk"] = nr
                        changed = True
            if changed:
                with open(fp, "w") as fh:
                    json.dump(data, fh, indent=2)
        except Exception:
            continue


def accept_finding(findings_list, finding_id):
    """Mark a finding as accepted. Returns updated list."""
    for f in findings_list:
        if f.get("id") == finding_id:
            f["accepted"] = True
            break
    return findings_list


def unaccept_finding(findings_list, finding_id):
    """Mark a finding as not accepted. Returns updated list."""
    for f in findings_list:
        if f.get("id") == finding_id:
            f["accepted"] = False
            break
    return findings_list


def add_note(findings_list, finding_id, note_text):
    """Add a timestamped note to a finding. Returns updated list."""
    for f in findings_list:
        if f.get("id") == finding_id:
            notes = f.get("notes", [])
            notes.append({"ts": datetime.now().isoformat(), "text": note_text})
            f["notes"] = notes
            break
    return findings_list


# ── Summaries ────────────────────────────────────────────────

def get_risk_summary(findings):
    """Return {CRITICAL: n, HIGH: n, MEDIUM: n, LOW: n, INFO: n}."""
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        r = f.get("risk", "INFO").upper() if isinstance(f.get("risk"), str) else "INFO"
        summary[r] = summary.get(r, 0) + 1
    return summary


def get_tool_breakdown(findings):
    """Return {tool_id: count} breakdown."""
    breakdown = {}
    for f in findings:
        tool = f.get("tool", "unknown")
        breakdown[tool] = breakdown.get(tool, 0) + 1
    return breakdown
