"""OSift tool adapter — OSINT reconnaissance."""

import json
from pathlib import Path

from adapters.base import ToolAdapter
from config import PYTHON3, TOOL_DIR


class OSiftAdapter(ToolAdapter):

    tool_id = "osift"
    tool_name = "OSift"
    tool_key = "OS"
    domain = "recon"
    script_path = str(TOOL_DIR / "OSift/osift.py")
    requires_sudo = True
    env_vars = {"CRUCIBLE_MANAGED": "1", "PYTHONUNBUFFERED": "1"}
    parallel_group = "osift"

    def build_command(self, project, settings, *, resume=False,
                      extra_args=None):
        import json as _json
        cmd = ["sudo", "-S", "-E", PYTHON3, self.script_path]
        proj_dir = project.get("project_dir", "")
        settings_path = None
        os_cfg = dict(settings)
        _launch_scope = self._normalize_scope(project.get("_launch_scope", ""))
        if proj_dir:
            _os_dir = project.get("tool_dirs", {}).get("osift", "")
            _candidates = []
            if _launch_scope:
                if _os_dir:
                    _candidates.append(Path(_os_dir) / f"os_settings_{_launch_scope}.json")
                _candidates.append(Path(proj_dir) / f"os_settings_{_launch_scope}.json")
            if _os_dir:
                _candidates.append(Path(_os_dir) / "os_settings.json")
            _candidates.append(Path(proj_dir) / "os_settings.json")
            settings_path = next((c for c in _candidates if c.exists()), None)
            if settings_path:
                cmd.extend(["--settings", str(settings_path)])
                try:
                    os_cfg = _json.loads(settings_path.read_text())
                except Exception:
                    pass
        company = (os_cfg.get("company") or "").strip()
        domains = os_cfg.get("domains", [])
        if not domains:
            td = os_cfg.get("target_domains", "")
            if isinstance(td, str) and td.strip():
                domains = [d.strip() for d in td.splitlines() if d.strip()]
            elif isinstance(td, list):
                domains = td
        if not domains:
            d = (os_cfg.get("domain") or "").strip()
            if d:
                domains = [d]
        if not company:
            company = (project.get("client_name") or "").strip()
        if not domains:
            domains = project.get("scope_definition", {}).get("domains", [])
        if company:
            cmd.extend(["-c", company])
        if domains:
            cmd.extend(["-d"] + domains)
        output_base = os_cfg.get("output_base", "")
        if not output_base:
            eng_dir = project.get("engagement_dir", "")
            td = project.get("tool_dirs", {}).get("osift", "")
            if td:
                output_base = td
            elif eng_dir:
                from config import TOOL_OUTPUT_DIRS
                output_base = str(Path(eng_dir) / TOOL_OUTPUT_DIRS.get("osift", "osift"))
        if output_base:
            cmd.extend(["--output-base", str(output_base)])
            cmd.extend(["--project-dir", str(output_base)])
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    def default_settings(self):
        return {
            "target_domains": "",
            "search_depth": "standard",
            "output_dir": "",
            "shodan_api_key": "",
            "censys_api_id": "",
            "censys_api_secret": "",
            "virustotal_api_key": "",
            "securitytrails_api_key": "",
            "hunter_api_key": "",
            "whoisxml_api_key": "",
            "fullcontact_api_key": "",
            "clearbit_api_key": "",
            "dehashed_api_key": "",
            "intelx_api_key": "",
            "binaryedge_api_key": "",
            "onyphe_api_key": "",
            "c99_api_key": "",
            "netlas_api_key": "",
            "zoomeye_api_key": "",
            "fofa_api_key": "",
            "urlscan_api_key": "",
            "builtwith_api_key": "",
            "passivetotal_api_key": "",
        }

    def settings_schema(self):
        return {"fields": [
            {"key": "target_domains", "label": "Target Domains",
             "type": "textarea",
             "hint": "One domain per line"},
            {"key": "search_depth", "label": "Search Depth",
             "type": "select", "options": ["light", "standard", "deep"]},
            {"key": "output_dir", "label": "Output Directory",
             "type": "text"},
            {"key": "shodan_api_key", "label": "Shodan API Key",
             "type": "password"},
            {"key": "censys_api_id", "label": "Censys API ID",
             "type": "password"},
            {"key": "censys_api_secret", "label": "Censys API Secret",
             "type": "password"},
            {"key": "virustotal_api_key", "label": "VirusTotal API Key",
             "type": "password"},
            {"key": "securitytrails_api_key",
             "label": "SecurityTrails API Key", "type": "password"},
            {"key": "hunter_api_key", "label": "Hunter.io API Key",
             "type": "password"},
            {"key": "whoisxml_api_key", "label": "WhoisXML API Key",
             "type": "password"},
            {"key": "fullcontact_api_key", "label": "FullContact API Key",
             "type": "password"},
            {"key": "clearbit_api_key", "label": "Clearbit API Key",
             "type": "password"},
            {"key": "dehashed_api_key", "label": "Dehashed API Key",
             "type": "password"},
            {"key": "intelx_api_key", "label": "IntelX API Key",
             "type": "password"},
            {"key": "binaryedge_api_key", "label": "BinaryEdge API Key",
             "type": "password"},
            {"key": "onyphe_api_key", "label": "ONYPHE API Key",
             "type": "password"},
            {"key": "c99_api_key", "label": "C99 API Key",
             "type": "password"},
            {"key": "netlas_api_key", "label": "Netlas API Key",
             "type": "password"},
            {"key": "zoomeye_api_key", "label": "ZoomEye API Key",
             "type": "password"},
            {"key": "fofa_api_key", "label": "FOFA API Key",
             "type": "password"},
            {"key": "urlscan_api_key", "label": "URLScan API Key",
             "type": "password"},
            {"key": "builtwith_api_key", "label": "BuiltWith API Key",
             "type": "password"},
            {"key": "passivetotal_api_key", "label": "PassiveTotal API Key",
             "type": "password"},
        ]}

    def load_findings(self, project_dir, tool_output_dir):
        td = Path(tool_output_dir)
        findings = []
        for fp in (td / "reports" / "findings_crucible.json",
                   td / "findings_crucible.json",
                   td / "reports" / "findings_crucible.json",  
                   td / "findings_crucible.json",  
                   td / "reports" / "findings_report.json",
                   td / "findings.json"):
            if fp.exists():
                findings = self._load_findings_file(str(fp.parent), fp.name)
                break
        findings = [f for f in findings if not self._is_unresolved_typosquat(f)]
        synth = self._synthesize_from_targets(td)
        if synth:
            existing_titles = {f.get("title", "").lower() for f in findings}
            for f in synth:
                if f.get("title", "").lower() not in existing_titles:
                    findings.append(f)
                    existing_titles.add(f.get("title", "").lower())
        self._enrich_remediation(findings)
        return findings

    @staticmethod
    def _is_unresolved_typosquat(f):
        title = (f.get("title") or "").lower()
        if "typosquat" not in title:
            return False
        desc = (f.get("description") or "").lower()
        return "not resolving" in desc

    def _synthesize_from_targets(self, td):
        """Create INFO findings from targets_osint.json for live propagation.

        OSift's write_targets_snapshot() skips subdomain/email/IP entries from
        findings_crucible.json during the scan (_SKIP_SNAP filter).  This method
        reads the structured data written to targets_osint.json and synthesises
        the corresponding INFO findings so they appear in real-time."""
        for candidate in (td / "reports" / "targets_osint.json",
                          td / "targets_osint.json"):
            if not candidate.exists():
                continue
            try:
                evidence_rel = str(candidate.relative_to(td))
            except ValueError:
                evidence_rel = str(candidate)
            try:
                data = json.loads(candidate.read_text())
            except (json.JSONDecodeError, OSError):
                continue
            findings = []
            domain = data.get("domain", "")
            generated = data.get("generated", "")
            _base = {
                "datetime": generated, "ip": "", "port": 0,
                "hostname": "", "risk": "INFO", "tool": "osift",
                "output": "", "command": "", "cves": "",
                "exploitdb": False, "metasploit": False,
                "exploit_details": [], "service": "",
                "output_file": evidence_rel, "remediation": "",
                "scope": "osint",
            }

            sub_names = []
            sub_sources = set()
            for sub in data.get("subdomains", []):
                if isinstance(sub, dict):
                    name = sub.get("host", "")
                    sources = sub.get("sources", [])
                else:
                    name, sources = str(sub), []
                if name:
                    sub_names.append(name)
                    sub_sources.update(sources)
            if sub_names:
                findings.append({**_base,
                    "title": "Discovery: Subdomain",
                    "sources": ",".join(sorted(sub_sources)) or "osift",
                    "description": "Subdomains discovered during OSINT "
                                   "reconnaissance of " + domain + ".",
                    "affected": " ".join(sorted(set(sub_names))),
                })

            email_addrs = []
            email_sources = set()
            for em in data.get("emails", []):
                if isinstance(em, dict):
                    addr = em.get("email", "")
                    sources = em.get("sources", [])
                else:
                    addr, sources = str(em), []
                if addr and domain and "@" in addr:
                    email_domain = addr.rsplit("@", 1)[1].lower()
                    if not email_domain.endswith(domain.lower()):
                        continue
                if addr:
                    email_addrs.append(addr)
                    email_sources.update(sources)
            if email_addrs:
                findings.append({**_base,
                    "title": "Discovery: Email Address",
                    "sources": ",".join(sorted(email_sources)) or "osift",
                    "description": "Email addresses discovered during OSINT "
                                   "reconnaissance of " + domain + ".",
                    "affected": " ".join(sorted(set(email_addrs))),
                })

            ip_addrs = []
            ip_sources = set()
            for ip_rec in data.get("ips", []):
                if isinstance(ip_rec, dict):
                    ip = ip_rec.get("ip", "")
                    sources = ip_rec.get("sources", [])
                else:
                    ip, sources = str(ip_rec), []
                if ip:
                    ip_addrs.append(ip)
                    ip_sources.update(sources)
            if ip_addrs:
                findings.append({**_base,
                    "title": "Discovery: IP Address",
                    "sources": ",".join(sorted(ip_sources)) or "osift",
                    "description": "IP addresses discovered during OSINT "
                                   "reconnaissance of " + domain + ".",
                    "affected": " ".join(sorted(set(ip_addrs))),
                })

            return findings
        return []

    _REMEDIATION_MAP = {
        "dns: missing caa record": (
            "Add a CAA DNS record restricting which Certificate Authorities "
            "may issue certificates for this domain. Example: "
            "example.com. IN CAA 0 issue \"letsencrypt.org\". "
            "Add a wildcard restriction with: "
            "example.com. IN CAA 0 issuewild \"letsencrypt.org\"."
        ),
        "dns: dmarc policy: monitor only": (
            "Upgrade the DMARC policy from p=none to p=quarantine or "
            "p=reject. Review RUA aggregate reports to confirm legitimate "
            "senders are covered before escalating. Update the _dmarc TXT "
            "record accordingly."
        ),
        "dns: dmarc policy: quarantine": (
            "Consider upgrading the DMARC policy from p=quarantine to "
            "p=reject for maximum spoofing protection once RUA reports "
            "confirm no legitimate mail is being quarantined."
        ),
        "dns: missing spf record": (
            "Add an SPF TXT record listing authorized mail servers. "
            "Example: v=spf1 include:_spf.google.com -all. "
            "Use -all (hard fail) rather than ~all (soft fail) to reject "
            "unauthorized senders."
        ),
        "dns: spf soft fail": (
            "Change the SPF qualifier from ~all (soft fail) to -all "
            "(hard fail) so receiving servers reject messages from "
            "unauthorized senders rather than marking them as suspicious."
        ),
        "dns: missing dmarc record": (
            "Add a DMARC TXT record at _dmarc.<domain>. Start with "
            "p=none and rua/ruf reporting to collect data, then escalate "
            "to p=quarantine or p=reject."
        ),
        "dns: missing dkim record": (
            "Configure DKIM signing for outbound email and publish the "
            "corresponding DKIM public key as a TXT record. Consult your "
            "mail provider documentation for the correct selector and key."
        ),
        "dns: missing caa issuewild": (
            "Add an issuewild CAA record to restrict wildcard certificate "
            "issuance. Example: example.com. IN CAA 0 issuewild "
            "\"letsencrypt.org\". Without this, any CA authorized by the "
            "issue record can also issue wildcard certificates."
        ),
        "dns: zone transfer allowed": (
            "Restrict DNS zone transfers (AXFR) to authorized secondary "
            "name servers only. Configure ACLs on the DNS server to deny "
            "zone transfers from untrusted sources."
        ),
        "dns: dnssec not enabled": (
            "Enable DNSSEC to protect against DNS spoofing and cache "
            "poisoning. Sign the zone and publish DS records in the "
            "parent zone. Use automated key rotation."
        ),
        "dns: dmarc subdomain policy: monitor only": (
            "Upgrade the DMARC subdomain policy (sp=) from none to "
            "quarantine or reject. Subdomains without their own DMARC "
            "record inherit this policy."
        ),
        "tls: expired certificate": (
            "Renew the certificate immediately. Implement automated "
            "renewal (ACME/Let's Encrypt) to prevent future expiry."
        ),
        "tls: self-signed certificate": (
            "Replace self-signed certificates with certificates issued "
            "by a trusted CA. Use ACME/Let's Encrypt for cost-free "
            "automation."
        ),
        "tls: untrusted ca": (
            "Replace the certificate with one issued by a publicly "
            "trusted CA. If internal-only, deploy the private CA root "
            "to all clients via group policy or MDM."
        ),
        "tls: deprecated protocol (tls 1.0)": (
            "Disable TLS 1.0 on the server and require TLS 1.2 or "
            "higher. Update client compatibility requirements."
        ),
        "tls: deprecated protocol (tls 1.1)": (
            "Disable TLS 1.1 on the server and require TLS 1.2 or higher."
        ),
    }

    def _enrich_remediation(self, findings):
        for f in findings:
            if (f.get("remediation") or "").strip():
                continue
            title = (f.get("title") or "").strip().lower()
            rem = self._REMEDIATION_MAP.get(title)
            if rem:
                f["remediation"] = rem

    def supports_resume(self):
        return True

    def supports_pause(self):
        return True
