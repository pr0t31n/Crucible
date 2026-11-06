"""Scattershot3 tool adapter — network recon (internal + external)."""

import json
from pathlib import Path

from adapters.base import ToolAdapter
from config import PYTHON3, TOOL_DIR


class Scattershot3Adapter(ToolAdapter):

    tool_id = "ss3"
    tool_name = "Scattershot3"
    tool_key = "SS"
    domain = "recon"
    script_path = str(TOOL_DIR / "Scattershot3/scattershot3.py")
    requires_sudo = True
    env_vars = {"CRUCIBLE_MANAGED": "1", "PYTHONUNBUFFERED": "1"}
    parallel_group = "exclusive"

    def build_command(self, project, settings, *, resume=False,
                      extra_args=None):
        cmd = ["sudo", "-S", "-E", PYTHON3, self.script_path]
        proj_dir = project.get("project_dir", "")
        ss3_dir = project.get("tool_dirs", {}).get("ss3", proj_dir)
        has_settings_file = False
        _launch_scope = self._normalize_scope(project.get("_launch_scope", ""))
        if proj_dir:
            _candidates = []
            if _launch_scope:
                if ss3_dir:
                    _candidates.append(Path(ss3_dir) / f"ss_settings_{_launch_scope}.json")
                _candidates.append(Path(proj_dir) / f"ss_settings_{_launch_scope}.json")
            if ss3_dir:
                _candidates.append(Path(ss3_dir) / "ss_settings.json")
            _candidates.append(Path(proj_dir) / "ss_settings.json")
            settings_path = next((c for c in _candidates if c.exists()), None)
            if settings_path:
                cmd.extend(["--settings", str(settings_path)])
                has_settings_file = True
            cmd.extend(["--project", ss3_dir or proj_dir])
        if not has_settings_file:
            targets = (settings.get("scan") or {}).get("targets", [])
            if not targets:
                raw = (settings.get("targets") or "").strip()
                if raw:
                    targets = [t.strip() for t in raw.splitlines()
                               if t.strip()]
            if not targets:
                targets = project.get("scope_definition", {}).get(
                    "network_cidrs", [])
            if targets:
                cmd.extend(targets)
        # -- Pass project-level exclusions to SS3 -------------------------
        exclusions = project.get("scope_definition", {}).get("exclusions", [])
        if exclusions:
            for exc in exclusions:
                exc = exc.strip() if isinstance(exc, str) else ""
                if exc:
                    cmd.extend(["--exclude", exc])

        eng_dir = project.get("engagement_dir", "")
        if eng_dir:
            from config import TOOL_OUTPUT_DIRS, TOOL_DIR
            tool_dirname = TOOL_OUTPUT_DIRS.get("ss3", "scattershot")
            ss3_ver = ""
            try:
                ss3_ver = (TOOL_DIR / "Scattershot3/VERSION").read_text().strip()
            except OSError:
                pass
            if ss3_ver >= "1.37.4":
                for scope_name, flag in (("internal", "--internal-dir"),
                                          ("external", "--external-dir")):
                    cmd.extend([flag, str(Path(eng_dir) / scope_name / tool_dirname)])
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    _ENGAGEMENT_KEYS = frozenset({
        "consultant", "consultant_email", "client_name", "client_short",
        "client_POC", "client_email", "start_date", "end_date",
    })
    _SCAN_KEYS = frozenset({
        "project", "targets", "target_file", "fast", "no_ssl", "no_banner",
        "no_web", "no_nuclei", "port_scan_workers", "web_timeout",
        "banner_timeout", "sslscan_timeout", "testssl_timeout",
        "nuclei_timeout", "wpscan_token",
        "discovery_min_rate", "discovery_min_parallelism", "timing_template",
        "passive_seed_duration", "exclude",
    })

    def default_settings(self):
        return {
            "client_name": "",
            "client_short": "",
            "consultant": "",
            "consultant_email": "",
            "start_date": "",
            "end_date": "",
            "targets": "",
            "fast": False,
            "no_ssl": False,
            "no_banner": False,
            "no_web": False,
            "no_nuclei": False,
            "port_scan_workers": 8,
            "web_timeout": 4,
            "banner_timeout": 3.0,
            "sslscan_timeout": 60,
            "testssl_timeout": 300,
            "nuclei_timeout": 600,
            "wpscan_token": "",
            "discovery_min_rate": 0,
            "discovery_min_parallelism": 20,
            "timing_template": "",
            "passive_seed_duration": 300,
        }

    def to_tool_format(self, settings):
        engagement = {}
        scan = {}
        for k, v in settings.items():
            if k in self._ENGAGEMENT_KEYS:
                engagement[k] = v
            elif k in self._SCAN_KEYS:
                scan[k] = v
        if isinstance(scan.get("targets"), str):
            raw = scan["targets"].strip()
            if raw:
                scan["targets"] = [t.strip() for t in raw.splitlines()
                                   if t.strip()]
            else:
                scan["targets"] = []
        if isinstance(scan.get("exclude"), str):
            raw = scan["exclude"].strip()
            if raw:
                scan["exclude"] = [e.strip() for e in raw.splitlines()
                                   if e.strip()]
            else:
                scan["exclude"] = []
        result = {}
        if engagement:
            result["engagement"] = engagement
        if scan:
            result["scan"] = scan
        return result

    def from_tool_format(self, settings):
        flat = {}
        for k, v in settings.items():
            if k in ("engagement", "scan") and isinstance(v, dict):
                flat.update(v)
            elif k != "_comment":
                flat[k] = v
        if isinstance(flat.get("targets"), list):
            flat["targets"] = "\n".join(flat["targets"])
        return flat

    def settings_schema(self):
        return {"fields": [
            {"key": "_section_scan", "label": "Scan Configuration",
             "type": "section"},
            {"key": "targets", "label": "Target IPs / CIDRs",
             "type": "textarea",
             "hint": "One IP or CIDR per line"},
            {"key": "fast", "label": "Fast Mode (top-1000 ports only)",
             "type": "checkbox"},
            {"key": "no_ssl", "label": "Disable SSL/TLS Scanning",
             "type": "checkbox"},
            {"key": "no_banner", "label": "Disable Banner Grabbing",
             "type": "checkbox"},
            {"key": "no_web", "label": "Disable HTTP Probing",
             "type": "checkbox"},
            {"key": "no_nuclei", "label": "Disable Nuclei Scanning",
             "type": "checkbox"},
            {"key": "port_scan_workers", "label": "Port Scan Workers",
             "type": "number", "min": 1, "max": 32},
            {"key": "web_timeout", "label": "HTTP Probe Timeout (s)",
             "type": "number", "min": 1, "max": 60},
            {"key": "banner_timeout", "label": "Banner Timeout (s)",
             "type": "number", "min": 1, "max": 30},
            {"key": "sslscan_timeout", "label": "sslscan Timeout (s)",
             "type": "number", "min": 10, "max": 600},
            {"key": "testssl_timeout", "label": "testssl Timeout (s)",
             "type": "number", "min": 30, "max": 1800},
            {"key": "nuclei_timeout", "label": "Nuclei Timeout (s)",
             "type": "number", "min": 60, "max": 3600},
            {"key": "wpscan_token", "label": "WPScan API Token",
             "type": "text",
             "hint": "Optional — enables vulnerability data enrichment"},
            {"key": "_section_discovery", "label": "Host Discovery",
             "type": "section"},
            {"key": "discovery_min_rate", "label": "Discovery Min Rate (pps)",
             "type": "number", "min": 0, "max": 100000,
             "hint": "nmap --min-rate for -sn discovery scans (0 = no limit)"},
            {"key": "discovery_min_parallelism",
             "label": "Discovery Min Parallelism",
             "type": "number", "min": 1, "max": 1000,
             "hint": "nmap --min-parallelism for discovery (default: 20)"},
            {"key": "timing_template", "label": "Timing Template",
             "type": "select",
             "options": [
                 {"value": "", "label": "Default (no override)"},
                 {"value": "0", "label": "T0 — Paranoid"},
                 {"value": "1", "label": "T1 — Sneaky"},
                 {"value": "2", "label": "T2 — Polite"},
                 {"value": "3", "label": "T3 — Normal"},
                 {"value": "4", "label": "T4 — Aggressive"},
                 {"value": "5", "label": "T5 — Insane"},
             ],
             "hint": "nmap timing template (-T0 through -T5) for discovery"},
            {"key": "_section_passive", "label": "Passive Recon Seed",
             "type": "section"},
            {"key": "passive_seed_duration",
             "label": "Passive Seed Duration (s)",
             "type": "number", "min": 0, "max": 900,
             "hint": "Seconds of tcpdump capture run concurrently with "
                     "Phase 1 discovery.  Trawler analyses the pcap in hunt "
                     "mode with the testing server excluded.  Catches SSDP, "
                     "mDNS, LLMNR, LLDP, ARP broadcast cycles.  "
                     "0 = disabled (default: 300)"},
        ]}

    def load_findings(self, project_dir, tool_output_dir):
        findings = []
        td = Path(tool_output_dir)
        from config import TOOL_OUTPUT_DIRS
        tool_dirname = TOOL_OUTPUT_DIRS.get("ss3", "scattershot")
        candidates = [
            ("internal", td / "internal" / tool_dirname),
            ("external", td / "external" / tool_dirname),
            ("internal", td / "internal" / tool_dirname / "int"),
            ("external", td / "external" / tool_dirname / "ext"),
            ("internal", td / "int"),
            ("external", td / "ext"),
        ]
        seen_scopes = set()
        for scope_name, scope_dir in candidates:
            if scope_name in seen_scopes:
                continue
            fp = scope_dir / "findings.json"
            if not fp.exists():
                continue
            seen_scopes.add(scope_name)
            with open(fp) as f:
                data = json.load(f)
            items = (data if isinstance(data, list)
                     else data.get("findings", []))
            for finding in items:
                finding["scope"] = scope_name
                finding["tool"] = "scattershot3"
                findings.append(finding)
            self._enrich_evidence(scope_dir, items)
            try:
                prefix = str(scope_dir.relative_to(td))
            except ValueError:
                prefix = scope_dir.name
            self._prefix_scope_paths(items, prefix, td)
        return findings

    @staticmethod
    def _prefix_scope_paths(items, scope, tool_dir):
        """Ensure output_file paths are relative to tool_dir, not scope root."""
        scope_prefix = scope + "/"
        td_resolved = str(Path(tool_dir).resolve())
        for f in items:
            raw = f.get("output_file", "")
            if not raw:
                continue
            parts = raw.replace("\n", ",").split(",")
            fixed = []
            for p in parts:
                p = p.strip()
                if not p:
                    continue
                if p.startswith("/"):
                    try:
                        p = str(Path(p).resolve().relative_to(td_resolved))
                    except (ValueError, OSError):
                        pass
                elif not p.startswith(scope_prefix):
                    p = scope_prefix + p
                fixed.append(p)
            if fixed:
                f["output_file"] = ",".join(fixed)

    @staticmethod
    def _enrich_evidence(scope_dir, findings):
        """Backfill empty output_file from correlated.json + disk scan."""
        import os
        corr_path = scope_dir / "correlated.json"
        ev_index = {}
        host_nmap = {}
        if corr_path.exists():
            try:
                with open(corr_path) as fh:
                    correlated = json.load(fh)
            except (json.JSONDecodeError, OSError):
                correlated = {}
            hosts = correlated.get("hosts", {})
            for ip, host_data in hosts.items():
                for port_str, pdata in host_data.get("ports", {}).items():
                    for tr in pdata.get("tool_results", []):
                        of = tr.get("output_file", "")
                        if of:
                            tool = tr.get("tool", "")
                            ev_index.setdefault((ip, port_str, tool), []).append(of)
                            ev_index.setdefault((ip, port_str), []).append(of)
                            if tool == "nmap" and ip not in host_nmap:
                                host_nmap[ip] = of

        hosts_dir = scope_dir / "hosts"

        for f in findings:
            if f.get("output_file"):
                continue
            fip = f.get("ip") or ""
            fport = f.get("port")
            fport_str = str(fport) if fport and fport != 0 and str(fport) != "0" else ""
            sources_raw = f.get("sources") or ""
            sources = [s.strip() for s in
                       sources_raw.replace(",", "\n").split("\n") if s.strip()]
            matched = []
            ips = [fip] if fip else []
            affected = f.get("affected") or ""
            if not fip and affected:
                import re
                ips = re.findall(r'\d+\.\d+\.\d+\.\d+', affected)
            title_lower = (f.get("title") or "").lower()
            is_udp = "udp" in title_lower

            for ip in ips:
                if fport_str and sources:
                    for src in sources:
                        matched.extend(ev_index.get((ip, fport_str, src), []))
                if not matched and fport_str:
                    matched.extend(ev_index.get((ip, fport_str), []))
                if not matched and not fport_str and not is_udp and ip in host_nmap:
                    matched.append(host_nmap[ip])

            if hosts_dir.is_dir():
                for ip in ips:
                    ip_safe = ip.replace(".", "_")
                    ip_dir = hosts_dir / ip_safe
                    if not ip_dir.is_dir():
                        continue
                    if not fport_str:
                        if is_udp:
                            for p in sorted(ip_dir.glob(ip_safe + "_udp_*")):
                                if p.suffix in (".xml", ".txt", ".nmap", ".gnmap") and ".log" not in p.name:
                                    matched.append(str(p.relative_to(scope_dir)).replace(os.sep, "/"))
                            if ip in host_nmap:
                                matched.append(host_nmap[ip])
                        if not matched:
                            for p in sorted(ip_dir.glob("portscan_*")):
                                if p.suffix in (".txt", ".xml", ".nmap", ".gnmap") and ".log" not in p.name:
                                    matched.append(str(p.relative_to(scope_dir)).replace(os.sep, "/"))
                    elif not matched:
                        for sub in [ip_dir / "web" / fport_str, ip_dir / "services"]:
                            if not sub.is_dir():
                                continue
                            for src in sources:
                                for p in sorted(sub.glob("*" + src + "*")):
                                    if p.is_file() and ".log" not in p.name:
                                        matched.append(str(p.relative_to(scope_dir)).replace(os.sep, "/"))
                            if matched:
                                break
                        if not matched:
                            for p in sorted(ip_dir.glob("portscan_*")):
                                if p.suffix in (".txt", ".xml") and ".log" not in p.name:
                                    matched.append(str(p.relative_to(scope_dir)).replace(os.sep, "/"))
                                    break

            seen = set()
            unique = []
            for p in matched:
                if p not in seen:
                    seen.add(p)
                    unique.append(p)
            if unique:
                f["output_file"] = ",".join(unique)

    def supports_resume(self):
        return True

    def supports_pause(self):
        return True
