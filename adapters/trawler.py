"""Trawler tool adapter — network traffic analysis."""

from pathlib import Path

from adapters.base import ToolAdapter
from config import PYTHON3, TOOL_DIR


class TrawlerAdapter(ToolAdapter):

    tool_id = "trawler"
    tool_name = "Trawler"
    tool_key = "TR"
    domain = "traffic"
    script_path = str(TOOL_DIR / "Trawler/trawler.py")
    requires_sudo = False
    env_vars = {"CRUCIBLE_MANAGED": "1", "PYTHONUNBUFFERED": "1"}
    parallel_group = "any"

    _PCAP_EXTS = {".pcap", ".pcapng", ".cap", ".ntar", ".erf", ".snoop"}

    def validate_launch(self, project, settings):
        pcap = settings.get("pcap_file", "")
        if not pcap:
            return False, "No pcap file configured — Trawler requires captured network traffic"
        if not Path(pcap).exists():
            return False, f"PCAP file not found: {pcap}"
        return True, ""

    def build_command(self, project, settings, *, resume=False,
                      extra_args=None):
        cmd = [PYTHON3, self.script_path]

        pcap = settings.get("pcap_file", "")
        if pcap:
            cmd.extend(["--pcap", pcap])

        targets = settings.get("targets", [])
        if targets:
            for t in targets:
                cmd.extend(["--target", t])

        output_dir = settings.get("output_dir", "")
        if not output_dir:
            td = (project.get("tool_dirs") or {}).get("trawler")
            if td:
                output_dir = td
        if output_dir:
            cmd.extend(["--output-dir", output_dir])

        scope = self._normalize_scope(
            project.get("_launch_scope") or settings.get("scope", "ext"))
        cmd.extend(["--scope", scope])

        client = settings.get("client") or project.get("client_short", "trawler")
        cmd.extend(["--client", client])

        if extra_args:
            cmd.extend(extra_args)
        return cmd

    def default_settings(self):
        return {
            "pcap_file": "",
            "output_dir": "",
            "targets": [],
        }

    def settings_schema(self):
        return {"fields": [
            {"key": "pcap_file", "label": "PCAP File", "type": "file",
             "accept": ".pcap,.pcapng,.cap"},
            {"key": "output_dir", "label": "Output Directory",
             "type": "text"},
            {"key": "targets", "label": "Target IPs", "type": "tags",
             "placeholder": "10.0.0.1"},
        ]}

    def load_findings(self, project_dir, tool_output_dir):
        return self._load_findings_file(tool_output_dir, "findings.json")
