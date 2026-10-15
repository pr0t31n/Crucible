"""Nessus tool adapter for Crucible v2.0.

Nessus is API-driven (not subprocess) so build_command returns an empty list.
The actual scan lifecycle is managed by the NessusClient helper methods that
talk to the Nessus REST API.
"""

import json
from pathlib import Path

from adapters.base import ToolAdapter
from config import NESSUS_DEFAULT_PORT


class NessusAdapter(ToolAdapter):
    tool_id = "nessus"
    tool_name = "Nessus"
    tool_key = "NE"
    domain = "vuln"
    script_path = ""  # No script — API-driven
    requires_sudo = False
    env_vars = {}
    parallel_group = "any"

    def build_command(self, project, settings, *, resume=False, extra_args=None):
        return []  # API-driven, not subprocess

    def default_settings(self):
        return {
            "nessus_url": "",
            "nessus_port": NESSUS_DEFAULT_PORT,
            "access_key": "",
            "secret_key": "",
            "scan_name": "",
            "policy_id": None,
            "targets": "",
            "folder_id": None,
            "exclude_targets": "",
            "scan_template": "advanced",
        }

    def settings_schema(self):
        return {"fields": [
            {"key": "nessus_url", "label": "Nessus URL", "type": "text",
             "placeholder": "https://nessus.local"},
            {"key": "nessus_port", "label": "Nessus Port", "type": "number",
             "min": 1, "max": 65535},
            {"key": "access_key", "label": "Access Key", "type": "password"},
            {"key": "secret_key", "label": "Secret Key", "type": "password"},
            {"key": "scan_name", "label": "Scan Name", "type": "text"},
            {"key": "policy_id", "label": "Policy ID", "type": "number"},
            {"key": "targets", "label": "Targets (comma-separated)", "type": "textarea"},
            {"key": "exclude_targets", "label": "Exclude Targets", "type": "textarea"},
            {"key": "folder_id", "label": "Folder ID", "type": "number"},
            {"key": "scan_template", "label": "Scan Template", "type": "select",
             "options": ["basic", "advanced", "discovery", "webapp"]},
        ]}

    def load_findings(self, project_dir, tool_output_dir):
        td = Path(tool_output_dir)
        # Nessus exports land as nessus_findings.json in the project dir
        fp = td / "nessus_findings.json"
        if not fp.exists():
            fp = td / "findings.json"
        if not fp.exists():
            # Check for .nessus XML export converted to JSON
            fp = td / "nessus_export.json"
        if not fp.exists():
            return []
        with open(fp) as f:
            data = json.load(f)
        findings = data if isinstance(data, list) else data.get("findings", [])
        for finding in findings:
            finding.setdefault("tool", "nessus")
            # Normalise Nessus severity integers to risk strings
            if "severity" in finding and "risk" not in finding:
                sev_map = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
                finding["risk"] = sev_map.get(finding["severity"], "INFO")
            # Map plugin_id to nessus_plugin_id for v1.1 schema
            if "plugin_id" in finding and "nessus_plugin_id" not in finding:
                finding["nessus_plugin_id"] = finding["plugin_id"]
            if "plugin_name" in finding and "nessus_plugin_name" not in finding:
                finding["nessus_plugin_name"] = finding["plugin_name"]
        return findings

    def supports_test_connection(self):
        return True

    def test_connection_script(self):
        return None  # Connection test is handled inline via the API
