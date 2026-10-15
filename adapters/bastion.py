"""Bastion adapter — firewall configuration audit."""

from adapters.base import ToolAdapter
from config import TOOL_DIR


class BastionAdapter(ToolAdapter):

    tool_id = "bastion"
    tool_name = "Bastion"
    tool_key = "BA"
    domain = "firewall"
    script_path = str(TOOL_DIR / "Bastion/bastion.py")

    def build_command(self, project, settings, *, resume=False, extra_args=None):
        cmd = ["python3", self.script_path]
        vendor = settings.get("firewall_vendor", "palo_alto")
        cmd.extend(["--vendor", vendor])
        td = project.get("tool_dirs", {}).get("bastion", "")
        if td:
            cmd.extend(["--output-dir", td])
        config_dir = settings.get("config_dir", "")
        if config_dir:
            cmd.extend(["--config-dir", config_dir])
        else:
            configs = settings.get("config_files", [])
            for cf in configs:
                cmd.extend(["--config", cf])
        if settings.get("skip_threat_intel"):
            cmd.append("--skip-threat-intel")
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    def default_settings(self):
        return {
            "firewall_vendor": "palo_alto",
            "config_files": [],
            "audit_rules": "default",
            "check_zones": True,
            "check_compliance": True,
            "check_shadowed": True,
            "check_permissive": True,
            "max_rules": 50000,
        }

    def settings_schema(self):
        return {
            "firewall_vendor": {"label": "Firewall Vendor", "type": "select",
                                "options": ["palo_alto", "cisco", "fortigate",
                                            "checkpoint", "juniper", "sophos", "other"]},
            "config_files": {"label": "Configuration Files", "type": "file_list",
                             "hint": "Upload firewall configuration files",
                             "accept": ".xml,.conf,.cfg,.txt,.json"},
            "audit_rules": {"label": "Audit Rule Set", "type": "select",
                            "options": ["default", "strict", "pci", "nist"]},
            "check_zones": {"label": "Check Zone Segmentation", "type": "checkbox"},
            "check_compliance": {"label": "Check Policy Compliance", "type": "checkbox"},
            "check_shadowed": {"label": "Detect Shadowed Rules", "type": "checkbox"},
            "check_permissive": {"label": "Flag Overly Permissive Rules", "type": "checkbox"},
            "max_rules": {"label": "Max Rules to Analyze", "type": "number", "advanced": True},
        }

    def load_findings(self, project_dir, tool_output_dir):
        return self._load_findings_file(tool_output_dir, "findings.json")
