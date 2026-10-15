"""Forge adapter — cloud infrastructure security audit."""

from adapters.base import ToolAdapter
from config import TOOL_DIR


class ForgeAdapter(ToolAdapter):

    tool_id = "forge"
    tool_name = "Forge"
    tool_key = "FG"
    domain = "cloud"
    script_path = str(TOOL_DIR / "Forge/forge.py")
    parallel_group = "exclusive"

    def build_command(self, project, settings, *, resume=False, extra_args=None):
        cmd = ["python3", self.script_path]
        provider = settings.get("cloud_provider", "aws")
        cmd.extend(["--provider", provider])
        if settings.get("aws_profile"):
            cmd.extend(["--aws-profile", settings["aws_profile"]])
        if settings.get("aws_region"):
            cmd.extend(["--aws-region", settings["aws_region"]])
        if settings.get("azure_subscription"):
            cmd.extend(["--azure-subscription", settings["azure_subscription"]])
        if settings.get("gcp_project"):
            cmd.extend(["--gcp-project", settings["gcp_project"]])
        td = project.get("tool_dirs", {}).get("forge", "")
        if td:
            cmd.extend(["--output", td])
        cmd.extend(["--client-short", project.get("client_short", "")])
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    def default_settings(self):
        return {
            "cloud_provider": "aws",
            "aws_profile": "", "aws_region": "",
            "azure_subscription": "", "azure_tenant": "",
            "gcp_project": "", "gcp_key_file": "",
            "scan_iam": True, "scan_storage": True,
            "scan_compute": True, "scan_network": True,
            "scan_secrets": True, "scan_logging": True,
            "threads": 4, "timeout": 120,
        }

    def settings_schema(self):
        return {
            "cloud_provider": {"label": "Cloud Provider", "type": "select",
                               "options": ["aws", "azure", "gcp"]},
            "aws_profile": {"label": "AWS Profile", "type": "text",
                            "hint": "Named profile from ~/.aws/credentials"},
            "aws_region": {"label": "AWS Region", "type": "text",
                           "hint": "e.g. us-east-1"},
            "azure_subscription": {"label": "Azure Subscription ID", "type": "text"},
            "azure_tenant": {"label": "Azure Tenant ID", "type": "text"},
            "gcp_project": {"label": "GCP Project ID", "type": "text"},
            "gcp_key_file": {"label": "GCP Service Account Key File", "type": "text",
                             "hint": "Path to JSON key file"},
            "scan_iam": {"label": "Scan IAM", "type": "checkbox"},
            "scan_storage": {"label": "Scan Storage", "type": "checkbox"},
            "scan_compute": {"label": "Scan Compute", "type": "checkbox"},
            "scan_network": {"label": "Scan Network", "type": "checkbox"},
            "scan_secrets": {"label": "Scan Secrets Manager", "type": "checkbox"},
            "scan_logging": {"label": "Scan Logging/Monitoring", "type": "checkbox"},
            "threads": {"label": "Threads", "type": "number", "advanced": True},
            "timeout": {"label": "Timeout (s)", "type": "number", "advanced": True},
        }

    def load_findings(self, project_dir, tool_output_dir):
        return self._load_findings_file(tool_output_dir, "findings.json")
