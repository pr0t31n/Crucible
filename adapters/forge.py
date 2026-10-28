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
            cmd.extend(["--project", td])
        cmd.extend(["--client-short", project.get("client_short", "")])
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    def build_env(self, project, settings):
        """Pass AWS credentials via environment to avoid ps visibility."""
        env = {}
        if settings.get("aws_access_key_id"):
            env["FORGE_AWS_ACCESS_KEY_ID"] = settings["aws_access_key_id"]
        if settings.get("aws_secret_key"):
            env["FORGE_AWS_SECRET_KEY"] = settings["aws_secret_key"]
        if settings.get("aws_console_url"):
            env["FORGE_AWS_CONSOLE_URL"] = settings["aws_console_url"]
        if settings.get("aws_console_user"):
            env["FORGE_AWS_CONSOLE_USER"] = settings["aws_console_user"]
        if settings.get("aws_console_pass"):
            env["FORGE_AWS_CONSOLE_PASS"] = settings["aws_console_pass"]
        return env

    def default_settings(self):
        return {
            "cloud_provider": "aws",
            "aws_auth_method": "profile",
            "aws_profile": "", "aws_region": "",
            "aws_access_key_id": "", "aws_secret_key": "",
            "aws_console_url": "", "aws_console_user": "", "aws_console_pass": "",
            "azure_subscription": "", "azure_tenant": "",
            "gcp_project": "", "gcp_key_file": "",
            "scan_iam": True, "scan_storage": True,
            "scan_compute": True, "scan_network": True,
            "scan_secrets": True, "scan_logging": True,
            "threads": 4, "timeout": 120,
        }

    def settings_schema(self):
        _aws = {"cloud_provider": ["aws"]}
        _azure = {"cloud_provider": ["azure"]}
        _gcp = {"cloud_provider": ["gcp"]}
        _aws_profile = {"cloud_provider": ["aws"], "aws_auth_method": ["profile"]}
        _aws_keys = {"cloud_provider": ["aws"], "aws_auth_method": ["keys"]}
        _aws_console = {"cloud_provider": ["aws"], "aws_auth_method": ["console"]}
        return {
            "cloud_provider": {"label": "Cloud Provider", "type": "select",
                               "options": ["aws", "azure", "gcp"]},
            "aws_auth_method": {"label": "AWS Authentication", "type": "select",
                                "options": [
                                    {"value": "profile", "label": "CLI Profile"},
                                    {"value": "keys", "label": "Access Keys"},
                                    {"value": "console", "label": "Console Login"},
                                ],
                                "depends_on": _aws},
            "aws_region": {"label": "AWS Region", "type": "text",
                           "hint": "e.g. us-east-1",
                           "depends_on": _aws},
            "aws_profile": {"label": "AWS CLI Profile", "type": "text",
                            "hint": "Named profile from ~/.aws/credentials",
                            "depends_on": _aws_profile},
            "aws_access_key_id": {"label": "AWS Access Key ID", "type": "text",
                                  "hint": "From IAM → Users → Security credentials",
                                  "depends_on": _aws_keys},
            "aws_secret_key": {"label": "AWS Secret Access Key", "type": "password",
                               "hint": "Paired with access key ID above",
                               "depends_on": _aws_keys},
            "aws_console_url": {"label": "AWS Console Sign-In URL", "type": "text",
                                "hint": "e.g. https://123456789012.signin.aws.amazon.com/console",
                                "depends_on": _aws_console},
            "aws_console_user": {"label": "AWS Console Username", "type": "text",
                                 "hint": "IAM username for console login",
                                 "depends_on": _aws_console},
            "aws_console_pass": {"label": "AWS Console Password", "type": "password",
                                 "hint": "IAM password — used once to create temp access keys",
                                 "depends_on": _aws_console},
            "azure_subscription": {"label": "Azure Subscription ID", "type": "text",
                                   "depends_on": _azure},
            "azure_tenant": {"label": "Azure Tenant ID", "type": "text",
                             "depends_on": _azure},
            "gcp_project": {"label": "GCP Project ID", "type": "text",
                            "depends_on": _gcp},
            "gcp_key_file": {"label": "GCP Service Account Key File", "type": "text",
                             "hint": "Path to JSON key file",
                             "depends_on": _gcp},
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
