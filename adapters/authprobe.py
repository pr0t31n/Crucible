"""AuthProbe tool adapter — authentication fingerprinting."""

from adapters.base import ToolAdapter
from config import PYTHON3, TOOL_DIR


class AuthProbeAdapter(ToolAdapter):

    tool_id = "authprobe"
    tool_name = "AuthProbe"
    tool_key = "AP"
    domain = "recon"
    script_path = str(TOOL_DIR / "AuthProbe/authprobe.py")
    requires_sudo = False
    env_vars = {"PYTHONUNBUFFERED": "1"}
    parallel_group = "any"

    def supports_pause(self):
        return False

    def build_command(self, project, settings, *, resume=False,
                      extra_args=None):
        cmd = [PYTHON3, self.script_path]
        url = settings.get("target_url", "")
        if url:
            cmd.extend(["--url", url])
        username = settings.get("username", "")
        if username:
            cmd.extend(["--username", username])
        password = settings.get("password", "")
        if password:
            cmd.extend(["--password", password])
        if settings.get("rendered"):
            cmd.append("--rendered")
        cmd.append("--json")
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    def default_settings(self):
        return {
            "target_url": "",
            "username": "",
            "password": "",
            "rendered": False,
        }

    def settings_schema(self):
        return {"fields": [
            {"key": "target_url", "label": "Target URL", "type": "text",
             "placeholder": "https://target.com/login"},
            {"key": "username", "label": "Username", "type": "text"},
            {"key": "password", "label": "Password", "type": "password"},
            {"key": "rendered", "label": "Use Rendered Mode (headless browser)",
             "type": "checkbox"},
        ]}

    def load_findings(self, project_dir, tool_output_dir):
        return []
