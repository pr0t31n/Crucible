"""Shared base for all Aether-family wireless adapters."""

from pathlib import Path

from adapters.base import ToolAdapter
from config import PYTHON3


class AetherBaseAdapter(ToolAdapter):
    domain = "wireless"
    requires_sudo = False
    parallel_group = "exclusive"
    _settings_prefix: str = ""

    @property
    def env_vars(self):
        return {"CRUCIBLE_MANAGED": "1", "CRUCIBLE_TOOL_ID": self.tool_id,
                "PYTHONUNBUFFERED": "1"}

    def supports_pause(self):
        return True

    def build_command(self, project, settings, *, resume=False, extra_args=None):
        config_path = Path(project.get("project_dir", "")) / f"{self._settings_prefix}_settings.json"
        session_dir = project.get("tool_dirs", {}).get(self.tool_id, "")
        cmd = [PYTHON3, self.script_path, "--config", str(config_path),
               "--project", str(session_dir)]
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    def load_findings(self, project_dir, tool_output_dir):
        return self._load_findings_file(tool_output_dir, "findings.json")
