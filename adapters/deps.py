"""Adapter for the Dependencies console — catchall for external CLI tools."""

import shutil
from datetime import datetime
from pathlib import Path

from adapters.base import ToolAdapter

_TS = lambda: datetime.now().strftime("%Y%m%d_%H%M%S")


class _ExternalBase(ToolAdapter):
    is_external = True

    def load_findings(self, project_dir, tool_output_dir):
        return []

    def default_settings(self):
        return {}


class DepsAdapter(_ExternalBase):
    tool_id = "deps"
    tool_name = "Dependencies"
    tool_key = "DP"
    domain = "deps"

    _DEP_TOOLS = {
        "o365spray": {"binary": "o365spray", "name": "o365spray"},
    }

    def settings_schema(self):
        return {"fields": [
            {"key": "dep_tool", "label": "Dependency Tool", "type": "select",
             "options": sorted(self._DEP_TOOLS.keys())},
        ]}

    def build_command(self, project, settings, *, resume=False,
                      extra_args=None):
        dep_tool = settings.get("dep_tool", "")
        builder = getattr(self, f"_build_{dep_tool.replace('-', '_')}_cmd", None)
        if builder:
            return builder(project, settings, extra_args)
        return []

    def _build_o365spray_cmd(self, project, settings, extra_args=None):
        binary = shutil.which("o365spray")
        if not binary:
            return []
        domain = settings.get("target", "")
        email_file = settings.get("email_file", "")
        td = (project.get("tool_dirs") or {}).get("deps", "")
        cmd = [binary, "--enum"]
        if email_file:
            cmd.extend(["-U", str(email_file)])
        if domain:
            cmd.extend(["--domain", domain])
        if td:
            out_dir = str(Path(td) / f"o365spray_{_TS()}")
            cmd.extend(["--output", out_dir])
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    def prepare_email_file(self, project, emails, scope="external"):
        """Write harvested emails to a file in the deps output dir.

        Returns the file path or None.
        """
        td = (project.get("tool_dirs") or {}).get("deps", "")
        if not td:
            return None
        td_path = Path(td)
        td_path.mkdir(parents=True, exist_ok=True)
        email_file = td_path / f"o365_emails_{_TS()}.txt"
        email_file.write_text("\n".join(sorted(set(emails))) + "\n")
        return str(email_file)
