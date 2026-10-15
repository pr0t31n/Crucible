"""Isotope adapter — detailed file analysis."""

from pathlib import Path

from adapters.base import ToolAdapter
from config import TOOL_DIR

PYTHON3 = "python3"


class IsotopeAdapter(ToolAdapter):

    tool_id = "isotope"
    tool_name = "Isotope"
    tool_key = "IS"
    domain = "file"
    script_path = str(TOOL_DIR / "Isotope/isotope.py")

    def validate_launch(self, project, settings):
        project_dir = Path(project.get("project_dir", ""))
        tool_dir = (project.get("tool_dirs") or {}).get("isotope")
        scope = self._normalize_scope(project.get("_launch_scope"))
        settings_path = self._find_settings(project_dir, tool_dir, scope, "is")
        if not settings_path.exists():
            return False, f"Settings file not found: {settings_path}"
        return True, ""

    def build_command(self, project, settings, *, resume=False, extra_args=None):
        project_dir = Path(project.get("project_dir", ""))
        tool_dir = (project.get("tool_dirs") or {}).get("isotope")
        scope = self._normalize_scope(project.get("_launch_scope"))
        settings_path = self._find_settings(project_dir, tool_dir, scope, "is")
        cmd = [PYTHON3, self.script_path, "--settings", str(settings_path)]
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    @staticmethod
    def _find_settings(project_dir, tool_dir, scope, prefix):
        candidates = []
        for base in ([Path(tool_dir)] if tool_dir else []) + [project_dir]:
            if scope:
                candidates.append(base / f"{prefix}_settings_{scope}.json")
            candidates.append(base / f"{prefix}_settings.json")
        for p in candidates:
            if p.exists():
                return p
        return candidates[0]

    def default_settings(self):
        return {
            "target_files": [],
            "modules": ["identification", "entropy", "strings", "code",
                        "metadata", "binary", "secrets", "hashing", "archive"],
            "archive_depth": 5,
            "max_string_length": 256,
            "min_string_length": 4,
            "entropy_block_size": 256,
            "hash_algorithms": "md5,sha1,sha256",
        }

    def settings_schema(self):
        return {"fields": [
            {"key": "modules", "label": "Analysis Modules",
             "type": "tags",
             "placeholder": "identification, entropy, strings, code, metadata, binary, secrets, hashing, archive"},
            {"key": "archive_depth", "label": "Archive Extraction Depth",
             "type": "number", "required": False},
            {"key": "hash_algorithms", "label": "Hash Algorithms",
             "type": "text", "required": False,
             "placeholder": "md5,sha1,sha256,sha512"},
        ]}

    def load_findings(self, project_dir, tool_output_dir):
        return self._load_findings_file(tool_output_dir, "findings.json")
