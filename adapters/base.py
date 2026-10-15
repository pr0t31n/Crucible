"""ToolAdapter — abstract base class for all tool adapters."""

import json
import subprocess
import sys
from abc import ABC, abstractmethod
from pathlib import Path


class ToolAdapter(ABC):

    tool_id: str = ""
    tool_name: str = ""
    tool_key: str = ""
    domain: str = ""
    script_path: str = ""
    requires_sudo: bool = False
    env_vars: dict = {}
    parallel_group: str = "any"

    @abstractmethod
    def build_command(self, project, settings, *, resume=False,
                      extra_args=None):
        ...

    @abstractmethod
    def default_settings(self):
        ...

    @abstractmethod
    def settings_schema(self):
        ...

    @abstractmethod
    def load_findings(self, project_dir, tool_output_dir):
        ...

    def parse_token(self, token_type, payload):
        return payload

    def load_action_items(self, project_dir, tool_output_dir):
        fp = Path(tool_output_dir) / "action_items.json"
        if fp.exists():
            with open(fp) as f:
                return json.load(f)
        return []

    def normalize_finding(self, finding):
        return finding

    def post_exit_cleanup(self, project_dir):
        pass

    def to_tool_format(self, settings):
        """Transform flat UI settings into the format the tool's settings file expects.
        Override in adapters whose tools expect a different layout."""
        return settings

    def from_tool_format(self, settings):
        """Transform a tool's native settings-file format into flat UI keys.
        Inverse of to_tool_format()."""
        return settings

    def validate_launch(self, project, settings):
        """Check prerequisites before launching. Returns (ok, reason_str)."""
        if self.script_path and not Path(self.script_path).exists():
            return False, (f"{self.tool_name} is not installed. "
                           f"Run Arsenal to install it.")
        return True, ""

    def supports_resume(self):
        return False

    def supports_pause(self):
        return False

    def supports_test_connection(self):
        return False

    def test_connection_script(self):
        return None

    # ── shared helpers for subclasses ────────────────────────

    _SCOPE_SHORT = {"internal": "int", "external": "ext"}

    @staticmethod
    def _normalize_scope(scope):
        """Normalize long-form scope names to short CLI form (int/ext)."""
        if not scope:
            return scope
        return ToolAdapter._SCOPE_SHORT.get(scope, scope)

    def _load_findings_file(self, tool_output_dir, *filenames):
        """Load findings from the first matching JSON file in tool_output_dir.
        Sets tool_id on each finding."""
        td = Path(tool_output_dir)
        for name in filenames:
            fp = td / name
            if fp.exists():
                with open(fp) as f:
                    data = json.load(f)
                items = data if isinstance(data, list) else data.get("findings", [])
                for item in items:
                    if not item.get("tool"):
                        item["tool"] = self.tool_id
                    item["_source_file"] = str(fp)
                return items
        return []

    def _load_multitarget_findings(self, tool_output_dir):
        """Load findings from root findings.json + per-target subdirectories."""
        findings = []
        td = Path(tool_output_dir)
        fp = td / "findings.json"
        if fp.exists():
            with open(fp) as f:
                data = json.load(f)
            items = data if isinstance(data, list) else data.get("findings", [])
            for finding in items:
                if not finding.get("tool"):
                    finding["tool"] = self.tool_id
                finding["_source_file"] = str(fp)
                findings.append(finding)
        if td.is_dir():
            for subdir in sorted(td.iterdir()):
                if subdir.is_dir() and (subdir / "findings.json").exists():
                    sfp = subdir / "findings.json"
                    with open(sfp) as f:
                        data = json.load(f)
                    items = (data if isinstance(data, list)
                             else data.get("findings", []))
                    _sd_name = subdir.name
                    for finding in items:
                        if not finding.get("tool"):
                            finding["tool"] = self.tool_id
                        finding.setdefault("target_dir", _sd_name)
                        finding["_source_file"] = str(sfp)
                        _of = (finding.get("output_file") or "").strip()
                        if _of and not _of.startswith("/"):
                            if _of.startswith("["):
                                try:
                                    _arr = json.loads(_of)
                                    for _it in _arr:
                                        for _k in ("req", "resp", "log", "path", "file"):
                                            _v = _it.get(_k, "")
                                            if _v and not _v.startswith("/") and not _v.startswith(_sd_name + "/"):
                                                _it[_k] = f"{_sd_name}/{_v}"
                                    finding["output_file"] = json.dumps(_arr)
                                except (json.JSONDecodeError, TypeError):
                                    pass
                            elif not _of.startswith(_sd_name + "/"):
                                import re as _re_of
                                _parts = []
                                for _p in _re_of.split(r"[,\n]", _of):
                                    _p = _p.strip()
                                    if _p and not _p.startswith("/") and not _p.startswith(_sd_name + "/"):
                                        _p = f"{_sd_name}/{_p}"
                                    if _p:
                                        _parts.append(_p)
                                if _parts:
                                    finding["output_file"] = ",".join(_parts)
                        findings.append(finding)
        return findings

    def _kill_stale_processes(self, proc_names):
        """Kill straggler processes by name (Linux only)."""
        if sys.platform != "linux":
            return
        for name in proc_names:
            try:
                subprocess.run(["pkill", "-f", name],
                               capture_output=True, timeout=5)
            except Exception:
                pass
