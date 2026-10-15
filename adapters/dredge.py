"""DredgeAdapter — Crucible adapter for the Dredge endpoint security auditor."""

from pathlib import Path

from adapters.base import ToolAdapter


def _detect_collection(path_str):
    """Detect what kind of Dredge collection lives at the given path.

    Returns (collection_path, collection_type) where type is one of:
        "cmd_dir"  — CMD batch output directory (has _sections.txt / meta.txt)
        "ps1_json" — PS1 collection JSON file
        None       — nothing recognisable found
    """
    p = Path(path_str)

    if p.is_file() and p.suffix.lower() == ".json":
        return str(p), "ps1_json"

    if p.is_dir():
        if (p / "_sections.txt").exists() or (p / "meta.txt").exists():
            return str(p), "cmd_dir"

        has_subdirs = any(
            d.is_dir() for d in p.iterdir()
            if d.name in ("system_info", "registry_hardening", "user_accounts",
                          "network_config", "processes", "services")
        )
        if has_subdirs:
            return str(p), "cmd_dir"

        for candidate in sorted(p.glob("*.json")):
            try:
                import json
                with open(candidate) as f:
                    data = json.load(f)
                if isinstance(data, dict) and (
                    "system_info" in data
                    or "dredge_version" in data
                    or "collection_timestamp" in data
                    or "sections_collected" in data
                ):
                    return str(candidate), "ps1_json"
            except Exception:
                continue

    return None, None


class DredgeAdapter(ToolAdapter):

    tool_id = "dredge"
    tool_name = "Dredge"
    tool_key = "DG"
    domain = "endpoint"
    script_path = "/opt/pr0t31n/Dredge/dredge.py"
    requires_sudo = False
    env_vars = {"CRUCIBLE_MANAGED": "1", "PYTHONUNBUFFERED": "1"}
    parallel_group = "any"

    def supports_pause(self):
        return True

    def build_command(self, project, settings, *, resume=False, extra_args=None):
        cmd = ["python3", self.script_path]

        collection = settings.get("collection_path", "").strip()
        winrm_host = settings.get("winrm_host", "")

        if winrm_host:
            cmd += ["--winrm-host", winrm_host]
            if settings.get("winrm_user"):
                cmd += ["--winrm-user", settings["winrm_user"]]
            if settings.get("winrm_pass"):
                cmd += ["--winrm-pass", settings["winrm_pass"]]
            port = settings.get("winrm_port", 5985)
            if port and int(port) != 5985:
                cmd += ["--winrm-port", str(port)]
            if settings.get("winrm_ssl"):
                cmd += ["--winrm-ssl"]
        elif collection:
            resolved, ctype = _detect_collection(collection)
            if resolved:
                cmd += ["--collection", resolved]

        td = project.get("tool_dirs", {}).get("dredge", "")
        if td:
            cmd.extend(["--output-dir", td])
        else:
            eng_dir = project.get("engagement_dir",
                                  project.get("project_dir", ""))
            if eng_dir:
                cmd += ["--output-dir", eng_dir]

        client = project.get("client_short", project.get("client", ""))
        if client:
            cmd += ["--client", client]

        if settings.get("vt_api_key"):
            cmd += ["--vt-api-key", settings["vt_api_key"]]
        if settings.get("abuseipdb_key"):
            cmd += ["--abuseipdb-key", settings["abuseipdb_key"]]

        skip = settings.get("skip_sections", "")
        if skip:
            cmd += ["--skip-analyzers"] + [s.strip()
                                           for s in skip.split(",") if s.strip()]

        if extra_args:
            cmd += extra_args

        return cmd

    def default_settings(self):
        return {
            "collection_path": "",
            "winrm_host": "",
            "winrm_user": "",
            "winrm_pass": "",
            "winrm_port": 5985,
            "winrm_ssl": False,
            "vt_api_key": "",
            "abuseipdb_key": "",
            "skip_sections": "",
        }

    def settings_schema(self):
        return {
            "fields": [
                {"key": "collection_path",
                 "label": "Collection Path (JSON file or CMD batch directory)",
                 "type": "file", "required": False,
                 "placeholder": "/path/to/collection.json or /path/to/dredge_cmd_HOST_TS/",
                 "help": "PS1 collection JSON file, CMD batch output directory, "
                         "or a folder containing either. Auto-detected."},
                {"key": "winrm_host", "label": "WinRM Host (optional)",
                 "type": "text", "placeholder": "10.0.0.50 or hostname"},
                {"key": "winrm_user", "label": "WinRM Username",
                 "type": "text", "placeholder": "Administrator"},
                {"key": "winrm_pass", "label": "WinRM Password",
                 "type": "password"},
                {"key": "winrm_port", "label": "WinRM Port",
                 "type": "number", "default": 5985},
                {"key": "winrm_ssl", "label": "WinRM SSL",
                 "type": "checkbox", "default": False},
                {"key": "vt_api_key", "label": "VirusTotal API Key (optional)",
                 "type": "password"},
                {"key": "abuseipdb_key", "label": "AbuseIPDB Key (optional)",
                 "type": "password"},
                {"key": "skip_sections", "label": "Skip Analyzers",
                 "type": "text",
                 "placeholder": "ad,browser (comma-separated)"},
            ]
        }

    def from_tool_format(self, settings):
        if "collection_file" in settings and "collection_path" not in settings:
            settings["collection_path"] = settings.pop("collection_file")
        return settings

    def validate_launch(self, project, settings):
        collection = settings.get("collection_path", "").strip()
        winrm_host = settings.get("winrm_host", "").strip()
        if not collection and not winrm_host:
            return False, "Provide a collection path or WinRM host"
        if collection:
            p = Path(collection)
            if not p.exists():
                return False, f"Collection path not found: {collection}"
            resolved, ctype = _detect_collection(collection)
            if resolved is None:
                return False, (f"Cannot detect Dredge collection at {collection}. "
                               "Expected a PS1 JSON file or CMD batch directory "
                               "(with _sections.txt or system_info/ etc.)")
        return True, ""

    def load_findings(self, project_dir, tool_output_dir):
        return self._load_multitarget_findings(tool_output_dir)
