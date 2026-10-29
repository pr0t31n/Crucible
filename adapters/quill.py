"""Quill adapter — mobile application security analysis."""

from adapters.base import ToolAdapter
from config import TOOL_DIR


class QuillAdapter(ToolAdapter):

    tool_id = "quill"
    tool_name = "Quill"
    tool_key = "QU"
    domain = "mobile"
    script_path = str(TOOL_DIR / "Quill/quill.py")

    def build_command(self, project, settings, *, resume=False, extra_args=None):
        cmd = ["python3", self.script_path]
        platform = settings.get("mobile_platform", "auto")
        cmd.extend(["--platform", platform])
        td = project.get("tool_dirs", {}).get("quill", "")
        scope = project.get("_launch_scope", "")
        if td and scope and scope.startswith("file:"):
            import os
            fname = scope.split(":", 1)[1]
            file_dir = os.path.join(td, fname)
            os.makedirs(file_dir, exist_ok=True)
            cmd.extend(["--project", file_dir])
            project["_scope_tool_dir"] = file_dir
        elif td:
            cmd.extend(["--project", td])
        ea = list(extra_args or [])
        if "--app" in ea:
            idx = ea.index("--app")
            if idx + 1 < len(ea):
                cmd.extend(["--app", ea[idx + 1]])
                ea = ea[:idx] + ea[idx + 2:]
        else:
            app_files = settings.get("app_files", [])
            if app_files:
                cmd.extend(["--app", app_files[0]])
        if settings.get("dynamic_analysis"):
            cmd.append("--dynamic")
        if settings.get("frida_device"):
            cmd.extend(["--frida-device", settings["frida_device"]])
        if settings.get("mitm_analysis"):
            cmd.append("--mitm")
            mitm_dur = settings.get("mitm_duration")
            if mitm_dur and mitm_dur != 120:
                cmd.extend(["--mitm-duration", str(mitm_dur)])
            mitm_port = settings.get("mitm_port")
            if mitm_port and mitm_port != 8080:
                cmd.extend(["--mitm-port", str(mitm_port)])
        cmd.extend(["--client-short", project.get("client_short", "")])
        if ea:
            cmd.extend(ea)
        return cmd

    def expand_queue_entries(self, settings):
        """Return per-file queue kwargs when multiple app files are configured."""
        app_files = settings.get("app_files", [])
        if len(app_files) <= 1:
            return None
        import os
        entries = []
        for af in app_files:
            fname = os.path.basename(af)
            entries.append({
                "extra_args": ["--app", af],
                "scope": f"file:{fname}",
                "label": fname,
            })
        return entries

    def default_settings(self):
        return {
            "mobile_platform": "auto",
            "app_files": [],
            "dynamic_analysis": False,
            "frida_device": "",
            "check_permissions": True,
            "check_hardening": True,
            "check_data_storage": True,
            "check_network": True,
            "check_crypto": True,
            "decompile": True,
            "threads": 4,
            "mitm_analysis": False,
            "mitm_duration": 120,
            "mitm_port": 8080,
        }

    def settings_schema(self):
        return {
            "mobile_platform": {"label": "Platform", "type": "select",
                                "options": [
                                    {"value": "auto", "label": "Auto-Detect"},
                                    {"value": "android", "label": "Android"},
                                    {"value": "ios", "label": "iOS"},
                                ]},
            "app_files": {"label": "Application Files", "type": "file_list",
                          "hint": "Upload APK, IPA, or AAB files",
                          "accept": ".apk,.ipa,.aab,.xapk"},
            "dynamic_analysis": {"label": "Enable Dynamic Analysis", "type": "checkbox",
                                 "hint": "Requires Frida and a connected device/emulator"},
            "frida_device": {"label": "Frida Device ID", "type": "text",
                             "hint": "Device serial for dynamic analysis"},
            "check_permissions": {"label": "Check Permissions", "type": "checkbox"},
            "check_hardening": {"label": "Check Binary Hardening", "type": "checkbox"},
            "check_data_storage": {"label": "Check Data Storage", "type": "checkbox"},
            "check_network": {"label": "Check Network Security", "type": "checkbox"},
            "check_crypto": {"label": "Check Cryptography", "type": "checkbox"},
            "decompile": {"label": "Decompile Application", "type": "checkbox"},
            "threads": {"label": "Threads", "type": "number", "advanced": True},
            "mitm_analysis": {"label": "Enable MITM Traffic Analysis", "type": "checkbox",
                              "hint": "Capture + analyse live traffic via mitmproxy + Frida SSL bypass"},
            "mitm_duration": {"label": "MITM Capture Duration (sec)", "type": "number",
                              "hint": "How long to capture traffic (default: 120)"},
            "mitm_port": {"label": "MITM Proxy Port", "type": "number",
                          "hint": "mitmproxy listen port (default: 8080)"},
        }

    def load_findings(self, project_dir, tool_output_dir):
        return self._load_findings_file(tool_output_dir, "findings.json")
