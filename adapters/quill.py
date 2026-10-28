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
        platform = settings.get("mobile_platform", "android")
        cmd.extend(["--platform", platform])
        td = project.get("tool_dirs", {}).get("quill", "")
        if td:
            cmd.extend(["--project", td])
        app_files = settings.get("app_files", [])
        for af in app_files:
            cmd.extend(["--app", af])
        if settings.get("dynamic_analysis"):
            cmd.append("--dynamic")
        if settings.get("frida_device"):
            cmd.extend(["--frida-device", settings["frida_device"]])
        cmd.extend(["--client-short", project.get("client_short", "")])
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    def default_settings(self):
        return {
            "mobile_platform": "android",
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
        }

    def settings_schema(self):
        return {
            "mobile_platform": {"label": "Platform", "type": "select",
                                "options": ["android", "ios", "both"]},
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
        }

    def load_findings(self, project_dir, tool_output_dir):
        return self._load_findings_file(tool_output_dir, "findings.json")
