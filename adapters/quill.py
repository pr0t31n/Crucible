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
        app_files = settings.get("app_files", [])
        has_app = False
        if "--app" in ea:
            idx = ea.index("--app")
            if idx + 1 < len(ea):
                cmd.extend(["--app", ea[idx + 1]])
                ea = ea[:idx] + ea[idx + 2:]
                has_app = True
        elif app_files:
            cmd.extend(["--app", app_files[0]])
            has_app = True
        if not has_app and platform == "auto":
            platform = "android"
            cmd[cmd.index("--platform") + 1] = platform
        mode = settings.get("analysis_mode", "static")
        cmd.extend(["--mode", mode])
        frida_on = settings.get("frida_analysis", False)
        mitm_on = settings.get("mitm_analysis", False)
        if mode in ("dynamic", "full") and frida_on:
            if settings.get("frida_device"):
                cmd.extend(["--device", settings["frida_device"]])
            if settings.get("target_process"):
                cmd.extend(["--target-process", settings["target_process"]])
        if mitm_on:
            cmd.append("--mitm")
            mitm_port = settings.get("mitm_port")
            if mitm_port and mitm_port != 8080:
                cmd.extend(["--mitm-port", str(mitm_port)])
            upstream = settings.get("mitm_upstream_proxy", "").strip()
            if upstream:
                cmd.extend(["--mitm-upstream-proxy", upstream])
            burp_ca = settings.get("mitm_burp_ca", "").strip()
            if burp_ca:
                cmd.extend(["--mitm-burp-ca", burp_ca])
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
            "analysis_mode": "static",
            "frida_analysis": False,
            "frida_device": "",
            "target_process": "",
            "mitm_analysis": False,
            "mitm_port": 8080,
            "mitm_upstream_proxy": "",
            "mitm_burp_ca": "",
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
                          "accept": ".apk,.ipa,.aab,.xapk",
                          "depends_on": {"analysis_mode": ["static", "full"]}},
            "analysis_mode": {"label": "Analysis Mode", "type": "select",
                              "options": [
                                  {"value": "static", "label": "Static Only"},
                                  {"value": "dynamic", "label": "Dynamic Only"},
                                  {"value": "full", "label": "Static + Dynamic"},
                              ]},
            "frida_analysis": {"label": "Frida Dynamic Analysis", "type": "checkbox",
                               "hint": "Attach Frida for runtime instrumentation and SSL pinning bypass",
                               "depends_on": {"analysis_mode": ["dynamic", "full"]}},
            "frida_device": {"label": "Device ID", "type": "text",
                             "hint": "Device serial (leave blank for USB)",
                             "depends_on": {"frida_analysis": ["true"]}},
            "target_process": {"label": "Target Process", "type": "text",
                               "hint": "Package name (com.example.app) or bundle ID; "
                                       "auto-detected from binary if provided, otherwise "
                                       "use 'adb shell pm list packages' or 'frida-ps -U'",
                               "depends_on": {"frida_analysis": ["true"]}},
            "mitm_analysis": {"label": "MITM Traffic Capture", "type": "checkbox",
                              "hint": "Capture + analyse traffic via mitmproxy; "
                                      "works standalone or alongside Frida for auto SSL bypass",
                              "depends_on": {"analysis_mode": ["dynamic", "full"]}},
            "mitm_port": {"label": "Proxy Port", "type": "number",
                          "hint": "mitmproxy listen port (default: 8080)",
                          "depends_on": {"mitm_analysis": ["true"]}},
            "mitm_upstream_proxy": {
                "label": "Upstream Proxy",
                "type": "text",
                "hint": "Proxy URL to forward traffic through (e.g. Burp, ZAP, Charles). "
                        "Chain: Device → Quill MITM → Proxy → Internet. "
                        "Leave blank if not using an upstream proxy.",
                "depends_on": {"mitm_analysis": ["true"]}},
            "mitm_burp_ca": {
                "label": "Proxy CA Certificate (cert+key PEM)",
                "type": "text",
                "hint": "Path to your upstream proxy's CA (cert+key PEM). "
                        "When set, Quill signs with this CA so the device "
                        "only needs one CA trusted — no second CA install. "
                        "For Burp: Proxy → Import/Export CA → Certificate and Private Key in PEM.",
                "depends_on": {"mitm_upstream_proxy": ["_nonempty"]}},
        }

    def load_findings(self, project_dir, tool_output_dir):
        return self._load_findings_file(tool_output_dir, "findings.json")
