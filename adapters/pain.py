"""PainAdapter — pAIn (AI pipeline prompt-injection) tool adapter for Crucible v2.0."""

from pathlib import Path
import json
from adapters.base import ToolAdapter
from config import PYTHON3, TOOL_DIR


class PainAdapter(ToolAdapter):

    tool_id = "pain"
    tool_name = "pAIn"
    tool_key = "PI"
    domain = "ai"
    script_path = str(TOOL_DIR / "pAIn/pain.py")
    requires_sudo = False
    env_vars = {"CRUCIBLE_MANAGED": "1", "PYTHONUNBUFFERED": "1"}
    parallel_group = "any"

    # ── command builder ─────────────────────────────────────────

    def build_command(self, project, settings, *, resume=False,
                      extra_args=None):
        project_dir = Path(project.get("project_dir", ""))
        tool_dir = (project.get("tool_dirs") or {}).get("pain")
        scope = self._normalize_scope(project.get("_launch_scope"))
        settings_path = self._find_settings(project_dir, tool_dir, scope, "pi")

        merged = dict(self.default_settings())
        if settings_path.exists():
            try:
                merged.update(json.loads(settings_path.read_text()))
            except Exception:
                pass
        merged.update({k: v for k, v in (settings or {}).items() if v})

        target_url = merged.get("target_url", "")
        if not target_url:
            target_url = project.get("target_url", "")

        config = self._build_pain_config(merged, target_url, project)

        config_path = project_dir / "pi_config.json"
        config_path.write_text(json.dumps(config, indent=2))

        out_dir = ""
        if tool_dir:
            out_dir = tool_dir
        else:
            out_dir = str(project_dir / "pain")

        cmd = [PYTHON3, self.script_path,
               "--target", str(config_path),
               "--output", out_dir]

        modules = merged.get("modules", "")
        if modules and modules != "all":
            cmd.extend(["--categories", modules])

        formats = merged.get("formats", "all")
        if formats and formats != "all":
            cmd.extend(["--formats", formats])

        ai_type = merged.get("ai_type", "auto")
        if ai_type and ai_type != "auto":
            cmd.extend(["--ai-type", ai_type])

        if merged.get("all_variants"):
            cmd.append("--all-variants")
        if merged.get("whisper_mode"):
            cmd.append("--whisper-mode")
        if merged.get("nuclei_ai"):
            cmd.append("--nuclei-ai")
        if not merged.get("verify_ssl", True):
            cmd.append("--no-ssl-verify")

        model = merged.get("model", "")
        if model:
            cmd.extend(["--model", model])

        if extra_args:
            cmd.extend(extra_args)
        return cmd

    def _build_pain_config(self, settings, target_url, project):
        """Build pAIn config JSON from Crucible project settings,
        passing through all auth details from the project."""
        config = {
            "endpoint": target_url,
            "timeout": settings.get("timeout", 30),
            "verify_ssl": settings.get("verify_ssl", True),
        }

        auth = settings.get("auth", {})
        if not auth:
            auth = {}

        method = auth.get("method", settings.get("auth_method", "none"))

        if method == "bearer":
            token = (auth.get("auth_token") or auth.get("token")
                     or settings.get("bearer_token", ""))
            if token:
                config.setdefault("auth", {})["type"] = "bearer"
                config["auth"]["token"] = token
        elif method == "cookie":
            cookie = (auth.get("session_cookie") or auth.get("cookie_value")
                      or settings.get("cookie", ""))
            if cookie:
                config.setdefault("auth", {})["type"] = "cookie"
                config["auth"]["token"] = cookie
        elif method == "apikey":
            api_key = (auth.get("api_key") or settings.get("api_key", ""))
            key_name = (auth.get("api_key_header") or auth.get("api_key_name")
                        or "X-API-Key")
            if api_key:
                config.setdefault("extra_headers", {})[key_name] = api_key
        elif method == "basic":
            username = auth.get("username") or settings.get("username", "")
            password = auth.get("password") or settings.get("password", "")
            if username:
                config.setdefault("auth", {})["type"] = "form"
                config["auth"]["username"] = username
                config["auth"]["password"] = password
        elif method == "form_login":
            username = auth.get("username") or settings.get("username", "")
            password = auth.get("password") or settings.get("password", "")
            login_url = auth.get("login_url") or settings.get("login_url", "")
            if login_url:
                config["login_url"] = login_url
                config.setdefault("auth", {})["type"] = "form"
                config["auth"]["username"] = username
                config["auth"]["password"] = password
                csrf = auth.get("csrf_field", "")
                if csrf:
                    config["auth"]["csrf_field"] = csrf
        elif method == "custom":
            custom_headers = auth.get("custom_headers", {})
            if custom_headers:
                config.setdefault("extra_headers", {}).update(custom_headers)

        auth_header = settings.get("auth_header", "")
        if auth_header and ":" in auth_header:
            k, _, v = auth_header.partition(":")
            config.setdefault("extra_headers", {})[k.strip()] = v.strip()

        extra_headers = auth.get("custom_headers") or settings.get("extra_headers") or {}
        if extra_headers:
            config.setdefault("extra_headers", {}).update(extra_headers)

        upload_url = settings.get("upload_url", "")
        if upload_url:
            config["upload_url"] = upload_url

        verify_url = settings.get("verify_url", "")
        if verify_url:
            config["verify"] = {
                "url": verify_url,
                "delay": settings.get("verify_delay", 3),
            }

        file_field = settings.get("file_field", "")
        if file_field:
            config["file_field"] = file_field
        resp_field = settings.get("resp_field", "")
        if resp_field:
            config["response_field"] = resp_field

        proxy = settings.get("proxy") or project.get("proxy", "")
        if proxy:
            config["proxy"] = proxy

        return config

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

    # ── default settings ────────────────────────────────────────

    def default_settings(self):
        return {
            "target_url": "",
            "output_dir": "",
            "ai_type": "auto",
            "model": "",
            "formats": "all",
            "modules": "all",
            "timeout": 30,
            "verify_ssl": True,
            "all_variants": False,
            "whisper_mode": False,
            "nuclei_ai": False,
            "file_field": "file",
            "resp_field": "text",
            "upload_url": "",
            "verify_url": "",
            "verify_delay": 3,
            "proxy": "",
            "auth_method": "none",
            "auth": {
                "method": "none",
                "auth_token": "", "token_type": "Bearer",
                "username": "", "password": "",
                "api_key": "", "api_key_header": "X-API-Key",
                "login_url": "", "csrf_field": "",
                "session_cookie": "",
                "cookie_value": "",
                "custom_headers": {},
            },
        }

    # ── settings schema (for UI rendering) ──────────────────────

    def settings_schema(self):
        return {"fields": [
            {"key": "target_url", "label": "Target URL",
             "type": "text", "required": True,
             "hint": "AI endpoint URL (e.g. https://api.example.com/analyze)"},
            {"key": "ai_type", "label": "AI Type",
             "type": "select", "required": False,
             "options": ["auto", "chat", "file-upload", "api", "transcription"]},
            {"key": "model", "label": "Model Name",
             "type": "text", "required": False,
             "hint": "Target model identifier (optional)"},
            {"key": "formats", "label": "File Formats",
             "type": "text", "required": False,
             "hint": "Comma-separated (pdf,png,wav,mp3,...) or 'all'"},
            {"key": "modules", "label": "Test Modules",
             "type": "text", "required": False,
             "hint": "Comma-separated categories or 'all'"},
            {"key": "timeout", "label": "Timeout (s)",
             "type": "number", "required": False},
            {"key": "verify_ssl", "label": "Verify SSL",
             "type": "checkbox", "required": False},
            {"key": "all_variants", "label": "Test All Variants",
             "type": "checkbox", "required": False,
             "hint": "Test all payload variants per category (slower but thorough)"},
            {"key": "whisper_mode", "label": "Whisper Mode",
             "type": "checkbox", "required": False,
             "hint": "Detect verbatim storage of spoken injections"},
            {"key": "nuclei_ai", "label": "Run Nuclei AI Templates",
             "type": "checkbox", "required": False,
             "hint": "Run nuclei with AI-specific vulnerability templates"},
            {"key": "file_field", "label": "Upload Field Name",
             "type": "text", "required": False},
            {"key": "resp_field", "label": "Response Field",
             "type": "text", "required": False},
            {"key": "upload_url", "label": "Upload URL",
             "type": "text", "required": False,
             "hint": "If different from target URL"},
            {"key": "verify_url", "label": "Verify URL",
             "type": "text", "required": False,
             "hint": "URL to poll for stored results"},
            {"key": "verify_delay", "label": "Verify Delay (s)",
             "type": "number", "required": False},
            {"key": "proxy", "label": "HTTP Proxy",
             "type": "text", "required": False},
            {"key": "auth", "label": "Authentication",
             "type": "auth_config"},
        ]}

    # ── findings loader ─────────────────────────────────────────

    def load_findings(self, project_dir, tool_output_dir):
        return self._load_multitarget_findings(tool_output_dir)

    # ── capabilities ────────────────────────────────────────────

    def supports_resume(self):
        return False

    def supports_pause(self):
        return True

    def supports_test_connection(self):
        return False
