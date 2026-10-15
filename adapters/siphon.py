"""SiphonAdapter — Siphon (API pentest) tool adapter for Crucible v2.0."""

from pathlib import Path
from adapters.base import ToolAdapter
from config import PYTHON3, TOOL_DIR


class SiphonAdapter(ToolAdapter):

    tool_id = "siphon"
    tool_name = "Siphon"
    tool_key = "SI"
    domain = "api"
    script_path = str(TOOL_DIR / "Siphon/siphon.py")
    requires_sudo = False
    env_vars = {"CRUCIBLE_MANAGED": "1", "PYTHONUNBUFFERED": "1"}
    parallel_group = "exclusive"

    # ── command builder ─────────────────────────────────────────

    def build_command(self, project, settings, *, resume=False,
                      extra_args=None):
        project_dir = Path(project.get("project_dir", ""))
        tool_dir = (project.get("tool_dirs") or {}).get("siphon")
        scope = self._normalize_scope(project.get("_launch_scope"))
        settings_path = self._find_settings(project_dir, tool_dir, scope, "si")
        cmd = [PYTHON3, self.script_path, "--settings", str(settings_path)]
        if resume:
            output_dir = settings.get("output_dir", "")
            if output_dir:
                cmd.extend(["--resume", str(output_dir)])
            else:
                cmd.extend(["--resume", str(project_dir)])
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

    # ── default settings ────────────────────────────────────────

    def default_settings(self):
        return {
            "api_base_url": "", "api_base_urls": [],
            "openapi_url": "", "api_spec_files": [],
            "output_dir": "",
            "consultant": "", "client_name": "", "client_short": "",
            "email": "", "start_date": "", "end_date": "",
            "proxy": "", "user_agent": "", "verify_ssl": False,
            "threads": 10, "timeout": 10,
            "extra_headers": {},
            "environment": "non-production",
            "jwt_secret": "",
            "rate_limit_threshold": 50,
            "mass_assignment_fields": [],
            "phases": {
                "discovery": True, "chaining": True,
                "recon": True, "fuzzing": True,
                "injection": True, "auth_bypass": True,
                "rate_limiting": True, "mass_assignment": True,
                "ssrf": True, "data_exposure": True,
                "graphql": False, "business_flows": True,
                "bola": False, "bfla": False,
                "cross_user": False, "session": False,
                "jwt": False, "sensitive_files": True,
                "tls": True, "unsafe_consumption": True,
                "verb_tampering": True, "soap": True,
                "file_upload_info": True,
                "access_matrix": False, "protocols": True,
            },
            "auth": {
                "enabled": False, "method": "bearer",
                "auth_token": "", "token_type": "Bearer",
                "username": "", "password": "", "domain": "",
                "kerberos_principal": "",
                "api_key": "", "api_key_header": "X-API-Key",
                "api_key_query": "", "api_key_cookie_name": "api_key",
                "api_key_cookie_domain": "",
                "login_url": "", "login_method": "POST",
                "login_data": "{}", "login_content_type": "application/json",
                "login_username_field": "username",
                "login_password_field": "password",
                "login_token_path": "token",
                "csrf_field": "", "csrf_header": "",
                "oauth_token_url": "", "oauth_client_id": "",
                "oauth_client_secret": "", "oauth_scope": "",
                "oauth1_consumer_key": "", "oauth1_consumer_secret": "",
                "oauth1_token": "", "oauth1_token_secret": "",
                "oidc_id_token": "",
                "saml_assertion": "", "saml_token_url": "",
                "saml_assertion_header": "Authorization",
                "mtls_cert": "", "mtls_key": "", "mtls_ca_bundle": "",
                "totp_secret": "", "totp_field": "otp",
                "hmac_key_id": "", "hmac_secret": "",
                "hmac_algorithm": "sha256", "hmac_header": "Authorization",
                "aws_access_key_id": "", "aws_secret_access_key": "",
                "aws_region": "us-east-1", "aws_service": "execute-api",
                "aws_session_token": "",
                "custom_headers": {},
                "auth_type": "", "session_cookie": "",
            },
            "auth_matrix": [],
        }

    # ── settings schema (for UI rendering) ──────────────────────

    def settings_schema(self):
        return {"fields": [
            {"key": "api_base_url", "label": "API Base URL",
             "type": "text", "required": True},
            {"key": "api_base_urls", "label": "Additional API URLs",
             "type": "text_list", "required": False},
            {"key": "openapi_url", "label": "OpenAPI/Swagger Spec URL",
             "type": "text", "required": False},
            {"key": "api_spec_files", "label": "API Spec Files",
             "type": "text_list", "required": False},
            {"key": "environment", "label": "Environment",
             "type": "select", "required": True,
             "options": ["non-production", "production"]},
            {"key": "proxy", "label": "HTTP Proxy",
             "type": "text", "required": False},
            {"key": "user_agent", "label": "User-Agent",
             "type": "text", "required": False},
            {"key": "verify_ssl", "label": "Verify SSL",
             "type": "checkbox", "required": False},
            {"key": "threads", "label": "Threads",
             "type": "number", "required": False},
            {"key": "timeout", "label": "Timeout (s)",
             "type": "number", "required": False},
            {"key": "jwt_secret", "label": "JWT Secret (for testing)",
             "type": "password", "required": False},
            {"key": "rate_limit_threshold", "label": "Rate-Limit Threshold",
             "type": "number", "required": False},
            {"key": "phases", "label": "Test Phases",
             "type": "phase_toggles"},
            {"key": "auth", "label": "Authentication",
             "type": "auth_config"},
            {"key": "auth_matrix", "label": "Auth Matrix",
             "type": "auth_matrix"},
        ]}

    # ── findings loader ─────────────────────────────────────────

    def load_findings(self, project_dir, tool_output_dir):
        return self._load_multitarget_findings(tool_output_dir)

    # ── capabilities ────────────────────────────────────────────

    def supports_resume(self):
        return True

    def supports_pause(self):
        return True

    def supports_test_connection(self):
        return True

    def test_connection_script(self):
        return str(TOOL_DIR / "Siphon/testConnection.py")
