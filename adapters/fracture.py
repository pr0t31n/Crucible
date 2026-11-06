"""FractureAdapter — Fracture (web-app pentest) tool adapter for Crucible v2.0."""

from pathlib import Path
from adapters.base import ToolAdapter
from config import PYTHON3, TOOL_DIR


class FractureAdapter(ToolAdapter):

    tool_id = "fracture"
    tool_name = "Fracture"
    tool_key = "FR"
    domain = "webapp"
    script_path = str(TOOL_DIR / "Fracture/fracture.py")
    requires_sudo = False
    env_vars = {"CRUCIBLE_MANAGED": "1", "PYTHONUNBUFFERED": "1"}
    parallel_group = "exclusive"

    # ── command builder ─────────────────────────────────────────

    def build_command(self, project, settings, *, resume=False,
                      extra_args=None):
        project_dir = Path(project.get("project_dir", ""))
        tool_dir = (project.get("tool_dirs") or {}).get("fracture")
        scope = self._normalize_scope(project.get("_launch_scope"))
        settings_path = self._find_settings(project_dir, tool_dir, scope, "fr")
        cmd = [PYTHON3, self.script_path, "--settings", str(settings_path)]
        if resume:
            cmd.append("--resume")
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

    # ── default settings (flat adapter view — written as nested for Fracture) ──

    def default_settings(self):
        return {
            "target_url": "", "output_dir": "",
            "unauthenticated": False, "no_browser_assist": False,
            "consultant": "", "client_name": "", "client_short": "",
            "email": "", "start_date": "", "end_date": "",
            "proxy": "", "user_agent": "", "verify_ssl": True,
            "follow_redirects": True, "threads": 10, "timeout": 30,
            "crawl_depth": 3, "max_crawl_pages": 500,
            "sqlmap_timeout": 120, "nuclei_timeout": 120,
            "wordlist": "", "gobuster_wordlist": "",
            "wpscan_token": "",
            "detect_session_timeout": True,
            "extra_headers": {},
            "phases": {
                "recon": True, "tls": True, "headers": True,
                "crawl": True, "injection": True, "traversal": True,
                "ssrf": True, "auth_bypass": True, "files": True,
                "vulnscan": True, "graphql": True, "auth_recon": True,
                "authorization": True, "session": True, "csrf": True,
                "cross_user": True,
            },
            "per_target_auth": {},
            "auth": {
                "enabled": False, "method": "auto",
                "username": "", "password": "",
                "login_url": "", "login_mode": "standard",
                "token": "", "token_header": "Authorization",
                "api_key": "", "api_key_name": "",
                "cookie_name": "", "cookie_value": "",
                "client_cert": "", "client_key": "",
                "totp_secret": "", "hmac_secret": "",
                "aws_access_key": "", "aws_secret_key": "",
                "aws_region": "",
                "kerberos_realm": "", "kerberos_kdc": "",
                "proxy_header_name": "", "proxy_header_value": "",
                "custom_headers": {},
                "saml_idp_url": "", "saml_sp_url": "",
                "oidc_issuer": "", "oidc_client_id": "",
                "oidc_client_secret": "",
            },
            "auth_matrix": [],
        }

    # ── settings schema (for UI rendering) ──────────────────────

    def settings_schema(self):
        return {"fields": [
            {"key": "target_url", "label": "Target URLs",
             "type": "textarea", "required": True,
             "hint": "One URL per line"},
            {"key": "unauthenticated", "label": "Unauthenticated",
             "type": "checkbox", "required": False,
             "hint": "Skip all authentication — test as an unauthenticated user only"},
            {"key": "no_browser_assist", "label": "No Browser-Assist",
             "type": "checkbox", "required": False,
             "hint": "Skip browser-assisted login — fall back to unauthenticated if automation fails"},
            {"key": "proxy", "label": "HTTP Proxy",
             "type": "text", "required": False},
            {"key": "user_agent", "label": "User-Agent",
             "type": "text", "required": False},
            {"key": "verify_ssl", "label": "Verify SSL",
             "type": "checkbox", "required": False},
            {"key": "follow_redirects", "label": "Follow Redirects",
             "type": "checkbox", "required": False},
            {"key": "threads", "label": "Threads",
             "type": "number", "required": False},
            {"key": "timeout", "label": "Timeout (s)",
             "type": "number", "required": False},
            {"key": "crawl_depth", "label": "Crawl Depth",
             "type": "number", "required": False},
            {"key": "max_crawl_pages", "label": "Max Crawl Pages",
             "type": "number", "required": False},
            {"key": "sqlmap_timeout", "label": "SQLMap Timeout (s)",
             "type": "number", "required": False},
            {"key": "nuclei_timeout", "label": "Nuclei Timeout (s)",
             "type": "number", "required": False},
            {"key": "wordlist", "label": "Wordlist",
             "type": "text", "required": False},
            {"key": "gobuster_wordlist", "label": "Gobuster Wordlist",
             "type": "text", "required": False},
            {"key": "wpscan_token", "label": "WPScan Token",
             "type": "password", "required": False},
            {"key": "phases", "label": "Test Phases",
             "type": "phase_toggles"},
            {"key": "auth", "label": "Authentication",
             "type": "auth_config"},
            {"key": "auth_matrix", "label": "Auth Matrix",
             "type": "auth_matrix"},
            {"key": "per_target_auth", "label": "Per-Target Authentication",
             "type": "per_target_auth_table"},
        ]}

    # ── format converters (nested scan.* ↔ flat UI keys) ────────

    def from_tool_format(self, settings):
        scan = settings.get("scan", {})
        if isinstance(scan, dict):
            urls = scan.get("target_urls", [])
            main = scan.get("target_url", "")
            if urls:
                all_urls = [main] + [u for u in urls if u != main] if main else urls
                settings["target_url"] = "\n".join(u for u in all_urls if u)
            elif main:
                settings["target_url"] = main
        return settings

    def to_tool_format(self, settings):
        raw = settings.get("target_url", "")
        if isinstance(raw, str) and raw.strip():
            urls = [u.strip() for u in raw.split("\n") if u.strip()]
            scan = settings.setdefault("scan", {})
            scan["target_url"] = urls[0] if urls else ""
            scan["target_urls"] = urls
        return settings

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
        return str(TOOL_DIR / "Fracture/testConnection.py")
