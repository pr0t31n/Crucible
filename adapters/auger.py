"""AugerAdapter — Auger (database security audit) tool adapter for Crucible v2.0."""

from pathlib import Path
from adapters.base import ToolAdapter
from config import PYTHON3, TOOL_DIR


class AugerAdapter(ToolAdapter):

    tool_id = "auger"
    tool_name = "Auger"
    tool_key = "AU"
    domain = "db"
    script_path = str(TOOL_DIR / "Auger/auger.py")
    requires_sudo = False
    env_vars = {"CRUCIBLE_MANAGED": "1", "PYTHONUNBUFFERED": "1"}
    parallel_group = "any"

    def supports_pause(self):
        return True

    def validate_launch(self, project, settings):
        project_dir = Path(project.get("project_dir", ""))
        tool_dir = (project.get("tool_dirs") or {}).get("auger")
        scope = self._normalize_scope(project.get("_launch_scope"))
        sp = self._find_settings(project_dir, tool_dir, scope, "au")
        if not sp.exists():
            return False, "No settings file — Auger requires a configured database target"
        host = settings.get("host", "")
        if not host:
            import json
            try:
                disk = json.loads(sp.read_text())
                host = disk.get("host", "")
            except (json.JSONDecodeError, OSError):
                pass
        if not host:
            return False, "No target host configured"
        return True, ""

    # ── command builder ─────────────────────────────────────────

    def build_command(self, project, settings, *, resume=False,
                      extra_args=None):
        project_dir = Path(project.get("project_dir", ""))
        tool_dir = (project.get("tool_dirs") or {}).get("auger")
        scope = self._normalize_scope(project.get("_launch_scope"))
        settings_path = self._find_settings(project_dir, tool_dir, scope, "au")
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

    # ── default settings ────────────────────────────────────────

    def default_settings(self):
        return {
            "host": "", "port": 5432, "db_type": "postgresql",
            "username": "", "password": "", "database": "",
            "auth_type": "password",
            "ssl": False, "ssl_cert": "", "ssl_key": "", "ssl_ca": "",
            "ssl_verify": False,
            "jdbc_url": "",
            "aws_profile": "", "aws_region": "",
            "timeout": 30, "threads": 4,
            "cred_delay": 0.5,
            "output_dir": "",
            "consultant": "", "client_name": "", "client_short": "",
            "email": "", "start_date": "", "end_date": "",
        }

    # ── settings schema (for UI rendering) ──────────────────────

    def settings_schema(self):
        return {"fields": [
            {"key": "host", "label": "Target Host",
             "type": "text", "required": True},
            {"key": "port", "label": "Port",
             "type": "number", "required": True},
            {"key": "db_type", "label": "Database Type",
             "type": "select", "required": True,
             "options": [
                 "mysql", "mariadb", "postgresql", "mssql", "oracle",
                 "mongodb", "redis", "cassandra", "elasticsearch",
                 "couchdb", "influxdb", "neo4j", "memcached",
                 "rds", "dynamodb", "redshift",
             ]},
            {"key": "username", "label": "Username",
             "type": "text", "required": False},
            {"key": "password", "label": "Password",
             "type": "password", "required": False},
            {"key": "database", "label": "Database/Schema",
             "type": "text", "required": False},
            {"key": "auth_type", "label": "Auth Type",
             "type": "select", "required": False,
             "options": ["password", "ssl", "kerberos", "ldap", "iam"]},
            {"key": "ssl", "label": "Enable SSL/TLS",
             "type": "checkbox", "required": False},
            {"key": "ssl_cert", "label": "SSL Client Certificate",
             "type": "text", "required": False},
            {"key": "ssl_key", "label": "SSL Client Key",
             "type": "text", "required": False},
            {"key": "ssl_ca", "label": "SSL CA Bundle",
             "type": "text", "required": False},
            {"key": "jdbc_url", "label": "JDBC URL",
             "type": "text", "required": False},
            {"key": "aws_profile", "label": "AWS Profile",
             "type": "text", "required": False},
            {"key": "aws_region", "label": "AWS Region",
             "type": "text", "required": False},
            {"key": "timeout", "label": "Timeout (s)",
             "type": "number", "required": False},
            {"key": "threads", "label": "Threads",
             "type": "number", "required": False},
            {"key": "cred_delay", "label": "Credential Delay (s)",
             "type": "number", "required": False},
        ]}

    # ── findings loader ─────────────────────────────────────────

    def load_findings(self, project_dir, tool_output_dir):
        return self._load_findings_file(tool_output_dir, "findings.json")

    # ── capabilities ────────────────────────────────────────────

    def supports_test_connection(self):
        return True

    def test_connection_script(self):
        return str(TOOL_DIR / "Auger/testConnection.py")
