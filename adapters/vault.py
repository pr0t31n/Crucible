"""VaultAdapter — Vault (AD credential testing) tool adapter for Crucible v2.0."""

from pathlib import Path
from adapters.base import ToolAdapter
from config import PYTHON3, TOOL_DIR


class VaultAdapter(ToolAdapter):

    tool_id = "vault"
    tool_name = "Vault"
    tool_key = "VT"
    domain = "ad"
    script_path = str(TOOL_DIR / "Vault/vault.py")
    requires_sudo = False
    env_vars = {"VAULT_MANAGED": "1", "PYTHONUNBUFFERED": "1"}
    parallel_group = "any"

    def supports_pause(self):
        return False

    def validate_launch(self, project, settings):
        project_dir = Path(project.get("project_dir", ""))
        tool_dir = (project.get("tool_dirs") or {}).get("vault")
        scope = self._normalize_scope(project.get("_launch_scope"))
        sp = self._find_settings(project_dir, tool_dir, scope, "vt")
        if not sp.exists():
            return False, "No settings file — Vault requires a configured AD target"
        target = settings.get("target", "")
        if not target:
            import json
            try:
                disk = json.loads(sp.read_text())
                target = disk.get("target", "")
            except (json.JSONDecodeError, OSError):
                pass
        if not target:
            return False, "No target DC configured"
        return True, ""

    # ── command builder ─────────────────────────────────────────

    def build_command(self, project, settings, *, resume=False,
                      extra_args=None):
        project_dir = Path(project.get("project_dir", ""))
        tool_dir = (project.get("tool_dirs") or {}).get("vault")
        scope = self._normalize_scope(project.get("_launch_scope"))
        settings_path = self._find_settings(project_dir, tool_dir, scope, "vt")

        import json
        try:
            disk = json.loads(settings_path.read_text())
        except (json.JSONDecodeError, OSError):
            disk = {}

        s = {**disk, **settings}

        target = s.get("target", "")
        cmd = [PYTHON3, self.script_path, "--target", target]

        if s.get("user"):
            cmd.extend(["--user", s["user"]])
        if s.get("password"):
            cmd.extend(["--password", s["password"]])
        if s.get("domain"):
            cmd.extend(["--domain", s["domain"]])
        if s.get("users_file"):
            cmd.extend(["--users-file", s["users_file"]])
        if s.get("modules") and s["modules"] != "all":
            cmd.extend(["--modules", s["modules"]])
        if s.get("hashes"):
            cmd.extend(["--hashes", s["hashes"]])
        if s.get("ccache"):
            cmd.extend(["--ccache", s["ccache"]])
        if s.get("targets_file"):
            cmd.extend(["--targets-file", s["targets_file"]])
        if s.get("timeout"):
            cmd.extend(["--timeout", str(s["timeout"])])
        if s.get("spn"):
            cmd.extend(["--spn", s["spn"]])
        if s.get("password_list"):
            cmd.extend(["--password-list", s["password_list"]])
        if s.get("spray_delay"):
            cmd.extend(["--spray-delay", str(s["spray_delay"])])
        if s.get("lockout_threshold"):
            cmd.extend(["--lockout-threshold", str(s["lockout_threshold"])])

        client_short = (project.get("client_short")
                        or s.get("client_short") or "default")
        cmd.extend(["--client-short", client_short])

        client_name = project.get("client_name") or s.get("client_name") or ""
        if client_name:
            cmd.extend(["--client-name", client_name])

        engagement = project.get("engagement_name") or s.get("engagement_name") or ""
        if engagement:
            cmd.extend(["--engagement-name", engagement])

        out_dir = str(tool_dir) if tool_dir else str(project_dir)
        cmd.extend(["--project", out_dir])

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
            "target": "", "domain": "", "user": "", "password": "",
            "hashes": "", "ccache": "", "users_file": "",
            "modules": "all", "targets_file": "", "timeout": 900,
            "spn": "", "password_list": "", "spray_delay": 30,
            "lockout_threshold": 5,
            "consultant": "", "client_name": "", "client_short": "",
            "email": "", "start_date": "", "end_date": "",
        }

    # ── settings schema (for UI rendering) ──────────────────────

    def settings_schema(self):
        return {"fields": [
            {"key": "target", "label": "Target DC / SMB Host",
             "type": "text", "required": True},
            {"key": "domain", "label": "Domain / Realm",
             "type": "text", "required": False},
            {"key": "user", "label": "Username",
             "type": "text", "required": False},
            {"key": "password", "label": "Password",
             "type": "password", "required": False},
            {"key": "hashes", "label": "NTLM Hash (LMHASH:NTHASH)",
             "type": "password", "required": False},
            {"key": "ccache", "label": "Kerberos ccache File",
             "type": "text", "required": False},
            {"key": "users_file", "label": "Users File (one per line)",
             "type": "text", "required": False},
            {"key": "targets_file", "label": "Targets File (one IP per line)",
             "type": "text", "required": False},
            {"key": "modules", "label": "Modules",
             "type": "select", "required": False,
             "options": [
                 "all", "credential", "enum", "exec", "relay",
                 "secretsdump", "kerberoast", "asreproast", "smb_relay",
                 "ldap_enum", "sid_enum", "sam_dump", "delegation", "spn_scan",
                 "pth_exec", "dcom_exec", "tgt_request", "service_ticket",
                 "share_enum", "reg_secrets", "gpp_passwords",
                 "ntlm_relay", "password_spray", "dpapi",
             ]},
            {"key": "spn", "label": "Target SPN (for service_ticket)",
             "type": "text", "required": False},
            {"key": "password_list", "label": "Password List File (for spray)",
             "type": "text", "required": False},
            {"key": "spray_delay", "label": "Spray Delay (s)",
             "type": "number", "required": False},
            {"key": "lockout_threshold", "label": "Lockout Threshold",
             "type": "number", "required": False},
            {"key": "timeout", "label": "Timeout (s)",
             "type": "number", "required": False},
        ]}

    # ── findings loader ─────────────────────────────────────────

    def load_findings(self, project_dir, tool_output_dir):
        return self._load_multitarget_findings(tool_output_dir)

    # ── capabilities ────────────────────────────────────────────

    def supports_test_connection(self):
        return False
