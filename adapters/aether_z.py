"""Aether-Z (ZigBee) tool adapter for Crucible v2.0."""

from adapters.aether_base import AetherBaseAdapter
from config import TOOL_DIR


class AetherZAdapter(AetherBaseAdapter):
    tool_id = "aether_z"
    tool_name = "Aether-Z (ZigBee)"
    tool_key = "AZ"
    script_path = str(TOOL_DIR / "Aether-Z/aether_z.py")
    _settings_prefix = "az"

    def default_settings(self):
        return {
            "interface": "",
            "channel": None,
            "channels": [],
            "target_panids": [],
            "target_eui64s": [],
            "timeout_per_phase": 300,
            "capture_duration": 3600,
            "client_name": "",
            "client_short": "",
            "phases": {
                "survey": True,
                "key_recovery": True,
                "enumeration": True,
                "attacks": False,
                "firmware": False,
            },
            "authorization": {
                "physical_access": False,
                "injection": False,
                "dos": False,
            },
            "zll_master_key": "",
            "network_keys": [],
        }

    def settings_schema(self):
        return {"fields": [
            {"key": "interface", "label": "ZigBee Interface", "type": "text",
             "placeholder": "/dev/ttyUSB0"},
            {"key": "channel", "label": "ZigBee Channel", "type": "number",
             "min": 11, "max": 26},
            {"key": "channels", "label": "Channel List", "type": "tag_list"},
            {"key": "target_panids", "label": "Target PAN IDs", "type": "tag_list"},
            {"key": "target_eui64s", "label": "Target EUI-64s", "type": "tag_list"},
            {"key": "timeout_per_phase", "label": "Timeout per Phase (s)", "type": "number",
             "min": 60, "max": 7200},
            {"key": "client_name", "label": "Client Name", "type": "text"},
            {"key": "client_short", "label": "Client Short", "type": "text"},
            {"key": "phases", "label": "Test Phases", "type": "phase_toggles"},
            {"key": "authorization", "label": "Authorization Flags", "type": "phase_toggles"},
            {"key": "network_keys", "label": "Known Network Keys", "type": "tag_list"},
        ]}

    def post_exit_cleanup(self, project_dir):
        self._kill_stale_processes([
            "zbstumbler", "zbdump", "zbdsniff", "zbscapy",
            "zbreplay", "zbassocflood", "zbpanidconflictflood",
            "zbfind", "zbid", "z3sec", "goodfet",
        ])
