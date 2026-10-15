"""Aether-U (UWB/RTLS) tool adapter for Crucible v2.0."""

from adapters.aether_base import AetherBaseAdapter
from config import TOOL_DIR


class AetherUAdapter(AetherBaseAdapter):
    tool_id = "aether_u"
    tool_name = "Aether-U (UWB)"
    tool_key = "AW"
    script_path = str(TOOL_DIR / "Aether-U/aether_u.py")
    _settings_prefix = "aw"

    def default_settings(self):
        return {
            "rtls_host": "",
            "rtls_port": 8081,
            "mqtt_host": "",
            "mqtt_port": 1883,
            "uwb_channel": 5,
            "uwb_prf": 64,
            "timeout_per_phase": 300,
            "capture_duration": 1800,
            "client_name": "",
            "client_short": "",
            "phases": {
                "survey": True,
                "protocol_analysis": True,
                "active_interaction": True,
                "physical_attacks": False,
                "network_app": True,
            },
            "scope": {
                "hosts": [],
                "eui64s": [],
            },
            "credentials": {
                "username": "",
                "password": "",
            },
        }

    def settings_schema(self):
        return {"fields": [
            {"key": "rtls_host", "label": "RTLS Host", "type": "text",
             "placeholder": "192.168.1.100"},
            {"key": "rtls_port", "label": "RTLS Port", "type": "number",
             "min": 1, "max": 65535},
            {"key": "mqtt_host", "label": "MQTT Broker Host", "type": "text"},
            {"key": "mqtt_port", "label": "MQTT Broker Port", "type": "number",
             "min": 1, "max": 65535},
            {"key": "uwb_channel", "label": "UWB Channel", "type": "number",
             "min": 0, "max": 15},
            {"key": "uwb_prf", "label": "UWB PRF (MHz)", "type": "select",
             "options": [16, 64]},
            {"key": "timeout_per_phase", "label": "Timeout per Phase (s)", "type": "number",
             "min": 60, "max": 7200},
            {"key": "client_name", "label": "Client Name", "type": "text"},
            {"key": "client_short", "label": "Client Short", "type": "text"},
            {"key": "phases", "label": "Test Phases", "type": "phase_toggles"},
            {"key": "scope.hosts", "label": "Scope Hosts", "type": "tag_list"},
            {"key": "scope.eui64s", "label": "Scope EUI-64s", "type": "tag_list"},
            {"key": "credentials.username", "label": "RTLS Username", "type": "text"},
            {"key": "credentials.password", "label": "RTLS Password", "type": "password"},
        ]}

    def post_exit_cleanup(self, project_dir):
        self._kill_stale_processes([
            "mosquitto_sub", "mosquitto_pub", "sqlmap",
        ])
