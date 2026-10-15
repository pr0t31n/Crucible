"""Aether-B (Bluetooth) tool adapter for Crucible v2.0."""

import subprocess

from adapters.aether_base import AetherBaseAdapter
from config import TOOL_DIR


class AetherBAdapter(AetherBaseAdapter):
    tool_id = "aether_b"
    tool_name = "Aether-B (Bluetooth)"
    tool_key = "AB"
    script_path = str(TOOL_DIR / "Aether-B/aether_b.py")
    _settings_prefix = "ab"

    def default_settings(self):
        return {
            "hci_device": "hci0",
            "ubertooth_device": "/dev/ttyACM0",
            "target_bdaddrs": [],
            "target_uuids": [],
            "timeout_per_phase": 300,
            "capture_duration": 3600,
            "client_name": "",
            "client_short": "",
            "phases": {
                "passive_recon": True,
                "enumeration": True,
                "key_recovery": True,
                "exploitation": False,
                "firmware": False,
            },
            "authorization": {
                "physical_access": False,
                "injection": False,
                "dos": False,
                "pairing": False,
                "cve_testing": False,
            },
        }

    def settings_schema(self):
        return {"fields": [
            {"key": "hci_device", "label": "HCI Device", "type": "text",
             "placeholder": "hci0"},
            {"key": "ubertooth_device", "label": "Ubertooth Device", "type": "text",
             "placeholder": "/dev/ttyACM0"},
            {"key": "target_bdaddrs", "label": "Target BD_ADDRs", "type": "tag_list"},
            {"key": "target_uuids", "label": "Target UUIDs", "type": "tag_list"},
            {"key": "timeout_per_phase", "label": "Timeout per Phase (s)", "type": "number",
             "min": 60, "max": 7200},
            {"key": "client_name", "label": "Client Name", "type": "text"},
            {"key": "client_short", "label": "Client Short", "type": "text"},
            {"key": "phases", "label": "Test Phases", "type": "phase_toggles"},
            {"key": "authorization", "label": "Authorization Flags", "type": "phase_toggles"},
        ]}

    def post_exit_cleanup(self, project_dir):
        self._kill_stale_processes([
            "ubertooth-scan", "ubertooth-btle", "ubertooth-rx",
            "btscanner", "bettercap", "crackle", "gattacker",
            "bluetoolkit", "hcitool", "gatttool",
        ])
        try:
            subprocess.run(["hciconfig", "hci0", "reset"],
                           capture_output=True, timeout=5)
        except Exception:
            pass
