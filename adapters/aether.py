"""Aether (WiFi) tool adapter for Crucible v2.0."""

import subprocess

from adapters.aether_base import AetherBaseAdapter
from config import TOOL_DIR


class AetherAdapter(AetherBaseAdapter):
    tool_id = "aether"
    tool_name = "Aether (WiFi)"
    tool_key = "AE"
    script_path = str(TOOL_DIR / "Aether/aether.py")
    _settings_prefix = "ae"

    def default_settings(self):
        return {
            "interface": "",
            "ap_interface": "",
            "target_ssids": [],
            "passive_ssids": [],
            "scope_default_mode": "active",
            "scope_modes": {},
            "scrape_url": "",
            "scrape_depth": 3,
            "client_name": "",
            "client_short": "",
            "phases": {
                "contextual_intel": True,
                "meraki_recon": True,
                "wep": True,
                "pmkid": True,
                "pmkid_roam": False,
                "wpa_handshake": True,
                "deauth_handshake": True,
                "wpa_enterprise": False,
                "dragonblood_sae": True,
                "dragonblood_drain": False,
                "rogue_ap": False,
                "karma": False,
                "mana_loud": False,
                "client_attacks": True,
                "eap_downgrade": False,
                "eap_fast_anon": False,
                "sae_downgrade": False,
                "legacy_attacks": True,
                "server_cert_analysis": True,
                "ipsk_test": True,
                "captive_portal_test": True,
                "eaptls_identity_analysis": True,
                "post_connection": False,
                "krack": True,
            },
        }

    def settings_schema(self):
        return {"fields": [
            {"key": "interface", "label": "Wireless Interface", "type": "interface_picker"},
            {"key": "ap_interface", "label": "AP Interface (optional)", "type": "interface_picker"},
            {"key": "scope_default_mode", "label": "Default Scope Mode", "type": "select",
             "options": [{"value": "active", "label": "Active"}, {"value": "passive", "label": "Passive"}]},
            {"key": "target_ssids", "label": "Active Scope SSIDs", "type": "tag_list"},
            {"key": "passive_ssids", "label": "Passive Scope SSIDs", "type": "tag_list"},
            {"key": "scrape_url", "label": "Scrape URL (wordlist)", "type": "text"},
            {"key": "scrape_depth", "label": "Scrape Depth", "type": "number", "min": 1, "max": 10},
            {"key": "client_name", "label": "Client Name", "type": "text"},
            {"key": "client_short", "label": "Client Short", "type": "text"},
            {"key": "phases", "label": "Attack Phases", "type": "phase_toggles"},
        ]}

    def post_exit_cleanup(self, project_dir):
        self._kill_stale_processes([
            "airodump-ng", "airbase-ng", "airmon-ng", "hostapd",
            "dnsmasq", "bettercap", "hashcat", "hcxdumptool",
            "mdk4", "responder", "wash", "reaver", "aireplay-ng",
        ])
        try:
            subprocess.run(["systemctl", "restart", "NetworkManager"],
                           capture_output=True, timeout=10)
        except Exception:
            pass
