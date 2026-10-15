"""Wireless interface management for Crucible v2.0.

Interface discovery, SSID scanning, mode management, and radio cleanup
for the Aether family of wireless testing tools.
"""

import logging
import os
import platform
import re
import subprocess

log = logging.getLogger("crucible.wireless")

STRAGGLER_PROCESSES = [
    "airodump", "airbase", "airmon", "hostapd", "dnsmasq",
    "bettercap", "hashcat", "hcxdumptool", "mdk4", "responder",
    "wash", "reaver", "aireplay",
]

AETHER_PHASES = [
    "Phase 0: WEP Testing / Wireless Intelligence",
    "Phase 1a: PMKID Capture",
    "Phase 1b: WPA Handshake + WPS",
    "Phase 1c: Deauth + Handshake",
    "Phase 2: WPA-Enterprise",
    "Phase 3: WPA3 SAE Testing",
    "Phase 4: WPA3 Exhaustion",
    "Phase 5: KRACK Testing",
    "Phase 6: Rogue AP / Evil Twin",
    "Phase 6b: KARMA / MANA Attack",
    "Phase 7: Client-Side Attacks",
    "Phase 8: EAP Downgrade",
    "Phase 9: SAE Transition Downgrade",
    "Phase 10: Post-Connection Attacks",
    "Phase 11: Legacy/Niche Attacks",
]


def get_wifi_interfaces():
    """Detect wireless interfaces. Returns list of interface name strings."""
    system = platform.system()
    interfaces = []

    if system == "Linux":
        net_dir = "/sys/class/net"
        if os.path.isdir(net_dir):
            for iface in os.listdir(net_dir):
                if os.path.exists(os.path.join(net_dir, iface, "wireless")):
                    interfaces.append(iface)
        if not interfaces:
            try:
                r = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=10)
                for line in r.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("Interface "):
                        interfaces.append(line.split()[1])
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

    elif system == "Darwin":
        try:
            r = subprocess.run(
                ["networksetup", "-listallhardwareports"],
                capture_output=True, text=True, timeout=10,
            )
            lines = r.stdout.splitlines()
            for i, line in enumerate(lines):
                if "Wi-Fi" in line or "AirPort" in line:
                    for j in range(i + 1, min(i + 3, len(lines))):
                        if lines[j].startswith("Device:"):
                            interfaces.append(lines[j].split(":")[1].strip())
                            break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    return interfaces


def get_interface_info(interface):
    """Get interface details (mode, channel, etc.). Returns dict."""
    info = {"interface": interface, "mode": "unknown", "channel": None, "type": "unknown"}
    system = platform.system()

    if system == "Linux":
        try:
            r = subprocess.run(
                ["iw", "dev", interface, "info"],
                capture_output=True, text=True, timeout=10,
            )
            for line in r.stdout.splitlines():
                line = line.strip()
                if line.startswith("type "):
                    info["mode"] = line.split()[1]
                elif line.startswith("channel "):
                    m = re.match(r"channel\s+(\d+)", line)
                    if m:
                        info["channel"] = int(m.group(1))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    elif system == "Darwin":
        try:
            r = subprocess.run(
                ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"],
                capture_output=True, text=True, timeout=10,
            )
            for line in r.stdout.splitlines():
                line = line.strip()
                if line.startswith("channel:"):
                    try:
                        info["channel"] = int(line.split(":")[1].strip())
                    except ValueError:
                        pass
                elif line.startswith("state:"):
                    info["mode"] = line.split(":")[1].strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    return info


def scan_ssids(interface=None):
    """Scan for visible SSIDs. Returns list of AP dicts."""
    system = platform.system()
    aps = []

    if system == "Darwin":
        try:
            cmd = [
                "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
                "-s",
            ]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            lines = r.stdout.strip().splitlines()
            if len(lines) < 2:
                return aps
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 7:
                    ssid = parts[0]
                    bssid = parts[1]
                    rssi = parts[2]
                    channel = parts[3]
                    security = " ".join(parts[6:])
                    aps.append({
                        "ssid": ssid, "bssid": bssid,
                        "signal": int(rssi) if rssi.lstrip("-").isdigit() else 0,
                        "channel": channel, "security": security,
                    })
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    elif system == "Linux":
        iface = interface or "wlan0"
        try:
            r = subprocess.run(
                ["sudo", "iwlist", iface, "scan"],
                capture_output=True, text=True, timeout=30,
            )
            current = {}
            for line in r.stdout.splitlines():
                line = line.strip()
                if "Cell" in line and "Address:" in line:
                    if current.get("bssid"):
                        aps.append(current)
                    current = {"bssid": line.split("Address:")[1].strip()}
                elif "ESSID:" in line:
                    current["ssid"] = line.split('"')[1] if '"' in line else ""
                elif "Channel:" in line:
                    current["channel"] = line.split(":")[1].strip()
                elif "Signal level=" in line:
                    m = re.search(r"Signal level[=:](-?\d+)", line)
                    if m:
                        current["signal"] = int(m.group(1))
                elif "Encryption key:" in line:
                    current["encrypted"] = "on" in line.lower()
                elif line.startswith("IE:"):
                    current.setdefault("security", line.split(":", 1)[1].strip())
            if current.get("bssid"):
                aps.append(current)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    return aps


def fix_interface(interface):
    """Restore interface from monitor to managed mode. Returns (ok, message)."""
    system = platform.system()

    if system != "Linux":
        return False, "Interface fix only supported on Linux"

    steps = []
    try:
        r = subprocess.run(
            ["airmon-ng", "stop", interface],
            capture_output=True, text=True, timeout=30,
        )
        steps.append(f"airmon-ng stop: exit {r.returncode}")
        if r.returncode == 0:
            subprocess.run(
                ["systemctl", "restart", "NetworkManager"],
                capture_output=True, timeout=15,
            )
            steps.append("NetworkManager restarted")
            return True, "; ".join(steps)
    except FileNotFoundError:
        steps.append("airmon-ng not found, using iw fallback")
    except subprocess.TimeoutExpired:
        steps.append("airmon-ng timed out")

    try:
        subprocess.run(["ip", "link", "set", interface, "down"],
                        capture_output=True, timeout=10)
        subprocess.run(["iw", "dev", interface, "set", "type", "managed"],
                        capture_output=True, timeout=10)
        subprocess.run(["ip", "link", "set", interface, "up"],
                        capture_output=True, timeout=10)
        steps.append("iw fallback: mode set to managed")
        subprocess.run(["systemctl", "restart", "NetworkManager"],
                        capture_output=True, timeout=15)
        steps.append("NetworkManager restarted")
        return True, "; ".join(steps)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        steps.append(f"fallback failed: {e}")
        return False, "; ".join(steps)


def force_radio_cleanup():
    """Kill straggler wireless processes and restore interfaces.
    Called after every Aether tool exit (even crashes).
    """
    if os.path.isfile("/usr/local/bin/aether-post.sh"):
        try:
            subprocess.run(["bash", "/usr/local/bin/aether-post.sh"], timeout=30)
            log.info("Radio cleanup via aether-post.sh")
            return
        except subprocess.TimeoutExpired:
            log.warning("aether-post.sh timed out")

    killed = []
    for proc_name in STRAGGLER_PROCESSES:
        r = subprocess.run(["pkill", "-f", proc_name],
                            capture_output=True, check=False)
        if r.returncode == 0:
            killed.append(proc_name)

    if killed:
        log.info("Killed straggler processes: %s", ", ".join(killed))

    if platform.system() == "Linux":
        subprocess.run(["systemctl", "restart", "NetworkManager"],
                        capture_output=True, check=False)
        log.info("NetworkManager restarted")
