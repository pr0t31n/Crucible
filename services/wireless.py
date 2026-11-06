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


_USB_VENDOR_IDS = {
    "0cf3": "Qualcomm/Atheros", "148f": "Ralink/MediaTek", "0bda": "Realtek",
    "2357": "TP-Link", "0846": "NETGEAR", "0b05": "ASUS",
    "13b1": "Linksys", "2001": "D-Link", "050d": "Belkin",
    "7392": "Edimax", "0e8d": "MediaTek", "0586": "ZyXEL",
    "2c4e": "Alfa Network", "0ace": "ZyDAS", "0df6": "Sitecom",
    "1737": "Linksys", "20f4": "TRENDnet", "1eda": "AirPcap",
    "0b3b": "Tekram", "1740": "EnGenius", "0e66": "Hawking",
    "15a9": "Gemtek", "057c": "AVM", "0411": "BUFFALO",
    "0471": "Philips", "083a": "Accton", "1385": "NETGEAR",
    "0cde": "Z-Com", "167b": "ZyDAS", "0db0": "Micro Star",
    "04bb": "I-O DATA", "07d1": "D-Link", "1044": "LITE-ON",
    "1286": "Marvell", "1a3b": "Alfa Network",
}

_PCI_VENDOR_IDS = {
    "8086": "Intel", "168c": "Qualcomm/Atheros", "14e4": "Broadcom",
    "1814": "Ralink/MediaTek", "10ec": "Realtek", "1b4b": "Marvell",
    "11ab": "Marvell", "1ae9": "Wilocity", "17cb": "Qualcomm",
    "02d0": "Broadcom", "14c3": "MediaTek",
}


def _detect_bus_and_vendor_linux(interface):
    """Detect bus type (USB/PCI/Integrated) and manufacturer on Linux."""
    bus = "Unknown"
    vendor = ""
    dev_path = f"/sys/class/net/{interface}/device"
    try:
        real = os.path.realpath(dev_path)
        if "/usb" in real:
            bus = "USB"
            vid_path = os.path.join(dev_path, "idVendor")
            if os.path.isfile(vid_path):
                vid = open(vid_path).read().strip().lower()
                vendor = _USB_VENDOR_IDS.get(vid, "")
            if not vendor:
                try:
                    r = subprocess.run(
                        ["lsusb"], capture_output=True, text=True, timeout=5,
                    )
                    for line in r.stdout.splitlines():
                        parts = line.split("ID ")
                        if len(parts) > 1:
                            tokens = parts[1].split(None, 1)
                            if len(tokens) > 1 and tokens[0].split(":")[0].lower() == vid:
                                vendor = tokens[1].split("[")[0].strip()[:30]
                                break
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    pass
        else:
            bus = "Integrated"
            vid_path = os.path.join(dev_path, "vendor")
            if os.path.isfile(vid_path):
                vid = open(vid_path).read().strip().lower().replace("0x", "")
                vendor = _PCI_VENDOR_IDS.get(vid, "")
            if not vendor:
                subsys = os.path.join(dev_path, "subsystem_vendor")
                if os.path.isfile(subsys):
                    svid = open(subsys).read().strip().lower().replace("0x", "")
                    vendor = _PCI_VENDOR_IDS.get(svid, "")
    except (OSError, IOError):
        pass
    return bus, vendor


def _detect_bus_and_vendor_darwin(interface):
    """Detect bus type and manufacturer on macOS."""
    bus = "Integrated"
    vendor = "Apple"
    try:
        r = subprocess.run(
            ["system_profiler", "SPUSBDataType"],
            capture_output=True, text=True, timeout=10,
        )
        if interface.lower() in r.stdout.lower() or "wireless" in r.stdout.lower():
            for line in r.stdout.splitlines():
                line = line.strip()
                if line.startswith("Manufacturer:"):
                    usb_mfr = line.split(":", 1)[1].strip()
                    if usb_mfr:
                        bus = "USB"
                        vendor = usb_mfr[:30]
                        break
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return bus, vendor


def get_interface_info(interface):
    """Get interface details (mode, channel, bus, manufacturer). Returns dict."""
    info = {
        "interface": interface, "mode": "unknown", "channel": None,
        "type": "unknown", "bus": "Unknown", "manufacturer": "",
    }
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
        info["bus"], info["manufacturer"] = _detect_bus_and_vendor_linux(interface)

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
        info["bus"], info["manufacturer"] = _detect_bus_and_vendor_darwin(interface)

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
