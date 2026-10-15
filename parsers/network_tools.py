"""Parser for pcap/pcapng network capture files."""

import re
import shutil
import subprocess
from datetime import datetime, timezone
from parsers.base import BaseParser

_PCAP_LE = b'\xd4\xc3\xb2\xa1'
_PCAP_BE = b'\xa1\xb2\xc3\xd4'
_PCAPNG = b'\x0a\x0d\x0d\x0a'
_RE_IP = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


class PcapParser(BaseParser):
    TOOL_ID = "pcap"
    TOOL_NAME = "PCAP Capture"
    SUPPORTED_FORMATS = ["pcap", "pcapng", "cap"]

    def parse(self):
        try:
            with open(self.file_path, "rb") as f:
                magic = f.read(4)
            file_size = self.file_path.stat().st_size
        except OSError:
            return

        if magic == _PCAP_LE or magic == _PCAP_BE:
            fmt = "pcap"
        elif magic == _PCAPNG:
            fmt = "pcapng"
        else:
            fmt = "unknown"

        self.emit("log", f"PCAP file detected: {fmt}, {file_size:,} bytes")
        yield ("log", f"PCAP file detected: {fmt}, {file_size:,} bytes")
        yield ("intel", {
            "type": "pcap", "format": fmt,
            "size": file_size, "file": str(self.file_path),
        })

        tshark = shutil.which("tshark")
        if not tshark:
            self.emit("log", "tshark not available — skipping pcap IP extraction")
            return

        try:
            proc = subprocess.run(
                [tshark, "-r", str(self.file_path), "-q", "-z", "conv,ip"],
                capture_output=True, text=True, timeout=30, errors="replace",
            )
            ips = set()
            for m in _RE_IP.finditer(proc.stdout):
                ip = m.group(1)
                if not ip.startswith("0.") and not ip.startswith("255."):
                    ips.add(ip)
            for ip in sorted(ips):
                yield ("target", {"ip": ip, "source": "pcap"})
            self.emit("log", f"Extracted {len(ips)} unique IP(s) from pcap")
        except (subprocess.TimeoutExpired, OSError, Exception) as exc:
            self.emit("log", f"tshark analysis failed: {exc}")

    def extract_targets(self):
        targets = set()
        tshark = shutil.which("tshark")
        if not tshark:
            return targets
        try:
            proc = subprocess.run(
                [tshark, "-r", str(self.file_path),
                 "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-q"],
                capture_output=True, text=True, timeout=15, errors="replace",
            )
            for m in _RE_IP.finditer(proc.stdout):
                ip = m.group(1)
                if not ip.startswith("0.") and not ip.startswith("255."):
                    targets.add(ip)
        except (subprocess.TimeoutExpired, OSError, Exception):
            pass
        return targets
