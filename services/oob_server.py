"""Crucible OOB (Out-of-Band) callback server module.

Provides an HTTP listener that records token hits from OOB interactions
(blind XSS, SSRF, XXE, DNS rebinding, etc.) during managed tool scans.
"""

import json
import logging
import shutil
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler

log = logging.getLogger("crucible.oob")

try:
    import requests as _requests
except ImportError:
    _requests = None


# ── OOBCallbackServer ──────────────────────────────────────────────

_STATIC_HTML = (
    "<!doctype html><html><head><title>Resource</title></head>"
    "<body><p>OK</p></body></html>"
)


class _OOBHandler(BaseHTTPRequestHandler):

    def _handle_request(self):
        token = self.path.strip("/").split("/")[0] if self.path.strip("/") else ""
        body_snippet = ""
        content_len = int(self.headers.get("Content-Length", 0) or 0)
        if content_len > 0:
            raw = self.rfile.read(min(content_len, 4096))
            body_snippet = raw.decode("utf-8", errors="replace")[:1024]

        if token:
            registry = self.server.oob_registry
            lock = self.server.oob_lock
            with lock:
                for scan_id, tokens in registry.items():
                    if token in tokens:
                        hit = {
                            "token": token,
                            "source_ip": self.client_address[0],
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "method": self.command,
                            "path": self.path,
                            "headers": dict(self.headers),
                            "body_snippet": body_snippet,
                        }
                        tokens[token].append(hit)
                        log.info("OOB hit: token=%s src=%s method=%s",
                                 token, self.client_address[0], self.command)
                        break

        if self.command == "GET":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(_STATIC_HTML.encode())
        elif self.command in ("POST", "PUT", "PATCH"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{}")
        else:
            self.send_response(200)
            self.end_headers()

    do_GET = _handle_request
    do_POST = _handle_request
    do_PUT = _handle_request
    do_DELETE = _handle_request
    do_HEAD = _handle_request
    do_OPTIONS = _handle_request
    do_PATCH = _handle_request

    def log_message(self, format, *args):
        pass


class OOBCallbackServer:
    """Thread-safe OOB callback HTTP server."""

    def __init__(self):
        self._server = None
        self._thread = None
        self._lock = threading.Lock()
        self._registry: dict[str, dict[str, list]] = {}
        self._port = None

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, port: int = 9999):
        if self.is_running:
            return
        self._port = port
        self._server = HTTPServer(("0.0.0.0", port), _OOBHandler)
        self._server.oob_registry = self._registry
        self._server.oob_lock = self._lock
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name=f"oob-callback-{port}", daemon=True)
        self._thread.start()
        log.info("OOB callback server started on port %d", port)

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        self._thread = None
        log.info("OOB callback server stopped")

    def register_tokens(self, scan_id: str, tokens: list[str]):
        with self._lock:
            if scan_id not in self._registry:
                self._registry[scan_id] = {}
            for t in tokens:
                if t not in self._registry[scan_id]:
                    self._registry[scan_id][t] = []

    def get_hits(self, scan_id: str) -> list[dict]:
        with self._lock:
            token_map = self._registry.get(scan_id, {})
            hits = []
            for token_hits in token_map.values():
                hits.extend(token_hits)
            return list(hits)

    def clear_scan(self, scan_id: str):
        with self._lock:
            self._registry.pop(scan_id, None)


# ── PublicIPDetector ───────────────────────────────────────────────

class PublicIPDetector:
    """Detect the host's public IP via external services."""

    _SERVICES = [
        "https://api.ipify.org",
        "https://icanhazip.com",
        "https://ifconfig.me/ip",
        "https://checkip.amazonaws.com",
    ]
    _CACHE_TTL = 300

    def __init__(self):
        self._cached_ip = None
        self._cached_at = 0.0

    def detect(self) -> str:
        now = time.monotonic()
        if self._cached_ip and (now - self._cached_at) < self._CACHE_TTL:
            return self._cached_ip

        if _requests is None:
            return ""

        for url in self._SERVICES:
            try:
                resp = _requests.get(url, timeout=5)
                if resp.status_code == 200:
                    ip = resp.text.strip()
                    if ip:
                        self._cached_ip = ip
                        self._cached_at = now
                        return ip
            except Exception:
                continue
        return self._cached_ip or ""


# ── FirewallManager ────────────────────────────────────────────────

class FirewallManager:
    """Detect and manipulate the host firewall to open/close OOB ports."""

    def __init__(self):
        self._opened: dict[tuple[int, str], str] = {}

    def detect_firewall(self) -> str:
        for fw in ("ufw", "iptables", "firewall-cmd"):
            if shutil.which(fw):
                return fw.replace("firewall-cmd", "firewalld")
        return "none"

    def open_port(self, port: int, protocol: str = "tcp") -> tuple[bool, str, str]:
        fw = self.detect_firewall()
        if fw == "ufw":
            open_cmd = f"sudo ufw allow {port}/{protocol}"
            close_cmd = f"sudo ufw delete allow {port}/{protocol}"
        elif fw == "iptables":
            open_cmd = (f"sudo iptables -I INPUT -p {protocol} "
                        f"--dport {port} -j ACCEPT")
            close_cmd = (f"sudo iptables -D INPUT -p {protocol} "
                         f"--dport {port} -j ACCEPT")
        elif fw == "firewalld":
            open_cmd = f"sudo firewall-cmd --add-port={port}/{protocol}"
            close_cmd = f"sudo firewall-cmd --remove-port={port}/{protocol}"
        else:
            return (True, "", "")

        try:
            subprocess.run(open_cmd, shell=True, capture_output=True,
                           timeout=15, check=True)
            self._opened[(port, protocol)] = close_cmd
            return (True, open_cmd, close_cmd)
        except Exception as exc:
            return (False, open_cmd, str(exc))

    def close_port(self, port: int, protocol: str = "tcp") -> bool:
        key = (port, protocol)
        close_cmd = self._opened.pop(key, None)
        if not close_cmd:
            fw = self.detect_firewall()
            if fw == "ufw":
                close_cmd = f"sudo ufw delete allow {port}/{protocol}"
            elif fw == "iptables":
                close_cmd = (f"sudo iptables -D INPUT -p {protocol} "
                             f"--dport {port} -j ACCEPT")
            elif fw == "firewalld":
                close_cmd = f"sudo firewall-cmd --remove-port={port}/{protocol}"
            else:
                return True
        try:
            subprocess.run(close_cmd, shell=True, capture_output=True,
                           timeout=15, check=True)
            return True
        except Exception:
            return False

    def is_port_open(self, port: int) -> bool:
        fw = self.detect_firewall()
        try:
            if fw == "ufw":
                r = subprocess.run("sudo ufw status", shell=True,
                                   capture_output=True, timeout=15, text=True)
                return f"{port}" in r.stdout
            elif fw == "iptables":
                r = subprocess.run("sudo iptables -L INPUT -n", shell=True,
                                   capture_output=True, timeout=15, text=True)
                return f"dpt:{port}" in r.stdout
            elif fw == "firewalld":
                r = subprocess.run("sudo firewall-cmd --list-ports", shell=True,
                                   capture_output=True, timeout=15, text=True)
                return f"{port}/" in r.stdout
        except Exception:
            pass
        return False

    def cleanup(self):
        for (port, proto), close_cmd in list(self._opened.items()):
            try:
                subprocess.run(close_cmd, shell=True, capture_output=True,
                               timeout=15)
            except Exception:
                pass
        self._opened.clear()


# ── ReachabilityVerifier ───────────────────────────────────────────

class ReachabilityVerifier:
    """Verify that the OOB callback URL is reachable."""

    def verify(self, url: str, proxy_url: str = None) -> tuple[bool, str]:
        if _requests is None:
            return (False, "requests library not available")
        proxies = None
        if proxy_url:
            proxies = {"http": proxy_url, "https": proxy_url}
        try:
            resp = _requests.get(url, timeout=10, proxies=proxies)
            if resp.status_code == 200:
                return (True, "Callback server reachable")
            return (False, f"Unexpected status {resp.status_code}")
        except _requests.ConnectionError as exc:
            return (False, f"Connection failed: {exc}")
        except _requests.Timeout:
            return (False, "Connection timed out (10s)")
        except Exception as exc:
            return (False, str(exc))


# ── OOBManager (high-level orchestrator) ───────────────────────────

class OOBManager:
    """Orchestrates the OOB callback server, IP detection, firewall, and
    reachability verification for a single project."""

    def __init__(self):
        self.server = OOBCallbackServer()
        self.ip_detector = PublicIPDetector()
        self.fw_manager = FirewallManager()
        self.verifier = ReachabilityVerifier()
        self.mode = None
        self.port = None
        self.public_ip = None
        self.callback_url = None

    def setup(self, mode: str, port: int, proxy_settings: dict = None) -> dict:
        self.mode = mode
        self.port = port
        result = {"mode": mode, "port": port}

        self.server.start(port)
        result["server_started"] = self.server.is_running

        if mode == "public":
            self.public_ip = self.ip_detector.detect()
            result["public_ip"] = self.public_ip

            success, open_cmd, close_cmd = self.fw_manager.open_port(port)
            result["firewall_opened"] = success
            result["firewall_open_cmd"] = open_cmd
            result["firewall_close_cmd"] = close_cmd

            if self.public_ip:
                self.callback_url = f"http://{self.public_ip}:{port}"
            else:
                self.callback_url = f"http://0.0.0.0:{port}"
        else:
            self.callback_url = f"http://0.0.0.0:{port}"

        result["callback_url"] = self.callback_url
        return result

    def verify(self, proxy_settings: dict = None) -> dict:
        proxy_url = None
        if proxy_settings:
            addr = proxy_settings.get("address", "")
            ptype = proxy_settings.get("type", "http")
            if addr:
                dns_over = proxy_settings.get("dns_over_proxy", False)
                if ptype == "socks5" and dns_over:
                    scheme = "socks5h"
                elif ptype == "socks5":
                    scheme = "socks5"
                else:
                    scheme = ptype
                proxy_url = f"{scheme}://{addr}"

        url = self.callback_url or f"http://0.0.0.0:{self.port or 9999}"
        ok, detail = self.verifier.verify(url, proxy_url=proxy_url)
        return {"reachable": ok, "detail": detail, "url": url,
                "proxy_url": proxy_url}

    def teardown(self) -> dict:
        result = {}
        self.server.stop()
        result["server_stopped"] = True

        if self.mode == "public" and self.port:
            closed = self.fw_manager.close_port(self.port)
            result["firewall_closed"] = closed

        self.fw_manager.cleanup()
        result["cleanup"] = True
        self.mode = None
        self.port = None
        self.public_ip = None
        self.callback_url = None
        return result

    def register_tokens(self, scan_id: str, tokens: list[str]):
        self.server.register_tokens(scan_id, tokens)

    def get_hits(self, scan_id: str) -> list[dict]:
        return self.server.get_hits(scan_id)

    def clear_scan(self, scan_id: str):
        self.server.clear_scan(scan_id)

    def get_status(self) -> dict:
        with self.server._lock:
            active = len(self.server._registry)
        return {
            "running": self.server.is_running,
            "mode": self.mode,
            "port": self.port,
            "public_ip": self.public_ip,
            "callback_url": self.callback_url,
            "active_scans": active,
        }
