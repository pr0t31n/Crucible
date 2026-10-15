"""Nessus API client — lifecycle management for Crucible v2.0."""

import json
import logging
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import requests
from requests.exceptions import ConnectionError, Timeout

log = logging.getLogger("crucible.nessus")


class NessusClient:
    """Full Nessus API lifecycle manager.

    Lifecycle: Configure → Create Scan → Launch → Poll Status → Export → Download → Parse
    """

    def __init__(self, host, port=8834, access_key="", secret_key="", verify_ssl=False,
                 _token=None, _api_token=None, _session=None):
        self.base_url = f"https://{host}:{port}"
        self.session = _session or requests.Session()
        if _token:
            self.session.headers["X-Cookie"] = f"token={_token}"
            if _api_token:
                self.session.headers["X-API-Token"] = _api_token
        elif not _session:
            self.session.headers["X-ApiKeys"] = f"accessKey={access_key};secretKey={secret_key}"
        self.session.verify = verify_ssl
        self._timeout = 30
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        _retry = Retry(total=3, connect=2, read=2,
                        backoff_factor=1.0,
                        status_forcelist=[502, 503],
                        allowed_methods=None)
        self.session.mount("https://", HTTPAdapter(max_retries=_retry))

    @classmethod
    def _extract_api_token(cls, sess, base_url):
        """Try multiple methods to extract the Nessus API token for CSRF."""
        import re as _re
        _UUID = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        _targeted = [
            _re.compile(r'getApiToken[^}]{0,80}return\s*["\'](' + _UUID + r')["\']'),
            _re.compile(r'api[_-]?token["\s:=]+["\'](' + _UUID + r')["\']', _re.I),
            _re.compile(r'nessus[_-]?api[_-]?token["\s:=]+["\'](' + _UUID + r')["\']', _re.I),
        ]
        _fallback = _re.compile(r'["\'](' + _UUID + r')["\']')

        for _js_path in ("/nessus6.js", "/nessus10.js"):
            try:
                js_r = sess.get(f"{base_url}{_js_path}", timeout=15)
                if js_r.status_code != 200:
                    continue
                _text = js_r.text
                for pat in _targeted:
                    m = pat.search(_text)
                    if m:
                        return m.group(1)
                m = _fallback.search(_text[:200000])
                if m:
                    return m.group(1)
            except Exception:
                continue
        try:
            html_r = sess.get(f"{base_url}/", timeout=10)
            if html_r.status_code == 200:
                for pat in _targeted:
                    m = pat.search(html_r.text[:200000])
                    if m:
                        return m.group(1)
        except Exception:
            pass
        return None

    @classmethod
    def from_credentials(cls, url="", username="", password="", verify_ssl=False):
        """Create client by authenticating with username/password session."""
        from urllib.parse import urlparse

        url = (url or "").strip().rstrip("/") or "https://127.0.0.1:8834"
        if not url.startswith("http"):
            url = f"https://{url}"

        p = urlparse(url)
        host = p.hostname or "127.0.0.1"
        port = p.port or 8834
        _base = f"https://{host}:{port}"

        sess = requests.Session()
        sess.verify = verify_ssl

        r = sess.post(f"{_base}/session",
                      json={"username": username, "password": password}, timeout=15)
        if r.status_code != 200:
            raise ConnectionError(f"Authentication failed (HTTP {r.status_code})")

        token = r.json().get("token", "")
        sess.headers["X-Cookie"] = f"token={token}"

        api_token = cls._extract_api_token(sess, _base)
        if not api_token:
            log.warning("Nessus API token not found — POST requests may fail (CSRF)")

        return cls(host=host, port=port, verify_ssl=verify_ssl,
                   _token=token, _api_token=api_token, _session=sess)

    def _url(self, path):
        return f"{self.base_url}{path}"

    def _get(self, path, **kwargs):
        return self.session.get(self._url(path), timeout=self._timeout, **kwargs)

    def _post(self, path, **kwargs):
        try:
            return self.session.post(self._url(path), timeout=self._timeout, **kwargs)
        except ConnectionError as e:
            if "ConnectionResetError" in str(e) or "ConnectionReset" in str(e):
                if not self.session.headers.get("X-API-Token"):
                    raise ConnectionError(
                        "Nessus rejected the request (connection reset). "
                        "This usually means the CSRF API token could not be "
                        "extracted. Try using API keys in Nessus Settings instead."
                    ) from e
            raise

    def _put(self, path, **kwargs):
        return self.session.put(self._url(path), timeout=self._timeout, **kwargs)

    def _delete(self, path, **kwargs):
        return self.session.delete(self._url(path), timeout=self._timeout, **kwargs)

    # ── Connection test ──────────────────────────────────────────
    def test_connection(self):
        """Test connectivity to the Nessus server. Returns (ok, message)."""
        try:
            r = self._get("/server/status")
            if r.status_code == 200:
                data = r.json()
                status = data.get("status", "unknown")
                return True, f"Connected. Server status: {status}"
            return False, f"HTTP {r.status_code}: {r.text[:200]}"
        except ConnectionError:
            return False, f"Cannot connect to {self.base_url}"
        except Timeout:
            return False, f"Connection timed out to {self.base_url}"
        except Exception as e:
            return False, str(e)

    # ── Server info ──────────────────────────────────────────────
    def server_properties(self):
        r = self._get("/server/properties")
        r.raise_for_status()
        return r.json()

    # ── Templates ────────────────────────────────────────────────
    def list_templates(self):
        """List scan policy templates."""
        r = self._get("/editor/scan/templates")
        r.raise_for_status()
        data = r.json()
        return data.get("templates", [])

    # ── Policies ─────────────────────────────────────────────────
    def list_policies(self):
        r = self._get("/policies")
        r.raise_for_status()
        data = r.json()
        return data.get("policies", [])

    # ── Folders ──────────────────────────────────────────────────
    def list_folders(self):
        r = self._get("/folders")
        r.raise_for_status()
        data = r.json()
        return data.get("folders", [])

    # ── Scan CRUD ────────────────────────────────────────────────
    def create_scan(self, name, targets, template_uuid, policy_id=None,
                    folder_id=None, advanced_settings=None,
                    exclusions=None):
        """Create a new scan. Returns the scan_id (int).

        advanced_settings: dict with optional keys:
          discovery: {ping_methods: ["ARP","TCP","ICMP","UDP"]}
          port_range: "default" | "21, 22, 80" | "1-2000" | "all"
          port_scanners: ["tcp", "syn", "udp"]
          webapp_scanning: bool
        exclusions: list of IPs/CIDRs/hostnames to exclude from scanning
        """
        settings = {
            "name": name,
            "text_targets": targets if isinstance(targets, str) else ",".join(targets),
        }
        if exclusions:
            excl_str = exclusions if isinstance(exclusions, str) else ",".join(exclusions)
            if excl_str.strip():
                settings["text_targets_exclude"] = excl_str
        if folder_id:
            settings["folder_id"] = folder_id
        if policy_id:
            settings["policy_id"] = policy_id

        payload = {}
        if template_uuid:
            payload["uuid"] = template_uuid
        if policy_id:
            payload["settings"] = settings
            payload["settings"]["policy_id"] = policy_id
        else:
            payload["settings"] = settings

        if advanced_settings:
            adv = advanced_settings
            discovery = adv.get("discovery", {})
            ping_methods = discovery.get("ping_methods", [])
            if ping_methods:
                settings["ping"] = "yes"
                for m in ["ARP", "TCP", "ICMP", "UDP"]:
                    settings[f"ping_{m.lower()}"] = "yes" if m in ping_methods else "no"
            else:
                settings["ping"] = "no"

            port_range = adv.get("port_range", "default")
            if port_range and port_range != "default":
                settings["portscan_range"] = port_range

            scanners = adv.get("port_scanners", [])
            if scanners:
                settings["scan_network_ports"] = "yes"
                settings["tcp_scanner"] = "yes" if "tcp" in scanners else "no"
                settings["syn_scanner"] = "yes" if "syn" in scanners else "no"
                settings["udp_scanner"] = "yes" if "udp" in scanners else "no"

            if adv.get("webapp_scanning"):
                settings["assess_web_applications"] = "yes"

        r = self._post("/scans", json=payload)
        r.raise_for_status()
        data = r.json()
        return data["scan"]["id"]

    def launch_scan(self, scan_id):
        """Launch a scan. Returns the scan UUID string."""
        r = self._post(f"/scans/{scan_id}/launch")
        r.raise_for_status()
        return r.json().get("scan_uuid", "")

    def scan_status(self, scan_id):
        """Get scan status. Returns dict with status, progress, hosts info."""
        r = self._get(f"/scans/{scan_id}")
        r.raise_for_status()
        data = r.json()
        info = data.get("info", {})
        return {
            "status": info.get("status", "unknown"),
            "progress": info.get("scanner_start") and info.get("scanner_end"),
            "host_count": len(data.get("hosts", [])),
            "history": data.get("history", []),
            "vulnerabilities": data.get("vulnerabilities", []),
        }

    def list_scans(self):
        r = self._get("/scans")
        r.raise_for_status()
        data = r.json()
        return data.get("scans", []) or []

    def delete_scan(self, scan_id):
        r = self._delete(f"/scans/{scan_id}")
        r.raise_for_status()

    # ── Export ────────────────────────────────────────────────────
    def export_scan(self, scan_id, fmt="nessus"):
        """Request a scan export. Returns the file_id for download polling.
        fmt: "nessus" (XML), "csv", "html"
        """
        r = self._post(f"/scans/{scan_id}/export", json={"format": fmt})
        r.raise_for_status()
        return r.json()["file"]

    def export_status(self, scan_id, file_id):
        """Check export readiness. Returns status string ("loading" or "ready")."""
        r = self._get(f"/scans/{scan_id}/export/{file_id}/status")
        r.raise_for_status()
        return r.json().get("status", "loading")

    def download_export(self, scan_id, file_id):
        """Download the exported file. Returns raw bytes."""
        r = self._get(f"/scans/{scan_id}/export/{file_id}/download", stream=True)
        r.raise_for_status()
        return r.content

    def export_and_download(self, scan_id, fmt="nessus", poll_interval=5, max_wait=600):
        """Export, poll until ready, download. Returns bytes or raises."""
        file_id = self.export_scan(scan_id, fmt)
        elapsed = 0
        while elapsed < max_wait:
            status = self.export_status(scan_id, file_id)
            if status == "ready":
                return self.download_export(scan_id, file_id)
            time.sleep(poll_interval)
            elapsed += poll_interval
        raise TimeoutError(f"Export not ready after {max_wait}s")

    # ── Upload ───────────────────────────────────────────────────
    def upload_nessus_file(self, file_path):
        """Upload a .nessus file to the server. Returns the file key."""
        with open(file_path, "rb") as f:
            r = self._post("/file/upload", files={"Filedata": (Path(file_path).name, f, "text/xml")})
        r.raise_for_status()
        return r.json().get("fileuploaded", "")

    def import_scan(self, file_key, folder_id=None):
        """Import a previously uploaded .nessus file."""
        payload = {"file": file_key}
        if folder_id:
            payload["folder_id"] = folder_id
        r = self._post("/scans/import", json=payload)
        r.raise_for_status()
        return r.json()

    # ── Parse .nessus XML ────────────────────────────────────────
    @staticmethod
    def parse_nessus_xml(xml_path):
        """Parse a .nessus XML file into a list of finding dicts.

        Maps Nessus severity integers to risk strings:
          0=INFO, 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL
        """
        sev_map = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
        findings = []

        tree = ET.parse(xml_path)
        root = tree.getroot()

        for report in root.iter("Report"):
            for host in report.iter("ReportHost"):
                host_ip = host.get("name", "")
                # Extract host properties
                hostname = ""
                os_name = ""
                for tag in host.iter("tag"):
                    tag_name = tag.get("name", "")
                    if tag_name == "host-fqdn":
                        hostname = tag.text or ""
                    elif tag_name == "host-ip":
                        host_ip = tag.text or host_ip
                    elif tag_name == "operating-system":
                        os_name = tag.text or ""

                for item in host.iter("ReportItem"):
                    severity = int(item.get("severity", 0))
                    port = int(item.get("port", 0))
                    plugin_id = int(item.get("pluginID", 0))
                    plugin_name = item.get("pluginName", "")
                    svc_name = item.get("svc_name", "")
                    protocol = item.get("protocol", "")

                    description = ""
                    synopsis = ""
                    solution = ""
                    plugin_output = ""
                    cve_list = []
                    cvss_score = None
                    cvss_vector = ""
                    exploit_available = False
                    exploitability_ease = ""

                    for child in item:
                        tag = child.tag
                        text = (child.text or "").strip()
                        if tag == "description":
                            description = text
                        elif tag == "synopsis":
                            synopsis = text
                        elif tag == "solution":
                            solution = text
                        elif tag == "plugin_output":
                            plugin_output = text
                        elif tag == "cve":
                            cve_list.append(text)
                        elif tag == "cvss3_base_score":
                            try:
                                cvss_score = float(text)
                            except (ValueError, TypeError):
                                pass
                        elif tag == "cvss3_vector":
                            cvss_vector = text
                        elif tag == "cvss_base_score" and cvss_score is None:
                            try:
                                cvss_score = float(text)
                            except (ValueError, TypeError):
                                pass
                        elif tag == "cvss_vector" and not cvss_vector:
                            cvss_vector = text
                        elif tag == "exploit_available":
                            exploit_available = text.lower() == "true"
                        elif tag == "exploitability_ease":
                            exploitability_ease = text

                    finding = {
                        "tool": "nessus",
                        "title": plugin_name,
                        "ip": host_ip,
                        "port": port,
                        "hostname": hostname,
                        "service": svc_name,
                        "risk": sev_map.get(severity, "INFO"),
                        "description": description or synopsis,
                        "remediation": solution,
                        "output": plugin_output[:4096] if plugin_output else "",
                        "cves": ",".join(cve_list),
                        "nessus_plugin_id": plugin_id,
                        "nessus_plugin_name": plugin_name,
                        "plugin_output": plugin_output,
                        "cvss_score": cvss_score,
                        "cvss_vector": cvss_vector,
                        "exploitdb": exploit_available,
                        "metasploit": "Metasploit" in exploitability_ease,
                        "exploit_details": [],
                        "sources": "nessus",
                        "affected": f"{host_ip}:{port}",
                        "command": f"Nessus plugin {plugin_id}",
                        "datetime": "",
                    }
                    findings.append(finding)

        return findings

    @staticmethod
    def save_findings(findings, output_path):
        """Save parsed findings to a JSON file."""
        with open(output_path, "w") as f:
            json.dump(findings, f, indent=2, default=str)
        log.info("Saved %d Nessus findings to %s", len(findings), output_path)
