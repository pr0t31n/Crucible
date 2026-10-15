"""Nmap XML parser — matches SS3 finding title/risk conventions."""

import re
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from parsers.base import BaseParser

_INSECURE_PROTOCOLS = {
    "ftp": "FTP", "telnet": "Telnet", "rsh": "RSH", "rlogin": "Rlogin",
    "rexec": "Rexec", "finger": "Finger", "tftp": "TFTP",
    "snmp": "SNMP (v1/v2c)",
}

_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 8008, 3000, 5000, 9443,
              4443, 3443, 8444, 9090, 8081, 8082, 8083, 8084, 8085}

_STANDARD_PORT_FOR_SERVICE = {
    "ssh": 22, "ftp": 21, "telnet": 23, "smtp": 25, "dns": 53,
    "http": 80, "pop3": 110, "imap": 143, "https": 443,
    "smb": 445, "mssql": 1433, "oracle": 1521, "mysql": 3306,
    "rdp": 3389, "postgresql": 5432, "redis": 6379,
    "vnc": 5900, "mongodb": 27017,
}


class NmapParser(BaseParser):
    TOOL_ID = "nmap"
    TOOL_NAME = "nmap"
    SUPPORTED_FORMATS = ["xml"]

    def parse(self):
        self.emit("[nmap] Parsing XML")
        try:
            tree = ET.parse(str(self.file_path))
        except ET.ParseError as e:
            self.emit(f"[nmap] XML parse error: {e}")
            return
        root = tree.getroot()
        scan_start = root.get("startstr", "")
        nmap_args = root.get("args", "")

        for host_el in root.findall(".//host"):
            status = host_el.find("status")
            if status is not None and status.get("state") != "up":
                continue

            ip = ""
            hostname = ""
            addr_el = host_el.find("address[@addrtype='ipv4']")
            if addr_el is None:
                addr_el = host_el.find("address[@addrtype='ipv6']")
            if addr_el is not None:
                ip = addr_el.get("addr", "")

            hn_el = host_el.find(".//hostname")
            if hn_el is not None:
                hostname = hn_el.get("name", "")

            yield ("target", {"ip": ip, "hostname": hostname})
            self.emit(f"[nmap] Host: {ip}" +
                      (f" ({hostname})" if hostname else ""))

            ports_data = []
            for port_el in host_el.findall(".//port"):
                port_state = port_el.find("state")
                if port_state is None:
                    continue
                state = port_state.get("state", "")
                if state not in ("open", "open|filtered"):
                    continue

                port_num = int(port_el.get("portid", "0"))
                proto = port_el.get("protocol", "tcp")
                svc_el = port_el.find("service")
                service = svc_el.get("name", "") if svc_el is not None else ""
                product = svc_el.get("product", "") if svc_el is not None else ""
                version = svc_el.get("version", "") if svc_el is not None else ""
                extra = svc_el.get("extrainfo", "") if svc_el is not None else ""

                port_data = {
                    "ip": ip, "port": port_num, "protocol": proto,
                    "service": service, "hostname": hostname,
                    "product": product, "version": version,
                    "state": state,
                }
                ports_data.append(port_data)
                yield ("port", port_data)

                # NSE scripts on this port
                for script_el in port_el.findall("script"):
                    yield from self._handle_nse(
                        script_el, ip, port_num, hostname, service,
                        nmap_args)

            # Host-level scripts
            hostscript = host_el.find("hostscript")
            if hostscript is not None:
                for script_el in hostscript.findall("script"):
                    yield from self._handle_nse(
                        script_el, ip, 0, hostname, "", nmap_args)

            # Open Ports finding (aggregate)
            open_ports = [p for p in ports_data if p["state"] == "open"]
            if open_ports:
                yield from self._emit_open_ports(
                    ip, hostname, open_ports, nmap_args)

            # UDP open|filtered
            udp_filtered = [p for p in ports_data
                            if p["state"] == "open|filtered"
                            and p["protocol"] == "udp"]
            if udp_filtered:
                yield from self._emit_udp_filtered(
                    ip, hostname, udp_filtered, nmap_args)

            # Insecure protocol detection
            for pd in open_ports:
                svc = pd["service"].lower()
                if svc in _INSECURE_PROTOCOLS:
                    name = _INSECURE_PROTOCOLS[svc]
                    if svc == "http" and pd["port"] in (80, 8080, 8000, 8008):
                        yield ("finding", self._finding(
                            ip, pd["port"], hostname,
                            title="Insecure Protocol Detected: HTTP",
                            risk="LOW",
                            description=f"HTTP service detected on port "
                                        f"{pd['port']} without TLS encryption.",
                            command=nmap_args,
                            service=pd["service"],
                        ))
                    else:
                        yield ("finding", self._finding(
                            ip, pd["port"], hostname,
                            title=f"Insecure Protocol Detected: {name}",
                            risk="MEDIUM" if svc in ("telnet", "ftp",
                                                      "rsh", "rlogin",
                                                      "rexec") else "LOW",
                            description=f"{name} is an insecure protocol that "
                                        f"transmits data in cleartext.",
                            command=nmap_args,
                            service=pd["service"],
                        ))

            # Non-standard port detection
            for pd in open_ports:
                svc = pd["service"].lower()
                port = pd["port"]
                if svc in ("http", "https") and port not in _WEB_PORTS:
                    yield ("finding", self._finding(
                        ip, port, hostname,
                        title="Non-Standard Web Port Detected",
                        risk="INFO",
                        description=f"Web service ({svc}) detected on "
                                    f"non-standard port {port}.",
                        command=nmap_args,
                        service=pd["service"],
                    ))
                std = _STANDARD_PORT_FOR_SERVICE.get(svc)
                if std and port != std and svc not in ("http", "https"):
                    yield ("finding", self._finding(
                        ip, port, hostname,
                        title=f"Non-Standard Port for {svc.upper()}",
                        risk="INFO",
                        description=f"{svc.upper()} running on port {port} "
                                    f"instead of standard port {std}.",
                        command=nmap_args,
                        service=pd["service"],
                    ))

        self.emit("[nmap] Parse complete")

    def extract_targets(self):
        targets = set()
        try:
            tree = ET.parse(str(self.file_path))
            for addr in tree.findall(".//address[@addrtype='ipv4']"):
                targets.add(addr.get("addr", ""))
            for addr in tree.findall(".//address[@addrtype='ipv6']"):
                targets.add(addr.get("addr", ""))
            for hn in tree.findall(".//hostname"):
                n = hn.get("name", "")
                if n:
                    targets.add(n)
        except ET.ParseError:
            pass
        targets.discard("")
        return targets

    def _emit_open_ports(self, ip, hostname, ports, cmd):
        lines = []
        for p in sorted(ports, key=lambda x: x["port"]):
            svc = p["service"] or "unknown"
            prod = p["product"]
            ver = p["version"]
            desc = f"{p['port']}/{p['protocol']} {svc}"
            if prod:
                desc += f" ({prod}"
                if ver:
                    desc += f" {ver}"
                desc += ")"
            lines.append(desc)

        yield ("finding", self._finding(
            ip, 0, hostname,
            title="Discovery: Open Ports",
            risk="INFO",
            description=f"{len(ports)} open port(s) identified.",
            output="\n".join(lines),
            command=cmd,
        ))

    def _emit_udp_filtered(self, ip, hostname, ports, cmd):
        lines = [f"{p['port']}/udp {p['service'] or 'unknown'}"
                 for p in sorted(ports, key=lambda x: x["port"])]
        yield ("finding", self._finding(
            ip, 0, hostname,
            title="Unconfirmed UDP Ports (open|filtered)",
            risk="INFO",
            description=f"{len(ports)} UDP port(s) in open|filtered state.",
            output="\n".join(lines),
            command=cmd,
        ))

    def _handle_nse(self, script_el, ip, port, hostname, service, cmd):
        script_id = script_el.get("id", "")
        output = script_el.get("output", "").strip()
        if not script_id:
            return

        # SMBv1
        if script_id == "smb-protocols" and "SMBv1" in output:
            yield ("finding", self._finding(
                ip, port or 445, hostname,
                title="SMBv1 Protocol Enabled (EternalBlue risk)",
                risk="HIGH",
                description="SMBv1 is enabled. This protocol is deprecated "
                            "and vulnerable to EternalBlue (MS17-010).",
                output=output, command=cmd, service=service,
                cves="CVE-2017-0144",
            ))

        # EternalBlue
        elif script_id == "smb-vuln-ms17-010":
            if "VULNERABLE" in output:
                yield ("finding", self._finding(
                    ip, port or 445, hostname,
                    title="EternalBlue (MS17-010) — Host Confirmed Vulnerable",
                    risk="CRITICAL",
                    description="Host is confirmed vulnerable to MS17-010 "
                                "(EternalBlue) remote code execution.",
                    output=output, command=cmd, service=service,
                    cves="CVE-2017-0144,CVE-2017-0145,CVE-2017-0146",
                ))

        # SMB signing
        elif script_id == "smb2-security-mode":
            if "signing" in output.lower():
                if "not required" in output.lower():
                    if "enabled" in output.lower():
                        yield ("finding", self._finding(
                            ip, port or 445, hostname,
                            title="SMB Signing Enabled but Not Required",
                            risk="MEDIUM",
                            description="SMB signing is enabled but not "
                                        "required. An attacker could relay "
                                        "SMB authentication.",
                            output=output, command=cmd, service=service,
                        ))
                    else:
                        yield ("finding", self._finding(
                            ip, port or 445, hostname,
                            title="SMB Signing Disabled or Not Required",
                            risk="HIGH",
                            description="SMB message signing is disabled. "
                                        "This allows SMB relay attacks.",
                            output=output, command=cmd, service=service,
                        ))

        # MS12-020 RDP
        elif script_id == "rdp-vuln-ms12-020":
            if "VULNERABLE" in output:
                yield ("finding", self._finding(
                    ip, port or 3389, hostname,
                    title="MS12-020 RDP Vulnerability Detected",
                    risk="CRITICAL",
                    description="Host is vulnerable to MS12-020, a "
                                "pre-authentication RDP vulnerability.",
                    output=output, command=cmd, service=service,
                    cves="CVE-2012-0002",
                ))

        # SSHv1
        elif script_id == "sshv1":
            if "supported" in output.lower():
                yield ("finding", self._finding(
                    ip, port or 22, hostname,
                    title="SSH Vulnerability: SSHv1 Protocol Supported",
                    risk="HIGH",
                    description="SSH protocol version 1 is supported. "
                                "SSHv1 has known cryptographic weaknesses.",
                    output=output, command=cmd, service=service,
                ))

        # SSH auth methods
        elif script_id == "ssh-auth-methods":
            if "none_auth" in output.lower() or "'none'" in output.lower():
                yield ("finding", self._finding(
                    ip, port or 22, hostname,
                    title="SSH Vulnerability: 'none' Authentication Accepted "
                          "(libSSH Bypass CVE-2018-10933)",
                    risk="CRITICAL",
                    description="SSH server accepts 'none' authentication, "
                                "potentially allowing unauthenticated access.",
                    output=output, command=cmd, service=service,
                    cves="CVE-2018-10933",
                ))

        # NFS
        elif script_id in ("nfs-showmount", "nfs-ls"):
            if output:
                yield ("finding", self._finding(
                    ip, port or 2049, hostname,
                    title="NFS Export Points Enumerated",
                    risk="MEDIUM",
                    description="NFS export points were enumerated on this "
                                "host. Improperly configured NFS shares may "
                                "expose sensitive data.",
                    output=output, command=cmd, service=service,
                ))

        # Heartbleed
        elif script_id == "ssl-heartbleed":
            if "VULNERABLE" in output:
                yield ("finding", self._finding(
                    ip, port, hostname,
                    title="Heartbleed (CVE-2014-0160) Vulnerability Detected",
                    risk="CRITICAL",
                    description="The host is vulnerable to the Heartbleed "
                                "bug (CVE-2014-0160), which allows attackers "
                                "to read memory from the server.",
                    output=output, command=cmd, service=service,
                    cves="CVE-2014-0160",
                ))

        # SSL cert info
        elif script_id == "ssl-cert":
            if output:
                is_self_signed = "self-signed" in output.lower()
                if is_self_signed:
                    yield ("finding", self._finding(
                        ip, port, hostname,
                        title="SSL/TLS Certificate: Self-Signed",
                        risk="MEDIUM",
                        description="The SSL/TLS certificate is self-signed "
                                    "and will not be trusted by clients.",
                        output=output, command=cmd, service=service,
                    ))
                else:
                    yield ("finding", self._finding(
                        ip, port, hostname,
                        title="SSL/TLS Certificate Information",
                        risk="INFO",
                        description="SSL/TLS certificate details.",
                        output=output, command=cmd, service=service,
                    ))

        # Vulners
        elif script_id == "vulners":
            for line in output.splitlines():
                m = re.match(r'\s*(CVE-\d{4}-\d+)\s+(\d+\.?\d*)\s', line)
                if m:
                    cve = m.group(1)
                    score = float(m.group(2))
                    risk = "CRITICAL" if score >= 9.0 else \
                           "HIGH" if score >= 7.0 else \
                           "MEDIUM" if score >= 4.0 else "LOW"
                    yield ("finding", self._finding(
                        ip, port, hostname,
                        title=f"Vulners: {cve} (CVSS {score})",
                        risk=risk,
                        description=f"Vulnerability {cve} identified via "
                                    f"vulners with CVSS score {score}.",
                        output=line.strip(), command=cmd, service=service,
                        cves=cve,
                        cvss_score=score,
                    ))

        # Generic NSE with VULNERABLE
        elif "VULNERABLE" in output and script_id not in (
                "smb-vuln-ms17-010", "rdp-vuln-ms12-020",
                "ssl-heartbleed"):
            yield ("finding", self._finding(
                ip, port, hostname,
                title=f"NSE Vulnerability: {script_id}",
                risk="HIGH",
                description=f"NSE script {script_id} reports the host as "
                            f"vulnerable.",
                output=output, command=cmd, service=service,
            ))

    @staticmethod
    def _finding(ip, port, hostname, *, title, risk, description,
                 output="", command="", service="", cves="",
                 cvss_score=None):
        f = {
            "id": str(uuid.uuid4()),
            "tool": "nmap",
            "title": title,
            "risk": risk,
            "ip": ip,
            "port": int(port),
            "hostname": hostname,
            "description": description,
            "output": output[:4096],
            "command": command,
            "service": service,
            "cves": cves,
            "datetime": datetime.now().isoformat(),
            "sources": "nmap",
            "affected": f"{ip}:{port}" if port else ip,
            "remediation": "",
            "exploitdb": False,
            "metasploit": False,
            "exploit_details": [],
            "output_file": "",
        }
        if cvss_score is not None:
            f["cvss_score"] = cvss_score
        return f
