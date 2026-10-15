"""Adapters for external (non-pr0t31n) CLI tools launched from action items."""

import shutil
from datetime import datetime
from pathlib import Path

from adapters.base import ToolAdapter

_TS = lambda: datetime.now().strftime("%Y%m%d_%H%M%S")


class _ExternalAdapter(ToolAdapter):
    """Base for external CLI tools — no findings loader, no resume."""

    is_external = True

    def load_findings(self, project_dir, tool_output_dir):
        return []

    def default_settings(self):
        return {}


class NucleiAdapter(_ExternalAdapter):
    tool_id = "nuclei"
    tool_name = "Nuclei"
    tool_key = "NU"
    domain = "vuln"

    def settings_schema(self):
        return {"fields": [
            {"key": "severity", "label": "Severity Filter",
             "type": "select", "options": [
                 "critical,high,medium,low,info",
                 "critical,high,medium,low",
                 "critical,high,medium",
                 "critical,high",
                 "critical",
             ]},
            {"key": "rate_limit", "label": "Rate Limit (req/s)",
             "type": "number", "min": 1, "max": 1000},
            {"key": "concurrency", "label": "Concurrency",
             "type": "number", "min": 1, "max": 100},
            {"key": "timeout", "label": "Timeout (seconds)",
             "type": "number", "min": 10, "max": 3600},
            {"key": "templates", "label": "Templates (comma-separated)",
             "type": "text", "placeholder": "Leave blank for all"},
            {"key": "exclude_templates", "label": "Exclude Templates",
             "type": "text"},
        ]}

    def build_command(self, project, settings, *, resume=False,
                      extra_args=None):
        binary = shutil.which("nuclei")
        if not binary:
            return []
        td = (project.get("tool_dirs") or {}).get("nuclei", "")
        out = Path(td) / f"nuclei_{_TS()}.jsonl" if td else None
        cmd = [binary]
        target = settings.get("target") or ""
        if target:
            cmd.extend(["-target", target])
        sev = settings.get("severity", "critical,high,medium,low,info")
        if sev:
            cmd.extend(["-severity", sev])
        rl = settings.get("rate_limit")
        if rl:
            cmd.extend(["-rate-limit", str(rl)])
        conc = settings.get("concurrency")
        if conc:
            cmd.extend(["-concurrency", str(conc)])
        to = settings.get("timeout")
        if to:
            cmd.extend(["-timeout", str(to)])
        tmpl = settings.get("templates")
        if tmpl:
            cmd.extend(["-templates", tmpl])
        excl = settings.get("exclude_templates")
        if excl:
            cmd.extend(["-exclude-templates", excl])
        if out:
            cmd.extend(["-jsonl", "-output", str(out)])
        if extra_args:
            cmd.extend(extra_args)
        return cmd


class TestSSLAdapter(_ExternalAdapter):
    tool_id = "testssl"
    tool_name = "testssl.sh"
    tool_key = "TS"
    domain = "tls"

    def default_settings(self):
        return {
            "color_off": True,
            "warnings_off": True,
            "quiet": True,
            "connect_timeout": 10,
            "openssl_timeout": 10,
            "timeout": 300,
            "protocols": True,
            "ciphers": True,
            "vulnerabilities": True,
            "headers": True,
        }

    def settings_schema(self):
        return {"fields": [
            {"key": "timeout", "label": "Timeout (seconds) — increase for re-runs",
             "type": "number", "min": 30, "max": 3600},
            {"key": "connect_timeout",
             "label": "TCP Connect Timeout (seconds)",
             "type": "number", "min": 1, "max": 120},
            {"key": "openssl_timeout",
             "label": "OpenSSL Timeout (seconds)",
             "type": "number", "min": 1, "max": 120},
            {"key": "protocols", "label": "Check Protocols",
             "type": "checkbox"},
            {"key": "ciphers", "label": "Check Ciphers",
             "type": "checkbox"},
            {"key": "vulnerabilities", "label": "Check Vulnerabilities",
             "type": "checkbox"},
            {"key": "headers", "label": "Check HTTP Headers",
             "type": "checkbox"},
            {"key": "color_off", "label": "Disable Color Output",
             "type": "checkbox"},
            {"key": "warnings_off", "label": "Suppress Warnings",
             "type": "checkbox"},
            {"key": "quiet", "label": "Quiet Mode",
             "type": "checkbox"},
        ]}

    def build_command(self, project, settings, *, resume=False,
                      extra_args=None):
        binary = shutil.which("testssl") or shutil.which("testssl.sh")
        if not binary:
            return []
        td = (project.get("tool_dirs") or {}).get("testssl", "")
        target = settings.get("target", "")
        cmd = [binary]
        if settings.get("color_off", True):
            cmd.extend(["--color", "0"])
        if settings.get("warnings_off", True):
            cmd.extend(["--warnings", "off"])
        if settings.get("quiet", True):
            cmd.append("--quiet")
        ct = settings.get("connect_timeout", 10)
        if ct:
            cmd.extend(["--connect-timeout", str(ct)])
        ot = settings.get("openssl_timeout", 10)
        if ot:
            cmd.extend(["--openssl-timeout", str(ot)])
        if td:
            out = Path(td) / f"testssl_{_TS()}.json"
            cmd.extend(["--jsonfile", str(out)])
        if settings.get("protocols"):
            cmd.append("-p")
        if settings.get("ciphers"):
            cmd.append("-E")
        if settings.get("vulnerabilities"):
            cmd.append("-U")
        if settings.get("headers"):
            cmd.append("-h")
        if target:
            cmd.append(target)
        if extra_args:
            cmd.extend(extra_args)
        return cmd


class SSLScanAdapter(_ExternalAdapter):
    tool_id = "sslscan"
    tool_name = "sslscan"
    tool_key = "SL"
    domain = "tls"

    def settings_schema(self):
        return {"fields": [
            {"key": "show_ciphers", "label": "Show Supported Ciphers",
             "type": "checkbox"},
            {"key": "no_colour", "label": "No Colour Output",
             "type": "checkbox"},
            {"key": "timeout", "label": "Timeout (seconds)",
             "type": "number", "min": 1, "max": 300},
        ]}

    def build_command(self, project, settings, *, resume=False,
                      extra_args=None):
        binary = shutil.which("sslscan")
        if not binary:
            return []
        td = (project.get("tool_dirs") or {}).get("sslscan", "")
        target = settings.get("target", "")
        cmd = [binary]
        if td:
            out = Path(td) / f"sslscan_{_TS()}.xml"
            cmd.extend(["--xml=" + str(out)])
        if settings.get("show_ciphers"):
            cmd.append("--show-ciphers")
        if settings.get("no_colour"):
            cmd.append("--no-colour")
        to = settings.get("timeout")
        if to:
            cmd.extend(["--connect-timeout=" + str(to)])
        if target:
            cmd.append(target)
        if extra_args:
            cmd.extend(extra_args)
        return cmd


class DroopeScanAdapter(_ExternalAdapter):
    tool_id = "droopescan"
    tool_name = "droopescan"
    tool_key = "DS"
    domain = "webapp"

    def settings_schema(self):
        return {"fields": [
            {"key": "cms", "label": "CMS Type", "type": "select",
             "options": ["drupal", "wordpress", "joomla", "silverstripe",
                         "moodle"]},
            {"key": "threads", "label": "Threads",
             "type": "number", "min": 1, "max": 50},
        ]}

    def build_command(self, project, settings, *, resume=False,
                      extra_args=None):
        binary = shutil.which("droopescan")
        if not binary:
            return []
        target = settings.get("target", "")
        cms = settings.get("cms", "drupal")
        cmd = [binary, "scan", cms, "-u", target]
        threads = settings.get("threads")
        if threads:
            cmd.extend(["-t", str(threads)])
        td = (project.get("tool_dirs") or {}).get("droopescan", "")
        if td:
            out = Path(td) / f"droopescan_{_TS()}.json"
            cmd.extend(["--output", "json", ">", str(out)])
        if extra_args:
            cmd.extend(extra_args)
        return cmd


class DNSTwistAdapter(_ExternalAdapter):
    tool_id = "dnstwist"
    tool_name = "dnstwist"
    tool_key = "DT"
    domain = "recon"

    def settings_schema(self):
        return {"fields": [
            {"key": "registered_only", "label": "Show Registered Only",
             "type": "checkbox"},
            {"key": "whois", "label": "WHOIS Lookups",
             "type": "checkbox"},
            {"key": "geoip", "label": "GeoIP Lookups",
             "type": "checkbox"},
            {"key": "threads", "label": "Threads",
             "type": "number", "min": 1, "max": 50},
        ]}

    def build_command(self, project, settings, *, resume=False,
                      extra_args=None):
        binary = shutil.which("dnstwist")
        if not binary:
            return []
        target = settings.get("target", "")
        td = (project.get("tool_dirs") or {}).get("dnstwist", "")
        cmd = [binary]
        if settings.get("registered_only"):
            cmd.append("--registered")
        if settings.get("whois"):
            cmd.append("--whois")
        if settings.get("geoip"):
            cmd.append("--geoip")
        threads = settings.get("threads")
        if threads:
            cmd.extend(["--threads", str(threads)])
        if td:
            out = Path(td) / f"dnstwist_{_TS()}.json"
            cmd.extend(["--format", "json", "--output", str(out)])
        if target:
            cmd.append(target)
        if extra_args:
            cmd.extend(extra_args)
        return cmd


class XURLFind3rAdapter(_ExternalAdapter):
    tool_id = "xurlfind3r"
    tool_name = "xurlfind3r"
    tool_key = "XU"
    domain = "recon"

    def default_settings(self):
        return {
            "include_subdomains": True,
            "monochrome": True,
            "silent": True,
            "timeout": 900,
        }

    def settings_schema(self):
        return {"fields": [
            {"key": "timeout", "label": "Timeout (seconds) — increase for re-runs",
             "type": "number", "min": 30, "max": 7200},
            {"key": "include_subdomains", "label": "Include Subdomains",
             "type": "checkbox"},
            {"key": "monochrome", "label": "Monochrome (no color)",
             "type": "checkbox"},
            {"key": "silent", "label": "Silent (suppress banner)",
             "type": "checkbox"},
            {"key": "threads", "label": "Threads",
             "type": "number", "min": 1, "max": 50},
        ]}

    def build_command(self, project, settings, *, resume=False,
                      extra_args=None):
        binary = shutil.which("xurlfind3r")
        if not binary:
            return []
        target = settings.get("target", "")
        td = (project.get("tool_dirs") or {}).get("xurlfind3r", "")
        cmd = [binary, "-d", target]
        if settings.get("include_subdomains", True):
            cmd.append("--include-subdomains")
        if settings.get("monochrome", True):
            cmd.append("-m")
        if settings.get("silent", True):
            cmd.append("-s")
        threads = settings.get("threads")
        if threads:
            cmd.extend(["-t", str(threads)])
        if td:
            out = Path(td) / f"xurlfind3r_{_TS()}.txt"
            cmd.extend(["-o", str(out)])
        if extra_args:
            cmd.extend(extra_args)
        return cmd


class EmailHarvesterAdapter(_ExternalAdapter):
    tool_id = "emailharvester"
    tool_name = "EmailHarvester"
    tool_key = "EH"
    domain = "recon"

    def settings_schema(self):
        return {"fields": [
            {"key": "engines", "label": "Search Engines",
             "type": "text", "placeholder": "all (default)"},
            {"key": "limit", "label": "Result Limit",
             "type": "number", "min": 1, "max": 1000},
        ]}

    def build_command(self, project, settings, *, resume=False,
                      extra_args=None):
        binary = shutil.which("EmailHarvester") or shutil.which("emailharvester")
        if not binary:
            return []
        target = settings.get("target", "")
        td = (project.get("tool_dirs") or {}).get("emailharvester", "")
        cmd = [binary, "-d", target]
        engines = settings.get("engines")
        if engines and engines != "all":
            cmd.extend(["-e", engines])
        limit = settings.get("limit")
        if limit:
            cmd.extend(["-l", str(limit)])
        cmd.append("--noprint")
        if td:
            out = Path(td) / f"emailharvester_{_TS()}.txt"
            cmd.extend(["-s", str(out)])
        if extra_args:
            cmd.extend(extra_args)
        return cmd


class ASNMapAdapter(_ExternalAdapter):
    tool_id = "asnmap"
    tool_name = "asnmap"
    tool_key = "AN"
    domain = "recon"

    def settings_schema(self):
        return {"fields": [
            {"key": "json_output", "label": "JSON Output",
             "type": "checkbox"},
        ]}

    def build_command(self, project, settings, *, resume=False,
                      extra_args=None):
        binary = shutil.which("asnmap")
        if not binary:
            return []
        target = settings.get("target", "")
        td = (project.get("tool_dirs") or {}).get("asnmap", "")
        cmd = [binary, "-a", target]
        if settings.get("json_output"):
            cmd.append("-json")
        if td:
            out = Path(td) / f"asnmap_{_TS()}.txt"
            cmd.extend(["-o", str(out)])
        if extra_args:
            cmd.extend(extra_args)
        return cmd


class WebAnalyzeAdapter(_ExternalAdapter):
    tool_id = "webanalyze"
    tool_name = "webanalyze"
    tool_key = "WA"
    domain = "recon"

    def settings_schema(self):
        return {"fields": [
            {"key": "crawl", "label": "Crawl Depth",
             "type": "number", "min": 0, "max": 10},
            {"key": "redirect", "label": "Follow Redirects",
             "type": "checkbox"},
            {"key": "workers", "label": "Workers",
             "type": "number", "min": 1, "max": 20},
        ]}

    def build_command(self, project, settings, *, resume=False,
                      extra_args=None):
        binary = shutil.which("webanalyze")
        if not binary:
            return []
        target = settings.get("target", "")
        td = (project.get("tool_dirs") or {}).get("webanalyze", "")
        cmd = [binary, "-host", target]
        crawl = settings.get("crawl")
        if crawl is not None:
            cmd.extend(["-crawl", str(crawl)])
        if settings.get("redirect"):
            cmd.append("-redirect")
        workers = settings.get("workers")
        if workers:
            cmd.extend(["-worker", str(workers)])
        if td:
            out = Path(td) / f"webanalyze_{_TS()}.json"
            cmd.extend(["-output", "json"])
        if extra_args:
            cmd.extend(extra_args)
        return cmd


class AmassAdapter(_ExternalAdapter):
    tool_id = "amass"
    tool_name = "Amass"
    tool_key = "AM"
    domain = "recon"

    def default_settings(self):
        return {
            "passive": True,
            "timeout": 10,
        }

    def settings_schema(self):
        return {"fields": [
            {"key": "timeout", "label": "Timeout (minutes) — increase for re-runs",
             "type": "number", "min": 1, "max": 120},
            {"key": "passive", "label": "Passive Mode (no active probing)",
             "type": "checkbox"},
        ]}

    def build_command(self, project, settings, *, resume=False,
                      extra_args=None):
        binary = shutil.which("amass")
        if not binary:
            return []
        target = settings.get("target", "")
        td = (project.get("tool_dirs") or {}).get("amass", "")
        cmd = [binary, "enum"]
        if settings.get("passive", True):
            cmd.append("-passive")
        cmd.extend(["-d", target])
        to = settings.get("timeout", 10)
        if to:
            cmd.extend(["-timeout", str(to)])
        if td:
            out = Path(td) / f"amass_{_TS()}.txt"
            cmd.extend(["-o", str(out)])
        if extra_args:
            cmd.extend(extra_args)
        return cmd
