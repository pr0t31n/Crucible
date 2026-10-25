"""Scope manager — scope definition, target checking, dynamic discovery.

Determines whether a target (IP, hostname, URL, SSID) falls within a
project's defined scope.  Used by the ActionEngine to tag action items
as in-scope or out-of-scope, and by the UI to highlight scope issues.

Thread-safe: parsed scope objects are cached per project_id.
"""

import ipaddress
import logging
import threading
from urllib.parse import urlparse

log = logging.getLogger("crucible.scope_manager")


class ScopeManager:
    """Parse, cache, and check scope definitions for projects."""

    def __init__(self):
        self._cache = {}       # {project_id: parsed_scope}
        self._lock = threading.Lock()

    # ── Scope loading ───────────────────────────────────────────────────

    def load_scope(self, project):
        """Parse and cache scope definition from project metadata.

        Parameters
        ----------
        project : dict
            Full project dict (must include ``id`` and
            ``scope_definition``).

        Returns
        -------
        dict  with keys: networks, urls, domains, ips, ssids,
              db_targets, exclusion_networks, exclusion_hosts
        """
        pid = project.get("id", "")
        scope_def = project.get("scope_definition", {})

        # Parse network CIDRs
        networks = []
        for cidr in scope_def.get("network_cidrs", []):
            if not cidr:
                continue
            cidr = cidr.strip()
            if not cidr:
                continue
            try:
                networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                log.warning("Invalid CIDR in scope: %r", cidr)

        # Parse target URLs and extract domains/IPs
        urls = []
        domains = set()
        scope_ips = set()
        for raw_url in scope_def.get("target_urls", []):
            if not raw_url:
                continue
            parsed = urlparse(raw_url if "://" in raw_url
                              else f"http://{raw_url}")
            urls.append(parsed)
            host = parsed.hostname
            if host:
                domains.add(host.lower())
                try:
                    scope_ips.add(ipaddress.ip_address(host))
                except ValueError as exc:
                    log.debug("scope URL host not IP: %s", exc)

        # OSINT domains
        for d in scope_def.get("domains", []):
            if d and d.strip():
                domains.add(d.strip().lower())

        # Wireless SSIDs
        ssids = [s.strip() for s in scope_def.get("wireless_ssids", []) if s and s.strip()]

        # DB targets
        db_targets = [d for d in scope_def.get("db_targets", []) if d]

        # Endpoint targets (Dredge)
        endpoint_targets = [e.strip() for e in scope_def.get("endpoint_targets", []) if e and e.strip()]

        # Exclusions — can be IPs, CIDRs, hostnames, or URLs
        exclusion_networks = []
        exclusion_hosts = set()
        for exc in scope_def.get("exclusions", []):
            if not exc:
                continue
            try:
                exclusion_networks.append(
                    ipaddress.ip_network(exc, strict=False))
            except ValueError:
                exclusion_hosts.add(exc.lower().strip())

        parsed = {
            "networks": networks,
            "urls": urls,
            "domains": domains,
            "ips": scope_ips,
            "ssids": ssids,
            "db_targets": db_targets,
            "endpoint_targets": endpoint_targets,
            "exclusion_networks": exclusion_networks,
            "exclusion_hosts": exclusion_hosts,
        }

        with self._lock:
            self._cache[pid] = parsed

        return parsed

    def _get_scope(self, project):
        """Retrieve cached scope or parse it."""
        pid = project.get("id", "")
        with self._lock:
            cached = self._cache.get(pid)
        if cached is not None:
            return cached
        return self.load_scope(project)

    def invalidate(self, project_id):
        """Drop cached scope for a project (call after scope edit)."""
        with self._lock:
            self._cache.pop(project_id, None)

    # ── Exclusion check ─────────────────────────────────────────────────

    def is_excluded(self, project, target):
        """Check if target is in the exclusion list.

        ``target`` can be an IP string, hostname, or URL.
        """
        scope = self._get_scope(project)

        # Try as IP
        try:
            addr = ipaddress.ip_address(target)
            for net in scope["exclusion_networks"]:
                if addr in net:
                    return True
        except ValueError:
            pass

        # Check hostname / URL host
        host = target.lower().strip()
        if "://" in host:
            parsed = urlparse(host)
            host = (parsed.hostname or "").lower()
        if host in scope["exclusion_hosts"]:
            return True

        return False

    # ── IP check ────────────────────────────────────────────────────────

    def is_ip_in_scope(self, project, ip_str):
        """Check if an IP is in any of the scope CIDRs / IPs and not
        excluded."""
        ip_str = ip_str.strip() if ip_str else ""
        if not ip_str:
            return False
        if self.is_excluded(project, ip_str):
            return False

        scope = self._get_scope(project)
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False

        # Direct IP match
        if addr in scope["ips"]:
            return True

        # CIDR match
        for net in scope["networks"]:
            if addr in net:
                return True

        return False

    # ── URL check ───────────────────────────────────────────────────────

    def is_url_in_scope(self, project, url_str):
        """Check if a URL's host is in scope."""
        parsed = urlparse(url_str if "://" in url_str
                          else f"http://{url_str}")
        host = parsed.hostname
        if not host:
            return False

        if self.is_excluded(project, host):
            return False

        scope = self._get_scope(project)

        # Domain match
        if host.lower() in scope["domains"]:
            return True

        # Subdomain match — check if host ends with .domain
        host_lower = host.lower()
        for domain in scope["domains"]:
            if host_lower.endswith(f".{domain}"):
                return True

        # IP match (URL may use an IP as host)
        try:
            addr = ipaddress.ip_address(host)
            if addr in scope["ips"]:
                return True
            for net in scope["networks"]:
                if addr in net:
                    return True
        except ValueError:
            pass

        return False

    # ── Generic check ───────────────────────────────────────────────────

    def is_in_scope(self, project, target):
        """Check if a target (IP, URL, or hostname) is within the
        project's scope.

        Tries IP check first, then URL, then hostname-as-domain.
        """
        if self.is_excluded(project, target):
            return False

        # Try as IP
        try:
            ipaddress.ip_address(target)
            return self.is_ip_in_scope(project, target)
        except ValueError:
            pass

        # Try as URL
        if "://" in target or "/" in target:
            return self.is_url_in_scope(project, target)

        # Treat as hostname — check against domains
        scope = self._get_scope(project)
        target_lower = target.lower().strip()
        if target_lower in scope["domains"]:
            return True
        for domain in scope["domains"]:
            if target_lower.endswith(f".{domain}"):
                return True

        return False

    # ── SSID check ──────────────────────────────────────────────────────

    def is_ssid_in_scope(self, project, ssid):
        """Check if a wireless SSID is in scope."""
        scope = self._get_scope(project)
        return ssid in scope["ssids"]

    # ── DB target check ─────────────────────────────────────────────────

    def is_db_in_scope(self, project, db_target):
        """Check if a DB target (host:port or connection string) is in
        scope."""
        scope = self._get_scope(project)
        if db_target in scope["db_targets"]:
            return True
        # Also check if the host part is in scope
        host = db_target.split(":")[0] if ":" in db_target else db_target
        return self.is_ip_in_scope(project, host) or \
            self.is_in_scope(project, host)

    # ── OOS eligibility ─────────────────────────────────────────────────

    def is_oos_eligible(self, project, hostname="", ip_str=""):
        """Check if a derived target is eligible for out-of-scope testing.

        A derived target is eligible if it shares EITHER:
          - A parent domain with an explicitly in-scope domain, OR
          - An IP address with an explicitly in-scope IP/CIDR

        Returns True if eligible (may be tested under OOS modes 2/3),
        False if it should remain untested.
        """
        scope = self._get_scope(project)

        if self.is_excluded(project, hostname or ip_str):
            return False

        # Check parent domain match
        if hostname:
            h = hostname.lower().strip()
            for domain in scope["domains"]:
                if h == domain or h.endswith(f".{domain}"):
                    return True

        # Check IP match against scope CIDRs and IPs
        if ip_str:
            ip_str = ip_str.strip()
            try:
                addr = ipaddress.ip_address(ip_str)
                if addr in scope["ips"]:
                    return True
                for net in scope["networks"]:
                    if addr in net:
                        return True
            except ValueError as exc:
                log.debug("is_oos_eligible ip not valid: %s", exc)

        return False

    # ── Dynamic discovery tracking ──────────────────────────────────────

    def add_dynamic_target(self, project_dir, target_data):
        """Add a dynamically discovered target to scope tracking.

        This does NOT modify the project's scope_definition — it just
        records the target in a discovery log for the operator to review.
        """
        import json
        from pathlib import Path

        discovery_file = Path(project_dir) / "discovered_targets.json"
        try:
            if discovery_file.exists():
                with open(discovery_file) as f:
                    targets = json.load(f)
            else:
                targets = []
        except (json.JSONDecodeError, OSError) as exc:
            log.debug("add_dynamic_target load failed: %s", exc)
            targets = []

        # Dedup by (ip, port) or (ssid) or (url)
        dedup_key = target_data.get("ip", "") + ":" + \
            str(target_data.get("port", ""))
        if target_data.get("ssid"):
            dedup_key = f"ssid:{target_data['ssid']}"
        elif target_data.get("url"):
            dedup_key = f"url:{target_data['url']}"

        for existing in targets:
            ek = existing.get("ip", "") + ":" + \
                str(existing.get("port", ""))
            if existing.get("ssid"):
                ek = f"ssid:{existing['ssid']}"
            elif existing.get("url"):
                ek = f"url:{existing['url']}"
            if ek == dedup_key:
                return None  # already tracked

        from datetime import datetime
        target_data.setdefault("discovered_at", datetime.now().isoformat())
        targets.append(target_data)

        with open(discovery_file, "w") as f:
            json.dump(targets, f, indent=2)

        return target_data

    def get_discovered_targets(self, project_dir):
        """Load the discovered targets log."""
        import json
        from pathlib import Path

        fp = Path(project_dir) / "discovered_targets.json"
        if not fp.exists():
            return []
        try:
            with open(fp) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            log.debug("get_discovered_targets load failed: %s", exc)
            return []
