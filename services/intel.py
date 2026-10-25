"""Intel service — aggregate intelligence data from tool outputs.

Loads and normalises intelligence artefacts that tools produce during
their scans: structure maps, API maps, access matrices, auth status,
target profiles, and inventories.  The UI's Intelligence panel consumes
these through the ``/api/intel/<project_id>`` routes.

All loaders are fail-safe — a missing or malformed file returns None
rather than raising.
"""

import json
import logging
from pathlib import Path

log = logging.getLogger("crucible.intel")


def _safe_load(fp):
    """Load a JSON file, returning None on any error."""
    try:
        if fp.exists():
            with open(fp) as f:
                return json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        log.debug("Failed to load %s: %s", fp, exc)
    return None


class IntelService:
    """Aggregate intelligence data from tool output directories."""

    # ── Fracture outputs ────────────────────────────────────────────────

    def get_structure_map(self, tool_output_dir):
        """Load structure_map.json from Fracture output.

        Contains the site structure tree (directories, pages, forms,
        parameters) discovered during Fracture's spider phase.
        """
        return _safe_load(Path(tool_output_dir) / "structure_map.json")

    def get_access_matrix(self, tool_output_dir):
        """Load access_matrix.json from Fracture or Siphon.

        Maps resources to roles/credentials and their access levels.
        """
        return _safe_load(Path(tool_output_dir) / "access_matrix.json")

    def get_auth_status(self, tool_output_dir):
        """Load authentication_status.json.

        Tracks which credentials are active, expired, locked, or
        invalid across all tested auth providers.
        """
        return _safe_load(
            Path(tool_output_dir) / "authentication_status.json")

    def get_target_profile(self, tool_output_dir):
        """Load target_profile.json.

        Technology stack, server headers, framework detection, and
        environment fingerprinting.
        """
        return _safe_load(Path(tool_output_dir) / "target_profile.json")

    # ── Siphon outputs ──────────────────────────────────────────────────

    def get_api_map(self, tool_output_dir):
        """Load api_map.json from Siphon output.

        Contains the discovered API surface: endpoints, methods,
        parameters, auth requirements, and response schemas.
        """
        return _safe_load(Path(tool_output_dir) / "api_map.json")

    def get_api_inventory(self, tool_output_dir):
        """Load api_inventory.json from Siphon output.

        Full inventory of API endpoints with metadata: discovered vs
        spec-defined, auth required, rate limits, etc.
        """
        return _safe_load(Path(tool_output_dir) / "api_inventory.json")

    # ── AuthProbe outputs ───────────────────────────────────────────────

    def get_access_points(self, tool_output_dir):
        """Load access_points.json from AuthProbe.

        Login pages, auth endpoints, SSO providers, and token endpoints
        discovered by AuthProbe.
        """
        return _safe_load(Path(tool_output_dir) / "access_points.json")

    # ── Scattershot3 / OSift outputs ────────────────────────────────────

    def get_software_inventory(self, tool_output_dir):
        """Load software_inventory.json from Scattershot3."""
        return _safe_load(
            Path(tool_output_dir) / "software_inventory.json")

    def get_hosts_inventory(self, tool_output_dir, scope=None):
        """Load hosts.json from Scattershot3's inventory dir."""
        td = Path(tool_output_dir)
        if scope:
            scoped = _safe_load(td / scope / "inventory" / "hosts.json")
            if scoped is not None:
                return scoped
        return _safe_load(td / "inventory" / "hosts.json")

    def get_services_inventory(self, tool_output_dir, scope=None):
        """Load services.json from Scattershot3's inventory dir."""
        td = Path(tool_output_dir)
        if scope:
            scoped = _safe_load(td / scope / "inventory" / "services.json")
            if scoped is not None:
                return scoped
        return _safe_load(td / "inventory" / "services.json")

    def get_dns_records(self, tool_output_dir):
        """Load dns_records.json from OSift output."""
        return _safe_load(Path(tool_output_dir) / "dns_records.json")

    def get_osint_targets(self, tool_output_dir):
        """Load targets_osint.json from OSift output, enriched with
        all root domains from the domains/ directory."""
        td = Path(tool_output_dir)
        for candidate in (td / "reports" / "targets_osint.json",
                          td / "targets_osint.json"):
            if candidate.exists():
                try:
                    data = json.loads(candidate.read_text())
                except (json.JSONDecodeError, OSError) as exc:
                    log.debug("get_osint_targets load failed: %s", exc)
                    continue
                primary = data.get("domain", "")
                all_domains = [primary] if primary else []
                domains_dir = td / "domains"
                if domains_dir.is_dir():
                    for d in sorted(domains_dir.iterdir()):
                        if d.is_dir() and d.name not in all_domains:
                            all_domains.append(d.name)
                if len(all_domains) > 1:
                    data["domains"] = all_domains
                return data
        return None

    def get_osint_breaches(self, tool_output_dir):
        """Load and combine all breach/credential leak data from OSift output."""
        td = Path(tool_output_dir)
        combined = []
        seen = set()
        for candidate in (td / "company" / "breach_data" / "dehashed_results.json",
                          td / "reports" / "dehashed_results.json",
                          td / "dehashed_results.json",
                          td / "company" / "breach_data" / "hibp_results.json",
                          td / "reports" / "breach_results.json"):
            data = _safe_load(candidate)
            if data is not None:
                results = data if isinstance(data, list) else data.get(
                    "results", data.get("entries", []))
                for entry in results:
                    key = (str(entry.get("email", "")),
                           str(entry.get("password", entry.get("hashed_password", ""))),
                           str(entry.get("username", "")))
                    if key not in seen:
                        seen.add(key)
                        combined.append(entry)
        return combined if combined else None

    # ── Auger outputs ───────────────────────────────────────────────────

    def get_db_inventory(self, tool_output_dir):
        """Load db_inventory.json from Auger output.

        Databases, schemas, tables, users, and privilege levels.
        """
        return _safe_load(Path(tool_output_dir) / "db_inventory.json")

    # ── Trawler outputs ─────────────────────────────────────────────────

    def get_traffic_analysis(self, tool_output_dir):
        """Load traffic.json from Trawler output."""
        return _safe_load(Path(tool_output_dir) / "traffic.json")

    # ── Aggregation helpers ─────────────────────────────────────────────

    @staticmethod
    def _resolve_dir(project, tool_key):
        """Resolve tool output dir from tool_dirs or engagement_dir."""
        from config import TOOL_OUTPUT_DIRS
        td = project.get("tool_dirs", {}).get(tool_key)
        if td:
            return td
        eng_dir = project.get("engagement_dir",
                              project.get("project_dir", ""))
        if not eng_dir:
            return None
        if tool_key == "ss3":
            return eng_dir
        return str(Path(eng_dir) / TOOL_OUTPUT_DIRS.get(tool_key, tool_key))

    def get_all_intel(self, project):
        """Aggregate all available intelligence for a project.

        Returns a dict keyed by intel type, with None for unavailable
        data.
        """
        result = {}

        fr_dir = self._resolve_dir(project, "fracture")
        if fr_dir:
            result["structure_map"] = self.get_structure_map(fr_dir)
            result["access_matrix"] = self.get_access_matrix(fr_dir)
            result["auth_status"] = self.get_auth_status(fr_dir)
            result["target_profile"] = self.get_target_profile(fr_dir)

        si_dir = self._resolve_dir(project, "siphon")
        if si_dir:
            result["api_map"] = self.get_api_map(si_dir)
            result["api_inventory"] = self.get_api_inventory(si_dir)
            if not result.get("access_matrix"):
                result["access_matrix"] = self.get_access_matrix(si_dir)
            if not result.get("auth_status"):
                result["auth_status"] = self.get_auth_status(si_dir)

        ap_dir = self._resolve_dir(project, "authprobe")
        if ap_dir:
            result["access_points"] = self.get_access_points(ap_dir)

        ss_dir = self._resolve_dir(project, "ss3")
        if ss_dir:
            result["software_inventory"] = self.get_software_inventory(
                ss_dir)
            result["hosts_inventory"] = self.get_hosts_inventory(ss_dir)
            result["hosts_inventory_ext"] = self.get_hosts_inventory(
                ss_dir, "ext")
            result["hosts_inventory_int"] = self.get_hosts_inventory(
                ss_dir, "int")
            result["services_inventory"] = self.get_services_inventory(
                ss_dir)
            result["services_inventory_ext"] = self.get_services_inventory(
                ss_dir, "ext")
            result["services_inventory_int"] = self.get_services_inventory(
                ss_dir, "int")

        os_dir = self._resolve_dir(project, "osift")
        if os_dir:
            result["dns_records"] = self.get_dns_records(os_dir)
            result["osint_targets"] = self.get_osint_targets(os_dir)
            result["osint_breaches"] = self.get_osint_breaches(os_dir)

        au_dir = self._resolve_dir(project, "auger")
        if au_dir:
            result["db_inventory"] = self.get_db_inventory(au_dir)

        tr_dir = self._resolve_dir(project, "trawler")
        if tr_dir:
            result["traffic_analysis"] = self.get_traffic_analysis(tr_dir)

        result = {k: v for k, v in result.items() if v is not None}
        return result

    def get_intel_summary(self, project):
        """Return a lightweight summary of which intel is available."""
        summary = {}

        checks = {
            "fracture": [
                ("structure_map", "structure_map.json"),
                ("access_matrix", "access_matrix.json"),
                ("auth_status", "authentication_status.json"),
                ("target_profile", "target_profile.json"),
            ],
            "siphon": [
                ("api_map", "api_map.json"),
                ("api_inventory", "api_inventory.json"),
            ],
            "authprobe": [
                ("access_points", "access_points.json"),
            ],
            "ss3": [
                ("software_inventory", "software_inventory.json"),
                ("hosts_inventory", "inventory/hosts.json"),
                ("services_inventory", "inventory/services.json"),
            ],
            "osift": [
                ("dns_records", "dns_records.json"),
                ("osint_targets", "reports/targets_osint.json"),
            ],
            "auger": [
                ("db_inventory", "db_inventory.json"),
            ],
            "trawler": [
                ("traffic_analysis", "traffic.json"),
            ],
        }

        for tool_id, file_checks in checks.items():
            td = self._resolve_dir(project, tool_id)
            if not td:
                continue
            td_path = Path(td)
            search_dirs = [td_path]
            if tool_id == "ss3":
                for scope in ("ext", "int"):
                    sd = td_path / scope
                    if sd.is_dir():
                        search_dirs.append(sd)
            for intel_key, filename in file_checks:
                for sd in search_dirs:
                    fp = sd / filename
                    if fp.exists():
                        try:
                            summary[intel_key] = {
                                "available": True,
                                "source_tool": tool_id,
                                "file": filename,
                                "size_bytes": fp.stat().st_size,
                            }
                        except OSError as exc:
                            log.debug("intel_summary stat failed: %s", exc)
                        break

        return summary
