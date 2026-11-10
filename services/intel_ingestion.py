"""Intel ingestion — populates FindingsDB intelligence tables from tool JSON output.

Reads flat JSON files from tool output directories and populates the
FindingsDB intelligence tables.  Called when a project is loaded or
when a managed tool finishes.

Self-contained — no Crucible imports.
"""

import json
import logging
import mimetypes
import os
import re
from datetime import datetime
from pathlib import Path

log = logging.getLogger(__name__)

# ── Availability guard ────────────────────────────────────────────────────────

try:
    import sys as _s
    if "/opt/pr0t31n/shared" not in _s.path:
        _s.path.insert(0, "/opt/pr0t31n/shared")
    import pr0t31n_findings_db  # noqa: F401
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False


def is_available():
    return _AVAILABLE


# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe_load(path):
    """Load a JSON file, return None on failure."""
    try:
        p = Path(path)
        if p.exists() and p.stat().st_size > 0:
            return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        pass
    return None


def _safe_load_jsonl(path):
    """Load a JSONL file, return list of dicts or empty list on failure."""
    out = []
    try:
        p = Path(path)
        if not p.exists() or p.stat().st_size == 0:
            return out
        with p.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except Exception:
                        pass
    except Exception:
        pass
    return out


def _find_json(tool_dirs, *filenames):
    """Yield (tool_key, path) for each matching JSON file in tool_dirs."""
    for tid, tpath in tool_dirs.items():
        d = Path(tpath)
        if not d.is_dir():
            continue
        for name in filenames:
            p = d / name
            if p.is_file():
                yield tid, p


def _find_glob(tool_dirs, pattern):
    """Yield (tool_key, path) for each file matching glob pattern."""
    for tid, tpath in tool_dirs.items():
        d = Path(tpath)
        if not d.is_dir():
            continue
        for p in d.rglob(pattern):
            if p.is_file():
                yield tid, p


def _tool_key(tid):
    """Normalise a tool key like 'int_ss3' to just 'ss3'."""
    parts = tid.split("_", 1)
    if len(parts) == 2 and parts[0] in ("int", "ext", "dmz"):
        return parts[1]
    return tid


def _rel(path, project_dir):
    """Make a path relative to project_dir for storage."""
    try:
        return str(Path(path).relative_to(project_dir))
    except (ValueError, TypeError):
        return str(path)


_CHUNK_SIZE = 65536  # 64 KB per console chunk

_IMAGE_EXTS = frozenset({".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"})


# ═══════════════════════════════════════════════════════════════════════════════
#  Ingestor Functions
# ═══════════════════════════════════════════════════════════════════════════════

# ---------------------------------------------------------------------------
# 1. Structure Maps (Fracture)
# ---------------------------------------------------------------------------

def _ingest_structure_maps(db, project_dir, tool_dirs):
    for tid, path in _find_json(tool_dirs, "structure_map.json"):
        data = _safe_load(path)
        if not isinstance(data, list):
            continue
        tool = _tool_key(tid)
        for entry in data:
            if not isinstance(entry, dict):
                continue
            url = entry.get("url") or entry.get("path")
            if not url:
                continue
            url_id = db.add_structure_url(
                url=url,
                method=entry.get("method", "GET"),
                status_code=entry.get("status_code") or entry.get("status"),
                content_type=entry.get("content_type"),
                content_length=entry.get("content_length"),
                redirect_url=entry.get("redirect_url") or entry.get("redirect"),
                depth=entry.get("depth", 0),
                source=entry.get("source"),
                response_time_ms=entry.get("response_time_ms")
                    or entry.get("response_time"),
            )
            # Children: parameters
            for param in entry.get("params", entry.get("parameters", [])):
                if isinstance(param, dict):
                    db.add_structure_param(
                        url_id=url_id,
                        name=param.get("name", ""),
                        param_type=param.get("type") or param.get("param_type"),
                        value=param.get("value"),
                        location=param.get("location") or param.get("in"),
                    )
            # Children: forms
            for form in entry.get("forms", []):
                if isinstance(form, dict):
                    db.add_structure_form(
                        url_id=url_id,
                        action=form.get("action"),
                        method=form.get("method", "POST"),
                        enctype=form.get("enctype"),
                        input_count=form.get("input_count", 0),
                    )
            # Children: headers
            for hdr in entry.get("response_headers", entry.get("headers", [])):
                if isinstance(hdr, dict):
                    db.add_structure_header(
                        url_id=url_id,
                        direction=hdr.get("direction", "response"),
                        name=hdr.get("name", ""),
                        value=hdr.get("value"),
                    )
        try:
            db._conn.commit()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 2. Access Matrices (Fracture + Siphon)
# ---------------------------------------------------------------------------

def _ingest_access_matrices(db, project_dir, tool_dirs):
    for tid, path in _find_json(tool_dirs, "access_matrix.json"):
        data = _safe_load(path)
        if not isinstance(data, list):
            continue
        tool = _tool_key(tid)
        for entry in data:
            if not isinstance(entry, dict):
                continue
            db.add_access_matrix_entry(
                tool=entry.get("tool", tool),
                endpoint_path=entry.get("endpoint_path")
                    or entry.get("endpoint") or entry.get("path", ""),
                role=entry.get("role", ""),
                method=entry.get("method", "GET"),
                expected_status=entry.get("expected_status")
                    or entry.get("expected"),
                actual_status=entry.get("actual_status")
                    or entry.get("actual"),
                result=entry.get("result"),
                auth_type=entry.get("auth_type"),
                notes=entry.get("notes"),
            )
        try:
            db._conn.commit()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 3. Auth Intel (Fracture + Siphon)
# ---------------------------------------------------------------------------

def _ingest_auth_intel(db, project_dir, tool_dirs):
    for tid, path in _find_json(tool_dirs,
                                 "authentication_status.json",
                                 "auth_status.json"):
        data = _safe_load(path)
        if not isinstance(data, dict):
            continue
        tool = _tool_key(tid)
        # Sessions
        for sess in data.get("sessions", data.get("session_list", [])):
            if not isinstance(sess, dict):
                continue
            token_raw = sess.get("token") or sess.get("value") or ""
            token_preview = token_raw[:20] if token_raw else None
            sess_id = db.add_auth_session(
                tool=sess.get("tool", tool),
                session_name=sess.get("name") or sess.get("session_name"),
                auth_type=sess.get("auth_type") or sess.get("type"),
                valid=int(sess.get("valid", True)),
                username=sess.get("username") or sess.get("user"),
                role=sess.get("role"),
                token_preview=token_preview,
                expires_at=sess.get("expires_at") or sess.get("expires"),
            )
            # Cookies nested under session
            for cookie in sess.get("cookies", []):
                if isinstance(cookie, dict):
                    db.add_auth_cookie(
                        session_id=sess_id,
                        name=cookie.get("name", ""),
                        domain=cookie.get("domain"),
                        path=cookie.get("path", "/"),
                        secure=int(cookie.get("secure", False)),
                        httponly=int(cookie.get("httponly", False)),
                        samesite=cookie.get("samesite"),
                        expires_at=cookie.get("expires_at")
                            or cookie.get("expires"),
                    )
        # Top-level cookies (some tools emit them flat)
        for cookie in data.get("cookies", []):
            if not isinstance(cookie, dict):
                continue
            db.add_auth_cookie(
                session_id=None,
                name=cookie.get("name", ""),
                domain=cookie.get("domain"),
                path=cookie.get("path", "/"),
                secure=int(cookie.get("secure", False)),
                httponly=int(cookie.get("httponly", False)),
                samesite=cookie.get("samesite"),
                expires_at=cookie.get("expires_at") or cookie.get("expires"),
            )
        try:
            db._conn.commit()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 4. Screenshots
# ---------------------------------------------------------------------------

def _ingest_screenshots(db, project_dir, tool_dirs):
    for tid, tpath in tool_dirs.items():
        d = Path(tpath)
        if not d.is_dir():
            continue
        tool = _tool_key(tid)

        # SS3: hosts/*/web/*/screenshots/
        for img in d.rglob("screenshots/*"):
            if not img.is_file() or img.suffix.lower() not in _IMAGE_EXTS:
                continue
            _ingest_one_screenshot(db, project_dir, img, tool)

        # Fracture: screenshots/ at top-level
        ss_dir = d / "screenshots"
        if ss_dir.is_dir():
            for img in ss_dir.iterdir():
                if img.is_file() and img.suffix.lower() in _IMAGE_EXTS:
                    _ingest_one_screenshot(db, project_dir, img, tool)

    try:
        db._conn.commit()
    except Exception:
        pass


def _ingest_one_screenshot(db, project_dir, img_path, tool):
    """Insert metadata for a single screenshot image file."""
    rel_path = _rel(img_path, project_dir)
    # Extract IP/port from path structure: hosts/<ip>/web/<port>/...
    ip, port, url = None, None, None
    parts = img_path.parts
    try:
        if "hosts" in parts:
            idx = parts.index("hosts")
            if idx + 1 < len(parts):
                ip = parts[idx + 1]
            if "web" in parts:
                widx = parts.index("web")
                if widx + 1 < len(parts):
                    try:
                        port = int(parts[widx + 1])
                    except (ValueError, TypeError):
                        pass
    except (ValueError, IndexError):
        pass
    try:
        stat = img_path.stat()
        file_size = stat.st_size
    except Exception:
        file_size = None
    db.add_screenshot(
        tool=tool,
        file_path=rel_path,
        url=url,
        ip=ip,
        port=port,
        file_size=file_size,
    )


# ---------------------------------------------------------------------------
# 5. Target Profiles (Fracture)
# ---------------------------------------------------------------------------

def _ingest_target_profiles(db, project_dir, tool_dirs):
    for tid, path in _find_json(tool_dirs,
                                 "target_profile.json",
                                 "dns_resolution.json"):
        data = _safe_load(path)
        tool = _tool_key(tid)
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            continue
        for entry in data:
            if not isinstance(entry, dict):
                continue
            target_url = (entry.get("target_url") or entry.get("url")
                          or entry.get("target") or "")
            if not target_url:
                continue
            techs = entry.get("technologies") or entry.get("tech") or []
            if isinstance(techs, list):
                techs_json = json.dumps(techs)
            else:
                techs_json = json.dumps([])
            db.add_target_profile(
                tool=entry.get("tool", tool),
                target_url=target_url,
                resolved_ip=entry.get("resolved_ip") or entry.get("ip"),
                server_header=entry.get("server_header") or entry.get("server"),
                technologies_json=techs_json,
                cms=entry.get("cms"),
                framework=entry.get("framework"),
                language=entry.get("language"),
                waf_detected=entry.get("waf_detected") or entry.get("waf"),
                cdn_detected=entry.get("cdn_detected") or entry.get("cdn"),
            )
        try:
            db._conn.commit()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 6. Hostname Intel (SS3)
# ---------------------------------------------------------------------------

def _ingest_hostname_intel(db, project_dir, tool_dirs):
    for tid, path in _find_json(tool_dirs, "hostname_intelligence.json"):
        data = _safe_load(path)
        if not isinstance(data, list):
            continue
        for entry in data:
            if not isinstance(entry, dict):
                continue
            hostname = entry.get("hostname")
            if not hostname:
                continue
            db.add_hostname_intel(
                hostname=hostname,
                ip=entry.get("ip"),
                environment_tag=entry.get("environment_tag")
                    or entry.get("environment"),
                application_tag=entry.get("application_tag")
                    or entry.get("application"),
                hardware_tag=entry.get("hardware_tag")
                    or entry.get("hardware"),
                role_tag=entry.get("role_tag") or entry.get("role"),
                confidence=entry.get("confidence", 0.0),
            )
        try:
            db._conn.commit()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 7. Server Roles (SS3)
# ---------------------------------------------------------------------------

def _ingest_server_roles(db, project_dir, tool_dirs):
    for tid, path in _find_json(tool_dirs, "server_roles.json"):
        data = _safe_load(path)
        if not isinstance(data, list):
            continue
        for entry in data:
            if not isinstance(entry, dict):
                continue
            ip = entry.get("ip")
            role = entry.get("role")
            if not ip or not role:
                continue
            db.add_server_role(
                ip=ip,
                role=role,
                confidence=entry.get("confidence", 0.0),
                evidence=entry.get("evidence"),
            )
        try:
            db._conn.commit()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 7b. Network Software Inventory (SS3 — software + host_software tables)
# ---------------------------------------------------------------------------

def _ingest_network_software(db, project_dir, tool_dirs):
    if not hasattr(db, "bulk_insert_network_software"):
        return
    rows = []
    for tid, path in _find_json(tool_dirs,
                                 "inventory/software.json",
                                 "software_inventory.json"):
        tk = _tool_key(tid)
        if tk not in ("ss3", "scattershot3"):
            continue
        data = _safe_load(path)
        if data is None:
            continue
        items = data if isinstance(data, list) else (
            data.get("software") or data.get("technologies") or [])
        for item in items:
            if isinstance(item, dict):
                rows.append(item)
    for tid, path in _find_json(tool_dirs,
                                 "correlated.json",
                                 "inventory/hosts.json"):
        tk = _tool_key(tid)
        if tk not in ("ss3", "scattershot3"):
            continue
        data = _safe_load(path)
        if not data:
            continue
        hosts = data.get("hosts", data) if isinstance(data, dict) else data
        if isinstance(hosts, dict):
            host_iter = [(k, v) for k, v in hosts.items()
                         if k not in ("meta", "_") and isinstance(v, dict)]
        elif isinstance(hosts, list):
            host_iter = [(h.get("ip", ""), h) for h in hosts
                         if isinstance(h, dict)]
        else:
            continue
        for ip, h in host_iter:
            ports = h.get("ports", {})
            port_items = ports.values() if isinstance(ports, dict) else (
                ports if isinstance(ports, list) else [])
            for p in port_items:
                if not isinstance(p, dict):
                    continue
                product = p.get("product", "")
                if not product:
                    continue
                rows.append({
                    "software": product,
                    "version": p.get("version", ""),
                    "ip": ip, "port": p.get("port", 0),
                    "hostname": h.get("hostname", ""),
                    "method": "nmap service detection",
                    "os": p.get("os", ""),
                })
    if rows:
        db.bulk_insert_network_software(rows)
    try:
        db._conn.commit()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 8. OSINT Domains + WHOIS (OSift)
# ---------------------------------------------------------------------------

def _ingest_osint_domains(db, project_dir, tool_dirs):
    for tid, path in _find_json(tool_dirs, "domains.json"):
        data = _safe_load(path)
        if not isinstance(data, list):
            continue
        if data:
            db.bulk_insert_osint_domains(data)
        # Look for per-domain whois files adjacent
        parent = path.parent
        for dom_entry in data:
            domain = dom_entry.get("domain") if isinstance(dom_entry, dict) else None
            if not domain:
                continue
            # Look up the domain_id we just inserted
            row = db._conn.execute(
                "SELECT id FROM osint_domains WHERE domain = ?",
                (domain,)).fetchone()
            if not row:
                continue
            domain_id = row[0]
            # Try <domain>_whois.json and whois_<domain>.json
            for whois_name in (f"{domain}_whois.json",
                               f"whois_{domain}.json"):
                wp = parent / whois_name
                whois_data = _safe_load(wp)
                if isinstance(whois_data, dict):
                    db.add_osint_whois(
                        domain_id=domain_id,
                        raw_text=whois_data.get("raw_text")
                            or whois_data.get("raw"),
                        registrant_org=whois_data.get("registrant_org")
                            or whois_data.get("registrant"),
                        registrant_country=whois_data.get("registrant_country")
                            or whois_data.get("country"),
                        admin_email=whois_data.get("admin_email"),
                        tech_email=whois_data.get("tech_email"),
                        parsed=whois_data,
                    )
        try:
            db._conn.commit()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 9. OSINT Wayback URLs (OSift)
# ---------------------------------------------------------------------------

def _ingest_osint_wayback(db, project_dir, tool_dirs):
    for tid, path in _find_glob(tool_dirs, "wayback_urls_*.txt"):
        # Extract domain from filename: wayback_urls_<domain>.txt
        stem = path.stem  # wayback_urls_example.com
        domain = stem.replace("wayback_urls_", "", 1)
        if not domain:
            continue
        batch = []
        try:
            with path.open(encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    url = line.strip()
                    if url and url.startswith(("http://", "https://")):
                        batch.append({
                            "domain": domain,
                            "url": url,
                        })
                    if len(batch) >= 5000:
                        db.bulk_insert_osint_wayback_urls(batch)
                        batch.clear()
        except Exception:
            pass
        if batch:
            db.bulk_insert_osint_wayback_urls(batch)
    # Also check for wayback_urls.json (structured)
    for tid, path in _find_json(tool_dirs, "wayback_urls.json"):
        data = _safe_load(path)
        if isinstance(data, list) and data:
            db.bulk_insert_osint_wayback_urls(data)
    try:
        db._conn.commit()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 10. OSINT Typosquats (OSift)
# ---------------------------------------------------------------------------

def _ingest_osint_typosquats(db, project_dir, tool_dirs):
    for tid, path in _find_glob(tool_dirs, "dnstwist_*.json"):
        data = _safe_load(path)
        if not isinstance(data, list):
            continue
        # Extract domain from filename: dnstwist_<domain>.json
        stem = path.stem
        domain = stem.replace("dnstwist_", "", 1)
        enriched = []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            entry.setdefault("domain", domain)
            # Map dnstwist output fields to our schema
            enriched.append({
                "domain": entry.get("domain-name", entry.get("domain", domain)),
                "variant": entry.get("domain-name", entry.get("variant", "")),
                "fuzzer": entry.get("fuzzer"),
                "dns_a": entry.get("dns-a") or entry.get("dns_a"),
                "dns_aaaa": entry.get("dns-aaaa") or entry.get("dns_aaaa"),
                "dns_mx": entry.get("dns-mx") or entry.get("dns_mx"),
                "dns_ns": entry.get("dns-ns") or entry.get("dns_ns"),
                "registered": bool(entry.get("dns-a") or entry.get("dns_a")),
                "ssdeep_score": entry.get("ssdeep-score")
                    or entry.get("ssdeep_score"),
            })
        if enriched:
            # Correct: domain should be the original, variant is the twist
            for e in enriched:
                e["domain"] = domain
            db.bulk_insert_osint_typosquats(enriched)
    try:
        db._conn.commit()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 11. Firewall Data (Bastion)
# ---------------------------------------------------------------------------

def _ingest_firewall_data(db, project_dir, tool_dirs):
    # firewall_rules.json / rules.json
    for tid, path in _find_json(tool_dirs, "firewall_rules.json", "rules.json"):
        data = _safe_load(path)
        if isinstance(data, list) and data:
            db.bulk_insert_firewall_rules(data)

    # zone_map.json
    for tid, path in _find_json(tool_dirs, "zone_map.json", "zones.json"):
        data = _safe_load(path)
        if isinstance(data, list) and data:
            db.bulk_insert_firewall_zones(data)

    # policy_compliance.json
    for tid, path in _find_json(tool_dirs,
                                 "policy_compliance.json",
                                 "compliance.json"):
        data = _safe_load(path)
        if isinstance(data, list) and data:
            db.bulk_insert_firewall_compliance(data)

    try:
        db._conn.commit()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 12. Cloud Data (Forge)
# ---------------------------------------------------------------------------

def _ingest_cloud_data(db, project_dir, tool_dirs):
    # cloud_inventory.json
    for tid, path in _find_json(tool_dirs,
                                 "cloud_inventory.json",
                                 "resources.json"):
        data = _safe_load(path)
        if isinstance(data, list) and data:
            db.bulk_insert_cloud_resources(data)

    # iam_matrix.json
    for tid, path in _find_json(tool_dirs, "iam_matrix.json", "iam.json"):
        data = _safe_load(path)
        if isinstance(data, dict):
            policies = data.get("policies", [])
            if isinstance(policies, list) and policies:
                db.bulk_insert_cloud_iam_policies(policies)
            roles = data.get("roles", [])
            if isinstance(roles, list) and roles:
                db.bulk_insert_cloud_iam_roles(roles)
        elif isinstance(data, list) and data:
            db.bulk_insert_cloud_iam_policies(data)

    # service_dashboard.json
    for tid, path in _find_json(tool_dirs,
                                 "service_dashboard.json",
                                 "services.json"):
        data = _safe_load(path)
        if isinstance(data, list) and data:
            db.bulk_insert_cloud_services(data)

    try:
        db._conn.commit()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 13. Traffic Data (Trawler)
# ---------------------------------------------------------------------------

def _ingest_traffic_data(db, project_dir, tool_dirs):
    for tid, path in _find_json(tool_dirs,
                                 "traffic.json",
                                 "conversations.json"):
        data = _safe_load(path)
        if isinstance(data, dict):
            # traffic.json may have {conversations: [...], summary: {...}}
            convos = data.get("conversations", [])
            if isinstance(convos, list) and convos:
                db.bulk_insert_traffic_conversations(convos)
            summary = data.get("summary", {})
            if isinstance(summary, dict):
                batch = []
                for k, v in summary.items():
                    numeric = None
                    if isinstance(v, (int, float)):
                        numeric = float(v)
                    batch.append({
                        "key": k,
                        "value": str(v) if v is not None else None,
                        "numeric_value": numeric,
                        "category": "traffic",
                    })
                if batch:
                    db.bulk_insert_traffic_summary(batch)
        elif isinstance(data, list) and data:
            db.bulk_insert_traffic_conversations(data)

    try:
        db._conn.commit()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 14. Database Audit (Auger)
# ---------------------------------------------------------------------------

def _ingest_db_audit(db, project_dir, tool_dirs):
    # db_schema.json
    for tid, path in _find_json(tool_dirs, "db_schema.json", "schema.json"):
        data = _safe_load(path)
        if isinstance(data, list) and data:
            db.bulk_insert_db_schemas(data)
            # After schemas are inserted, process nested tables/columns
            for schema_entry in data:
                if not isinstance(schema_entry, dict):
                    continue
                host = schema_entry.get("host")
                port = schema_entry.get("port")
                schema_name = schema_entry.get("schema_name")
                if not schema_name:
                    continue
                row = db._conn.execute(
                    "SELECT id FROM db_schemas WHERE host IS ? AND port IS ? "
                    "AND schema_name = ?",
                    (host, port, schema_name)).fetchone()
                if not row:
                    continue
                schema_id = row[0]
                tables = schema_entry.get("tables", [])
                for tbl in tables:
                    if not isinstance(tbl, dict):
                        continue
                    tbl["schema_id"] = schema_id
                if tables:
                    db.bulk_insert_db_tables(tables)

    # db_privileges.json
    for tid, path in _find_json(tool_dirs,
                                 "db_privileges.json",
                                 "privileges.json"):
        data = _safe_load(path)
        if isinstance(data, list) and data:
            db.bulk_insert_db_privileges(data)

    try:
        db._conn.commit()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 15. Endpoint Data (Dredge)
# ---------------------------------------------------------------------------

def _ingest_endpoint_data(db, project_dir, tool_dirs):
    # software_inventory.json
    for tid, path in _find_json(tool_dirs, "software_inventory.json"):
        data = _safe_load(path)
        if isinstance(data, list) and data:
            db.bulk_insert_endpoint_software(data)

    # hardening_results.json
    for tid, path in _find_json(tool_dirs, "hardening_results.json"):
        data = _safe_load(path)
        if isinstance(data, list) and data:
            db.bulk_insert_endpoint_hardening(data)

    # cis_assessment.json
    for tid, path in _find_json(tool_dirs, "cis_assessment.json"):
        data = _safe_load(path)
        if isinstance(data, list) and data:
            db.bulk_insert_endpoint_compliance(data)

    # ad_assessment.json
    for tid, path in _find_json(tool_dirs, "ad_assessment.json"):
        data = _safe_load(path)
        if isinstance(data, list) and data:
            db.bulk_insert_endpoint_ad(data)

    # browser_audit.json
    for tid, path in _find_json(tool_dirs, "browser_audit.json"):
        data = _safe_load(path)
        if isinstance(data, list) and data:
            db.bulk_insert_endpoint_browsers(data)

    try:
        db._conn.commit()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 16. Mobile Data (Quill)
# ---------------------------------------------------------------------------

def _ingest_mobile_data(db, project_dir, tool_dirs):
    # component_map.json
    for tid, path in _find_json(tool_dirs, "component_map.json"):
        data = _safe_load(path)
        if isinstance(data, list) and data:
            db.bulk_insert_mobile_components(data)

    # permission_matrix.json
    for tid, path in _find_json(tool_dirs, "permission_matrix.json"):
        data = _safe_load(path)
        if isinstance(data, list) and data:
            db.bulk_insert_mobile_permissions(data)

    # data_flow.json
    for tid, path in _find_json(tool_dirs, "data_flow.json"):
        data = _safe_load(path)
        if isinstance(data, list) and data:
            db.bulk_insert_mobile_data_flows(data)

    # traffic_analysis.json
    for tid, path in _find_json(tool_dirs, "traffic_analysis.json"):
        data = _safe_load(path)
        if isinstance(data, list) and data:
            db.bulk_insert_mobile_traffic(data)

    try:
        db._conn.commit()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 17. Isotope Data
# ---------------------------------------------------------------------------

def _ingest_isotope_data(db, project_dir, tool_dirs):
    # strings.json
    for tid, path in _find_json(tool_dirs, "strings.json"):
        data = _safe_load(path)
        if isinstance(data, list) and data:
            db.bulk_insert_isotope_strings(data)

    # properties.json
    for tid, path in _find_json(tool_dirs, "properties.json"):
        data = _safe_load(path)
        if isinstance(data, list) and data:
            db.bulk_insert_isotope_properties(data)

    # entropy.json
    for tid, path in _find_json(tool_dirs, "entropy.json"):
        data = _safe_load(path)
        if isinstance(data, list) and data:
            db.bulk_insert_isotope_entropy(data)

    # secrets.json
    for tid, path in _find_json(tool_dirs, "secrets.json"):
        data = _safe_load(path)
        if isinstance(data, list) and data:
            db.bulk_insert_isotope_secrets(data)

    # code_analysis.json
    for tid, path in _find_json(tool_dirs, "code_analysis.json"):
        data = _safe_load(path)
        if isinstance(data, list) and data:
            db.bulk_insert_isotope_code(data)

    # binary_analysis.json
    for tid, path in _find_json(tool_dirs, "binary_analysis.json"):
        data = _safe_load(path)
        if isinstance(data, list) and data:
            db.bulk_insert_isotope_binary(data)

    # iocs.json
    for tid, path in _find_json(tool_dirs, "iocs.json"):
        data = _safe_load(path)
        if isinstance(data, list) and data:
            db.bulk_insert_isotope_iocs(data)

    # contents.json
    for tid, path in _find_json(tool_dirs, "contents.json"):
        data = _safe_load(path)
        if isinstance(data, list) and data:
            db.bulk_insert_isotope_contents(data)

    # metadata.json (Isotope-specific)
    for tid, path in _find_json(tool_dirs, "isotope_metadata.json"):
        data = _safe_load(path)
        if isinstance(data, list) and data:
            db.bulk_insert_isotope_metadata(data)

    try:
        db._conn.commit()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 18. Output Files Index
# ---------------------------------------------------------------------------

def _ingest_output_files(db, project_dir, tool_dirs):
    for tid, tpath in tool_dirs.items():
        d = Path(tpath)
        if not d.is_dir():
            continue
        tool = _tool_key(tid)
        batch_count = 0
        for fpath in d.rglob("*"):
            if not fpath.is_file():
                continue
            # Skip very large files and hidden files
            fname = fpath.name
            if fname.startswith("."):
                continue
            try:
                stat = fpath.stat()
            except Exception:
                continue
            rel_path = _rel(fpath, project_dir)
            ext = fpath.suffix.lower() if fpath.suffix else None
            mtime = None
            try:
                mtime = datetime.fromtimestamp(stat.st_mtime).isoformat()
            except Exception:
                pass
            ct, _ = mimetypes.guess_type(str(fpath))
            db.add_output_file(
                path=rel_path,
                filename=fname,
                tool=tool,
                extension=ext,
                file_size=stat.st_size,
                mtime=mtime,
                content_type=ct,
            )
            batch_count += 1
            if batch_count % 500 == 0:
                try:
                    db._conn.commit()
                except Exception:
                    pass
    try:
        db._conn.commit()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 19. Action Items
# ---------------------------------------------------------------------------

def _ingest_action_items(db, project_dir, tool_dirs):
    for tid, path in _find_json(tool_dirs, "action_items.json"):
        data = _safe_load(path)
        if not isinstance(data, list):
            continue
        for item in data:
            if not isinstance(item, dict):
                continue
            if not item.get("target"):
                continue
            db.insert_action_item(item)
    try:
        db._conn.commit()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 20. Console Logs (per-tool scan.log)
# ---------------------------------------------------------------------------

def _ingest_console_logs(db, project_dir, tool_dirs):
    for tid, tpath in tool_dirs.items():
        d = Path(tpath)
        log_file = d / "scan.log"
        if not log_file.is_file():
            continue
        tool = _tool_key(tid)
        try:
            file_size = log_file.stat().st_size
        except Exception:
            continue
        if file_size == 0:
            continue
        chunk_idx = 0
        byte_offset = 0
        try:
            with log_file.open(encoding="utf-8", errors="replace") as fh:
                while True:
                    chunk = fh.read(_CHUNK_SIZE)
                    if not chunk:
                        break
                    db.add_console_chunk(
                        tool_id=tool,
                        chunk_index=chunk_idx,
                        text=chunk,
                        byte_offset=byte_offset,
                    )
                    byte_offset += len(chunk.encode("utf-8"))
                    chunk_idx += 1
        except Exception:
            pass
    try:
        db._conn.commit()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 21. Crucible Logs + Errors
# ---------------------------------------------------------------------------

def _ingest_crucible_logs(db, project_dir, tool_dirs):
    pd = Path(project_dir) if not isinstance(project_dir, Path) else project_dir

    # crucible_logs.jsonl
    logs_path = pd / "crucible_logs.jsonl"
    if logs_path.is_file():
        entries = _safe_load_jsonl(logs_path)
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            ts = (entry.get("timestamp") or entry.get("ts")
                  or entry.get("datetime") or "")
            msg = entry.get("message") or entry.get("msg") or ""
            if not ts or not msg:
                continue
            db.add_crucible_log(
                timestamp=ts,
                message=msg,
                level=entry.get("level", "INFO"),
                tool=entry.get("tool"),
                extra_json=json.dumps({
                    k: v for k, v in entry.items()
                    if k not in ("timestamp", "ts", "datetime", "message",
                                 "msg", "level", "tool")
                }) if len(entry) > 4 else None,
            )

    # crucible_errors.jsonl
    errors_path = pd / "crucible_errors.jsonl"
    if errors_path.is_file():
        entries = _safe_load_jsonl(errors_path)
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            ts = (entry.get("timestamp") or entry.get("ts")
                  or entry.get("datetime") or "")
            msg = entry.get("message") or entry.get("msg") or ""
            if not ts or not msg:
                continue
            db.add_crucible_error(
                timestamp=ts,
                message=msg,
                level=entry.get("level", "ERROR"),
                tool=entry.get("tool"),
                traceback=entry.get("traceback") or entry.get("tb"),
                extra_json=json.dumps({
                    k: v for k, v in entry.items()
                    if k not in ("timestamp", "ts", "datetime", "message",
                                 "msg", "level", "tool", "traceback", "tb")
                }) if len(entry) > 5 else None,
            )

    try:
        db._conn.commit()
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════════════
#  Ingestor Registry
# ═══════════════════════════════════════════════════════════════════════════════

_INGESTORS = [
    ("structure_maps",  _ingest_structure_maps),
    ("access_matrices", _ingest_access_matrices),
    ("auth_intel",      _ingest_auth_intel),
    ("screenshots",     _ingest_screenshots),
    ("target_profiles", _ingest_target_profiles),
    ("hostname_intel",  _ingest_hostname_intel),
    ("server_roles",    _ingest_server_roles),
    ("network_software", _ingest_network_software),
    ("osint_domains",   _ingest_osint_domains),
    ("osint_wayback",   _ingest_osint_wayback),
    ("osint_typosquats", _ingest_osint_typosquats),
    ("firewall_data",   _ingest_firewall_data),
    ("cloud_data",      _ingest_cloud_data),
    ("traffic_data",    _ingest_traffic_data),
    ("db_audit",        _ingest_db_audit),
    ("endpoint_data",   _ingest_endpoint_data),
    ("mobile_data",     _ingest_mobile_data),
    ("isotope_data",    _ingest_isotope_data),
    ("output_files",    _ingest_output_files),
    ("action_items",    _ingest_action_items),
    ("console_logs",    _ingest_console_logs),
    ("crucible_logs",   _ingest_crucible_logs),
]


# ═══════════════════════════════════════════════════════════════════════════════
#  Master Ingestion Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

def ingest_all(db, project_dir, tool_dirs=None, scope_tool_dirs=None):
    """Master ingestion — run all ingestors for a project.

    Parameters
    ----------
    db : FindingsDB
        An open FindingsDB instance.
    project_dir : str | Path
        Root of the project output directory.
    tool_dirs : dict[str, str] | None
        Mapping of tool_id -> output directory path.
    scope_tool_dirs : dict[str, dict[str, str]] | None
        Mapping of scope_key -> {tool_id -> output directory path}.
    """
    if not db or not project_dir:
        return
    pd = Path(project_dir)

    # Collect all tool directories into a single flat map
    all_dirs = {}
    if tool_dirs:
        for tid, tpath in tool_dirs.items():
            all_dirs[tid] = Path(tpath)
    if scope_tool_dirs:
        for scope, tools in scope_tool_dirs.items():
            if not isinstance(tools, dict):
                continue
            for tid, tpath in tools.items():
                all_dirs[f"{scope}_{tid}"] = Path(tpath)

    # Run each ingestor — never fail the whole pipeline
    for name, fn in _INGESTORS:
        try:
            fn(db, pd, all_dirs)
        except Exception as e:
            log.debug("ingest_%s failed: %s", name, e)

    try:
        db._conn.commit()
    except Exception:
        pass


def ingest_single(db, project_dir, tool_id, tool_output_dir,
                  scope=None, ingestors=None):
    """Run ingestion for a single tool — called when a tool finishes.

    Parameters
    ----------
    db : FindingsDB
        An open FindingsDB instance.
    project_dir : str | Path
        Root of the project output directory.
    tool_id : str
        The tool key (e.g. "ss3", "fracture").
    tool_output_dir : str | Path
        The tool's output directory path.
    scope : str | None
        Scope key (e.g. "int", "ext"), if applicable.
    ingestors : list[str] | None
        Optional list of specific ingestor names to run.
        If None, runs all ingestors.
    """
    if not db or not project_dir or not tool_output_dir:
        return
    pd = Path(project_dir)
    key = f"{scope}_{tool_id}" if scope else tool_id
    all_dirs = {key: Path(tool_output_dir)}

    registry = _INGESTORS
    if ingestors:
        allowed = set(ingestors)
        registry = [(n, f) for n, f in _INGESTORS if n in allowed]

    for name, fn in registry:
        try:
            fn(db, pd, all_dirs)
        except Exception as e:
            log.debug("ingest_%s failed for %s: %s", name, tool_id, e)

    try:
        db._conn.commit()
    except Exception:
        pass
