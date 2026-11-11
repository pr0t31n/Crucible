"""Intel token handler — routes __CRUCIBLE_INTEL__ payloads to FindingsDB.

Each tool emits:
    __CRUCIBLE_INTEL__:{"type":"<subtype>","data":{...}}
or bulk:
    __CRUCIBLE_INTEL__:{"type":"<subtype>","bulk":true,"data":[{...},…]}

This module maps each subtype to the correct FindingsDB insert method,
resolving internal IDs (host_id, port_id, url_id) where needed.
Imported by process_manager.py; no Flask dependencies.
"""

import json
import logging

log = logging.getLogger("crucible.intel_handler")

_STRIP_KEYS = frozenset({"tool_id", "project_id", "ts", "type",
                          "_intel_subtype"})


def _clean(row: dict) -> dict:
    return {k: v for k, v in row.items() if k not in _STRIP_KEYS}


# ── subtype → handler function ───────────────────────────────────────────
# Each handler takes (db, row) and does the insert.
# Methods that take raw data use _simple_kwargs or _simple_row.
# Methods that need ID resolution have explicit handlers.

def _sw(db, row):
    db.bulk_insert_network_software([_clean(row)])

def _hostname_intel(db, row):
    r = _clean(row)
    ip = r.get("ip", "")
    if ip:
        db.ensure_host(ip, is_alive=1 if r.get("alive", True) else 0)
    r.pop("alive", None)
    r.pop("scope", None)
    if r.get("hostname"):
        safe = {k: v for k, v in r.items()
                if k in ("hostname", "ip", "environment_tag",
                         "application_tag", "hardware_tag",
                         "role_tag", "confidence")}
        db.add_hostname_intel(**safe)


def _port_intel(db, row):
    r = _clean(row)
    ip = r.get("ip", "")
    if not ip:
        return
    host_id = db.ensure_host(ip)
    port_num = int(r.get("port", 0))
    if not port_num:
        return
    proto = r.get("proto", r.get("protocol", "tcp"))
    state = r.get("state", "open")
    port_id = db.ensure_port(host_id, port_num, proto, state)
    name = r.get("name", "")
    product = r.get("product", "")
    version = r.get("version", "")
    if port_id and (name or product or version):
        db.set_service(port_id, name=name, product=product,
                       version=version,
                       extra_info=r.get("extrainfo", ""))

def _server_role(db, row):
    r = _clean(row)
    db.add_server_role(**r)

def _dns_record(db, row):
    r = _clean(row)
    db.add_dns_record(**r)

def _certificate(db, row):
    ip = row.get("ip", "")
    port = row.get("port")
    if not ip or port is None:
        return
    host_id = db.ensure_host(ip)
    port_id = db.ensure_port(host_id, int(port))
    r = _clean(row)
    r.pop("ip", None)
    r.pop("port", None)
    r.pop("hostname", None)
    db.add_certificate(port_id, **r)

def _screenshot(db, row):
    r = _clean(row)
    db.add_screenshot(**r)

def _target_profile(db, row):
    r = _clean(row)
    db.add_target_profile(**r)

def _structure_url(db, row):
    r = _clean(row)
    params = r.pop("params", [])
    forms = r.pop("forms", [])
    headers = r.pop("headers", [])
    url_id = db.add_structure_url(**r)
    if url_id:
        for p in (params or []):
            try:
                db.add_structure_param(url_id, **p)
            except Exception:
                pass
        for f in (forms or []):
            try:
                db.add_structure_form(url_id, **f)
            except Exception:
                pass
        for h in (headers or []):
            try:
                db.add_structure_header(url_id, **h)
            except Exception:
                pass

def _structure_param(db, row):
    url_id = row.get("url_id")
    if not url_id:
        return
    r = _clean(row)
    r.pop("url_id", None)
    db.add_structure_param(url_id, **r)

def _structure_form(db, row):
    url_id = row.get("url_id")
    if not url_id:
        return
    r = _clean(row)
    r.pop("url_id", None)
    db.add_structure_form(url_id, **r)

def _structure_header(db, row):
    url_id = row.get("url_id")
    if not url_id:
        return
    r = _clean(row)
    r.pop("url_id", None)
    db.add_structure_header(url_id, **r)

def _api_endpoint(db, row):
    r = _clean(row)
    url = r.pop("url", "")
    method = r.pop("method", "GET")
    status_code = r.pop("status_code", None)
    content_type = r.pop("content_type", "")
    source = r.pop("source", "")
    db.add_structure_url(url=url, method=method, status_code=status_code,
                         content_type=content_type, source=source)

def _access_matrix(db, row):
    r = _clean(row)
    if "endpoint_path" in r:
        db.add_access_matrix_entry(**r)
    elif "roles" in r:
        for role in r.get("roles", []):
            try:
                db.add_server_role(ip="", role=role,
                                   confidence=1.0, evidence="access_matrix")
            except Exception:
                pass

def _auth_session(db, row):
    r = _clean(row)
    db.add_auth_session(**r)

def _auth_cookie(db, row):
    r = _clean(row)
    db.add_auth_cookie(**r)

def _osint_domain(db, row):
    r = _clean(row)
    db.add_osint_domain(**r)

def _osint_whois(db, row):
    r = _clean(row)
    db.add_osint_whois(**r)

def _osint_email(db, row):
    r = _clean(row)
    db.add_email(**r)

def _osint_subdomain(db, row):
    r = _clean(row)
    db.add_subdomain(**r)

def _osint_phone(db, row):
    r = _clean(row)
    if hasattr(db, "add_osint_phone"):
        db.add_osint_phone(**r)

def _osint_breach(db, row):
    r = _clean(row)
    if hasattr(db, "add_osint_breach"):
        db.add_osint_breach(**r)
    elif hasattr(db, "bulk_insert_osint_breaches"):
        db.bulk_insert_osint_breaches([r])

def _osint_person(db, row):
    r = _clean(row)
    if hasattr(db, "add_osint_person"):
        db.add_osint_person(**r)
    elif hasattr(db, "bulk_insert_osint_people"):
        db.bulk_insert_osint_people([r])

def _osint_wayback(db, row):
    r = _clean(row)
    db.add_osint_wayback_url(**r)

def _osint_typosquat(db, row):
    r = _clean(row)
    db.add_osint_typosquat(**r)

def _firewall_rule(db, row):
    r = _clean(row)
    db.add_firewall_rule(**r)

def _firewall_zone(db, row):
    r = _clean(row)
    db.add_firewall_zone(**r)

def _firewall_compliance(db, row):
    r = _clean(row)
    db.add_firewall_compliance(**r)

def _cloud_resource(db, row):
    r = _clean(row)
    db.add_cloud_resource(**r)

def _cloud_iam_policy(db, row):
    r = _clean(row)
    db.add_cloud_iam_policy(**r)

def _cloud_iam_role(db, row):
    r = _clean(row)
    db.add_cloud_iam_role(**r)

def _cloud_service(db, row):
    r = _clean(row)
    db.add_cloud_service(**r)

def _traffic_conversation(db, row):
    r = _clean(row)
    db.add_traffic_conversation(**r)

def _traffic_summary(db, row):
    r = _clean(row)
    db.add_traffic_summary(**r)

def _db_schema(db, row):
    r = _clean(row)
    db.add_db_schema(**r)

def _db_table(db, row):
    r = _clean(row)
    db.add_db_table(**r)

def _db_column(db, row):
    r = _clean(row)
    db.add_db_column(**r)

def _db_privilege(db, row):
    r = _clean(row)
    db.add_db_privilege(**r)

def _endpoint_software(db, row):
    r = _clean(row)
    db.add_endpoint_software(**r)

def _endpoint_hardening(db, row):
    r = _clean(row)
    db.add_endpoint_hardening(**r)

def _endpoint_compliance(db, row):
    r = _clean(row)
    db.add_endpoint_compliance(**r)

def _endpoint_ad(db, row):
    r = _clean(row)
    db.add_endpoint_ad(**r)

def _endpoint_browser(db, row):
    r = _clean(row)
    db.add_endpoint_browser(**r)

def _endpoint_inventory(db, row):
    r = _clean(row)
    db.add_endpoint_inventory(**r)

def _mobile_component(db, row):
    r = _clean(row)
    db.add_mobile_component(**r)

def _mobile_permission(db, row):
    r = _clean(row)
    db.add_mobile_permission(**r)

def _mobile_data_flow(db, row):
    r = _clean(row)
    db.add_mobile_data_flow(**r)

def _mobile_traffic(db, row):
    r = _clean(row)
    db.add_mobile_traffic(**r)

def _isotope_string(db, row):
    r = _clean(row)
    db.add_isotope_string(**r)

def _isotope_property(db, row):
    r = _clean(row)
    db.add_isotope_property(**r)

def _isotope_entropy(db, row):
    r = _clean(row)
    db.add_isotope_entropy(**r)

def _isotope_secret(db, row):
    r = _clean(row)
    db.add_isotope_secret(**r)

def _isotope_code(db, row):
    r = _clean(row)
    db.add_isotope_code(**r)

def _isotope_binary(db, row):
    r = _clean(row)
    db.add_isotope_binary(**r)

def _isotope_ioc(db, row):
    r = _clean(row)
    db.add_isotope_ioc(**r)

def _isotope_content(db, row):
    r = _clean(row)
    db.add_isotope_content(**r)

def _isotope_metadata(db, row):
    r = _clean(row)
    db.add_isotope_metadata(**r)

def _mobile_hardening(db, row):
    r = _clean(row)
    for app in (r.get("apps") or [r]):
        for check in (app.get("checks") or []):
            try:
                db.add_endpoint_hardening(
                    check_id=check.get("name", ""),
                    status=check.get("status", "unknown"),
                    category="mobile",
                    details=check.get("details", ""),
                )
            except Exception:
                pass

def _mobile_domain(db, row):
    r = _clean(row)
    for d in (r.get("domains") or [r]):
        domain = d if isinstance(d, str) else d.get("domain", d.get("subdomain", ""))
        if domain:
            try:
                db.add_subdomain(domain, source="quill")
            except Exception:
                pass

def _mobile_email(db, row):
    r = _clean(row)
    for e in (r.get("emails") or [r]):
        email = e if isinstance(e, str) else e.get("email", "")
        if email:
            try:
                db.add_email(email, source="quill")
            except Exception:
                pass

def _mobile_api_endpoint(db, row):
    r = _clean(row)
    url = r.get("url") or r.get("path", "")
    if url:
        db.add_structure_url(
            url, method=r.get("method", "GET"),
            status_code=r.get("status_code"),
            content_type=r.get("content_type"),
        )

def _wireless_network(db, row):
    r = _clean(row)
    db.add_wireless_network(**r)

def _output_file(db, row):
    r = _clean(row)
    db.add_output_file(**r)

def _console_chunk(db, row):
    r = _clean(row)
    db.add_console_chunk(**r)

def _network_posture(db, row):
    r = _clean(row)
    db.add_network_posture(**r)

def _cookie(db, row):
    r = _clean(row)
    db.add_cookie(**r)

def _webapp_intel(db, row):
    r = _clean(row)
    db.add_webapp_intel(**r)

def _api_inventory(db, row):
    r = _clean(row)
    db.add_api_inventory(**r)

def _firewall_config(db, row):
    r = _clean(row)
    db.add_firewall_config(**r)

def _endpoint_overview(db, row):
    r = _clean(row)
    db.add_endpoint_overview(**r)

def _endpoint_network(db, row):
    r = _clean(row)
    db.add_endpoint_network(**r)

def _endpoint_disk(db, row):
    r = _clean(row)
    db.add_endpoint_disk(**r)

def _endpoint_hardware(db, row):
    r = _clean(row)
    db.add_endpoint_hardware(**r)


# ── dispatch table: subtype → (single_handler, bulk_method_or_None) ──────
_DISPATCH = {
    "software":          (_sw,               "bulk_insert_network_software"),
    "hostname_intel":    (_hostname_intel,     None),
    "server_role":       (_server_role,        None),
    "dns_record":        (_dns_record,         None),
    "certificate":       (_certificate,        None),
    "screenshot":        (_screenshot,         None),
    "target_profile":    (_target_profile,     None),
    "structure_url":     (_structure_url,       None),
    "structure_param":   (_structure_param,     None),
    "structure_form":    (_structure_form,      None),
    "structure_header":  (_structure_header,    None),
    "api_endpoint":      (_api_endpoint,        None),
    "access_matrix":     (_access_matrix,       None),
    "auth_session":      (_auth_session,        None),
    "auth_cookie":       (_auth_cookie,         None),
    "osint_domain":      (_osint_domain,       "bulk_insert_osint_domains"),
    "osint_whois":       (_osint_whois,        "bulk_insert_osint_whois"),
    "osint_email":       (_osint_email,         None),
    "osint_subdomain":   (_osint_subdomain,     None),
    "osint_phone":       (_osint_phone,        "bulk_insert_osint_phones"),
    "osint_breach":      (_osint_breach,        None),
    "osint_person":      (_osint_person,        None),
    "osint_wayback":     (_osint_wayback,      "bulk_insert_osint_wayback_urls"),
    "osint_typosquat":   (_osint_typosquat,    "bulk_insert_osint_typosquats"),
    "firewall_rule":     (_firewall_rule,      "bulk_insert_firewall_rules"),
    "firewall_zone":     (_firewall_zone,      "bulk_insert_firewall_zones"),
    "firewall_compliance": (_firewall_compliance, "bulk_insert_firewall_compliance"),
    "cloud_resource":    (_cloud_resource,     "bulk_insert_cloud_resources"),
    "cloud_iam_policy":  (_cloud_iam_policy,   "bulk_insert_cloud_iam_policies"),
    "cloud_iam_role":    (_cloud_iam_role,     "bulk_insert_cloud_iam_roles"),
    "cloud_service":     (_cloud_service,      "bulk_insert_cloud_services"),
    "traffic_conversation": (_traffic_conversation, "bulk_insert_traffic_conversations"),
    "traffic_summary":   (_traffic_summary,    "bulk_insert_traffic_summary"),
    "db_schema":         (_db_schema,          "bulk_insert_db_schemas"),
    "db_table":          (_db_table,           "bulk_insert_db_tables"),
    "db_column":         (_db_column,          "bulk_insert_db_columns"),
    "db_privilege":      (_db_privilege,       "bulk_insert_db_privileges"),
    "endpoint_software": (_endpoint_software,  "bulk_insert_endpoint_software"),
    "endpoint_hardening": (_endpoint_hardening, "bulk_insert_endpoint_hardening"),
    "endpoint_compliance": (_endpoint_compliance, "bulk_insert_endpoint_compliance"),
    "endpoint_ad":       (_endpoint_ad,        "bulk_insert_endpoint_ad"),
    "endpoint_browser":  (_endpoint_browser,   "bulk_insert_endpoint_browsers"),
    "endpoint_inventory": (_endpoint_inventory, "bulk_insert_endpoint_inventory"),
    "mobile_component":  (_mobile_component,   "bulk_insert_mobile_components"),
    "mobile_permission": (_mobile_permission,  "bulk_insert_mobile_permissions"),
    "mobile_data_flow":  (_mobile_data_flow,   "bulk_insert_mobile_data_flows"),
    "mobile_traffic":    (_mobile_traffic,     "bulk_insert_mobile_traffic"),
    "mobile_hardening":  (_mobile_hardening,    None),
    "mobile_domain":     (_mobile_domain,       None),
    "mobile_email":      (_mobile_email,        None),
    "mobile_api_endpoint": (_mobile_api_endpoint, None),
    "isotope_string":    (_isotope_string,     "bulk_insert_isotope_strings"),
    "isotope_property":  (_isotope_property,   "bulk_insert_isotope_properties"),
    "isotope_entropy":   (_isotope_entropy,    "bulk_insert_isotope_entropy"),
    "isotope_secret":    (_isotope_secret,     "bulk_insert_isotope_secrets"),
    "isotope_code":      (_isotope_code,       "bulk_insert_isotope_code"),
    "isotope_binary":    (_isotope_binary,     "bulk_insert_isotope_binary"),
    "isotope_ioc":       (_isotope_ioc,        "bulk_insert_isotope_iocs"),
    "isotope_content":   (_isotope_content,    "bulk_insert_isotope_contents"),
    "isotope_metadata":  (_isotope_metadata,   "bulk_insert_isotope_metadata"),
    "wireless_network":  (_wireless_network,    None),
    "wireless_ap":       (_wireless_network,    None),
    "subdomain":         (_osint_subdomain,     None),
    "email":             (_osint_email,         None),
    "endpoint":          (_endpoint_inventory,  "bulk_insert_endpoint_inventory"),
    "host":              (_hostname_intel,       None),
    "port":              (_port_intel,          None),
    "output_file":       (_output_file,         None),
    "console_chunk":     (_console_chunk,       None),
    "network_posture":   (_network_posture,    "bulk_insert_network_posture"),
    "cookie":            (_cookie,             "bulk_insert_cookies"),
    "webapp_intel":      (_webapp_intel,       "bulk_insert_webapp_intel"),
    "api_inventory":     (_api_inventory,      "bulk_insert_api_inventory"),
    "firewall_config":   (_firewall_config,    "bulk_insert_firewall_config"),
    "endpoint_overview": (_endpoint_overview,  "bulk_insert_endpoint_overview"),
    "endpoint_network":  (_endpoint_network,   "bulk_insert_endpoint_network"),
    "endpoint_disk":     (_endpoint_disk,      "bulk_insert_endpoint_disk"),
    "endpoint_hardware": (_endpoint_hardware,  "bulk_insert_endpoint_hardware"),
}


def handle_intel(findings_engine, socketio, project_id: str,
                 tool_id: str, data: dict) -> None:
    """Route an INTEL token payload to the correct FindingsDB method."""
    intel_type = data.get("type", "")
    if not intel_type:
        log.warning("INTEL token missing 'type' from %s", tool_id)
        return

    spec = _DISPATCH.get(intel_type)
    if spec is None:
        log.warning("Unknown INTEL subtype %r from %s", intel_type, tool_id)
        return

    handler_fn, bulk_method = spec
    is_bulk = data.get("bulk", False)
    payload = data.get("data")
    if payload is None:
        log.warning("INTEL token %r missing 'data' from %s",
                     intel_type, tool_id)
        return

    if not findings_engine:
        return

    try:
        from models.project import get_project
        project = get_project(project_id)
    except Exception as exc:
        log.warning("handle_intel: project %s: %s", project_id[:8], exc)
        return

    db = findings_engine._get_db(project_id, project)
    if db is None:
        log.debug("handle_intel: no DB for project %s", project_id[:8])
        return

    try:
        if is_bulk and isinstance(payload, list):
            if bulk_method and hasattr(db, bulk_method):
                cleaned = [_clean(r) for r in payload if isinstance(r, dict)]
                getattr(db, bulk_method)(cleaned)
            else:
                for row in payload:
                    if isinstance(row, dict):
                        handler_fn(db, row)
        elif isinstance(payload, dict):
            handler_fn(db, payload)
        elif isinstance(payload, list):
            if bulk_method and hasattr(db, bulk_method):
                cleaned = [_clean(r) for r in payload if isinstance(r, dict)]
                getattr(db, bulk_method)(cleaned)
            else:
                for row in payload:
                    if isinstance(row, dict):
                        handler_fn(db, row)

        try:
            db._conn.commit()
        except Exception:
            pass
    except Exception as exc:
        log.warning("handle_intel DB insert (%s/%s): %s",
                     intel_type, tool_id, exc)

    try:
        room = f"project_{project_id}"
        socketio.emit("tool_intel", {
            "type": intel_type,
            "tool_id": tool_id,
            "project_id": project_id,
            "count": len(payload) if isinstance(payload, list) else 1,
        }, room=room)
    except Exception as exc:
        log.debug("handle_intel socketio emit: %s", exc)
