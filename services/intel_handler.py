"""Intel token handler — routes __CRUCIBLE_INTEL__ payloads to FindingsDB.

Each tool emits:
    __CRUCIBLE_INTEL__:{"type":"<subtype>","data":{...}}
or bulk:
    __CRUCIBLE_INTEL__:{"type":"<subtype>","bulk":true,"data":[{...},…]}

This module maps each subtype to the correct FindingsDB insert method,
resolving internal IDs (host_id, port_id, url_id) where needed.
Imported by process_manager.py; no Flask dependencies.
"""

import inspect
import json
import logging

log = logging.getLogger("crucible.intel_handler")

_STRIP_KEYS = frozenset({"tool_id", "project_id", "ts", "type",
                          "_intel_subtype"})


def _clean(row: dict) -> dict:
    return {k: v for k, v in row.items() if k not in _STRIP_KEYS}


def _safe_db_call(method, row, intel_type=""):
    """Call a DB method filtering kwargs to its accepted params."""
    sig = inspect.signature(method)
    params = sig.parameters
    if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return method(**row)
    accepted = {k: v for k, v in row.items()
                if k in params and k != "self"}
    for pname, p in params.items():
        if pname == "self":
            continue
        if (p.default is inspect.Parameter.empty
                and p.kind not in (inspect.Parameter.VAR_POSITIONAL,
                                   inspect.Parameter.VAR_KEYWORD)
                and pname not in accepted):
            log.error("intel_handler: %s/%s missing required arg '%s' "
                      "(row keys: %s)", intel_type, method.__name__,
                      pname, list(row.keys()))
            return None
    return method(**accepted)


# ── subtype → handler function ───────────────────────────────────────────
# Each handler takes (db, row) and does the insert.
# Methods that take raw data use _safe_db_call for kwargs filtering.
# Methods that need ID resolution have explicit handlers.

def _sw(db, row):
    db.bulk_insert_network_software([_clean(row)])

def _hostname_intel(db, row):
    r = _clean(row)
    ip = r.get("ip", "")
    scope_id = r.pop("_scope_id", None)
    if ip:
        _host_kw = {"is_alive": 1 if r.get("alive", True) else 0}
        if scope_id is not None:
            _host_kw["scope_id"] = scope_id
        if r.get("os_family"):
            _host_kw["os_family"] = r["os_family"]
        if r.get("os_name"):
            _host_kw["os_name"] = r["os_name"]
        db.ensure_host(ip, **_host_kw)
    r.pop("alive", None)
    r.pop("scope", None)
    if r.get("hostname"):
        safe = {k: v for k, v in r.items()
                if k in ("hostname", "ip", "environment_tag",
                         "application_tag", "hardware_tag",
                         "role_tag", "confidence")}
        if scope_id is not None:
            safe["scope_id"] = scope_id
        db.add_hostname_intel(**safe)


def _host_os(db, row):
    r = _clean(row)
    ip = r.get("ip", "")
    if not ip:
        return
    kw = {}
    scope_id = r.pop("_scope_id", None)
    if scope_id is not None:
        kw["scope_id"] = scope_id
    if r.get("os_family"):
        kw["os_family"] = r["os_family"]
    if r.get("os_name"):
        kw["os_name"] = r["os_name"]
    db.ensure_host(ip, **kw)


def _port_intel(db, row):
    r = _clean(row)
    ip = r.get("ip", "")
    if not ip:
        return
    scope_id = r.pop("_scope_id", None)
    host_id = db.ensure_host(ip, scope_id=scope_id)
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
    sid = r.pop("_scope_id", None)
    if sid is not None:
        r["scope_id"] = sid
    _safe_db_call(db.add_server_role, r)

def _dns_record(db, row):
    r = _clean(row)
    _safe_db_call(db.add_dns_record, r)

def _certificate(db, row):
    ip = row.get("ip", "")
    port = row.get("port")
    if not ip or port is None:
        return
    scope_id = row.get("_scope_id")
    host_id = db.ensure_host(ip, scope_id=scope_id)
    port_id = db.ensure_port(host_id, int(port))
    r = _clean(row)
    r.pop("ip", None)
    r.pop("port", None)
    r.pop("hostname", None)
    r.pop("_scope_id", None)
    sig = inspect.signature(db.add_certificate)
    pnames = [n for n in sig.parameters if n != "self"]
    accepted = {k: v for k, v in r.items() if k in pnames}
    db.add_certificate(port_id, **accepted)

def _screenshot(db, row):
    r = _clean(row)
    if "path" in r and "file_path" not in r:
        r["file_path"] = r.pop("path")
    if "screenshot_path" in r and "file_path" not in r:
        r["file_path"] = r.pop("screenshot_path")
    if "tool" not in r:
        r["tool"] = "fracture"
    _safe_db_call(db.add_screenshot, r)

def _target_profile(db, row):
    r = _clean(row)
    _safe_db_call(db.add_target_profile, r)

def _structure_url(db, row):
    r = _clean(row)
    if "url" not in r and "path" in r:
        base = r.get("target_url", r.get("base_url", ""))
        path = r.pop("path")
        r["url"] = (base.rstrip("/") + "/" + path.lstrip("/")) if base else path
    if "status" in r and "status_code" not in r:
        r["status_code"] = r.pop("status")
    if "auth_only" in r and "auth_required" not in r:
        r["auth_required"] = 1 if r.pop("auth_only") else 0
    if "auth_users" in r and "auth_roles" not in r:
        au = r.pop("auth_users")
        r["auth_roles"] = json.dumps(au) if isinstance(au, list) else au
    if "rogue" in r and "is_rogue" not in r:
        r["is_rogue"] = 1 if r.pop("rogue") else 0
    sid = r.pop("_scope_id", None)
    if sid is not None:
        r["scope_id"] = sid
    params = r.pop("params", [])
    forms = r.pop("forms", [])
    headers = r.pop("headers", [])
    url_id = _safe_db_call(db.add_structure_url, r)
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
    paths = r.pop("paths", r.pop("path_access", None))
    if paths and isinstance(paths, list):
        tool = r.get("tool", "")
        target_url = r.get("target_url", "")
        scope_id = r.get("_scope_id")
        for pe in paths:
            path = pe.get("path") or pe.get("url", "")
            access = pe.get("access", {})
            body_class_map = pe.get("body_class", {})
            for role, status in access.items():
                entry = {
                    "tool": tool,
                    "endpoint_path": path,
                    "role": role,
                    "actual_status": status if isinstance(status, int) else None,
                    "result": "allowed" if (isinstance(status, int) and status < 400) else "denied",
                    "target_url": target_url,
                }
                bc = body_class_map.get(role)
                if bc:
                    entry["body_class"] = str(bc)
                    if isinstance(bc, str) and "denied" in bc.lower():
                        entry["body_denied"] = 1
                if scope_id:
                    entry["scope_id"] = scope_id
                _safe_db_call(db.add_access_matrix_entry, entry)
        return
    if "endpoint_path" in r:
        sid = r.pop("_scope_id", None)
        if sid is not None:
            r["scope_id"] = sid
        _safe_db_call(db.add_access_matrix_entry, r)

def _auth_session(db, row):
    r = _clean(row)
    cookies = r.pop("cookies", None)
    r.pop("headers", None)
    if "status" in r and "valid" not in r:
        r["valid"] = 1 if str(r.pop("status")).lower() in ("active", "valid", "1", "true") else 0
    sid = r.pop("_scope_id", None)
    target_url = r.get("target_url", "")
    try:
        session_id = _safe_db_call(db.add_auth_session, r)
    except Exception:
        session_id = None
        tool = r.get("tool", "")
        role = r.get("role", r.get("session_name", ""))
        try:
            cur = db._conn.execute(
                "SELECT id FROM auth_sessions WHERE tool = ? AND role = ? "
                "AND target_url = ? ORDER BY id DESC LIMIT 1",
                (tool, role, target_url))
            hit = cur.fetchone()
            if hit:
                session_id = hit[0] if isinstance(hit, (tuple, list)) else hit["id"]
                updates = {k: v for k, v in r.items()
                           if k not in ("tool", "role", "target_url") and v is not None}
                if updates:
                    set_clause = ", ".join(f"{k} = ?" for k in updates)
                    db._conn.execute(
                        f"UPDATE auth_sessions SET {set_clause} WHERE id = ?",
                        list(updates.values()) + [session_id])
        except Exception:
            log.warning("_auth_session: upsert fallback failed", exc_info=True)
    if session_id and cookies and isinstance(cookies, list):
        for ck in cookies:
            if isinstance(ck, dict) and ck.get("name"):
                ck["session_id"] = session_id
                ck["tool"] = r.get("tool", "")
                _auth_cookie(db, ck)

def _auth_cookie(db, row):
    r = _clean(row)
    if "httpOnly" in r and "httponly" not in r:
        r["httponly"] = r.pop("httpOnly")
    if "sameSite" in r and "samesite" not in r:
        r["samesite"] = r.pop("sameSite")
    if "session_id" not in r:
        tool = r.get("tool", "unknown")
        role = r.get("role", r.get("username", "default"))
        target_url = r.get("target_url", "")
        try:
            cur = db._conn.execute(
                "SELECT id FROM auth_sessions WHERE tool = ? AND role = ? "
                "AND target_url = ? ORDER BY id DESC LIMIT 1",
                (tool, role, target_url))
            hit = cur.fetchone()
            if hit:
                r["session_id"] = hit[0] if isinstance(hit, (tuple, list)) else hit["id"]
            else:
                db.add_auth_session(tool=tool, role=role, status="active",
                                    target_url=target_url)
                cur2 = db._conn.execute(
                    "SELECT id FROM auth_sessions WHERE tool = ? AND role = ? "
                    "AND target_url = ? ORDER BY id DESC LIMIT 1",
                    (tool, role, target_url))
                hit2 = cur2.fetchone()
                if hit2:
                    r["session_id"] = hit2[0] if isinstance(hit2, (tuple, list)) else hit2["id"]
        except Exception:
            log.warning("_auth_cookie: session_id resolve failed", exc_info=True)
            return
    _safe_db_call(db.add_auth_cookie, r)

def _osint_domain(db, row):
    r = _clean(row)
    _safe_db_call(db.add_osint_domain, r)

def _osint_whois(db, row):
    r = _clean(row)
    if "domain_id" not in r and "domain" in r:
        domain_name = r.pop("domain")
        try:
            cur = db._conn.execute(
                "SELECT id FROM osint_domains WHERE domain = ?",
                (domain_name,))
            hit = cur.fetchone()
            if hit:
                r["domain_id"] = hit[0] if isinstance(hit, (tuple, list)) else hit["id"]
            else:
                db.add_osint_domain(domain=domain_name, source=r.get("source", "osift"))
                cur2 = db._conn.execute(
                    "SELECT id FROM osint_domains WHERE domain = ?",
                    (domain_name,))
                hit2 = cur2.fetchone()
                if hit2:
                    r["domain_id"] = hit2[0] if isinstance(hit2, (tuple, list)) else hit2["id"]
        except Exception:
            log.warning("_osint_whois: domain_id resolve failed for %s", domain_name, exc_info=True)
            return
    if "registrar" in r and "registrant_org" not in r:
        r["registrant_org"] = r.pop("registrar")
    extra = {}
    for k in ("created", "expires", "source", "registrant_name",
              "registrant_email", "registrant_state", "registrant_city"):
        v = r.pop(k, None)
        if v is not None:
            extra[k] = v
    ns = r.pop("nameservers", None)
    if ns is not None:
        extra["nameservers"] = ", ".join(str(s) for s in ns) if isinstance(ns, list) else ns
    if extra:
        existing = r.get("parsed") or {}
        if isinstance(existing, str):
            try:
                existing = json.loads(existing)
            except (json.JSONDecodeError, TypeError):
                existing = {}
        existing.update(extra)
        r["parsed"] = existing
    r.pop("tool", None)
    r.pop("_scope_id", None)
    _safe_db_call(db.add_osint_whois, r)

def _osint_email(db, row):
    r = _clean(row)
    _safe_db_call(db.add_email, r)

def _osint_certificate(db, row):
    r = _clean(row)
    if hasattr(db, "add_osint_certificate"):
        _safe_db_call(db.add_osint_certificate, r)

def _osint_subdomain(db, row):
    r = _clean(row)
    src = r.get("source")
    if isinstance(src, list):
        r["source"] = ", ".join(str(s) for s in src) if src else None
    _safe_db_call(db.add_subdomain, r)

def _osint_phone(db, row):
    r = _clean(row)
    if hasattr(db, "add_osint_phone"):
        _safe_db_call(db.add_osint_phone, r)

def _osint_breach(db, row):
    r = _clean(row)
    if hasattr(db, "add_osint_breach"):
        _safe_db_call(db.add_osint_breach, r)
    elif hasattr(db, "bulk_insert_osint_breaches"):
        db.bulk_insert_osint_breaches([r])

def _osint_person(db, row):
    r = _clean(row)
    if hasattr(db, "add_osint_person"):
        _safe_db_call(db.add_osint_person, r)
    elif hasattr(db, "bulk_insert_osint_people"):
        db.bulk_insert_osint_people([r])

def _osint_wayback(db, row):
    r = _clean(row)
    if "domain" not in r:
        url = r.get("url", "")
        if url:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                r["domain"] = parsed.netloc or parsed.path.split("/")[0] or ""
            except Exception:
                r["domain"] = ""
        else:
            r["domain"] = ""
    if not r.get("domain") or not r.get("url"):
        return
    r.pop("tool", None)
    r.pop("_scope_id", None)
    _safe_db_call(db.add_osint_wayback_url, r)

def _osint_typosquat(db, row):
    r = _clean(row)
    _safe_db_call(db.add_osint_typosquat, r)

def _firewall_rule(db, row):
    r = _clean(row)
    _safe_db_call(db.add_firewall_rule, r)

def _firewall_zone(db, row):
    r = _clean(row)
    _safe_db_call(db.add_firewall_zone, r)

def _firewall_compliance(db, row):
    r = _clean(row)
    _safe_db_call(db.add_firewall_compliance, r)

def _cloud_resource(db, row):
    r = _clean(row)
    _safe_db_call(db.add_cloud_resource, r)

def _cloud_iam_policy(db, row):
    r = _clean(row)
    _safe_db_call(db.add_cloud_iam_policy, r)

def _cloud_iam_role(db, row):
    r = _clean(row)
    _safe_db_call(db.add_cloud_iam_role, r)

def _cloud_service(db, row):
    r = _clean(row)
    _safe_db_call(db.add_cloud_service, r)

def _traffic_conversation(db, row):
    r = _clean(row)
    _safe_db_call(db.add_traffic_conversation, r)

def _traffic_summary(db, row):
    r = _clean(row)
    _safe_db_call(db.add_traffic_summary, r)

def _db_schema(db, row):
    r = _clean(row)
    _safe_db_call(db.add_db_schema, r)

def _db_table(db, row):
    r = _clean(row)
    _safe_db_call(db.add_db_table, r)

def _db_column(db, row):
    r = _clean(row)
    _safe_db_call(db.add_db_column, r)

def _db_privilege(db, row):
    r = _clean(row)
    _safe_db_call(db.add_db_privilege, r)

def _endpoint_software(db, row):
    r = _clean(row)
    _safe_db_call(db.add_endpoint_software, r)

def _endpoint_hardening(db, row):
    r = _clean(row)
    _safe_db_call(db.add_endpoint_hardening, r)

def _endpoint_compliance(db, row):
    r = _clean(row)
    _safe_db_call(db.add_endpoint_compliance, r)

def _endpoint_ad(db, row):
    r = _clean(row)
    _safe_db_call(db.add_endpoint_ad, r)

def _endpoint_browser(db, row):
    r = _clean(row)
    _safe_db_call(db.add_endpoint_browser, r)

def _endpoint_inventory(db, row):
    r = _clean(row)
    _safe_db_call(db.add_endpoint_inventory, r)

def _mobile_component(db, row):
    r = _clean(row)
    _safe_db_call(db.add_mobile_component, r)

def _mobile_permission(db, row):
    r = _clean(row)
    _safe_db_call(db.add_mobile_permission, r)

def _mobile_data_flow(db, row):
    r = _clean(row)
    _safe_db_call(db.add_mobile_data_flow, r)

def _mobile_traffic(db, row):
    r = _clean(row)
    _safe_db_call(db.add_mobile_traffic, r)

def _isotope_string(db, row):
    r = _clean(row)
    _safe_db_call(db.add_isotope_string, r)

def _isotope_property(db, row):
    r = _clean(row)
    _safe_db_call(db.add_isotope_property, r)

def _isotope_entropy(db, row):
    r = _clean(row)
    _safe_db_call(db.add_isotope_entropy, r)

def _isotope_secret(db, row):
    r = _clean(row)
    _safe_db_call(db.add_isotope_secret, r)

def _isotope_code(db, row):
    r = _clean(row)
    _safe_db_call(db.add_isotope_code, r)

def _isotope_binary(db, row):
    r = _clean(row)
    _safe_db_call(db.add_isotope_binary, r)

def _isotope_ioc(db, row):
    r = _clean(row)
    _safe_db_call(db.add_isotope_ioc, r)

def _isotope_content(db, row):
    r = _clean(row)
    _safe_db_call(db.add_isotope_content, r)

def _isotope_metadata(db, row):
    r = _clean(row)
    _safe_db_call(db.add_isotope_metadata, r)

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
    _safe_db_call(db.add_wireless_network, r)

def _wireless_ap(db, row):
    r = _clean(row)
    bssid = r.get("bssid", "")
    if not bssid:
        return
    db.add_wireless_network(
        bssid,
        ssid=r.get("ssid", ""),
        channel=r.get("channel"),
        encryption=r.get("encryption", ""),
        cipher=r.get("cipher", ""),
        auth=r.get("auth", "") or r.get("auth_type", ""),
        signal_dbm=r.get("signal_dbm") or r.get("power") or r.get("power_dbm"),
        vendor=r.get("vendor", ""),
        model=r.get("model", ""),
        product_line=r.get("product_line", ""),
        wps=r.get("wps", False),
        laa=r.get("laa", False),
        wps_version=r.get("wps_version", ""),
        wps_locked=r.get("wps_locked"),
        manufacturer=r.get("manufacturer", ""),
        model_name=r.get("model_name", ""),
        device_name=r.get("device_name", ""),
    )

def _wireless_client(db, row):
    r = _clean(row)
    mac = r.get("mac", "")
    if not mac:
        return
    try:
        db.add_wireless_client(
            mac,
            vendor=r.get("vendor", ""),
            associated_bssid=r.get("associated_bssid", "") or r.get("bssid", ""),
            associated_ssid=r.get("associated_ssid", "") or r.get("ssid", ""),
            signal_dbm=r.get("signal_dbm") or r.get("power"),
            packets=r.get("packets", 0),
        )
    except AttributeError:
        db.add_wireless_network(mac, **r)
    probes = r.get("probes", []) or r.get("probed_ssids", [])
    if probes and isinstance(probes, list):
        for ssid in probes:
            if ssid:
                try:
                    db.add_wireless_probe(mac, ssid)
                except AttributeError:
                    pass

def _wireless_probe(db, row):
    r = _clean(row)
    client_mac = r.get("client_mac", "") or r.get("mac", "")
    probed_ssids = r.get("probed_ssids", []) or r.get("probes", [])
    probed_ssid = r.get("probed_ssid", "")
    if probed_ssid and not probed_ssids:
        probed_ssids = [probed_ssid]
    if not client_mac and not probed_ssids:
        _safe_db_call(db.add_wireless_network, r)
        return
    for ssid in probed_ssids:
        if ssid and client_mac:
            try:
                db.add_wireless_probe(client_mac, ssid)
            except AttributeError:
                pass

def _output_file(db, row):
    r = _clean(row)
    _safe_db_call(db.add_output_file, r)

def _console_chunk(db, row):
    r = _clean(row)
    _safe_db_call(db.add_console_chunk, r)

def _network_posture(db, row):
    r = _clean(row)
    if "subnets" in r and isinstance(r["subnets"], list):
        scope_id = r.get("_scope_id")
        for sn in r["subnets"]:
            cidr = sn.get("cidr", "")
            if not cidr:
                continue
            sn_data = {
                "cidr": cidr,
                "host_count": sn.get("host_count", 0),
                "open_hosts": sn.get("open_hosts", 0),
                "filtered_hosts": sn.get("filtered_hosts", 0),
                "closed_hosts": sn.get("closed_hosts", 0),
                "segmented": 1 if sn.get("segmented") else 0,
            }
            if scope_id:
                sn_data["scope_id"] = scope_id
            try:
                conn = db._conn
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS network_posture_subnets ("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, cidr TEXT NOT NULL, "
                    "host_count INTEGER DEFAULT 0, open_hosts INTEGER DEFAULT 0, "
                    "filtered_hosts INTEGER DEFAULT 0, closed_hosts INTEGER DEFAULT 0, "
                    "segmented INTEGER DEFAULT 0, scope_id INTEGER, "
                    "UNIQUE(cidr, scope_id))")
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS network_posture_hosts ("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    "subnet_id INTEGER REFERENCES network_posture_subnets(id) ON DELETE CASCADE, "
                    "ip TEXT NOT NULL, hostname TEXT, posture TEXT, "
                    "open_port_count INTEGER DEFAULT 0, port_open INTEGER DEFAULT 0, "
                    "port_closed INTEGER DEFAULT 0, port_filtered INTEGER DEFAULT 0, "
                    "port_scanned INTEGER DEFAULT 0)")
                cur = conn.execute(
                    "INSERT OR REPLACE INTO network_posture_subnets "
                    "(cidr, host_count, open_hosts, filtered_hosts, closed_hosts, "
                    "segmented, scope_id) VALUES (?,?,?,?,?,?,?)",
                    (sn_data["cidr"], sn_data["host_count"], sn_data["open_hosts"],
                     sn_data["filtered_hosts"], sn_data["closed_hosts"],
                     sn_data["segmented"], sn_data.get("scope_id")))
                subnet_id = cur.lastrowid
                for h in sn.get("hosts", []):
                    conn.execute(
                        "INSERT INTO network_posture_hosts "
                        "(subnet_id, ip, hostname, posture, open_port_count, "
                        "port_open, port_closed, port_filtered, port_scanned) "
                        "VALUES (?,?,?,?,?,?,?,?,?)",
                        (subnet_id, h.get("ip", ""), h.get("hostname", ""),
                         h.get("posture", ""), h.get("open_port_count", 0),
                         h.get("open", h.get("port_open", 0)),
                         h.get("closed", h.get("port_closed", 0)),
                         h.get("filtered", h.get("port_filtered", 0)),
                         h.get("scanned", h.get("port_scanned", 0))))
                conn.commit()
            except Exception:
                log.warning("network_posture subnet insert failed", exc_info=True)
        return
    for k, v in list(r.items()):
        if isinstance(v, (dict, list)):
            r[k] = json.dumps(v, default=str)
    if "category" not in r:
        r["category"] = r.pop("type", r.get("tool", "posture"))
    if "check_name" not in r:
        r["check_name"] = r.pop("check", r.pop("name", "summary"))
    if "status" not in r:
        r["status"] = r.pop("result", "info")
    sid = r.pop("_scope_id", None)
    if sid is not None:
        r["scope_id"] = sid
    _safe_db_call(db.add_network_posture, r)

_COOKIE_COLS = {
    "name", "domain", "path", "secure", "httponly", "samesite",
    "expires_at", "scope", "tool", "url", "risk", "issues", "value", "role",
}

def _cookie(db, row):
    r = _clean(row)
    mf = r.pop("missing_flags", None)
    if isinstance(mf, dict) and not r.get("issues"):
        flagged = [k for k, v in mf.items() if v]
        if flagged:
            r["issues"] = "Missing: " + ", ".join(flagged)
    raw = r.pop("raw", None)
    if raw and not r.get("name"):
        try:
            parts = raw.split(";")
            kv = parts[0].strip()
            eq = kv.find("=")
            if eq > 0:
                r["name"] = kv[:eq].strip()
                r.setdefault("value", kv[eq+1:].strip())
                for attr in parts[1:]:
                    attr = attr.strip().lower()
                    if attr.startswith("domain="):
                        r.setdefault("domain", attr.split("=", 1)[1].strip())
                    elif attr.startswith("path="):
                        r.setdefault("path", attr.split("=", 1)[1].strip())
                    elif attr == "secure":
                        r.setdefault("secure", True)
                    elif attr == "httponly":
                        r.setdefault("httponly", True)
                    elif attr.startswith("samesite="):
                        r.setdefault("samesite", attr.split("=", 1)[1].strip())
        except Exception:
            pass
    ip = r.pop("ip", None)
    port = r.pop("port", None)
    hostname = r.pop("hostname", None)
    if not r.get("url") and ip:
        scheme = r.pop("scheme", "https")
        r["url"] = f"{scheme}://{ip}" + (f":{port}" if port else "")
    r.pop("scheme", None)
    filtered = {k: v for k, v in r.items() if k in _COOKIE_COLS}
    if not filtered.get("name"):
        return
    _safe_db_call(db.add_cookie, filtered)

def _webapp_intel(db, row):
    r = _clean(row)
    if "x_powered_by" in r and "powered_by" not in r:
        r["powered_by"] = r.pop("x_powered_by")
    if "frameworks" in r and isinstance(r["frameworks"], list):
        r["frameworks"] = json.dumps(r["frameworks"])
    if "programming_languages" in r and isinstance(r["programming_languages"], list):
        r["programming_languages"] = json.dumps(r["programming_languages"])
    if "tls_protocols" in r and isinstance(r["tls_protocols"], list):
        r["tls_protocols"] = json.dumps(r["tls_protocols"])
    if "backend_ips" in r and isinstance(r["backend_ips"], list):
        r["backend_ips"] = json.dumps(r["backend_ips"])
    sid = r.pop("_scope_id", None)
    if sid is not None:
        r["scope_id"] = sid
    _safe_db_call(db.add_webapp_intel, r)

def _api_inventory(db, row):
    r = _clean(row)
    _safe_db_call(db.add_api_inventory, r)

def _firewall_config(db, row):
    r = _clean(row)
    _safe_db_call(db.add_firewall_config, r)

def _endpoint_overview(db, row):
    r = _clean(row)
    _safe_db_call(db.add_endpoint_overview, r)

def _endpoint_network(db, row):
    r = _clean(row)
    _safe_db_call(db.add_endpoint_network, r)

def _endpoint_disk(db, row):
    r = _clean(row)
    _safe_db_call(db.add_endpoint_disk, r)

def _endpoint_hardware(db, row):
    r = _clean(row)
    _safe_db_call(db.add_endpoint_hardware, r)


# ── survey (Aether wireless survey) ──────────────────────────────────────

def _safe_int(val, default=0):
    if val is None or val == "":
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _survey_ap(db, row):
    r = _clean(row)
    loc_name = r.get("location", "")
    if not loc_name:
        return
    bssid = r.get("bssid", "")
    if not bssid:
        return
    loc_id = db.ensure_survey_location(loc_name)
    db.upsert_survey_ap(
        loc_id, bssid,
        ssid=r.get("ssid", ""),
        channel=_safe_int(r.get("channel", 0)),
        encryption=r.get("encryption", ""),
        cipher=r.get("cipher", ""),
        auth=r.get("auth", ""),
        signal=_safe_int(r.get("signal", r.get("power_dbm")), -100),
        beacons=_safe_int(r.get("beacons", 0)),
        client_count=_safe_int(r.get("client_count", 0)),
        wps=1 if r.get("wps") else 0,
        in_scope=1 if r.get("in_scope") else 0,
    )
    db.add_wireless_network(
        bssid,
        ssid=r.get("ssid", ""),
        channel=r.get("channel"),
        encryption=r.get("encryption", ""),
        cipher=r.get("cipher", ""),
        auth=r.get("auth", ""),
        signal_dbm=r.get("signal") or r.get("power_dbm"),
        wps=r.get("wps", False),
    )


def _survey_rogue_classify(db, row):
    r = _clean(row)
    bssid = r.get("bssid", "")
    if not bssid:
        return
    db.classify_survey_rogue(
        bssid,
        r.get("ssid", ""),
        r.get("classification", "uncategorized"),
    )


def _domain_intel(db, row):
    r = _clean(row)
    dn = r.get("domain_name", "")
    src = r.get("source", "")
    if not dn or not src:
        return
    _safe_db_call(db.add_domain_intel, r)


# ── dispatch table: subtype → (single_handler, bulk_method_or_None) ──────
_DISPATCH = {
    "software":          (_sw,               "bulk_insert_network_software"),
    "hostname_intel":    (_hostname_intel,     None),
    "host_os":           (_host_os,            None),
    "server_role":       (_server_role,        None),
    "domain_intel":      (_domain_intel,       "bulk_insert_domain_intel"),
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
    "osint_whois":       (_osint_whois,         None),
    "osint_certificate": (_osint_certificate,  "bulk_insert_osint_certificates"),
    "osint_email":       (_osint_email,         None),
    "osint_subdomain":   (_osint_subdomain,     None),
    "osint_phone":       (_osint_phone,        "bulk_insert_osint_phones"),
    "osint_breach":      (_osint_breach,        None),
    "osint_person":      (_osint_person,        None),
    "osint_wayback":     (_osint_wayback,       None),
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
    "wireless_ap":       (_wireless_ap,          None),
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
    "wireless_client":   (_wireless_client,      None),
    "wireless_probe":    (_wireless_probe,       None),
    "wireless_handshake": (_wireless_network,   None),
    "ble_device":        (_wireless_network,    None),
    "ble_service":       (_wireless_network,    None),
    "zigbee_network":    (_wireless_network,    None),
    "zigbee_device":     (_wireless_network,    None),
    "usb_device":        (_wireless_network,    None),
    "survey_ap":             (_survey_ap,              None),
    "survey_rogue_classify": (_survey_rogue_classify,  None),
}

_SCOPED_INTEL_SUBTYPES = frozenset({
    "hostname_intel", "host", "host_os", "port", "certificate",
    "software", "server_role", "network_posture", "screenshot",
    "cookie", "webapp_intel", "dns_record", "structure_url",
    "structure_param", "structure_form", "structure_header",
    "domain_intel", "api_endpoint", "access_matrix", "auth_session",
    "auth_cookie", "target_profile", "api_inventory",
    "firewall_rule", "firewall_zone", "firewall_compliance",
    "firewall_config", "cloud_resource", "cloud_iam_policy",
    "cloud_iam_role", "cloud_service", "traffic_conversation",
    "traffic_summary", "db_schema", "db_table", "db_column",
    "db_privilege", "endpoint_software", "endpoint_hardening",
    "endpoint_compliance", "endpoint_ad", "endpoint_browser",
    "endpoint_inventory", "endpoint_overview", "endpoint_network",
    "endpoint_disk", "endpoint_hardware", "osint_domain",
    "osint_whois", "osint_certificate", "osint_email", "osint_subdomain", "osint_phone",
    "osint_breach", "osint_person", "osint_wayback", "osint_typosquat",
    "mobile_component", "mobile_permission", "mobile_data_flow",
    "mobile_traffic", "mobile_hardening", "mobile_domain",
    "mobile_email", "mobile_api_endpoint",
    "isotope_string", "isotope_property", "isotope_entropy",
    "isotope_secret", "isotope_code", "isotope_binary",
    "isotope_ioc", "isotope_content", "isotope_metadata",
    "wireless_network", "wireless_ap", "wireless_client",
    "wireless_probe", "wireless_handshake",
    "ble_device", "ble_service", "zigbee_network", "zigbee_device",
    "usb_device", "survey_ap", "survey_rogue_classify",
    "output_file", "console_chunk",
    "subdomain", "email", "endpoint",
})


def _resolve_project_scope_id(db, project, tool_id=None):
    base_tool = tool_id.split(":")[0] if tool_id and ":" in tool_id else tool_id
    if base_tool:
        scope_tools = project.get("scope_tools") or {}
        for scope_name, tools in scope_tools.items():
            if base_tool in (tools or []):
                return db.ensure_scope(scope_name)
    scopes = project.get("active_scopes") or []
    if not scopes:
        s = project.get("scope", "external")
        scopes = [] if s == "multi" else [s]
    if len(scopes) == 1:
        return db.ensure_scope(scopes[0])
    return None


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

    db = findings_engine._get_db(project_id, project, create=True)
    if db is None:
        log.warning("handle_intel: cannot open/create DB for project %s",
                     project_id[:8])
        return

    scope_id = None
    if intel_type in _SCOPED_INTEL_SUBTYPES:
        scope_id = _resolve_project_scope_id(db, project, tool_id=tool_id)

    base_tool = tool_id.split(":")[0] if tool_id and ":" in tool_id else tool_id

    def _ensure_tool(row):
        if isinstance(row, dict) and "tool" not in row and base_tool:
            row["tool"] = base_tool

    try:
        if is_bulk and isinstance(payload, list):
            if bulk_method and hasattr(db, bulk_method):
                cleaned = [_clean(r) for r in payload if isinstance(r, dict)]
                for c in cleaned:
                    _ensure_tool(c)
                    if scope_id is not None:
                        c["_scope_id"] = scope_id
                getattr(db, bulk_method)(cleaned)
            else:
                for row in payload:
                    if isinstance(row, dict):
                        _ensure_tool(row)
                        if scope_id is not None:
                            row["_scope_id"] = scope_id
                        handler_fn(db, row)
        elif isinstance(payload, dict):
            _ensure_tool(payload)
            if scope_id is not None:
                payload["_scope_id"] = scope_id
            handler_fn(db, payload)
        elif isinstance(payload, list):
            if bulk_method and hasattr(db, bulk_method):
                cleaned = [_clean(r) for r in payload if isinstance(r, dict)]
                for c in cleaned:
                    _ensure_tool(c)
                    if scope_id is not None:
                        c["_scope_id"] = scope_id
                getattr(db, bulk_method)(cleaned)
            else:
                for row in payload:
                    if isinstance(row, dict):
                        _ensure_tool(row)
                        if scope_id is not None:
                            row["_scope_id"] = scope_id
                        handler_fn(db, row)

        try:
            db._conn.commit()
        except Exception:
            pass
    except Exception as exc:
        log.warning("handle_intel DB insert (%s/%s): %s",
                     intel_type, tool_id, exc)
        try:
            socketio.emit("tool_error", {
                "project_id": project_id,
                "tool_id": tool_id,
                "message": f"Intel DB insert failed ({intel_type}): {exc}",
                "level": "ERROR",
            }, room=f"project_{project_id}")
        except Exception:
            pass

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
