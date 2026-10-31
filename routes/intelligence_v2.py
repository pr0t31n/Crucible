"""Intelligence v2 routes — DB-backed paginated endpoints.

Provides paginated, filtered access to all intelligence panel data via
FindingsDB queries instead of loading full JSON files.  Each endpoint
returns ``{items, total, page, pages}`` (or ``{error}`` on failure).

Register this blueprint in Crucible's app factory::

    from routes.intelligence_v2 import intel_v2
    app.register_blueprint(intel_v2)
"""

import logging

from flask import Blueprint, request, jsonify

log = logging.getLogger("crucible.routes.intelligence_v2")

intel_v2 = Blueprint("intel_v2", __name__)

# ── FindingsDB handle cache ───────────────────────────────────────

_db_cache = {}


def _get_db(project):
    """Get or create a FindingsDB handle for *project*."""
    pid = project.get("id", "")
    if pid in _db_cache:
        return _db_cache[pid]
    try:
        from pathlib import Path
        import sys
        if "/opt/pr0t31n/shared" not in sys.path:
            sys.path.insert(0, "/opt/pr0t31n/shared")
        import pr0t31n_findings_db
        pd = project.get("project_dir") or project.get("engagement_dir", "")
        if not pd:
            return None
        db_path = Path(pd) / "findings.db"
        if not db_path.exists():
            return None
        db = pr0t31n_findings_db.FindingsDB(str(db_path))
        _db_cache[pid] = db
        return db
    except Exception:
        log.debug("_get_db failed for %s", pid, exc_info=True)
        return None


def _get_project(project_id):
    """Resolve project from Crucible's project store."""
    try:
        from models.project import get_project
        return get_project(project_id)
    except Exception:
        return None


def _paginate_params():
    """Extract standard pagination params from the request query string."""
    return {
        "page": max(1, int(request.args.get("page", 1))),
        "per_page": min(500, max(1, int(request.args.get("per_page", 50)))),
    }


def _search_param():
    """Return search string or None."""
    s = request.args.get("search", "").strip()
    return s if s else None


def _sort_params(default_sort="id", default_order="asc"):
    return {
        "sort": request.args.get("sort", default_sort),
        "order": request.args.get("order", default_order),
    }


def _err_404():
    return jsonify({"error": "not found"}), 404


def _err_503():
    return jsonify({"error": "db unavailable"}), 503


def _err_500(e):
    log.warning("intel_v2 error: %s", e, exc_info=True)
    return jsonify({"error": str(e)}), 500


def _empty_page(page=1):
    return {"items": [], "total": 0, "page": page, "pages": 0}


# ═══════════════════════════════════════════════════════════════════
#  Network Intelligence  (SS3)
# ═══════════════════════════════════════════════════════════════════

@intel_v2.route("/api/intel/v2/hosts/<project_id>")
def api_intel_v2_hosts(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    search = _search_param()
    sp = _sort_params(default_sort="ip")
    try:
        result = db.query_hosts(search=search, **p, **sp)
        return jsonify(result)
    except AttributeError:
        return jsonify(_empty_page(p["page"]))
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/ports/<project_id>")
def api_intel_v2_ports(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    ip = request.args.get("ip")
    sp = _sort_params(default_sort="port")
    try:
        result = db.query_ports(ip=ip, **p, **sp)
        return jsonify(result)
    except AttributeError:
        return jsonify(_empty_page(p["page"]))
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/services/<project_id>")
def api_intel_v2_services(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_services(search=search, **p)
        return jsonify(result)
    except AttributeError:
        return jsonify(_empty_page(p["page"]))
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/software/<project_id>")
def api_intel_v2_software(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_software(search=search, **p)
        return jsonify(result)
    except AttributeError:
        return jsonify(_empty_page(p["page"]))
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/hostname-intel/<project_id>")
def api_intel_v2_hostname_intel(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    search = _search_param()
    env_tag = request.args.get("environment_tag")
    try:
        result = db.query_hostname_intel(
            environment_tag=env_tag, search=search, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/server-roles/<project_id>")
def api_intel_v2_server_roles(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    ip = request.args.get("ip")
    role = request.args.get("role")
    try:
        result = db.query_server_roles(ip=ip, role=role, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/screenshots/<project_id>")
def api_intel_v2_screenshots(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    ip = request.args.get("ip")
    tool = request.args.get("tool")
    try:
        result = db.query_screenshots(tool=tool, ip=ip, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


# ═══════════════════════════════════════════════════════════════════
#  WebApp Intelligence  (Fracture)
# ═══════════════════════════════════════════════════════════════════

@intel_v2.route("/api/intel/v2/structure-urls/<project_id>")
def api_intel_v2_structure_urls(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    search = _search_param()
    status_code = request.args.get("status_code", type=int)
    source = request.args.get("source")
    try:
        result = db.query_structure_urls(
            status_code=status_code, source=source, search=search, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/structure-params/<project_id>")
def api_intel_v2_structure_params(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    search = _search_param()
    url_id = request.args.get("url_id", type=int)
    try:
        result = db.query_structure_params(
            url_id=url_id, search=search, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/access-matrix/<project_id>")
def api_intel_v2_access_matrix(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    tool = request.args.get("tool")
    role = request.args.get("role")
    result_filter = request.args.get("result")
    try:
        result = db.query_access_matrix_entries(
            tool=tool, role=role, result=result_filter, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/auth-sessions/<project_id>")
def api_intel_v2_auth_sessions(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    tool = request.args.get("tool")
    try:
        result = db.query_auth_sessions(tool=tool, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/target-profiles/<project_id>")
def api_intel_v2_target_profiles(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    tool = request.args.get("tool")
    try:
        result = db.query_target_profiles(tool=tool, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


# ═══════════════════════════════════════════════════════════════════
#  OSINT  (OSift)
# ═══════════════════════════════════════════════════════════════════

@intel_v2.route("/api/intel/v2/osint-domains/<project_id>")
def api_intel_v2_osint_domains(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_osint_domains(search=search, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/osint-emails/<project_id>")
def api_intel_v2_osint_emails(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_osint_emails(search=search, **p)
        return jsonify(result)
    except AttributeError:
        return jsonify(_empty_page(p["page"]))
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/osint-breaches/<project_id>")
def api_intel_v2_osint_breaches(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    search = _search_param()
    email_id = request.args.get("email_id", type=int)
    try:
        result = db.query_osint_breaches(email_id=email_id, search=search, **p)
        return jsonify(result)
    except AttributeError:
        return jsonify(_empty_page(p["page"]))
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/osint-people/<project_id>")
def api_intel_v2_osint_people(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_osint_people(search=search, **p)
        return jsonify(result)
    except AttributeError:
        return jsonify(_empty_page(p["page"]))
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/osint-subdomains/<project_id>")
def api_intel_v2_osint_subdomains(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_osint_subdomains(search=search, **p)
        return jsonify(result)
    except AttributeError:
        return jsonify(_empty_page(p["page"]))
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/osint-dns/<project_id>")
def api_intel_v2_osint_dns(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    search = _search_param()
    record_type = request.args.get("record_type")
    try:
        result = db.query_osint_dns(
            record_type=record_type, search=search, **p)
        return jsonify(result)
    except AttributeError:
        return jsonify(_empty_page(p["page"]))
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/osint-certificates/<project_id>")
def api_intel_v2_osint_certificates(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_osint_certificates(search=search, **p)
        return jsonify(result)
    except AttributeError:
        return jsonify(_empty_page(p["page"]))
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/osint-wayback/<project_id>")
def api_intel_v2_osint_wayback(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    domain = request.args.get("domain")
    mime_type = request.args.get("mime_type")
    try:
        result = db.query_osint_wayback_urls(
            domain=domain, mime_type=mime_type, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/osint-typosquats/<project_id>")
def api_intel_v2_osint_typosquats(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    domain = request.args.get("domain")
    fuzzer = request.args.get("fuzzer")
    try:
        result = db.query_osint_typosquats(
            domain=domain, fuzzer=fuzzer, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/osint-phones/<project_id>")
def api_intel_v2_osint_phones(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    search = _search_param()
    phone_type = request.args.get("phone_type")
    person_id = request.args.get("person_id", type=int)
    try:
        result = db.query_osint_phones(
            person_id=person_id, phone_type=phone_type, search=search, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


# ═══════════════════════════════════════════════════════════════════
#  Firewall  (Bastion)
# ═══════════════════════════════════════════════════════════════════

@intel_v2.route("/api/intel/v2/firewall-rules/<project_id>")
def api_intel_v2_firewall_rules(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    action = request.args.get("action")
    source_zone = request.args.get("source_zone")
    dest_zone = request.args.get("dest_zone")
    search = _search_param()
    try:
        result = db.query_firewall_rules(
            action=action, source_zone=source_zone, dest_zone=dest_zone,
            search=search, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/firewall-zones/<project_id>")
def api_intel_v2_firewall_zones(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    zone_type = request.args.get("zone_type")
    try:
        result = db.query_firewall_zones(zone_type=zone_type, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/firewall-compliance/<project_id>")
def api_intel_v2_firewall_compliance(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    status = request.args.get("status")
    framework = request.args.get("framework")
    search = _search_param()
    try:
        result = db.query_firewall_compliance(
            status=status, framework=framework, search=search, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


# ═══════════════════════════════════════════════════════════════════
#  Cloud  (Forge)
# ═══════════════════════════════════════════════════════════════════

@intel_v2.route("/api/intel/v2/cloud-resources/<project_id>")
def api_intel_v2_cloud_resources(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    resource_type = request.args.get("resource_type")
    region = request.args.get("region")
    search = _search_param()
    try:
        result = db.query_cloud_resources(
            resource_type=resource_type, region=region, search=search, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/cloud-iam-policies/<project_id>")
def api_intel_v2_cloud_iam_policies(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    policy_type = request.args.get("policy_type")
    search = _search_param()
    try:
        result = db.query_cloud_iam_policies(
            policy_type=policy_type, search=search, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/cloud-iam-roles/<project_id>")
def api_intel_v2_cloud_iam_roles(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    search = _search_param()
    is_service_role = request.args.get("is_service_role")
    if is_service_role is not None:
        is_service_role = is_service_role.lower() in ("1", "true", "yes")
    try:
        result = db.query_cloud_iam_roles(
            is_service_role=is_service_role, search=search, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/cloud-services/<project_id>")
def api_intel_v2_cloud_services(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_cloud_services(search=search, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


# ═══════════════════════════════════════════════════════════════════
#  Traffic  (Trawler)
# ═══════════════════════════════════════════════════════════════════

@intel_v2.route("/api/intel/v2/traffic-conversations/<project_id>")
def api_intel_v2_traffic_conversations(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    src_ip = request.args.get("src_ip")
    dst_ip = request.args.get("dst_ip")
    protocol = request.args.get("protocol")
    try:
        result = db.query_traffic_conversations(
            src_ip=src_ip, dst_ip=dst_ip, protocol=protocol, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/traffic-summary/<project_id>")
def api_intel_v2_traffic_summary(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    category = request.args.get("category")
    search = _search_param()
    try:
        result = db.query_traffic_summary(
            category=category, search=search, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


# ═══════════════════════════════════════════════════════════════════
#  DB Audit  (Auger)
# ═══════════════════════════════════════════════════════════════════

@intel_v2.route("/api/intel/v2/db-schemas/<project_id>")
def api_intel_v2_db_schemas(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    db_type = request.args.get("db_type")
    host = request.args.get("host")
    search = _search_param()
    try:
        result = db.query_db_schemas(
            db_type=db_type, host=host, search=search, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/db-tables/<project_id>")
def api_intel_v2_db_tables(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    schema_id = request.args.get("schema_id", type=int)
    search = _search_param()
    try:
        result = db.query_db_tables(
            schema_id=schema_id, search=search, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/db-privileges/<project_id>")
def api_intel_v2_db_privileges(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    grantee = request.args.get("grantee")
    privilege_type = request.args.get("privilege_type")
    try:
        result = db.query_db_privileges(
            grantee=grantee, privilege_type=privilege_type, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


# ═══════════════════════════════════════════════════════════════════
#  Endpoint Security  (Dredge)
# ═══════════════════════════════════════════════════════════════════

@intel_v2.route("/api/intel/v2/endpoint-software/<project_id>")
def api_intel_v2_endpoint_software(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    search = _search_param()
    category = request.args.get("category")
    try:
        result = db.query_endpoint_software(
            search=search, category=category, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/endpoint-hardening/<project_id>")
def api_intel_v2_endpoint_hardening(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    status = request.args.get("status")
    category = request.args.get("category")
    try:
        result = db.query_endpoint_hardening(
            status=status, category=category, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/endpoint-compliance/<project_id>")
def api_intel_v2_endpoint_compliance(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    framework = request.args.get("framework")
    status = request.args.get("status")
    try:
        result = db.query_endpoint_compliance(
            framework=framework, status=status, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/endpoint-ad/<project_id>")
def api_intel_v2_endpoint_ad(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    check_category = request.args.get("check_category")
    search = _search_param()
    try:
        result = db.query_endpoint_ad(
            check_category=check_category, search=search, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/endpoint-browsers/<project_id>")
def api_intel_v2_endpoint_browsers(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_endpoint_browsers(search=search, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


# ═══════════════════════════════════════════════════════════════════
#  Mobile  (Quill)
# ═══════════════════════════════════════════════════════════════════

@intel_v2.route("/api/intel/v2/mobile-components/<project_id>")
def api_intel_v2_mobile_components(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    component_type = request.args.get("component_type")
    search = _search_param()
    try:
        result = db.query_mobile_components(
            component_type=component_type, search=search, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/mobile-permissions/<project_id>")
def api_intel_v2_mobile_permissions(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    search = _search_param()
    protection_level = request.args.get("protection_level")
    try:
        result = db.query_mobile_permissions(
            protection_level=protection_level, search=search, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/mobile-data-flows/<project_id>")
def api_intel_v2_mobile_data_flows(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    encrypted = request.args.get("encrypted")
    if encrypted is not None:
        encrypted = encrypted.lower() in ("1", "true", "yes")
    search = _search_param()
    try:
        result = db.query_mobile_data_flows(
            encrypted=encrypted, search=search, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/mobile-traffic/<project_id>")
def api_intel_v2_mobile_traffic(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    host = request.args.get("host")
    search = _search_param()
    try:
        result = db.query_mobile_traffic(host=host, search=search, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


# ═══════════════════════════════════════════════════════════════════
#  Isotope  (file analysis)
# ═══════════════════════════════════════════════════════════════════

@intel_v2.route("/api/intel/v2/isotope-strings/<project_id>")
def api_intel_v2_isotope_strings(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    string_type = request.args.get("string_type")
    search = _search_param()
    try:
        result = db.query_isotope_strings(
            string_type=string_type, search=search, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/isotope-secrets/<project_id>")
def api_intel_v2_isotope_secrets(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    secret_type = request.args.get("secret_type")
    search = _search_param()
    try:
        result = db.query_isotope_secrets(
            secret_type=secret_type, search=search, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/isotope-iocs/<project_id>")
def api_intel_v2_isotope_iocs(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    ioc_type = request.args.get("ioc_type")
    search = _search_param()
    try:
        result = db.query_isotope_iocs(
            ioc_type=ioc_type, search=search, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/isotope-properties/<project_id>")
def api_intel_v2_isotope_properties(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    category = request.args.get("category")
    search = _search_param()
    try:
        result = db.query_isotope_properties(
            category=category, search=search, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


# ═══════════════════════════════════════════════════════════════════
#  Cross-Cutting
# ═══════════════════════════════════════════════════════════════════

@intel_v2.route("/api/intel/v2/action-items/<project_id>")
def api_intel_v2_action_items(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    status = request.args.get("status")
    tool = request.args.get("tool")
    try:
        result = db.get_action_items(status=status, tool=tool, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/output-files/<project_id>")
def api_intel_v2_output_files(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    tool = request.args.get("tool")
    extension = request.args.get("extension")
    search = _search_param()
    try:
        result = db.query_output_files(
            tool=tool, extension=extension, search=search, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/crucible-logs/<project_id>")
def api_intel_v2_crucible_logs(project_id):
    """Crucible logs with optional time-range filtering (from_ts / to_ts)."""
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    level = request.args.get("level")
    tool = request.args.get("tool")
    from_ts = request.args.get("from_ts")
    to_ts = request.args.get("to_ts")
    try:
        result = db.query_crucible_logs(
            level=level, tool=tool, from_ts=from_ts, to_ts=to_ts, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/crucible-errors/<project_id>")
def api_intel_v2_crucible_errors(project_id):
    """Crucible errors with optional time-range filtering (from_ts / to_ts)."""
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    level = request.args.get("level")
    tool = request.args.get("tool")
    from_ts = request.args.get("from_ts")
    to_ts = request.args.get("to_ts")
    try:
        result = db.query_crucible_errors(
            level=level, tool=tool, from_ts=from_ts, to_ts=to_ts, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/console/<project_id>/<tool_id>")
def api_intel_v2_console(project_id, tool_id):
    """Console output for a specific tool, paginated or tail-N."""
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    tail = request.args.get("tail", type=int)
    try:
        if tail:
            text = db.get_console_text(tool_id)
            if text:
                lines = text.splitlines()
                tail_lines = lines[-tail:] if tail < len(lines) else lines
                return jsonify({
                    "text": "\n".join(tail_lines),
                    "total_lines": len(lines),
                    "returned_lines": len(tail_lines),
                })
            return jsonify({"text": "", "total_lines": 0, "returned_lines": 0})
        result = db.query_console_chunks(tool_id, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


# ═══════════════════════════════════════════════════════════════════
#  Summary  (lightweight counts for all intelligence types)
# ═══════════════════════════════════════════════════════════════════

def _safe_count(db, method_name, **kwargs):
    """Call a count_* method if it exists, else return 0."""
    fn = getattr(db, method_name, None)
    if fn is None:
        return 0
    try:
        return fn(**kwargs)
    except Exception:
        return 0


def _safe_table_count(db, table_name):
    """Direct COUNT(*) on a table, returning 0 on any error."""
    try:
        row = db._conn.execute(
            f"SELECT COUNT(*) FROM [{table_name}]").fetchone()
        return row[0] if row else 0
    except Exception:
        return 0


@intel_v2.route("/api/intel/v2/summary/<project_id>")
def api_intel_v2_summary(project_id):
    """Lightweight overview: counts for each intelligence type.

    Returns a flat dict like::

        {"hosts": 150, "ports": 2300, "structure_urls": 45000, ...}
    """
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    try:
        counts = {
            # Network (SS3)
            "hosts": _safe_table_count(db, "hosts"),
            "ports": _safe_table_count(db, "ports"),
            "services": _safe_table_count(db, "services"),
            "software": _safe_table_count(db, "software"),
            "hostname_intel": _safe_count(db, "count_hostname_intel"),
            "server_roles": _safe_count(db, "count_server_roles"),
            "screenshots": _safe_count(db, "count_screenshots"),
            # WebApp (Fracture)
            "structure_urls": _safe_count(db, "count_structure_urls"),
            "structure_params": _safe_count(db, "count_structure_params"),
            "access_matrix": _safe_count(db, "count_access_matrix_entries"),
            "auth_sessions": _safe_count(db, "count_auth_sessions"),
            "target_profiles": _safe_count(db, "count_target_profiles"),
            # OSINT (OSift)
            "osint_domains": _safe_table_count(db, "osint_domains"),
            "osint_emails": _safe_table_count(db, "osint_emails"),
            "osint_breaches": _safe_table_count(db, "osint_breaches"),
            "osint_people": _safe_table_count(db, "osint_people"),
            "osint_subdomains": _safe_table_count(db, "osint_subdomains"),
            "osint_wayback": _safe_table_count(db, "osint_wayback_urls"),
            "osint_typosquats": _safe_table_count(db, "osint_typosquats"),
            "osint_phones": _safe_table_count(db, "osint_phones"),
            # Firewall (Bastion)
            "firewall_rules": _safe_table_count(db, "firewall_rules"),
            "firewall_zones": _safe_table_count(db, "firewall_zones"),
            "firewall_compliance": _safe_table_count(db, "firewall_compliance"),
            # Cloud (Forge)
            "cloud_resources": _safe_table_count(db, "cloud_resources"),
            "cloud_iam_policies": _safe_table_count(db, "cloud_iam_policies"),
            "cloud_iam_roles": _safe_table_count(db, "cloud_iam_roles"),
            "cloud_services": _safe_table_count(db, "cloud_services"),
            # Traffic (Trawler)
            "traffic_conversations": _safe_table_count(db, "traffic_conversations"),
            "traffic_summary": _safe_table_count(db, "traffic_summary"),
            # DB Audit (Auger)
            "db_schemas": _safe_table_count(db, "db_schemas"),
            "db_tables": _safe_table_count(db, "db_tables"),
            "db_privileges": _safe_table_count(db, "db_privileges"),
            # Endpoint Security (Dredge)
            "endpoint_software": _safe_table_count(db, "endpoint_software"),
            "endpoint_hardening": _safe_table_count(db, "endpoint_hardening"),
            "endpoint_compliance": _safe_table_count(db, "endpoint_compliance"),
            "endpoint_ad": _safe_table_count(db, "endpoint_ad_checks"),
            "endpoint_browsers": _safe_table_count(db, "endpoint_browsers"),
            # Mobile (Quill)
            "mobile_components": _safe_table_count(db, "mobile_components"),
            "mobile_permissions": _safe_table_count(db, "mobile_permissions"),
            "mobile_data_flows": _safe_table_count(db, "mobile_data_flows"),
            "mobile_traffic": _safe_table_count(db, "mobile_traffic"),
            # Isotope (file analysis)
            "isotope_strings": _safe_table_count(db, "isotope_strings"),
            "isotope_secrets": _safe_table_count(db, "isotope_secrets"),
            "isotope_iocs": _safe_table_count(db, "isotope_iocs"),
            "isotope_properties": _safe_table_count(db, "isotope_properties"),
            # Cross-cutting
            "action_items": _safe_table_count(db, "action_items"),
            "output_files": _safe_count(db, "count_output_files"),
            "crucible_logs": _safe_count(db, "count_crucible_logs"),
            "crucible_errors": _safe_count(db, "count_crucible_errors"),
            "console_chunks": _safe_count(db, "count_console_chunks"),
        }
        return jsonify(counts)
    except Exception as e:
        return _err_500(e)
