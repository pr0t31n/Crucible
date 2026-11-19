"""Intelligence v2 routes — DB-backed paginated endpoints.

Provides paginated, filtered access to all intelligence panel data via
FindingsDB queries instead of loading full JSON files.  Each endpoint
returns ``{items, total, page, pages}`` (or ``{error}`` on failure).

Register this blueprint in Crucible's app factory::

    from routes.intelligence_v2 import intel_v2
    app.register_blueprint(intel_v2)
"""

import json
import logging
from pathlib import Path

from flask import Blueprint, request, jsonify

log = logging.getLogger("crucible.routes.intelligence_v2")

intel_v2 = Blueprint("intel_v2", __name__)

# ── FindingsDB handle cache ───────────────────────────────────────

_db_cache = {}
_idb_cache = {}


def _get_db(project):
    """Get or create a FindingsDB handle for *project*."""
    pid = project.get("id", "")
    if pid in _db_cache:
        db = _db_cache[pid]
        try:
            db._conn.execute("SELECT 1")
            return db
        except Exception:
            log.warning("intel_v2: stale DB handle for %s — reconnecting", pid)
            try:
                db.close()
            except Exception:
                pass
            del _db_cache[pid]
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
        scope_tools = project.get("scope_tools") or {}
        for scope_name in scope_tools:
            try:
                db.ensure_scope(scope_name)
            except Exception:
                pass
        log.info("intel_v2: opened FindingsDB for %s at %s", pid, db_path)
        return db
    except Exception:
        log.warning("_get_db failed for %s", pid, exc_info=True)
        return None


def _get_idb(project):
    """Get or create an IntelligenceDB handle for *project*."""
    pid = project.get("id", "")
    if pid in _idb_cache:
        idb = _idb_cache[pid]
        try:
            idb._conn.execute("SELECT 1")
            return idb
        except Exception:
            try:
                idb.close()
            except Exception:
                pass
            del _idb_cache[pid]
    try:
        import sys
        if "/opt/pr0t31n/shared" not in sys.path:
            sys.path.insert(0, "/opt/pr0t31n/shared")
        import pr0t31n_intelligence_db
        pd = project.get("project_dir") or project.get("engagement_dir", "")
        if not pd:
            return None
        db_path = Path(pd) / "findings.db"
        if not db_path.exists():
            return None
        idb = pr0t31n_intelligence_db.IntelligenceDB(str(db_path))
        _idb_cache[pid] = idb
        return idb
    except Exception:
        log.warning("_get_idb failed for %s", pid, exc_info=True)
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
    return jsonify({"error": "Internal error"}), 500


_SCOPE_DISPLAY_TO_KEY = {
    "External": "external", "Internal": "internal",
    "Web Application": "webapp", "API": "api", "OSINT": "osint",
    "Database": "database", "PCAP Analysis": "pcap",
    "Wi-Fi (802.11)": "wifi", "Bluetooth (802.15.1)": "bluetooth",
    "Zigbee (802.15.4)": "zigbee",
    "Ultra-Wideband (UWB) (802.15.4z)": "uwb",
    "Firewall Config Analysis": "firewall",
    "Cloud Infrastructure": "cloud", "Mobile Application": "mobile",
    "File Analysis": "file", "Endpoint Security": "endpoint",
}


def _resolve_scope_id(db, scope_param):
    """Resolve a scope query-param (display name or key) to a DB scope_id."""
    if not scope_param or not db:
        return None
    key = _SCOPE_DISPLAY_TO_KEY.get(scope_param, scope_param).lower()
    return db.get_scope_id(key)


def _scope_tool_params(db):
    """Extract scope_id and tool from request query string."""
    tool = request.args.get("tool")
    scope_id = _resolve_scope_id(db, request.args.get("scope"))
    return {"scope_id": scope_id, "tool": tool}




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
    stp = _scope_tool_params(db)
    try:
        result = db.query_hosts(search=search, scope_id=stp["scope_id"],
                                **p, **sp)
        return jsonify(result)
    except AttributeError as e:
        log.warning("intel_v2 hosts AttributeError for %s: %s", project_id, e, exc_info=True)
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
    stp = _scope_tool_params(db)
    try:
        result = db.query_ports(ip=ip, scope_id=stp["scope_id"], **p, **sp)
        return jsonify(result)
    except AttributeError as e:
        log.warning("intel_v2 ports AttributeError for %s: %s", project_id, e, exc_info=True)
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
    stp = _scope_tool_params(db)
    try:
        result = db.query_services(search=search, scope_id=stp["scope_id"],
                                   **p)
        return jsonify(result)
    except AttributeError as e:
        log.warning("intel_v2 services AttributeError for %s: %s", project_id, e, exc_info=True)
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
        return jsonify(_empty_page(1))
    p = _paginate_params()
    search = _search_param()
    stp = _scope_tool_params(db)
    try:
        result = db.query_software(search=search,
                                   scope_id=stp["scope_id"], **p)
        return jsonify(result)
    except Exception as e:
        log.warning("intel_v2 software error for %s: %s", project_id, e, exc_info=True)
    return jsonify(_empty_page(p["page"]))


@intel_v2.route("/api/intel/v2/hostname-intel/<project_id>")
def api_intel_v2_hostname_intel(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    db_empty = True
    if db:
        try:
            p = _paginate_params()
            search = _search_param()
            stp = _scope_tool_params(db)
            env_tag = request.args.get("environment_tag")
            result = db.query_hostname_intel(
                environment_tag=env_tag, search=search,
                scope_id=stp["scope_id"], **p)
            if result.get("total", 0) > 0:
                return jsonify(result)
        except Exception:
            pass
    return jsonify(_empty_page())


@intel_v2.route("/api/intel/v2/server-roles/<project_id>")
def api_intel_v2_server_roles(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if db:
        try:
            p = _paginate_params()
            stp = _scope_tool_params(db)
            ip = request.args.get("ip")
            role = request.args.get("role")
            result = db.query_server_roles(ip=ip, role=role,
                                           scope_id=stp["scope_id"], **p)
            if result.get("total", 0) > 0:
                return jsonify(result)
        except Exception:
            pass
    return jsonify(_empty_page())


@intel_v2.route("/api/intel/v2/screenshots/<project_id>")
def api_intel_v2_screenshots(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    stp = _scope_tool_params(db)
    ip = request.args.get("ip")
    tool = stp["tool"] or request.args.get("tool")
    try:
        result = db.query_screenshots(tool=tool, ip=ip,
                                      scope_id=stp["scope_id"], **p)
        if not result.get("items"):
            total = db._conn.execute(
                "SELECT COUNT(*) FROM screenshots").fetchone()[0]
            log.warning("screenshots: 0 items returned for %s "
                        "(tool=%s ip=%s scope_id=%s) but table has %d rows; "
                        "db_path=%s",
                        project_id[:8], tool, ip,
                        stp.get("scope_id"), total,
                        getattr(db, "db_path", "?"))
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/network-posture/<project_id>")
def api_intel_v2_network_posture(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if db:
        try:
            p = _paginate_params()
            search = _search_param()
            stp = _scope_tool_params(db)
            result = db.query_network_posture(search=search,
                                              tool=stp["tool"], **p)
            if result.get("total", 0) > 0:
                return jsonify(result)
        except Exception:
            pass
    return jsonify(_empty_page())


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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    status_code = request.args.get("status_code", type=int)
    source = request.args.get("source")
    try:
        result = db.query_structure_urls(
            status_code=status_code, source=source, search=search, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    url_id = request.args.get("url_id", type=int)
    try:
        result = db.query_structure_params(
            url_id=url_id, search=search, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    tool = request.args.get("tool")
    role = request.args.get("role")
    result_filter = request.args.get("result")
    try:
        result = db.query_access_matrix_entries(
            tool=tool, role=role, result=result_filter, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    tool = request.args.get("tool")
    try:
        result = db.query_auth_sessions(tool=tool, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    tool = request.args.get("tool")
    try:
        result = db.query_target_profiles(tool=tool, scope_id=stp["scope_id"], **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/cookies/<project_id>")
def api_intel_v2_cookies(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    p = _paginate_params()
    search = _search_param()
    stp = _scope_tool_params(db)
    tool = stp["tool"] or request.args.get("tool")
    try:
        result = db.query_cookies(search=search, tool=tool, **p)
        return jsonify(result)
    except AttributeError as e:
        log.warning("intel_v2 cookies AttributeError for %s: %s", project_id, e, exc_info=True)
        return jsonify(_empty_page(p["page"]))
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/webapp-intel/<project_id>")
def api_intel_v2_webapp_intel(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    tool = request.args.get("tool")
    try:
        result = db.query_webapp_intel(search=search, tool=tool, scope_id=stp["scope_id"], **p)
        return jsonify(result)
    except AttributeError as e:
        log.warning("intel_v2 webapp_intel AttributeError for %s: %s", project_id, e, exc_info=True)
        return jsonify(_empty_page(p["page"]))
    except Exception as e:
        return _err_500(e)


# ═══════════════════════════════════════════════════════════════════
#  API Intelligence  (Siphon)
# ═══════════════════════════════════════════════════════════════════

@intel_v2.route("/api/intel/v2/api-inventory/<project_id>")
def api_intel_v2_api_inventory(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_api_inventory(search=search, scope_id=stp["scope_id"], **p)
        return jsonify(result)
    except AttributeError as e:
        log.warning("intel_v2 api_inventory AttributeError for %s: %s", project_id, e, exc_info=True)
        return jsonify(_empty_page(p["page"]))
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_osint_domains(search=search, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_osint_emails(search=search, scope_id=stp["scope_id"], **p)
        return jsonify(result)
    except AttributeError as e:
        log.warning("intel_v2 osint_emails AttributeError for %s: %s", project_id, e, exc_info=True)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    email_id = request.args.get("email_id", type=int)
    try:
        result = db.query_osint_breaches(email_id=email_id, search=search, scope_id=stp["scope_id"], **p)
        return jsonify(result)
    except AttributeError as e:
        log.warning("intel_v2 osint_breaches AttributeError for %s: %s", project_id, e, exc_info=True)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_osint_people(search=search, scope_id=stp["scope_id"], **p)
        return jsonify(result)
    except AttributeError as e:
        log.warning("intel_v2 osint_people AttributeError for %s: %s", project_id, e, exc_info=True)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_osint_subdomains(search=search, scope_id=stp["scope_id"], **p)
        return jsonify(result)
    except AttributeError as e:
        log.warning("intel_v2 osint_subdomains AttributeError for %s: %s", project_id, e, exc_info=True)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    record_type = request.args.get("record_type")
    try:
        result = db.query_osint_dns(
            record_type=record_type, search=search, scope_id=stp["scope_id"], **p)
        return jsonify(result)
    except AttributeError as e:
        log.warning("intel_v2 osint_dns AttributeError for %s: %s", project_id, e, exc_info=True)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_osint_certificates(search=search, scope_id=stp["scope_id"], **p)
        return jsonify(result)
    except AttributeError as e:
        log.warning("intel_v2 osint_certificates AttributeError for %s: %s", project_id, e, exc_info=True)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    domain = request.args.get("domain")
    mime_type = request.args.get("mime_type")
    try:
        result = db.query_osint_wayback_urls(
            domain=domain, mime_type=mime_type, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    domain = request.args.get("domain")
    fuzzer = request.args.get("fuzzer")
    try:
        result = db.query_osint_typosquats(
            domain=domain, fuzzer=fuzzer, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    phone_type = request.args.get("phone_type")
    person_id = request.args.get("person_id", type=int)
    try:
        result = db.query_osint_phones(
            person_id=person_id, phone_type=phone_type, search=search, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    action = request.args.get("action")
    source_zone = request.args.get("source_zone")
    dest_zone = request.args.get("dest_zone")
    search = _search_param()
    try:
        result = db.query_firewall_rules(
            action=action, source_zone=source_zone, dest_zone=dest_zone,
            search=search, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    zone_type = request.args.get("zone_type")
    try:
        result = db.query_firewall_zones(zone_type=zone_type, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    status = request.args.get("status")
    framework = request.args.get("framework")
    search = _search_param()
    try:
        result = db.query_firewall_compliance(
            status=status, framework=framework, search=search, scope_id=stp["scope_id"], **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/firewall-config/<project_id>")
def api_intel_v2_firewall_config(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_firewall_config(search=search, scope_id=stp["scope_id"], **p)
        return jsonify(result)
    except AttributeError as e:
        log.warning("intel_v2 firewall_config AttributeError for %s: %s", project_id, e, exc_info=True)
        return jsonify(_empty_page(p["page"]))
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    resource_type = request.args.get("resource_type")
    region = request.args.get("region")
    search = _search_param()
    try:
        result = db.query_cloud_resources(
            resource_type=resource_type, region=region, search=search, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    policy_type = request.args.get("policy_type")
    search = _search_param()
    try:
        result = db.query_cloud_iam_policies(
            policy_type=policy_type, search=search, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    is_service_role = request.args.get("is_service_role")
    if is_service_role is not None:
        is_service_role = is_service_role.lower() in ("1", "true", "yes")
    try:
        result = db.query_cloud_iam_roles(
            is_service_role=is_service_role, search=search, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_cloud_services(search=search, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    src_ip = request.args.get("src_ip")
    dst_ip = request.args.get("dst_ip")
    protocol = request.args.get("protocol")
    try:
        result = db.query_traffic_conversations(
            src_ip=src_ip, dst_ip=dst_ip, protocol=protocol, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    category = request.args.get("category")
    search = _search_param()
    try:
        result = db.query_traffic_summary(
            category=category, search=search, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    db_type = request.args.get("db_type")
    host = request.args.get("host")
    search = _search_param()
    try:
        result = db.query_db_schemas(
            db_type=db_type, host=host, search=search, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    schema_id = request.args.get("schema_id", type=int)
    search = _search_param()
    try:
        result = db.query_db_tables(
            schema_id=schema_id, search=search, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    grantee = request.args.get("grantee")
    privilege_type = request.args.get("privilege_type")
    try:
        result = db.query_db_privileges(
            grantee=grantee, privilege_type=privilege_type, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    category = request.args.get("category")
    try:
        result = db.query_endpoint_software(
            search=search, category=category, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    status = request.args.get("status")
    category = request.args.get("category")
    try:
        result = db.query_endpoint_hardening(
            status=status, category=category, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    framework = request.args.get("framework")
    status = request.args.get("status")
    try:
        result = db.query_endpoint_compliance(
            framework=framework, status=status, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    check_category = request.args.get("check_category")
    search = _search_param()
    try:
        result = db.query_endpoint_ad(
            check_category=check_category, search=search, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_endpoint_browsers(search=search, scope_id=stp["scope_id"], **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/endpoint-overview/<project_id>")
def api_intel_v2_endpoint_overview(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_endpoint_overview(search=search, scope_id=stp["scope_id"], **p)
        return jsonify(result)
    except AttributeError as e:
        log.warning("intel_v2 endpoint_overview AttributeError for %s: %s", project_id, e, exc_info=True)
        return jsonify(_empty_page(p["page"]))
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/endpoint-network/<project_id>")
def api_intel_v2_endpoint_network(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_endpoint_network(search=search, scope_id=stp["scope_id"], **p)
        return jsonify(result)
    except AttributeError as e:
        log.warning("intel_v2 endpoint_network AttributeError for %s: %s", project_id, e, exc_info=True)
        return jsonify(_empty_page(p["page"]))
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/endpoint-disk/<project_id>")
def api_intel_v2_endpoint_disk(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_endpoint_disk(search=search, scope_id=stp["scope_id"], **p)
        return jsonify(result)
    except AttributeError as e:
        log.warning("intel_v2 endpoint_disk AttributeError for %s: %s", project_id, e, exc_info=True)
        return jsonify(_empty_page(p["page"]))
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/endpoint-hardware/<project_id>")
def api_intel_v2_endpoint_hardware(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_endpoint_hardware(search=search, scope_id=stp["scope_id"], **p)
        return jsonify(result)
    except AttributeError as e:
        log.warning("intel_v2 endpoint_hardware AttributeError for %s: %s", project_id, e, exc_info=True)
        return jsonify(_empty_page(p["page"]))
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    component_type = request.args.get("component_type")
    search = _search_param()
    try:
        result = db.query_mobile_components(
            component_type=component_type, search=search, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    protection_level = request.args.get("protection_level")
    try:
        result = db.query_mobile_permissions(
            protection_level=protection_level, search=search, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    encrypted = request.args.get("encrypted")
    if encrypted is not None:
        encrypted = encrypted.lower() in ("1", "true", "yes")
    search = _search_param()
    try:
        result = db.query_mobile_data_flows(
            encrypted=encrypted, search=search, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    host = request.args.get("host")
    search = _search_param()
    try:
        result = db.query_mobile_traffic(host=host, search=search, scope_id=stp["scope_id"], **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/mobile-hardening/<project_id>")
def api_intel_v2_mobile_hardening(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_mobile_hardening(search=search, scope_id=stp["scope_id"], **p)
        return jsonify(result)
    except AttributeError as e:
        log.warning("intel_v2 mobile_hardening AttributeError for %s: %s", project_id, e, exc_info=True)
        return jsonify(_empty_page(p["page"]))
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/mobile-domains/<project_id>")
def api_intel_v2_mobile_domains(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_mobile_domains(search=search, scope_id=stp["scope_id"], **p)
        return jsonify(result)
    except AttributeError as e:
        log.warning("intel_v2 mobile_domains AttributeError for %s: %s", project_id, e, exc_info=True)
        return jsonify(_empty_page(p["page"]))
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/mobile-emails/<project_id>")
def api_intel_v2_mobile_emails(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_mobile_emails(search=search, scope_id=stp["scope_id"], **p)
        return jsonify(result)
    except AttributeError as e:
        log.warning("intel_v2 mobile_emails AttributeError for %s: %s", project_id, e, exc_info=True)
        return jsonify(_empty_page(p["page"]))
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/mitm-cert/<project_id>")
def api_intel_v2_mitm_cert(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_mobile_mitm_certs(search=search, scope_id=stp["scope_id"], **p)
        return jsonify(result)
    except AttributeError as e:
        log.warning("intel_v2 mitm_cert AttributeError for %s: %s", project_id, e, exc_info=True)
        return jsonify(_empty_page(p["page"]))
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    string_type = request.args.get("string_type")
    search = _search_param()
    try:
        result = db.query_isotope_strings(
            string_type=string_type, search=search, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    secret_type = request.args.get("secret_type")
    search = _search_param()
    try:
        result = db.query_isotope_secrets(
            secret_type=secret_type, search=search, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    ioc_type = request.args.get("ioc_type")
    search = _search_param()
    try:
        result = db.query_isotope_iocs(
            ioc_type=ioc_type, search=search, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    category = request.args.get("category")
    search = _search_param()
    try:
        result = db.query_isotope_properties(
            category=category, search=search, scope_id=stp["scope_id"], **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/isotope-entropy/<project_id>")
def api_intel_v2_isotope_entropy(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_isotope_entropy(search=search, scope_id=stp["scope_id"], **p)
        return jsonify(result)
    except AttributeError as e:
        log.warning("intel_v2 isotope_entropy AttributeError for %s: %s", project_id, e, exc_info=True)
        return jsonify(_empty_page(p["page"]))
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/isotope-contents/<project_id>")
def api_intel_v2_isotope_contents(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_isotope_contents(search=search, scope_id=stp["scope_id"], **p)
        return jsonify(result)
    except AttributeError as e:
        log.warning("intel_v2 isotope_contents AttributeError for %s: %s", project_id, e, exc_info=True)
        return jsonify(_empty_page(p["page"]))
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/isotope-code/<project_id>")
def api_intel_v2_isotope_code(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_isotope_code(search=search, scope_id=stp["scope_id"], **p)
        return jsonify(result)
    except AttributeError as e:
        log.warning("intel_v2 isotope_code AttributeError for %s: %s", project_id, e, exc_info=True)
        return jsonify(_empty_page(p["page"]))
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/isotope-metadata/<project_id>")
def api_intel_v2_isotope_metadata(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_isotope_metadata(search=search, scope_id=stp["scope_id"], **p)
        return jsonify(result)
    except AttributeError as e:
        log.warning("intel_v2 isotope_metadata AttributeError for %s: %s", project_id, e, exc_info=True)
        return jsonify(_empty_page(p["page"]))
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/isotope-binary/<project_id>")
def api_intel_v2_isotope_binary(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    stp = _scope_tool_params(db)
    p = _paginate_params()
    search = _search_param()
    try:
        result = db.query_isotope_binary(search=search, scope_id=stp["scope_id"], **p)
        return jsonify(result)
    except AttributeError as e:
        log.warning("intel_v2 isotope_binary AttributeError for %s: %s", project_id, e, exc_info=True)
        return jsonify(_empty_page(p["page"]))
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    status = request.args.get("status")
    tool = request.args.get("tool")
    try:
        result = db.get_action_items(status=status, tool=tool, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    tool = request.args.get("tool")
    extension = request.args.get("extension")
    search = _search_param()
    try:
        result = db.query_output_files(
            tool=tool, extension=extension, search=search, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    level = request.args.get("level")
    tool = request.args.get("tool")
    from_ts = request.args.get("from_ts")
    to_ts = request.args.get("to_ts")
    try:
        result = db.query_crucible_logs(
            level=level, tool=tool, from_ts=from_ts, to_ts=to_ts, scope_id=stp["scope_id"], **p)
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
    stp = _scope_tool_params(db)
    p = _paginate_params()
    level = request.args.get("level")
    tool = request.args.get("tool")
    from_ts = request.args.get("from_ts")
    to_ts = request.args.get("to_ts")
    try:
        result = db.query_crucible_errors(
            level=level, tool=tool, from_ts=from_ts, to_ts=to_ts, scope_id=stp["scope_id"], **p)
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
#  Domain Intelligence  (SS3 internal)
# ═══════════════════════════════════════════════════════════════════

@intel_v2.route("/api/intel/v2/domain-intel/<project_id>")
def api_intel_v2_domain_intel(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if db:
        try:
            stp = _scope_tool_params(db)
            p = _paginate_params()
            domain = request.args.get("domain")
            ip = request.args.get("ip")
            is_dc = request.args.get("is_dc")
            kw = {}
            if domain:
                kw["domain_name"] = domain
            if ip:
                kw["source_ip"] = ip
            if is_dc is not None:
                kw["is_dc"] = is_dc.lower() in ("1", "true", "yes")
            result = db.query_domain_intel(**kw, scope_id=stp["scope_id"], **p)
            if result.get("total", 0) > 0:
                return jsonify(result)
        except Exception:
            pass
    return jsonify(_empty_page())


@intel_v2.route("/api/intel/v2/domain-overview/<project_id>")
def api_intel_v2_domain_overview(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if db:
        try:
            fn = getattr(db, "query_domain_intel_aggregated", None)
            if fn:
                result = fn()
                if result.get("summary", {}).get("domains_discovered", 0) > 0:
                    return jsonify(result)
        except Exception:
            pass
    return jsonify({"summary": {"domains_discovered": 0,
                                "domain_controllers": 0,
                                "member_hosts": 0,
                                "sources_used": []},
                    "domains": []})


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
            "isotope_entropy": _safe_table_count(db, "isotope_entropy"),
            "isotope_contents": _safe_table_count(db, "isotope_contents"),
            "isotope_code": _safe_table_count(db, "isotope_code"),
            "isotope_metadata": _safe_table_count(db, "isotope_metadata"),
            "isotope_binary": _safe_table_count(db, "isotope_binary"),
            # Network posture (SS3)
            "network_posture": _safe_table_count(db, "network_posture"),
            # Domain intelligence (SS3)
            "domain_intel": _safe_count(db, "count_domain_intel"),
            # WebApp / API
            "cookies": _safe_table_count(db, "cookies"),
            "webapp_intel": _safe_table_count(db, "webapp_intel"),
            "api_inventory": _safe_table_count(db, "api_inventory"),
            # Firewall config (Bastion)
            "firewall_config": _safe_table_count(db, "firewall_config"),
            # Mobile extras (Quill)
            "mobile_hardening": _safe_table_count(db, "mobile_hardening"),
            "mobile_domains": _safe_table_count(db, "mobile_domains"),
            "mobile_emails": _safe_table_count(db, "mobile_emails"),
            "mobile_mitm_certs": _safe_table_count(db, "mobile_mitm_certs"),
            # Endpoint extras (Dredge)
            "endpoint_overview": _safe_table_count(db, "endpoint_overview"),
            "endpoint_network": _safe_table_count(db, "endpoint_network"),
            "endpoint_disk": _safe_table_count(db, "endpoint_disk"),
            "endpoint_hardware": _safe_table_count(db, "endpoint_hardware"),
            # Software vulnerability cross-reference
            "software_vulns": _safe_count(db, "count_software_vulns"),
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


# ═══════════════════════════════════════════════════════════════════
#  Re-ingestion  (manual trigger for migrating JSON → DB)
# ═══════════════════════════════════════════════════════════════════

@intel_v2.route("/api/intel/v2/reingest/<project_id>", methods=["POST"])
def api_intel_v2_reingest(project_id):
    """Trigger full re-ingestion of tool JSON files into FindingsDB.

    Use this to populate the DB for engagements that ran before the
    DB-first pipeline was deployed, or after clearing/recreating the DB.
    """
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return _err_503()
    try:
        from services.intel_ingestion import ingest_all
        ingest_all(
            db,
            project.get("project_dir", "") or project.get("engagement_dir", ""),
            tool_dirs=project.get("tool_dirs"),
            scope_tool_dirs=project.get("scope_tool_dirs"),
        )
        return jsonify({"ok": True, "message": "Re-ingestion complete"})
    except Exception as e:
        return _err_500(e)


# ═══════════════════════════════════════════════════════════════════════════
#  Wireless Intelligence (Aether wifi-* tabs)
# ═══════════════════════════════════════════════════════════════════════════

@intel_v2.route("/api/intel/v2/wifi-aps/<pid>")
def api_wifi_aps(pid):
    project = _get_project(pid)
    if not project:
        return _empty_page()
    db = _get_db(project)
    if not db:
        return _empty_page()
    p = _paginate_params()
    search = _search_param()
    sort = request.args.get("sort", "signal_dbm")
    order = request.args.get("order", "desc")
    try:
        return jsonify(db.query_wireless_aps(
            page=p["page"], per_page=p["per_page"],
            search=search, sort=sort, order=order))
    except AttributeError:
        log.warning("api_wifi_aps: DB missing query_wireless_aps", exc_info=True)
        return _empty_page()


@intel_v2.route("/api/intel/v2/wifi-clients/<pid>")
def api_wifi_clients(pid):
    project = _get_project(pid)
    if not project:
        return _empty_page()
    db = _get_db(project)
    if not db:
        return _empty_page()
    p = _paginate_params()
    search = _search_param()
    sort = request.args.get("sort", "last_seen")
    order = request.args.get("order", "desc")
    try:
        return jsonify(db.query_wireless_clients(
            page=p["page"], per_page=p["per_page"],
            search=search, sort=sort, order=order))
    except AttributeError:
        log.warning("api_wifi_clients: DB missing query_wireless_clients", exc_info=True)
        return _empty_page()


@intel_v2.route("/api/intel/v2/wifi-encryption/<pid>")
def api_wifi_encryption(pid):
    project = _get_project(pid)
    if not project:
        return jsonify({})
    db = _get_db(project)
    if not db:
        return jsonify({})
    try:
        return jsonify(db.query_wireless_encryption())
    except AttributeError:
        log.warning("api_wifi_encryption: DB missing query_wireless_encryption", exc_info=True)
        return jsonify({})


@intel_v2.route("/api/intel/v2/wifi-vendors/<pid>")
def api_wifi_vendors(pid):
    project = _get_project(pid)
    if not project:
        return jsonify({})
    db = _get_db(project)
    if not db:
        return jsonify({})
    try:
        return jsonify(db.query_wireless_vendors())
    except AttributeError:
        log.warning("api_wifi_vendors: DB missing query_wireless_vendors", exc_info=True)
        return jsonify({})


@intel_v2.route("/api/intel/v2/wifi-channels/<pid>")
def api_wifi_channels(pid):
    project = _get_project(pid)
    if not project:
        return jsonify({})
    db = _get_db(project)
    if not db:
        return jsonify({})
    try:
        return jsonify(db.query_wireless_channels())
    except AttributeError:
        log.warning("api_wifi_channels: DB missing query_wireless_channels", exc_info=True)
        return jsonify({})


@intel_v2.route("/api/intel/v2/wifi-probes/<pid>")
def api_wifi_probes(pid):
    project = _get_project(pid)
    if not project:
        return _empty_page()
    db = _get_db(project)
    if not db:
        return _empty_page()
    p = _paginate_params()
    search = _search_param()
    sort = request.args.get("sort", "client_count")
    order = request.args.get("order", "desc")
    try:
        return jsonify(db.query_wireless_probes(
            page=p["page"], per_page=p["per_page"],
            search=search, sort=sort, order=order))
    except AttributeError:
        log.warning("api_wifi_probes: DB missing query_wireless_probes", exc_info=True)
        return _empty_page()


@intel_v2.route("/api/intel/v2/wifi-wps/<pid>")
def api_wifi_wps(pid):
    project = _get_project(pid)
    if not project:
        return _empty_page()
    db = _get_db(project)
    if not db:
        return _empty_page()
    p = _paginate_params()
    search = _search_param()
    sort = request.args.get("sort", "bssid")
    order = request.args.get("order", "asc")
    try:
        return jsonify(db.query_wireless_wps(
            page=p["page"], per_page=p["per_page"],
            search=search, sort=sort, order=order))
    except AttributeError:
        log.warning("api_wifi_wps: DB missing query_wireless_wps", exc_info=True)
        return _empty_page()


@intel_v2.route("/api/intel/v2/wifi-firmware/<pid>")
def api_wifi_firmware(pid):
    project = _get_project(pid)
    if not project:
        return jsonify({"matches": []})
    db = _get_db(project)
    if not db:
        return jsonify({"matches": []})
    try:
        return jsonify(db.query_wireless_firmware())
    except AttributeError:
        log.warning("api_wifi_firmware: DB missing query_wireless_firmware", exc_info=True)
        return jsonify({"matches": []})


# ═══════════════════════════════════════════════════════════════════════════
#  Intelligence View Endpoints — structured aggregated data for JS renderers
# ═══════════════════════════════════════════════════════════════════════════

@intel_v2.route("/api/intel/v2/structure-view/<project_id>")
def api_intel_v2_structure_view(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    idb = _get_idb(project)
    if not idb:
        log.warning("structure-view: idb=None for %s", project_id)
        return jsonify({"structure_map": {}, "api_map": {}})
    try:
        stp = _scope_tool_params(_get_db(project) or idb)
        result = idb.query_structure_tree(scope_id=stp.get("scope_id"))
        sm = result.get("structure_map", {})
        n = sum(len(v.get("paths", {})) for v in sm.values()) if sm else 0
        log.info("structure-view: scope_id=%s targets=%d paths=%d",
                 stp.get("scope_id"), len(sm), n)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/access-view/<project_id>")
def api_intel_v2_access_view(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    idb = _get_idb(project)
    if not idb:
        return jsonify({"access_matrix": {}})
    try:
        stp = _scope_tool_params(_get_db(project) or idb)
        return jsonify(idb.query_access_matrix_view(scope_id=stp.get("scope_id")))
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/auth-view/<project_id>")
def api_intel_v2_auth_view(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    idb = _get_idb(project)
    if not idb:
        return jsonify({"auth_status": []})
    try:
        stp = _scope_tool_params(_get_db(project) or idb)
        return jsonify(idb.query_auth_view(scope_id=stp.get("scope_id")))
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/cookies-view/<project_id>")
def api_intel_v2_cookies_view(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    idb = _get_idb(project)
    if not idb:
        return jsonify({"cookies": {"all": [], "site_wide": [], "per_role": {}, "stats": {}}})
    try:
        stp = _scope_tool_params(_get_db(project) or idb)
        return jsonify(idb.query_cookies_view(scope_id=stp.get("scope_id")))
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/webapp-view/<project_id>")
def api_intel_v2_webapp_view(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    idb = _get_idb(project)
    if not idb:
        return jsonify({"dns": None, "infrastructure": {}, "target_profile": {}})
    try:
        stp = _scope_tool_params(_get_db(project) or idb)
        return jsonify(idb.query_webapp_view(scope_id=stp.get("scope_id")))
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/osint-domains-view/<project_id>")
def api_intel_v2_osint_domains_view(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    idb = _get_idb(project)
    if not idb:
        return jsonify({"osint_domains": {}})
    try:
        return jsonify(idb.query_osint_domains_view())
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/osint-dns-view/<project_id>")
def api_intel_v2_osint_dns_view(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    idb = _get_idb(project)
    if not idb:
        return jsonify({"osint_dns": {}})
    try:
        return jsonify(idb.query_osint_dns_grouped())
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/posture-view/<project_id>")
def api_intel_v2_posture_view(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    idb = _get_idb(project)
    if not idb:
        return jsonify({"subnets": [], "subnet_count": 0, "segmented_count": 0})
    try:
        stp = _scope_tool_params(_get_db(project) or idb)
        return jsonify(idb.query_network_posture_view(scope_id=stp.get("scope_id")))
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/hostname-view/<project_id>")
def api_intel_v2_hostname_view(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    idb = _get_idb(project)
    if not idb:
        return jsonify({"hosts": [], "summary": {}})
    try:
        stp = _scope_tool_params(_get_db(project) or idb)
        kind = request.args.get("kind")
        return jsonify(idb.query_hostname_intel_view(
            scope_id=stp.get("scope_id"), kind=kind))
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/roles-view/<project_id>")
def api_intel_v2_roles_view(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    idb = _get_idb(project)
    if not idb:
        return jsonify({"roles": [], "summary": {"role_counts": {}}})
    try:
        stp = _scope_tool_params(_get_db(project) or idb)
        return jsonify(idb.query_server_roles_view(scope_id=stp.get("scope_id")))
    except Exception as e:
        return _err_500(e)


# ═══════════════════════════════════════════════════════════════════════════
#  Survey Location CRUD
# ═══════════════════════════════════════════════════════════════════════════

@intel_v2.route("/api/intel/v2/survey-locations/<pid>", methods=["GET"])
def api_survey_locations(pid):
    project = _get_project(pid)
    if not project:
        return jsonify({"items": [], "total": 0})
    db = _get_db(project)
    if not db:
        return jsonify({"items": [], "total": 0})
    try:
        locations = db.list_survey_locations()
    except AttributeError:
        log.warning("api_survey_locations: DB missing list_survey_locations", exc_info=True)
        return jsonify({"items": [], "total": 0})
    return jsonify({"items": locations, "total": len(locations)})


@intel_v2.route("/api/intel/v2/survey-locations/<pid>", methods=["POST"])
def api_survey_location_create(pid):
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Location name required"}), 400
    project = _get_project(pid)
    if not project:
        return jsonify({"error": "Project not found"}), 404
    db = _get_db(project)
    if not db:
        return jsonify({"error": "DB unavailable"}), 500
    try:
        loc_id = db.ensure_survey_location(name)
    except Exception as exc:
        log.warning("api_survey_location_create: %s", exc, exc_info=True)
        return jsonify({"error": str(exc)}), 500
    return jsonify({"ok": True, "id": loc_id, "name": name})


@intel_v2.route("/api/intel/v2/survey-locations/<pid>/<int:loc_id>",
                methods=["DELETE"])
def api_survey_location_delete(pid, loc_id):
    project = _get_project(pid)
    if not project:
        return jsonify({"error": "Project not found"}), 404
    db = _get_db(project)
    if not db:
        return jsonify({"error": "DB unavailable"}), 500
    try:
        db.delete_survey_location(loc_id)
    except Exception as exc:
        log.warning("api_survey_location_delete: %s", exc, exc_info=True)
        return jsonify({"error": str(exc)}), 500
    return jsonify({"ok": True})


# ═══════════════════════════════════════════════════════════════════════════
#  Survey AP queries
# ═══════════════════════════════════════════════════════════════════════════

@intel_v2.route("/api/intel/v2/survey-aps/<pid>")
def api_survey_aps(pid):
    project = _get_project(pid)
    if not project:
        return _empty_page()
    db = _get_db(project)
    if not db:
        return _empty_page()
    loc_id = request.args.get("location_id", type=int)
    if not loc_id:
        return _empty_page()
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 200, type=int)
    search = request.args.get("search", "")
    sort = request.args.get("sort", "signal")
    order = request.args.get("order", "desc")
    try:
        return jsonify(db.query_survey_aps(
            loc_id, page=page, per_page=per_page,
            search=search, sort=sort, order=order))
    except AttributeError:
        log.warning("api_survey_aps: DB missing query_survey_aps", exc_info=True)
        return _empty_page()


# ═══════════════════════════════════════════════════════════════════════════
#  Rogue AP queries + classification
# ═══════════════════════════════════════════════════════════════════════════

@intel_v2.route("/api/intel/v2/survey-rogues/<pid>")
def api_survey_rogues(pid):
    project = _get_project(pid)
    if not project:
        return _empty_page()
    db = _get_db(project)
    if not db:
        return _empty_page()
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 200, type=int)
    search = request.args.get("search", "")
    sort = request.args.get("sort", "best_signal")
    order = request.args.get("order", "desc")
    try:
        return jsonify(db.query_survey_rogues(
            page=page, per_page=per_page,
            search=search, sort=sort, order=order))
    except AttributeError:
        log.warning("api_survey_rogues: DB missing query_survey_rogues", exc_info=True)
        return _empty_page()


@intel_v2.route("/api/intel/v2/survey-rogues/<pid>/classify",
                methods=["POST"])
def api_survey_rogue_classify(pid):
    body = request.get_json(silent=True) or {}
    bssid = (body.get("bssid") or "").strip()
    ssid = (body.get("ssid") or "").strip()
    classification = (body.get("classification") or "").strip().lower()
    valid = ("known", "nearby", "rogue", "uncategorized")
    if not bssid or classification not in valid:
        return jsonify({"error": "bssid and valid classification required"}), 400
    project = _get_project(pid)
    if not project:
        return jsonify({"error": "Project not found"}), 404
    db = _get_db(project)
    if not db:
        return jsonify({"error": "DB unavailable"}), 500
    try:
        db.classify_survey_rogue(bssid, ssid, classification)
    except Exception as exc:
        log.warning("api_survey_rogue_classify: %s", exc, exc_info=True)
        return jsonify({"error": str(exc)}), 500
    if classification == "rogue":
        _emit_rogue_finding(pid, db, bssid, ssid)
    return jsonify({"ok": True})


def _emit_rogue_finding(pid, db, bssid, ssid):
    """Auto-generate a HIGH finding when an AP is classified as ROGUE."""
    try:
        from flask import current_app
        import uuid
        from datetime import datetime
        finding_data = {
            "id": str(uuid.uuid4()),
            "tool": "aether",
            "title": "Rogue Access Point: %s" % (ssid or bssid),
            "risk": "HIGH",
            "severity": "HIGH",
            "description": (
                "An unauthorized wireless access point was detected during "
                "survey. BSSID: %s, SSID: %s. "
                "This AP is not part of the authorized wireless "
                "infrastructure and may represent a security threat."
                % (bssid, ssid or "(hidden)")
            ),
            "remediation": (
                "Investigate the rogue access point. Locate and disable the "
                "unauthorized device. Implement wireless intrusion "
                "detection/prevention (WIDS/WIPS) to detect future rogue APs."
            ),
            "ip": bssid,
            "hostname": ssid,
            "port": 0,
            "service": "wifi",
            "sources": "Aether Survey",
            "affected": ("%s (%s)" % (ssid, bssid)) if ssid else bssid,
            "datetime": datetime.now().isoformat(),
            "ssid": ssid,
            "bssid": bssid,
            "catalogue_id": "AE-ROGUE-001",
            "exploitdb": False,
            "metasploit": False,
        }
        db.insert_finding(finding_data)
        socketio = current_app.extensions.get("socketio")
        if socketio:
            socketio.emit("tool_finding", finding_data,
                          room="project_%s" % pid)
    except Exception as exc:
        log.warning("_emit_rogue_finding: %s", exc, exc_info=True)


# ═══════════════════════════════════════════════════════════════════════════
#  Survey start / stop / status
# ═══════════════════════════════════════════════════════════════════════════

@intel_v2.route("/api/intel/v2/survey/start/<pid>", methods=["POST"])
def api_survey_start(pid):
    body = request.get_json(silent=True) or {}
    location = (body.get("location") or "").strip()
    interface = (body.get("interface") or "").strip()
    if not location or not interface:
        return jsonify({"error": "location and interface required"}), 400
    from flask import current_app
    pm = current_app.extensions.get("process_manager")
    if not pm:
        return jsonify({"error": "Process manager unavailable"}), 500
    if pm.is_running(pid, "aether"):
        return jsonify({"error": "Aether is already running"}), 409
    project = _get_project(pid)
    if not project:
        return jsonify({"error": "Project not found"}), 404
    from models.settings import load_settings
    settings = load_settings(project.get("project_dir", ""), "aether")
    settings["interface"] = interface
    ok = pm.launch(
        pid, "aether",
        project=project, settings=settings,
        extra_args=["--survey", "--location", location],
    )
    if not ok:
        return jsonify({"error": "Failed to launch (may already be running)"}), 409
    return jsonify({"ok": True})


@intel_v2.route("/api/intel/v2/survey/stop/<pid>", methods=["POST"])
def api_survey_stop(pid):
    from flask import current_app
    pm = current_app.extensions.get("process_manager")
    if not pm:
        return jsonify({"error": "Process manager unavailable"}), 500
    killed = pm.kill(pid, "aether")
    return jsonify({"ok": killed})


@intel_v2.route("/api/intel/v2/survey/status/<pid>")
def api_survey_status(pid):
    from flask import current_app
    pm = current_app.extensions.get("process_manager")
    if not pm:
        return jsonify({"running": False})
    running = pm.is_running(pid, "aether")
    return jsonify({"running": running})


# ═══════════════════════════════════════════════════════════════════
#  Software Vulnerability Cross-Reference
# ═══════════════════════════════════════════════════════════════════

@intel_v2.route("/api/intel/v2/software-vulns/<project_id>")
def api_intel_v2_software_vulns(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return jsonify(_empty_page(1))
    p = _paginate_params()
    search = _search_param()
    try:
        fn = getattr(db, "query_software_vulns", None)
        if not fn:
            return jsonify(_empty_page(p["page"]))
        result = fn(search=search, **p)
        return jsonify(result)
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/cve-crossref/<project_id>")
def api_intel_v2_cve_crossref(project_id):
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return jsonify({"summary": {}, "software": [], "details": []})
    try:
        fn = getattr(db, "query_software_cve_crossref", None)
        if not fn:
            return jsonify({"summary": {}, "software": [], "details": []})
        return jsonify(fn())
    except Exception as e:
        return _err_500(e)


@intel_v2.route("/api/intel/v2/enrich-searchsploit/<project_id>",
                methods=["POST"])
def api_intel_v2_enrich_searchsploit(project_id):
    import shutil
    import subprocess
    ssploit = shutil.which("searchsploit")
    if not ssploit:
        return jsonify({"error": "searchsploit not found on this system"}), 400
    project = _get_project(project_id)
    if not project:
        return _err_404()
    db = _get_db(project)
    if not db:
        return jsonify({"error": "Database not available"}), 503
    try:
        sw_rows = db._conn.execute("""
            SELECT DISTINCT s.id, s.product, s.vendor, hs.version
            FROM host_software hs
            JOIN software s ON s.id = hs.software_id
            WHERE s.product IS NOT NULL AND s.product != ''
        """).fetchall()
        if not sw_rows:
            return jsonify({"enriched": 0, "message": "No software to enrich"})
        seen = set()
        results = []
        for sw_id, product, vendor, version in sw_rows:
            term = product.strip()
            if version and version.strip():
                term += " " + version.strip().split()[0]
            if term in seen:
                continue
            seen.add(term)
            try:
                proc = subprocess.run(
                    [ssploit, "--json", "-t", term],
                    capture_output=True, text=True, timeout=15)
                if proc.returncode != 0 or not proc.stdout.strip():
                    continue
                data = json.loads(proc.stdout)
                exploits = data.get("RESULTS_EXPLOIT", [])
                for ex in exploits[:10]:
                    title = ex.get("Title", "").strip()
                    edb_id = ex.get("EDB-ID", "")
                    path = ex.get("Path", "")
                    results.append({
                        "software_id": sw_id,
                        "title": title,
                        "edb_id": str(edb_id) if edb_id else "",
                        "version": version or "",
                        "risk": "HIGH" if any(k in title.lower()
                            for k in ("remote code", "rce", "injection",
                                      "overflow", "privilege")) else "MEDIUM",
                        "source": "searchsploit",
                        "url": (f"https://www.exploit-db.com/exploits/{edb_id}"
                                if edb_id else ""),
                        "description": f"Exploit: {path}" if path else title,
                    })
            except (subprocess.TimeoutExpired, json.JSONDecodeError):
                continue
        if results:
            fn = getattr(db, "bulk_insert_software_vulns", None)
            if fn:
                fn(results)
        return jsonify({
            "enriched": len(results),
            "products_checked": len(seen),
            "message": f"Found {len(results)} potential exploits "
                       f"across {len(seen)} products",
        })
    except Exception as e:
        return _err_500(e)
