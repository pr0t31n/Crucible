"""OOB (Out-of-Band) callback API routes for Crucible v2."""

import logging

from flask import Blueprint, request, jsonify, current_app

from routes._helpers import require_project

log = logging.getLogger("crucible.routes.oob")

oob_bp = Blueprint("oob", __name__)


def _get_managers() -> dict:
    mgrs = current_app.config.get("OOB_MANAGERS")
    if mgrs is None:
        mgrs = {}
        current_app.config["OOB_MANAGERS"] = mgrs
    return mgrs


def _get_manager(project_id: str):
    return _get_managers().get(project_id)


def _find_manager_for_scan(scan_id: str):
    for pid, mgr in _get_managers().items():
        hits = mgr.server._registry
        with mgr.server._lock:
            if scan_id in hits:
                return mgr
    return None


@oob_bp.route("/api/oob/setup", methods=["POST"])
def api_oob_setup():
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    if not project_id:
        return jsonify({"error": "project_id required"}), 400

    if project_id != "wizard":
        require_project(project_id)

    mode = data.get("mode", "local")
    if mode not in ("local", "public"):
        return jsonify({"error": "mode must be 'local' or 'public'"}), 400

    port = int(data.get("port", 9999))

    managers = _get_managers()
    mgr = managers.get(project_id)
    if mgr and mgr.server.is_running:
        mgr.teardown()

    from services.oob_server import OOBManager
    mgr = OOBManager()
    managers[project_id] = mgr

    try:
        result = mgr.setup(mode, port)
        return jsonify(result)
    except Exception as exc:
        log.error("OOB setup failed for %s: %s", project_id, exc)
        return jsonify({"error": str(exc)}), 500


@oob_bp.route("/api/oob/verify", methods=["POST"])
def api_oob_verify():
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    if not project_id:
        return jsonify({"error": "project_id required"}), 400

    mgr = _get_manager(project_id)
    if not mgr:
        return jsonify({"error": "No OOB server running for project"}), 404

    proxy_settings = None
    project = None
    if project_id != "wizard":
        project = require_project(project_id)
    proj_dir = (project or {}).get("project_dir", "")
    if proj_dir:
        try:
            from models.settings import load_settings
            fr_settings = load_settings(proj_dir, "fr")
            proxy_addr = fr_settings.get("proxy", "")
            if proxy_addr:
                proxy_settings = {
                    "address": proxy_addr,
                    "type": fr_settings.get("proxy_type", "http"),
                    "dns_over_proxy": fr_settings.get("dns_over_proxy", False),
                }
        except Exception:
            pass

    try:
        result = mgr.verify(proxy_settings=proxy_settings)
        return jsonify(result)
    except Exception as exc:
        log.error("OOB verify failed for %s: %s", project_id, exc)
        return jsonify({"error": str(exc)}), 500


@oob_bp.route("/api/oob/register-tokens", methods=["POST"])
def api_oob_register_tokens():
    data = request.get_json(silent=True) or {}
    scan_id = data.get("scan_id")
    tokens = data.get("tokens", [])
    if not scan_id or not tokens:
        return jsonify({"error": "scan_id and tokens required"}), 400

    project_id = data.get("project_id")
    mgr = None
    if project_id:
        mgr = _get_manager(project_id)
    if not mgr:
        managers = _get_managers()
        for pid, m in managers.items():
            if m.server.is_running:
                mgr = m
                break

    if not mgr:
        return jsonify({"error": "No OOB server running"}), 404

    mgr.register_tokens(scan_id, tokens)
    return jsonify({"status": "ok", "count": len(tokens)})


@oob_bp.route("/api/oob/hits/<scan_id>", methods=["GET"])
def api_oob_hits(scan_id):
    mgr = _find_manager_for_scan(scan_id)
    if not mgr:
        managers = _get_managers()
        for pid, m in managers.items():
            if m.server.is_running:
                hits = m.get_hits(scan_id)
                return jsonify({"hits": hits})
        return jsonify({"hits": []})

    hits = mgr.get_hits(scan_id)
    return jsonify({"hits": hits})


@oob_bp.route("/api/oob/scan/<scan_id>", methods=["DELETE"])
def api_oob_clear_scan(scan_id):
    for pid, mgr in _get_managers().items():
        mgr.clear_scan(scan_id)
    return jsonify({"status": "ok"})


@oob_bp.route("/api/oob/teardown", methods=["POST"])
def api_oob_teardown():
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    if not project_id:
        return jsonify({"error": "project_id required"}), 400

    managers = _get_managers()
    mgr = managers.pop(project_id, None)
    if mgr:
        try:
            result = mgr.teardown()
            return jsonify(result)
        except Exception as exc:
            log.error("OOB teardown failed for %s: %s", project_id, exc)
            return jsonify({"error": str(exc)}), 500

    return jsonify({"status": "ok"})


@oob_bp.route("/api/oob/status/<project_id>", methods=["GET"])
def api_oob_status(project_id):
    mgr = _get_manager(project_id)
    if not mgr:
        return jsonify({"running": False})
    return jsonify(mgr.get_status())
