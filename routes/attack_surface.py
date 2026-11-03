"""Attack Surface API routes."""

import logging
from flask import Blueprint, request, jsonify
from routes._helpers import require_project, get_ext

attack_surface_bp = Blueprint("attack_surface", __name__)
log = logging.getLogger("crucible.routes.attack_surface")


def _engine():
    return get_ext("findings_engine")


@attack_surface_bp.route("/api/attack-surface/<project_id>")
def api_attack_surface(project_id):
    """Per-project host inventory with port/service/severity breakdown."""
    project = require_project(project_id)
    fe = _engine()
    if not fe:
        return jsonify({"error": "Findings engine not available"}), 503

    sort = request.args.get("sort", "severity")
    filter_risk = request.args.get("filter_risk")

    from services.attack_surface import build_surface
    result = build_surface(fe, project_id, project,
                           sort=sort, filter_risk=filter_risk)
    return jsonify(result)
