"""Integration API routes — Nexus status, external orchestration."""

from flask import Blueprint, request, jsonify, session
from routes._helpers import require_project

integration_bp = Blueprint("integration", __name__)


@integration_bp.route("/api/nexus-status")
def nexus_status():
    """Public endpoint for Nexus hub to probe this instance."""
    return jsonify({"status": "online"})


@integration_bp.route("/api/projects/<project_id>/status")
def project_status(project_id):
    """Public endpoint for external status polling."""
    project = require_project(project_id)
    return jsonify({
        "id": project_id,
        "name": project.get("name"),
        "tools": project.get("tools", []),
        "created": project.get("created"),
    })
