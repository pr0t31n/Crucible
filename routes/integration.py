"""Integration API routes — Nexus status, Arbiter projects, external orchestration."""

from flask import Blueprint, request, jsonify, session
from config import VERSION, APP_NAME, PORT, TOOLS
from models.project import list_projects
from routes._helpers import require_project

integration_bp = Blueprint("integration", __name__)


@integration_bp.route("/api/nexus-status")
def nexus_status():
    """Public endpoint for Nexus hub to probe this instance."""
    return jsonify({
        "app": APP_NAME,
        "version": VERSION,
        "status": "online",
        "port": PORT,
        "tools": list(TOOLS.keys()),
    })


@integration_bp.route("/api/arbiter-projects")
def arbiter_projects():
    """Public endpoint listing projects for Arbiter catalogue enrichment."""
    projects = list_projects()
    return jsonify({
        "projects": [
            {"id": p.get("id"), "name": p.get("name"),
             "client": p.get("client_name"), "created": p.get("created")}
            for p in projects
        ]
    })


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


@integration_bp.route("/api/project-template")
def project_template():
    """Return the project creation template (for automation)."""
    return jsonify({
        "template": {
            "name": "", "client_name": "", "client_short": "",
            "scope": "external",
            "tools": list(TOOLS.keys()),
            "consultant": {"name": "", "title": "", "email": ""},
            "client_poc": {"name": "", "phone": "", "email": ""},
            "start_date": "", "end_date": "",
            "scope_definition": {
                "network_cidrs": [], "target_urls": [], "api_specs": [],
                "wireless_ssids": [], "db_targets": [], "exclusions": [],
            },
        }
    })


@integration_bp.route("/api/execute-project", methods=["POST"])
def execute_project():
    """Create and auto-launch a project from external orchestration."""
    if not session.get("authenticated"):
        return jsonify({"error": "Authentication required"}), 401
    data = request.get_json(silent=True) or {}
    from models.project import create_project
    pid, meta = create_project(data)
    return jsonify({"ok": True, "project_id": pid, "project": meta})
