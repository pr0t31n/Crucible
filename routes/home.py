"""Home routes — index, project list, wizard entry."""

import logging
from pathlib import Path

from flask import Blueprint, render_template, redirect, url_for, jsonify
from models.project import list_projects, get_project
import config

home_bp = Blueprint("home", __name__)
log = logging.getLogger("crucible.routes.home")


@home_bp.route("/")
def index():
    projects = list_projects()
    return render_template("index.html", projects=projects)


@home_bp.route("/new_project")
def new_project_wizard():
    return render_template("wizard.html", project=None, edit_mode=False)


@home_bp.route("/edit_project/<project_id>")
def edit_project(project_id):
    project = get_project(project_id)
    if not project:
        return redirect(url_for("home.index"))
    return render_template("wizard.html", project=project, edit_mode=True)


# ── FindingsDB dependency & conversion endpoints ───────────

@home_bp.route("/api/findings-db-status")
def api_findings_db_status():
    return jsonify({"available": config.FINDINGS_DB_AVAILABLE})


@home_bp.route("/api/project-db-status/<project_id>")
def api_project_db_status(project_id):
    project = get_project(project_id)
    if not project:
        return jsonify({"error": "not found"}), 404
    eng_dir = project.get("engagement_dir", project.get("project_dir", ""))
    has_db = bool(eng_dir and Path(eng_dir, config.FINDINGS_DB_FILENAME).exists())
    return jsonify({"has_db": has_db, "project_id": project_id})


@home_bp.route("/api/convert-engagement/<project_id>", methods=["POST"])
def api_convert_engagement(project_id):
    if not config.FINDINGS_DB_AVAILABLE:
        return jsonify({"error": "FindingsDB module not available"}), 503
    project = get_project(project_id)
    if not project:
        return jsonify({"error": "not found"}), 404
    eng_dir = project.get("engagement_dir", project.get("project_dir", ""))
    if not eng_dir:
        return jsonify({"error": "no engagement directory"}), 400
    db_path = Path(eng_dir) / config.FINDINGS_DB_FILENAME
    if db_path.exists():
        return jsonify({"ok": True, "message": "Already converted", "skipped": True})
    try:
        import sys
        if "/opt/pr0t31n/shared" not in sys.path:
            sys.path.insert(0, "/opt/pr0t31n/shared")
        import pr0t31n_findings_db
        db = pr0t31n_findings_db.FindingsDB(str(db_path))
        total = db.migrate_legacy_project(eng_dir, project)
        db.close()
        log.info("Converted engagement %s: %d findings ingested", project_id, total)
        return jsonify({"ok": True, "findings": total,
                        "message": f"Converted {total} findings to database"})
    except Exception as exc:
        log.exception("Engagement conversion failed for %s", project_id)
        return jsonify({"error": str(exc)}), 500
