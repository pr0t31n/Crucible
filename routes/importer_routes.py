"""Import API routes — file/folder import, job management, parser registry."""

import logging
import uuid
from pathlib import Path

from flask import Blueprint, request, jsonify
from routes._helpers import require_project, get_ext

importer_bp = Blueprint("importer", __name__)
log = logging.getLogger("crucible.routes.importer")


def _imp():
    return get_ext("importer")


@importer_bp.route("/api/import/tools", methods=["GET"])
def api_import_tools():
    imp = _imp()
    if not imp:
        return jsonify({"error": "Importer not available", "tools": []}), 503
    try:
        tools = imp.registry.list_tools()
    except Exception as exc:
        import logging
        logging.getLogger("crucible.importer").exception("Failed to list import tools")
        return jsonify({"error": str(exc), "tools": []}), 500
    return jsonify({"tools": tools})


@importer_bp.route("/api/import/<project_id>/file", methods=["POST"])
def api_import_file(project_id):
    project = require_project(project_id)
    imp = _imp()
    if not imp:
        return jsonify({"error": "Importer not available"}), 503

    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "No file provided"}), 400

    manual_tool = request.form.get("tool_override") or request.form.get("tool") or None
    scope_override = request.form.get("scope") or None

    project_dir = project.get("project_dir", "")
    if not project_dir:
        return jsonify({"error": "Project has no directory"}), 400

    staging = Path(project_dir) / "_import_staging"
    staging.mkdir(parents=True, exist_ok=True)
    safe_name = Path(f.filename).name
    dest = staging / f"{uuid.uuid4().hex[:12]}_{safe_name}"
    f.save(str(dest))

    try:
        job = imp.submit_file(
            project_id, project, str(dest),
            manual_tool=manual_tool,
            scope_override=scope_override,
        )
    except Exception as exc:
        log.exception("Import submit failed for %s", safe_name)
        return jsonify({"error": str(exc)}), 500

    return jsonify(job)


@importer_bp.route("/api/import/<project_id>/folder", methods=["POST"])
def api_import_folder(project_id):
    project = require_project(project_id)
    imp = _imp()
    if not imp:
        return jsonify({"error": "Importer not available"}), 503

    project_dir = project.get("project_dir", "")
    if not project_dir:
        return jsonify({"error": "Project has no directory"}), 400

    files = request.files.getlist("files")
    if not files:
        return jsonify({"error": "No files provided"}), 400

    manual_tool = request.form.get("tool_override") or None

    staging = Path(project_dir) / "_import_staging"
    staging.mkdir(parents=True, exist_ok=True)

    jobs_created = 0
    skipped = 0
    for f in files:
        if not f.filename:
            continue
        safe_name = Path(f.filename).name
        dest = staging / f"{uuid.uuid4().hex[:12]}_{safe_name}"
        f.save(str(dest))
        try:
            job = imp.submit_file(
                project_id, project, str(dest),
                manual_tool=manual_tool,
            )
            if job:
                jobs_created += 1
            else:
                skipped += 1
        except Exception:
            log.exception("Folder import: failed to submit %s", safe_name)
            skipped += 1

    return jsonify({"jobs_created": jobs_created, "skipped": skipped})


@importer_bp.route("/api/import/<project_id>/jobs", methods=["GET"])
def api_import_jobs(project_id):
    require_project(project_id)
    imp = _imp()
    if not imp:
        return jsonify({"error": "Importer not available"}), 503
    return jsonify({"jobs": imp.get_jobs(project_id)})


@importer_bp.route("/api/import/<project_id>/job/<job_id>", methods=["GET"])
def api_import_job(project_id, job_id):
    require_project(project_id)
    imp = _imp()
    if not imp:
        return jsonify({"error": "Importer not available"}), 503

    job = imp.get_job(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    if job.get("project_id") != project_id:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)


@importer_bp.route("/api/import/<project_id>/console/<job_id>", methods=["GET"])
def api_import_console(project_id, job_id):
    require_project(project_id)
    imp = _imp()
    if not imp:
        return jsonify({"error": "Importer not available"}), 503

    lines = imp.get_console(job_id)
    return jsonify({"job_id": job_id, "lines": lines})


@importer_bp.route("/api/import/<project_id>/job/<job_id>",
                    methods=["DELETE"])
def api_import_cancel(project_id, job_id):
    require_project(project_id)
    imp = _imp()
    if not imp:
        return jsonify({"error": "Importer not available"}), 503

    ok, msg = imp.cancel_job(job_id)
    if not ok:
        return jsonify({"error": msg}), 400
    return jsonify({"ok": True, "message": msg})


@importer_bp.route("/api/import/<project_id>/job/<job_id>/retry",
                    methods=["POST"])
def api_import_retry(project_id, job_id):
    project = require_project(project_id)
    imp = _imp()
    if not imp:
        return jsonify({"error": "Importer not available"}), 503

    old_job = imp.get_job(job_id)
    if not old_job:
        return jsonify({"error": "Job not found"}), 404
    if old_job.get("project_id") != project_id:
        return jsonify({"error": "Job not found"}), 404
    if old_job.get("status") != "FAILED":
        return jsonify({"error": "Only FAILED jobs can be retried"}), 400

    try:
        new_job = imp.submit_file(
            project_id, project, old_job["file_path"],
            manual_tool=old_job.get("manual_tool"),
            scope_override=old_job.get("scope_override"),
        )
    except Exception as exc:
        log.exception("Retry failed for job %s", job_id)
        return jsonify({"error": str(exc)}), 500

    return jsonify(new_job)
