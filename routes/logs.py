"""Logs API routes — structured logs, errors, status with time-range filtering."""

from flask import Blueprint, request, jsonify
from routes._helpers import require_project, get_ext
from models.logs import load_logs, load_errors, count_errors, parse_dt_arg, clear_logs, clear_errors

logs_bp = Blueprint("logs", __name__)


def _common_filters():
    """Extract common query args for log/error endpoints."""
    return (
        parse_dt_arg(request.args.get("from")),
        parse_dt_arg(request.args.get("to")),
        request.args.get("tool"),
        request.args.get("level"),
    )


@logs_bp.route("/api/logs/<project_id>")
def api_logs(project_id):
    """Structured logs with optional time-range, tool, and level filter.
    Accepts ?from=, ?to= (datetime-local format), ?tool=, ?level=."""
    project = require_project(project_id)
    proj_dir = project.get("project_dir", "")
    if not proj_dir:
        return jsonify({"entries": [], "error_count": 0})

    from_dt, to_dt, tool_filter, level_filter = _common_filters()
    entries = load_logs(proj_dir, from_dt=from_dt, to_dt=to_dt,
                        tool_filter=tool_filter, level_filter=level_filter)
    return jsonify({
        "entries": entries,
        "total": len(entries),
        "error_count": count_errors(entries),
    })


@logs_bp.route("/api/errors/<project_id>")
def api_errors(project_id):
    """Structured errors with optional time-range, tool, and level filter.
    Accepts ?from=, ?to=, ?tool=, ?level=."""
    project = require_project(project_id)
    proj_dir = project.get("project_dir", "")
    if not proj_dir:
        return jsonify({"entries": [], "error_count": 0})

    from_dt, to_dt, tool_filter, level_filter = _common_filters()
    entries = load_errors(proj_dir, from_dt=from_dt, to_dt=to_dt,
                          tool_filter=tool_filter, level_filter=level_filter)
    return jsonify({
        "entries": entries,
        "total": len(entries),
        "error_count": count_errors(entries),
    })


@logs_bp.route("/api/status/<project_id>")
def api_status(project_id):
    """Return cached phase/status data for all tools."""
    pm = get_ext("process_manager")
    if not pm:
        return jsonify({"statuses": {}})
    statuses = pm.get_all_status(project_id)
    return jsonify({"statuses": statuses})


@logs_bp.route("/api/clear-logs/<project_id>", methods=["POST"])
def api_clear_logs(project_id):
    project = require_project(project_id)
    proj_dir = project.get("project_dir", "")
    if proj_dir:
        clear_logs(proj_dir)
    return jsonify({"ok": True})


@logs_bp.route("/api/clear-errors/<project_id>", methods=["POST"])
def api_clear_errors(project_id):
    project = require_project(project_id)
    proj_dir = project.get("project_dir", "")
    if proj_dir:
        clear_errors(proj_dir)
    return jsonify({"ok": True})
