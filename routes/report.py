"""Report generation routes — PDF pentest report via Playwright/Chromium."""

import io
import logging
from pathlib import Path

from flask import Blueprint, request, jsonify, send_file
from routes._helpers import require_project, get_ext

log = logging.getLogger("crucible.report")

report_bp = Blueprint("report", __name__)


def _engagement_incomplete(project_id, project):
    """Check if any tools are running or queued.

    Uses both the in-memory process manager AND the on-disk action-items
    status so that tools survive a server restart.
    """
    pm = get_ext("process_manager")
    pm_running = set()
    try:
        if pm:
            pm_running = set(pm.running_tools(project_id))
    except Exception:
        log.exception("Failed to check process manager running tools")

    proj_dir = project.get("project_dir")
    ai_running = set()
    ai_queued = set()
    if proj_dir:
        try:
            from models.action_items import load_action_items
            items = load_action_items(proj_dir,
                                      tool_dirs=project.get("tool_dirs"))
            for item in items:
                status = item.get("status", "")
                tool = item.get("recommended_tool", "unknown")
                if status == "running":
                    ai_running.add(tool)
                elif status == "queued":
                    ai_queued.add(tool)
        except Exception:
            log.exception("Failed to load action items for incomplete check")

    running = sorted(pm_running | ai_running)
    queued = sorted(ai_queued - pm_running - ai_running)

    is_incomplete = bool(running or queued)
    log.info("Engagement %s incomplete check: incomplete=%s running=%s queued=%s "
             "pm_running=%s ai_running=%s ai_queued=%s",
             project_id, is_incomplete, running, queued,
             pm_running, ai_running, ai_queued)
    return is_incomplete, {
        "incomplete": is_incomplete,
        "running": running,
        "queued": queued,
    }


@report_bp.route("/api/engagement-status/<project_id>")
def api_engagement_status(project_id):
    """Check whether the engagement has tools running or queued."""
    project = require_project(project_id)
    _, details = _engagement_incomplete(project_id, project)
    return jsonify(details)


@report_bp.route("/api/report-types/<project_id>")
def api_report_types(project_id):
    """Return available report types filtered by the project's active scopes."""
    project = require_project(project_id)
    try:
        from services.report_generator import REPORT_TYPES
    except ImportError:
        return jsonify({"types": []}), 200
    scopes = set(project.get("active_scopes", []))
    types = []
    for key, info in REPORT_TYPES.items():
        gate = info.get("scope_gate")
        types.append({
            "key": key,
            "label": info["label"],
            "description": info["description"],
            "available": gate is None or gate in scopes,
            "scope_gate": gate,
        })
    return jsonify({"types": types})


@report_bp.route("/api/generate-report/<project_id>")
def api_generate_report(project_id):
    """Generate a pentest report PDF for the engagement."""
    project = require_project(project_id)

    fmt = request.args.get("format", "pdf").lower()
    report_type = request.args.get("report_type", "full").lower()
    custom_filename = request.args.get("filename", "").strip()

    is_incomplete, _ = _engagement_incomplete(project_id, project)

    try:
        from services.report_generator import (
            gather_report_data, build_report, generate_pdf, esc,
            REPORT_TYPES, gather_endpoint_data,
            build_disk_report, build_hardware_report,
            build_software_report, build_malicious_report,
            build_nist_report, build_stig_report, build_cis_report,
        )
    except ImportError as e:
        return jsonify({"error": f"Report generator not available: {e}"}), 501

    if report_type not in REPORT_TYPES:
        return jsonify({"error": f"Unknown report type: {report_type}"}), 400

    rt_info = REPORT_TYPES[report_type]
    gate = rt_info.get("scope_gate")
    if gate and gate not in set(project.get("active_scopes", [])):
        return jsonify({"error": f"Report type '{report_type}' requires '{gate}' scope"}), 403

    client_short = project.get("client_short", "report")
    if custom_filename:
        base_name = custom_filename
    else:
        base_name = f"{client_short}_{report_type}_report"

    _EP_BUILDERS = {
        "disk": build_disk_report,
        "hardware": build_hardware_report,
        "software": build_software_report,
        "malicious": build_malicious_report,
        "nist": build_nist_report,
        "stig": build_stig_report,
        "cis": build_cis_report,
    }

    if report_type == "full":
        data = gather_report_data(project)
        data["incomplete"] = is_incomplete

        if fmt == "html":
            html = build_report(data)
            return html, 200, {
                "Content-Type": "text/html; charset=utf-8",
                "Content-Disposition": f"inline; filename={base_name}.html",
            }

        try:
            pdf_bytes = generate_pdf(project, incomplete=is_incomplete)
        except Exception as e:
            log.exception("Report PDF generation failed")
            return jsonify({"error": f"PDF generation failed: {e}"}), 500

    else:
        ep_data = gather_endpoint_data(project)
        ep_data["incomplete"] = is_incomplete

        if fmt == "html":
            builder = _EP_BUILDERS.get(report_type)
            if not builder:
                return jsonify({"error": f"No builder for report type: {report_type}"}), 400
            html = builder(ep_data)
            return html, 200, {
                "Content-Type": "text/html; charset=utf-8",
                "Content-Disposition": f"inline; filename={base_name}.html",
            }

        try:
            pdf_bytes = generate_pdf(project, incomplete=is_incomplete,
                                     report_type=report_type)
        except Exception as e:
            log.exception("Report PDF generation failed")
            return jsonify({"error": f"PDF generation failed: {e}"}), 500

    buf = io.BytesIO(pdf_bytes)
    buf.seek(0)
    return send_file(
        buf,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"{base_name}.pdf",
    )
