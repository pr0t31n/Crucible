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
            # External scope
            gather_external_data,
            build_ext_vuln_report, build_ext_surface_report,
            build_ext_pci_report, build_ext_firewall_report,
            build_ext_exec_report,
            # OSINT scope
            gather_osint_data,
            build_osint_intel_report, build_osint_footprint_report,
            build_osint_email_report, build_osint_dns_report,
            build_osint_exec_report,
            # Internal scope
            gather_internal_data,
            build_int_vuln_report, build_int_segment_report,
            build_int_ad_report, build_int_smb_report,
            build_int_exec_report,
            # Wireless scope
            gather_wireless_data,
            build_wire_assess_report, build_wire_wifi_report,
            build_wire_rogue_report, build_wire_ble_report,
            build_wire_exec_report,
            # Web scope
            gather_web_data,
            build_web_vuln_report, build_web_owasp_report,
            build_web_tech_report, build_web_discovery_report,
            build_web_exec_report,
            # API scope
            gather_api_data,
            build_api_vuln_report, build_api_owasp_report,
            build_api_exec_report,
            # Cross-scope tools
            gather_trawler_data, build_trawler_report,
            gather_auger_data, build_auger_report,
            gather_bastion_data, build_bastion_report,
            gather_forge_data, build_forge_report,
            gather_quill_data, build_quill_report,
            gather_isotope_data, build_isotope_report,
            # Cross-scope universal
            gather_cross_scope_data,
            build_remediation_report, build_compliance_matrix_report,
            build_unified_exec_report,
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

    # ── Builder dispatch ────────────────────────────────────
    _EP_BUILDERS = {
        "disk": (gather_endpoint_data, build_disk_report),
        "hardware": (gather_endpoint_data, build_hardware_report),
        "software": (gather_endpoint_data, build_software_report),
        "malicious": (gather_endpoint_data, build_malicious_report),
        "nist": (gather_endpoint_data, build_nist_report),
        "stig": (gather_endpoint_data, build_stig_report),
        "cis": (gather_endpoint_data, build_cis_report),
    }

    _EXT_BUILDERS = {
        "ext_vuln": (gather_external_data, build_ext_vuln_report),
        "ext_surface": (gather_external_data, build_ext_surface_report),
        "ext_pci": (gather_external_data, build_ext_pci_report),
        "ext_firewall": (gather_external_data, build_ext_firewall_report),
        "ext_exec": (gather_external_data, build_ext_exec_report),
    }

    _OSINT_BUILDERS = {
        "osint_intel": (gather_osint_data, build_osint_intel_report),
        "osint_footprint": (gather_osint_data, build_osint_footprint_report),
        "osint_email": (gather_osint_data, build_osint_email_report),
        "osint_dns": (gather_osint_data, build_osint_dns_report),
        "osint_exec": (gather_osint_data, build_osint_exec_report),
    }

    _INT_BUILDERS = {
        "int_vuln": (gather_internal_data, build_int_vuln_report),
        "int_segment": (gather_internal_data, build_int_segment_report),
        "int_ad": (gather_internal_data, build_int_ad_report),
        "int_smb": (gather_internal_data, build_int_smb_report),
        "int_exec": (gather_internal_data, build_int_exec_report),
    }

    _WIRE_BUILDERS = {
        "wire_assess": (gather_wireless_data, build_wire_assess_report),
        "wire_wifi": (gather_wireless_data, build_wire_wifi_report),
        "wire_rogue": (gather_wireless_data, build_wire_rogue_report),
        "wire_ble": (gather_wireless_data, build_wire_ble_report),
        "wire_exec": (gather_wireless_data, build_wire_exec_report),
    }

    _WEB_BUILDERS = {
        "web_vuln": (gather_web_data, build_web_vuln_report),
        "web_owasp": (gather_web_data, build_web_owasp_report),
        "web_tech": (gather_web_data, build_web_tech_report),
        "web_discovery": (gather_web_data, build_web_discovery_report),
        "web_exec": (gather_web_data, build_web_exec_report),
    }

    _API_BUILDERS = {
        "api_vuln": (gather_api_data, build_api_vuln_report),
        "api_owasp": (gather_api_data, build_api_owasp_report),
        "api_exec": (gather_api_data, build_api_exec_report),
    }

    _TOOL_BUILDERS = {
        "trawler": (gather_trawler_data, build_trawler_report),
        "auger": (gather_auger_data, build_auger_report),
        "bastion": (gather_bastion_data, build_bastion_report),
        "forge": (gather_forge_data, build_forge_report),
        "quill": (gather_quill_data, build_quill_report),
        "isotope": (gather_isotope_data, build_isotope_report),
    }

    _CROSS_BUILDERS = {
        "remediation": (gather_cross_scope_data, build_remediation_report),
        "compliance_matrix": (gather_cross_scope_data, build_compliance_matrix_report),
        "unified_exec": (gather_cross_scope_data, build_unified_exec_report),
    }

    _ALL_BUILDERS = {}
    _ALL_BUILDERS.update(_EP_BUILDERS)
    _ALL_BUILDERS.update(_EXT_BUILDERS)
    _ALL_BUILDERS.update(_OSINT_BUILDERS)
    _ALL_BUILDERS.update(_INT_BUILDERS)
    _ALL_BUILDERS.update(_WIRE_BUILDERS)
    _ALL_BUILDERS.update(_WEB_BUILDERS)
    _ALL_BUILDERS.update(_API_BUILDERS)
    _ALL_BUILDERS.update(_TOOL_BUILDERS)
    _ALL_BUILDERS.update(_CROSS_BUILDERS)

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

    elif report_type in _ALL_BUILDERS:
        gatherer, builder = _ALL_BUILDERS[report_type]
        scope_data = gatherer(project)
        scope_data["incomplete"] = is_incomplete

        if fmt == "html":
            html = builder(scope_data)
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

    else:
        return jsonify({"error": f"No builder for report type: {report_type}"}), 400

    buf = io.BytesIO(pdf_bytes)
    buf.seek(0)
    return send_file(
        buf,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"{base_name}.pdf",
    )
