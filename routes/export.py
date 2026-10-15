"""Export API routes — PDF/HTML/XLSX exports, file content, output file listing."""

import io
import json
import mimetypes
from pathlib import Path

from flask import Blueprint, request, jsonify, send_file, Response
from routes._helpers import require_project, resolve_project_file, get_ext

try:
    import weasyprint
    _HAS_WEASYPRINT = True
except ImportError:
    _HAS_WEASYPRINT = False

export_bp = Blueprint("export", __name__)


@export_bp.route("/api/export-status-report/<project_id>")
def export_status_report(project_id):
    """Generate an HTML status report. Browser can print-to-PDF."""
    project = require_project(project_id)

    from services.findings_engine import FindingsEngine
    fe = get_ext("findings_engine") or FindingsEngine()
    findings = fe.get_findings(project_id, project)
    summary = fe.get_full_summary(project_id, project)
    from models.action_items import get_action_items_summary
    proj_dir = project.get("project_dir", "")
    ai_summary = get_action_items_summary(proj_dir) if proj_dir else {}

    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: risk_order.get(f.get("risk", "INFO"), 5))

    risk_colors = {
        "CRITICAL": "#dc2626", "HIGH": "#ea580c",
        "MEDIUM": "#d97706", "LOW": "#2563eb", "INFO": "#6b7280",
    }

    name = _esc(project.get("name", "Engagement"))
    client = _esc(project.get("client_name", ""))
    html_parts = [
        "<!DOCTYPE html><html><head>",
        f"<title>Crucible Status Report — {name}</title>",
        "<style>",
        "body{font-family:system-ui,sans-serif;margin:2em;color:#1f2937;max-width:900px;margin:auto}",
        "h1{font-size:1.5em;margin-bottom:0.25em}",
        "h2{font-size:1.2em;margin-top:2em;border-bottom:2px solid #e5e7eb;padding-bottom:0.25em}",
        "table{width:100%;border-collapse:collapse;margin:1em 0;font-size:0.85em}",
        "th,td{padding:6px 10px;text-align:left;border-bottom:1px solid #e5e7eb}",
        "th{background:#f9fafb;font-weight:600}",
        ".badge{display:inline-block;padding:2px 8px;border-radius:4px;color:white;font-size:0.75em;font-weight:600}",
        ".meta{color:#6b7280;font-size:0.9em}",
        "@media print{body{margin:0.5in}}",
        "</style></head><body>",
        f"<h1>Crucible Status Report</h1>",
        f"<p class='meta'>{name} — {client}</p>",
        f"<p class='meta'>Generated: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M')}</p>",
        "<h2>Summary</h2>",
        "<table><tr>",
    ]
    rs = summary.get("risk_summary", {})
    for risk in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = rs.get(risk, 0)
        color = risk_colors.get(risk, "#6b7280")
        html_parts.append(
            f"<td><span class='badge' style='background:{color}'>{risk}</span> {count}</td>"
        )
    html_parts.append("</tr></table>")
    html_parts.append(f"<p>Total findings: {summary.get('total', 0)} | "
                      f"Accepted: {summary.get('accepted_count', 0)} | "
                      f"FP: {summary.get('fp_count', 0)}</p>")

    html_parts.append("<h2>Findings</h2>")
    if findings:
        html_parts.append("<table><tr><th>Risk</th><th>CVSS</th><th>Title</th>"
                          "<th>IP:Port</th><th>CVEs</th><th>Tool</th>"
                          "<th>Description</th><th>Remediation</th></tr>")
        for f in findings:
            risk = f.get("risk", "INFO")
            color = risk_colors.get(risk, "#6b7280")
            ip = f.get("ip", "")
            port = f.get("port", "")
            addr = f"{ip}:{port}" if port else ip
            cvss = f.get("cvss_score")
            cvss_str = f"{cvss:.1f}" if cvss is not None else ""
            desc = (f.get("description", "") or "")[:300]
            impact = f.get("impact", "")
            if impact:
                desc = f"{desc} | Impact: {impact[:150]}"
            rem = (f.get("remediation", "") or "")[:200]
            cves = f.get("cves", "")
            html_parts.append(
                f"<tr><td><span class='badge' style='background:{color}'>{risk}</span></td>"
                f"<td>{_esc(cvss_str)}</td>"
                f"<td>{_esc(f.get('title', ''))}</td>"
                f"<td>{_esc(addr)}</td>"
                f"<td style='font-size:0.8em'>{_esc(cves)}</td>"
                f"<td>{_esc(f.get('tool', ''))}</td>"
                f"<td style='font-size:0.8em'>{_esc(desc)}</td>"
                f"<td style='font-size:0.8em'>{_esc(rem)}</td></tr>"
            )
        html_parts.append("</table>")
    else:
        html_parts.append("<p>No findings.</p>")

    html_parts.append("</body></html>")
    report_html = "\n".join(html_parts)
    client_short = project.get("client_short", "report")

    if request.args.get("format", "").lower() == "pdf":
        if not _HAS_WEASYPRINT:
            return jsonify({
                "error": "PDF export requires weasyprint. "
                         "Install with: pip3 install --break-system-packages weasyprint"
            }), 501
        pdf_bytes = weasyprint.HTML(string=report_html).write_pdf()
        buf = io.BytesIO(pdf_bytes)
        buf.seek(0)
        return send_file(
            buf, mimetype="application/pdf", as_attachment=True,
            download_name=f"{client_short}_status_report.pdf",
        )

    return Response(
        report_html,
        mimetype="text/html",
        headers={"Content-Disposition":
                 f"inline; filename={client_short}_status_report.html"},
    )


def _esc(text):
    """Minimal HTML escape."""
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


@export_bp.route("/api/file_content/<project_id>")
def api_file_content(project_id):
    """Read an evidence/output file as text."""
    project = require_project(project_id)
    rel_path = request.args.get("path", "")
    if not rel_path:
        return jsonify({"error": "path parameter required"}), 400
    full_path = resolve_project_file(project, rel_path)
    try:
        content = full_path.read_text(errors="replace")
        return jsonify({"content": content, "path": rel_path})
    except Exception:
        return jsonify({"error": "Failed to read file"}), 500


@export_bp.route("/api/file_serve/<project_id>")
def api_file_serve(project_id):
    """Serve a binary file (images, pcaps, etc.)."""
    project = require_project(project_id)
    rel_path = request.args.get("path", "")
    if not rel_path:
        return jsonify({"error": "path parameter required"}), 400
    full_path = resolve_project_file(project, rel_path)
    mime = mimetypes.guess_type(str(full_path))[0] or "application/octet-stream"
    return send_file(str(full_path), mimetype=mime)


@export_bp.route("/api/output_files/<project_id>")
def api_output_files(project_id):
    """List output files across all tool dirs."""
    project = require_project(project_id)

    tool_filter = request.args.get("tool")
    files = []

    tool_dirs = project.get("tool_dirs", {})
    if tool_filter:
        tool_dirs = {k: v for k, v in tool_dirs.items() if k == tool_filter}

    for tool_id, td in tool_dirs.items():
        tp = Path(td)
        if not tp.exists():
            continue
        for fp in sorted(tp.rglob("*")):
            if fp.is_file():
                files.append({
                    "tool": tool_id,
                    "path": str(fp.relative_to(tp)),
                    "name": fp.name,
                    "size": fp.stat().st_size,
                    "ext": fp.suffix,
                })

    return jsonify({"files": files, "total": len(files)})
