"""Findings API routes — CRUD, FP, risk override, notes, export, snapshots."""

import csv
import io
import json
import logging
from datetime import datetime
from pathlib import Path
from flask import Blueprint, request, jsonify, current_app, Response, send_file
from config import VALID_RISKS
from routes._helpers import require_project, get_ext

findings_bp = Blueprint("findings", __name__)
log = logging.getLogger("crucible.routes.findings")


def _engine():
    return get_ext("findings_engine")


def _audit_evidence(project, findings):
    """Log CRITICAL errors for findings that lack evidence files."""
    from models.logs import load_errors, append_error

    proj_dir = project.get("project_dir", "")
    if not proj_dir:
        return

    no_evidence = [f for f in findings
                   if not f.get("output_file") and not f.get("imported")]
    if not no_evidence:
        return

    existing = load_errors(proj_dir)
    reported_ids = {e.get("finding_id") for e in existing if e.get("finding_id")}

    for f in no_evidence:
        fid = f.get("id", "")
        if fid and fid in reported_ids:
            continue

        tool = f.get("tool") or f.get("_tool") or "unknown"
        sources = f.get("sources") or ""
        title = f.get("title") or "Untitled"
        affected = f.get("affected") or ""
        if not affected:
            ip = f.get("ip") or ""
            port = f.get("port")
            if ip:
                affected = ip
                if port and port != 0 and str(port) != "0":
                    affected += ":" + str(port)

        msg = "Finding generated without evidence files! Tool: %s" % tool
        if sources:
            msg += ", Source(s): %s" % sources
        msg += ', Finding: "%s"' % title
        if affected:
            msg += ", Affected: %s" % affected

        append_error(proj_dir, {
            "timestamp": datetime.now().isoformat(),
            "level": "CRITICAL",
            "tool": tool,
            "finding_id": fid,
            "message": msg,
        })


@findings_bp.route("/api/findings/<project_id>")
def api_findings(project_id):
    try:
        project = require_project(project_id)
        findings = _engine().get_findings(project_id, project)
        summary = _engine().get_full_summary(project_id, project)
        _audit_evidence(project, findings)
        return jsonify({"findings": findings, "summary": summary})
    except Exception as exc:
        log.exception("Error loading findings for %s", project_id)
        return jsonify({"error": str(exc)}), 500


@findings_bp.route("/api/findings/v2/<project_id>")
def api_findings_v2(project_id):
    """Paginated findings from FindingsDB — server-side filtering/sorting."""
    try:
        project = require_project(project_id)
        kwargs = {}
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 50, type=int)
        per_page = min(per_page, 500)
        kwargs["page"] = max(page, 1)
        kwargs["per_page"] = per_page
        risk = request.args.get("risk")
        if risk:
            kwargs["risk"] = risk
        tool = request.args.get("tool")
        if tool:
            kwargs["tool"] = [t.strip() for t in tool.split(",")]
        scope = request.args.get("scope")
        if scope:
            kwargs["scope"] = scope
        ip = request.args.get("ip")
        if ip:
            kwargs["ip"] = ip
        port = request.args.get("port")
        if port:
            kwargs["port"] = port
        hostname = request.args.get("hostname")
        if hostname:
            kwargs["hostname"] = hostname
        category = request.args.get("category")
        if category:
            kwargs["category"] = category
        search = request.args.get("search")
        if search:
            kwargs["search"] = search
        sort = request.args.get("sort", "risk_id,title")
        kwargs["sort"] = sort
        order = request.args.get("order", "asc")
        kwargs["order"] = order
        include_fp = request.args.get("include_fp", "0") == "1"
        kwargs["include_fp"] = include_fp
        include_oos = request.args.get("include_oos", "1") != "0"
        kwargs["include_oos"] = include_oos

        result = _engine().query_findings_db(project_id, project, **kwargs)
        if result is None:
            findings = _engine().get_findings(project_id, project)
            summary = _engine().get_full_summary(project_id, project)
            total = len(findings)
            start = (kwargs["page"] - 1) * per_page
            page_findings = findings[start:start + per_page]
            return jsonify({
                "findings": page_findings,
                "total": total,
                "page": kwargs["page"],
                "per_page": per_page,
                "pages": (total + per_page - 1) // per_page if per_page else 1,
                "summary": summary,
                "source": "cache",
            })
        result["source"] = "db"
        return jsonify(result)
    except Exception as exc:
        log.exception("Error in findings v2 for %s", project_id)
        return jsonify({"error": str(exc)}), 500


@findings_bp.route("/api/findings/v2/<project_id>/filters")
def api_findings_v2_filters(project_id):
    """Distinct scopes, tools, categories for filter dropdowns."""
    try:
        project = require_project(project_id)
        filters = _engine().get_filter_options(project_id, project)
        return jsonify(filters)
    except Exception as exc:
        log.exception("Error getting filter options for %s", project_id)
        return jsonify({"error": str(exc)}), 500


@findings_bp.route("/api/reload-findings/<project_id>", methods=["POST"])
def api_reload_findings(project_id):
    try:
        project = require_project(project_id)
        findings = _engine().refresh(project_id, project)
        summary = _engine().get_full_summary(project_id, project)
        _audit_evidence(project, findings)
        return jsonify({"findings": findings, "summary": summary})
    except Exception as exc:
        log.exception("Error reloading findings for %s", project_id)
        return jsonify({"error": str(exc)}), 500


@findings_bp.route("/api/findings-count/<project_id>")
def api_findings_count(project_id):
    try:
        project = require_project(project_id)
        db = _engine()._get_db(project_id, project)
        if db is not None:
            try:
                total = db._conn.execute(
                    "SELECT COUNT(*) FROM findings "
                    "WHERE is_false_positive=0").fetchone()[0]
                return jsonify({"count": total})
            except Exception:
                pass
        findings = _engine().get_findings(project_id, project)
        return jsonify({"count": len(findings)})
    except Exception as exc:
        log.warning("findings_count: %s", exc)
        return jsonify({"count": 0})


@findings_bp.route("/api/suppress-finding", methods=["POST"])
def api_suppress_finding():
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    finding_id = data.get("finding_id")
    if not project_id or not finding_id:
        return jsonify({"error": "project_id and finding_id required"}), 400
    project = require_project(project_id)
    updated, fp = _engine().mark_fp(project_id, project, finding_id)
    if fp is None:
        return jsonify({"error": "Finding not found"}), 404
    return jsonify({"ok": True, "remaining": len(updated)})


@findings_bp.route("/api/suppress-finding-partial", methods=["POST"])
def api_suppress_finding_partial():
    """Mark specific affected locations within a finding as false positive."""
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    finding_id = data.get("finding_id")
    affected_locations = data.get("affected_locations", [])
    if not project_id or not finding_id or not affected_locations:
        return jsonify({"error": "project_id, finding_id, and affected_locations required"}), 400
    if not isinstance(affected_locations, list):
        return jsonify({"error": "affected_locations must be a list"}), 400
    project = require_project(project_id)
    updated, fp_entries = _engine().mark_partial_fp(project_id, project, finding_id,
                                                    affected_locations)
    if fp_entries is None:
        return jsonify({"error": "Finding not found"}), 404
    return jsonify({"ok": True, "remaining": len(updated)})


@findings_bp.route("/api/unsuppress-finding", methods=["POST"])
def api_unsuppress_finding():
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    finding_id = data.get("finding_id")
    if not project_id or not finding_id:
        return jsonify({"error": "project_id and finding_id required"}), 400
    project = require_project(project_id)
    recovered = _engine().recover_fp(project_id, project, finding_id)
    if not recovered:
        return jsonify({"error": "FP not found"}), 404
    return jsonify({"ok": True, "recovered": recovered})


@findings_bp.route("/api/suppressions/<project_id>")
def api_suppressions(project_id):
    project = require_project(project_id)
    fps = _engine().get_false_positives(project_id, project)
    keys = [{"id": fp.get("id"), "title": fp.get("title")} for fp in fps]
    return jsonify({"suppressions": keys})


@findings_bp.route("/api/false-positives/<project_id>")
def api_false_positives(project_id):
    project = require_project(project_id)
    fps = _engine().get_false_positives(project_id, project)
    return jsonify({"false_positives": fps, "count": len(fps)})


@findings_bp.route("/api/risk-override", methods=["POST"])
def api_risk_override():
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    finding_id = data.get("finding_id")
    new_risk = data.get("risk", "").upper()
    reason = data.get("reason", "")
    if not all([project_id, finding_id, new_risk]):
        return jsonify({"error": "project_id, finding_id, risk required"}), 400
    if new_risk not in VALID_RISKS:
        return jsonify({"error": f"Invalid risk: {new_risk}"}), 400
    project = require_project(project_id)
    _engine().set_risk_override(project_id, finding_id, new_risk, reason,
                                project=project)
    return jsonify({"ok": True})


@findings_bp.route("/api/accept-finding", methods=["POST"])
def api_accept_finding():
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    finding_id = data.get("finding_id")
    if not project_id or not finding_id:
        return jsonify({"error": "project_id and finding_id required"}), 400
    _engine().set_accepted(project_id, finding_id, accepted=True)
    return jsonify({"ok": True})


@findings_bp.route("/api/unaccept-finding", methods=["POST"])
def api_unaccept_finding():
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    finding_id = data.get("finding_id")
    if not project_id or not finding_id:
        return jsonify({"error": "project_id and finding_id required"}), 400
    _engine().set_accepted(project_id, finding_id, accepted=False)
    return jsonify({"ok": True})


@findings_bp.route("/api/finding-notes", methods=["POST", "DELETE"])
def api_finding_notes():
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    finding_id = data.get("finding_id")
    text = data.get("text", "")
    if not project_id or not finding_id:
        return jsonify({"error": "project_id and finding_id required"}), 400
    if request.method == "POST":
        if not text:
            return jsonify({"error": "text required"}), 400
        _engine().append_note(project_id, finding_id, text)
        return jsonify({"ok": True})
    note_index = data.get("note_index")
    if note_index is None:
        return jsonify({"error": "note_index required for DELETE"}), 400
    _engine().delete_note(project_id, finding_id, int(note_index))
    return jsonify({"ok": True})


@findings_bp.route("/api/bulk-suppress-findings", methods=["POST"])
def api_bulk_suppress_findings():
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    finding_ids = data.get("finding_ids", [])
    if not project_id or not finding_ids:
        return jsonify({"error": "project_id and finding_ids required"}), 400
    project = require_project(project_id)
    suppressed = 0
    failed = 0
    for fid in finding_ids:
        updated, fp = _engine().mark_fp(project_id, project, fid)
        if fp is not None:
            suppressed += 1
        else:
            failed += 1
    return jsonify({"ok": True, "suppressed": suppressed, "failed": failed})


@findings_bp.route("/api/bulk-accept-findings", methods=["POST"])
def api_bulk_accept_findings():
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    finding_ids = data.get("finding_ids", [])
    if not project_id or not finding_ids:
        return jsonify({"error": "project_id and finding_ids required"}), 400
    project = require_project(project_id)
    for fid in finding_ids:
        _engine().set_accepted(project_id, fid, accepted=True)
    return jsonify({"ok": True, "accepted": len(finding_ids)})


@findings_bp.route("/api/bulk-risk-override", methods=["POST"])
def api_bulk_risk_override():
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    finding_ids = data.get("finding_ids", [])
    new_risk = data.get("risk", "").upper()
    reason = data.get("reason", "")
    if not project_id or not finding_ids or not new_risk:
        return jsonify({"error": "project_id, finding_ids, and risk required"}), 400
    if new_risk not in VALID_RISKS:
        return jsonify({"error": f"Invalid risk: {new_risk}"}), 400
    project = require_project(project_id)
    for fid in finding_ids:
        _engine().set_risk_override(project_id, fid, new_risk, reason,
                                    project=project)
    return jsonify({"ok": True, "updated": len(finding_ids)})


@findings_bp.route("/api/finding/workflow/<project_id>")
def api_finding_workflow(project_id):
    """Finding workflow: host correlation, CVE correlation, attack surface."""
    try:
        project = require_project(project_id)
        fe = _engine()
        workflow = fe.get_finding_workflow(project_id, project)
        return jsonify({"workflow": workflow})
    except Exception as exc:
        log.exception("Error building finding workflow for %s", project_id)
        return jsonify({"error": str(exc)}), 500


@findings_bp.route("/api/host-correlation/<project_id>")
def api_host_correlation(project_id):
    """Per-host aggregation of findings across tools."""
    try:
        project = require_project(project_id)
        hosts = _engine().get_host_correlation(project_id, project)
        return jsonify({"hosts": hosts, "total": len(hosts)})
    except Exception as exc:
        log.exception("Error building host correlation for %s", project_id)
        return jsonify({"error": str(exc)}), 500


@findings_bp.route("/api/finding/attach-evidence/<project_id>", methods=["POST"])
def api_attach_evidence(project_id):
    """Attach an evidence file (PoC, screenshot, etc.) to a finding."""
    project = require_project(project_id)
    project_dir = project.get("project_dir", "")
    if not project_dir:
        return jsonify({"error": "No project directory"}), 400

    finding_id = request.form.get("finding_id", "")
    if not finding_id:
        return jsonify({"error": "finding_id required"}), 400

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    safe_name = Path(f.filename).name
    if ".." in safe_name or "/" in safe_name or "\\" in safe_name:
        return jsonify({"error": "Invalid filename"}), 400

    evidence_dir = Path(project_dir) / "evidence" / finding_id
    evidence_dir.mkdir(parents=True, exist_ok=True)
    dest = evidence_dir / safe_name
    f.save(str(dest))

    try:
        rel = str(dest.relative_to(project_dir))
    except ValueError as exc:
        log.debug("evidence relative_to: %s", exc)
        rel = str(dest)

    fe = _engine()
    findings = fe.get_findings(project_id, project)
    updated = False
    for fnd in findings:
        if fnd.get("id") == finding_id:
            existing = fnd.get("output_file") or ""
            if existing:
                paths = set(existing.split("\n"))
                paths.add(rel)
                fnd["output_file"] = "\n".join(sorted(paths))
            else:
                fnd["output_file"] = rel
            updated = True
            break

    if updated:
        _persist_evidence_update(project_dir, finding_id, rel)

    log.info("Attached evidence %s to finding %s in project %s",
             safe_name, finding_id, project_id)
    return jsonify({"ok": True, "path": rel, "filename": safe_name})


def _persist_evidence_update(project_dir, finding_id, new_path):
    """Update output_file in all findings.json files that contain this finding."""
    pd = Path(project_dir)
    for fj in pd.rglob("findings.json"):
        try:
            data = json.loads(fj.read_text())
            items = data if isinstance(data, list) else data.get("findings", [])
            changed = False
            for f in items:
                if f.get("id") == finding_id:
                    existing = f.get("output_file") or ""
                    if new_path not in existing:
                        if existing:
                            f["output_file"] = existing + "\n" + new_path
                        else:
                            f["output_file"] = new_path
                        changed = True
            if changed:
                if isinstance(data, list):
                    fj.write_text(json.dumps(data, indent=2, default=str))
                else:
                    data["findings"] = items
                    fj.write_text(json.dumps(data, indent=2, default=str))
        except (json.JSONDecodeError, OSError) as exc:
            log.debug("persist_evidence_update: %s", exc)
            continue


@findings_bp.route("/api/cve-correlation/<project_id>")
def api_cve_correlation(project_id):
    """Per-CVE aggregation of findings across tools/hosts."""
    try:
        project = require_project(project_id)
        cves = _engine().get_cve_correlation(project_id, project)
        return jsonify({"cves": cves, "total": len(cves)})
    except Exception as exc:
        log.exception("Error building CVE correlation for %s", project_id)
        return jsonify({"error": str(exc)}), 500


@findings_bp.route("/api/compare-scans", methods=["POST"])
def api_compare_scans():
    """Delta between two project scan snapshots."""
    data = request.get_json(silent=True) or {}
    project_id_a = data.get("project_id_a") or data.get("project_id")
    project_id_b = data.get("project_id_b")
    if not project_id_a or not project_id_b:
        return jsonify({"error": "project_id_a and project_id_b required"}), 400

    try:
        project_a = require_project(project_id_a)
        project_b = require_project(project_id_b)
        fe = _engine()

        findings_a = fe.get_findings(project_id_a, project_a)
        findings_b = fe.get_findings(project_id_b, project_b)

        ids_a = {f.get("id") for f in findings_a if f.get("id")}
        ids_b = {f.get("id") for f in findings_b if f.get("id")}

        key_a = {}
        for f in findings_a:
            k = (f.get("title", "").lower(), f.get("ip", ""),
                 str(f.get("port", "")))
            key_a[k] = f
        key_b = {}
        for f in findings_b:
            k = (f.get("title", "").lower(), f.get("ip", ""),
                 str(f.get("port", "")))
            key_b[k] = f

        new_in_b = [key_b[k] for k in key_b if k not in key_a]
        resolved = [key_a[k] for k in key_a if k not in key_b]
        persistent = [key_a[k] for k in key_a if k in key_b]

        risk_changed = []
        for k in key_a:
            if k in key_b:
                ra = (key_a[k].get("risk") or "INFO").upper()
                rb = (key_b[k].get("risk") or "INFO").upper()
                if ra != rb:
                    risk_changed.append({
                        "title": key_a[k].get("title"),
                        "ip": key_a[k].get("ip"),
                        "port": key_a[k].get("port"),
                        "risk_before": ra,
                        "risk_after": rb,
                    })

        return jsonify({
            "new": len(new_in_b),
            "resolved": len(resolved),
            "persistent": len(persistent),
            "risk_changed": risk_changed,
            "new_findings": new_in_b[:100],
            "resolved_findings": resolved[:100],
        })
    except Exception as exc:
        log.exception("Error comparing scans")
        return jsonify({"error": str(exc)}), 500


@findings_bp.route("/api/snapshot-findings/<project_id>", methods=["POST"])
def api_snapshot_findings(project_id):
    """Create a timestamped snapshot of the current findings."""
    try:
        project = require_project(project_id)
        findings = _engine().get_findings(project_id, project)
        proj_dir = Path(project.get("project_dir", ""))
        if not proj_dir.exists():
            return jsonify({"error": "Project directory not found"}), 404
        snap_dir = proj_dir / "snapshots"
        snap_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        snap_file = snap_dir / f"{ts}.json"
        snap_file.write_text(json.dumps(findings, indent=2, default=str))
        return jsonify({"ok": True, "snapshot": ts, "count": len(findings)})
    except Exception as exc:
        log.exception("Error creating snapshot for %s", project_id)
        return jsonify({"error": str(exc)}), 500


@findings_bp.route("/api/snapshots/<project_id>")
def api_list_snapshots(project_id):
    """List available findings snapshots."""
    project = require_project(project_id)
    proj_dir = Path(project.get("project_dir", ""))
    snap_dir = proj_dir / "snapshots"
    snapshots = []
    if snap_dir.exists():
        for fp in sorted(snap_dir.glob("*.json"), reverse=True):
            try:
                data = json.loads(fp.read_text())
                count = len(data) if isinstance(data, list) else 0
            except (json.JSONDecodeError, OSError) as exc:
                log.debug("snapshot count read: %s", exc)
                count = 0
            snapshots.append({
                "id": fp.stem,
                "filename": fp.name,
                "count": count,
                "size": fp.stat().st_size,
            })
    return jsonify({"snapshots": snapshots})


@findings_bp.route("/api/diff-findings/<project_id>")
def api_diff_findings(project_id):
    """Compare current findings against a snapshot."""
    snapshot_id = request.args.get("snapshot")
    if not snapshot_id:
        return jsonify({"error": "snapshot parameter required"}), 400
    project = require_project(project_id)
    proj_dir = Path(project.get("project_dir", ""))
    snap_file = proj_dir / "snapshots" / f"{snapshot_id}.json"
    if not snap_file.exists():
        return jsonify({"error": "Snapshot not found"}), 404

    try:
        old_findings = json.loads(snap_file.read_text())
        if not isinstance(old_findings, list):
            return jsonify({"error": "Invalid snapshot format"}), 400
        current_findings = _engine().get_findings(project_id, project)

        def _key(f):
            return (
                (f.get("tool") or "").lower(),
                (f.get("title") or "").lower(),
                f.get("ip") or "",
                str(f.get("port") or ""),
            )

        old_keys = {}
        for f in old_findings:
            old_keys[_key(f)] = f
        cur_keys = {}
        for f in current_findings:
            cur_keys[_key(f)] = f

        added = [cur_keys[k] for k in cur_keys if k not in old_keys]
        removed = [old_keys[k] for k in old_keys if k not in cur_keys]
        unchanged_count = len([k for k in cur_keys if k in old_keys])

        risk_changed = []
        for k in cur_keys:
            if k in old_keys:
                ra = (old_keys[k].get("risk") or "INFO").upper()
                rb = (cur_keys[k].get("risk") or "INFO").upper()
                if ra != rb:
                    risk_changed.append({
                        "title": cur_keys[k].get("title"),
                        "ip": cur_keys[k].get("ip"),
                        "port": cur_keys[k].get("port"),
                        "risk_before": ra,
                        "risk_after": rb,
                    })

        return jsonify({
            "snapshot": snapshot_id,
            "added": added[:200],
            "added_count": len(added),
            "removed": removed[:200],
            "removed_count": len(removed),
            "unchanged_count": unchanged_count,
            "risk_changed": risk_changed,
        })
    except Exception as exc:
        log.exception("Error diffing findings for %s", project_id)
        return jsonify({"error": str(exc)}), 500


_CSV_COLUMNS = [
    "id", "tool", "scope", "risk", "cvss_score", "cvss_vector",
    "title", "ip", "port", "hostname", "service", "affected",
    "target_url", "description", "impact", "remediation",
    "output", "output_file", "command", "sources",
    "cves", "cwe", "kev", "owasp", "owasp_api",
    "nessus_plugin_id", "nessus_plugin_name", "qualys_qid",
    "mitre_attack", "searchsploit_terms", "metasploit_modules",
    "exploitdb", "metasploit", "exploit_details",
    "nist", "nist_csf2", "nist_800_53", "nist_800_171",
    "pci_dss_4", "iso_27001", "iso_27002", "soc2", "hitrust", "gdpr",
    "remediation_effort", "remediation_component", "remediation_category",
    "confidence", "accepted", "notes",
    "ssid", "bssid", "wireless_data",
    "api_endpoint_path", "api_method", "api_from_spec", "is_rogue_endpoint",
    "subdevice", "interface", "instance", "classification",
    "catalogue_id", "phase", "datetime",
]


def _csv_val(v):
    if v is None:
        return ""
    if isinstance(v, bool):
        return "Yes" if v else "No"
    if isinstance(v, list):
        if v and isinstance(v[0], dict):
            return json.dumps(v, separators=(",", ":"))
        return ", ".join(str(x) for x in v)
    if isinstance(v, dict):
        return json.dumps(v, separators=(",", ":"))
    return str(v)


@findings_bp.route("/api/export-findings/<project_id>")
def api_export_findings_csv(project_id):
    project = require_project(project_id)
    findings = _engine().get_findings(project_id, project)
    extra_keys = set()
    for f in findings:
        extra_keys.update(f.keys())
    cols = list(_CSV_COLUMNS)
    for k in sorted(extra_keys - set(cols)):
        if not k.startswith("_"):
            cols.append(k)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(cols)
    for f in findings:
        writer.writerow([_csv_val(f.get(c)) for c in cols])
    output = io.BytesIO(buf.getvalue().encode("utf-8-sig"))
    name = request.args.get("filename")
    if not name:
        cs = project.get("client_short", "findings")
        name = cs + "_findings"
    return send_file(output, mimetype="text/csv", as_attachment=True,
                     download_name=f"{name}.csv")


# ── Unmerged CSV export ──────────────────────────────────────

def _load_unmerged_findings(project):
    """Load findings from all tools WITHOUT cross-tool deduplication.
    Each tool's findings retain their original identity; only
    within-tool dedup (by the adapter) applies."""
    from models.findings import (
        load_findings_from_tool, _resolve_tool_dir, _apply_title_renames,
    )
    from config import TOOL_OUTPUT_DIRS

    all_findings = []
    tool_ids = set(project.get("tool_dirs", {}).keys())
    tool_ids.update(project.get("tools", []))
    loaded = set()

    for scope_key, scope_dirs in (project.get("scope_tool_dirs") or {}).items():
        for tool_id, td in (scope_dirs or {}).items():
            if td and (tool_id, td) not in loaded and Path(td).exists():
                loaded.add((tool_id, td))
                findings = load_findings_from_tool(td, tool_id)
                for f in findings:
                    f.setdefault("scope", scope_key)
                    f["title"] = _apply_title_renames(f.get("title") or "")
                all_findings.extend(findings)

    for tool_id in tool_ids:
        td = _resolve_tool_dir(project, tool_id)
        if td and (tool_id, td) not in loaded:
            loaded.add((tool_id, td))
            findings = load_findings_from_tool(td, tool_id)
            for f in findings:
                f["title"] = _apply_title_renames(f.get("title") or "")
            all_findings.extend(findings)

    excluded = set(project.get("scope_definition", {}).get("exclusions", []))
    if excluded:
        all_findings = [f for f in all_findings if f.get("ip", "") not in excluded]

    return all_findings


@findings_bp.route("/api/export-findings-unmerged/<project_id>")
def api_export_findings_unmerged_csv(project_id):
    project = require_project(project_id)
    findings = _load_unmerged_findings(project)
    _engine()._enrich_from_catalogue(findings)

    extra_keys = set()
    for f in findings:
        extra_keys.update(f.keys())
    cols = list(_CSV_COLUMNS)
    for k in sorted(extra_keys - set(cols)):
        if not k.startswith("_"):
            cols.append(k)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(cols)
    for f in sorted(findings, key=lambda x: (
        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(
            x.get("risk", "INFO"), 5),
        x.get("title", ""),
        x.get("ip", ""),
    )):
        writer.writerow([_csv_val(f.get(c)) for c in cols])
    output = io.BytesIO(buf.getvalue().encode("utf-8-sig"))
    name = request.args.get("filename")
    if not name:
        cs = project.get("client_short", "findings")
        name = cs + "_findings_unmerged"
    return send_file(output, mimetype="text/csv", as_attachment=True,
                     download_name=f"{name}.csv")


# ── Per-tool XLSX export ─────────────────────────────────────

_SCOPE_ABBREV = {
    "external": "EXT", "internal": "INT", "osint": "OSINT",
    "webapp": "WEB", "api": "API", "database": "DB",
    "wireless": "WIFI", "ext": "EXT", "int": "INT",
}

_TOOL_SHEET_ABBREV = {
    "ss3": "SS3", "osift": "OSIFT", "trawler": "TRAWL",
    "fracture": "FR", "siphon": "SI", "auger": "AU",
    "aether": "AE", "aether_b": "AE_B", "aether_z": "AE_Z", "aether_u": "AE_U",
    "nessus": "NE", "bastion": "BA", "forge": "FG", "quill": "QU",
    "isotope": "IS", "authprobe": "AP", "nuclei": "NU",
}


def _build_sheet_name(scope, tool_id, seen):
    """Build a unique sheet name like EXT_SS3, INT_NE_2."""
    scope_part = _SCOPE_ABBREV.get(scope, scope.upper()[:6]) if scope else "ALL"
    tool_part = _TOOL_SHEET_ABBREV.get(tool_id, tool_id.upper()[:5])
    base = f"{scope_part}_{tool_part}"
    if base not in seen:
        seen[base] = 1
        return base
    seen[base] += 1
    return f"{base}_{seen[base]}"


def _xlsx_val(v):
    if v is None:
        return ""
    if isinstance(v, bool):
        return "Yes" if v else "No"
    if isinstance(v, (int, float)):
        return v
    if isinstance(v, list):
        if v and isinstance(v[0], dict):
            return json.dumps(v, separators=(",", ":"))
        return ", ".join(str(x) for x in v)
    if isinstance(v, dict):
        return json.dumps(v, separators=(",", ":"))
    return str(v)


def _add_nessus_csv_sheets(wb, nessus_dir, scope_key, seen_names, header_font,
                           header_fill):
    """Add one sheet per original Nessus CSV, preserving exact columns."""
    originals = Path(nessus_dir) / "originals"
    csv_files = sorted(originals.glob("*.csv")) if originals.is_dir() else []
    if not csv_files:
        merged_csv = Path(nessus_dir) / "findings.csv"
        if merged_csv.exists():
            csv_files = [merged_csv]
    for csv_file in csv_files:
        try:
            with open(csv_file, "r", errors="replace") as fh:
                reader = csv.reader(fh)
                rows = list(reader)
            if not rows:
                continue
            sheet_name = _build_sheet_name(scope_key, "nessus", seen_names)[:31]
            ws = wb.create_sheet(title=sheet_name)
            for col_idx, h in enumerate(rows[0], 1):
                cell = ws.cell(row=1, column=col_idx, value=h)
                cell.font = header_font
                cell.fill = header_fill
            for row_idx, row in enumerate(rows[1:], 2):
                for col_idx, val in enumerate(row, 1):
                    ws.cell(row=row_idx, column=col_idx, value=val)
            for col_idx in range(1, len(rows[0]) + 1):
                ws.column_dimensions[
                    ws.cell(row=1, column=col_idx).column_letter
                ].width = 18
        except (OSError, csv.Error) as exc:
            log.debug("xlsx csv sheet: %s", exc)
            continue


@findings_bp.route("/api/export-findings-xlsx/<project_id>")
def api_export_findings_xlsx(project_id):
    project = require_project(project_id)
    from models.findings import load_findings_from_tool, _resolve_tool_dir, _apply_title_renames
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill

    tool_ids = set(project.get("tool_dirs", {}).keys())
    tool_ids.update(project.get("tools", []))
    loaded = set()
    sheet_groups = []
    nessus_dirs = []

    for scope_key, scope_dirs in (project.get("scope_tool_dirs") or {}).items():
        for tool_id, td in (scope_dirs or {}).items():
            if td and (tool_id, td) not in loaded and Path(td).exists():
                loaded.add((tool_id, td))
                if tool_id == "nessus":
                    nessus_dirs.append((scope_key, td))
                    continue
                findings = load_findings_from_tool(td, tool_id)
                for f in findings:
                    f.setdefault("scope", scope_key)
                    f["title"] = _apply_title_renames(f.get("title") or "")
                if findings:
                    sheet_groups.append((scope_key, tool_id, findings))

    for tool_id in tool_ids:
        td = _resolve_tool_dir(project, tool_id)
        if td and (tool_id, td) not in loaded:
            loaded.add((tool_id, td))
            if tool_id == "nessus":
                scope = ""
                for sk, sdirs in (project.get("scope_tool_dirs") or {}).items():
                    if sdirs.get("nessus") == td:
                        scope = sk
                        break
                nessus_dirs.append((scope, td))
                continue
            findings = load_findings_from_tool(td, tool_id)
            for f in findings:
                f["title"] = _apply_title_renames(f.get("title") or "")
            if findings:
                scope = findings[0].get("scope", "")
                sheet_groups.append((scope, tool_id, findings))

    excluded = set(project.get("scope_definition", {}).get("exclusions", []))
    if excluded:
        for i, (scope, tid, findings) in enumerate(sheet_groups):
            sheet_groups[i] = (scope, tid, [
                f for f in findings if f.get("ip", "") not in excluded
            ])
        sheet_groups = [(s, t, fl) for s, t, fl in sheet_groups if fl]

    all_for_enrich = [f for _, _, fl in sheet_groups for f in fl]
    _engine()._enrich_from_catalogue(all_for_enrich)

    wb = Workbook()
    wb.remove(wb.active)
    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill("solid", fgColor="2d3748")

    cols = list(_CSV_COLUMNS)
    seen_names = {}

    for scope_key, tool_id, findings in sheet_groups:
        sheet_name = _build_sheet_name(scope_key, tool_id, seen_names)[:31]
        ws = wb.create_sheet(title=sheet_name)
        for col_idx, h in enumerate(cols, 1):
            cell = ws.cell(row=1, column=col_idx, value=h)
            cell.font = header_font
            cell.fill = header_fill
        for row_idx, f in enumerate(
            sorted(findings, key=lambda x: (
                {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(
                    x.get("risk", "INFO"), 5),
                x.get("title", ""),
                x.get("ip", ""),
            )),
            2,
        ):
            for col_idx, c in enumerate(cols, 1):
                ws.cell(row=row_idx, column=col_idx, value=_xlsx_val(f.get(c)))
        for col_idx in range(1, len(cols) + 1):
            ws.column_dimensions[
                ws.cell(row=1, column=col_idx).column_letter
            ].width = 18

    for scope_key, nessus_td in nessus_dirs:
        _add_nessus_csv_sheets(wb, nessus_td, scope_key, seen_names,
                               header_font, header_fill)

    if not sheet_groups and not nessus_dirs:
        ws = wb.create_sheet(title="No Data")
        ws.cell(row=1, column=1, value="No findings data available.")

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    name = request.args.get("filename")
    if not name:
        cs = project.get("client_short", "findings")
        name = cs + "_findings"
    return send_file(
        buf,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True,
        download_name=f"{name}.xlsx",
    )
