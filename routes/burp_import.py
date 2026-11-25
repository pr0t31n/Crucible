"""Burp XML Import Wizard routes — preview and commit endpoints."""

import logging
import uuid
import threading
import time
from pathlib import Path

from flask import Blueprint, request, jsonify
from routes._helpers import require_project, get_ext

burp_import_bp = Blueprint("burp_import", __name__)
log = logging.getLogger("crucible.routes.burp_import")

_cache = {}
_cache_lock = threading.Lock()
_MAX_CACHE = 20


def _prune_cache():
    if len(_cache) > _MAX_CACHE:
        excess = sorted(_cache, key=lambda k: _cache[k].get("_ts", 0))
        for k in excess[: len(excess) - _MAX_CACHE]:
            _cache.pop(k, None)




def _safe_host(host_or_ip):
    """Replace dots and colons with underscores for filesystem safety."""
    return re.sub(r'[^\w-]', '_', host_or_ip or "unknown")[:120]


def _write_burp_evidence(project_dir, finding, parsed_issue):
    """Write Burp request/response as evidence files.

    Returns (req_rel, resp_rel) — run-dir-relative paths, or ("", "").
    """
    raw_req = parsed_issue.get("raw_request", "")
    raw_resp = parsed_issue.get("raw_response", "")
    if not raw_req and not raw_resp:
        return "", ""

    host = parsed_issue.get("hostname") or parsed_issue.get("ip") or "unknown"
    port = parsed_issue.get("port", 0) or 0
    safe_host = _safe_host(host)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Build evidence directory: <project_dir>/evidence/burp/<host>_<port>/
    ev_dir = Path(project_dir) / "evidence" / "burp" / f"{safe_host}_{port}"
    ev_dir.mkdir(parents=True, exist_ok=True)

    # Determine sequence number (NNNN) for this host/port pair
    existing = list(ev_dir.glob("BURP_*_request.txt"))
    seq = len(existing) + 1

    req_name = f"BURP_{seq:04d}_{ts}_request.txt"
    resp_name = f"BURP_{seq:04d}_{ts}_response.txt"
    req_path = ev_dir / req_name
    resp_path = ev_dir / resp_name

    try:
        if raw_req:
            req_path.write_text(raw_req, encoding="utf-8")
        if raw_resp:
            resp_path.write_text(raw_resp, encoding="utf-8")
    except OSError as exc:
        log.warning("Failed to write Burp evidence to %s: %s", ev_dir, exc)
        return "", ""

    # Return paths relative to the project dir
    try:
        req_rel = str(req_path.relative_to(project_dir)) if raw_req else ""
        resp_rel = str(resp_path.relative_to(project_dir)) if raw_resp else ""
    except ValueError:
        req_rel = str(req_path)
        resp_rel = str(resp_path)

    return req_rel, resp_rel

@burp_import_bp.route("/api/import/burp/<project_id>/preview",
                       methods=["POST"])
def api_burp_preview(project_id):
    project = require_project(project_id)

    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "No file provided"}), 400

    if not f.filename.lower().endswith(".xml"):
        return jsonify({"error": "File must be a Burp XML export (.xml)"}), 400

    project_dir = project.get("project_dir", "")
    if not project_dir:
        return jsonify({"error": "Project has no directory"}), 400

    staging = Path(project_dir) / "_import_staging"
    staging.mkdir(parents=True, exist_ok=True)
    safe_name = Path(f.filename).name
    dest = staging / f"{uuid.uuid4().hex[:12]}_{safe_name}"
    f.save(str(dest))

    try:
        from parsers.burp_xml import parse_xml, build_preview, file_sha256
    except ImportError:
        return jsonify({"error": "Burp XML parser not available"}), 503

    parsed = parse_xml(str(dest))
    if not parsed:
        dest.unlink(missing_ok=True)
        return jsonify({"error": "No issues found in Burp XML file"}), 400

    preview = build_preview(parsed, project)
    cache_key = file_sha256(str(dest))

    with _cache_lock:
        _cache[cache_key] = {
            "parsed": parsed,
            "file_path": str(dest),
            "_ts": time.time(),
        }
        _prune_cache()

    return jsonify({
        "ok": True,
        "cache_key": cache_key,
        "filename": safe_name,
        "total_issues": len(parsed),
        "hosts": preview["hosts"],
        "findings": [
            {
                "dedup_key": fp["dedup_key"],
                "title": fp["title"],
                "burp_name": fp.get("burp_name", ""),
                "risk": fp["risk"],
                "ip": fp["ip"],
                "port": fp["port"],
                "host_url": fp.get("host_url", ""),
                "catalogue_id": fp.get("catalogue_id", ""),
                "confidence": fp.get("confidence", ""),
                "dup_count": fp.get("dup_count", 1),
            }
            for fp in preview["findings"]
        ],
        "applicable_scopes": preview["applicable_scopes"],
    })


@burp_import_bp.route("/api/import/burp/<project_id>/commit",
                       methods=["POST"])
def api_burp_commit(project_id):
    project = require_project(project_id)

    data = request.get_json(silent=True) or {}
    cache_key = data.get("cache_key", "")
    scope = data.get("scope", "")
    hosts = data.get("hosts", [])
    finding_keys = data.get("finding_keys", [])

    if not cache_key:
        return jsonify({"error": "Missing cache_key"}), 400
    if not hosts:
        return jsonify({"error": "No hosts selected"}), 400
    if not finding_keys:
        return jsonify({"error": "No findings selected"}), 400

    with _cache_lock:
        entry = _cache.get(cache_key)
    if not entry:
        return jsonify({"error": "Upload expired — please re-upload the file"}), 410

    try:
        from parsers.burp_xml import build_findings
    except ImportError:
        return jsonify({"error": "Burp XML parser not available"}), 503

    parsed = entry["parsed"]
    findings = build_findings(parsed, scope, hosts, finding_keys)

    if not findings:
        return jsonify({"error": "No findings matched selection"}), 400

    # Build a lookup from dedup_key → parsed issue (for evidence data)
    parsed_by_key = {}
    for p in parsed:
        parsed_by_key[p["dedup_key"]] = p

    # Resolve project directory for evidence storage
    project_dir = project.get("project_dir", "") or project.get("engagement_dir", "")
    if not project_dir:
        scope_dirs = project.get("scope_tool_dirs", {})
        for sd in scope_dirs.values():
            if isinstance(sd, dict):
                for d in sd.values():
                    if d:
                        project_dir = str(Path(d).parent)
                        break
            elif sd:
                project_dir = str(Path(sd).parent)
                break
        if not project_dir:
            for td in project.get("tool_dirs", {}).values():
                if td:
                    project_dir = str(Path(td).parent)
                    break

    fe = get_ext("findings_engine")
    imported = 0
    for finding in findings:
        # Write Burp evidence files if we have raw request/response data
        if project_dir:
            dk = finding.get("_dedup_key", "")
            pi = parsed_by_key.get(dk)
            if not pi:
                # Try matching by title + host + path
                for p in parsed:
                    if (p["title"] == finding["title"] and
                            p["ip"] == finding["ip"] and
                            p["port"] == finding["port"]):
                        pi = p
                        break
            if pi and (pi.get("raw_request") or pi.get("raw_response")):
                req_rel, resp_rel = _write_burp_evidence(
                    project_dir, finding, pi)
                if req_rel or resp_rel:
                    evidence_paths = []
                    if req_rel:
                        evidence_paths.append(req_rel)
                    if resp_rel:
                        evidence_paths.append(resp_rel)
                    finding["output_file"] = "\n".join(evidence_paths)
                    if not finding.get("output"):
                        finding["output"] = ""
                    finding["output"] += (
                        f"\n\nEvidence files:\n"
                        f"  Request:  {req_rel}\n"
                        f"  Response: {resp_rel}")

        try:
            fe.add_live_finding(project_id, project, finding)
            imported += 1
        except Exception:
            log.exception("Failed to import Burp finding: %s",
                          finding.get("title"))

    with _cache_lock:
        _cache.pop(cache_key, None)
    file_path = entry.get("file_path")
    if file_path:
        Path(file_path).unlink(missing_ok=True)

    return jsonify({
        "ok": True,
        "imported": imported,
        "total": len(findings),
    })
