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

    fe = get_ext("findings_engine")
    imported = 0
    for finding in findings:
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
