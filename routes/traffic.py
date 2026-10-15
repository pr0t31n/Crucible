"""Traffic API routes — Trawler traffic data + pcap upload."""

import os
import tempfile
from pathlib import Path

from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename
from routes._helpers import require_project
from services.intel import IntelService

traffic_bp = Blueprint("traffic", __name__)
_intel = IntelService()


@traffic_bp.route("/api/traffic/<project_id>")
def api_traffic(project_id):
    project = require_project(project_id)
    tr_dir = project.get("tool_dirs", {}).get("trawler")
    data = _intel.get_traffic_analysis(tr_dir) if tr_dir else None
    return jsonify({"traffic": data})


@traffic_bp.route("/api/upload-pcap/<project_id>", methods=["POST"])
def api_upload_pcap(project_id):
    """Upload a pcap file for Trawler analysis."""
    project = require_project(project_id)

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    allowed = {".pcap", ".pcapng", ".cap"}
    ext = Path(f.filename).suffix.lower()
    if ext not in allowed:
        return jsonify({"error": f"Invalid file type: {ext}"}), 400

    tr_dir = project.get("tool_dirs", {}).get("trawler")
    if not tr_dir:
        return jsonify({"error": "Trawler not configured for this project"}), 400

    safe_name = secure_filename(f.filename)
    if not safe_name:
        return jsonify({"error": "Invalid filename"}), 400
    dest = Path(tr_dir) / safe_name
    dest.parent.mkdir(parents=True, exist_ok=True)
    f.save(str(dest))

    return jsonify({"ok": True, "path": str(dest), "filename": safe_name})
