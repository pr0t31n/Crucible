"""Standalone tools — routes for tools accessible from the homepage."""

import json
import threading
from pathlib import Path

from flask import Blueprint, jsonify, render_template, request

standalone_bp = Blueprint("standalone", __name__)

_merge_jobs = {}
_merge_lock = threading.Lock()


@standalone_bp.route("/tools/merger")
def merger_page():
    return render_template("merger.html")


@standalone_bp.route("/api/merger/browse", methods=["POST"])
def api_merger_browse():
    data = request.get_json(silent=True) or {}
    folder = data.get("folder", "").strip() or "/"
    folder_path = Path(folder)
    if not folder_path.is_dir():
        folder_path = folder_path.parent
        if not folder_path.is_dir():
            folder_path = Path("/")
    entries = []
    try:
        for item in sorted(folder_path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
            if item.name.startswith("."):
                continue
            entries.append({
                "name": item.name,
                "path": str(item),
                "is_dir": item.is_dir(),
            })
    except PermissionError:
        return jsonify({"error": f"Permission denied: {folder_path}",
                        "current": str(folder_path), "entries": []}), 403
    return jsonify({
        "current": str(folder_path),
        "parent": str(folder_path.parent) if folder_path != folder_path.parent else None,
        "entries": entries,
    })


@standalone_bp.route("/api/dredge/detect", methods=["POST"])
def api_dredge_detect():
    data = request.get_json(silent=True) or {}
    path_str = data.get("path", "").strip()
    if not path_str:
        return jsonify({"valid": False, "error": "No path provided"})

    p = Path(path_str)
    if not p.exists():
        return jsonify({"valid": False, "error": f"Path not found: {path_str}"})

    from adapters.dredge import _detect_collection
    resolved, ctype = _detect_collection(path_str)
    if resolved is None:
        return jsonify({
            "valid": False,
            "path": path_str,
            "error": "Not a recognisable Dredge collection (expected PS1 JSON or CMD batch directory)",
        })

    labels = {"ps1_json": "PowerShell Collection JSON", "cmd_dir": "CMD Batch Output Directory"}
    return jsonify({
        "valid": True,
        "path": resolved,
        "type": ctype,
        "label": labels.get(ctype, ctype),
    })


@standalone_bp.route("/api/merger/scan", methods=["POST"])
def api_merger_scan():
    data = request.get_json(silent=True) or {}
    folder = data.get("folder", "").strip()
    if not folder:
        return jsonify({"error": "Folder path required"}), 400

    folder_path = Path(folder)
    if not folder_path.is_dir():
        return jsonify({"error": f"Not a valid directory: {folder}"}), 400

    from tools.merger import EngagementMerger

    logs = []
    merger = EngagementMerger(folder, callback=lambda m: logs.append(m))
    sources = merger.scan()

    source_list = []
    for src in sources:
        source_list.append({
            "type": src.type,
            "path": str(src.path),
            "name": src.meta.get("name", src.path.name) if src.meta else src.path.name,
            "label": src.label,
        })

    return jsonify({"sources": source_list, "logs": logs})


@standalone_bp.route("/api/merger/merge", methods=["POST"])
def api_merger_merge():
    data = request.get_json(silent=True) or {}
    folder = data.get("folder", "").strip()
    name = data.get("name", "").strip() or None

    if not folder:
        return jsonify({"error": "Folder path required"}), 400

    folder_path = Path(folder)
    if not folder_path.is_dir():
        return jsonify({"error": f"Not a valid directory: {folder}"}), 400

    from tools.merger import EngagementMerger

    logs = []
    merger = EngagementMerger(folder, output_name=name,
                              callback=lambda m: logs.append(m))
    sources = merger.scan()
    if not sources:
        return jsonify({"error": "No mergeable sources found", "logs": logs}), 400

    eng_dir = merger.merge(sources)
    if not eng_dir:
        return jsonify({"error": "Merge failed", "logs": logs}), 500

    from models.project import reload_projects
    reload_projects()

    meta_path = eng_dir / "crucible_meta.json"
    project_id = None
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text())
            project_id = meta.get("id")
        except (json.JSONDecodeError, OSError):
            pass

    return jsonify({
        "ok": True,
        "engagement_dir": str(eng_dir),
        "project_id": project_id,
        "source_count": len(sources),
        "logs": logs,
    })


STANDALONE_TOOLS = [
    {
        "id": "merger",
        "name": "Engagement Merger",
        "desc": "Merge multiple Crucible/Vantage engagements and Nessus results into one",
        "icon": "merge",
        "url": "/tools/merger",
    },
    {
        "id": "authprobe",
        "name": "AuthProbe",
        "desc": "Detect authentication methods, fingerprint software, probe well-known endpoints",
        "icon": "shield",
        "url": None,
        "modal": True,
    },
]


@standalone_bp.route("/api/standalone_tools")
def api_standalone_tools():
    return jsonify(STANDALONE_TOOLS)
