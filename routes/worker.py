"""Worker delegation routes — register, test, delegate, recall."""

import json
from pathlib import Path

from flask import Blueprint, request, jsonify
from config import PORT, WORKERS_FILE
from routes._helpers import get_ext

worker_bp = Blueprint("worker", __name__)


def _load_workers():
    if WORKERS_FILE.exists():
        with open(WORKERS_FILE) as f:
            return json.load(f)
    return []


def _save_workers(workers):
    with open(WORKERS_FILE, "w") as f:
        json.dump(workers, f, indent=2)


def _get_delegate():
    return get_ext("worker_delegate")


@worker_bp.route("/api/workers")
def api_list_workers():
    return jsonify({"workers": _load_workers()})


@worker_bp.route("/api/workers/register", methods=["POST"])
def api_register_worker():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    name = data.get("name", "").strip()
    if not url:
        return jsonify({"error": "Worker URL required"}), 400
    workers = _load_workers()
    for w in workers:
        if w.get("url") == url:
            return jsonify({"error": "Worker already registered"}), 409
    from datetime import datetime
    worker_entry = {
        "url": url, "name": name or url,
        "port": data.get("port", PORT),
        "registered": datetime.now().isoformat(),
        "status": "unknown",
    }
    workers.append(worker_entry)
    _save_workers(workers)

    delegate = _get_delegate()
    if delegate:
        delegate.register_worker(
            name=worker_entry["name"],
            url=url,
            port=worker_entry["port"],
        )

    return jsonify({"ok": True})


@worker_bp.route("/api/workers/remove", methods=["POST"])
def api_remove_worker():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    name = data.get("name", "")
    workers = _load_workers()
    removed = None
    new_workers = []
    for w in workers:
        if w.get("url") == url or w.get("name") == name:
            removed = w
        else:
            new_workers.append(w)
    _save_workers(new_workers)

    if removed:
        delegate = _get_delegate()
        if delegate:
            delegate.remove_worker(removed.get("name", ""))

    return jsonify({"ok": True})


@worker_bp.route("/api/workers/test", methods=["POST"])
def api_test_worker():
    data = request.get_json(silent=True) or {}
    name = data.get("name", "")
    if not name:
        return jsonify({"error": "Worker name required"}), 400

    delegate = _get_delegate()
    if not delegate:
        return jsonify({"error": "Worker delegation not initialized"}), 500

    ok, message = delegate.test_worker(name)
    if ok:
        workers = _load_workers()
        for w in workers:
            if w.get("name") == name:
                w["status"] = "online"
        _save_workers(workers)

    return jsonify({"ok": ok, "message": message})


@worker_bp.route("/api/workers/delegate", methods=["POST"])
def api_delegate_tool():
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id", "")
    tool_id = data.get("tool_id", "")
    worker_name = data.get("worker_name", "")
    settings = data.get("settings", {})

    if not all([project_id, tool_id, worker_name]):
        return jsonify({"error": "project_id, tool_id, and worker_name required"}), 400

    delegate = _get_delegate()
    if not delegate:
        return jsonify({"error": "Worker delegation not initialized"}), 500

    try:
        delegation_id = delegate.delegate_tool(
            project_id, tool_id, worker_name, settings,
            project_meta=data.get("project_meta"),
            scope=data.get("scope"),
        )
        return jsonify({"ok": True, "delegation_id": delegation_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@worker_bp.route("/api/workers/recall", methods=["POST"])
def api_recall_delegation():
    data = request.get_json(silent=True) or {}
    delegation_id = data.get("delegation_id", "")
    if not delegation_id:
        return jsonify({"error": "delegation_id required"}), 400

    delegate = _get_delegate()
    if not delegate:
        return jsonify({"error": "Worker delegation not initialized"}), 500

    ok = delegate.recall_delegation(delegation_id)
    return jsonify({"ok": ok})


@worker_bp.route("/api/worker/accept", methods=["POST"])
def api_accept_delegation():
    """Accept a delegation from a primary Crucible instance."""
    data = request.get_json(silent=True) or {}
    delegation_id = data.get("delegation_id", "")
    tool_id = data.get("tool_id", "")
    settings = data.get("settings", {})

    if not delegation_id or not tool_id:
        return jsonify({"accepted": False, "reason": "Missing fields"}), 400

    return jsonify({"accepted": True, "delegation_id": delegation_id})


@worker_bp.route("/api/worker/status")
def api_worker_status():
    """Report this instance's status as a worker."""
    delegate = _get_delegate()
    delegations = delegate.list_delegations() if delegate else []
    return jsonify({
        "status": "online",
        "active_delegations": len(delegations),
        "delegations": delegations,
    })
