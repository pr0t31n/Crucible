"""Sessions API routes — auth session management endpoints."""

from flask import Blueprint, request, jsonify
from routes._helpers import require_project

sessions_bp = Blueprint("sessions", __name__)


def _get_sm():
    from services.session_manager import (
        get_sessions, get_session_detail, get_session_count,
        register_session, kill_session, kill_all_sessions,
        refresh_session, get_auth_for_tool,
    )
    return {
        "get_sessions": get_sessions,
        "get_session_detail": get_session_detail,
        "get_session_count": get_session_count,
        "register_session": register_session,
        "kill_session": kill_session,
        "kill_all_sessions": kill_all_sessions,
        "refresh_session": refresh_session,
        "get_auth_for_tool": get_auth_for_tool,
    }


@sessions_bp.route("/api/sessions/<project_id>")
def api_sessions(project_id):
    require_project(project_id)
    sm = _get_sm()
    return jsonify({
        "sessions": sm["get_sessions"](project_id),
        "counts": sm["get_session_count"](project_id),
    })


@sessions_bp.route("/api/sessions/<project_id>/count")
def api_session_count(project_id):
    require_project(project_id)
    sm = _get_sm()
    return jsonify(sm["get_session_count"](project_id))


@sessions_bp.route("/api/sessions/<project_id>/<session_id>")
def api_session_detail(project_id, session_id):
    require_project(project_id)
    sm = _get_sm()
    detail = sm["get_session_detail"](project_id, session_id)
    if not detail:
        return jsonify({"error": "Session not found"}), 404
    return jsonify(detail)


@sessions_bp.route("/api/sessions/<project_id>", methods=["POST"])
def api_register_session(project_id):
    require_project(project_id)
    sm = _get_sm()
    body = request.get_json(silent=True) or {}

    kwargs = {}
    for key in ("label", "auth_type", "framework", "origin_tool", "scope",
                "target_url", "access_token", "refresh_token", "cookies",
                "headers", "credentials", "token_endpoint", "refresh_endpoint",
                "heartbeat_url"):
        if key in body:
            kwargs[key] = body[key]

    if body.get("expires_in"):
        import time
        kwargs["expires_at"] = time.time() + int(body["expires_in"])
    elif body.get("expires_at"):
        kwargs["expires_at"] = float(body["expires_at"])

    sess = sm["register_session"](project_id, **kwargs)
    return jsonify(sess), 201


@sessions_bp.route("/api/sessions/<project_id>/<session_id>/kill", methods=["POST"])
def api_kill_session(project_id, session_id):
    require_project(project_id)
    sm = _get_sm()
    ok = sm["kill_session"](project_id, session_id)
    if not ok:
        return jsonify({"error": "Session not found"}), 404
    return jsonify({"ok": True})


@sessions_bp.route("/api/sessions/<project_id>/kill-all", methods=["POST"])
def api_kill_all(project_id):
    require_project(project_id)
    sm = _get_sm()
    sm["kill_all_sessions"](project_id)
    return jsonify({"ok": True})


@sessions_bp.route("/api/sessions/<project_id>/<session_id>/refresh", methods=["POST"])
def api_refresh_session(project_id, session_id):
    require_project(project_id)
    sm = _get_sm()
    ok = sm["refresh_session"](project_id, session_id)
    if not ok:
        return jsonify({"error": "Refresh failed or session dead"}), 400
    return jsonify({"ok": True})


@sessions_bp.route("/api/sessions/<project_id>/<session_id>/auth", methods=["POST"])
def api_get_auth(project_id, session_id):
    require_project(project_id)
    sm = _get_sm()
    body = request.get_json(silent=True) or {}
    tool_id = body.get("tool_id", "")
    auth = sm["get_auth_for_tool"](project_id, session_id, tool_id)
    if not auth:
        return jsonify({"error": "Session not found or dead"}), 404
    return jsonify(auth)
