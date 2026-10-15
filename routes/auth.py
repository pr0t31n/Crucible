"""Auth routes — login, logout, change-password."""

import logging
import time
import threading

from flask import Blueprint, make_response, render_template, request, redirect, url_for, session, flash
import _auth

auth_bp = Blueprint("auth", __name__)
_log = logging.getLogger("crucible.auth")


def _make_login_response(html):
    resp = make_response(html)
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

_login_attempts: dict[str, list[float]] = {}
_attempts_lock = threading.Lock()
_MAX_ATTEMPTS = 5
_WINDOW_SECONDS = 60
_LOCKOUT_SECONDS = 900


def _is_rate_limited(ip: str) -> bool:
    now = time.time()
    with _attempts_lock:
        attempts = _login_attempts.get(ip, [])
        attempts = [t for t in attempts if now - t < _LOCKOUT_SECONDS]
        _login_attempts[ip] = attempts
        recent = [t for t in attempts if now - t < _WINDOW_SECONDS]
        return len(recent) >= _MAX_ATTEMPTS


def _record_attempt(ip: str) -> None:
    with _attempts_lock:
        _login_attempts.setdefault(ip, []).append(time.time())


def _clear_attempts(ip: str) -> None:
    with _attempts_lock:
        _login_attempts.pop(ip, None)


def _safe_next(nxt: str) -> str:
    if not nxt or nxt.startswith("//") or "://" in nxt or nxt.startswith("\\"):
        return "/"
    if not nxt.startswith("/"):
        return "/"
    return nxt


@auth_bp.route("/session-expired")
def session_expired():
    _auth.revoke_session_token(session.get("session_token"))
    session.clear()
    resp = redirect(url_for("auth.login", expired="1"))
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.delete_cookie("crucible_session", path="/")
    return resp


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        csrf = _auth.generate_csrf()
        expired_msg = "Session expired. Please log in again." if request.args.get("expired") else None
        resp = _make_login_response(
            render_template("login.html", csrf_token=csrf, error=expired_msg))
        return resp

    client_ip = request.remote_addr or "unknown"

    csrf_tok = request.form.get("csrf_token", "")
    if not _auth.check_csrf(csrf_tok):
        _log.warning("Login CSRF validation failed from %s (stale token)", client_ip)
        csrf = _auth.generate_csrf()
        resp = _make_login_response(
            render_template("login.html", csrf_token=csrf,
                            error="Session expired. Please log in again."))
        return resp

    if _is_rate_limited(client_ip):
        _log.warning("Login rate-limited for %s", client_ip)
        csrf = _auth.generate_csrf()
        return render_template("login.html", csrf_token=csrf,
                               error="Too many login attempts. Try again later.")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if _auth.verify_credentials(username, password):
        _clear_attempts(client_ip)
        _auth.validate_csrf(csrf_tok)
        session.permanent = True
        session["username"] = username
        session["authenticated"] = True
        session["session_token"] = _auth.create_session_token()
        _log.info("Login SUCCESS user=%s ip=%s", username, client_ip)

        if _auth.is_default_credentials(username, password):
            return redirect(url_for("auth.change_password", force=1))

        nxt = _safe_next(request.args.get("next", "/"))
        return redirect(nxt)

    _record_attempt(client_ip)
    _log.warning("Login FAILED user=%s ip=%s", username, client_ip)
    csrf = _auth.generate_csrf()
    return render_template("login.html", csrf_token=csrf,
                           error="Invalid credentials.")


@auth_bp.route("/api/session-check")
def session_check():
    from flask import jsonify
    return jsonify({"ok": True})


@auth_bp.route("/logout")
def logout():
    username = session.get("username", "unknown")
    client_ip = request.remote_addr or "unknown"
    _auth.revoke_session_token(session.get("session_token"))
    session.clear()
    _log.info("Logout user=%s ip=%s", username, client_ip)
    resp = redirect(url_for("auth.login"))
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    return resp


@auth_bp.route("/auth/change-password", methods=["GET", "POST"])
def change_password():
    force = request.args.get("force") == "1"

    if request.method == "GET":
        csrf = _auth.generate_csrf()
        return render_template("change_password.html",
                               csrf_token=csrf, force=force, error=None)

    csrf_tok = request.form.get("csrf_token", "")
    if not _auth.validate_csrf(csrf_tok):
        _log.warning("Change-password CSRF validation failed (stale token)")
        csrf = _auth.generate_csrf()
        return _make_login_response(render_template(
            "change_password.html", csrf_token=csrf, force=force, error=None))

    new_password = request.form.get("new_password", "")
    confirm = request.form.get("confirm_password", "")

    if new_password != confirm:
        csrf = _auth.generate_csrf()
        return render_template("change_password.html",
                               csrf_token=csrf, force=force,
                               error="Passwords do not match.")

    if len(new_password) < 8:
        csrf = _auth.generate_csrf()
        return render_template("change_password.html",
                               csrf_token=csrf, force=force,
                               error="Password must be at least 8 characters.")

    if force:
        new_username = request.form.get("new_username", "").strip()
        if not new_username or len(new_username) < 3:
            csrf = _auth.generate_csrf()
            return render_template("change_password.html",
                                   csrf_token=csrf, force=force,
                                   error="Username must be at least 3 characters.")

        if _auth.is_blocked_username(new_username):
            csrf = _auth.generate_csrf()
            return render_template("change_password.html",
                                   csrf_token=csrf, force=force,
                                   error="That username is not allowed.")

        if _auth.is_blocked_password(new_password):
            csrf = _auth.generate_csrf()
            return render_template("change_password.html",
                                   csrf_token=csrf, force=force,
                                   error="That password is too common.")

        _auth.update_credentials(new_username, new_password)
        session["username"] = new_username
        _log.info("Credentials changed (forced) new_user=%s ip=%s",
                  new_username, request.remote_addr)
        return redirect("/")
    else:
        current = request.form.get("current_password", "")
        username = session.get("username", "")
        if not _auth.verify_credentials(username, current):
            csrf = _auth.generate_csrf()
            return render_template("change_password.html",
                                   csrf_token=csrf, force=force,
                                   error="Current password is incorrect.")

        if _auth.is_blocked_password(new_password):
            csrf = _auth.generate_csrf()
            return render_template("change_password.html",
                                   csrf_token=csrf, force=force,
                                   error="That password is too common.")

        _auth.update_credentials(username, new_password)
        _log.info("Password changed user=%s ip=%s",
                  username, request.remote_addr)
        return redirect("/")
