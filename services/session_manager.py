"""SessionManager — centralized auth session keepalive service.

Captures, stores, and proactively refreshes authentication sessions so
tools can share live credentials across runs without token expiry.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import threading
import time
import uuid
from datetime import datetime, timezone

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("crucible.session_manager")

_managers: dict[str, "SessionManager"] = {}
_managers_lock = threading.Lock()

_REFRESH_MARGIN_S = 120
_HEARTBEAT_INTERVAL_S = 45
_CHECK_INTERVAL_S = 30
_MAX_REFRESH_FAILURES = 3

_STATUS_LIVE = "live"
_STATUS_EXPIRING = "expiring"
_STATUS_DEAD = "dead"

_TYPE_OAUTH2 = "oauth2"
_TYPE_JWT = "jwt"
_TYPE_COOKIE = "cookie"
_TYPE_BASIC = "basic"
_TYPE_APIKEY = "apikey"
_TYPE_BEARER_STATIC = "bearer_static"
_TYPE_NTLM = "ntlm"
_TYPE_CUSTOM = "custom"

_STATIC_TYPES = frozenset((_TYPE_BASIC, _TYPE_APIKEY, _TYPE_BEARER_STATIC))


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _decode_jwt_payload(token: str) -> dict | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = parts[1]
        pad = 4 - len(payload) % 4
        if pad != 4:
            payload += "=" * pad
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return None


def _mask_token(tok: str, visible: int = 8) -> str:
    if not tok:
        return ""
    if len(tok) <= visible:
        return "****"
    return tok[:visible] + "****"


class Session:
    """A single managed authentication session."""

    def __init__(self, *, session_id: str | None = None,
                 label: str = "", auth_type: str = _TYPE_CUSTOM,
                 framework: str = "", origin_tool: str = "",
                 scope: str = "", target_url: str = "",
                 access_token: str = "", refresh_token: str = "",
                 cookies: dict | None = None, headers: dict | None = None,
                 credentials: dict | None = None,
                 token_endpoint: str = "", refresh_endpoint: str = "",
                 heartbeat_url: str = "", expires_at: float | None = None,
                 jwt_claims: dict | None = None):
        self.id = session_id or uuid.uuid4().hex
        self.label = label
        self.auth_type = auth_type
        self.framework = framework
        self.origin_tool = origin_tool
        self.scope = scope
        self.target_url = target_url
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.credentials = credentials or {}
        self.token_endpoint = token_endpoint
        self.refresh_endpoint = refresh_endpoint or token_endpoint
        self.heartbeat_url = heartbeat_url
        self.expires_at = expires_at
        self.jwt_claims = jwt_claims or {}
        self.status = _STATUS_LIVE
        self.started_at = _now_iso()
        self.last_refresh = _now_iso()
        self.died_at: str | None = None
        self.death_reason: str | None = None
        self.refresh_failures = 0
        self.refresh_history: list[dict] = []
        self.consumers: list[str] = []
        self._lock = threading.Lock()

        if self.access_token and not self.jwt_claims:
            claims = _decode_jwt_payload(self.access_token)
            if claims:
                self.jwt_claims = claims
                if not self.expires_at and "exp" in claims:
                    self.expires_at = float(claims["exp"])

        if not self.label:
            self.label = f"{self.auth_type} — {self.origin_tool or 'manual'}"

    def is_static(self) -> bool:
        return self.auth_type in _STATIC_TYPES

    def seconds_until_expiry(self) -> float | None:
        if self.expires_at is None:
            return None
        return self.expires_at - time.time()

    def mark_dead(self, reason: str):
        with self._lock:
            self.status = _STATUS_DEAD
            self.died_at = _now_iso()
            self.death_reason = reason

    def mark_refreshed(self, new_token: str | None = None,
                       new_expires: float | None = None):
        with self._lock:
            self.last_refresh = _now_iso()
            self.refresh_failures = 0
            if new_token:
                self.access_token = new_token
                claims = _decode_jwt_payload(new_token)
                if claims:
                    self.jwt_claims = claims
            if new_expires is not None:
                self.expires_at = new_expires
            elif self.jwt_claims.get("exp"):
                self.expires_at = float(self.jwt_claims["exp"])
            self.status = _STATUS_LIVE
            self.refresh_history.append({
                "ts": self.last_refresh,
                "outcome": "success",
                "new_expiry": datetime.fromtimestamp(
                    self.expires_at, tz=timezone.utc).isoformat()
                if self.expires_at else None,
            })

    def record_refresh_failure(self, reason: str):
        with self._lock:
            self.refresh_failures += 1
            self.refresh_history.append({
                "ts": _now_iso(),
                "outcome": "failure",
                "reason": reason,
            })
            if self.refresh_failures >= _MAX_REFRESH_FAILURES:
                self.status = _STATUS_DEAD
                self.died_at = _now_iso()
                self.death_reason = f"Refresh exhausted after {self.refresh_failures} failures: {reason}"

    def add_consumer(self, tool_id: str):
        with self._lock:
            if tool_id and tool_id not in self.consumers:
                self.consumers.append(tool_id)

    def to_dict(self, *, include_secrets: bool = False) -> dict:
        ttl = self.seconds_until_expiry()
        d = {
            "id": self.id,
            "label": self.label,
            "auth_type": self.auth_type,
            "framework": self.framework,
            "origin_tool": self.origin_tool,
            "scope": self.scope,
            "target_url": self.target_url,
            "token_preview": _mask_token(self.access_token),
            "has_refresh_token": bool(self.refresh_token),
            "has_cookies": bool(self.cookies),
            "status": self.status,
            "started_at": self.started_at,
            "last_refresh": self.last_refresh,
            "expires_at": datetime.fromtimestamp(
                self.expires_at, tz=timezone.utc).isoformat()
            if self.expires_at else None,
            "ttl_seconds": round(ttl) if ttl is not None else None,
            "died_at": self.died_at,
            "death_reason": self.death_reason,
            "consumers": list(self.consumers),
            "refresh_failures": self.refresh_failures,
        }
        if include_secrets:
            d["access_token"] = self.access_token
            d["refresh_token"] = _mask_token(self.refresh_token)
            d["cookies"] = {k: _mask_token(v) for k, v in self.cookies.items()}
            d["headers"] = dict(self.headers)
            d["jwt_claims"] = dict(self.jwt_claims)
            d["refresh_endpoint"] = self.refresh_endpoint
            d["heartbeat_url"] = self.heartbeat_url
            d["refresh_history"] = list(self.refresh_history[-50:])
        return d

    def get_auth_for_tool(self) -> dict:
        """Return auth data a tool can use directly."""
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "cookies": dict(self.cookies),
            "headers": dict(self.headers),
            "credentials": dict(self.credentials),
            "auth_type": self.auth_type,
            "expires_at": self.expires_at,
        }


class SessionManager:
    """Per-project session keepalive manager."""

    def __init__(self, project_id: str):
        self.project_id = project_id
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()
        self._timer: threading.Timer | None = None
        self._running = False

    def start(self):
        self._running = True
        self._schedule_check()
        log.info("session-mgr: started for %s", self.project_id[:8])

    def stop(self):
        self._running = False
        if self._timer:
            self._timer.cancel()
            self._timer = None
        log.info("session-mgr: stopped for %s", self.project_id[:8])

    def _schedule_check(self):
        if not self._running:
            return
        self._timer = threading.Timer(_CHECK_INTERVAL_S, self._check_loop)
        self._timer.daemon = True
        self._timer.start()

    def _check_loop(self):
        if not self._running:
            return
        with self._lock:
            sessions = list(self._sessions.values())
        for sess in sessions:
            if sess.status == _STATUS_DEAD:
                continue
            if sess.is_static() and not sess.heartbeat_url:
                continue
            if sess.is_static() and sess.heartbeat_url:
                self._heartbeat_session(sess)
                continue
            ttl = sess.seconds_until_expiry()
            if ttl is not None and ttl < 300 and sess.status == _STATUS_LIVE:
                sess.status = _STATUS_EXPIRING
            if ttl is not None and ttl <= _REFRESH_MARGIN_S:
                self._refresh_session(sess)
            elif sess.heartbeat_url:
                self._heartbeat_session(sess)
        self._schedule_check()

    def _refresh_session(self, sess: Session):
        try:
            if sess.auth_type == _TYPE_OAUTH2 and sess.refresh_token:
                self._refresh_oauth2(sess)
            elif sess.auth_type == _TYPE_JWT and sess.credentials:
                self._reauth_jwt(sess)
            elif sess.auth_type == _TYPE_COOKIE:
                self._heartbeat_session(sess)
            else:
                sess.mark_dead("No refresh strategy available")
        except Exception as exc:
            sess.record_refresh_failure(str(exc))
            log.debug("session-mgr: refresh failed for %s: %s", sess.id[:8], exc)

    def _refresh_oauth2(self, sess: Session):
        data = {
            "grant_type": "refresh_token",
            "refresh_token": sess.refresh_token,
        }
        if sess.credentials.get("client_id"):
            data["client_id"] = sess.credentials["client_id"]
        if sess.credentials.get("client_secret"):
            data["client_secret"] = sess.credentials["client_secret"]

        ep = sess.refresh_endpoint or sess.token_endpoint
        if not ep:
            sess.record_refresh_failure("No token endpoint configured")
            return

        resp = requests.post(ep, data=data, verify=False, timeout=15)
        if resp.status_code != 200:
            sess.record_refresh_failure(f"HTTP {resp.status_code}: {resp.text[:200]}")
            return

        body = resp.json()
        new_access = body.get("access_token", "")
        new_refresh = body.get("refresh_token")
        expires_in = body.get("expires_in")
        new_exp = time.time() + int(expires_in) if expires_in else None

        if not new_access:
            sess.record_refresh_failure("Empty access_token in response")
            return

        sess.mark_refreshed(new_token=new_access, new_expires=new_exp)
        if new_refresh:
            sess.refresh_token = new_refresh
        log.info("session-mgr: oauth2 refreshed %s", sess.id[:8])

    def _reauth_jwt(self, sess: Session):
        ep = sess.token_endpoint
        if not ep:
            sess.record_refresh_failure("No token endpoint for re-auth")
            return

        creds = sess.credentials
        payload = {}
        for k in ("username", "email", "password", "client_id", "client_secret"):
            if creds.get(k):
                payload[k] = creds[k]

        resp = requests.post(ep, json=payload, verify=False, timeout=15)
        if resp.status_code not in (200, 201):
            sess.record_refresh_failure(f"Re-auth HTTP {resp.status_code}")
            return

        body = resp.json()
        new_token = (body.get("access_token") or body.get("token")
                     or body.get("jwt") or body.get("id_token") or "")
        if not new_token:
            for v in body.values():
                if isinstance(v, str) and v.count(".") == 2 and len(v) > 50:
                    new_token = v
                    break
        if not new_token:
            sess.record_refresh_failure("No token in re-auth response")
            return

        expires_in = body.get("expires_in")
        new_exp = time.time() + int(expires_in) if expires_in else None
        sess.mark_refreshed(new_token=new_token, new_expires=new_exp)
        log.info("session-mgr: jwt re-auth refreshed %s", sess.id[:8])

    def _heartbeat_session(self, sess: Session):
        url = sess.heartbeat_url or sess.target_url
        if not url:
            return

        hdrs = dict(sess.headers)
        jar = requests.cookies.RequestsCookieJar()
        for name, val in sess.cookies.items():
            jar.set(name, val)

        try:
            resp = requests.get(url, headers=hdrs, cookies=jar,
                                verify=False, timeout=10, allow_redirects=False)
            if resp.status_code in (401, 403):
                sess.record_refresh_failure(f"Heartbeat returned {resp.status_code}")
            else:
                new_cookies = {k: v for k, v in resp.cookies.items()}
                if new_cookies:
                    sess.cookies.update(new_cookies)
                sess.mark_refreshed()
                log.debug("session-mgr: heartbeat OK for %s", sess.id[:8])
        except Exception as exc:
            sess.record_refresh_failure(f"Heartbeat error: {exc}")

    def register_session(self, **kwargs) -> Session:
        sess = Session(**kwargs)
        with self._lock:
            self._sessions[sess.id] = sess
        log.info("session-mgr: registered %s (%s) for %s",
                 sess.id[:8], sess.auth_type, self.project_id[:8])
        return sess

    def kill_session(self, session_id: str, *, revoke: bool = True) -> bool:
        with self._lock:
            sess = self._sessions.get(session_id)
        if not sess:
            return False
        if revoke and sess.auth_type == _TYPE_OAUTH2 and sess.refresh_endpoint:
            try:
                revoke_url = sess.refresh_endpoint.replace("/token", "/revoke")
                requests.post(revoke_url,
                              data={"token": sess.access_token},
                              verify=False, timeout=5)
            except Exception:
                pass
        sess.mark_dead("Manually killed")
        return True

    def kill_all(self):
        with self._lock:
            sessions = list(self._sessions.values())
        for sess in sessions:
            if sess.status != _STATUS_DEAD:
                sess.mark_dead("Kill all — manually killed")

    def remove_session(self, session_id: str) -> bool:
        with self._lock:
            return self._sessions.pop(session_id, None) is not None

    def get_session(self, session_id: str) -> Session | None:
        with self._lock:
            return self._sessions.get(session_id)

    def get_all_sessions(self) -> list[dict]:
        with self._lock:
            sessions = list(self._sessions.values())
        live = sorted(
            [s for s in sessions if s.status != _STATUS_DEAD],
            key=lambda s: s.last_refresh or "", reverse=True)
        dead = sorted(
            [s for s in sessions if s.status == _STATUS_DEAD],
            key=lambda s: s.died_at or "", reverse=True)
        return [s.to_dict() for s in live + dead]

    def get_session_detail(self, session_id: str) -> dict | None:
        sess = self.get_session(session_id)
        if not sess:
            return None
        return sess.to_dict(include_secrets=True)

    def get_auth_for_tool(self, session_id: str, tool_id: str) -> dict | None:
        sess = self.get_session(session_id)
        if not sess or sess.status == _STATUS_DEAD:
            return None
        sess.add_consumer(tool_id)
        return sess.get_auth_for_tool()

    def refresh_now(self, session_id: str) -> bool:
        sess = self.get_session(session_id)
        if not sess or sess.status == _STATUS_DEAD:
            return False
        self._refresh_session(sess)
        return sess.status != _STATUS_DEAD

    def session_count(self) -> dict:
        with self._lock:
            sessions = list(self._sessions.values())
        live = sum(1 for s in sessions if s.status != _STATUS_DEAD)
        dead = sum(1 for s in sessions if s.status == _STATUS_DEAD)
        return {"live": live, "dead": dead, "total": live + dead}


def get_manager(project_id: str) -> SessionManager | None:
    with _managers_lock:
        return _managers.get(project_id)


def ensure_manager(project_id: str) -> SessionManager:
    with _managers_lock:
        mgr = _managers.get(project_id)
        if mgr:
            return mgr
        mgr = SessionManager(project_id)
        _managers[project_id] = mgr
        mgr.start()
        return mgr


def stop_manager(project_id: str):
    with _managers_lock:
        mgr = _managers.pop(project_id, None)
    if mgr:
        mgr.stop()


def register_session(project_id: str, **kwargs) -> dict:
    mgr = ensure_manager(project_id)
    sess = mgr.register_session(**kwargs)
    return sess.to_dict()


def kill_session(project_id: str, session_id: str) -> bool:
    mgr = get_manager(project_id)
    if not mgr:
        return False
    return mgr.kill_session(session_id)


def kill_all_sessions(project_id: str):
    mgr = get_manager(project_id)
    if mgr:
        mgr.kill_all()


def get_sessions(project_id: str) -> list[dict]:
    mgr = get_manager(project_id)
    if not mgr:
        return []
    return mgr.get_all_sessions()


def get_session_detail(project_id: str, session_id: str) -> dict | None:
    mgr = get_manager(project_id)
    if not mgr:
        return None
    return mgr.get_session_detail(session_id)


def get_session_count(project_id: str) -> dict:
    mgr = get_manager(project_id)
    if not mgr:
        return {"live": 0, "dead": 0, "total": 0}
    return mgr.session_count()


def get_auth_for_tool(project_id: str, session_id: str, tool_id: str) -> dict | None:
    mgr = get_manager(project_id)
    if not mgr:
        return None
    return mgr.get_auth_for_tool(session_id, tool_id)


def refresh_session(project_id: str, session_id: str) -> bool:
    mgr = get_manager(project_id)
    if not mgr:
        return False
    return mgr.refresh_now(session_id)
