"""Crucible v2.0 — Unified Penetration Testing Platform."""

import ssl
import sys
import signal
import logging
import threading
import traceback
from datetime import timedelta
from pathlib import Path

from flask import Flask
from flask_socketio import SocketIO

VERSION = Path(__file__).resolve().parent.joinpath("VERSION").read_text().strip()

APP_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(APP_DIR))

import _auth
import config

socketio = SocketIO()


def create_app():
    app = Flask(__name__,
                static_folder=str(config.STATIC_DIR),
                template_folder=str(config.TEMPLATE_DIR))

    _secret = _auth.load_secret_key()
    app.config["SECRET_KEY"] = _secret
    import hashlib as _hl
    _inst = _hl.sha256(_secret.encode()).hexdigest()[:8]
    app.config["SESSION_COOKIE_NAME"] = f"crucible_{_inst}"
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
        minutes=config.SESSION_TIMEOUT_MINUTES)
    app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

    _auth.init_auth()

    @app.context_processor
    def _inject_globals():
        return {
            "app_version": VERSION,
            "app_name": config.APP_NAME,
            "palettes": config.PALETTES,
            "tools_config": {k: {**v, "script": str(v["script"]) if v.get("script") else None,
                                    "installed": v.get("script") is not None and Path(v["script"]).exists()}
                            for k, v in config.TOOLS.items()},
        }

    @app.before_request
    def _gate():
        return _auth.auth_gate()

    @app.after_request
    def _headers(response):
        if "Upgrade" not in response.headers:
            response.headers["Connection"] = "close"
        return _auth.apply_security_headers(response)

    from werkzeug.exceptions import HTTPException

    @app.errorhandler(HTTPException)
    def _handle_http_error(exc):
        from flask import jsonify as _jf, request as _req
        if _req.path.startswith("/api/"):
            return _jf({"error": exc.description}), exc.code
        return exc

    @app.errorhandler(Exception)
    def _handle_error(exc):
        from flask import jsonify as _jf, request as _req
        _log = logging.getLogger("crucible.error")
        _log.error("Unhandled exception on %s %s: %s",
                   _req.method, _req.path, exc, exc_info=True)
        if _req.path.startswith("/api/"):
            return _jf({"error": "Internal server error"}), 500
        return "Internal Server Error", 500

    from routes.auth import auth_bp
    from routes.home import home_bp
    from routes.project import project_bp
    from routes.console import console_bp
    from routes.findings import findings_bp
    from routes.action_items import action_items_bp
    from routes.settings import settings_bp
    from routes.logs import logs_bp
    from routes.targets import targets_bp
    from routes.intelligence import intelligence_bp
    from routes.nessus import nessus_bp
    from routes.traffic import traffic_bp
    from routes.export import export_bp
    from routes.worker import worker_bp
    from routes.integration import integration_bp
    from routes.shell import shell_bp
    from routes.standalone import standalone_bp
    from routes.report import report_bp
    from routes.importer_routes import importer_bp
    from routes.sessions import sessions_bp
    from routes.attack_surface import attack_surface_bp
    from routes.burp_import import burp_import_bp

    for bp in (auth_bp, home_bp, project_bp, console_bp, findings_bp,
               action_items_bp, settings_bp, logs_bp, targets_bp,
               intelligence_bp, nessus_bp, traffic_bp, export_bp,
               worker_bp, integration_bp, shell_bp, standalone_bp,
               report_bp, importer_bp, sessions_bp,
               attack_surface_bp, burp_import_bp):
        app.register_blueprint(bp)

    try:
        from routes.intelligence_v2 import intel_v2
        app.register_blueprint(intel_v2)
    except ImportError:
        pass

    socketio.init_app(app, cors_allowed_origins=[],
                      async_mode="threading", manage_session=False)

    from services.process_manager import ProcessManager
    from services.queue_manager import QueueManager
    from services.worker_delegate import WorkerDelegate
    from services.findings_engine import FindingsEngine
    from services.action_engine import ActionEngine
    from services.scope_manager import ScopeManager

    fe = FindingsEngine()
    sm = ScopeManager()
    ae = ActionEngine(scope_manager=sm)
    pm = ProcessManager(socketio)
    qm = QueueManager(process_manager=pm, app=app)
    pm.set_queue_manager(qm)
    pm.set_action_engine(ae)
    pm.set_findings_engine(fe)
    fe.set_action_engine(ae)
    wd = WorkerDelegate(socketio=socketio, process_manager=pm,
                        findings_engine=fe)

    app.extensions["process_manager"] = pm
    app.extensions["queue_manager"] = qm
    app.extensions["socketio"] = socketio
    app.extensions["worker_delegate"] = wd
    app.extensions["findings_engine"] = fe
    app.extensions["action_engine"] = ae
    app.extensions["scope_manager"] = sm

    from services.importer import ImporterService
    imp = ImporterService(socketio=socketio, findings_engine=fe,
                          action_engine=ae, scope_manager=sm)
    app.extensions["importer"] = imp

    from services.kev_enricher import KEVEnricher
    kev = KEVEnricher()
    fe.set_kev_enricher(kev)
    kev.start()
    app.extensions["kev_enricher"] = kev

    def _kev_backfill():
        import time as _t
        _t.sleep(10)
        kev.backfill(fe, app)
    threading.Thread(target=_kev_backfill, name="kev-backfill",
                     daemon=True).start()

    from services.scheduler import SchedulerService
    sched = SchedulerService(process_manager=pm, queue_manager=qm, app=app)
    sched.start()
    app.extensions["scheduler"] = sched

    from models.action_items import get_store as _get_ai_store
    ai_store = _get_ai_store()
    ai_store.start_reconciliation_loop(app, interval=300)
    app.extensions["action_item_store"] = ai_store

    pm.startup_recovery(app)

    from services.beacon_client import start_beacon as _start_beacon
    from models.project import list_projects
    try:
        for proj in list_projects():
            pid = proj.get("id")
            if pid and proj.get("beacon_enabled") and proj.get("beacon_url"):
                _start_beacon(pid, app)
    except Exception as exc:
        log.debug("beacon startup: %s", exc)

    from sockets.connection import register_connection_events
    from sockets.tools import register_tool_events
    from sockets.prompts import register_prompt_events
    from sockets.workers import register_worker_events
    from sockets.shell import register_shell_events
    register_connection_events(socketio)
    register_tool_events(socketio, pm, qm)
    register_prompt_events(socketio, pm)
    register_worker_events(socketio, wd)
    register_shell_events(socketio)

    from sockets.importer_events import register_importer_events
    register_importer_events(socketio, imp)

    return app


def _setup_logging():
    """Configure logging infrastructure — file + console.

    Without this, every log.info/debug/warning call is invisible because
    the root logger defaults to WARNING with no handlers.
    """
    from logging.handlers import RotatingFileHandler

    log_dir = APP_DIR / "logs"
    log_dir.mkdir(exist_ok=True)
    log_file = log_dir / "crucible.log"

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S")

    fh = RotatingFileHandler(
        str(log_file), maxBytes=10 * 1024 * 1024, backupCount=5,
        encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    ch = logging.StreamHandler()
    ch.setLevel(logging.WARNING)
    ch.setFormatter(fmt)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(fh)
    root.addHandler(ch)

    from services.engagement_log_handler import EngagementLogHandler
    eh = EngagementLogHandler(level=logging.INFO)
    eh.setFormatter(fmt)
    root.addHandler(eh)

    logging.getLogger("engineio").setLevel(logging.WARNING)
    logging.getLogger("socketio").setLevel(logging.WARNING)


def main():
    _setup_logging()
    app = create_app()
    log = logging.getLogger("werkzeug")
    log.setLevel(logging.WARNING)

    from werkzeug.serving import WSGIRequestHandler

    class _QuietHandler(WSGIRequestHandler):
        def handle(self):
            try:
                return super().handle()
            except (ssl.SSLError, ConnectionResetError, BrokenPipeError, OSError) as exc:
                print(f"  [TLS] {type(exc).__name__}: {exc}")

        def run_wsgi(self):
            _srv = self.server
            _real_log = _srv.log
            def _filtered_log(type, message, *args):
                if type == "error" and "write() before start_response" in message:
                    return
                _real_log(type, message, *args)
            _srv.log = _filtered_log
            try:
                return super().run_wsgi()
            except AssertionError as exc:
                if "write() before start_response" in str(exc):
                    pass
                else:
                    raise
            finally:
                _srv.log = _real_log

    _ssl = _auth.make_ssl_context()

    # Override server_bind to skip socket.getfqdn() which does a 30s
    # reverse DNS lookup on 0.0.0.0 when the system's rDNS is broken.
    import http.server as _hs
    import socketserver as _ss
    def _fast_server_bind(self):
        _ss.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = host or "localhost"
        self.server_port = port
    _hs.HTTPServer.server_bind = _fast_server_bind

    def _sigterm(signum, frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, _sigterm)

    print(f"\n  Crucible v{VERSION}")
    print(f"  https://0.0.0.0:{config.PORT}\n")

    socketio.run(app, host="0.0.0.0", port=config.PORT, debug=False,
                 allow_unsafe_werkzeug=True,
                 request_handler=_QuietHandler,
                 ssl_context=_ssl)


if __name__ == "__main__":
    main()
