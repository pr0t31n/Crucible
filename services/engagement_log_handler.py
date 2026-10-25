"""EngagementLogHandler — routes Python logging into per-engagement JSONL.

Thread-local storage tracks which engagement each thread belongs to.
The handler writes qualifying records (INFO+ from crucible.* loggers)
to the active engagement's crucible_logs.jsonl / crucible_errors.jsonl.
"""

import logging
import threading
from datetime import datetime, timezone

_ctx = threading.local()

_ERROR_LEVELS = {"ERROR", "EXCEPTION", "TOOL_ERROR", "FATAL", "CRITICAL"}
_LEVEL_MAP = {
    logging.DEBUG: "DEBUG",
    logging.INFO: "INFO",
    logging.WARNING: "WARNING",
    logging.ERROR: "ERROR",
    logging.CRITICAL: "CRITICAL",
}


def set_engagement_context(project_id: str, project_dir: str,
                           tool_id: str = "crucible") -> None:
    _ctx.project_id = project_id
    _ctx.project_dir = project_dir
    _ctx.tool_id = tool_id


def clear_engagement_context() -> None:
    _ctx.project_id = None
    _ctx.project_dir = None
    _ctx.tool_id = None


class EngagementLogHandler(logging.Handler):
    """Writes crucible.* log records into the active engagement's JSONL."""

    def __init__(self, level=logging.INFO):
        super().__init__(level)
        self._in_emit = threading.local()

    def emit(self, record: logging.LogRecord) -> None:
        if not getattr(record, "name", "").startswith("crucible"):
            return
        if getattr(self._in_emit, "active", False):
            return
        project_dir = getattr(_ctx, "project_dir", None)
        if not project_dir:
            return
        tool_id = getattr(_ctx, "tool_id", None) or "crucible"
        level_str = _LEVEL_MAP.get(record.levelno, record.levelname)
        entry = {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "tool": tool_id,
            "level": level_str,
            "message": self.format(record),
            "source": "crucible-internal",
            "logger": record.name,
        }
        self._in_emit.active = True
        try:
            from models.logs import append_log, append_error
            append_log(project_dir, entry)
            if level_str in _ERROR_LEVELS:
                append_error(project_dir, entry)
        except Exception:
            pass
        finally:
            self._in_emit.active = False
