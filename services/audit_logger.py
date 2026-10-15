"""Per-project audit logger — lifecycle events to disk."""

import json
import threading
import logging
from pathlib import Path
from datetime import datetime, timezone

log = logging.getLogger("crucible.audit")

_lock = threading.Lock()


def _now():
    return datetime.now(timezone.utc).isoformat()


def audit(project_dir, event, **kwargs):
    """Append one audit event to the project's audit.log + audit.log.jsonl."""
    if not project_dir:
        return
    d = Path(project_dir)
    d.mkdir(parents=True, exist_ok=True)

    ts = _now()
    details = " ".join(f"{k}={v}" for k, v in kwargs.items() if v is not None)
    line = f"[{ts}] {event}" + (f"  {details}" if details else "") + "\n"

    entry = {"ts": ts, "event": event}
    entry.update({k: v for k, v in kwargs.items() if v is not None})

    with _lock:
        try:
            with open(d / "audit.log", "a") as f:
                f.write(line)
        except OSError:
            log.warning("Failed to write audit.log in %s", project_dir)

        try:
            with open(d / "audit.log.jsonl", "a") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except OSError:
            log.warning("Failed to write audit.log.jsonl in %s", project_dir)
