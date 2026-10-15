"""Logs model — log/error entry management with time-range filtering."""

import json
from datetime import datetime
from pathlib import Path

# Error levels that count for pill badges (per CLAUDE.md §14g)
ERROR_LEVELS = {"ERROR", "EXCEPTION", "TOOL_ERROR", "FATAL", "CRITICAL"}


def load_logs(project_dir, from_dt=None, to_dt=None, tool_filter=None,
              level_filter=None):
    """Load log entries from crucible_logs.jsonl.
    Apply optional time-range, tool, and level filters.
    Returns list of log entry dicts, newest first."""
    entries = _load_jsonl(Path(project_dir) / "crucible_logs.jsonl")
    if tool_filter:
        entries = [e for e in entries if e.get("tool") == tool_filter]
    if level_filter:
        lf = level_filter.upper()
        entries = [e for e in entries
                   if (e.get("level") or "INFO").upper() == lf]
    entries = _apply_time_filter(entries, from_dt, to_dt)
    entries.reverse()  # newest first
    return entries


def load_errors(project_dir, from_dt=None, to_dt=None, tool_filter=None,
                level_filter=None):
    """Load error entries from crucible_errors.jsonl.
    Apply optional time-range, tool, and level filters."""
    entries = _load_jsonl(Path(project_dir) / "crucible_errors.jsonl")
    if tool_filter:
        entries = [e for e in entries if e.get("tool") == tool_filter]
    if level_filter:
        lf = level_filter.upper()
        entries = [e for e in entries
                   if (e.get("level") or "ERROR").upper() == lf]
    entries = _apply_time_filter(entries, from_dt, to_dt)
    entries.reverse()
    return entries


def append_log(project_dir, entry):
    """Append a log entry to crucible_logs.jsonl."""
    _append_jsonl(Path(project_dir) / "crucible_logs.jsonl", entry)


def append_error(project_dir, entry):
    """Append an error entry to crucible_errors.jsonl."""
    _append_jsonl(Path(project_dir) / "crucible_errors.jsonl", entry)


def count_errors(entries):
    """Count only ERROR-level entries (for pill badge per §14g)."""
    return sum(1 for e in entries if e.get("level", "").upper() in ERROR_LEVELS)


def clear_logs(project_dir):
    fp = Path(project_dir) / "crucible_logs.jsonl"
    if fp.exists():
        fp.unlink()


def clear_errors(project_dir):
    fp = Path(project_dir) / "crucible_errors.jsonl"
    if fp.exists():
        fp.unlink()


def _load_jsonl(file_path):
    if not file_path.exists():
        return []
    entries = []
    with open(file_path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return entries


def _append_jsonl(file_path, entry):
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, "a") as f:
        f.write(json.dumps(entry) + "\n")


def _apply_time_filter(entries, from_dt, to_dt):
    if not from_dt and not to_dt:
        return entries
    filtered = []
    for e in entries:
        ts_str = e.get("ts", "")
        if not ts_str:
            filtered.append(e)
            continue
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            filtered.append(e)
            continue
        if from_dt and ts < from_dt:
            continue
        if to_dt and ts > to_dt:
            continue
        filtered.append(e)
    return filtered


def parse_dt_arg(dt_str):
    """Parse a datetime-local string (HTML5 format) into a datetime object.
    Returns None if empty/invalid."""
    if not dt_str:
        return None
    try:
        return datetime.fromisoformat(dt_str)
    except (ValueError, TypeError):
        return None
