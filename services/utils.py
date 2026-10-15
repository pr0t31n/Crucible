"""Shared utility functions for Crucible services."""

from datetime import datetime


def now_iso() -> str:
    return datetime.now().isoformat()


def now_ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def project_room(project_id: str) -> str:
    return f"project:{project_id}"
