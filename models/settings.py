"""Settings model — per-tool settings read/write with defaults."""

import json
from pathlib import Path


def get_tool_defaults(tool_id):
    """Get default settings for a tool via its adapter."""
    from adapters import get_adapter
    adapter = get_adapter(tool_id)
    if adapter:
        return adapter.default_settings()
    return {}


def load_settings(project_dir, tool_id, scope=None):
    """Load settings for a tool, merging with defaults."""
    from config import TOOL_SETTINGS_PREFIX
    from adapters import get_adapter
    prefix = TOOL_SETTINGS_PREFIX.get(tool_id, tool_id)
    if scope:
        fp = Path(project_dir) / f"{prefix}_settings_{scope}.json"
        if not fp.exists():
            fp = Path(project_dir) / f"{prefix}_settings.json"
    else:
        fp = Path(project_dir) / f"{prefix}_settings.json"
    defaults = get_tool_defaults(tool_id)
    if fp.exists():
        with open(fp) as f:
            saved = json.load(f)
        adapter = get_adapter(tool_id)
        if adapter:
            saved = adapter.from_tool_format(saved)
        merged = {**defaults, **saved}
        for key in defaults:
            if isinstance(defaults[key], dict) and isinstance(saved.get(key), dict):
                merged[key] = {**defaults[key], **saved[key]}
        return merged
    return defaults


def save_settings(project_dir, tool_id, settings):
    """Save tool settings — transforms to tool format before writing."""
    from config import TOOL_SETTINGS_PREFIX
    from adapters import get_adapter
    prefix = TOOL_SETTINGS_PREFIX.get(tool_id, tool_id)
    fp = Path(project_dir) / f"{prefix}_settings.json"
    fp.parent.mkdir(parents=True, exist_ok=True)
    adapter = get_adapter(tool_id)
    if adapter:
        tool_data = adapter.to_tool_format(settings)
    else:
        tool_data = settings
    existing = {}
    if fp.exists():
        try:
            with open(fp) as f:
                existing = json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    _deep_merge(existing, tool_data)
    with open(fp, "w") as f:
        json.dump(existing, f, indent=2)


def _deep_merge(base, updates):
    """Recursively merge updates into base dict."""
    for k, v in updates.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v


def get_settings_schema(tool_id):
    """Get the UI schema for a tool's settings form."""
    from adapters import get_adapter
    adapter = get_adapter(tool_id)
    if adapter:
        return adapter.settings_schema()
    return {"fields": []}


def validate_settings(tool_id, settings):
    """Basic validation: check required fields from schema."""
    schema = get_settings_schema(tool_id)
    errors = []
    for field in schema.get("fields", []):
        if field.get("required") and not settings.get(field["key"]):
            errors.append(f"{field['label']} is required")
    return errors
