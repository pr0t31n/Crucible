"""Unified protocol-token parser for Crucible v2.

All tools emit __CRUCIBLE_*__ tokens when CRUCIBLE_MANAGED=1.

Thread-safe: no mutable instance state.
"""

import json

from services.utils import now_iso as _now_iso

# ── prefix → (token_type, family) ───────────────────────────────────────

_PREFIXES: list[tuple[str, str, str]] = sorted(
    [
        ("__CRUCIBLE_ACTION_ITEM__:", "action_item", "crucible"),
        ("__CRUCIBLE_FINDING__:",     "finding",     "crucible"),
        ("__CRUCIBLE_PORT__:",        "port",        "crucible"),
        ("__CRUCIBLE_TARGET__:",      "target",      "crucible"),
        ("__CRUCIBLE_PROMPT__:",      "prompt",      "crucible"),
        ("__CRUCIBLE_STATUS__:",      "status",      "crucible"),
        ("__CRUCIBLE_LOG__:",         "log",         "crucible"),
        ("__CRUCIBLE_ERR__:",         "error",       "crucible"),
    ],
    key=lambda t: -len(t[0]),
)


class TokenParser:
    """Stateless, thread-safe parser for tool protocol tokens."""

    # Expose the table for introspection (read-only; tuple list is immutable).
    TOKEN_PREFIXES = _PREFIXES

    # ── public API ───────────────────────────────────────────────────────

    def is_token(self, line: str) -> bool:
        """Quick check — does *line* start with any known token prefix?"""
        for prefix, _, _ in _PREFIXES:
            if line.startswith(prefix):
                return True
        return False

    def parse_line(self, line: str) -> tuple:
        """Parse a single stdout line.

        Returns ``(token_type, prefix_family, payload)`` when the line
        carries a recognised token, or ``(None, None, None)`` otherwise.

        *token_type*:     "log" | "error" | "prompt" | "status" |
                          "action_item" | "target" | "port" | "finding"
        *prefix_family*:  "crucible"
        *payload*:        raw string after the prefix (stripped of leading
                          whitespace).
        """
        for prefix, token_type, family in _PREFIXES:
            if line.startswith(prefix):
                payload = line[len(prefix):].lstrip()
                return token_type, family, payload
        return None, None, None

    def parse_payload(self, token_type: str, prefix_family: str,
                      payload: str) -> dict:
        """Decode *payload* into a structured dict.

        All tokens use JSON payloads.

        A ``"ts"`` key is always present in the returned dict (set to
        *now* when the payload does not supply one).
        """
        result = self._try_json(payload)

        if "ts" not in result:
            result["ts"] = _now_iso()

        return result

    # ── internals ────────────────────────────────────────────────────────

    @staticmethod
    def _try_json(payload: str) -> dict:
        """Attempt JSON decode; fall back to ``{"message": payload}``."""
        try:
            obj = json.loads(payload)
            if isinstance(obj, dict):
                return obj
            return {"message": obj}
        except (json.JSONDecodeError, ValueError):
            return {"message": payload}
