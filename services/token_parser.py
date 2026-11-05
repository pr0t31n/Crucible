"""Unified protocol-token parser for Crucible v2.

All tools emit __CRUCIBLE_*__ tokens when CRUCIBLE_MANAGED=1.
Legacy __VANTAGE_*__ and __SPECTRE_*__ prefixes are still parsed
for backward compatibility with older tool versions.

Thread-safe: no mutable instance state.
"""

import json

from services.utils import now_iso as _now_iso

# ── prefix → (token_type, family) ───────────────────────────────────────

_PREFIXES: list[tuple[str, str, str]] = sorted(
    [
        # Crucible (colon-delimited) ──────────────────────────────────────
        ("__CRUCIBLE_ACTION_ITEM__:", "action_item", "crucible"),
        ("__CRUCIBLE_FINDING__:",     "finding",     "crucible"),
        ("__CRUCIBLE_PORT__:",        "port",        "crucible"),
        ("__CRUCIBLE_TARGET__:",      "target",      "crucible"),
        ("__CRUCIBLE_PROMPT__:",      "prompt",      "crucible"),
        ("__CRUCIBLE_STATUS__:",      "status",      "crucible"),
        ("__CRUCIBLE_LOG__:",         "log",         "crucible"),
        ("__CRUCIBLE_ERR__:",         "error",       "crucible"),
        # Legacy backward-compat: __VANTAGE_*__ tokens from pre-Crucible tools
        ("__VANTAGE_ACTION_ITEM__:",  "action_item", "vantage"),
        ("__VANTAGE_FINDING__:",      "finding",     "vantage"),
        ("__VANTAGE_PROMPT__:",       "prompt",      "vantage"),
        ("__VANTAGE_STATUS__:",       "status",      "vantage"),
        ("__VANTAGE_TARGET__:",       "target",      "vantage"),
        ("__VANTAGE_LOG__:",          "log",         "vantage"),
        ("__VANTAGE_ERR__:",          "error",       "vantage"),
        ("__VANTAGE_PORT__:",         "port",        "vantage"),
        # Spectre (space-delimited) ───────────────────────────────────────
        ("__SPECTRE_FINDING__ ",      "finding",     "spectre"),
        ("__SPECTRE_PROMPT__ ",       "prompt",      "spectre"),
        ("__SPECTRE_STATUS__ ",       "status",      "spectre"),
        ("__SPECTRE_LOG__ ",          "log",         "spectre"),
        ("__SPECTRE_ERR__ ",          "error",       "spectre"),
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
        *prefix_family*:  "crucible" | "vantage" (legacy) | "spectre"
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

        Crucible family (and legacy Vantage) expect JSON payloads.  Spectre uses
        JSON for ``status`` and ``finding`` tokens but plain text for
        ``log``, ``error``, and ``prompt``.

        A ``"ts"`` key is always present in the returned dict (set to
        *now* when the payload does not supply one).
        """
        result: dict

        if prefix_family == "spectre":
            result = self._parse_spectre(token_type, payload)
        else:
            # crucible / vantage (legacy) — always JSON
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

    @staticmethod
    def _parse_spectre(token_type: str, payload: str) -> dict:
        """Decode a Spectre-family payload.

        ``status`` and ``finding`` tokens are JSON; everything else is
        plain text wrapped in ``{"message": ...}``.
        """
        if token_type in ("status", "finding"):
            try:
                obj = json.loads(payload)
                if isinstance(obj, dict):
                    return obj
                return {"message": obj}
            except (json.JSONDecodeError, ValueError):
                return {"message": payload}
        return {"message": payload}
