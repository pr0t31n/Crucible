"""Base parser class for all tool-output import parsers."""

from pathlib import Path


class BaseParser:
    """Abstract parser that all tool parsers inherit from.

    Subclasses set TOOL_ID, TOOL_NAME, SUPPORTED_FORMATS, then implement
    parse() and extract_targets().
    """

    TOOL_ID = ""
    TOOL_NAME = ""
    SUPPORTED_FORMATS = []

    def __init__(self, file_path, emit_fn=None):
        self.file_path = Path(file_path)
        self.emit = emit_fn or (lambda *a, **kw: None)

    def parse(self):
        """Yield (item_type, data) tuples.

        item_type is one of:
          'finding'  — vulnerability finding dict
          'target'   — discovered host/domain dict
          'port'     — discovered port/service dict
          'intel'    — intelligence item (subdomain, email, etc.)
          'log'      — informational log line (str)
        """
        raise NotImplementedError

    def extract_targets(self):
        """Quick-scan file to extract IPs/domains for scope detection.
        Should be fast — no full parse needed.
        Returns set of target strings (IPs and/or hostnames)."""
        raise NotImplementedError
