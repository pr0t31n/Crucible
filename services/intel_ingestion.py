"""Intel ingestion — DISABLED.

All intelligence data flows through tokens → DB in real time.
JSON file ingestion has been removed.

The ingest_all() and ingest_single() entry points are kept as no-ops
so callers (e.g. the /api/intel/v2/reingest/ migration endpoint) do
not crash.  They do nothing.
"""

import logging

log = logging.getLogger(__name__)

_AVAILABLE = True


def is_available():
    return _AVAILABLE


def ingest_all(db, project_dir, tool_dirs=None, scope_tool_dirs=None):
    log.debug("ingest_all: no-op — JSON ingestion disabled")


def ingest_single(db, project_dir, tool_id, tool_output_dir,
                  scope=None, ingestors=None):
    log.debug("ingest_single: no-op — JSON ingestion disabled")
