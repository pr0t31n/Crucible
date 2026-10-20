"""Action items model — CRUD, dedup, persistence.

v2 architecture: ActionItemStore holds an in-memory cache per project,
backed by the project-root action_items.json as the single source of
truth.  Reads serve from cache; writes mutate cache and persist.
A background reconciliation sweep picks up tool-written files without
blocking user requests.
"""

import json
import re
import uuid
import threading
import time
import logging
from datetime import datetime
from pathlib import Path

_ai_lock = threading.Lock()
log = logging.getLogger("crucible.action_items")

_URL_SCHEME_RE = re.compile(r'^https?://')


def _sanitize_ip(ip_str):
    """Strip URL scheme and trailing slash/port from an IP field."""
    if not ip_str or not isinstance(ip_str, str):
        return ip_str
    cleaned = _URL_SCHEME_RE.sub('', ip_str).rstrip('/')
    if ':' in cleaned and not cleaned.startswith('['):
        cleaned = cleaned.rsplit(':', 1)[0]
    trail = re.search(r'(https?|ftp)$', cleaned)
    if trail:
        cleaned = cleaned[:trail.start()]
    return cleaned


def _load_from_file(fp):
    """Load a single action_items.json file."""
    if not fp.exists():
        return []
    try:
        with open(fp) as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


# ── Dedup / normalization helpers ────────────────────────────────────

_DEFAULT_PORTS = {"https": "443", "http": "80"}


def _normalize_target(raw):
    if not raw:
        return ""
    raw = raw.strip().rstrip("/").lower()
    from urllib.parse import urlparse
    if "://" in raw:
        p = urlparse(raw)
        host = p.hostname or ""
        port = str(p.port) if p.port else _DEFAULT_PORTS.get(p.scheme, "")
        if host and port:
            return f"{host}:{port}"
        return host or raw
    if ":" in raw and not raw.startswith("["):
        return raw
    return raw


def _dedup_key(item):
    return (
        (item.get("recommended_tool") or "").lower(),
        _normalize_target(item.get("target") or ""),
    )


_DNS_RESOLVERS = frozenset({
    "1.1.1.1", "1.0.0.1", "1.0.1.1",
    "8.8.8.8", "8.8.4.4",
    "9.9.9.9", "9.9.9.10",
    "208.67.222.222", "208.67.220.220",
    "64.6.64.6", "64.6.65.6",
    "149.112.112.112",
    "185.228.168.9", "185.228.169.9",
    "77.88.8.8", "77.88.8.1",
    "4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4", "4.2.2.5", "4.2.2.6",
    "76.76.19.19", "76.223.122.150",
    "94.140.14.14", "94.140.15.15",
    "199.85.126.10", "199.85.127.10",
    "156.154.70.1", "156.154.71.1",
})

_VALID_OOS_TOOLS = frozenset({"ss3", "fracture", "siphon"})


def _item_ip(item):
    ip = item.get("ip")
    if ip and isinstance(ip, str):
        return ip.strip().lower()
    target = item.get("target", "")
    if not target:
        return ""
    return _sanitize_ip(target).strip().lower()


def _save_to_path(fp, items):
    fp = Path(fp)
    fp.parent.mkdir(parents=True, exist_ok=True)
    with open(fp, "w") as f:
        json.dump(items, f, indent=2)


# ═══════════════════════════════════════════════════════════════════════
# ActionItemStore — in-memory cached store per project
# ═══════════════════════════════════════════════════════════════════════

class ActionItemStore:
    """In-memory cache for action items, backed by project-root JSON.

    All reads serve from cache.  Writes mutate cache + persist to the
    master file.  A periodic reconciliation sweep merges items from
    tool output directories without blocking user requests.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._stores = {}       # project_dir → list[dict]
        self._keys = {}         # project_dir → set of dedup keys
        self._dirty = set()     # project_dirs needing persist
        self._reconcile_thread = None
        self._stop = threading.Event()

    def shutdown(self):
        self._stop.set()
        if self._reconcile_thread:
            self._reconcile_thread.join(timeout=5)

    # ── Cache management ────────────────────────────────────

    def _master_path(self, project_dir):
        return Path(project_dir) / "action_items.json"

    def _ensure_loaded(self, project_dir):
        """Load from master file if not yet cached. Caller holds _lock."""
        if project_dir in self._stores:
            return
        fp = self._master_path(project_dir)
        items = _load_from_file(fp)
        items = [i for i in items if _item_ip(i) not in _DNS_RESOLVERS]
        items = [i for i in items if "typosquat" not in
                 (i.get("title") or i.get("target") or "").lower()]
        keys = {_dedup_key(i) for i in items}
        self._stores[project_dir] = items
        self._keys[project_dir] = keys

    def _persist(self, project_dir):
        """Write cache to master file. Caller holds _lock."""
        items = self._stores.get(project_dir, [])
        _save_to_path(self._master_path(project_dir), items)
        self._dirty.discard(project_dir)

    def invalidate(self, project_dir):
        """Drop cache for a project — next access reloads from disk."""
        with self._lock:
            self._stores.pop(project_dir, None)
            self._keys.pop(project_dir, None)
            self._dirty.discard(project_dir)

    # ── Read operations (cache-backed) ──────────────────────

    def get_items(self, project_dir, tool_dirs=None):
        """Return all action items for a project."""
        with self._lock:
            self._ensure_loaded(project_dir)
            return list(self._stores.get(project_dir, []))

    def get_item(self, project_dir, item_id):
        with self._lock:
            self._ensure_loaded(project_dir)
            for item in self._stores.get(project_dir, []):
                if item.get("id") == item_id:
                    return dict(item)
        return None

    def get_items_by_status(self, project_dir, status=None):
        items = self.get_items(project_dir)
        if status:
            return [i for i in items if i.get("status") == status]
        return items

    def get_items_by_tool(self, project_dir, tool_id):
        items = self.get_items(project_dir)
        return [i for i in items if i.get("recommended_tool") == tool_id]

    def get_items_by_category(self, project_dir, category):
        items = self.get_items(project_dir)
        return [i for i in items if i.get("category") == category]

    def get_summary(self, project_dir):
        items = self.get_items(project_dir)
        by_status = {}
        by_category = {}
        by_tool = {}
        for item in items:
            s = item.get("status") or "pending"
            by_status[s] = by_status.get(s, 0) + 1
            c = item.get("category") or "other"
            by_category[c] = by_category.get(c, 0) + 1
            t = item.get("recommended_tool") or "unknown"
            by_tool[t] = by_tool.get(t, 0) + 1
        return {
            "by_status": by_status,
            "by_category": by_category,
            "by_tool": by_tool,
            "total": len(items),
            "pending": by_status.get("pending", 0),
            "queued": by_status.get("queued", 0),
            "running": by_status.get("running", 0),
            "complete": by_status.get("complete", 0),
            "dismissed": by_status.get("dismissed", 0),
        }

    # ── Write operations (cache + persist) ──────────────────

    def add_item(self, project_dir, item):
        """Add an action item if not duplicate. Returns the item or None."""
        rt = item.get("recommended_tool")
        if rt and rt != rt.lower():
            item["recommended_tool"] = rt.lower()
        p = item.get("priority", "")
        if p and p != p.upper():
            item["priority"] = p.upper()
        if item.get("ip"):
            item["ip"] = _sanitize_ip(item["ip"])
        meta = item.get("metadata")
        if isinstance(meta, dict) and meta.get("ip"):
            meta["ip"] = _sanitize_ip(meta["ip"])
        ip_val = _item_ip(item)
        if ip_val and ip_val in _DNS_RESOLVERS:
            return None

        key = _dedup_key(item)
        with self._lock:
            self._ensure_loaded(project_dir)
            if key in self._keys[project_dir]:
                return None
            item.setdefault("id", f"ai_{uuid.uuid4().hex[:12]}")
            item.setdefault("status", "pending")
            item.setdefault("created", datetime.now().isoformat())
            item.setdefault("approval_tier", "confirm")
            item.setdefault("priority", "MEDIUM")
            item.setdefault("category", "other")
            item.setdefault("in_scope", True)
            self._stores[project_dir].append(item)
            self._keys[project_dir].add(key)
            self._persist(project_dir)
            return item

    def add_items_batch(self, project_dir, items):
        """Add multiple items in one lock cycle. Returns list of added items."""
        added = []
        with self._lock:
            self._ensure_loaded(project_dir)
            for item in items:
                rt = item.get("recommended_tool")
                if rt and rt != rt.lower():
                    item["recommended_tool"] = rt.lower()
                p = item.get("priority", "")
                if p and p != p.upper():
                    item["priority"] = p.upper()
                if item.get("ip"):
                    item["ip"] = _sanitize_ip(item["ip"])
                meta = item.get("metadata")
                if isinstance(meta, dict) and meta.get("ip"):
                    meta["ip"] = _sanitize_ip(meta["ip"])
                ip_val = _item_ip(item)
                if ip_val and ip_val in _DNS_RESOLVERS:
                    continue
                key = _dedup_key(item)
                if key in self._keys[project_dir]:
                    continue
                item.setdefault("id", f"ai_{uuid.uuid4().hex[:12]}")
                item.setdefault("status", "pending")
                item.setdefault("created", datetime.now().isoformat())
                item.setdefault("approval_tier", "confirm")
                item.setdefault("priority", "MEDIUM")
                item.setdefault("category", "other")
                item.setdefault("in_scope", True)
                self._stores[project_dir].append(item)
                self._keys[project_dir].add(key)
                added.append(item)
            if added:
                self._persist(project_dir)
        return added

    def update_status(self, project_dir, item_id, new_status,
                      extra_fields=None):
        with self._lock:
            self._ensure_loaded(project_dir)
            for item in self._stores.get(project_dir, []):
                if item.get("id") == item_id:
                    item["status"] = new_status
                    item["updated"] = datetime.now().isoformat()
                    if new_status == "complete":
                        item["completed_at"] = datetime.now().isoformat()
                    elif new_status == "dismissed":
                        item["dismissed_at"] = datetime.now().isoformat()
                    if extra_fields:
                        item.update(extra_fields)
                    break
            self._persist(project_dir)

    def bulk_update_status(self, project_dir, item_ids, new_status):
        with self._lock:
            self._ensure_loaded(project_dir)
            id_set = set(item_ids)
            now = datetime.now().isoformat()
            for item in self._stores.get(project_dir, []):
                if item.get("id") in id_set:
                    item["status"] = new_status
                    item["updated"] = now
                    if new_status == "complete":
                        item["completed_at"] = now
                    elif new_status == "dismissed":
                        item["dismissed_at"] = now
            self._persist(project_dir)

    def update_tool_status(self, project_dir, tool_id, from_statuses,
                           new_status, targets=None):
        target_set = {t.strip().lower() for t in targets} if targets else None
        updated = []
        with self._lock:
            self._ensure_loaded(project_dir)
            now = datetime.now().isoformat()
            for item in self._stores.get(project_dir, []):
                rt = (item.get("recommended_tool") or "").lower()
                if rt != tool_id:
                    continue
                if item.get("status") not in from_statuses:
                    continue
                if item.get("in_scope") is False:
                    if target_set is None:
                        continue
                    item_target = (item.get("target") or
                                   item.get("ip") or "").strip().lower()
                    if item_target not in target_set:
                        continue
                item["status"] = new_status
                item["updated"] = now
                if new_status == "complete":
                    item["completed_at"] = now
                updated.append(item.get("id"))
            if updated:
                self._persist(project_dir)
        return updated

    def dismiss(self, project_dir, item_id):
        self.update_status(project_dir, item_id, "dismissed")

    def remove(self, project_dir, item_id):
        with self._lock:
            self._ensure_loaded(project_dir)
            items = self._stores.get(project_dir, [])
            self._stores[project_dir] = [
                i for i in items if i.get("id") != item_id]
            self._keys[project_dir] = {
                _dedup_key(i) for i in self._stores[project_dir]}
            self._persist(project_dir)

    def clear(self, project_dir, status_filter=None):
        with self._lock:
            self._ensure_loaded(project_dir)
            if status_filter:
                items = self._stores.get(project_dir, [])
                self._stores[project_dir] = [
                    i for i in items if i.get("status") != status_filter]
            else:
                self._stores[project_dir] = []
            self._keys[project_dir] = {
                _dedup_key(i) for i in self._stores[project_dir]}
            self._persist(project_dir)

    def clear_by_tool(self, project_dir, tool_id):
        with self._lock:
            self._ensure_loaded(project_dir)
            items = self._stores.get(project_dir, [])
            self._stores[project_dir] = [
                i for i in items
                if (i.get("recommended_tool") or "").lower() != tool_id]
            self._keys[project_dir] = {
                _dedup_key(i) for i in self._stores[project_dir]}
            self._persist(project_dir)

    def add_note(self, project_dir, item_id, note_text):
        with self._lock:
            self._ensure_loaded(project_dir)
            for item in self._stores.get(project_dir, []):
                if item.get("id") == item_id:
                    notes = item.setdefault("notes", [])
                    notes.append({
                        "ts": datetime.now().isoformat(),
                        "text": note_text,
                    })
                    item["updated"] = datetime.now().isoformat()
                    break
            self._persist(project_dir)

    # ── Repairs (in-place on cache) ─────────────────────────

    def repair_stale_running(self, project_dir, running_tools):
        updated = []
        with self._lock:
            self._ensure_loaded(project_dir)
            for item in self._stores.get(project_dir, []):
                if item.get("status") == "running":
                    tool = (item.get("recommended_tool") or "").lower()
                    if tool not in running_tools:
                        item["status"] = "pending"
                        item["updated"] = datetime.now().isoformat()
                        updated.append(item.get("id"))
            if updated:
                self._persist(project_dir)
        return updated

    def repair_oos_flags(self, project_dir, scope_checker, project):
        with self._lock:
            self._ensure_loaded(project_dir)
            items = self._stores.get(project_dir, [])
            dirty = False

            oos_ips_with_tool = set()
            for i in items:
                if i.get("category") == "oos_target":
                    rt = (i.get("recommended_tool") or "").lower()
                    if rt in _VALID_OOS_TOOLS:
                        ip = _item_ip(i)
                        if ip:
                            oos_ips_with_tool.add(ip)

            pre_len = len(items)
            items = [i for i in items if _item_ip(i) not in _DNS_RESOLVERS]
            items = [i for i in items if not (
                i.get("category") == "oos_target"
                and (i.get("recommended_tool") or "").lower()
                not in _VALID_OOS_TOOLS
                and _item_ip(i) in oos_ips_with_tool
            )]
            if len(items) != pre_len:
                dirty = True

            for item in items:
                if item.get("category") == "oos_target":
                    if item.get("in_scope") is not False:
                        item["in_scope"] = False
                        dirty = True
                    meta = item.get("metadata") or {}
                    eligible = meta.get("oos_eligible", False)
                    if item.get("priority") == "MEDIUM" and not eligible:
                        item["priority"] = "LOW"
                        dirty = True
                elif item.get("category") != "oos_target" \
                        and item.get("in_scope") is False:
                    ip = (item.get("ip")
                          or (item.get("metadata") or {}).get("ip")
                          or "")
                    target = item.get("target", "")
                    actually_in = False
                    if ip and scope_checker:
                        actually_in = scope_checker.is_ip_in_scope(
                            project, ip)
                    if not actually_in and target and scope_checker:
                        import re as _re
                        _asn_pat = _re.compile(r'^AS\d+$', _re.IGNORECASE)
                        parts = _re.split(r'[\n,]+', target)
                        for raw in parts:
                            for p in raw.split():
                                p = p.strip()
                                if not p:
                                    continue
                                if _asn_pat.match(p):
                                    continue
                                if scope_checker.is_in_scope(project, p):
                                    actually_in = True
                                    break
                            if actually_in:
                                break
                    if actually_in:
                        item["in_scope"] = True
                        title_raw = item.get("title", "")
                        if title_raw.lower().startswith(
                                "out of scope ip identified:"):
                            item["title"] = ("OSINT IP Identified:"
                                             + title_raw[27:])
                        rt = (item.get("recommended_tool") or "").lower()
                        if not rt or rt not in _VALID_OOS_TOOLS:
                            item["recommended_tool"] = "ss3"
                        meta = item.get("metadata") or {}
                        if meta.get("oos_eligible"):
                            meta["oos_eligible"] = False
                            item["metadata"] = meta
                        dirty = True

            for item in items:
                if item.get("in_scope") is True:
                    rt = (item.get("recommended_tool") or "").lower()
                    if not rt or rt == "manual":
                        title = item.get("title", "")
                        if title.lower().startswith("osint ip identified:"):
                            item["recommended_tool"] = "ss3"
                            dirty = True

            _seen_keys = {}
            _deduped = []
            for item in items:
                k = _dedup_key(item)
                if k not in _seen_keys:
                    _seen_keys[k] = True
                    _deduped.append(item)
            if len(_deduped) != len(items):
                items = _deduped
                dirty = True

            self._stores[project_dir] = items
            self._keys[project_dir] = {_dedup_key(i) for i in items}
            if dirty:
                self._persist(project_dir)

    def load_and_repair(self, project_dir, scope_checker, project,
                        running_tools, tool_dirs=None):
        """Single-pass load + both repairs. Returns repaired items list."""
        self.repair_stale_running(project_dir, running_tools or set())
        if scope_checker:
            self.repair_oos_flags(project_dir, scope_checker, project)
        return self.get_items(project_dir, tool_dirs=tool_dirs)

    # ── Reconciliation (background) ─────────────────────────

    def reconcile(self, project_dir, tool_dirs=None):
        """Merge items from tool output directories into the master cache.

        Called periodically or after tool completion. Scans tool dirs for
        action_items.json files and merges any new items.
        """
        from config import TOOL_OUTPUT_DIRS
        pd = Path(project_dir)
        new_items = []
        checked = {str(self._master_path(project_dir))}

        def _collect(fp):
            fp_str = str(fp)
            if fp_str in checked:
                return
            checked.add(fp_str)
            if not fp.exists():
                return
            for item in _load_from_file(fp):
                new_items.append(item)

        for tool_id, subdir in TOOL_OUTPUT_DIRS.items():
            _collect(pd / subdir / "action_items.json")
            if tool_id == "ss3":
                for scope in ("ext", "int"):
                    sd = pd / scope
                    if sd.is_dir():
                        for sub in sd.iterdir():
                            if sub.is_dir():
                                _collect(sub / "action_items.json")

        _collect(pd / "ext" / "action_items.json")
        _collect(pd / "int" / "action_items.json")

        if tool_dirs:
            for td in tool_dirs.values():
                td_p = Path(td)
                _collect(td_p / "action_items.json")
                if td_p.is_dir():
                    for sub in td_p.iterdir():
                        if sub.is_dir():
                            _collect(sub / "action_items.json")

        if pd.is_dir():
            for child in pd.iterdir():
                if child.is_dir() and not child.name.startswith("."):
                    _collect(child / "action_items.json")
                    for sub in child.iterdir():
                        if sub.is_dir() and not sub.name.startswith("."):
                            _collect(sub / "action_items.json")

        if not new_items:
            return 0

        added = self.add_items_batch(project_dir, new_items)
        if added:
            log.info("Reconciliation merged %d new items for %s",
                     len(added), project_dir)
        return len(added)

    def reconcile_tool(self, project_dir, tool_dir):
        """Merge items from a single tool's output directory.

        Called after tool completion — reads one known path instead of
        scanning the whole project tree.
        """
        fp = Path(tool_dir) / "action_items.json"
        if not fp.exists():
            return 0
        new_items = _load_from_file(fp)
        if not new_items:
            return 0
        added = self.add_items_batch(project_dir, new_items)
        return len(added)

    def start_reconciliation_loop(self, app, interval=300):
        """Start a background thread that periodically reconciles all projects."""
        if self._reconcile_thread and self._reconcile_thread.is_alive():
            return

        def _loop():
            time.sleep(30)
            while not self._stop.wait(interval):
                try:
                    with app.app_context():
                        from models.project import list_projects
                        for proj in list_projects():
                            if self._stop.is_set():
                                break
                            pd = proj.get("project_dir", "")
                            if pd:
                                self.reconcile(
                                    pd,
                                    tool_dirs=proj.get("tool_dirs"))
                except Exception:
                    log.exception("Reconciliation sweep failed")

        self._reconcile_thread = threading.Thread(
            target=_loop, name="ai-reconcile", daemon=True)
        self._reconcile_thread.start()
        log.info("Action item reconciliation loop started (interval=%ds)",
                 interval)


# ═══════════════════════════════════════════════════════════════════════
# Legacy compatibility shims
# ═══════════════════════════════════════════════════════════════════════
# These free functions match the old API so existing callers (routes,
# ActionEngine, ProcessManager, QueueManager) keep working without
# changes.  They delegate to the module-level _store instance.
# Once all callers are migrated to use the store directly, these
# can be removed.

_store = ActionItemStore()


def get_store():
    """Return the module-level ActionItemStore singleton."""
    return _store


def load_action_items(project_dir, tool_dirs=None):
    """Legacy: return items from cache (no full scan on every call)."""
    return _store.get_items(project_dir, tool_dirs=tool_dirs)


def save_action_items(project_dir, items):
    """Legacy: overwrite master file and invalidate cache."""
    fp = Path(project_dir) / "action_items.json"
    with _ai_lock:
        fp.parent.mkdir(parents=True, exist_ok=True)
        with open(fp, "w") as f:
            json.dump(items, f, indent=2)
    _store.invalidate(project_dir)


def add_action_item(project_dir, item):
    return _store.add_item(project_dir, item)


def update_action_item_status(project_dir, item_id, new_status,
                              extra_fields=None):
    _store.update_status(project_dir, item_id, new_status,
                         extra_fields=extra_fields)


def dismiss_action_item(project_dir, item_id):
    _store.dismiss(project_dir, item_id)


def bulk_update_status(project_dir, item_ids, new_status):
    _store.bulk_update_status(project_dir, item_ids, new_status)


def get_action_item(project_dir, item_id):
    return _store.get_item(project_dir, item_id)


def get_action_items_by_status(project_dir, status=None):
    return _store.get_items_by_status(project_dir, status)


def update_tool_action_items_status(project_dir, tool_id, from_statuses,
                                    new_status, targets=None):
    return _store.update_tool_status(project_dir, tool_id, from_statuses,
                                     new_status, targets=targets)


def get_action_items_by_tool(project_dir, tool_id):
    return _store.get_items_by_tool(project_dir, tool_id)


def get_action_items_by_category(project_dir, category):
    return _store.get_items_by_category(project_dir, category)


def get_action_items_summary(project_dir):
    return _store.get_summary(project_dir)


def remove_action_item(project_dir, item_id):
    _store.remove(project_dir, item_id)


def clear_action_items(project_dir, status_filter=None):
    _store.clear(project_dir, status_filter)


def clear_action_items_by_tool(project_dir, tool_id):
    _store.clear_by_tool(project_dir, tool_id)


def add_action_item_note(project_dir, item_id, note_text):
    _store.add_note(project_dir, item_id, note_text)


def repair_stale_running(project_dir, running_tools):
    return _store.repair_stale_running(project_dir, running_tools)


def repair_oos_flags(project_dir, scope_checker, project):
    _store.repair_oos_flags(project_dir, scope_checker, project)


def load_and_repair(project_dir, scope_checker, project, running_tools,
                    tool_dirs=None):
    return _store.load_and_repair(project_dir, scope_checker, project,
                                  running_tools, tool_dirs=tool_dirs)
