"""Findings engine -- cross-tool aggregation, caching, refresh."""

import json
import re
import threading
import logging
from pathlib import Path

try:
    import sys as _sys
    if "/opt/pr0t31n/shared" not in _sys.path:
        _sys.path.insert(0, "/opt/pr0t31n/shared")
    import pr0t31n_findings_db as _fdb
except ImportError:
    _fdb = None

from services.audit_logger import audit as _audit
from models.findings import (
    load_all_findings, load_false_positives, mark_false_positive,
    mark_partial_fp as _mark_partial_fp,
    recover_false_positive, override_risk, persist_risk_override,
    apply_risk_overrides,
    accept_finding, unaccept_finding, add_note, get_risk_summary,
    get_tool_breakdown, deduplicate, _risk_sort_key,
)

log = logging.getLogger("crucible.findings_engine")


class FindingsEngine:
    """In-memory cache and refresh logic for cross-tool findings."""

    def set_action_engine(self, ae):
        self._action_engine = ae

    # ── Read ─────────────────────────────────────────────────

    def _get_refresh_lock(self, project_id):
        with self._refresh_locks_mu:
            if project_id not in self._refresh_locks:
                self._refresh_locks[project_id] = threading.Lock()
            return self._refresh_locks[project_id]

    def get_findings(self, project_id, project):
        """Get deduplicated findings for a project. Uses cache if available.

        When the cache is cold, only one thread runs refresh() while
        concurrent callers wait and then read from the now-warm cache.
        """
        with self._lock:
            if project_id in self._cache:
                return list(self._cache[project_id])
        rlock = self._get_refresh_lock(project_id)
        with rlock:
            with self._lock:
                if project_id in self._cache:
                    return list(self._cache[project_id])
            return self.refresh(project_id, project)

    def get_false_positives(self, project_id, project):
        """Get false positives for a project."""
        with self._lock:
            if project_id in self._fp_cache:
                return list(self._fp_cache[project_id])
        project_dir = project.get("project_dir", "")
        if not project_dir:
            return []
        fps = load_false_positives(project_dir)
        with self._lock:
            self._fp_cache[project_id] = fps
        return list(fps)

    # ── Refresh ──────────────────────────────────────────────

    _TOOL_NAME_TO_ID = {
        "scattershot3": "ss3", "scattershot": "ss3",
        "osift": "osift",
        "fracture": "fracture",
        "siphon": "siphon",
    }

    _TOOL_ID_TO_DIR = {
        "ss3": "Scattershot3", "osift": "OSift",
        "fracture": "Fracture", "siphon": "Siphon",
        "auger": "Auger", "trawler": "Trawler",
        "authprobe": "AuthProbe", "bastion": "Bastion",
        "forge": "Forge", "quill": "Quill", "isotope": "Isotope",
        "aether": "Aether", "aether_b": "Aether-B",
        "aether_z": "Aether-Z", "aether_u": "Aether-U",
        "gearbox": "Gearbox", "phalanx": "Phalanx",
        "dredge": "Dredge", "pain": "pAIn",
        "anvil": "Anvil", "vault": "Vault",
        "drift": "Drift", "pivot": "Pivot",
    }

    _ENRICH_FIELDS = [
        ("category", "category"),
        ("cvss_v3_base", "cvss_score"), ("cvss_vector", "cvss_vector"),
        ("cwe", "cwe"), ("kev", "kev"),
        ("owasp_web", "owasp"), ("owasp_api", "owasp_api"),
        ("description", "description"),
        ("impact", "impact"),
        ("remediation_brief", "remediation"),
        ("remediation_effort", "remediation_effort"),
        ("remediation_component", "remediation_component"),
        ("remediation_category", "remediation_category"),
        ("mitre_attack", "mitre_attack"),
        ("searchsploit_terms", "searchsploit_terms"),
        ("metasploit_modules", "metasploit_modules"),
        ("nessus_plugin_ids", "nessus_plugin_ids"),
        ("qualys_qids", "qualys_qids"),
        ("cve_examples", "cve_examples"),
        ("nist_csf2", "nist_csf2"), ("nist_800_53", "nist_800_53"),
        ("nist_800_171", "nist_800_171"), ("pci_dss_4", "pci_dss_4"),
        ("iso_27001", "iso_27001"), ("iso_27002", "iso_27002"),
        ("soc2", "soc2"), ("hitrust", "hitrust"), ("gdpr", "gdpr"),
    ]

    _NESSUS_AUTHORITATIVE = frozenset({"cvss_score", "cvss_vector"})

    def __init__(self):
        self._cache = {}
        self._fp_cache = {}
        self._lock = threading.Lock()
        self._refresh_locks = {}
        self._refresh_locks_mu = threading.Lock()
        self._action_engine = None
        self._catalogues = {}
        self._catalogues_loaded = False
        self._catalogues_ready = threading.Event()
        self._db_handles = {}
        self._db_lock = threading.Lock()
        threading.Thread(target=self._preload_catalogues,
                         name="catalogue-preload", daemon=True).start()

    def _get_db(self, project_id, project):
        """Get or create a FindingsDB handle for a project."""
        if _fdb is None:
            return None
        with self._db_lock:
            db = self._db_handles.get(project_id)
            if db is not None:
                return db
        eng_dir = project.get("engagement_dir") or project.get("project_dir", "")
        if not eng_dir:
            return None
        from config import FINDINGS_DB_FILENAME
        db_path = Path(eng_dir) / FINDINGS_DB_FILENAME
        try:
            db = _fdb.FindingsDB(str(db_path))
            with self._db_lock:
                self._db_handles[project_id] = db
            return db
        except Exception:
            log.debug("Could not open FindingsDB at %s", db_path)
            return None

    def _close_db(self, project_id):
        """Close and discard a DB handle."""
        with self._db_lock:
            db = self._db_handles.pop(project_id, None)
        if db:
            try:
                db.close()
            except Exception:
                pass

    def query_findings_db(self, project_id, project, **kwargs):
        """Query findings from DB with server-side pagination.

        Accepted kwargs: page, per_page, risk, tool, scope, ip, port,
        hostname, category, search, sort, order, oos.
        Returns dict: {findings, total, page, pages, summary}.
        """
        db = self._get_db(project_id, project)
        if db is None:
            return None
        try:
            result = db.query_findings(**kwargs)
            summary = db.get_summary()
            result["summary"] = summary
            return result
        except Exception:
            log.exception("FindingsDB query failed for %s", project_id)
            return None

    def get_filter_options(self, project_id, project):
        """Return distinct scopes, tools, and categories for filter dropdowns."""
        db = self._get_db(project_id, project)
        if db is not None:
            try:
                scopes = [r["name"] for r in db._conn.execute(
                    "SELECT DISTINCT s.name FROM findings f "
                    "JOIN scopes s ON f.scope_id=s.id "
                    "WHERE f.is_false_positive=0 ORDER BY s.name"
                ).fetchall() if r["name"]]
                tools = [{"id": r["tool_id"], "name": r["tool_name"]} for r in
                         db._conn.execute(
                    "SELECT DISTINCT f.tool_id, t.name as tool_name "
                    "FROM findings f JOIN tools t ON f.tool_id=t.id "
                    "WHERE f.is_false_positive=0 ORDER BY t.name"
                ).fetchall()]
                categories = [r["name"] for r in db._conn.execute(
                    "SELECT DISTINCT c.name FROM findings f "
                    "JOIN categories c ON f.category_id=c.id "
                    "WHERE f.is_false_positive=0 ORDER BY c.name"
                ).fetchall() if r["name"]]
                return {"scopes": scopes, "tools": tools,
                        "categories": categories, "source": "db"}
            except Exception:
                log.debug("DB filter options failed for %s", project_id)
        findings = self.get_findings(project_id, project)
        scopes = sorted({f.get("scope", "") for f in findings} - {""})
        tool_set = {}
        for f in findings:
            t = f.get("tool", "")
            if t and t not in tool_set:
                tool_set[t] = t
        tools = [{"id": t, "name": t} for t in sorted(tool_set)]
        categories = sorted({f.get("category", "") for f in findings} - {""})
        return {"scopes": scopes, "tools": tools,
                "categories": categories, "source": "cache"}

    def _preload_catalogues(self):
        try:
            self._load_catalogues()
        except Exception:
            log.exception("Background catalogue pre-load failed")
        finally:
            self._catalogues_ready.set()

    def _load_catalogues(self):
        if self._catalogues_loaded:
            return
        from config import TOOL_DIR
        for tid, dirname in self._TOOL_ID_TO_DIR.items():
            cat_path = TOOL_DIR / dirname / "findings_catalogue.json"
            if not cat_path.exists():
                continue
            try:
                raw = json.loads(cat_path.read_text())
                if isinstance(raw, dict):
                    entries = raw.get("findings") or raw.get("entries") or []
                else:
                    entries = raw
                exact = {}
                prefixes = []
                for entry in entries:
                    title = entry.get("title", "")
                    if "{" in title:
                        prefix = title[:title.index("{")]
                        if prefix:
                            prefixes.append((prefix, entry))
                    else:
                        exact[title] = entry
                self._catalogues[tid] = {"exact": exact, "prefixes": prefixes}
            except Exception:
                log.exception("Failed to load catalogue for %s", tid)
        master_path = Path("/opt/pr0t31n/shared/master_findings_catalogue.json")
        if not master_path.exists():
            master_path = TOOL_DIR / "Arbiter" / "findings_catalogue.json"
            if master_path.exists():
                log.warning("Master catalogue not at /opt/pr0t31n/shared/ — "
                            "falling back to Arbiter-local copy")
        if master_path.exists():
            try:
                raw = json.loads(master_path.read_text())
                if isinstance(raw, dict):
                    entries = raw.get("findings") or raw.get("entries") or []
                else:
                    entries = raw
                exact = {}
                aliases = {}
                prefixes = []
                for entry in entries:
                    title = entry.get("title", "")
                    if "{" in title:
                        prefix = title[:title.index("{")]
                        if prefix:
                            prefixes.append((prefix, entry))
                    else:
                        exact[title] = entry
                    for alias in entry.get("aliases", []):
                        if alias and alias not in exact:
                            aliases[alias] = entry
                self._catalogues["_master"] = {
                    "exact": exact, "prefixes": prefixes, "aliases": aliases,
                }
                log.info("Loaded master catalogue: %d entries, %d aliases from %s",
                         len(exact), len(aliases), master_path)
            except Exception:
                log.exception("Failed to load master catalogue from %s", master_path)
        else:
            log.warning("No master catalogue found — install Shared repo "
                        "and run: pr0t31n_catalogue.py merge --output "
                        "/opt/pr0t31n/shared/master_findings_catalogue.json")
        self._catalogues_loaded = True
        log.info("Loaded findings catalogues for %d tools", len(self._catalogues))

    def _match_catalogue(self, cat, title):
        """Match a finding title against a catalogue's exact/prefix/alias indexes."""
        entry = cat["exact"].get(title)
        if entry:
            return entry
        for prefix, pentry in cat["prefixes"]:
            if title.startswith(prefix):
                return pentry
        alias_map = cat.get("aliases")
        if alias_map:
            entry = alias_map.get(title)
            if entry:
                return entry
            for alias, aentry in alias_map.items():
                if title.startswith(alias):
                    return aentry
        return None

    def _enrich_from_catalogue(self, findings):
        self._catalogues_ready.wait(timeout=30)
        if not self._catalogues:
            return
        master = self._catalogues.get("_master")
        enriched = 0
        for f in findings:
            t = (f.get("tool") or "").split(":")[0]
            tid = self._TOOL_NAME_TO_ID.get(t, t)
            cat = self._catalogues.get(tid)
            title = f.get("title", "")
            orig_title = f.get("_original_title", "")
            entry = None
            if cat:
                entry = self._match_catalogue(cat, title)
                if not entry and orig_title and orig_title != title:
                    entry = self._match_catalogue(cat, orig_title)
            if not entry and master:
                entry = self._match_catalogue(master, title)
                if not entry and orig_title and orig_title != title:
                    entry = self._match_catalogue(master, orig_title)
            if not entry:
                continue
            did_enrich = False
            for cat_field, finding_field in self._ENRICH_FIELDS:
                val = entry.get(cat_field)
                if val is None or val == "" or val == []:
                    continue
                if isinstance(val, str) and val.strip() == "":
                    continue
                existing = f.get(finding_field)
                has_existing = existing is not None and existing != "" \
                    and existing != [] \
                    and not (isinstance(existing, str) and existing.strip() == "")
                if has_existing and finding_field in self._NESSUS_AUTHORITATIVE:
                    continue
                f[finding_field] = val
                did_enrich = True
            if did_enrich:
                pids = f.get("nessus_plugin_ids")
                if pids and not f.get("nessus_plugin_id"):
                    f["nessus_plugin_id"] = pids[0]
                qids = f.get("qualys_qids")
                if qids and not f.get("qualys_qid"):
                    f["qualys_qid"] = qids[0]
                enriched += 1
        if enriched:
            log.info("Enriched %d findings from catalogues", enriched)

    @staticmethod
    def _build_tool_scope_map(project):
        """Build {tool_id: scope_key} from project's scope_tools."""
        scope_tools = project.get("scope_tools") or {}
        out = {}
        for scope_key, tools in scope_tools.items():
            for t in (tools or []):
                out[t] = scope_key
        return out

    _URL_SCHEME_RE = re.compile(r'^https?://')

    @staticmethod
    def _sanitize_finding(f):
        ip = f.get("ip") or ""
        if ip:
            cleaned = FindingsEngine._URL_SCHEME_RE.sub("", ip).rstrip("/")
            trail = re.search(r'(https?|ftp)$', cleaned)
            if trail:
                cleaned = cleaned[:trail.start()]
            if cleaned != ip:
                f["ip"] = cleaned
        hn = f.get("hostname") or ""
        if hn:
            cleaned = FindingsEngine._URL_SCHEME_RE.sub("", hn).rstrip("/")
            trail = re.search(r'(https?|ftp)$', cleaned)
            if trail:
                cleaned = cleaned[:trail.start()]
            if cleaned != hn:
                f["hostname"] = cleaned

    _AFF_LOC_RE = re.compile(r'^(?:https?://)?([^:/\s]+)')

    def _apply_oos_flags(self, findings, project):
        """Tag findings whose target is not explicitly in-scope as oos=True.

        Only marks findings when oos_handling is 'separated' or 'combined'.
        When 'explicit', no OOS flags are set (current behaviour).

        For merged findings (ip/hostname blank after dedup), checks each
        location in 'affected' — if ANY is in scope, the finding is in-scope.
        """
        oos_mode = project.get("oos_handling", "explicit")
        if oos_mode == "explicit":
            return

        from flask import current_app
        sm = current_app.extensions.get("scope_manager")
        if not sm:
            return

        for f in findings:
            ip = f.get("ip") or ""
            hostname = f.get("hostname") or ""
            target = hostname or ip

            if target:
                if sm.is_in_scope(project, target):
                    f["oos"] = False
                    continue
                if ip and sm.is_in_scope(project, ip):
                    f["oos"] = False
                    continue

            affected = f.get("affected") or ""
            if not target and affected:
                # After dedup merge, affected can contain mixed in-scope
                # hostnames and OOS IPs.  Don't override an existing
                # oos=True (set per-IP at import) based on a hostname
                # match — a subdomain may resolve to a third-party CDN.
                if f.get("oos") is True:
                    continue
                any_in_scope = False
                for loc in affected.split("\n"):
                    loc = loc.strip()
                    if not loc:
                        continue
                    m = self._AFF_LOC_RE.match(loc)
                    host = m.group(1) if m else loc
                    host = host.split(":")[0]
                    if host and sm.is_in_scope(project, host):
                        any_in_scope = True
                        break
                if any_in_scope:
                    f["oos"] = False
                    continue

            if not target and not affected:
                continue

            if target and sm.is_oos_eligible(project, hostname=hostname, ip_str=ip):
                f["oos"] = True
                if oos_mode == "separated":
                    title = f.get("title", "")
                    if not title.endswith(" - OOS"):
                        f["title"] = title + " - OOS"
            else:
                f["oos"] = True

    @staticmethod
    def _is_finding_excluded(f, sm, project):
        """Check if a finding's IP or hostname is in the exclusion list."""
        ip = (f.get("ip") or "").strip()
        hostname = (f.get("hostname") or "").strip()
        if ip and sm.is_excluded(project, ip):
            return True
        if hostname and sm.is_excluded(project, hostname):
            return True
        return False

    def refresh(self, project_id, project):
        """Force refresh findings from disk. Returns the refreshed list."""
        findings = load_all_findings(project)
        project_dir = project.get("project_dir", "")
        fps = load_false_positives(project_dir) if project_dir else []
        fp_ids = {fp.get("id") for fp in fps if fp.get("id")}
        active = [f for f in findings if f.get("id") not in fp_ids]
        for f in active:
            self._sanitize_finding(f)

        # Retroactive exclusion: filter findings whose IP/hostname is excluded
        try:
            from flask import current_app
            sm = current_app.extensions.get("scope_manager")
            if sm:
                before = len(active)
                active = [f for f in active
                          if not self._is_finding_excluded(f, sm, project)]
                excluded = before - len(active)
                if excluded:
                    log.info("Excluded %d findings for project %s (exclusion list)",
                             excluded, project_id)
        except RuntimeError as exc:
            log.debug("scope exclusion outside flask context: %s", exc)

        tsm = self._build_tool_scope_map(project)
        if tsm:
            for f in active:
                t = (f.get("tool") or "").split(":")[0]
                tid = self._TOOL_NAME_TO_ID.get(t, t)
                if tid in tsm:
                    f["scope"] = tsm[tid]
        self._enrich_from_catalogue(active)
        self._apply_oos_flags(active, project)
        apply_risk_overrides(active, project)
        with self._lock:
            self._cache[project_id] = active
            self._fp_cache[project_id] = fps
        if self._action_engine and project_dir:
            threading.Thread(
                target=self._generate_actions_batch,
                args=(project_dir, list(active), project),
                name="ai-gen-refresh", daemon=True).start()
        threading.Thread(
            target=self._populate_db,
            args=(project_id, project, list(active)),
            name="fdb-populate", daemon=True).start()
        log.info("Refreshed findings for project %s: %d active, %d FP",
                 project_id, len(active), len(fps))
        return list(active)

    def _populate_db(self, project_id, project, findings):
        """Bulk-insert enriched findings into FindingsDB (background)."""
        db = self._get_db(project_id, project)
        if db is None:
            return
        try:
            db.bulk_insert(findings)
            log.info("Populated FindingsDB for %s: %d findings", project_id,
                     len(findings))
        except Exception:
            log.exception("FindingsDB populate failed for %s", project_id)

    # ── Invalidate ───────────────────────────────────────────

    def invalidate(self, project_id):
        """Invalidate cache for a project (forces reload on next access)."""
        with self._lock:
            self._cache.pop(project_id, None)
            self._fp_cache.pop(project_id, None)
        self._close_db(project_id)

    def invalidate_all(self):
        """Invalidate all cached findings."""
        with self._lock:
            self._cache.clear()
            self._fp_cache.clear()

    # ── Live finding injection ───────────────────────────────

    def add_live_finding(self, project_id, finding, project=None):
        """Add a finding from a live tool stream (before it's written to disk).

        When FindingsDB is available, inserts directly into DB (O(1) via
        UNIQUE dedup_key constraint) instead of re-deduplicating the entire
        in-memory cache.  The cache is still updated for backward compat
        with the legacy /api/findings/ endpoint.
        """
        if project:
            try:
                from flask import current_app
                sm = current_app.extensions.get("scope_manager")
                if sm and self._is_finding_excluded(finding, sm, project):
                    return
            except RuntimeError as exc:
                log.debug("scope check outside app context: %s", exc)
        self._enrich_from_catalogue([finding])
        if project:
            apply_risk_overrides([finding], project)

        if _fdb and project:
            try:
                db = self._get_db(project_id, project)
                if db:
                    db.insert_finding(finding)
            except Exception:
                pass

        with self._lock:
            cached = self._cache.get(project_id)
            if cached is None:
                self._cache[project_id] = deduplicate([finding])
            else:
                merged = list(cached)
                merged.append(finding)
                deduped = deduplicate(merged)
                if project:
                    apply_risk_overrides(deduped, project)
                self._cache[project_id] = deduped
        if self._action_engine and project:
            project_dir = project.get("project_dir", "")
            if project_dir:
                source = finding.get("tool") or finding.get("source_tool", "")
                try:
                    self._action_engine.process_finding(
                        project_dir, finding, source, project=project)
                except Exception:
                    log.exception("Failed to generate action for live finding")

    def remove_live_finding(self, project_id, finding_id):
        """Remove a finding from the live cache by id."""
        with self._lock:
            cached = self._cache.get(project_id)
            if cached is None:
                return
            self._cache[project_id] = [
                f for f in cached if f.get("id") != finding_id
            ]

    def bulk_add_findings(self, project_id, findings, project=None):
        """Batch-insert findings into DB.  Used by ImporterService for
        parsed scanner files.  Falls back to per-finding add_live_finding
        when DB is not available."""
        if _fdb and project:
            try:
                db = self._get_db(project_id, project)
                if db:
                    self._enrich_from_catalogue(findings)
                    if project:
                        apply_risk_overrides(findings, project)
                    db.bulk_insert(findings)
                    with self._lock:
                        cached = self._cache.get(project_id)
                        if cached is None:
                            self._cache[project_id] = deduplicate(findings)
                        else:
                            merged = list(cached) + findings
                            self._cache[project_id] = deduplicate(merged)
                    return
            except Exception:
                log.debug("bulk_add_findings DB path failed, falling back")
        for f in findings:
            self.add_live_finding(project_id, f, project=project)

    def ingest_stragglers(self, project_id, project, tool_id=None):
        """Ingest findings from final JSON files that weren't live-injected.

        Called by _post_completion() before the full refresh.  The DB's UNIQUE
        dedup_key constraint makes this idempotent — duplicates of
        already-injected findings are silently skipped.
        """
        if not _fdb or not project:
            return
        try:
            db = self._get_db(project_id, project)
            if not db:
                return
        except Exception:
            return
        tool_dirs = project.get("tool_dirs", {})
        scope_tool_dirs = project.get("scope_tool_dirs", {})
        loaded = set()

        for scope_name, dirs in scope_tool_dirs.items():
            for tid, td in dirs.items():
                if tool_id and tid != tool_id:
                    continue
                if (tid, td) in loaded:
                    continue
                loaded.add((tid, td))
                fp = Path(td) / "findings.json"
                if fp.exists():
                    try:
                        db.ingest_findings_json(str(fp), tool_id=tid,
                                                scope=scope_name)
                    except Exception:
                        pass

        for tid, td in tool_dirs.items():
            if tool_id and tid != tool_id:
                continue
            if (tid, td) in loaded:
                continue
            loaded.add((tid, td))
            fp = Path(td) / "findings.json"
            if fp.exists():
                try:
                    db.ingest_findings_json(str(fp), tool_id=tid)
                except Exception:
                    pass

    # ── Mutations ────────────────────────────────────────────

    def mark_fp(self, project_id, project, finding_id):
        """Mark a finding as false positive. Returns (updated_findings, fp_finding)."""
        project_dir = project.get("project_dir", "")
        with self._lock:
            cached = self._cache.get(project_id, [])
            target = None
            for f in cached:
                if f.get("id") == finding_id:
                    target = f
                    break
        if not target or not project_dir:
            return None, None
        updated = mark_false_positive(project_dir, target, cached)
        with self._lock:
            self._cache[project_id] = updated
            self._fp_cache.pop(project_id, None)
        db = self._get_db(project_id, project)
        if db:
            try:
                db.mark_false_positive(finding_id)
            except Exception:
                log.debug("DB FP mark failed for %s", finding_id)
        _audit(project_dir, "FINDING_FP", finding_id=finding_id,
               title=target.get("title", ""))
        return list(updated), target

    def mark_partial_fp(self, project_id, project, finding_id, affected_locations):
        """Mark specific affected locations as FP. Returns (updated_findings, fp_entries)."""
        project_dir = project.get("project_dir", "")
        with self._lock:
            cached = self._cache.get(project_id, [])
            target = None
            for f in cached:
                if f.get("id") == finding_id:
                    target = f
                    break
        if not target or not project_dir:
            return None, None
        updated, fp_entries = _mark_partial_fp(project_dir, target, cached,
                                               affected_locations)
        with self._lock:
            self._cache[project_id] = updated
            self._fp_cache.pop(project_id, None)
        _audit(project_dir, "FINDING_PARTIAL_FP", finding_id=finding_id,
               title=target.get("title", ""),
               affected_locations=", ".join(affected_locations))
        return list(updated), fp_entries

    def recover_fp(self, project_id, project, finding_id):
        """Recover a finding from false positive. Returns the recovered finding or None."""
        project_dir = project.get("project_dir", "")
        if not project_dir:
            return None
        recovered = recover_false_positive(project_dir, finding_id)
        if recovered:
            self.add_live_finding(project_id, recovered)
            with self._lock:
                self._fp_cache.pop(project_id, None)
            db = self._get_db(project_id, project)
            if db:
                try:
                    db.recover_false_positive(finding_id)
                except Exception:
                    log.debug("DB FP recover failed for %s", finding_id)
            _audit(project_dir, "FINDING_RECOVER_FP", finding_id=finding_id)
        return recovered

    def set_risk_override(self, project_id, finding_id, new_risk, reason="",
                          project_dir="", project=None):
        """Override risk level for a finding."""
        with self._lock:
            cached = self._cache.get(project_id, [])
            self._cache[project_id] = override_risk(cached, finding_id,
                                                     new_risk, reason)
            if project:
                persist_risk_override(cached, finding_id, new_risk, project,
                                      reason=reason)
        if not project_dir and project:
            project_dir = project.get("project_dir", "")
        if project:
            db = self._get_db(project_id, project)
            if db:
                try:
                    db.override_risk(finding_id, new_risk, reason)
                except Exception:
                    log.debug("DB risk override failed for %s", finding_id)
        _audit(project_dir, "RISK_OVERRIDE", finding_id=finding_id,
               new_risk=new_risk, reason=reason)

    def set_accepted(self, project_id, finding_id, accepted=True):
        """Accept or unaccept a finding."""
        with self._lock:
            cached = self._cache.get(project_id, [])
            if accepted:
                self._cache[project_id] = accept_finding(cached, finding_id)
            else:
                self._cache[project_id] = unaccept_finding(cached, finding_id)

    def append_note(self, project_id, finding_id, note_text):
        """Add a note to a finding."""
        with self._lock:
            cached = self._cache.get(project_id, [])
            self._cache[project_id] = add_note(cached, finding_id, note_text)

    def delete_note(self, project_id, finding_id, note_index):
        """Delete a note from a finding by index."""
        with self._lock:
            cached = self._cache.get(project_id, [])
            for f in cached:
                if f.get("id") == finding_id:
                    notes = f.get("notes", [])
                    if 0 <= note_index < len(notes):
                        notes.pop(note_index)
                    break

    # ── Action-item generation ────────────────────────────────

    def _generate_actions(self, project_dir, findings, project=None):
        """Generate action items for all findings via ActionEngine (legacy)."""
        for f in findings:
            source = f.get("tool") or f.get("source_tool", "")
            try:
                self._action_engine.process_finding(
                    project_dir, f, source, project=project)
            except Exception:
                log.exception("Failed to generate actions for finding %s",
                              f.get("id", "?"))

    def _generate_actions_batch(self, project_dir, findings, project=None):
        """Batch-generate action items — runs in a background thread."""
        from models.action_items import get_store as _get_ai_store
        store = _get_ai_store()
        existing_fids = set()
        for ai in store.get_items(project_dir):
            fid = (ai.get("metadata") or {}).get("finding_id")
            if fid:
                existing_fids.add(fid)
        collector = []
        for f in findings:
            fid = f.get("id")
            if fid and fid in existing_fids:
                continue
            source = f.get("tool") or f.get("source_tool", "")
            try:
                self._action_engine.process_finding(
                    project_dir, f, source, project=project,
                    _collector=collector)
            except Exception:
                log.exception("Failed to generate actions for finding %s",
                              f.get("id", "?"))
        if collector:
            added = store.add_items_batch(project_dir, collector)
            if added:
                log.info("Background action gen: %d new items from %d findings",
                         len(added), len(findings))

    # ── Cross-tool correlation ──────────────────────────────

    def get_host_correlation(self, project_id, project):
        """Group findings by (ip, port) across all tools.

        Returns a list of host dicts sorted by max risk, each containing:
          ip, hostname, ports, tools, cves, max_risk, total_findings.
        """
        findings = self.get_findings(project_id, project)
        hosts = {}
        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

        for f in findings:
            ip = f.get("ip", "")
            hostname = f.get("hostname", "")
            if not ip and not hostname:
                continue
            host_key = ip or hostname
            port = str(f.get("port", 0))
            tool = f.get("tool", "unknown")
            risk = (f.get("risk") or "INFO").upper()

            if host_key not in hosts:
                hosts[host_key] = {
                    "ip": ip, "hostname": hostname,
                    "ports": {}, "tools": set(),
                    "cves": set(), "findings_count": 0,
                }
            host = hosts[host_key]
            if hostname and not host["hostname"]:
                host["hostname"] = hostname
            host["tools"].add(tool)
            host["findings_count"] += 1

            cves = f.get("cves", "")
            if cves:
                for cve in cves.split(","):
                    cve = cve.strip()
                    if cve:
                        host["cves"].add(cve)

            if port not in host["ports"]:
                host["ports"][port] = {
                    "port": int(port) if port.isdigit() else 0,
                    "service": f.get("service", ""),
                    "findings": [],
                    "tools": set(),
                    "risk_counts": {},
                }
            port_info = host["ports"][port]
            port_info["findings"].append({
                "id": f.get("id"),
                "title": f.get("title", ""),
                "risk": risk,
                "tool": tool,
                "accepted": f.get("accepted", False),
                "kev": f.get("kev", False),
                "cvss_score": f.get("cvss_score"),
                "cves": cves,
            })
            port_info["tools"].add(tool)
            port_info["risk_counts"][risk] = \
                port_info["risk_counts"].get(risk, 0) + 1
            if f.get("service") and not port_info["service"]:
                port_info["service"] = f["service"]

        result = []
        for ip, host in hosts.items():
            port_list = []
            max_risk = "INFO"
            for port_key, pi in sorted(host["ports"].items(),
                                        key=lambda x: int(x[0]) if x[0].isdigit() else 0):
                pi["tools"] = sorted(pi["tools"])
                port_list.append(pi)
                for r in pi["risk_counts"]:
                    if risk_order.get(r, 5) < risk_order.get(max_risk, 5):
                        max_risk = r
            result.append({
                "ip": ip,
                "hostname": host["hostname"],
                "ports": port_list,
                "tools": sorted(host["tools"]),
                "cves": sorted(host["cves"]),
                "max_risk": max_risk,
                "total_findings": host["findings_count"],
            })

        result.sort(key=lambda h: risk_order.get(h["max_risk"], 5))
        return result

    def get_cve_correlation(self, project_id, project):
        """Group findings by CVE across all tools/hosts."""
        findings = self.get_findings(project_id, project)
        cve_map = {}
        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

        for f in findings:
            cves = f.get("cves", "")
            if not cves:
                continue
            for cve in cves.split(","):
                cve = cve.strip()
                if not cve:
                    continue
                if cve not in cve_map:
                    cve_map[cve] = {
                        "cve": cve, "findings": [],
                        "hosts": set(), "tools": set(),
                        "max_risk": "INFO", "kev": False,
                    }
                entry = cve_map[cve]
                entry["findings"].append({
                    "id": f.get("id"),
                    "title": f.get("title", ""),
                    "ip": f.get("ip", ""),
                    "port": f.get("port", 0),
                    "risk": (f.get("risk") or "INFO").upper(),
                    "tool": f.get("tool", ""),
                })
                entry["hosts"].add(f.get("ip", ""))
                entry["tools"].add(f.get("tool", ""))
                if f.get("kev"):
                    entry["kev"] = True
                r = (f.get("risk") or "INFO").upper()
                if risk_order.get(r, 5) < risk_order.get(entry["max_risk"], 5):
                    entry["max_risk"] = r

        result = []
        for cve, entry in cve_map.items():
            entry["hosts"] = sorted(entry["hosts"])
            entry["tools"] = sorted(entry["tools"])
            entry["host_count"] = len(entry["hosts"])
            result.append(entry)

        result.sort(key=lambda e: (
            risk_order.get(e["max_risk"], 5),
            -e["host_count"],
        ))
        return result

    def get_finding_workflow(self, project_id, project):
        """Finding workflow: host correlation + CVE correlation + attack surface."""
        host_corr = self.get_host_correlation(project_id, project)
        cve_corr = self.get_cve_correlation(project_id, project)
        findings = self.get_findings(project_id, project)

        multi_tool_hosts = [h for h in host_corr if len(h["tools"]) > 1]
        kev_findings = [f for f in findings if f.get("kev")]

        return {
            "host_correlation": host_corr,
            "cve_correlation": cve_corr,
            "multi_tool_hosts": multi_tool_hosts,
            "kev_findings": [{
                "id": f.get("id"), "title": f.get("title"),
                "ip": f.get("ip"), "port": f.get("port"),
                "risk": f.get("risk"), "tool": f.get("tool"),
                "cves": f.get("cves"),
            } for f in kev_findings],
            "attack_surface": {
                "total_hosts": len(host_corr),
                "total_ports": sum(len(h["ports"]) for h in host_corr),
                "total_cves": len(cve_corr),
                "kev_count": len(kev_findings),
                "tools_active": len(set(
                    t for h in host_corr for t in h["tools"])),
            },
        }

    # ── Summaries ────────────────────────────────────────────

    def get_summary(self, project_id, project):
        """Return risk summary dict for a project."""
        findings = self.get_findings(project_id, project)
        return get_risk_summary(findings)

    def get_full_summary(self, project_id, project):
        """Return {risk_counts, tool_breakdown, findings_count, ...}."""
        findings = self.get_findings(project_id, project)
        rc = get_risk_summary(findings)
        return {
            "risk_counts": rc,
            "risk_summary": rc,
            "tool_breakdown": get_tool_breakdown(findings),
            "findings_count": len(findings),
            "total": len(findings),
            "accepted_count": sum(1 for f in findings if f.get("accepted")),
            "fp_count": len(self.get_false_positives(project_id, project)),
        }
