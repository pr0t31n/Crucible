"""CISA KEV (Known Exploited Vulnerabilities) enrichment service."""

import json
import logging
import threading
import time
import urllib.request
import urllib.error

log = logging.getLogger("crucible.kev_enricher")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REFRESH_INTERVAL = 86400  # 24 hours


class KEVEnricher:

    def __init__(self):
        self._catalogue = {}
        self._lock = threading.Lock()
        self._loaded = False

    def start(self):
        threading.Thread(target=self._refresh_loop,
                         name="kev-refresh", daemon=True).start()

    def _refresh_loop(self):
        while True:
            self.refresh()
            time.sleep(REFRESH_INTERVAL)

    def refresh(self):
        try:
            req = urllib.request.Request(KEV_URL, headers={
                "User-Agent": "Crucible-KEV-Enricher/1.0",
                "Accept": "application/json",
            })
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
            vulns = data.get("vulnerabilities", [])
            new_cat = {}
            for v in vulns:
                cve = v.get("cveID", "").strip().upper()
                if cve:
                    new_cat[cve] = {
                        "cve": cve,
                        "vendor": v.get("vendorProject", ""),
                        "product": v.get("product", ""),
                        "name": v.get("vulnerabilityName", ""),
                        "date_added": v.get("dateAdded", ""),
                        "due_date": v.get("dueDate", ""),
                        "ransomware": v.get("knownRansomwareCampaignUse", "Unknown") == "Known",
                    }
            with self._lock:
                self._catalogue = new_cat
                self._loaded = True
            log.info("KEV catalogue refreshed: %d entries", len(new_cat))
        except Exception:
            log.exception("KEV catalogue refresh failed")

    @property
    def loaded(self):
        return self._loaded

    @property
    def count(self):
        with self._lock:
            return len(self._catalogue)

    def check_cves(self, cve_string):
        if not cve_string or not self._loaded:
            return []
        with self._lock:
            cat = self._catalogue
        matches = []
        for raw in str(cve_string).replace(";", ",").split(","):
            cve = raw.strip().upper()
            if cve in cat:
                matches.append(cat[cve])
        return matches

    def enrich(self, finding):
        if not self._loaded:
            return
        cves = finding.get("cves", "")
        matches = self.check_cves(cves)
        if matches:
            finding["kev"] = True
            finding["kev_details"] = matches

    def backfill(self, findings_engine, app):
        if not self._loaded:
            return
        try:
            from models.project import list_projects
            with app.app_context():
                projects = list_projects()
                total = 0
                for proj in projects:
                    pid = proj.get("id")
                    if not pid:
                        continue
                    findings = findings_engine.get_findings(pid, proj)
                    if not findings:
                        continue
                    for f in findings:
                        if f.get("kev"):
                            continue
                        cves = f.get("cves", "")
                        matches = self.check_cves(cves)
                        if matches:
                            f["kev"] = True
                            f["kev_details"] = matches
                            total += 1
                            db = findings_engine._get_db(pid, proj)
                            if db:
                                try:
                                    db.update_finding(f.get("id"),
                                                      {"kev": True,
                                                       "kev_details": json.dumps(matches)})
                                except Exception:
                                    pass
                if total:
                    log.info("KEV backfill: tagged %d findings", total)
        except Exception:
            log.exception("KEV backfill failed")
