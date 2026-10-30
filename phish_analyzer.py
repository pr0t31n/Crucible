#!/usr/bin/env python3 -I
"""
GoPhish Campaign Analyzer — identifies email security artifacts in
phishing campaign results and produces corrected engagement metrics.

Detects automated clicks/opens from email security platforms (Proofpoint,
Microsoft Defender, Mimecast, Barracuda, etc.) by cross-referencing IP
geolocation, user-agent fingerprinting, and timing analysis.

Part of the pr0t31n Crucible toolkit.

Usage:
    python3 phish_analyzer.py <events.csv> [<results.csv>] [OPTIONS]

Options:
    --no-geo          Skip IP geolocation (offline mode)
    --cache PATH      Geo cache file (default: <events>.geo_cache.json)
    --json PATH       Write JSON report
    --csv PATH        Write corrected results CSV
    -v, --verbose     Show per-event classification detail
"""

import argparse
import csv
import ipaddress
import json
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

SCRIPT_VERSION = "1.0.0"

# ── Known email security infrastructure ───────────────────────────

KNOWN_SECURITY_CIDRS = {
    # Proofpoint
    "67.231.144.0/20": "Proofpoint",
    "148.163.128.0/19": "Proofpoint",
    # Mimecast
    "207.211.30.0/24": "Mimecast",
    "207.211.31.0/24": "Mimecast",
    "91.220.42.0/24": "Mimecast",
    "91.220.43.0/24": "Mimecast",
    "185.58.84.0/22": "Mimecast",
    # Barracuda
    "64.235.144.0/20": "Barracuda",
    "209.222.80.0/21": "Barracuda",
    # Cisco ESA / IronPort
    "184.50.0.0/15": "Cisco ESA",
}

_SECURITY_NETS = {
    ipaddress.ip_network(cidr): vendor
    for cidr, vendor in KNOWN_SECURITY_CIDRS.items()
}

SCANNER_UA_SIGS = [
    "X11; Linux x86_64",
    "PhishGuard",
    "URLDefense",
]

VENDOR_NAME_PATTERNS = {
    "proofpoint": "Proofpoint",
    "mimecast": "Mimecast",
    "barracuda": "Barracuda",
    "microsoft": "Microsoft",
    "google": "Google",
    "cisco": "Cisco",
    "fortinet": "FortiMail",
    "sophos": "Sophos",
    "trellix": "Trellix",
    "fireeye": "Trellix",
    "abnormal security": "Abnormal Security",
    "ironscales": "IronScales",
    "zscaler": "Zscaler",
}

HOSTING_NAME_PATTERNS = {
    "amazon": "AWS", "aws": "AWS",
    "microsoft azure": "Azure", "azure cloud": "Azure",
    "google cloud": "GCP",
    "digitalocean": "DigitalOcean",
    "linode": "Linode", "akamai": "Akamai",
    "vultr": "Vultr", "choopa": "Vultr",
    "ovh": "OVH", "ovhcloud": "OVH",
    "hetzner": "Hetzner",
    "m247": "M247",
    "leaseweb": "Leaseweb",
    "nobis": "Nobis", "ubiquity": "Ubiquity",
    "contabo": "Contabo",
    "hostwinds": "Hostwinds",
    "sharktech": "Sharktech",
    "psychz": "Psychz",
    "quadranet": "QuadraNet",
    "cloudflare": "Cloudflare",
    "fastly": "Fastly",
    "incapsula": "Imperva",
    "myloc": "myLoc", "wiit": "myLoc",
    "constant company": "Constant Company",
}

STATUS_RANK = {
    "Submitted Data": 4, "Clicked Link": 3,
    "Email Opened": 2, "Email Sent": 1, "Email Reported": 0,
}

FILTER_CLASSIFICATIONS = frozenset({
    "scanner", "security_infra", "proxy_automated", "proxy_ambiguous",
})

# ── Helpers ────────────────────────────────────────────────────────


def _parse_ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _match_pattern(text, patterns):
    if not text:
        return None
    lower = text.lower()
    for pat, label in patterns.items():
        if pat in lower:
            return label
    return None


def _is_scanner_ua(ua):
    if not ua:
        return False
    return any(sig in ua for sig in SCANNER_UA_SIGS)


def _check_security_cidr(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    for net, vendor in _SECURITY_NETS.items():
        if addr in net:
            return vendor
    return None


def _fmt_delta(secs):
    if secs is None:
        return "n/a"
    if secs < 0:
        return f"-{_fmt_delta(-secs)}"
    if secs < 60:
        return f"{secs:.0f}s"
    if secs < 3600:
        return f"{int(secs // 60)}m {int(secs % 60)}s"
    h = int(secs // 3600)
    m = int((secs % 3600) // 60)
    return f"{h}h {m}m"


def _short_ua(ua, maxlen=55):
    if not ua:
        return "(none)"
    if "iPhone" in ua:
        m = re.search(r"iPhone OS (\d+[_\d]*)", ua)
        ios = m.group(1).replace("_", ".") if m else "?"
        browser = "Safari"
        if "EdgiOS" in ua:
            browser = "Edge"
        elif "CriOS" in ua:
            browser = "Chrome"
        elif "FxiOS" in ua:
            browser = "Firefox"
        return f"iPhone iOS {ios} / {browser}"
    if "Macintosh" in ua:
        m = re.search(r"Mac OS X ([\d_]+)", ua)
        ver = m.group(1).replace("_", ".") if m else "?"
        browser = "Chrome"
        if "Edg/" in ua:
            browser = "Edge"
        elif "Firefox/" in ua:
            browser = "Firefox"
        elif "Safari/" in ua and "Chrome" not in ua:
            browser = "Safari"
        m2 = re.search(r"(?:Chrome|Edg|Firefox)/([\d.]+)", ua)
        bver = m2.group(1).split(".")[0] if m2 else "?"
        return f"macOS {ver} / {browser} {bver}"
    if "Windows NT" in ua:
        browser = "Chrome"
        if "Edg/" in ua:
            browser = "Edge"
        elif "Firefox/" in ua:
            browser = "Firefox"
        m = re.search(r"(?:Chrome|Edg|Firefox)/([\d.]+)", ua)
        bver = m.group(1).split(".")[0] if m else "?"
        return f"Windows / {browser} {bver}"
    if "Linux" in ua and "X11" in ua:
        m = re.search(r"Chrome/([\d.]+)", ua)
        bver = m.group(1).split(".")[0] if m else "?"
        return f"Linux / Chrome {bver} [SANDBOX]"
    return ua[:maxlen]


# ── Main analyzer ─────────────────────────────────────────────────


class PhishAnalyzer:

    def __init__(self, events_path, results_path=None, no_geo=False,
                 cache_path=None, verbose=False):
        self.events_path = Path(events_path)
        self.results_path = Path(results_path) if results_path else None
        self.no_geo = no_geo
        self.cache_path = (Path(cache_path) if cache_path
                           else self.events_path.with_suffix(".geo_cache.json"))
        self.verbose = verbose

        self.events = []
        self.users = {}
        self.sent_times = {}
        self.ip_profiles = {}
        self.detected_tech = {}
        self.dominant_proxy_ua = None

    # ── Data loading ──────────────────────────────────────────────

    def _load_events(self):
        with open(self.events_path, newline="", encoding="utf-8-sig") as f:
            for row in csv.DictReader(f):
                msg = row.get("message", "")
                if msg == "Campaign Created":
                    continue
                email = row.get("email", "").strip()
                if not email:
                    continue
                ts = _parse_ts(row["time"])
                ip = ua = None
                details = row.get("details", "")
                if details:
                    try:
                        d = json.loads(details)
                        ip = d.get("browser", {}).get("address")
                        ua = d.get("browser", {}).get("user-agent")
                    except (json.JSONDecodeError, AttributeError):
                        pass
                self.events.append({
                    "email": email, "time": ts, "message": msg,
                    "ip": ip, "ua": ua, "classification": None,
                })
                if msg == "Email Sent":
                    self.sent_times[email] = ts
                if email not in self.users:
                    self.users[email] = {
                        "email": email, "first_name": "", "last_name": "",
                        "gophish_status": "", "position": "",
                    }

    def _load_results(self):
        if not self.results_path or not self.results_path.exists():
            return
        with open(self.results_path, newline="", encoding="utf-8-sig") as f:
            for row in csv.DictReader(f):
                email = row.get("email", "").strip()
                if not email:
                    continue
                if email not in self.users:
                    self.users[email] = {
                        "email": email, "first_name": "", "last_name": "",
                        "gophish_status": "", "position": "",
                    }
                u = self.users[email]
                u["first_name"] = row.get("first_name", "")
                u["last_name"] = row.get("last_name", "")
                u["gophish_status"] = row.get("status", "")
                u["position"] = row.get("position", "")
                if not self.sent_times.get(email) and row.get("send_date"):
                    try:
                        self.sent_times[email] = _parse_ts(row["send_date"])
                    except Exception:
                        pass

    # ── IP geolocation ────────────────────────────────────────────

    def _collect_unique_ips(self):
        return sorted({ev["ip"] for ev in self.events if ev["ip"]})

    def _load_geo_cache(self):
        if self.cache_path and self.cache_path.exists():
            try:
                with open(self.cache_path) as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save_geo_cache(self, cache):
        try:
            with open(self.cache_path, "w") as f:
                json.dump(cache, f, indent=2)
        except Exception:
            pass

    def _batch_geolocate(self, ips):
        BATCH_SIZE = 100
        FIELDS = ("status,message,country,countryCode,regionName,city,"
                   "isp,org,as,asname,mobile,proxy,hosting,query")
        results = {}
        batches = [ips[i:i + BATCH_SIZE]
                   for i in range(0, len(ips), BATCH_SIZE)]
        for idx, batch in enumerate(batches):
            payload = [{"query": ip, "fields": FIELDS} for ip in batch]
            try:
                req = Request(
                    "http://ip-api.com/batch",
                    data=json.dumps(payload).encode(),
                    headers={"Content-Type": "application/json"},
                )
                with urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read())
                for item in data:
                    if item.get("status") == "success":
                        results[item["query"]] = item
                    else:
                        results[item.get("query", "")] = {}
            except (URLError, OSError, json.JSONDecodeError) as e:
                print(f"  [!] Geolocation batch {idx + 1} failed: {e}",
                      file=sys.stderr)
            if idx < len(batches) - 1:
                time.sleep(4)
        return results

    def _geolocate(self):
        all_ips = self._collect_unique_ips()
        if not all_ips:
            return

        cache = self._load_geo_cache() if not self.no_geo else {}
        uncached = [ip for ip in all_ips if ip not in cache]

        if uncached and not self.no_geo:
            print(f"  Geolocating {len(uncached)} IPs "
                  f"({len(all_ips) - len(uncached)} cached)...")
            fresh = self._batch_geolocate(uncached)
            cache.update(fresh)
            self._save_geo_cache(cache)

        for ip in all_ips:
            geo = cache.get(ip, {})
            profile = {
                "ip": ip,
                "country": geo.get("country", ""),
                "region": geo.get("regionName", ""),
                "city": geo.get("city", ""),
                "isp": geo.get("isp", ""),
                "org": geo.get("org", ""),
                "asn": geo.get("as", ""),
                "asname": geo.get("asname", ""),
                "is_hosting": bool(geo.get("hosting")),
                "is_proxy": bool(geo.get("proxy")),
                "is_mobile": bool(geo.get("mobile")),
                "vendor": None,
                "provider": None,
                "classification": "unknown",
            }

            cidr_vendor = _check_security_cidr(ip)
            if cidr_vendor:
                profile["vendor"] = cidr_vendor
                profile["classification"] = "security"
            else:
                for field in ("isp", "org", "asname"):
                    v = _match_pattern(profile[field], VENDOR_NAME_PATTERNS)
                    if v:
                        profile["vendor"] = v
                        break
                for field in ("isp", "org", "asname"):
                    h = _match_pattern(profile[field], HOSTING_NAME_PATTERNS)
                    if h:
                        profile["provider"] = h
                        break

                if profile["vendor"] and profile["is_hosting"]:
                    profile["classification"] = "security"
                elif profile["is_hosting"]:
                    profile["classification"] = "hosting"
                elif profile["is_proxy"]:
                    profile["classification"] = "proxy"
                elif profile["is_mobile"]:
                    profile["classification"] = "mobile"
                else:
                    profile["classification"] = "residential"

            self.ip_profiles[ip] = profile

    # ── Event classification ──────────────────────────────────────

    def _find_dominant_proxy_ua(self):
        hosting_click_uas = Counter()
        for ev in self.events:
            if ev["message"] != "Clicked Link":
                continue
            if _is_scanner_ua(ev.get("ua")):
                continue
            p = self.ip_profiles.get(ev.get("ip"), {})
            if p.get("is_hosting") or p.get("classification") in (
                    "hosting", "security"):
                hosting_click_uas[ev.get("ua", "")] += 1
        if not hosting_click_uas:
            return None
        top_ua, top_count = hosting_click_uas.most_common(1)[0]
        total = sum(hosting_click_uas.values())
        if total >= 3 and top_count / total > 0.50:
            return top_ua
        return None

    def _classify_events(self):
        self.dominant_proxy_ua = self._find_dominant_proxy_ua()

        scanner_times = defaultdict(list)
        for ev in self.events:
            if (ev["message"] == "Clicked Link"
                    and _is_scanner_ua(ev.get("ua"))):
                scanner_times[ev["email"]].append(ev["time"])

        for ev in self.events:
            ip = ev.get("ip")
            ua = ev.get("ua")
            msg = ev["message"]
            p = self.ip_profiles.get(ip, {}) if ip else {}

            if msg in ("Email Sent", "Campaign Created"):
                ev["classification"] = "meta"
                continue

            if msg == "Email Reported":
                ev["classification"] = "real"
                continue

            if not ip:
                ev["classification"] = "real"
                continue

            if _is_scanner_ua(ua):
                ev["classification"] = "scanner"
                continue

            if p.get("classification") == "security":
                ev["classification"] = "security_infra"
                continue

            # Submitted Data from any IP is real — bots don't fill forms
            if msg == "Submitted Data":
                ev["classification"] = "real"
                continue

            is_hosting = (p.get("is_hosting")
                          or p.get("classification") == "hosting")

            if is_hosting:
                if self.dominant_proxy_ua and ua == self.dominant_proxy_ua:
                    ev["classification"] = "proxy_automated"
                    continue

                if msg == "Clicked Link" and scanner_times.get(ev["email"]):
                    ev_time = ev["time"]
                    closest = min(
                        scanner_times[ev["email"]],
                        key=lambda st: abs((ev_time - st).total_seconds()),
                    )
                    gap = abs((ev_time - closest).total_seconds())
                    if gap <= 180:
                        ev["classification"] = "proxy_automated"
                        continue

                if msg == "Email Opened":
                    sent_t = self.sent_times.get(ev["email"])
                    if sent_t:
                        delta = (ev["time"] - sent_t).total_seconds()
                        if delta < 30:
                            ev["classification"] = "proxy_automated"
                            continue

                ev["classification"] = "proxy_ambiguous"
                continue

            ev["classification"] = "real"

    # ── Technology detection ──────────────────────────────────────

    def _detect_technology(self):
        techs = {}

        open_sources = defaultdict(set)
        scanner_sources = defaultdict(set)
        proxy_sources = defaultdict(set)

        for ev in self.events:
            ip = ev.get("ip")
            if not ip:
                continue
            p = self.ip_profiles.get(ip, {})
            cls = ev["classification"]

            if ev["message"] == "Email Opened" and cls in FILTER_CLASSIFICATIONS:
                prov = (p.get("provider") or p.get("vendor")
                        or p.get("isp", "Unknown"))
                open_sources[prov].add(ip)

            if cls == "scanner":
                prov = (p.get("provider") or p.get("vendor")
                        or p.get("isp", "Unknown"))
                scanner_sources[prov].add(ip)

            if cls == "proxy_automated":
                prov = p.get("provider") or p.get("isp", "Unknown")
                proxy_sources[prov].add(ip)

        for prov, ips in open_sources.items():
            if "Azure" in prov or "Microsoft" in prov:
                techs["Microsoft Defender for Office 365"] = {
                    "role": "Safe Links / Safe Attachments — automated "
                            "tracking pixel opens from Azure infrastructure",
                    "ip_count": len(ips),
                    "sample_ips": sorted(ips)[:5],
                }
            elif "Proofpoint" in prov:
                techs["Proofpoint Email Protection"] = {
                    "role": "Email gateway scanning",
                    "ip_count": len(ips),
                    "sample_ips": sorted(ips)[:5],
                }
            elif "Google" in prov or "GCP" in prov:
                techs["Google Workspace Email Security"] = {
                    "role": "Gmail scanning infrastructure",
                    "ip_count": len(ips),
                    "sample_ips": sorted(ips)[:5],
                }

        for prov, ips in scanner_sources.items():
            if "AWS" in prov:
                techs["Cloud URL Sandbox (AWS-hosted)"] = {
                    "role": "URL detonation sandbox — clicks links with "
                            "headless Linux browser to check for malware",
                    "ip_count": len(ips),
                    "sample_ips": sorted(ips)[:5],
                }
            elif "Azure" in prov or "Microsoft" in prov:
                t = techs.setdefault("Microsoft Defender for Office 365", {
                    "role": "Safe Links URL scanning",
                    "ip_count": 0,
                    "sample_ips": [],
                })
                t["ip_count"] += len(ips)
                t["sample_ips"] = sorted(set(t["sample_ips"]) | ips)[:5]
            elif "GCP" in prov or "Google" in prov:
                techs["Cloud URL Sandbox (GCP-hosted)"] = {
                    "role": "URL detonation sandbox hosted on Google Cloud",
                    "ip_count": len(ips),
                    "sample_ips": sorted(ips)[:5],
                }

        if proxy_sources:
            all_proxy_ips = set()
            provs = Counter()
            for prov, ips in proxy_sources.items():
                all_proxy_ips.update(ips)
                provs[prov] += len(ips)
            top = ", ".join(f"{p} ({c})" for p, c in provs.most_common(5))
            techs["URL Defense Proxy Chain"] = {
                "role": f"Automated URL re-verification via datacenter "
                        f"proxies: {top}",
                "ip_count": len(all_proxy_ips),
                "sample_ips": sorted(all_proxy_ips)[:5],
            }

        self.detected_tech = techs

    # ── User analysis ─────────────────────────────────────────────

    def _analyze_users(self):
        for u in self.users.values():
            u.update({
                "events_real": [], "events_filter": [], "events_meta": [],
                "real_opens": 0, "real_clicks": 0, "real_submits": 0,
                "filter_opens": 0, "filter_clicks": 0,
                "corrected_status": "Email Sent",
            })

        for ev in self.events:
            email = ev["email"]
            if email not in self.users:
                continue
            u = self.users[email]
            cls = ev["classification"]
            is_filter = cls in FILTER_CLASSIFICATIONS

            if cls == "meta":
                u["events_meta"].append(ev)
            elif is_filter:
                u["events_filter"].append(ev)
                if ev["message"] == "Email Opened":
                    u["filter_opens"] += 1
                elif ev["message"] == "Clicked Link":
                    u["filter_clicks"] += 1
            else:
                u["events_real"].append(ev)
                if ev["message"] == "Email Opened":
                    u["real_opens"] += 1
                elif ev["message"] == "Clicked Link":
                    u["real_clicks"] += 1
                elif ev["message"] == "Submitted Data":
                    u["real_submits"] += 1

        for u in self.users.values():
            if u["real_submits"] > 0:
                u["corrected_status"] = "Submitted Data"
            elif u["real_clicks"] > 0:
                u["corrected_status"] = "Clicked Link"
            elif u["real_opens"] > 0:
                u["corrected_status"] = "Email Opened"
            else:
                u["corrected_status"] = "Email Sent"

    # ── Main run ──────────────────────────────────────────────────

    def run(self):
        print(f"GoPhish Campaign Analyzer v{SCRIPT_VERSION}")
        print("─" * 60)
        print(f"  Events file:  {self.events_path}")
        if self.results_path:
            print(f"  Results file: {self.results_path}")
        print()

        print("  Loading data...")
        self._load_events()
        self._load_results()
        print(f"    {len(self.events)} events, {len(self.users)} users")

        if not self.no_geo:
            self._geolocate()
        else:
            print("  Geolocation: SKIPPED (--no-geo)")
            for ev in self.events:
                if ev["ip"] and ev["ip"] not in self.ip_profiles:
                    self.ip_profiles[ev["ip"]] = {
                        "ip": ev["ip"], "classification": "unknown",
                        "is_hosting": False, "is_proxy": False,
                        "is_mobile": False, "vendor": None, "provider": None,
                        "city": "", "region": "", "country": "", "isp": "",
                        "org": "", "asn": "", "asname": "",
                    }

        print("  Classifying events...")
        self._classify_events()
        self._detect_technology()
        self._analyze_users()
        print("  Done.\n")
        return self

    # ── Report: text ──────────────────────────────────────────────

    def report_text(self):
        lines = []
        W = 95

        lines.append("=" * W)
        lines.append("  GOPHISH CAMPAIGN ANALYSIS REPORT")
        lines.append(f"  Generated: "
                     f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  "
                     f"Analyzer v{SCRIPT_VERSION}")
        lines.append("=" * W)

        # ── Technology
        lines.append("\n── DETECTED EMAIL SECURITY TECHNOLOGY "
                     + "─" * (W - 40))
        if self.detected_tech:
            for tech, info in self.detected_tech.items():
                lines.append(f"\n  {tech}")
                lines.append(f"    Role: {info['role']}")
                n = info["ip_count"]
                ips = info.get("sample_ips", [])
                ip_str = ", ".join(ips[:3])
                if n > 3:
                    ip_str += f" (+{n - 3} more)"
                lines.append(f"    IPs:  {ip_str}")
        else:
            lines.append("\n  No email security infrastructure detected.")

        if self.dominant_proxy_ua:
            lines.append(f"\n  Dominant automated proxy UA "
                         f"({_short_ua(self.dominant_proxy_ua)}):")
            lines.append(f"    {self.dominant_proxy_ua}")

        # ── Summary
        lines.append(f"\n── CAMPAIGN SUMMARY {'─' * (W - 21)}\n")

        raw = Counter()
        corrected = Counter()
        for u in self.users.values():
            gs = u.get("gophish_status", "Email Sent") or "Email Sent"
            raw[gs] += 1
            corrected[u["corrected_status"]] += 1

        r_sent = sum(raw.values())
        r_opened = sum(raw[s] for s in
                       ("Email Opened", "Clicked Link", "Submitted Data"))
        r_clicked = raw["Clicked Link"] + raw["Submitted Data"]
        r_submit = raw["Submitted Data"]

        c_opened = sum(corrected[s] for s in
                       ("Email Opened", "Clicked Link", "Submitted Data"))
        c_clicked = corrected["Clicked Link"] + corrected["Submitted Data"]
        c_submit = corrected["Submitted Data"]

        hdr = (f"  {'Metric':<22} {'GoPhish Raw':>12} "
               f"{'Corrected':>12} {'Delta':>8}")
        lines.append(hdr)
        lines.append("  " + "─" * (len(hdr) - 2))
        lines.append(f"  {'Emails Sent':<22} {r_sent:>12} "
                     f"{r_sent:>12} {'':>8}")
        lines.append(f"  {'Emails Opened':<22} {r_opened:>12} "
                     f"{c_opened:>12} {c_opened - r_opened:>+8}")
        lines.append(f"  {'Clicked Link':<22} {r_clicked:>12} "
                     f"{c_clicked:>12} {c_clicked - r_clicked:>+8}")
        lines.append(f"  {'Submitted Data':<22} {r_submit:>12} "
                     f"{c_submit:>12} {c_submit - r_submit:>+8}")

        if r_sent > 0:
            lines.append("")
            lines.append(f"  {'Click rate:':<22} "
                         f"{r_clicked / r_sent * 100:>11.1f}% "
                         f"{c_clicked / r_sent * 100:>11.1f}%")
            lines.append(f"  {'Submit rate:':<22} "
                         f"{r_submit / r_sent * 100:>11.1f}% "
                         f"{c_submit / r_sent * 100:>11.1f}%")

        # ── Classification breakdown
        lines.append(f"\n── EVENT CLASSIFICATION BREAKDOWN "
                     f"{'─' * (W - 36)}\n")
        cls_counts = Counter(ev["classification"] for ev in self.events)
        cls_labels = [
            ("real", "Real (confirmed human)"),
            ("scanner", "Scanner (sandbox UA)"),
            ("security_infra", "Security infrastructure (known vendor IP)"),
            ("proxy_automated", "Automated proxy (URL Defense chain)"),
            ("proxy_ambiguous", "Ambiguous proxy (hosting IP, atypical UA)"),
            ("meta", "Meta (sent/created)"),
        ]
        for cls, label in cls_labels:
            c = cls_counts.get(cls, 0)
            if c:
                lines.append(f"  {label:<52} {c:>6} events")

        # ── All users
        lines.append(f"\n── ALL USERS {'─' * (W - 14)}\n")
        sorted_users = sorted(
            self.users.values(),
            key=lambda u: (
                -STATUS_RANK.get(u["corrected_status"], 0),
                -STATUS_RANK.get(u.get("gophish_status", ""), 0),
                u.get("last_name", ""),
            ),
        )

        hdr = (f"  {'Name':<26} {'GoPhish':<18} {'Real':>5} "
               f"{'Filter':>7}  {'Corrected':<18}")
        lines.append(hdr)
        lines.append("  " + "─" * (len(hdr) - 2))

        for u in sorted_users:
            name = (f"{u['first_name']} {u['last_name']}".strip()
                    or u["email"].split("@")[0])
            if len(name) > 25:
                name = name[:22] + "..."
            gs = u.get("gophish_status", "Email Sent") or "Email Sent"
            real_c = len(u["events_real"])
            filt_c = len(u["events_filter"])
            cs = u["corrected_status"]
            flag = " *" if cs != gs else ""
            lines.append(
                f"  {name:<26} {gs:<18} {real_c:>5} {filt_c:>7}  {cs}{flag}"
            )

        lines.append(f"\n  (* = corrected status differs from GoPhish)")

        # ── Failed users
        lines.append(f"\n── USERS WHO FAILED (real click or submission) "
                     f"{'─' * (W - 48)}\n")

        failed = [u for u in sorted_users
                  if u["corrected_status"] in ("Clicked Link",
                                                "Submitted Data")]
        if not failed:
            lines.append("  No users had confirmed real clicks or "
                         "submissions.")
        else:
            for u in failed:
                name = f"{u['first_name']} {u['last_name']}".strip()
                lines.append(f"  {name} ({u['email']})")
                lines.append(f"    Corrected status: {u['corrected_status']}")

                for ev in sorted(u["events_real"],
                                 key=lambda e: e["time"]):
                    if ev["message"] not in ("Clicked Link",
                                              "Submitted Data"):
                        continue
                    ip = ev.get("ip", "n/a")
                    p = self.ip_profiles.get(ip, {})
                    city = p.get("city", "?")
                    region = p.get("region", "?")
                    country = p.get("country", "")
                    loc = f"{city}, {region}"
                    if country and country != "United States":
                        loc += f", {country}"
                    isp = p.get("isp", "?")
                    ua = _short_ua(ev.get("ua"))
                    sent_t = self.sent_times.get(u["email"])
                    delta = _fmt_delta(
                        (ev["time"] - sent_t).total_seconds()
                    ) if sent_t else "?"
                    hosting = " [HOSTING]" if p.get("is_hosting") else ""

                    lines.append(
                        f"    {ev['message']:<18} {ip:<18} "
                        f"{loc}{hosting}"
                    )
                    lines.append(
                        f"      ISP: {isp}")
                    lines.append(
                        f"      UA:  {ua}  |  Δ: {delta}")
                lines.append("")

        # ── Never opened
        never_opened = [
            u for u in sorted_users
            if (u.get("gophish_status") in
                ("Email Opened", "Clicked Link", "Submitted Data")
                and u["corrected_status"] == "Email Sent"
                and u["filter_opens"] > 0)
        ]

        if never_opened:
            lines.append(
                f"── USERS WHO LIKELY NEVER OPENED "
                f"({len(never_opened)}) "
                f"{'─' * max(0, W - 38 - len(str(len(never_opened))))}\n"
            )
            lines.append("  All Email Opened events from security "
                         "infrastructure only:\n")
            for u in never_opened:
                name = (f"{u['first_name']} {u['last_name']}".strip()
                        or u["email"].split("@")[0])
                lines.append(f"  {name:<28} {u['email']}")
                open_ips = set()
                for ev in u["events_filter"]:
                    if ev["message"] == "Email Opened" and ev.get("ip"):
                        open_ips.add(ev["ip"])
                for oip in sorted(open_ips):
                    p = self.ip_profiles.get(oip, {})
                    prov = (p.get("provider") or p.get("vendor")
                            or p.get("isp", "?"))
                    loc = f"{p.get('city', '?')}, {p.get('region', '?')}"
                    lines.append(f"    └ {oip:<18} {prov:<20} {loc}")
            lines.append("")

        # ── IP summary
        lines.append(f"── IP CLASSIFICATION SUMMARY "
                     f"{'─' * (W - 30)}\n")
        ip_classes = Counter(
            p.get("classification", "unknown")
            for p in self.ip_profiles.values()
        )
        ip_labels = [
            ("security", "Known security vendor"),
            ("hosting", "Datacenter / hosting"),
            ("proxy", "Proxy / VPN"),
            ("mobile", "Mobile network"),
            ("residential", "Residential / business ISP"),
            ("unknown", "Unknown / unresolved"),
        ]
        for cls, label in ip_labels:
            c = ip_classes.get(cls, 0)
            if c:
                lines.append(f"  {label:<35} {c:>4} unique IPs")

        lines.append(f"\n{'=' * W}")
        return "\n".join(lines)

    # ── Report: JSON ──────────────────────────────────────────────

    def report_json(self):
        all_users = []
        failed = []

        for u in self.users.values():
            name = f"{u['first_name']} {u['last_name']}".strip()
            rec = {
                "email": u["email"],
                "name": name,
                "position": u.get("position", ""),
                "gophish_status": u.get("gophish_status", ""),
                "corrected_status": u["corrected_status"],
                "real_opens": u["real_opens"],
                "real_clicks": u["real_clicks"],
                "real_submits": u["real_submits"],
                "filter_opens": u["filter_opens"],
                "filter_clicks": u["filter_clicks"],
                "total_real_events": len(u["events_real"]),
                "total_filter_events": len(u["events_filter"]),
            }
            all_users.append(rec)

            if u["corrected_status"] in ("Clicked Link", "Submitted Data"):
                detail = dict(rec)
                detail["real_events"] = []
                for ev in u["events_real"]:
                    ip = ev.get("ip", "")
                    p = self.ip_profiles.get(ip, {})
                    sent_t = self.sent_times.get(u["email"])
                    delta = ((ev["time"] - sent_t).total_seconds()
                             if sent_t else None)
                    detail["real_events"].append({
                        "message": ev["message"],
                        "time": ev["time"].isoformat(),
                        "ip": ip,
                        "ua": ev.get("ua", ""),
                        "ua_short": _short_ua(ev.get("ua")),
                        "city": p.get("city", ""),
                        "region": p.get("region", ""),
                        "country": p.get("country", ""),
                        "isp": p.get("isp", ""),
                        "org": p.get("org", ""),
                        "is_hosting": p.get("is_hosting", False),
                        "is_mobile": p.get("is_mobile", False),
                        "seconds_after_send": delta,
                    })
                failed.append(detail)

        r_sent = len(self.users)
        r_opened = len([
            u for u in self.users.values()
            if u.get("gophish_status") in
            ("Email Opened", "Clicked Link", "Submitted Data")
        ])
        r_clicked = len([
            u for u in self.users.values()
            if u.get("gophish_status") in ("Clicked Link", "Submitted Data")
        ])
        r_submit = len([
            u for u in self.users.values()
            if u.get("gophish_status") == "Submitted Data"
        ])

        c_opened = len([
            u for u in self.users.values()
            if u["corrected_status"] in
            ("Email Opened", "Clicked Link", "Submitted Data")
        ])
        c_clicked = len([
            u for u in self.users.values()
            if u["corrected_status"] in ("Clicked Link", "Submitted Data")
        ])
        c_submit = len([
            u for u in self.users.values()
            if u["corrected_status"] == "Submitted Data"
        ])

        return {
            "analyzer_version": SCRIPT_VERSION,
            "generated": datetime.now().isoformat(),
            "events_file": str(self.events_path),
            "results_file": (str(self.results_path)
                             if self.results_path else None),
            "detected_technology": {
                k: {"role": v["role"], "ip_count": v["ip_count"],
                     "sample_ips": v.get("sample_ips", [])}
                for k, v in self.detected_tech.items()
            },
            "dominant_automated_ua": self.dominant_proxy_ua,
            "summary": {
                "raw": {"sent": r_sent, "opened": r_opened,
                        "clicked": r_clicked, "submitted": r_submit},
                "corrected": {"sent": r_sent, "opened": c_opened,
                              "clicked": c_clicked, "submitted": c_submit},
            },
            "event_classifications": dict(
                Counter(ev["classification"] for ev in self.events)
            ),
            "ip_classifications": dict(
                Counter(p["classification"]
                        for p in self.ip_profiles.values())
            ),
            "all_users": sorted(all_users, key=lambda u: u["email"]),
            "failed_users": failed,
            "never_opened": [
                {"email": u["email"],
                 "name": f"{u['first_name']} {u['last_name']}".strip()}
                for u in self.users.values()
                if (u.get("gophish_status") in
                    ("Email Opened", "Clicked Link", "Submitted Data")
                    and u["corrected_status"] == "Email Sent"
                    and u["filter_opens"] > 0)
            ],
        }

    def report_csv(self):
        rows = []
        for u in sorted(self.users.values(), key=lambda u: u["email"]):
            rows.append({
                "email": u["email"],
                "first_name": u["first_name"],
                "last_name": u["last_name"],
                "position": u.get("position", ""),
                "gophish_status": u.get("gophish_status", ""),
                "corrected_status": u["corrected_status"],
                "real_opens": u["real_opens"],
                "filter_opens": u["filter_opens"],
                "real_clicks": u["real_clicks"],
                "filter_clicks": u["filter_clicks"],
                "real_submits": u["real_submits"],
            })
        return rows


# ── CLI ───────────────────────────────────────────────────────────


def main():
    ap = argparse.ArgumentParser(
        description="Analyze GoPhish campaign data — identify and strip "
                    "email security filter artifacts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Part of the pr0t31n Crucible toolkit.",
    )
    ap.add_argument("events", help="GoPhish events CSV file")
    ap.add_argument("results", nargs="?", default=None,
                    help="GoPhish results CSV file (optional, adds user "
                         "names and positions)")
    ap.add_argument("--no-geo", action="store_true",
                    help="Skip IP geolocation (offline mode)")
    ap.add_argument("--cache", default=None,
                    help="Geo cache file path (default: alongside events "
                         "CSV)")
    ap.add_argument("--json", dest="json_out", default=None,
                    help="Write JSON report to file")
    ap.add_argument("--csv", dest="csv_out", default=None,
                    help="Write corrected results CSV to file")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="Show per-event classification detail")
    ap.add_argument("--version", action="version",
                    version=f"phish_analyzer {SCRIPT_VERSION}")
    args = ap.parse_args()

    if not Path(args.events).exists():
        print(f"Error: events file not found: {args.events}",
              file=sys.stderr)
        sys.exit(1)
    if args.results and not Path(args.results).exists():
        print(f"Error: results file not found: {args.results}",
              file=sys.stderr)
        sys.exit(1)

    analyzer = PhishAnalyzer(
        events_path=args.events,
        results_path=args.results,
        no_geo=args.no_geo,
        cache_path=args.cache,
        verbose=args.verbose,
    )
    analyzer.run()

    print(analyzer.report_text())

    if args.json_out:
        report = analyzer.report_json()
        with open(args.json_out, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\nJSON report written to {args.json_out}")

    if args.csv_out:
        rows = analyzer.report_csv()
        if rows:
            with open(args.csv_out, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=rows[0].keys())
                w.writeheader()
                w.writerows(rows)
            print(f"Corrected CSV written to {args.csv_out}")


if __name__ == "__main__":
    main()
