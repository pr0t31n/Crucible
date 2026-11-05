"""Crucible v2.0 — application configuration constants."""

import sys
import shutil
from pathlib import Path

VERSION = Path(__file__).resolve().parent.joinpath("VERSION").read_text().strip()
PORT = 5100
APP_NAME = "Crucible"
APP_SUBTITLE = "Unified Penetration Testing Platform"

APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
TEMPLATE_DIR = APP_DIR / "templates"

PYTHON3 = sys.executable or shutil.which("python3")

# ── Clients base directory (platform-aware) ──────────────────
if sys.platform == "darwin":
    CLIENTS_BASE = Path("/Users/Shared/clients")
elif sys.platform == "win32":
    CLIENTS_BASE = Path("C:/clients")
else:
    CLIENTS_BASE = Path("/clients")

if not CLIENTS_BASE.exists():
    if sys.platform in ("linux", "linux2"):
        try:
            CLIENTS_BASE.mkdir(parents=True, exist_ok=True)
        except OSError:
            CLIENTS_BASE = Path.home() / "clients"
    else:
        CLIENTS_BASE = Path.home() / "clients"

# ── Tool registry ────────────────────────────────────────────
TOOL_DIR = Path("/opt/pr0t31n")

TOOLS = {
    "ss3":      {"name": "Scattershot3",   "key": "SS", "domain": "recon",    "script": TOOL_DIR / "Scattershot3/scattershot3.py",  "sudo": True,  "group": "recon",    "desc": "Network reconnaissance and service enumeration"},
    "osift":    {"name": "OSift",          "key": "OS", "domain": "recon",    "script": TOOL_DIR / "OSift/osift.py",                "sudo": True,  "group": "recon",    "desc": "OSINT gathering and domain intelligence"},
    "trawler":  {"name": "Trawler",        "key": "TR", "domain": "traffic",  "script": TOOL_DIR / "Trawler/trawler.py",            "sudo": False, "group": "any",      "desc": "Network traffic capture and analysis"},
    "fracture": {"name": "Fracture",       "key": "FR", "domain": "webapp",   "script": TOOL_DIR / "Fracture/fracture.py",          "sudo": False, "group": "target",   "desc": "Web application vulnerability testing"},
    "siphon":   {"name": "Siphon",         "key": "SI", "domain": "api",      "script": TOOL_DIR / "Siphon/siphon.py",              "sudo": False, "group": "target",   "desc": "API security testing and endpoint analysis"},
    "auger":    {"name": "Auger",          "key": "AU", "domain": "db",       "script": TOOL_DIR / "Auger/auger.py",                "sudo": False, "group": "target",   "desc": "Database security auditing"},
    "aether":   {"name": "Aether (Wi-Fi)",     "key": "AE", "domain": "wireless", "script": TOOL_DIR / "Aether/aether.py",              "sudo": True,  "group": "wireless", "desc": "Wi-Fi security analysis"},
    "aether_b": {"name": "Aether (Bluetooth)", "key": "AB", "domain": "wireless", "script": TOOL_DIR / "Aether-B/aether_b.py",          "sudo": True,  "group": "wireless", "desc": "Bluetooth security analysis"},
    "aether_z": {"name": "Aether (Zigbee)",    "key": "AZ", "domain": "wireless", "script": TOOL_DIR / "Aether-Z/aether_z.py",          "sudo": True,  "group": "wireless", "desc": "Zigbee protocol analysis"},
    "aether_u": {"name": "Aether (UWB)",       "key": "AW", "domain": "wireless", "script": TOOL_DIR / "Aether-U/aether_u.py",          "sudo": True,  "group": "wireless", "desc": "Ultra-Wideband security analysis"},
    "authprobe":{"name": "AuthProbe",      "key": "AP", "domain": "recon",    "script": TOOL_DIR / "AuthProbe/authprobe.py",         "sudo": False, "group": "any",      "desc": "Authentication mechanism detection"},
    "nessus":   {"name": "Nessus",         "key": "NE", "domain": "vuln",     "script": None,                                       "sudo": False, "group": "any",      "desc": "Vulnerability scanning (external)"},
    "bastion":  {"name": "Bastion",        "key": "BA", "domain": "firewall", "script": TOOL_DIR / "Bastion/bastion.py",             "sudo": False, "group": "any",      "desc": "Firewall configuration audit"},
    "forge":    {"name": "Forge",          "key": "FG", "domain": "cloud",    "script": TOOL_DIR / "Forge/forge.py",                 "sudo": False, "group": "any",      "desc": "Cloud infrastructure security audit"},
    "quill":    {"name": "Quill",          "key": "QU", "domain": "mobile",   "script": TOOL_DIR / "Quill/quill.py",                 "sudo": False, "group": "any",      "desc": "Mobile application security analysis"},
    "isotope":  {"name": "Isotope",       "key": "IS", "domain": "file",     "script": TOOL_DIR / "Isotope/isotope.py",             "sudo": False, "group": "any",      "desc": "Detailed file analysis"},
    "dredge":   {"name": "Dredge",        "key": "DG", "domain": "endpoint", "script": TOOL_DIR / "Dredge/dredge.py",               "sudo": False, "group": "any",      "desc": "Windows endpoint security audit"},
    "vault":    {"name": "Vault",         "key": "VT", "domain": "ad",       "script": TOOL_DIR / "Vault/vault.py",                "sudo": False, "group": "any",      "desc": "Active Directory credential testing"},
    "pain":     {"name": "pAIn",          "key": "PI", "domain": "ai",       "script": TOOL_DIR / "pAIn/pain.py",                  "sudo": False, "group": "any",      "desc": "AI pipeline prompt-injection red-team testing"},
    # ── External CLI tools ──────────────────────────────────────
    "nuclei":         {"name": "Nuclei",          "key": "NU", "domain": "vuln",    "script": None, "sudo": False, "group": "any", "desc": "Template-based vulnerability scanner"},
    "testssl":        {"name": "testssl.sh",      "key": "TS", "domain": "tls",     "script": None, "sudo": False, "group": "any", "desc": "TLS/SSL cipher and protocol testing"},
    "sslscan":        {"name": "sslscan",         "key": "SL", "domain": "tls",     "script": None, "sudo": False, "group": "any", "desc": "SSL/TLS cipher enumeration"},
    "droopescan":     {"name": "droopescan",      "key": "DS", "domain": "webapp",  "script": None, "sudo": False, "group": "any", "desc": "CMS vulnerability scanner"},
    "dnstwist":       {"name": "dnstwist",        "key": "DT", "domain": "recon",   "script": None, "sudo": False, "group": "any", "desc": "Domain permutation and typosquatting detection"},
    "xurlfind3r":     {"name": "xurlfind3r",      "key": "XU", "domain": "recon",   "script": None, "sudo": False, "group": "any", "desc": "URL and endpoint discovery"},
    "emailharvester": {"name": "EmailHarvester",  "key": "EH", "domain": "recon",   "script": None, "sudo": False, "group": "any", "desc": "Email address harvesting"},
    "asnmap":         {"name": "asnmap",          "key": "AN", "domain": "recon",   "script": None, "sudo": False, "group": "any", "desc": "ASN and IP range mapping"},
    "webanalyze":     {"name": "webanalyze",      "key": "WA", "domain": "recon",   "script": None, "sudo": False, "group": "any", "desc": "Web technology fingerprinting"},
    # ── Dependencies console ────────────────────────────────────
    "deps":           {"name": "Dependencies",    "key": "DP", "domain": "deps",   "script": None, "sudo": False, "group": "any", "desc": "External dependency tools (o365spray, etc.)"},
}

AETHER_TOOLS = {"aether", "aether_b", "aether_z", "aether_u"}

# ── Parallelism groups ───────────────────────────────────────
# recon  — ss3 + osift can run together, but NOT with target tools
# target — fracture, siphon, auger are serial and block during recon
# wireless — single radio, strictly serial
# any    — independent tools, can run alongside anything
PARALLEL_GROUPS = {
    "exclusive": {"ss3", "fracture", "siphon", "forge"} | AETHER_TOOLS,
    "any":       {"trawler", "auger", "authprobe", "nessus", "bastion", "quill", "isotope", "dredge", "vault", "pain",
                  "nuclei", "testssl", "sslscan", "droopescan", "dnstwist",
                  "xurlfind3r", "emailharvester", "asnmap", "webanalyze", "deps"},
}
# OSift can run alongside SS3 but no other exclusive tool
OSIFT_COMPAT = frozenset({"ss3"})

# Tools eligible for auto-queue (pr0t31n tools + Nessus)
AUTO_QUEUE_TOOLS = {
    "ss3", "osift", "fracture", "siphon", "auger", "trawler",
    "authprobe", "nessus", "bastion", "forge", "quill", "isotope", "dredge", "vault", "pain",
} | AETHER_TOOLS

# ── Environment variables per tool ───────────────────────────
TOOL_ENV = {
    "ss3":      {"CRUCIBLE_MANAGED": "1", "PYTHONUNBUFFERED": "1"},
    "osift":    {"CRUCIBLE_MANAGED": "1", "PYTHONUNBUFFERED": "1"},
    "trawler":  {"CRUCIBLE_MANAGED": "1", "PYTHONUNBUFFERED": "1"},
    "fracture": {"CRUCIBLE_MANAGED": "1", "PYTHONUNBUFFERED": "1"},
    "siphon":   {"CRUCIBLE_MANAGED": "1", "PYTHONUNBUFFERED": "1"},
    "auger":    {"CRUCIBLE_MANAGED": "1", "PYTHONUNBUFFERED": "1"},
    "aether":   {"CRUCIBLE_MANAGED": "1", "PYTHONUNBUFFERED": "1"},
    "aether_b": {"CRUCIBLE_MANAGED": "1", "PYTHONUNBUFFERED": "1"},
    "aether_z": {"CRUCIBLE_MANAGED": "1", "PYTHONUNBUFFERED": "1"},
    "aether_u": {"CRUCIBLE_MANAGED": "1", "PYTHONUNBUFFERED": "1"},
    "authprobe":{"PYTHONUNBUFFERED": "1"},
    "nessus":   {},
    "bastion":  {"CRUCIBLE_MANAGED": "1", "PYTHONUNBUFFERED": "1"},
    "forge":    {"CRUCIBLE_MANAGED": "1", "PYTHONUNBUFFERED": "1"},
    "quill":    {"CRUCIBLE_MANAGED": "1", "PYTHONUNBUFFERED": "1"},
    "isotope":  {"CRUCIBLE_MANAGED": "1", "PYTHONUNBUFFERED": "1"},
    "dredge":   {"CRUCIBLE_MANAGED": "1", "PYTHONUNBUFFERED": "1"},
    "vault":    {"CRUCIBLE_MANAGED": "1", "PYTHONUNBUFFERED": "1"},
    "pain":     {"CRUCIBLE_MANAGED": "1", "PYTHONUNBUFFERED": "1"},
    "nuclei":         {},
    "testssl":        {},
    "sslscan":        {},
    "droopescan":     {},
    "dnstwist":       {},
    "xurlfind3r":     {},
    "emailharvester": {},
    "asnmap":         {},
    "webanalyze":     {},
    "deps":           {},
}

# ── Settings file prefixes per tool ──────────────────────────
TOOL_SETTINGS_PREFIX = {
    "ss3": "ss", "osift": "os", "trawler": "tr",
    "fracture": "fr", "siphon": "si", "auger": "au",
    "aether": "ae", "aether_b": "ab", "aether_z": "az", "aether_u": "aw",
    "authprobe": "ap", "nessus": "nessus",
    "bastion": "ba", "forge": "fg", "quill": "qu", "isotope": "is", "dredge": "dg", "vault": "vt", "pain": "pi",
    "nuclei": "nu", "testssl": "ts", "sslscan": "sl", "droopescan": "ds",
    "dnstwist": "dt", "xurlfind3r": "xu", "emailharvester": "eh",
    "asnmap": "an", "webanalyze": "wa", "deps": "dp",
}

# ── Buffer limits ────────────────────────────────────────────
MAX_CONSOLE_LINES = 5000
MAX_LOG_ENTRIES = 2000
MAX_ERR_ENTRIES = 500
ERR_PER_PAGE = 50
LOG_PER_PAGE = 100

# ── Session ──────────────────────────────────────────────────
SESSION_TIMEOUT_MINUTES = 30
SESSION_WARNING_MINUTES = 5

# ── Persisted files (app dir) ────────────────────────────────
WORKERS_FILE = APP_DIR / "workers.json"
EXECUTE_QUEUE_FILE = APP_DIR / "execute_queue.json"
OSIFT_MASTER_SETTINGS = APP_DIR / "osift_master_settings.json"

# ── Curated palettes (10) ────────────────────────────────────
PALETTES = [
    {"id": "tuxedo",      "name": "Tuxedo",      "category": "Professional"},
    {"id": "blueprint",   "name": "Blueprint",    "category": "Professional"},
    {"id": "forge",       "name": "Forge",        "category": "Professional"},
    {"id": "bloom",       "name": "Bloom",        "category": "Casual"},
    {"id": "ember",       "name": "Ember",        "category": "Casual"},
    {"id": "coruscant",   "name": "Coruscant",    "category": "Nerdy"},
    {"id": "neuromancer", "name": "Neuromancer",  "category": "Nerdy"},
    {"id": "synthwave",   "name": "Synthwave",    "category": "Nerdy"},
    {"id": "espresso",    "name": "Espresso",     "category": "Natural"},
    {"id": "sage",        "name": "Sage",         "category": "Natural"},
]

DEFAULT_PALETTE = "forge"
DEFAULT_MODE = "light"

# ── Tool output dir names (in client year dir) ───────────────
TOOL_OUTPUT_DIRS = {
    "ss3": "scattershot", "osift": "osift", "trawler": "trawler",
    "fracture": "fracture", "siphon": "siphon", "auger": "auger",
    "aether": "aether", "aether_b": "aether_b", "aether_z": "aether_z",
    "aether_u": "aether_u",
    "bastion": "bastion", "forge": "forge", "quill": "quill", "isotope": "isotope", "dredge": "dredge", "vault": "vault", "pain": "pain",
    "authprobe": "authprobe", "nessus": "nessus",
    "nuclei": "nuclei", "testssl": "testssl", "sslscan": "sslscan",
    "droopescan": "droopescan", "dnstwist": "dnstwist", "xurlfind3r": "xurlfind3r",
    "emailharvester": "emailharvester", "asnmap": "asnmap", "webanalyze": "webanalyze",
    "deps": "deps",
}

# ── Nessus defaults ──────────────────────────────────────────
NESSUS_DEFAULT_PORT = 8834
NESSUS_POLL_INTERVAL = 30

# ── Risk levels (canonical set) ─────────────────────────────
VALID_RISKS = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

# ── FindingsDB ──────────────────────────────────────────────
FINDINGS_DB_FILENAME = "findings.db"

try:
    import sys as _fdb_sys
    if "/opt/pr0t31n/shared" not in _fdb_sys.path:
        _fdb_sys.path.insert(0, "/opt/pr0t31n/shared")
    import pr0t31n_findings_db as _fdb_check  # noqa: F401
    FINDINGS_DB_AVAILABLE = True
    del _fdb_check
except ImportError:
    FINDINGS_DB_AVAILABLE = False

# ── Import tab ──────────────────────────────────────────────
IMPORT_MAX_CONCURRENT = 3

IMPORT_TOOL_MAP = {
    "nmap": "ss3",
    "nessus": "nessus",
    "nuclei": "fracture",
    "testssl": "ss3",
    "sslscan": "ss3",
    "ssh-audit": "ss3",
    "wpscan": "fracture",
    "ffuf": "fracture",
    "gobuster": "ss3",
    "feroxbuster": "fracture",
    "nikto": "fracture",
    "smbmap": "ss3",
    "enum4linux": "ss3",
    "hydra": "ss3",
    "responder": "ss3",
    "sqlmap": "fracture",
    "searchsploit": "ss3",
    "amass": "osift",
    "subfinder": "osift",
    "dnsx": "osift",
    "nslookup": "osift",
    "dig": "osift",
    "shodan": "osift",
    "shcheck": "fracture",
    "burp": "fracture",
    "pcap": "trawler",
    "webanalyze": "ss3",
    "dnstwist": "dnstwist",
    "droopescan": "droopescan",
    "dredge": "dredge",
    "impacket": "vault",
    "secretsdump": "vault",
}
