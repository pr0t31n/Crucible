#!/usr/bin/env python3
"""Crucible v2.0 installer — multi-platform."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

TOOL_NAME = "Crucible"
MIN_PYTHON = (3, 10)
APP_DIR = Path(__file__).resolve().parent
SHARED_DIR = Path("/opt/pr0t31n/shared")

SOCKETIO_CDN = (
    "https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.5/socket.io.min.js"
)


def _run(cmd, check=True):
    print(f"  → {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    return subprocess.run(cmd, shell=isinstance(cmd, str), check=check)


def _has(binary):
    return shutil.which(binary) is not None


def create_directories():
    """Create required runtime directories."""
    dirs = [
        APP_DIR / "static" / "js",
        APP_DIR / "static" / "css",
        APP_DIR / "static" / "img",
        APP_DIR / "templates",
        APP_DIR / "routes",
        APP_DIR / "models",
        APP_DIR / "services",
        APP_DIR / "adapters",
        APP_DIR / "sockets",
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
    print("  ✓ Directories created")


def _pip_installed(pkg_spec):
    import importlib.util
    name = pkg_spec.split(">=")[0].split("==")[0].split("[")[0].split("<")[0].strip()
    _IMPORT_MAP = {
        "pyyaml": "yaml", "Pillow": "PIL", "beautifulsoup4": "bs4",
        "flask-socketio": "flask_socketio", "python-nmap": "nmap",
        "python-docx": "docx", "pyOpenSSL": "OpenSSL",
        "charset-normalizer": "charset_normalizer",
        "webdriver-manager": "webdriver_manager",
    }
    mod = _IMPORT_MAP.get(name, name.replace("-", "_"))
    return importlib.util.find_spec(mod) is not None


def install_pip_deps():
    """Install Python packages. Always last, always --break-system-packages."""
    req = APP_DIR / "requirements.txt"
    if not req.exists():
        print("  ⚠ requirements.txt not found, skipping pip install")
        return
    with open(req) as fh:
        lines = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    missing = [l for l in lines if not _pip_installed(l)]
    if not missing:
        print("  ✓ all Python packages already installed")
        return
    failed = []
    for pkg in missing:
        print(f"  Installing {pkg} ...")
        try:
            _run([sys.executable, "-m", "pip", "install",
                  "--break-system-packages", pkg])
        except subprocess.CalledProcessError:
            print(f"  ⚠ {pkg} install failed (non-fatal)")
            failed.append(pkg)
    if failed:
        print(f"  ⚠ {len(failed)} package(s) failed: {', '.join(failed)}")


def vendor_shared_modules():
    """Vendor shared modules from /opt/pr0t31n/shared/ if available."""
    vendored = []

    auth_src = SHARED_DIR / "_auth.py"
    auth_dst = APP_DIR / "_auth.py"
    if auth_src.exists() and not auth_dst.exists():
        shutil.copy2(auth_src, auth_dst)
        vendored.append("_auth.py")

    sysinfo_src = SHARED_DIR / "pr0t31n_system_info.py"
    sysinfo_dst = APP_DIR / "pr0t31n_system_info.py"
    if sysinfo_src.exists() and not sysinfo_dst.exists():
        shutil.copy2(sysinfo_src, sysinfo_dst)
        vendored.append("pr0t31n_system_info.py")

    enrich_src = SHARED_DIR / "pr0t31n_v11_enrichment.js"
    enrich_dst = APP_DIR / "static" / "js" / "pr0t31n_v11_enrichment.js"
    if enrich_src.exists() and not enrich_dst.exists():
        shutil.copy2(enrich_src, enrich_dst)
        vendored.append("pr0t31n_v11_enrichment.js")

    if vendored:
        print(f"  ✓ Vendored: {', '.join(vendored)}")
    else:
        print("  ⚠ No shared modules found (or already vendored)")


def download_socketio_js():
    """Download socket.io.min.js from CDN if not already present."""
    dest = APP_DIR / "static" / "js" / "socket.io.min.js"
    if dest.exists():
        print("  ✓ socket.io.min.js already present")
        return

    print(f"  → Downloading socket.io.min.js ...")
    try:
        import urllib.request
        urllib.request.urlretrieve(SOCKETIO_CDN, str(dest))
        print(f"  ✓ Downloaded socket.io.min.js ({dest.stat().st_size} bytes)")
    except Exception as e:
        print(f"  ⚠ Failed to download socket.io.min.js: {e}")
        print("    Download manually from the CDN and place in static/js/")


def init_auth():
    """Initialize authentication if _auth.py is present."""
    auth_path = APP_DIR / "_auth.py"
    if not auth_path.exists():
        print("  ⚠ _auth.py not found — auth initialization skipped")
        return

    sys.path.insert(0, str(APP_DIR))
    try:
        import _auth
        _auth.init_auth()
        print("  ✓ Auth initialized")
    except Exception as e:
        print(f"  ⚠ Auth initialization failed: {e}")


def install_playwright():
    """Install Playwright Chromium browser for PDF report generation."""
    try:
        import playwright
        print("  ✓ playwright package installed")
    except ImportError:
        print("  ⚠ playwright not installed — report PDF generation unavailable")
        return
    env = os.environ.copy()
    env.pop("NODE_PATH", None)
    result = subprocess.run(
        [sys.executable, "-m", "playwright", "install", "--with-deps", "chromium"],
        capture_output=True, text=True, env=env,
    )
    if result.returncode == 0:
        print("  ✓ Playwright Chromium browser installed")
    else:
        print(f"  ⚠ Playwright browser install failed: {result.stderr[:200]}")
        if "Cannot find module" in (result.stderr or ""):
            print("    Hint: a stale node-playwright package may conflict.")
            print("    Try: sudo apt remove node-playwright && rerun install.py")


def main():
    if sys.version_info < MIN_PYTHON:
        v = ".".join(map(str, MIN_PYTHON))
        print(f"ERROR: Python {v}+ required (found {sys.version})")
        sys.exit(1)

    print(f"\n{'=' * 50}")
    print(f"  {TOOL_NAME} v2.0 — Installation")
    print(f"{'=' * 50}\n")

    print("[1/6] Creating directories...")
    create_directories()

    print("\n[2/6] Installing Python dependencies...")
    install_pip_deps()

    print("\n[3/6] Vendoring shared modules...")
    vendor_shared_modules()

    print("\n[4/6] Downloading static assets...")
    download_socketio_js()

    print("\n[5/6] Installing Playwright browser...")
    install_playwright()

    print("\n[6/6] Initializing authentication...")
    init_auth()

    print(f"\n{'=' * 50}")
    print(f"  {TOOL_NAME} v2.0 installed successfully.")
    print(f"  Start with: python3 {APP_DIR / 'app.py'}")
    print(f"{'=' * 50}\n")


if __name__ == "__main__":
    main()
