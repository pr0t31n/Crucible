#!/usr/bin/env python3
"""
Crucible — Flask web platform wrapping Fracture and Siphon
Install script
Location: /Users/pr0t31n/Crucible/
Service:  pr0t31n-crucible (port 5500)

NOTE: Crucible launches fracture.py and siphon.py as subprocesses.
This installer ONLY installs what Crucible's app.py directly uses.
Fracture and Siphon must be installed separately for full functionality.
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
import urllib.request

# ---------------------------------------------------------------------------
# ANSI colours
# ---------------------------------------------------------------------------
R  = "\033[1;31m"
G  = "\033[1;32m"
Y  = "\033[1;33m"
B  = "\033[1;34m"
C  = "\033[1;36m"
W  = "\033[0m"

def banner(msg):  print(f"\n{B}{'='*60}{W}\n{C}  {msg}{W}\n{B}{'='*60}{W}")
def info(msg):    print(f"{G}[+]{W} {msg}")
def warn(msg):    print(f"{Y}[!]{W} {msg}")
def error(msg):   print(f"{R}[x]{W} {msg}")
def step(msg):    print(f"{B}[>]{W} {msg}")

# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------
def detect_os():
    system = platform.system()
    if system == "Darwin":
        return "macos"
    if system == "Windows":
        return "windows"
    try:
        with open("/etc/os-release") as f:
            data = f.read().lower()
    except FileNotFoundError:
        return "linux-unknown"
    if "kali" in data or "debian" in data or "ubuntu" in data:
        return "apt"
    if "rhel" in data or "centos" in data or "rocky" in data or "fedora" in data:
        return "dnf"
    if "suse" in data or "opensuse" in data:
        return "zypper"
    return "linux-unknown"

OS = detect_os()

# ---------------------------------------------------------------------------
# Privilege helpers
# ---------------------------------------------------------------------------
def is_root():
    return os.getuid() == 0 if hasattr(os, "getuid") else False

def get_sudo_user():
    return os.environ.get("SUDO_USER", "")

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def run(cmd, check=True, capture=False):
    step(" ".join(cmd) if isinstance(cmd, list) else cmd)
    kwargs = dict(check=check)
    if capture:
        kwargs["capture_output"] = True
        kwargs["text"] = True
    return subprocess.run(cmd, **kwargs)

# ---------------------------------------------------------------------------
# brew helper — NEVER run as root
# ---------------------------------------------------------------------------
def brew_install(pkg):
    brew_path = shutil.which("brew")
    if not brew_path:
        for p in ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]:
            if os.path.isfile(p):
                brew_path = p
                break
    if not brew_path:
        warn(f"brew not found — skipping {pkg}")
        return

    cmd = [brew_path, "install", pkg]
    if is_root():
        sudo_user = get_sudo_user()
        if not sudo_user:
            warn(f"Running as root with no SUDO_USER — cannot run brew safely. Skipping {pkg}.")
            return
        cmd = ["sudo", "-u", sudo_user] + cmd
    run(cmd, check=False)

# ---------------------------------------------------------------------------
# Package managers
# ---------------------------------------------------------------------------
_apt_updated = False

def apt_install(packages):
    global _apt_updated
    if not _apt_updated:
        info("Running apt update + apt upgrade ...")
        run(["apt-get", "update", "-y"])
        run(["apt-get", "upgrade", "-y"])
        _apt_updated = True
    run(["apt-get", "install", "-y"] + packages)

def dnf_install(packages):
    run(["dnf", "install", "-y"] + packages)

def zypper_install(packages):
    run(["zypper", "install", "-y"] + packages)

# ---------------------------------------------------------------------------
# System packages
# ---------------------------------------------------------------------------
APT_PACKAGES = [
    "python3-pip", "python3-dev",
    "git",
    "openssl", "libssl-dev",
]
DNF_PACKAGES = [
    "python3-pip", "python3-devel",
    "git",
    "openssl", "openssl-devel",
]
ZYPPER_PACKAGES = [
    "python3-pip", "python3-devel",
    "git",
    "openssl", "libopenssl-devel",
]
BREW_PACKAGES = [
    "openssl", "git",
]

def install_system():
    banner("Phase: system packages")
    if OS == "apt":
        apt_install(APT_PACKAGES)
    elif OS == "dnf":
        dnf_install(DNF_PACKAGES)
    elif OS == "zypper":
        zypper_install(ZYPPER_PACKAGES)
    elif OS == "macos":
        for pkg in BREW_PACKAGES:
            brew_install(pkg)
    elif OS == "windows":
        warn("Windows: system package installation not supported. Install tools manually.")
    else:
        warn(f"Unknown OS '{OS}' — skipping system packages.")

# ---------------------------------------------------------------------------
# pip packages
# ---------------------------------------------------------------------------
PIP_PACKAGES = [
    "flask>=3.0.0",
    "flask-socketio>=5.3.0",
    "eventlet>=0.35.0",
    "psutil>=5.9.0",
    "werkzeug",
    "openpyxl>=3.1.0",
    "reportlab>=4.0.0",
]

OFFLINE_BUNDLE_URLS = {
    "flask":          "https://raw.githubusercontent.com/pr0t31n/OfflineInstallers/main/flask_offline_kali.tar.gz",
    "flask-socketio": "https://raw.githubusercontent.com/pr0t31n/OfflineInstallers/main/flask_socketio_offline_kali.tar.gz",
    "eventlet":       "https://raw.githubusercontent.com/pr0t31n/OfflineInstallers/main/eventlet_offline_kali.tar.gz",
    "werkzeug":       "https://raw.githubusercontent.com/pr0t31n/OfflineInstallers/main/werkzeug_offline_kali.tar.gz",
    "openpyxl":       "https://raw.githubusercontent.com/pr0t31n/OfflineInstallers/main/openpyxl_offline_kali.tar.gz",
    "reportlab":      "https://raw.githubusercontent.com/pr0t31n/OfflineInstallers/main/reportlab_offline_kali.tar.gz",
}

_OFFLINE_REPO_DIR = "/opt/OfflineInstallers"
_OFFLINE_REPO_URL = "https://github.com/pr0t31n/OfflineInstallers"


def _install_from_local_repo(pkg_name: str, tarball: str) -> bool:
    """Copy/reassemble a bundle from the already-cloned OfflineInstallers repo.
    Returns True if tarball was written successfully."""
    _local_tar = os.path.join(_OFFLINE_REPO_DIR, f"{pkg_name}_offline_kali.tar.gz")
    if os.path.isfile(_local_tar):
        shutil.copy2(_local_tar, tarball)
        return True
    _repo_parts = sorted([
        os.path.join(_OFFLINE_REPO_DIR, f)
        for f in os.listdir(_OFFLINE_REPO_DIR)
        if f.startswith(f"{pkg_name}_offline_kali.part.")
    ])
    if _repo_parts:
        info(f"  Reassembling {len(_repo_parts)} part(s) from cloned repo ...")
        with open(tarball, "wb") as _out:
            for _p in _repo_parts:
                with open(_p, "rb") as _f:
                    _out.write(_f.read())
        return True
    warn(f"{pkg_name} not found in cloned OfflineInstallers repo")
    return False


def _install_from_bundle(pkg_name: str, url: str) -> bool:
    """Download a pre-built offline bundle from GitHub and run install_offline.sh.
    Handles both single .tar.gz files and split .part.* files.
    If the OfflineInstallers repo is already cloned at /opt/OfflineInstallers,
    installs directly from there without any network downloads."""
    import tempfile
    _tmp = tempfile.mkdtemp(prefix=f"crucible_bundle_{pkg_name}_")
    _tarball = os.path.join(_tmp, f"{pkg_name}_offline_kali.tar.gz")
    _downloaded = False

    try:
        # Fast path: OfflineInstallers repo already cloned — skip all network attempts
        if os.path.isdir(os.path.join(_OFFLINE_REPO_DIR, ".git")):
            info(f"OfflineInstallers repo already cloned — installing {pkg_name} directly ...")
            _downloaded = _install_from_local_repo(pkg_name, _tarball)
        else:
            info(f"Downloading offline bundle for {pkg_name} ...")
            try:
                urllib.request.urlretrieve(url, _tarball)
                _downloaded = True
            except Exception:
                # Single file unavailable — try split parts (.part.aa, .part.ab, ...)
                _base = url.rsplit("/", 1)[0]
                _parts = []
                _found_gap = False
                for _a in "abcdefghijklmnopqrstuvwxyz":
                    if _found_gap:
                        break
                    for _b in "abcdefghijklmnopqrstuvwxyz":
                        _sfx = _a + _b
                        _pu = f"{_base}/{pkg_name}_offline_kali.part.{_sfx}"
                        _pp = os.path.join(_tmp, f"part.{_sfx}")
                        try:
                            urllib.request.urlretrieve(_pu, _pp)
                            _parts.append(_pp)
                        except Exception:
                            _found_gap = True
                            break
                if _parts:
                    info(f"  Reassembling {len(_parts)} part(s) ...")
                    with open(_tarball, "wb") as _out:
                        for _p in sorted(_parts):
                            with open(_p, "rb") as _f:
                                _out.write(_f.read())
                    _downloaded = True

            if not _downloaded:
                # Final fallback: clone OfflineInstallers repo to /opt/ and install from there
                _git = shutil.which("git")
                if _git:
                    info("githubusercontent.com inaccessible — cloning OfflineInstallers to /opt/ ...")
                    if os.path.isdir(os.path.join(_OFFLINE_REPO_DIR, ".git")):
                        subprocess.run([_git, "-C", _OFFLINE_REPO_DIR, "pull", "--ff-only"],
                                       check=False)
                    else:
                        subprocess.run([_git, "clone", "--depth=1", _OFFLINE_REPO_URL,
                                        _OFFLINE_REPO_DIR], check=False)
                    if os.path.isdir(_OFFLINE_REPO_DIR):
                        _downloaded = _install_from_local_repo(pkg_name, _tarball)

        if not _downloaded:
            warn(f"Could not download offline bundle for {pkg_name}")
            return False

        if subprocess.run(["tar", "xzf", _tarball, "-C", _tmp],
                          check=False).returncode != 0:
            warn(f"Failed to extract offline bundle for {pkg_name}")
            return False

        _install_sh = None
        for _root, _dirs, _files in os.walk(_tmp):
            if "install_offline.sh" in _files:
                _install_sh = os.path.join(_root, "install_offline.sh")
                break

        if not _install_sh:
            warn(f"install_offline.sh not found in {pkg_name} bundle")
            return False

        os.chmod(_install_sh, 0o755)
        _ok = subprocess.run(["bash", _install_sh], check=False).returncode == 0
        if _ok:
            info(f"{pkg_name} installed from offline bundle")
        else:
            warn(f"Offline bundle install failed for {pkg_name}")
        return _ok

    finally:
        shutil.rmtree(_tmp, ignore_errors=True)


def install_pip():
    banner("Phase: pip packages")
    info("Installing Crucible Python dependencies ...")
    for _pkg in PIP_PACKAGES:
        _r = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--break-system-packages", _pkg],
            check=False,
        )
        if _r.returncode != 0:
            _name = _pkg.split(">=")[0].split("==")[0].split("[")[0].strip()
            if _name in OFFLINE_BUNDLE_URLS:
                warn(f"pip install failed for {_name} — trying offline bundle ...")
                _install_from_bundle(_name, OFFLINE_BUNDLE_URLS[_name])
            else:
                warn(f"pip install failed for {_name}")

# ---------------------------------------------------------------------------
# Service files
# ---------------------------------------------------------------------------
APP_DIR  = "/opt/pr0t31n/Crucible"
APP_FILE = f"{APP_DIR}/app.py"
SVC_NAME = "pr0t31n-crucible"
PORT     = 5500

SYSTEMD_UNIT = f"""\
[Unit]
Description=Crucible — Web & API Assessment Platform (Fracture + Siphon)
After=network.target

[Service]
Type=simple
WorkingDirectory={APP_DIR}
ExecStart={sys.executable} {APP_FILE}
Restart=on-failure
RestartSec=5
Environment=FLASK_ENV=production
Environment=PORT={PORT}

[Install]
WantedBy=multi-user.target
"""

LAUNCHD_PLIST = f"""\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.pr0t31n.crucible</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
        <string>{APP_FILE}</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{APP_DIR}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PORT</key>
        <string>{PORT}</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/pr0t31n-crucible.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/pr0t31n-crucible.err</string>
</dict>
</plist>
"""

def install_service():
    banner("Service file installation")
    if OS in ("apt", "dnf", "zypper", "linux-unknown"):
        path = f"/etc/systemd/system/{SVC_NAME}.service"
        try:
            with open(path, "w") as f:
                f.write(SYSTEMD_UNIT)
            info(f"Wrote {path}")
            run(["systemctl", "daemon-reload"])
            run(["systemctl", "enable", SVC_NAME])
            info(f"Service {SVC_NAME} enabled.")
            run(["systemctl", "start", SVC_NAME])
            info(f"Service {SVC_NAME} started.")
        except PermissionError:
            warn("Not root — cannot write systemd unit. Run as root to install service.")
        except subprocess.CalledProcessError as e:
            warn(f"systemctl command failed (exit {e.returncode}): {' '.join(e.cmd)}")
            if e.stderr:
                for ln in e.stderr.strip().splitlines()[-6:]:
                    print(f"    {Y}{ln}{W}", flush=True)
    elif OS == "macos":
        path = "/Library/LaunchDaemons/com.pr0t31n.crucible.plist"
        try:
            with open(path, "w") as f:
                f.write(LAUNCHD_PLIST)
            info(f"Wrote {path}")
            run(["launchctl", "load", path], check=False)
            info("LaunchDaemon loaded.")
            info("Start with: launchctl start com.pr0t31n.crucible")
        except PermissionError:
            warn("Not root — cannot write LaunchDaemon plist. Run as root to install service.")
    else:
        warn("Service installation not supported on this OS.")

# ---------------------------------------------------------------------------
# Subprocess dependency warning
# ---------------------------------------------------------------------------
def print_dependency_warning():
    print(f"""
{R}{'='*60}{W}
{R}  IMPORTANT: Crucible depends on external tools!{W}
{R}{'='*60}{W}
{Y}  Crucible launches fracture.py and siphon.py as subprocesses.
  These tools and all their dependencies must be installed
  separately using their own install scripts:

    python3 /opt/pr0t31n/Fracture/install.py
    python3 /opt/pr0t31n/Siphon/install.py

  Without these, Crucible will start but scan functionality
  will not be available.
{W}""")

# ---------------------------------------------------------------------------
# Check / verify
# ---------------------------------------------------------------------------
VERIFY_PYTHON = ["flask", "flask_socketio", "eventlet", "psutil"]

def run_check():
    banner("Post-install verification")
    print(f"\n{C}Python imports:{W}")
    for pkg in VERIFY_PYTHON:
        try:
            __import__(pkg)
            info(f"{pkg:30s} {G}OK{W}")
        except Exception as e:
            warn(f"{pkg:30s} {Y}MISSING{W} ({type(e).__name__}: {e})")

    print(f"\n{C}Application:{W}")
    if os.path.isfile(APP_FILE):
        info(f"app.py found at {APP_FILE}")
    else:
        warn(f"app.py NOT found at {APP_FILE} — ensure Crucible is deployed.")

    print(f"\n{C}Subprocess dependencies:{W}")

    fracture_candidates = [
        "/opt/pr0t31n/Fracture/fracture.py",
    ]
    fracture_found = any(os.path.isfile(p) for p in fracture_candidates)
    if fracture_found:
        info(f"{'fracture.py':30s} {G}FOUND{W}")
    else:
        warn(f"{'fracture.py':30s} {Y}NOT FOUND — install separately{W}")

    siphon_candidates = [
        "/opt/pr0t31n/Siphon/siphon.py",
    ]
    siphon_found = any(os.path.isfile(p) for p in siphon_candidates)
    if siphon_found:
        info(f"{'siphon.py':30s} {G}FOUND{W}")
    else:
        warn(f"{'siphon.py':30s} {Y}NOT FOUND — install separately{W}")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
def print_summary(skips):
    banner("Post-install summary")
    info(f"Application : Crucible — Web & API Assessment Platform")
    info(f"Location    : {APP_DIR}")
    info(f"Service     : {SVC_NAME}  (port {PORT})")
    info(f"OS detected : {OS}")
    print()
    phases = ["system", "pip", "service"]
    for p in phases:
        status = f"{Y}SKIPPED{W}" if p in skips else f"{G}DONE{W}"
        print(f"  {p:10s} {status}")
    print()
    if OS in ("apt", "dnf", "zypper", "linux-unknown"):
        info(f"Manage service : systemctl {{start|stop|status}} {SVC_NAME}")
    elif OS == "macos":
        info("Manage service : launchctl {start|stop} com.pr0t31n.crucible")
    print_dependency_warning()

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Crucible installer")
    parser.add_argument("--skip-apt",     "--skip-system", dest="skip_system", action="store_true")
    parser.add_argument("--skip-pip",     action="store_true")
    parser.add_argument("--skip-go",      action="store_true", help="No-op (reserved for Arsenal compatibility)")
    parser.add_argument("--skip-git",     action="store_true", help="No-op (reserved for Arsenal compatibility)")
    parser.add_argument("--skip-service", action="store_true")
    parser.add_argument("--check",        action="store_true", help="Verify installation only")
    args = parser.parse_args()

    banner("Crucible — Web & API Assessment Platform — Installer")
    info(f"Detected OS : {OS}")
    info(f"Python      : {sys.executable}")
    print_dependency_warning()

    if args.check:
        run_check()
        return

    skips = set()

    if not args.skip_system:
        install_system()
    else:
        skips.add("system"); warn("Skipping system packages.")

    if not args.skip_pip:
        install_pip()
    else:
        skips.add("pip"); warn("Skipping pip packages.")

    if not args.skip_service:
        install_service()
    else:
        skips.add("service"); warn("Skipping service installation.")

    run_check()
    print_summary(skips)


if __name__ == "__main__":
    main()
