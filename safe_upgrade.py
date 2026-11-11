#!/usr/bin/env python3
"""
safe_upgrade.py — Tiered system upgrade with dependency recovery
                   and connectivity protection.

Performs safe, incremental package upgrades on Ubuntu/Kali/Debian
without dist-upgrade or full-upgrade.  Designed for remote systems
where losing connectivity is catastrophic.

Usage:
    sudo python3 safe_upgrade.py [options]
"""
from __future__ import annotations

import argparse
import fcntl
import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.10.0"

# ── ANSI ─────────────────────────────────────────────────────────────────────
_R = _G = _RD = _Y = _C = _DIM = _BLD = ""

def _init_color(enabled: bool) -> None:
    global _R, _G, _RD, _Y, _C, _DIM, _BLD
    if enabled:
        _R, _G, _RD, _Y, _C, _DIM, _BLD = (
            "\033[0m", "\033[32m", "\033[31m", "\033[33m",
            "\033[36m", "\033[2m", "\033[1m",
        )

# ── Logging ──────────────────────────────────────────────────────────────────
def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")

def _log(level: str, msg: str, indent: int = 0) -> None:
    pfx = "  " * indent
    ts = f"{_DIM}{_ts()}{_R} "
    if level == "+":
        print(f"{pfx}  {ts}{_G}[+]{_R} {msg}", flush=True)
    elif level == "-":
        print(f"{pfx}  {ts}{_RD}[-]{_R} {msg}", flush=True)
    elif level == "~":
        print(f"{pfx}  {ts}{_Y}[~]{_R} {msg}", flush=True)
    elif level == "*":
        print(f"{pfx}  {ts}{_C}[*]{_R} {msg}", flush=True)
    else:
        print(f"{pfx}  {ts}{msg}", flush=True)

def _phase_hdr(num: int | str, title: str) -> None:
    label = f"Phase {num}: {title}"
    bar = "─" * max(1, 50 - len(label))
    ts = _ts()
    print(f"\n{_DIM}{ts}{_R} {_BLD}── {label} {bar}{_R}", flush=True)

# ── Subprocess helpers ───────────────────────────────────────────────────────
_APT_ENV: dict = {}
_APT_OPTS: list[str] = [
    "-o", "Dpkg::Options::=--force-confdef",
    "-o", "Dpkg::Options::=--force-confold",
]

def _init_env() -> None:
    global _APT_ENV
    _APT_ENV = {
        **os.environ,
        "DEBIAN_FRONTEND": "noninteractive",
        "NEEDRESTART_MODE": "a",
        "UCF_FORCE_CONFFOLD": "1",
    }

def _run(cmd: list[str], timeout: int = 300, env: dict | None = None) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, env=env or None)
        return r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", f"Command timed out after {timeout}s"
    except Exception as e:
        return 1, "", str(e)

def _apt(args: list[str], timeout: int = 600) -> tuple[int, str, str]:
    cmd = ["apt-get"] + _APT_OPTS + args
    return _run(cmd, timeout=timeout, env=_APT_ENV)

def _dpkg(args: list[str], timeout: int = 300) -> tuple[int, str, str]:
    return _run(["dpkg"] + args, timeout=timeout, env=_APT_ENV)

# ── dpkg lock check ─────────────────────────────────────────────────────────
def _check_dpkg_lock() -> bool:
    """Return True if dpkg/apt locks are available (no other apt running)."""
    for lockfile in ("/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock",
                     "/var/lib/apt/lists/lock"):
        try:
            fd = os.open(lockfile, os.O_RDWR)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(fd, fcntl.LOCK_UN)
            except (BlockingIOError, OSError):
                os.close(fd)
                return False
            os.close(fd)
        except (PermissionError, FileNotFoundError, OSError):
            pass
    return True

# ── Connectivity detection ───────────────────────────────────────────────────
def _svc_active(name: str) -> bool:
    rc, out, _ = _run(["systemctl", "is-active", name], timeout=10)
    return out.strip() == "active"

def _proc_running(name: str) -> bool:
    rc, _, _ = _run(["pgrep", "-x", name], timeout=5)
    return rc == 0

def _port_listening(port: int) -> bool:
    rc, out, _ = _run(["ss", "-tlnp", f"sport = :{port}"], timeout=5)
    return f":{port}" in out

def _has_wg_interface() -> bool:
    rc, out, _ = _run(["ip", "link", "show", "type", "wireguard"], timeout=5)
    return rc == 0 and bool(out.strip())

_CONN_METHODS = [
    {
        "name": "SSH",
        "detect": lambda: (_svc_active("sshd") or _svc_active("ssh")) and _port_listening(22),
        "verify": lambda: _port_listening(22),
        "restart": ["sshd", "ssh"],
        "packages": {"openssh-server", "openssh-client", "openssh-sftp-server"},
    },
    {
        "name": "OpenVPN",
        "detect": lambda: _svc_active("openvpn") or _proc_running("openvpn"),
        "verify": lambda: _proc_running("openvpn"),
        "restart": ["openvpn"],
        "packages": {"openvpn"},
    },
    {
        "name": "WireGuard",
        "detect": _has_wg_interface,
        "verify": _has_wg_interface,
        "restart": [],
        "packages": {"wireguard", "wireguard-tools"},
    },
    {
        "name": "ZeroTier",
        "detect": lambda: _svc_active("zerotier-one"),
        "verify": lambda: _svc_active("zerotier-one"),
        "restart": ["zerotier-one"],
        "packages": {"zerotier-one"},
    },
]

# Packages that are always critical when ANY encrypted connectivity is active
_TLS_CRITICAL_EXACT = {"openssl"}
_TLS_CRITICAL_PREFIXES = ("libssl",)
# Networking packages always critical when ANY method is active
_NET_CRITICAL = {"iptables", "nftables", "ufw", "iproute2", "ifupdown",
                 "netplan.io", "network-manager", "systemd-resolved", "resolvconf"}

# ── Sensitive tier patterns ──────────────────────────────────────────────────
_SENSITIVE_EXACT = {"dpkg", "apt", "apt-utils", "libc6", "libc-bin",
                    "python3-minimal"}
_SENSITIVE_PREFIXES = ("libapt", "systemd", "libsystemd", "libgcc",
                       "linux-image", "linux-headers", "grub",
                       "python3.", "libpython3", "libpam")

# ── Classification ───────────────────────────────────────────────────────────
def _classify(pkg_name: str, active_critical: set[str]) -> str:
    if pkg_name in active_critical:
        return "critical"
    for pfx in _TLS_CRITICAL_PREFIXES:
        if pkg_name.startswith(pfx) and active_critical:
            return "critical"
    if pkg_name in _SENSITIVE_EXACT:
        return "sensitive"
    for pfx in _SENSITIVE_PREFIXES:
        if pkg_name.startswith(pfx):
            return "sensitive"
    return "normal"

# ── Repair helpers ───────────────────────────────────────────────────────────
# Package states that indicate trouble (dpkg -l first-two-char status field)
_BAD_STATES = {"iU", "iF", "iH", "iR", "uU", "uF", "uH", "uR",
               "rU", "rF", "rH", "rR", "hF", "hU", "hR",
               "pU", "pF", "pH", "pR"}
# 'rc' (removed, config-files) is normal — not broken

# All the ways dpkg/apt tell you about missing deps
_DEP_PATTERNS = [
    re.compile(r"depends on (\S+)"),
    re.compile(r"dependency problems.+?Package (\S+)"),
    re.compile(r"(\S+) is not configured"),
    re.compile(r"(\S+) is not installed"),
    re.compile(r"Depends:\s+(\S+)\s+but"),
    re.compile(r"Pre-Depends:\s+(\S+)\s+but"),
    re.compile(r"Package (\S+) is not configured yet"),
    re.compile(r"Errors were encountered while processing:\s*\n((?:\s+\S+\s*\n?)+)"),
]

def _extract_deps_from_error(err: str) -> set[str]:
    deps: set[str] = set()
    for pat in _DEP_PATTERNS:
        for m in pat.finditer(err):
            text = m.group(1).strip()
            for token in text.split():
                name = token.split(":")[0].strip()
                if name and not name.startswith("(") and not name.startswith("-"):
                    deps.add(name)
    return deps

def _get_broken_packages() -> dict[str, str]:
    """Return {pkg_name: status} for all packages in a bad dpkg state."""
    broken = {}
    rc, out, _ = _run(["dpkg", "-l"], timeout=30, env=_APT_ENV)
    for line in out.splitlines():
        if len(line) < 4 or line[0] == '+' or line[0] == '|':
            continue
        status = line[:2]
        if status in _BAD_STATES:
            parts = line.split()
            if len(parts) >= 2:
                name = parts[1].split(":")[0]
                broken[name] = status
    rc2, audit_out, _ = _dpkg(["--audit"], timeout=60)
    for line in audit_out.splitlines():
        parts = line.split()
        if parts:
            name = parts[0].split(":")[0]
            if name and name not in broken:
                broken[name] = "audit"
    return broken

def _get_pkg_deps(pkg: str) -> set[str]:
    """Get direct dependencies of a package from apt-cache."""
    rc, out, _ = _run(["apt-cache", "depends", "--installed", pkg], timeout=10)
    deps: set[str] = set()
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Depends:") or line.startswith("Pre-Depends:"):
            dep = line.split(":", 1)[1].strip().split(":")[0]
            if dep and not dep.startswith("<"):
                deps.add(dep)
    return deps

def _topo_sort_broken(broken_set: set[str]) -> list[str]:
    """Topological sort of broken packages by their deps — leaves first."""
    dep_map: dict[str, set[str]] = {}
    for pkg in broken_set:
        deps = _get_pkg_deps(pkg)
        dep_map[pkg] = deps & broken_set
    ordered: list[str] = []
    visited: set[str] = set()
    in_stack: set[str] = set()
    cycle_breakers: list[str] = []

    def _visit(p: str) -> None:
        if p in visited:
            return
        if p in in_stack:
            cycle_breakers.append(p)
            return
        in_stack.add(p)
        for d in dep_map.get(p, set()):
            _visit(d)
        in_stack.discard(p)
        visited.add(p)
        ordered.append(p)

    for pkg in sorted(broken_set):
        _visit(pkg)
    if cycle_breakers:
        for cb in cycle_breakers:
            if cb not in ordered:
                ordered.insert(0, cb)
    return ordered

def _configure_with_progress(broken: dict[str, str], max_passes: int = 8) -> dict[str, str]:
    """Multi-pass dpkg --configure with progress tracking.
    Returns dict of packages that remain broken after all passes."""
    remaining = dict(broken)
    for pass_num in range(1, max_passes + 1):
        if not remaining:
            break
        before = len(remaining)
        ordered = _topo_sort_broken(set(remaining.keys()))
        for pkg in ordered:
            if pkg not in remaining:
                continue
            rc, _, err = _dpkg(["--configure", pkg], timeout=120)
            if rc == 0:
                del remaining[pkg]
                continue
            dep_names = _extract_deps_from_error(err)
            for dep in dep_names:
                if dep in remaining and dep != pkg:
                    _dpkg(["--configure", dep], timeout=60)
            rc2, _, _ = _dpkg(["--configure", pkg], timeout=120)
            if rc2 == 0:
                del remaining[pkg]
        after = len(remaining)
        _log("*", f"Pass {pass_num}: {before - after} configured, {after} remaining")
        if after == before:
            break
    return remaining

def _force_configure_pkg(pkg: str) -> bool:
    """Force-configure a package to break dependency cycles."""
    rc, _, _ = _dpkg(["--force-depends", "--configure", pkg], timeout=120)
    return rc == 0

def _purge_reinstall(pkg: str, protected: set[str] | None = None) -> bool:
    """Last resort: purge a broken package and reinstall it.
    REFUSES to purge connectivity-protected packages."""
    if protected and _is_protected(pkg, protected):
        _log("-", f"  REFUSED purge of protected package {pkg}")
        return False
    _dpkg(["--purge", "--force-remove-reinstreq", "--force-depends", pkg], timeout=60)
    rc, _, _ = _apt(["install", "-y", pkg], timeout=300)
    return rc == 0

def _download_install(pkg: str) -> bool:
    """Download .deb via apt and install via dpkg directly."""
    dl_dir = "/tmp/_safe_upgrade_debs"
    os.makedirs(dl_dir, exist_ok=True)
    try:
        r = subprocess.run(
            ["apt-get", "download", pkg],
            capture_output=True, text=True, timeout=120,
            env=_APT_ENV, cwd=dl_dir,
        )
        if r.returncode != 0:
            if r.stderr:
                _log("~", f"    download failed: {r.stderr.strip().splitlines()[-1][:100]}")
            return False
    except subprocess.TimeoutExpired:
        _log("~", "    download timed out (120s)")
        return False
    except Exception as e:
        _log("~", f"    download error: {e}")
        return False
    import glob
    debs = sorted(glob.glob(f"{dl_dir}/{pkg}_*.deb"),
                  key=os.path.getmtime, reverse=True)
    if not debs:
        _log("~", f"    no .deb found after download")
        return False
    rc, _, err = _dpkg(["-i", "--force-depends", debs[0]], timeout=120)
    try:
        os.unlink(debs[0])
    except OSError:
        pass
    if rc != 0 and err:
        _log("~", f"    dpkg -i failed: {err.strip().splitlines()[-1][:100]}")
    return rc == 0

def _is_protected(pkg: str, protected: set[str]) -> bool:
    """Check if a package is connectivity-protected (exact match or TLS prefix)."""
    if pkg in protected:
        return True
    for pfx in _TLS_CRITICAL_PREFIXES:
        if pkg.startswith(pfx) and protected:
            return True
    return False

def _deep_repair(broken: dict[str, str], protected: set[str] | None = None,
                 active_methods: list[dict] | None = None) -> dict[str, str]:
    """Escalating repair for packages that survived multi-pass configure.
    Protected packages (connectivity-critical) get limited escalation:
    force-configure only, with connectivity checks before/after.
    Unprotected packages get full escalation: force-configure → download+dpkg-i → purge+reinstall."""
    remaining = dict(broken)
    if not remaining:
        return remaining
    if protected is None:
        protected = set()

    n_prot = sum(1 for p in remaining if _is_protected(p, protected))
    n_unprot = len(remaining) - n_prot
    _log("*", f"Deep repair: {len(remaining)} stubborn packages "
         f"({n_prot} protected, {n_unprot} unprotected)")

    # Stage 1: force-configure — safe for all packages
    ordered = _topo_sort_broken(set(remaining.keys()))
    for pkg in ordered:
        if pkg not in remaining:
            continue
        is_prot = _is_protected(pkg, protected)
        label = f"{_Y}[P]{_R} " if is_prot else ""
        # For protected packages, verify connectivity before touching them
        if is_prot and active_methods:
            pre = _verify_all_conn(active_methods)
            if not all(c["ok"] for c in pre):
                _log("~", f"  {label}SKIP force-configure {pkg} — connectivity already degraded")
                continue
        _log("*", f"  {label}Force-configure {pkg}…")
        if _force_configure_pkg(pkg):
            _log("+", f"  {label}{pkg} force-configured")
            del remaining[pkg]
            # Check connectivity didn't break
            if is_prot and active_methods:
                post = _verify_all_conn(active_methods)
                if not all(c["ok"] for c in post):
                    _log("-", f"  {_RD}CONNECTIVITY DEGRADED{_R} after force-configuring {pkg}")
                    for m in active_methods:
                        if not m["verify"]():
                            _log("*", f"  Restarting {m['name']}…")
                            _restart_services(m)
            continue

    if remaining:
        _dpkg(["--configure", "-a"], timeout=300)
        still_broken = _get_broken_packages()
        for pkg in list(remaining.keys()):
            if pkg not in still_broken:
                del remaining[pkg]

    # Stage 2: download+dpkg-i and purge+reinstall — ONLY for unprotected packages
    for pkg in list(remaining.keys()):
        if _is_protected(pkg, protected):
            _log("~", f"  {_Y}[P]{_R} {pkg} — protected, skipping destructive repair")
            continue
        _log("*", f"  Download + dpkg -i {pkg}…")
        if _download_install(pkg):
            _log("+", f"  {pkg} reinstalled via dpkg -i")
            del remaining[pkg]
            continue
        _log("*", f"  Purge + reinstall {pkg}…")
        if _purge_reinstall(pkg, protected=protected):
            _log("+", f"  {pkg} purge-reinstalled")
            del remaining[pkg]
        else:
            _log("-", f"  {pkg} UNRECOVERABLE")

    # Stage 3: protected packages that are still broken — try download+dpkg-i
    # with connectivity checks (no purge — too dangerous)
    for pkg in list(remaining.keys()):
        if not _is_protected(pkg, protected):
            continue
        if active_methods:
            pre = _verify_all_conn(active_methods)
            if not all(c["ok"] for c in pre):
                _log("~", f"  {_Y}[P]{_R} SKIP {pkg} — connectivity degraded")
                continue
        _log("*", f"  {_Y}[P]{_R} Download + dpkg -i {pkg} (no purge)…")
        if _download_install(pkg):
            _log("+", f"  {_Y}[P]{_R} {pkg} reinstalled via dpkg -i")
            del remaining[pkg]
            if active_methods:
                post = _verify_all_conn(active_methods)
                if not all(c["ok"] for c in post):
                    _log("-", f"  {_RD}CONNECTIVITY DEGRADED{_R} after reinstalling {pkg}")
                    for m in active_methods:
                        if not m["verify"]():
                            _log("*", f"  Restarting {m['name']}…")
                            _restart_services(m)
        else:
            _log("-", f"  {_Y}[P]{_R} {pkg} — cannot repair without purge, SKIPPING")

    if remaining:
        _dpkg(["--configure", "-a"], timeout=300)
        _apt(["install", "-f", "-y"], timeout=300)
        still_broken = _get_broken_packages()
        for pkg in list(remaining.keys()):
            if pkg not in still_broken:
                del remaining[pkg]

    return remaining

def _repair_quick() -> None:
    """Quick repair pass — multi-pass configure + apt fix."""
    broken = _get_broken_packages()
    if broken:
        _configure_with_progress(broken, max_passes=3)
    else:
        _dpkg(["--configure", "-a"], timeout=120)
    _apt(["install", "-f", "-y"], timeout=300)

def _resolve_deps(pkg: str, protected: set[str] | None = None) -> bool:
    """Resolve dependencies for a single package using the full repair stack.
    Protected packages skip purge-based recovery."""
    if protected is None:
        protected = set()
    rc, _, err = _dpkg(["--configure", pkg], timeout=120)
    if rc == 0:
        return True
    deps = _extract_deps_from_error(err)
    if deps:
        ordered = _topo_sort_broken(deps)
        for dep in ordered:
            _dpkg(["--configure", dep], timeout=60)
        rc2, _, err2 = _dpkg(["--configure", pkg], timeout=120)
        if rc2 == 0:
            return True
        new_deps = _extract_deps_from_error(err2) - deps
        for dep in new_deps:
            _dpkg(["--configure", dep], timeout=60)
        rc3, _, _ = _dpkg(["--configure", pkg], timeout=120)
        if rc3 == 0:
            return True
    if _force_configure_pkg(pkg):
        return True
    if _download_install(pkg):
        return True
    return False

# ── Upgrade engine ───────────────────────────────────────────────────────────
_stopping = False
_PROTECTED_PKGS: set[str] = set()  # populated by phase_preflight
_ACTIVE_METHODS: list[dict] = []   # populated by phase_preflight

def _apt_install(pkgs: list[str]) -> tuple[int, str, str]:
    return _apt(["install", "-y"] + pkgs, timeout=600)

_SYSTEMIC_PATTERNS = [
    (re.compile(r"Unable to acquire the dpkg frontend lock|Could not get lock", re.I),
     "dpkg lock held by another process"),
    (re.compile(r"No space left on device", re.I),
     "disk full"),
    (re.compile(r"Hash Sum mismatch", re.I),
     "repository hash mismatch (corrupt cache or mirror issue)"),
    (re.compile(r"Unmet dependencies|dependency problems", re.I),
     "unmet dependencies"),
    (re.compile(r"Temporary failure resolving|Could not resolve", re.I),
     "DNS resolution failure"),
    (re.compile(r"Failed to fetch|Connection failed|Unable to connect", re.I),
     "network connectivity issue"),
    (re.compile(r"packages have been kept back", re.I),
     "held-back packages (need dist-upgrade or manual resolution)"),
    (re.compile(r"pkgProblemResolver.*generated breaks|caused by held packages|Breaks existing package", re.I),
     "dependency resolution failure — held/broken packages block upgrade"),
    (re.compile(r"dpkg was interrupted|dpkg --configure -a", re.I),
     "interrupted dpkg (needs dpkg --configure -a)"),
]

def _check_systemic(err: str) -> str | None:
    """Check apt stderr for systemic failure patterns.
    Returns a human-readable reason string, or None if no systemic issue."""
    for pat, reason in _SYSTEMIC_PATTERNS:
        if pat.search(err):
            return reason
    try:
        st = os.statvfs("/var/cache/apt/archives")
        free_mb = (st.f_bavail * st.f_frsize) // (1024 * 1024)
        if free_mb < 100:
            return f"low disk space on /var/cache/apt/archives ({free_mb} MB free)"
    except OSError:
        pass
    if not _check_dpkg_lock():
        return "dpkg lock held by another process"
    return None

# ── Resolver escalation ─────────────────────────────────────────────────────
_SIM_REMOVE_RE = re.compile(r'^Remv\s+(\S+)')
_SIM_INSTALL_RE = re.compile(r'^Inst\s+(\S+)')
_SIM_KEPT_RE = re.compile(r'kept back.*?:\s*(.*)', re.I)

def _get_held_packages() -> list[str]:
    """Return list of packages with apt hold status."""
    rc, out, _ = _run(["apt-mark", "showhold"], timeout=15)
    if rc != 0:
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]

def _parse_simulation(stdout: str, stderr: str) -> dict:
    """Parse apt-get -s full-upgrade output into structured data."""
    removals: list[str] = []
    installs: list[str] = []
    kept_back: list[str] = []
    for line in stdout.splitlines():
        m = _SIM_REMOVE_RE.match(line)
        if m:
            removals.append(m.group(1).split(":")[0])
            continue
        m = _SIM_INSTALL_RE.match(line)
        if m:
            installs.append(m.group(1).split(":")[0])
    for line in (stderr + "\n" + stdout).splitlines():
        m = _SIM_KEPT_RE.search(line)
        if m:
            for pkg in m.group(1).split():
                name = pkg.strip().split(":")[0]
                if name:
                    kept_back.append(name)
    kept_re2 = re.compile(r'following packages have been kept back', re.I)
    in_kept_block = False
    for line in stdout.splitlines():
        if kept_re2.search(line):
            in_kept_block = True
            continue
        if in_kept_block:
            stripped = line.strip()
            if not stripped:
                in_kept_block = False
                continue
            for token in stripped.split():
                name = token.strip().split(":")[0]
                if name and name not in kept_back:
                    kept_back.append(name)
    return {
        "removals": removals,
        "installs": installs,
        "kept_back": kept_back,
    }

_DEP_ERR_RE = re.compile(
    r'Depends:\s+(\S+)\s+\(([^)]+)\)\s+but\s+(\S+)\s+is\s+to\s+be\s+installed', re.I)
_DEP_NOTINST_RE = re.compile(
    r'Depends:\s+(\S+).*but\s+it\s+is\s+not\s+going\s+to\s+be\s+installed', re.I)
_BREAKS_RE = re.compile(
    r'Breaks:\s+(\S+)\s+\(([^)]+)\)\s+but\s+(\S+)\s+is\s+to\s+be\s+installed', re.I)

def _parse_dep_errors_from_apt(stderr: str) -> dict:
    """Parse 'Depends: X but Y' patterns from apt stderr.
    Returns {dep_name: reason_string}."""
    deps: dict[str, str] = {}
    for m in _DEP_ERR_RE.finditer(stderr):
        dep, constraint, installed = m.group(1), m.group(2), m.group(3)
        name = dep.split(":")[0]
        deps[name] = f"needs {constraint}, have {installed}"
    for m in _DEP_NOTINST_RE.finditer(stderr):
        name = m.group(1).split(":")[0]
        deps[name] = "not going to be installed"
    for m in _BREAKS_RE.finditer(stderr):
        name = m.group(1).split(":")[0]
        deps[name] = f"breaks {m.group(2)}, have {m.group(3)}"
    return deps

def _probe_individual_installs(sample_pkgs: list[str],
                                max_probes: int = 30) -> tuple[list[str], list[str], dict]:
    """Probe individual packages with dry-run to see if they can be installed solo.
    Returns (installable, not_installable, {pkg: dep_errors})."""
    installable: list[str] = []
    not_installable: list[str] = []
    all_dep_errors: dict[str, dict] = {}
    for pkg in sample_pkgs[:max_probes]:
        rc, _, err = _apt(["-s", "install", pkg], timeout=30)
        if rc == 0:
            installable.append(pkg)
        else:
            not_installable.append(pkg)
            dep_errs = _parse_dep_errors_from_apt(err)
            if dep_errs:
                all_dep_errors[pkg] = dep_errs
    return installable, not_installable, all_dep_errors

def _find_root_dep_blockers(dep_errors: dict, protected: set[str],
                             max_depth: int = 4) -> list[str]:
    """Walk dependency chains to find packages that might unblock the resolver.
    Returns candidate packages to try installing first (deepest deps)."""
    all_deps: set[str] = set()
    for pkg_deps in dep_errors.values():
        all_deps.update(pkg_deps.keys())
    candidates: list[str] = []
    visited: set[str] = set()
    queue = list(all_deps)
    for _ in range(max_depth):
        next_queue: list[str] = []
        for dep in queue:
            if dep in visited:
                continue
            visited.add(dep)
            rc, _, err = _apt(["-s", "install", dep], timeout=30)
            if rc == 0:
                candidates.append(dep)
            else:
                deeper = _parse_dep_errors_from_apt(err)
                for d in deeper:
                    if d not in visited:
                        next_queue.append(d)
        if not next_queue:
            break
        queue = next_queue
    return candidates

# ── Deep dependency chain walk ("rabbit trail") ────────────────────────────
# Comprehensive per-package diagnosis using dpkg -s, apt-cache policy,
# apt-cache unmet, and recursive chain walking to find fixable leaves.

def _get_dpkg_status(pkg: str) -> dict:
    """Detailed dpkg status: state, version, depends, status_line."""
    rc, out, _ = _run(["dpkg", "-s", pkg], timeout=30)
    info = {"state": "unknown", "version": "", "depends": [],
            "status_line": "", "installed": False}
    if rc != 0:
        info["state"] = "not-installed"
        return info
    for line in out.splitlines():
        if line.startswith("Status:"):
            info["status_line"] = line.split(":", 1)[1].strip()
            parts = info["status_line"].split()
            if len(parts) >= 2:
                info["state"] = parts[1]
            info["installed"] = ("installed" in info["status_line"]
                                 or "unpacked" in info["status_line"])
        elif line.startswith("Version:"):
            info["version"] = line.split(":", 1)[1].strip()
        elif line.startswith("Depends:") or line.startswith("Pre-Depends:"):
            dep_str = line.split(":", 1)[1].strip()
            for dep_group in dep_str.split(","):
                dep_group = dep_group.strip()
                if not dep_group:
                    continue
                primary = dep_group.split("|")[0].strip()
                name = primary.split()[0].split(":")[0] if primary else ""
                if name and not name.startswith("<"):
                    info["depends"].append(name)
    return info


# ── Rabbit trail: system-wide unmet dep scan + leaf-first chain walk ────────
def _try_python3_apt() -> tuple:
    """Try to import python3-apt for fast in-process dep walking.
    Returns (apt_pkg_module, apt_module) or (None, None)."""
    try:
        import apt_pkg
        try:
            if not apt_pkg.init_done():
                apt_pkg.init()
                apt_pkg.init_config()
                apt_pkg.init_system()
        except AttributeError:
            apt_pkg.init()
            apt_pkg.init_config()
            apt_pkg.init_system()
        import apt
        return apt_pkg, apt
    except (ImportError, SystemError, Exception):
        return None, None

def _apt_cache_broken_map() -> dict[str, list[str]]:
    """Use python3-apt to find broken packages and their unsatisfied deps.
    Returns {pkg_name: [names of deps that are broken/missing]}.
    Falls back gracefully if python3-apt is not available."""
    _, apt_mod = _try_python3_apt()
    if apt_mod is None:
        return {}
    try:
        cache = apt_mod.Cache()
        broken_map: dict[str, list[str]] = {}
        for pkg in cache:
            if not pkg.is_inst_broken:
                continue
            broken_deps: list[str] = []
            ver = pkg.installed or pkg.candidate
            if ver is None:
                broken_map[pkg.name] = []
                continue
            for dep_group in ver.dependencies:
                satisfied = False
                for dep in dep_group:
                    if dep.name in cache:
                        dep_pkg = cache[dep.name]
                        if dep_pkg.is_installed and not dep_pkg.is_inst_broken:
                            satisfied = True
                            break
                if not satisfied and dep_group:
                    broken_deps.append(dep_group[0].name)
            broken_map[pkg.name] = broken_deps
        return broken_map
    except Exception:
        return {}

_UNMET_PKG_RE = re.compile(
    r'Package\s+(\S+)\s+version\s+\S+\s+has an unmet dep', re.I)

def _get_system_unmet() -> dict[str, list[str]]:
    """apt-cache unmet: all packages with unmet deps, system-wide."""
    rc, out, _ = _run(["apt-cache", "unmet"], timeout=60, env=_APT_ENV)
    if rc != 0:
        return {}
    unmet: dict[str, list[str]] = {}
    current_pkg = ""
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _UNMET_PKG_RE.match(line)
        if m:
            current_pkg = m.group(1).split(":")[0]
            if current_pkg not in unmet:
                unmet[current_pkg] = []
            continue
        if current_pkg and (line.startswith("Depends:") or
                            line.startswith("Pre-Depends:") or
                            line.startswith("Breaks:") or
                            line.startswith("Conflicts:")):
            unmet[current_pkg].append(line)
    return unmet

def _get_pkg_policy(pkg: str) -> dict:
    """apt-cache policy: installed version, candidate, priority."""
    rc, out, _ = _run(["apt-cache", "policy", pkg], timeout=10, env=_APT_ENV)
    info: dict = {"installed": "", "candidate": "", "priority": 500}
    if rc != 0:
        return info
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Installed:"):
            info["installed"] = line.split(":", 1)[1].strip()
        elif line.startswith("Candidate:"):
            info["candidate"] = line.split(":", 1)[1].strip()
        elif "***" in line:
            for p in line.split():
                try:
                    info["priority"] = int(p)
                    break
                except ValueError:
                    continue
    return info

def _fix_leaf_pkg(pkg: str, protected: set[str]) -> bool:
    """Targeted fix for a leaf package based on its dpkg state.
    A leaf is a broken package whose own deps are satisfied."""
    if _is_protected(pkg, protected):
        _log("~", f"    {_Y}[P]{_R} {pkg} — protected, configure-only")
        rc, _, _ = _dpkg(["--configure", pkg], timeout=60)
        return rc == 0

    status = _get_dpkg_status(pkg)
    sline = status["status_line"].lower()

    # Reinstreq: stuck waiting for reinstall — force-remove then reinstall
    if "reinstreq" in sline:
        _log("*", f"    {pkg}: reinstreq — force-purge + reinstall")
        _dpkg(["--purge", "--force-remove-reinstreq", pkg], timeout=60)
        rc, _, _ = _apt(["install", "-y", pkg], timeout=300)
        return rc == 0

    # Half-configured or unpacked: dpkg --configure
    if "half-configured" in sline or ("unpacked" in sline and "not-installed" not in sline):
        _log("*", f"    {pkg}: {status['state']} — configure")
        rc, _, _ = _dpkg(["--configure", pkg], timeout=60)
        if rc == 0:
            return True
        rc, _, _ = _dpkg(["--force-depends", "--configure", pkg], timeout=120)
        return rc == 0

    # Half-installed: needs reinstall
    if "half-installed" in sline:
        _log("*", f"    {pkg}: half-installed — reinstall")
        rc, _, _ = _apt(["install", "--reinstall", "-y", pkg], timeout=300)
        if rc == 0:
            return True
        return _download_install(pkg)

    # Try configure first (cheapest)
    rc, _, _ = _dpkg(["--configure", pkg], timeout=60)
    if rc == 0:
        return True

    # Try apt install to pull in correct version
    rc, _, _ = _apt(["install", "-y", pkg], timeout=120)
    if rc == 0:
        return True

    # Version mismatch: try installing specific candidate
    policy = _get_pkg_policy(pkg)
    if (policy["candidate"] and policy["candidate"] != "(none)" and
            policy["candidate"] != policy["installed"]):
        _log("*", f"    {pkg}: ver mismatch — installed={policy['installed']} "
             f"candidate={policy['candidate']}")
        rc, _, _ = _apt(["install", "-y", f"{pkg}={policy['candidate']}"],
                        timeout=120)
        if rc == 0:
            return True

    # Download + dpkg -i
    if _download_install(pkg):
        return True

    # Force-configure as last non-destructive step
    if _force_configure_pkg(pkg):
        return True

    return False

def _walk_dep_chain(start_pkgs: list[str], protected: set[str],
                    max_rounds: int = 8) -> tuple[int, list[str]]:
    """The 'rabbit trail': walk dependency chains bottom-up.
    1. apt-cache unmet + python3-apt → all packages with unmet deps
    2. Build graph: which broken pkgs depend on other broken pkgs
    3. Find leaves: broken packages whose own deps are NOT broken
    4. Fix leaves first using _fix_leaf_pkg (dpkg-state-aware)
    5. Re-scan and repeat until stable
    Returns (fixed_count, remaining_broken_names)."""
    total_fixed = 0
    tried_failed: set[str] = set()
    all_fixed: list[str] = []

    for round_num in range(1, max_rounds + 1):
        if _stopping:
            break
        unmet = _get_system_unmet()

        # Supplement with python3-apt on the first round only — catches
        # resolver-level breaks that apt-cache unmet misses. Expensive
        # (creates a full apt.Cache()), so don't repeat after round 1.
        if round_num == 1:
            p3a_map = _apt_cache_broken_map()
            if p3a_map:
                for pkg in p3a_map:
                    if pkg not in unmet:
                        unmet[pkg] = [f"Depends: {d}" for d in p3a_map[pkg]]
                _log("*", f"  python3-apt: {len(p3a_map)} broken in cache")

        if not unmet:
            _log("+", f"  Round {round_num}: no unmet deps remain")
            break

        _log("*", f"  Round {round_num}: {len(unmet)} packages with unmet deps")

        broken_set = set(unmet.keys())

        # Build graph: for each broken pkg, which of its unmet deps are also broken
        dep_on_broken: dict[str, set[str]] = {}
        for pkg in broken_set:
            broken_deps: set[str] = set()
            for dep_line in unmet.get(pkg, []):
                for token in dep_line.split():
                    name = token.split(":")[0].strip("(),")
                    if name in broken_set and name != pkg:
                        broken_deps.add(name)
                        break
            dep_on_broken[pkg] = broken_deps

        # Find leaves: broken packages whose deps are NOT themselves broken
        # Skip packages we already tried and failed on
        leaves: list[str] = []
        for pkg in sorted(broken_set):
            if pkg in tried_failed:
                continue
            if not dep_on_broken.get(pkg):
                leaves.append(pkg)

        if not leaves:
            # All remaining leaves were already tried — check if there are
            # untried non-leaf packages we can break a cycle on
            untried = sorted(broken_set - tried_failed)
            if untried:
                by_count = sorted(
                    ((p, dep_on_broken.get(p, set())) for p in untried),
                    key=lambda x: len(x[1]))
                if by_count:
                    leaves = [by_count[0][0]]
                    _log("~", f"  Dependency cycle — breaking at {leaves[0]} "
                         f"({len(by_count[0][1])} broken deps)")
            else:
                _log("~", f"  Round {round_num}: all broken packages already "
                     f"tried — stopping")
                break

        _log("*", f"  Leaves to fix: {len(leaves)}"
             f" ({len(tried_failed)} previously failed, skipped)")
        fixed_this_round = 0

        for pkg in leaves:
            if _stopping:
                break
            if _fix_leaf_pkg(pkg, protected):
                _log("+", f"    {pkg} fixed")
                fixed_this_round += 1
                all_fixed.append(pkg)
            else:
                _log("-", f"    {pkg} — could not fix")
                tried_failed.add(pkg)

        total_fixed += fixed_this_round

        if fixed_this_round == 0:
            _log("~", f"  Round {round_num}: no progress — stopping")
            break

        _log("+", f"  Round {round_num}: fixed {fixed_this_round} leaf packages")

        # Save progress checkpoint
        _save_checkpoint("rabbit_trail", all_fixed, sorted(tried_failed), {})

        # Let apt settle after fixing leaves
        _apt(["install", "-f", "-y"], timeout=300)

    remaining = _get_system_unmet()
    return total_fixed, sorted(remaining.keys())

# ── Additional resolver diagnostics ──────────────────────────────────────
_DEBUG_BROKEN_RE = re.compile(r'Broken\s+(\S+)\s+(Depends|PreDepends|Breaks|Conflicts)\s+on\s+(\S+)')
_DEBUG_CONSIDERING_RE = re.compile(r'Considering\s+(\S+)\s+\d+\s+as a solution')
_DEBUG_REMOVING_RE = re.compile(r'Removing\s+(\S+)\s+rather than')

def _check_pin_blocks() -> list[dict]:
    """Check for packages blocked by apt pin priorities."""
    blocked: list[dict] = []
    rc, out, _ = _run(["apt", "list", "--upgradable"], timeout=60, env=_APT_ENV)
    if rc != 0:
        return blocked
    sample: list[str] = []
    for line in out.splitlines():
        m = _UPG_RE.match(line) if line and "/" in line else None
        if m:
            sample.append(m.group(1).split(":")[0])
            if len(sample) >= 50:
                break
    for pkg in sample:
        policy = _get_pkg_policy(pkg)
        if not policy.get("candidate") or policy["candidate"] == "(none)":
            continue
        prio = policy.get("priority", 500)
        if prio < 0:
            blocked.append({"pkg": pkg, "priority": prio,
                            "installed": policy["installed"],
                            "candidate": policy["candidate"]})
        elif policy["installed"] == policy["candidate"] and policy["installed"] != "(none)":
            blocked.append({"pkg": pkg, "priority": prio,
                            "installed": policy["installed"],
                            "candidate": policy["candidate"],
                            "note": "candidate==installed despite upgradable listing"})
    return blocked

def _try_debug_resolver() -> dict:
    """Run apt-get with Debug::pkgProblemResolver to get conflict details.
    Returns {broken_pkgs: set, conflict_pairs: [(pkg, dep)], solutions: [pkg]}."""
    rc, out, err = _run(
        ["apt-get", "-o", "Debug::pkgProblemResolver=yes",
         "-s", "full-upgrade"],
        timeout=180, env=_APT_ENV)
    combined = out + "\n" + err
    broken_pkgs: set[str] = set()
    conflict_pairs: list[tuple[str, str]] = []
    solutions: list[str] = []
    removals: list[str] = []
    for line in combined.splitlines():
        m = _DEBUG_BROKEN_RE.search(line)
        if m:
            pkg = m.group(1).split(":")[0]
            dep = m.group(3).split(":")[0]
            broken_pkgs.add(pkg)
            conflict_pairs.append((pkg, dep))
            continue
        m = _DEBUG_CONSIDERING_RE.search(line)
        if m:
            solutions.append(m.group(1).split(":")[0])
            continue
        m = _DEBUG_REMOVING_RE.search(line)
        if m:
            removals.append(m.group(1).split(":")[0])
    return {
        "broken_pkgs": broken_pkgs,
        "conflict_pairs": conflict_pairs,
        "solutions": solutions,
        "removals": removals,
    }

def _try_aptitude_fallback(protected: set[str]) -> bool:
    """Try aptitude's more capable SAT-solver resolver.
    Simulates first, checks for protected removals, then executes if safe.
    Returns True if aptitude resolved the situation."""
    if not shutil.which("aptitude"):
        return False
    _log("*", "aptitude available — trying its resolver")

    rc, out, err = _run(
        ["aptitude", "-s", "safe-upgrade", "-y"],
        timeout=180, env=_APT_ENV)
    if rc == 0 and "No packages will be installed" not in out:
        removals: list[str] = []
        in_remove_section = False
        for line in out.splitlines():
            stripped = line.strip()
            if "REMOVED" in stripped.upper() and ":" in stripped:
                in_remove_section = True
                continue
            if in_remove_section:
                if not stripped or (":" in stripped and
                                   any(kw in stripped.upper()
                                       for kw in ("INSTALL", "UPGRADE", "KEPT"))):
                    in_remove_section = False
                    continue
                for token in stripped.split():
                    name = token.split(":")[0].rstrip("{}")
                    if name and name[0].isalpha():
                        removals.append(name)

        crit_removals = [p for p in removals if _is_protected(p, protected)]
        if crit_removals:
            _log("~", f"aptitude would remove protected packages: "
                 f"{', '.join(crit_removals[:10])}")
            _log("~", "Declining aptitude solution")
            return False

        _log("+", f"aptitude simulation passed (would remove {len(removals)} "
             f"non-critical packages) — executing")
        rc_real, out_real, err_real = _run(
            ["aptitude", "safe-upgrade", "-y"],
            timeout=600, env=_APT_ENV)
        if rc_real == 0:
            _log("+", "aptitude safe-upgrade succeeded")
            return True
        _log("-", f"aptitude execution failed (exit {rc_real})")
        if err_real.strip():
            for line in err_real.strip().splitlines()[-3:]:
                _log("", f"  {_DIM}{line.strip()}{_R}")
        return False

    # Simulation didn't find a solution — run why-not diagnostics
    rc_list, list_out, _ = _run(
        ["apt", "list", "--upgradable"], timeout=60, env=_APT_ENV)
    if rc_list == 0:
        for line in list_out.splitlines()[:5]:
            m = _UPG_RE.match(line) if line and "/" in line else None
            if m:
                pkg = m.group(1).split(":")[0]
                rc_why, why_out, _ = _run(
                    ["aptitude", "why-not", pkg], timeout=30, env=_APT_ENV)
                if rc_why == 0 and why_out.strip():
                    _log("*", f"  aptitude why-not {pkg}:")
                    for wline in why_out.strip().splitlines()[:5]:
                        _log("", f"    {_DIM}{wline.strip()}{_R}")
    return False

def _try_transition_installs(conflict_pairs: list[tuple[str, str]],
                              protected: set[str]) -> int:
    """Use apt-get install suffix syntax (pkg1- pkg2+) for library transitions.
    Returns count of successful transitions."""
    if not conflict_pairs:
        return 0
    fixed = 0
    seen: set[tuple[str, str]] = set()
    for old_pkg, new_dep in conflict_pairs:
        pair = (old_pkg, new_dep) if old_pkg < new_dep else (new_dep, old_pkg)
        if pair in seen:
            continue
        seen.add(pair)
        if _is_protected(old_pkg, protected) or _is_protected(new_dep, protected):
            continue
        # Check if this looks like a library transition (old- → new+)
        rc, _, err = _apt(["-s", "install", f"{old_pkg}-", f"{new_dep}+"], timeout=60)
        if rc == 0:
            _log("*", f"  Transition: {old_pkg}→{new_dep}")
            rc2, _, _ = _apt(["install", "-y", f"{old_pkg}-", f"{new_dep}+"], timeout=120)
            if rc2 == 0:
                _log("+", f"  {old_pkg}→{new_dep} transitioned")
                fixed += 1
            else:
                _log("-", f"  {old_pkg}→{new_dep} transition failed")
        if fixed >= 20:
            break
    return fixed

def _escalate_resolver(ctx: dict) -> bool:
    """Attempt safe escalation to fix the apt resolver.
    Returns True if the resolver is now clean (systemic issue cleared).
    NEVER runs full-upgrade. Works surgically on individual packages."""
    protected = ctx.get("critical_pkgs", set())
    active_methods = ctx.get("active_methods", [])

    _log("*", "Escalating resolver repair…")

    # ── Step 1: Check for held packages ──────────────────────────────────
    held = _get_held_packages()
    if held:
        _log("~", f"Found {len(held)} held packages: {', '.join(held[:20])}")
        _log("*", "Unholding all held packages (does not change installed versions)")
        for pkg in held:
            rc, _, _ = _run(["apt-mark", "unhold", pkg], timeout=10, env=_APT_ENV)
            if rc == 0:
                _log("+", f"  Unheld {pkg}")
            else:
                _log("-", f"  Failed to unhold {pkg}")

        # Retry apt install -f after unholding
        _log("*", "Retrying apt install -f after unholding…")
        rc, _, err = _apt(["install", "-f", "-y"], timeout=300)
        if rc == 0:
            _log("+", "Resolver clean after unholding packages")
            ctx.pop("_repair_systemic", None)
            return True
        _log("~", "Still broken after unholding")
    else:
        _log("", "  No held packages found")

    # ── Step 2: Simulate full-upgrade to diagnose the knot ───────────────
    _log("*", "Simulating full-upgrade to diagnose dependency knot (dry-run only)…")
    rc, sim_out, sim_err = _apt(["-s", "full-upgrade"], timeout=180)

    sim = _parse_simulation(sim_out, sim_err)
    removals = sim["removals"]
    installs = sim["installs"]
    kept_back = sim["kept_back"]

    if not removals and not installs and not kept_back:
        if rc != 0:
            _log("-", "Simulation failed with no actionable output")
            if sim_err.strip():
                for line in sim_err.strip().splitlines()[-5:]:
                    _log("", f"  {_DIM}{line.strip()}{_R}")
            # ── Step 2a: Rabbit trail — bottom-up dep chain walk ───────
            _log("*", "Running rabbit trail diagnostic (apt-cache unmet)…")
            unmet = _get_system_unmet()
            if unmet:
                _log("~", f"  {len(unmet)} packages with unmet deps — "
                     f"walking chains bottom-up")
                trail_fixed, trail_remaining = _walk_dep_chain(
                    list(unmet.keys()), protected, max_rounds=6)
                if trail_fixed > 0:
                    _log("+", f"Rabbit trail fixed {trail_fixed} packages")
                    rc_rt, _, _ = _apt(["install", "-f", "-y"], timeout=300)
                    if rc_rt == 0:
                        _log("+", "Resolver clean after rabbit trail repair")
                        ctx.pop("_repair_systemic", None)
                        return True
                    if not trail_remaining:
                        _log("+", "All unmet deps resolved — testing upgrade")
                        ctx.pop("_repair_systemic", None)
                        return True
                    _log("~", f"  {len(trail_remaining)} packages still have "
                         f"unmet deps after rabbit trail")
                else:
                    _log("~", "  Rabbit trail made no progress")
            else:
                _log("", "  apt-cache unmet reports nothing — deps look clean to apt")

            # ── Step 2b: Debug resolver for conflict details ─────────
            _log("*", "Running debug resolver to identify specific conflicts…")
            debug = _try_debug_resolver()
            if debug["broken_pkgs"]:
                _log("~", f"  Resolver sees {len(debug['broken_pkgs'])} broken packages")
                for bp in sorted(debug["broken_pkgs"])[:15]:
                    _log("", f"    {_DIM}{bp}{_R}")

                # If step 2a had nothing (apt-cache unmet was empty) but the
                # debug resolver found broken packages, feed those as seeds
                # back into the rabbit trail chain walker.
                if not unmet and debug["broken_pkgs"]:
                    _log("*", "  apt-cache unmet was empty but debug resolver "
                         "found broken packages — re-running rabbit trail "
                         "with debug seeds…")
                    trail_fixed2, trail_remaining2 = _walk_dep_chain(
                        sorted(debug["broken_pkgs"]), protected, max_rounds=6)
                    if trail_fixed2 > 0:
                        _log("+", f"  Debug-seeded rabbit trail fixed "
                             f"{trail_fixed2} packages")
                        rc_rt2, _, _ = _apt(["install", "-f", "-y"], timeout=300)
                        if rc_rt2 == 0:
                            _log("+", "Resolver clean after debug-seeded repair")
                            ctx.pop("_repair_systemic", None)
                            return True

                if debug["conflict_pairs"]:
                    _log("*", f"  {len(debug['conflict_pairs'])} conflict pairs found — "
                         f"trying library transition syntax")
                    t_fixed = _try_transition_installs(
                        debug["conflict_pairs"], protected)
                    if t_fixed > 0:
                        _log("+", f"  {t_fixed} library transitions resolved")
                        rc_t, _, _ = _apt(["install", "-f", "-y"], timeout=300)
                        if rc_t == 0:
                            _log("+", "Resolver clean after library transitions")
                            ctx.pop("_repair_systemic", None)
                            return True

            # ── Step 2c: Check for pin blocks ────────────────────────
            _log("*", "Checking for apt pin blocks…")
            pin_blocks = _check_pin_blocks()
            if pin_blocks:
                neg_pins = [pb for pb in pin_blocks if pb.get("priority", 500) < 0]
                _log("~", f"  {len(pin_blocks)} packages appear pin-blocked"
                     f" ({len(neg_pins)} with negative priority):")
                for pb in pin_blocks[:10]:
                    note = pb.get("note", f"priority={pb['priority']}")
                    _log("", f"    {_DIM}{pb['pkg']}: {note}{_R}")
                # Attempt to install negatively-pinned packages at candidate version
                if neg_pins:
                    _log("*", "  Trying to override negative pins with explicit version…")
                    pin_fixed = 0
                    for pb in neg_pins[:20]:
                        pkg = pb["pkg"]
                        cand = pb.get("candidate", "")
                        if not cand or cand == "(none)":
                            continue
                        if _is_protected(pkg, protected):
                            continue
                        rc_pin, _, _ = _apt(
                            ["install", "-y", f"{pkg}={cand}"], timeout=120)
                        if rc_pin == 0:
                            pin_fixed += 1
                            _log("+", f"    {pkg} installed at {cand}")
                    if pin_fixed > 0:
                        _log("+", f"  Overrode {pin_fixed} negative pins")
                        rc_pf, _, _ = _apt(["install", "-f", "-y"], timeout=300)
                        if rc_pf == 0:
                            _log("+", "Resolver clean after pin overrides")
                            ctx.pop("_repair_systemic", None)
                            return True

            # ── Step 2c½: Sources.list sanity check ─────────────────
            _log("*", "Checking sources.list sanity…")
            src_warnings = _check_sources_sanity()
            if src_warnings:
                for w in src_warnings:
                    _log("-", f"  {_RD}{w}{_R}")
                _log("~", "  Sources.list problems can cause resolver breakage — "
                     "review /etc/apt/sources.list and sources.list.d/")
            else:
                _log("+", "  Sources.list looks clean")

            # ── Step 2c¾: Version conflict detection ─────────────────
            _log("*", "Checking for version conflicts…")
            v_conflicts = _find_version_conflicts(sample if sample else [])
            if v_conflicts:
                _log("~", f"  {len(v_conflicts)} version conflicts detected:")
                vf_fixed = 0
                for vc in v_conflicts[:15]:
                    _log("", f"    {_DIM}{vc['pkg']} {vc['installed']} "
                         f"(needed by {vc['needed_by']}) → "
                         f"candidate {vc['candidate']}{_R}")
                    if not _is_protected(vc["pkg"], protected):
                        rc_vc, _, _ = _apt(
                            ["install", "-y", f"{vc['pkg']}={vc['candidate']}"],
                            timeout=120)
                        if rc_vc == 0:
                            vf_fixed += 1
                            _log("+", f"    {vc['pkg']} upgraded to {vc['candidate']}")
                if vf_fixed > 0:
                    rc_vf, _, _ = _apt(["install", "-f", "-y"], timeout=300)
                    if rc_vf == 0:
                        _log("+", "Resolver clean after version conflict fixes")
                        ctx.pop("_repair_systemic", None)
                        return True

            # ── Step 2d: Probe individual packages ───────────────────
            _log("*", "Probing individual packages to diagnose…")
            rc_list, list_out, _ = _run(
                ["apt", "list", "--upgradable"], timeout=60, env=_APT_ENV)
            sample: list[str] = []
            if rc_list == 0:
                for line in list_out.splitlines():
                    m = _UPG_RE.match(line) if line and "/" in line else None
                    if m:
                        name = m.group(1).split(":")[0]
                        sample.append(name)
                        if len(sample) >= 30:
                            break
            if not sample:
                sample = ["bash", "curl", "coreutils", "grep", "sed",
                          "findutils", "gzip", "tar", "diffutils", "file"]
            installable, not_installable, dep_errors = _probe_individual_installs(sample)
            n_ok = len(installable)
            n_fail = len(not_installable)
            _log("*", f"Probe results: {n_ok}/{n_ok + n_fail} packages can install individually")

            if n_ok > 0:
                _log("+", "Individual installs work — the resolver chokes on "
                     "coordinated batch upgrades only")
                _log("*", "Switching to individual upgrade mode")
                ctx.pop("_repair_systemic", None)
                ctx["_individual_mode"] = True
                return True

            # All probes failed — deeper diagnosis with chain walking
            if dep_errors:
                _log("~", "Dependency errors found:")
                all_blocking: set[str] = set()
                for pkg, deps in dep_errors.items():
                    for dep, reason in deps.items():
                        all_blocking.add(dep)
                        _log("", f"  {_DIM}{pkg} → {dep}: {reason}{_R}")

                _log("*", f"Walking dependency chains from {len(all_blocking)} "
                     f"blocking packages…")
                candidates = _find_root_dep_blockers(
                    dep_errors, protected, max_depth=4)
                if candidates:
                    _log("+", f"Found {len(candidates)} installable root dependencies")
                    any_installed = False
                    for cand in candidates:
                        if _is_protected(cand, protected):
                            _log("~", f"  {_Y}[P]{_R} {cand} — protected, skipping")
                            continue
                        _log("*", f"  Installing {cand}…")
                        rc_inst, _, _ = _apt(["install", "-y", cand], timeout=120)
                        if rc_inst == 0:
                            _log("+", f"  {cand} installed")
                            any_installed = True
                        else:
                            _log("-", f"  {cand} failed")
                    if any_installed:
                        rc_retest, _, _ = _apt(["install", "-f", "-y"], timeout=300)
                        if rc_retest == 0:
                            _log("+", "Resolver clean after installing root deps")
                            ctx.pop("_repair_systemic", None)
                            return True
                        inst2, _, _ = _probe_individual_installs(sample)
                        if len(inst2) > n_ok:
                            _log("+", f"Progress: {len(inst2)}/{len(sample)} "
                                 f"now installable (was {n_ok})")
                            ctx.pop("_repair_systemic", None)
                            ctx["_individual_mode"] = True
                            return True
                else:
                    _log("-", "No installable root dependencies found")

            # ── Step 2e: aptitude fallback ────────────────────────────
            if _try_aptitude_fallback(protected):
                _log("+", "aptitude found a viable solution — re-testing")
                rc_apt, _, _ = _apt(["install", "-f", "-y"], timeout=300)
                if rc_apt == 0:
                    ctx.pop("_repair_systemic", None)
                    return True

            _log("-", "Cannot resolve — all escalation paths exhausted")
            return False

        _log("~", "Simulation shows nothing to do — resolver may already be clean")
        rc_test, _, err_test = _apt(["install", "-f", "-y"], timeout=300)
        if rc_test == 0:
            ctx.pop("_repair_systemic", None)
            return True
        return False

    # Report what the simulation found
    if removals:
        _log("~", f"Simulation wants to REMOVE {len(removals)} packages:")
        for pkg in removals[:30]:
            is_crit = _is_protected(pkg, protected)
            tag = f" {_RD}[CRITICAL]{_R}" if is_crit else ""
            _log("", f"  {_DIM}{pkg}{_R}{tag}")
        if len(removals) > 30:
            _log("", f"  {_DIM}… and {len(removals) - 30} more{_R}")
    if installs:
        _log("", f"Simulation wants to install/upgrade {len(installs)} packages")
    if kept_back:
        _log("~", f"Simulation keeps back {len(kept_back)} packages: "
             f"{', '.join(kept_back[:15])}")

    # ── Step 3: Classify removals as safe vs critical ────────────────────
    critical_removals = [p for p in removals if _is_protected(p, protected)]
    safe_removals = [p for p in removals if not _is_protected(p, protected)]

    if critical_removals:
        _log("-", f"{len(critical_removals)} connectivity-critical packages would be removed — "
             f"will NOT touch them:")
        for pkg in critical_removals:
            _log("", f"  {_RD}{pkg}{_R}")

    # ── Step 4: Surgically process safe removal/transition pairs ─────────
    if not safe_removals:
        _log("~", "No safe removals to process — cannot resolve the knot automatically")
        if critical_removals:
            _log("-", "The dependency knot involves critical packages that cannot be "
                 "safely removed remotely")
            _log("-", "Manual intervention required — run interactively with console access")
        return False

    # Filter installs to safe ones (the simulation's replacement packages)
    safe_installs = [p for p in installs if not _is_protected(p, protected)]
    _log("*", f"Processing {len(safe_removals)} safe removals"
         f" + {len(safe_installs)} replacement installs…")
    resolved_count = 0
    failed_transitions: list[str] = []

    batch_size = 5
    for i in range(0, len(safe_removals), batch_size):
        if _stopping:
            break
        batch = safe_removals[i:i + batch_size]
        batch_label = f"Batch {i // batch_size + 1}"

        if active_methods:
            pre = _verify_all_conn(active_methods)
            if not all(c["ok"] for c in pre):
                _log("-", f"Connectivity degraded — stopping resolver escalation")
                break

        _log("*", f"  {batch_label}: removing {len(batch)} blocking packages…")
        for pkg in batch:
            rc, _, err = _apt(["remove", "-y", pkg], timeout=120)
            if rc == 0:
                _log("+", f"    Removed {pkg}")
                resolved_count += 1
            else:
                rc2, _, _ = _dpkg(["--purge", "--force-depends", pkg], timeout=60)
                if rc2 == 0:
                    _log("+", f"    Force-removed {pkg}")
                    resolved_count += 1
                else:
                    _log("-", f"    Cannot remove {pkg}")
                    failed_transitions.append(pkg)

        # After removal batch, try installing replacement packages
        rc_test, _, err_test = _apt(["install", "-f", "-y"], timeout=300)
        if rc_test == 0:
            _log("+", f"Resolver clean after removing {resolved_count} blocking packages")
            ctx.pop("_repair_systemic", None)
            if active_methods:
                post = _verify_all_conn(active_methods)
                post_str = "  ".join(
                    f"{_G}✓{_R} {c['name']}" if c["ok"] else f"{_RD}✗{_R} {c['name']}"
                    for c in post
                )
                _log("*", f"  Connectivity: {post_str}")
            return True

    # ── Step 5: Install replacement packages the simulation identified ───
    if resolved_count > 0 and safe_installs:
        _log("*", f"Installing {len(safe_installs)} replacement packages…")
        install_batch_size = 10
        for i in range(0, len(safe_installs), install_batch_size):
            if _stopping:
                break
            ibatch = safe_installs[i:i + install_batch_size]
            rc_ib, _, _ = _apt(["install", "-y"] + ibatch, timeout=300)
            if rc_ib == 0:
                _log("+", f"  Installed {len(ibatch)} replacements")
            else:
                for rpkg in ibatch:
                    _apt(["install", "-y", rpkg], timeout=120)
        rc_final, _, _ = _apt(["install", "-f", "-y"], timeout=300)
        if rc_final == 0:
            _log("+", "Resolver clean after installing replacements")
            ctx.pop("_repair_systemic", None)
            return True

    # ── Step 6: Final check ──────────────────────────────────────────────
    if resolved_count > 0:
        _log("~", f"Removed {resolved_count} blocking packages but resolver still not clean")
        rc, _, err = _apt(["install", "-f", "-y"], timeout=300)
        if rc == 0:
            ctx.pop("_repair_systemic", None)
            return True

    if failed_transitions:
        _log("-", f"{len(failed_transitions)} packages could not be removed:")
        for pkg in failed_transitions:
            _log("", f"  {_RD}{pkg}{_R}")

    _log("-", "Resolver escalation could not fully resolve the dependency knot")
    _log("-", "Manual intervention required with console access")
    return False

def _resolver_is_clean() -> bool:
    """Quick test: can apt install -f succeed?"""
    rc, _, _ = _apt(["install", "-f", "-y", "--dry-run"], timeout=60)
    return rc == 0

# ── dpkg --audit: find packages stuck mid-script ────────────────────────────
_AUDIT_PKG_RE = re.compile(r'^\s*(\S+)\s', re.M)

def _dpkg_audit() -> list[dict]:
    """Run dpkg --audit to find packages in inconsistent states.
    Catches packages stuck mid-postinst/mid-prerm that apt-cache unmet misses."""
    rc, out, _ = _run(["dpkg", "--audit"], timeout=60, env=_APT_ENV)
    if rc != 0 and not out.strip():
        return []
    entries: list[dict] = []
    current_section = ""
    for line in out.splitlines():
        line_stripped = line.strip()
        if not line_stripped:
            continue
        if line_stripped.startswith("The following") or line_stripped.startswith("Packages"):
            current_section = line_stripped
            continue
        if line and not line[0].isspace():
            continue
        m = _AUDIT_PKG_RE.match(line)
        if m:
            pkg = m.group(1).split(":")[0]
            entries.append({"pkg": pkg, "section": current_section})
    return entries

def _fix_audit_packages(entries: list[dict], protected: set[str]) -> int:
    """Fix packages found by dpkg --audit. Returns count fixed."""
    fixed = 0
    for entry in entries:
        pkg = entry["pkg"]
        if _is_protected(pkg, protected):
            _log("~", f"  {_Y}[P]{_R} {pkg} — protected, configure-only")
            rc, _, _ = _dpkg(["--configure", pkg], timeout=60)
            if rc == 0:
                fixed += 1
            continue
        status = _get_dpkg_status(pkg)
        sline = status["status_line"].lower()
        if "half-configured" in sline or "unpacked" in sline:
            rc, _, _ = _dpkg(["--configure", pkg], timeout=60)
            if rc == 0:
                _log("+", f"  {pkg} configured")
                fixed += 1
                continue
            rc, _, _ = _dpkg(["--force-depends", "--configure", pkg], timeout=120)
            if rc == 0:
                _log("+", f"  {pkg} force-configured")
                fixed += 1
                continue
        if "half-installed" in sline or "reinstreq" in sline:
            if "reinstreq" in sline:
                _dpkg(["--purge", "--force-remove-reinstreq", pkg], timeout=60)
            rc, _, _ = _apt(["install", "--reinstall", "-y", pkg], timeout=300)
            if rc == 0:
                _log("+", f"  {pkg} reinstalled")
                fixed += 1
                continue
        _log("-", f"  {pkg} — could not fix ({status['state']})")
    return fixed

# ── Sources.list sanity check ───────────────────────────────────────────────
def _check_sources_sanity() -> list[str]:
    """Check for common sources.list problems that cause resolver breakage."""
    warnings: list[str] = []
    sources_files: list[Path] = []
    for p in [Path("/etc/apt/sources.list")]:
        if p.exists():
            sources_files.append(p)
    sources_d = Path("/etc/apt/sources.list.d")
    if sources_d.is_dir():
        sources_files.extend(sorted(sources_d.glob("*.list")))
        sources_files.extend(sorted(sources_d.glob("*.sources")))

    suites_seen: set[str] = set()
    origins_seen: set[str] = set()
    for sf in sources_files:
        try:
            text = sf.read_text()
        except Exception:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 3 and parts[0] in ("deb", "deb-src"):
                url = parts[1]
                suite = parts[2]
                suites_seen.add(suite)
                if "debian.org" in url:
                    origins_seen.add("debian")
                elif "ubuntu.com" in url:
                    origins_seen.add("ubuntu")
                elif "kali.org" in url:
                    origins_seen.add("kali")

    if len(origins_seen) > 1:
        warnings.append(f"Mixed distro sources detected: {', '.join(sorted(origins_seen))}")
    mixed_releases = set()
    release_keywords = {"stable", "testing", "unstable", "sid", "experimental",
                        "bookworm", "bullseye", "buster", "trixie",
                        "jammy", "noble", "focal", "kinetic",
                        "kali-rolling", "kali-last-snapshot"}
    for s in suites_seen:
        base = s.split("-")[0] if "-" in s else s
        if base in release_keywords:
            mixed_releases.add(base)
    if len(mixed_releases) > 1:
        warnings.append(f"Mixed release suites: {', '.join(sorted(mixed_releases))}")

    rc, out, _ = _run(["apt-key", "list", "--keyring",
                        "/etc/apt/trusted.gpg"], timeout=15, env=_APT_ENV)
    if rc == 0 and "expired" in out.lower():
        warnings.append("Expired GPG keys in apt keyring")
    return warnings

# ── Progress checkpoint for resumption ──────────────────────────────────────
_CHECKPOINT_PATH = "/tmp/safe_upgrade_checkpoint.json"

def _save_checkpoint(phase: str, fixed_pkgs: list[str],
                     failed_pkgs: list[str], ctx_flags: dict) -> None:
    """Save progress so a restarted run can skip already-fixed packages."""
    data = {
        "version": VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "phase": phase,
        "fixed_packages": sorted(set(fixed_pkgs)),
        "failed_packages": sorted(set(failed_pkgs)),
        "flags": ctx_flags,
    }
    try:
        with open(_CHECKPOINT_PATH, "w") as f:
            json.dump(data, f, indent=2)
    except OSError:
        pass

def _load_checkpoint() -> dict | None:
    """Load a previous checkpoint if it exists and is recent (< 6 hours)."""
    try:
        with open(_CHECKPOINT_PATH) as f:
            data = json.load(f)
        ts = datetime.fromisoformat(data["timestamp"])
        age = (datetime.now(timezone.utc) - ts).total_seconds()
        if age > 6 * 3600:
            return None
        return data
    except (OSError, json.JSONDecodeError, KeyError, ValueError):
        return None

def _clear_checkpoint() -> None:
    try:
        os.remove(_CHECKPOINT_PATH)
    except OSError:
        pass

# ── Version conflict detection ──────────────────────────────────────────────
def _find_version_conflicts(sample_pkgs: list[str]) -> list[dict]:
    """Check if installed versions satisfy their reverse-deps' constraints.
    Uses dpkg --compare-versions to detect version mismatches."""
    conflicts: list[dict] = []
    for pkg in sample_pkgs[:30]:
        if _stopping:
            break
        rc, out, _ = _run(["apt-cache", "rdepends", "--installed", pkg],
                          timeout=15, env=_APT_ENV)
        if rc != 0:
            continue
        status = _get_dpkg_status(pkg)
        installed_ver = status.get("version", "")
        if not installed_ver:
            continue
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith(pkg) or line == "Reverse Depends:":
                continue
            rdep = line.split(":")[0].strip()
            if not rdep or rdep.startswith("|"):
                continue
            rdep_status = _get_dpkg_status(rdep)
            if not rdep_status["installed"]:
                continue
            for dep_name in rdep_status["depends"]:
                if dep_name == pkg:
                    break
            else:
                continue
            policy = _get_pkg_policy(pkg)
            if (policy["candidate"] and policy["candidate"] != "(none)" and
                    policy["candidate"] != installed_ver):
                conflicts.append({
                    "pkg": pkg,
                    "installed": installed_ver,
                    "needed_by": rdep,
                    "candidate": policy["candidate"],
                })
                break
    return conflicts

# ── end resolver escalation ─────────────────────────────────────────────────

def _upgrade_chunk(pkgs: list[str], depth: int = 0,
                   chunk_label: str = "") -> tuple[list[str], list[str]]:
    if not pkgs or _stopping:
        return [], list(pkgs)
    rc, out, err = _apt_install(pkgs)
    if rc == 0:
        return list(pkgs), []
    if depth == 0 and len(pkgs) > 1:
        _log("~", f"{chunk_label}chunk failed as a group — splitting to isolate failures")
        systemic = _check_systemic(err)
        if systemic:
            _log("-", f"  Systemic issue detected: {systemic}")
            # Probe ONE package individually before giving up on the whole chunk
            test_pkg = pkgs[0]
            rc_probe, _, _ = _apt_install([test_pkg])
            if rc_probe == 0:
                _log("+", f"  {test_pkg} installed individually — batch conflict, not per-package")
                _log("*", f"  Falling through to binary split…")
                # Don't skip — let the binary split try packages individually
            else:
                _log("-", f"  {test_pkg} also fails individually — truly systemic")
                _log("-", f"  Skipping binary-split retry — all {len(pkgs)} packages will fail for the same reason")
                for p in pkgs:
                    _log("-", f"  SKIP {p} ({systemic})")
                return [], list(pkgs)
        err_lines = [l.strip() for l in (err or "").splitlines() if l.strip() and not l.startswith("WARNING")]
        if err_lines:
            _log("~", f"  apt error output:")
            for line in err_lines[-5:]:
                _log("", f"    {_DIM}{line}{_R}")
    _repair_quick()
    if len(pkgs) == 1:
        err_reason = ""
        if err:
            systemic = _check_systemic(err)
            if systemic:
                err_reason = f" ({systemic})"
            else:
                for line in reversed((err or "").splitlines()):
                    line = line.strip()
                    if line and not line.startswith("WARNING") and not line.startswith("E:"):
                        err_reason = f" ({line[:80]})"
                        break
                if not err_reason:
                    for line in reversed((err or "").splitlines()):
                        line = line.strip()
                        if line.startswith("E:"):
                            err_reason = f" ({line[:80]})"
                            break
        _log("-", f"  {pkgs[0]} cannot be upgraded{err_reason}")
        return [], list(pkgs)
    if depth > 8:
        _log("-", f"  Giving up on {len(pkgs)} packages after 8 split retries")
        return [], list(pkgs)
    mid = len(pkgs) // 2
    lbl = f"{chunk_label}L{depth}/" if depth < 3 else ""
    rbll = f"{chunk_label}R{depth}/" if depth < 3 else ""
    if depth < 3:
        _log("*", f"  Split depth {depth}: trying {mid} left + {len(pkgs)-mid} right")
    ok_l, fail_l = _upgrade_chunk(pkgs[:mid], depth + 1, lbl)
    ok_r, fail_r = _upgrade_chunk(pkgs[mid:], depth + 1, rbll)
    total_ok = len(ok_l) + len(ok_r)
    total_fail = len(fail_l) + len(fail_r)
    if depth == 0 and total_ok == 0 and total_fail > 0:
        _log("-", f"  All {total_fail} packages failed after binary-split — likely a systemic issue")
        systemic = _check_systemic(err)
        if systemic:
            _log("-", f"  Root cause: {systemic}")
    return ok_l + ok_r, fail_l + fail_r

def _extract_err_reason(err: str) -> str:
    """Extract a human-readable failure reason from apt/dpkg stderr."""
    if not err:
        return "unknown error (no stderr)"
    systemic = _check_systemic(err)
    if systemic:
        return systemic
    for line in reversed(err.splitlines()):
        line = line.strip()
        if line.startswith("E:"):
            return line[:120]
    for line in reversed(err.splitlines()):
        line = line.strip()
        if line and not line.startswith("WARNING") and not line.startswith("N:"):
            return line[:120]
    return "unknown error"

def _upgrade_single(pkg: str) -> tuple[bool, str]:
    """Returns (success, failure_reason). failure_reason is '' on success."""
    rc, out, err = _apt_install([pkg])
    if rc == 0:
        return True, ""
    last_err = err
    deps = _extract_deps_from_error(err)
    if deps:
        _log("*", f"  Resolving {len(deps)} deps for {pkg}…")
        ordered = _topo_sort_broken(deps)
        for dep in ordered:
            _dpkg(["--configure", dep], timeout=60)
    _repair_quick()
    rc, out, err = _apt_install([pkg])
    if rc == 0:
        return True, ""
    if err:
        last_err = err
    _resolve_deps(pkg, protected=_PROTECTED_PKGS)
    rc, out, err = _apt_install([pkg])
    if rc == 0:
        return True, ""
    if err:
        last_err = err
    _log("*", f"  Trying download + dpkg -i for {pkg}…")
    if _download_install(pkg):
        _dpkg(["--configure", pkg], timeout=60)
        return True, ""
    return False, _extract_err_reason(last_err)

def _verify_all_conn(active_methods: list[dict]) -> list[dict]:
    results = []
    for m in active_methods:
        ok = m["verify"]()
        results.append({"name": m["name"], "ok": ok})
    return results

def _restart_services(method: dict) -> bool:
    for svc in method.get("restart", []):
        _run(["systemctl", "restart", svc], timeout=30)
    time.sleep(3)
    return method["verify"]()

# ── Inventory parsing ────────────────────────────────────────────────────────
_UPG_RE = re.compile(
    r'^(\S+?)(?:/\S+)?\s+(\S+)\s+\S+\s+\[upgradable from:\s+(\S+)\]'
)

def _get_upgradable(include_held: bool = False) -> list[dict]:
    rc, out, _ = _run(["apt", "list", "--upgradable"], timeout=120, env=_APT_ENV)
    held: set[str] = set()
    if not include_held:
        hrc, hout, _ = _run(["dpkg", "--get-selections"], timeout=30)
        for line in hout.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] == "hold":
                held.add(parts[0].split(":")[0])
    pkgs = []
    for line in out.splitlines():
        m = _UPG_RE.match(line)
        if not m:
            continue
        name = m.group(1).split(":")[0]
        if name in held:
            continue
        pkgs.append({
            "name": name,
            "new_ver": m.group(2),
            "old_ver": m.group(3),
        })
    return pkgs

# ── Snapshot ─────────────────────────────────────────────────────────────────
def _snapshot() -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"/tmp/safe_upgrade_snapshot_{ts}.json"
    rc, out, _ = _run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], timeout=30)
    pkgs = {}
    for line in out.splitlines():
        parts = line.split("\t", 1)
        if len(parts) == 2:
            pkgs[parts[0]] = parts[1]
    with open(path, "w") as f:
        json.dump({"timestamp": ts, "packages": pkgs}, f)
    return path

# ── OS detection ─────────────────────────────────────────────────────────────
def _detect_os() -> str:
    try:
        lines = Path("/etc/os-release").read_text().splitlines()
        kv = {}
        for line in lines:
            if "=" in line:
                k, v = line.split("=", 1)
                kv[k] = v.strip('"')
        return kv.get("PRETTY_NAME", "Unknown Linux")
    except Exception:
        return "Unknown Linux"

# ── Phases ───────────────────────────────────────────────────────────────────
def phase_preflight(args: argparse.Namespace) -> dict:
    _phase_hdr(0, "Pre-flight")
    if os.geteuid() != 0:
        _log("-", "Must run as root (use sudo)")
        sys.exit(1)
    if not _check_dpkg_lock():
        _log("-", "Another apt/dpkg process is running — cannot proceed")
        _log("", "Wait for it to finish or kill it, then retry.")
        sys.exit(2)
    os_name = _detect_os()
    _log("", f"OS:          {_BLD}{os_name}{_R}")
    active_methods: list[dict] = []
    all_critical_pkgs: set[str] = set()
    any_encrypted = False
    print(f"  {_DIM}{_ts()}{_R} Connectivity:", flush=True)
    for m in _CONN_METHODS:
        detected = m["detect"]()
        sym = f"{_G}✓{_R}" if detected else f"{_DIM}✗{_R}"
        print(f"    {sym} {m['name']}", flush=True)
        if detected:
            active_methods.append(m)
            all_critical_pkgs |= m["packages"]
            any_encrypted = True
    if any_encrypted:
        all_critical_pkgs |= _TLS_CRITICAL_EXACT
        all_critical_pkgs |= _NET_CRITICAL
    if not active_methods:
        _log("~", "No remote connectivity detected — critical tier will be empty")
    global _PROTECTED_PKGS, _ACTIVE_METHODS
    _PROTECTED_PKGS = set(all_critical_pkgs)
    _ACTIVE_METHODS = list(active_methods)
    snap = _snapshot()
    _log("", f"Snapshot:    {_DIM}{snap}{_R}")

    checkpoint = _load_checkpoint()
    if checkpoint:
        n_prev_fixed = len(checkpoint.get("fixed_packages", []))
        n_prev_failed = len(checkpoint.get("failed_packages", []))
        _log("~", f"Resume checkpoint found: {n_prev_fixed} previously fixed, "
             f"{n_prev_failed} previously failed (phase: {checkpoint.get('phase', '?')})")
    else:
        checkpoint = None

    return {
        "active_methods": active_methods,
        "critical_pkgs": all_critical_pkgs,
        "any_encrypted": any_encrypted,
        "args": args,
        "stats": {"upgraded": 0, "failed": 0, "skipped": 0},
        "failed_pkgs": [],
        "skipped_pkgs": [],
        "_checkpoint": checkpoint,
    }

def phase_repair(ctx: dict) -> None:
    _phase_hdr(1, "Repair")

    broken = _get_broken_packages()
    if broken:
        _log("~", f"{len(broken)} packages in bad state:")
        for name, st in sorted(broken.items()):
            _log("", f"  {_RD}{name}{_R} ({st})")
    else:
        _log("+", "No broken packages detected")

    _log("*", "Multi-pass dpkg --configure")
    remaining = _configure_with_progress(broken, max_passes=8) if broken else {}

    # dpkg --audit: find packages stuck mid-postinst/mid-prerm
    _log("*", "dpkg --audit")
    audit_entries = _dpkg_audit()
    if audit_entries:
        _log("~", f"{len(audit_entries)} packages in inconsistent state (dpkg audit)")
        audit_fixed = _fix_audit_packages(
            audit_entries, ctx.get("critical_pkgs", set()))
        if audit_fixed:
            _log("+", f"Fixed {audit_fixed}/{len(audit_entries)} audit entries")
    else:
        _log("+", "dpkg audit clean")

    _log("*", "apt-get install -f")
    rc, _, err = _apt(["install", "-f", "-y"], timeout=300)
    if rc == 0:
        _log("+", "apt fix-broken clean")
    else:
        _log("~", "apt install -f had issues")
        if err.strip():
            for line in err.strip().splitlines()[-3:]:
                _log("", f"  {_DIM}{line.strip()}{_R}")
        systemic = _check_systemic(err)
        if systemic:
            ctx["_repair_systemic"] = systemic
            _log("-", f"Systemic issue: {systemic}")

            # ── Escalate: try to fix the resolver ────────────────────────
            resolved = _escalate_resolver(ctx)
            if resolved:
                _log("+", "Resolver repaired by escalation")
            else:
                _log("-", "Resolver escalation failed — systemic issue persists")
                _log("~", "Upgrades will proceed but most will likely fail")

    if remaining:
        remaining = _get_broken_packages()
    if remaining:
        _log("*", f"{len(remaining)} packages still broken — escalating")
        still_bad = _deep_repair(remaining,
                                 protected=ctx.get("critical_pkgs", set()),
                                 active_methods=ctx.get("active_methods", []))
        if still_bad:
            _log("-", f"{len(still_bad)} packages UNRECOVERABLE:")
            for name in sorted(still_bad.keys()):
                _log("", f"  {_RD}{name}{_R}")
            _log("~", "Continuing — these may block related upgrades")
        else:
            _log("+", "All broken packages repaired")
    else:
        final = _get_broken_packages()
        if final:
            _log("~", f"{len(final)} packages still in bad state after repair")
        else:
            _log("+", "Package state clean")

    n_broken = len(_get_broken_packages())
    repair_issue = ctx.get("_repair_systemic")
    if n_broken:
        _log("", f"→ {n_broken} broken packages remain — refreshing package lists anyway")
    elif repair_issue:
        _log("", f"→ dpkg state is clean but apt resolver has issues — refreshing package lists")
    else:
        _log("", "→ Package state is clean — refreshing package lists")

def phase_update(ctx: dict) -> None:
    _phase_hdr(2, "Update")
    _log("*", "apt-get update")
    rc, _, err = _apt(["update", "-y"], timeout=300)
    if rc == 0:
        _log("+", "Package lists updated")
    else:
        _log("~", "apt-get update had errors — continuing with current lists")
        for line in (err or "").strip().splitlines()[-3:]:
            _log("", f"  {_DIM}{line.strip()}{_R}")
    _log("", "→ Package lists refreshed — scanning for upgradable packages")

def phase_inventory(ctx: dict) -> tuple[list[dict], list[dict], list[dict]]:
    _phase_hdr(3, "Inventory")
    pkgs = _get_upgradable(include_held=ctx["args"].include_held)
    normal, sensitive, critical = [], [], []
    for p in pkgs:
        tier = _classify(p["name"], ctx["critical_pkgs"])
        p["tier"] = tier
        if tier == "critical":
            critical.append(p)
        elif tier == "sensitive":
            sensitive.append(p)
        else:
            normal.append(p)
    total = len(pkgs)
    _log("", f"{_BLD}{total}{_R} packages upgradable")
    _log("", f"  Normal:    {_G}{len(normal)}{_R}")
    _log("", f"  Sensitive: {_Y}{len(sensitive)}{_R}")
    _log("", f"  Critical:  {_RD}{len(critical)}{_R}")
    if critical:
        names = ", ".join(p["name"] for p in critical)
        _log("", f"  {_DIM}Critical: {names}{_R}")
    if total == 0:
        _log("+", "System is up to date")
    return normal, sensitive, critical

def _phase_normal_individual(names: list[str], ctx: dict) -> None:
    """Install packages one at a time — used when batch installs fail but
    individual installs work (resolver can't coordinate mass upgrades)."""
    total = len(names)
    _phase_hdr(4, f"Normal ({total} packages, individual mode)")
    _log("~", "Batch installs trigger resolver conflicts — upgrading one at a time")
    _log("", f"  {_DIM}This is slower but avoids the batch coordination problem.{_R}")
    total_ok = 0
    total_fail = 0
    report_interval = max(25, total // 20)
    for i, pkg in enumerate(names):
        if _stopping:
            _log("~", f"Stopping — {total - i} packages remaining")
            ctx["stats"]["skipped"] += total - i
            break
        rc, _, err = _apt_install([pkg])
        if rc == 0:
            total_ok += 1
        else:
            total_fail += 1
            ctx["failed_pkgs"].append(pkg)
        done = i + 1
        if done % report_interval == 0 or done == total:
            pct = done * 100 // total
            _log("*", f"  Progress: {total_ok} upgraded, {total_fail} failed "
                 f"({done}/{total} — {pct}%)")
        # Every 100 packages, check if resolver cleared and switch to chunks
        if done == 100 and total_ok > 80 and total > 200:
            _log("*", "  Resolver looks healthy — testing batch mode…")
            test_batch = names[done:done + 10]
            if test_batch:
                rc_t, _, _ = _apt_install(test_batch)
                if rc_t == 0:
                    _log("+", "  Batch mode works now — switching back to chunks")
                    ctx["stats"]["upgraded"] += total_ok + len(test_batch)
                    ctx["stats"]["failed"] += total_fail
                    remaining = names[done + len(test_batch):]
                    if remaining:
                        _phase_normal_chunked(remaining, ctx, chunk_start_offset=done + len(test_batch))
                    return
    ctx["stats"]["upgraded"] += total_ok
    ctx["stats"]["failed"] += total_fail
    if total_ok == 0 and total_fail > 0:
        _log("-", f"WARNING: 0/{total} normal packages upgraded — all {total_fail} failed")
        _log("~", "Even individual installs are failing — check the errors above.")
    elif total_ok > 0:
        _log("+", f"Individual mode: {total_ok}/{total} upgraded, {total_fail} failed")

def _phase_normal_chunked(names: list[str], ctx: dict,
                           chunk_start_offset: int = 0) -> None:
    """Standard chunked upgrade — the original phase_normal logic."""
    chunk_size = ctx["args"].chunk_size
    n_chunks = math.ceil(len(names) / chunk_size)
    if chunk_start_offset == 0:
        repair_issue = ctx.get("_repair_systemic")
        if repair_issue:
            _log("~", f"WARNING: Phase 1 detected a systemic issue: {repair_issue}")
            _log("~", "Upgrades will likely fail — attempting first chunk as a test")
    total_ok = 0
    total_fail = 0
    for i in range(n_chunks):
        if _stopping:
            _log("~", "Stopping — skipping remaining chunks")
            ctx["stats"]["skipped"] += len(names) - (i * chunk_size)
            break
        chunk = names[i * chunk_size : (i + 1) * chunk_size]
        _log("*", f"Chunk {i+1}/{n_chunks} ({len(chunk)} packages)…")
        ok_pkgs, fail_pkgs = _upgrade_chunk(chunk)
        if fail_pkgs:
            _log("-", f"Chunk {i+1}: {len(ok_pkgs)} upgraded, {len(fail_pkgs)} failed")
            for fp in fail_pkgs:
                _log("-", f"  SKIP {fp}", indent=1)
                ctx["failed_pkgs"].append(fp)
            total_fail += len(fail_pkgs)
        else:
            _log("+", f"Chunk {i+1}: {len(ok_pkgs)}/{len(chunk)} upgraded")
        total_ok += len(ok_pkgs)
        if n_chunks > 1 and i < n_chunks - 1:
            _log("", f"  {_DIM}Progress: {total_ok} upgraded, {total_fail} failed, "
                 f"{n_chunks - i - 1} chunks remaining{_R}")
        if i == 0 and len(ok_pkgs) == 0 and len(fail_pkgs) == len(chunk) and n_chunks > 1:
            _log("~", f"First chunk entirely failed ({len(chunk)}/{len(chunk)}) — "
                 f"checking system health before continuing")
            # Probe a single package before giving up
            rc_single, _, err_single = _apt_install([fail_pkgs[0]])
            if rc_single == 0:
                _log("+", f"  {fail_pkgs[0]} installed individually — batch conflict only")
                _log("*", "  Switching to individual mode for remaining packages")
                ctx["stats"]["upgraded"] += 1
                ctx["stats"]["failed"] += len(fail_pkgs) - 1
                for fp in fail_pkgs[1:]:
                    ctx["failed_pkgs"].append(fp)
                remaining = names[(i + 1) * chunk_size:]
                if remaining:
                    _phase_normal_individual(remaining, ctx)
                return
            rc_test, _, err_test = _apt(["install", "-y", "--dry-run", fail_pkgs[0]], timeout=60)
            systemic = _check_systemic(err_test) if rc_test != 0 else None
            if systemic:
                _log("-", f"Systemic issue confirmed: {systemic}")
                _log("-", f"Skipping remaining {n_chunks - 1} chunks — fix the issue and re-run")
                for remaining_name in names[(i + 1) * chunk_size:]:
                    ctx["failed_pkgs"].append(remaining_name)
                total_fail += len(names) - (i + 1) * chunk_size
                break
    ctx["stats"]["upgraded"] += total_ok
    ctx["stats"]["failed"] += total_fail
    if total_ok == 0 and total_fail > 0:
        _log("-", f"WARNING: 0/{len(names)} normal packages upgraded — "
             f"all {total_fail} failed")
        _log("~", "This usually indicates a systemic issue (unmet deps, "
             "disk space, dpkg lock, network). Check the errors above.")

def phase_normal(pkgs: list[dict], ctx: dict) -> None:
    if not pkgs:
        return
    names = [p["name"] for p in pkgs]
    if ctx.get("_individual_mode"):
        _phase_normal_individual(names, ctx)
        return
    chunk_size = ctx["args"].chunk_size
    n_chunks = math.ceil(len(names) / chunk_size)
    _phase_hdr(4, f"Normal ({len(names)} packages, {n_chunks} chunks)")
    _phase_normal_chunked(names, ctx)

def phase_sensitive(pkgs: list[dict], ctx: dict) -> None:
    if not pkgs:
        return
    _phase_hdr(5, f"Sensitive ({len(pkgs)} packages)")
    repair_issue = ctx.get("_repair_systemic")
    if repair_issue:
        _log("-", f"WARNING: Phase 1 detected systemic issue: {repair_issue}")
        _log("-", f"Skipping {len(pkgs)} sensitive packages — resolve the issue first")
        for p in pkgs:
            ctx["stats"]["skipped"] += 1
            ctx["skipped_pkgs"].append(p["name"])
        return
    for p in pkgs:
        if _stopping:
            _log("~", "Stopping — skipping remaining sensitive packages")
            ctx["stats"]["skipped"] += 1
            ctx["skipped_pkgs"].append(p["name"])
            continue
        _log("*", f"Upgrading {p['name']} ({p['old_ver']} → {p['new_ver']})")
        ok, reason = _upgrade_single(p["name"])
        if ok:
            _log("+", f"{p['name']} upgraded")
            ctx["stats"]["upgraded"] += 1
        else:
            _log("-", f"{p['name']} FAILED — {reason}")
            ctx["stats"]["failed"] += 1
            ctx["failed_pkgs"].append(p["name"])

def phase_critical(pkgs: list[dict], ctx: dict) -> None:
    if not pkgs:
        return
    _phase_hdr(6, f"Critical ({len(pkgs)} packages)")
    repair_issue = ctx.get("_repair_systemic")
    if repair_issue:
        _log("-", f"WARNING: Phase 1 detected systemic issue: {repair_issue}")
        _log("-", f"Skipping {len(pkgs)} critical packages — resolve the issue first")
        for p in pkgs:
            ctx["stats"]["skipped"] += 1
            ctx["skipped_pkgs"].append(p["name"])
        return
    active = ctx["active_methods"]
    for p in pkgs:
        if _stopping:
            _log("~", "Stopping — skipping remaining critical packages")
            ctx["stats"]["skipped"] += 1
            ctx["skipped_pkgs"].append(p["name"])
            continue
        conn_status = _verify_all_conn(active)
        pre_ok = all(c["ok"] for c in conn_status)
        status_str = "  ".join(
            f"{_G}✓{_R} {c['name']}" if c["ok"] else f"{_RD}✗{_R} {c['name']}"
            for c in conn_status
        )
        _log("*", f"Pre-check: {status_str}")
        if not pre_ok:
            _log("~", f"SKIP {p['name']} — connectivity already degraded")
            ctx["stats"]["skipped"] += 1
            ctx["skipped_pkgs"].append(p["name"])
            continue
        _log("*", f"Upgrading {p['name']} ({p['old_ver']} → {p['new_ver']})")
        ok, reason = _upgrade_single(p["name"])
        if ok:
            _log("+", f"{p['name']} upgraded")
            ctx["stats"]["upgraded"] += 1
        else:
            _log("-", f"{p['name']} FAILED — {reason}")
            _log("~", f"  Attempting connectivity recovery…")
            ctx["stats"]["failed"] += 1
            ctx["failed_pkgs"].append(p["name"])
        time.sleep(2)
        post_status = _verify_all_conn(active)
        post_ok = all(c["ok"] for c in post_status)
        post_str = "  ".join(
            f"{_G}✓{_R} {c['name']}" if c["ok"] else f"{_RD}✗{_R} {c['name']}"
            for c in post_status
        )
        _log("*", f"Post-check: {post_str}")
        if not post_ok:
            _log("-", f"{_RD}CONNECTIVITY DEGRADED{_R} after upgrading {p['name']}")
            for m in active:
                if not m["verify"]():
                    _log("*", f"Restarting {m['name']}…")
                    if _restart_services(m):
                        _log("+", f"{m['name']} recovered")
                    else:
                        _log("-", f"{_RD}{m['name']} STILL DOWN{_R}")

def phase_cleanup(ctx: dict) -> None:
    if ctx["args"].no_cleanup:
        return
    _phase_hdr(7, "Cleanup")
    _log("*", "Checking autoremove candidates…")
    rc, out, _ = _apt(["autoremove", "--dry-run"], timeout=120)
    removable: list[str] = []
    for line in out.splitlines():
        m = re.match(r'^Remv\s+(\S+)', line)
        if m:
            removable.append(m.group(1))
    crit_remove = [p for p in removable if p in ctx["critical_pkgs"]]
    sens_remove = [p for p in removable if _classify(p, set()) == "sensitive"]
    if crit_remove or sens_remove:
        _log("~", f"Autoremove would remove critical/sensitive packages — SKIPPING")
        for p in crit_remove + sens_remove:
            _log("", f"  {_RD}{p}{_R}")
    elif removable:
        _log("*", f"Removing {len(removable)} orphaned packages")
        rc, _, _ = _apt(["autoremove", "-y"], timeout=300)
        if rc == 0:
            _log("+", f"Removed {len(removable)} packages")
        else:
            _log("~", "autoremove had issues")
    else:
        _log("+", "No orphaned packages")
    _log("*", "apt-get clean")
    _apt(["clean"], timeout=60)
    _log("+", "Package cache cleared")

# ── Summary ──────────────────────────────────────────────────────────────────
def _print_summary(ctx: dict, t0: float) -> None:
    elapsed = time.time() - t0
    mins = int(elapsed) // 60
    secs = int(elapsed) % 60
    stats = ctx["stats"]
    print(flush=True)
    print(f"{_BLD}═══════════════════════════════════════════════════{_R}", flush=True)
    print(f"  {_BLD}Summary{_R}", flush=True)
    print(f"{_BLD}═══════════════════════════════════════════════════{_R}", flush=True)
    print(f"  Upgraded:  {_G}{stats['upgraded']}{_R}", flush=True)
    print(f"  Failed:    {_RD}{stats['failed']}{_R}", flush=True)
    print(f"  Skipped:   {_Y}{stats['skipped']}{_R}", flush=True)
    print(f"  Duration:  {mins}m {secs:02d}s", flush=True)
    if ctx["failed_pkgs"]:
        print(f"\n  {_RD}Failed packages:{_R}", flush=True)
        for p in ctx["failed_pkgs"]:
            print(f"    {_RD}•{_R} {p}", flush=True)
    if ctx["skipped_pkgs"]:
        print(f"\n  {_Y}Skipped packages:{_R}", flush=True)
        for p in ctx["skipped_pkgs"]:
            print(f"    {_Y}•{_R} {p}", flush=True)
    if ctx["active_methods"]:
        results = _verify_all_conn(ctx["active_methods"])
        line = "  ".join(
            f"{_G}✓{_R} {c['name']}" if c["ok"] else f"{_RD}✗{_R} {c['name']}"
            for c in results
        )
        print(f"\n  Connectivity: {line}", flush=True)
    print(f"{_BLD}═══════════════════════════════════════════════════{_R}", flush=True)

# ── Signal handling ──────────────────────────────────────────────────────────
def _on_signal(signum, frame):
    global _stopping
    _stopping = True
    _log("~", "\nInterrupt received — finishing current operation and cleaning up…")

# ── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Safe tiered system upgrade with connectivity protection")
    parser.add_argument("--dry-run", action="store_true",
                        help="Analyze only — don't upgrade anything")
    parser.add_argument("--chunk-size", type=int, default=25,
                        help="Packages per normal-tier chunk (default 25)")
    parser.add_argument("--skip-critical", action="store_true",
                        help="Don't upgrade connectivity-critical packages")
    parser.add_argument("--skip-sensitive", action="store_true",
                        help="Don't upgrade system-core packages")
    parser.add_argument("--no-cleanup", action="store_true",
                        help="Skip apt autoremove and clean")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI color output")
    parser.add_argument("--repair-only", action="store_true",
                        help="Only repair broken package state")
    parser.add_argument("--include-held", action="store_true",
                        help="Include held packages in upgrade")
    args = parser.parse_args()

    use_color = not args.no_color and sys.stdout.isatty()
    _init_color(use_color)
    _init_env()

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"\n{_BLD}═══════════════════════════════════════════════════{_R}", flush=True)
    print(f"  {_BLD}Safe Upgrade{_R} v{VERSION} — {now}", flush=True)
    if args.dry_run:
        print(f"  {_Y}DRY RUN — no changes will be made{_R}", flush=True)
    print(f"{_BLD}═══════════════════════════════════════════════════{_R}", flush=True)

    t0 = time.time()

    ctx = phase_preflight(args)

    phase_repair(ctx)
    if args.repair_only:
        _log("+", "Repair complete — exiting (--repair-only)")
        return

    phase_update(ctx)
    normal, sensitive, critical = phase_inventory(ctx)

    if args.dry_run:
        print(f"\n  {_Y}Dry run complete — no packages were upgraded.{_R}", flush=True)
        return

    total = len(normal) + len(sensitive) + len(critical)
    if total == 0:
        return

    chunk_size = args.chunk_size
    n_chunks = math.ceil(len(normal) / chunk_size) if normal else 0
    if normal:
        _log("", f"→ {total} upgradable — starting with {len(normal)} normal packages in {n_chunks} chunks")
    elif sensitive:
        _log("", f"→ {total} upgradable — no normal packages, starting with {len(sensitive)} sensitive")
    else:
        _log("", f"→ {total} upgradable — all critical, proceeding with connectivity checks")

    if not _stopping and normal:
        _log("", f"  {_DIM}Normal packages are low-risk libraries, utilities, and tools that can be")
        _log("", f"  upgraded in parallel batches without connectivity checks.{_R}")
        phase_normal(normal, ctx)

    if not _stopping and normal:
        s = ctx["stats"]
        if sensitive:
            _log("", f"→ Normal tier done ({s['upgraded']} upgraded, {s['failed']} failed) — moving to {len(sensitive)} sensitive packages")
        elif critical:
            _log("", f"→ Normal tier done ({s['upgraded']} upgraded, {s['failed']} failed) — moving to {len(critical)} critical packages")
        else:
            _log("", f"→ Normal tier done ({s['upgraded']} upgraded, {s['failed']} failed)")

    if not _stopping and not args.skip_sensitive:
        if sensitive:
            _log("", f"  {_DIM}Sensitive packages touch system-core components (kernel, libc, systemd).")
            _log("", f"  Upgrading one at a time with dependency resolution.{_R}")
        phase_sensitive(sensitive, ctx)
    elif args.skip_sensitive and sensitive:
        _log("~", f"Skipping {len(sensitive)} sensitive packages (--skip-sensitive)")
        ctx["stats"]["skipped"] += len(sensitive)

    if not _stopping and sensitive and critical:
        _log("", f"→ Sensitive tier done — moving to {len(critical)} critical packages with connectivity checks")

    if not _stopping and not args.skip_critical:
        if critical:
            _log("", f"  {_DIM}Critical packages manage network connectivity (SSH, VPN, firewall).")
            _log("", f"  Each upgrade is bracketed by connectivity checks — will stop if connection drops.{_R}")
        phase_critical(critical, ctx)
    elif args.skip_critical and critical:
        _log("~", f"Skipping {len(critical)} critical packages (--skip-critical)")
        ctx["stats"]["skipped"] += len(critical)

    if not _stopping and critical and ctx["active_methods"]:
        post = _verify_all_conn(ctx["active_methods"])
        conn_str = "  ".join(
            f"{_G}✓{_R} {c['name']}" if c["ok"] else f"{_RD}✗{_R} {c['name']}"
            for c in post
        )
        _log("", f"→ Critical tier done — connectivity: {conn_str}")

    if _stopping:
        _log("*", "Interrupted — running final repair pass")
        _repair_quick()

    if not _stopping:
        s = ctx["stats"]
        _log("", f"→ All upgrade tiers complete ({s['upgraded']} upgraded, {s['failed']} failed, {s['skipped']} skipped) — cleaning up")
        _log("", f"  {_DIM}Removing orphaned packages and clearing the apt cache.{_R}")
        phase_cleanup(ctx)
        _clear_checkpoint()

    _print_summary(ctx, t0)


if __name__ == "__main__":
    main()
