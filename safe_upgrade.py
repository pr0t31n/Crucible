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

VERSION = "1.2.0"

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
            return False
    except (subprocess.TimeoutExpired, Exception):
        return False
    import glob
    debs = sorted(glob.glob(f"{dl_dir}/{pkg}_*.deb"),
                  key=os.path.getmtime, reverse=True)
    if not debs:
        return False
    rc, _, _ = _dpkg(["-i", "--force-depends", debs[0]], timeout=120)
    try:
        os.unlink(debs[0])
    except OSError:
        pass
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

def _upgrade_chunk(pkgs: list[str], depth: int = 0,
                   chunk_label: str = "") -> tuple[list[str], list[str]]:
    if not pkgs or _stopping:
        return [], list(pkgs)
    rc, out, err = _apt_install(pkgs)
    if rc == 0:
        return list(pkgs), []
    if depth == 0 and len(pkgs) > 1:
        _log("~", f"{chunk_label}chunk failed as a group — splitting to isolate failures")
    _repair_quick()
    if len(pkgs) == 1:
        _log("-", f"  {pkgs[0]} cannot be upgraded (depth {depth})")
        return [], list(pkgs)
    if depth > 8:
        _log("-", f"  Giving up on {len(pkgs)} packages after 8 split retries")
        return [], list(pkgs)
    mid = len(pkgs) // 2
    lbl = f"{chunk_label}L{depth}/" if depth < 3 else ""
    rbll = f"{chunk_label}R{depth}/" if depth < 3 else ""
    if depth < 2:
        _log("*", f"  Split depth {depth}: trying {mid} left + {len(pkgs)-mid} right")
    ok_l, fail_l = _upgrade_chunk(pkgs[:mid], depth + 1, lbl)
    ok_r, fail_r = _upgrade_chunk(pkgs[mid:], depth + 1, rbll)
    return ok_l + ok_r, fail_l + fail_r

def _upgrade_single(pkg: str) -> bool:
    rc, out, err = _apt_install([pkg])
    if rc == 0:
        return True
    deps = _extract_deps_from_error(err)
    if deps:
        _log("*", f"  Resolving {len(deps)} deps for {pkg}…")
        ordered = _topo_sort_broken(deps)
        for dep in ordered:
            _dpkg(["--configure", dep], timeout=60)
    _repair_quick()
    rc, out, err = _apt_install([pkg])
    if rc == 0:
        return True
    _resolve_deps(pkg, protected=_PROTECTED_PKGS)
    rc, out, err = _apt_install([pkg])
    if rc == 0:
        return True
    _log("*", f"  Trying download + dpkg -i for {pkg}…")
    if _download_install(pkg):
        _dpkg(["--configure", pkg], timeout=60)
        return True
    return False

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
    return {
        "active_methods": active_methods,
        "critical_pkgs": all_critical_pkgs,
        "any_encrypted": any_encrypted,
        "args": args,
        "stats": {"upgraded": 0, "failed": 0, "skipped": 0},
        "failed_pkgs": [],
        "skipped_pkgs": [],
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

    _log("*", "apt-get install -f")
    rc, _, err = _apt(["install", "-f", "-y"], timeout=300)
    if rc == 0:
        _log("+", "apt fix-broken clean")
    else:
        _log("~", "apt install -f had issues")
        if err.strip():
            for line in err.strip().splitlines()[-3:]:
                _log("", f"  {_DIM}{line.strip()}{_R}")

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
    if n_broken:
        _log("", f"→ {n_broken} broken packages remain — refreshing package lists anyway")
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

def phase_normal(pkgs: list[dict], ctx: dict) -> None:
    if not pkgs:
        return
    chunk_size = ctx["args"].chunk_size
    names = [p["name"] for p in pkgs]
    n_chunks = math.ceil(len(names) / chunk_size)
    _phase_hdr(4, f"Normal ({len(names)} packages, {n_chunks} chunks)")
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
    ctx["stats"]["upgraded"] += total_ok
    ctx["stats"]["failed"] += total_fail

def phase_sensitive(pkgs: list[dict], ctx: dict) -> None:
    if not pkgs:
        return
    _phase_hdr(5, f"Sensitive ({len(pkgs)} packages)")
    for p in pkgs:
        if _stopping:
            _log("~", "Stopping — skipping remaining sensitive packages")
            ctx["stats"]["skipped"] += 1
            ctx["skipped_pkgs"].append(p["name"])
            continue
        _log("*", f"Upgrading {p['name']} ({p['old_ver']} → {p['new_ver']})")
        if _upgrade_single(p["name"]):
            _log("+", f"{p['name']} upgraded")
            ctx["stats"]["upgraded"] += 1
        else:
            _log("-", f"{p['name']} FAILED")
            ctx["stats"]["failed"] += 1
            ctx["failed_pkgs"].append(p["name"])

def phase_critical(pkgs: list[dict], ctx: dict) -> None:
    if not pkgs:
        return
    _phase_hdr(6, f"Critical ({len(pkgs)} packages)")
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
        if _upgrade_single(p["name"]):
            _log("+", f"{p['name']} upgraded")
            ctx["stats"]["upgraded"] += 1
        else:
            _log("-", f"{p['name']} FAILED — attempting recovery")
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

    if not _stopping:
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
        phase_sensitive(sensitive, ctx)
    elif args.skip_sensitive and sensitive:
        _log("~", f"Skipping {len(sensitive)} sensitive packages (--skip-sensitive)")
        ctx["stats"]["skipped"] += len(sensitive)

    if not _stopping and sensitive and critical:
        _log("", f"→ Sensitive tier done — moving to {len(critical)} critical packages with connectivity checks")

    if not _stopping and not args.skip_critical:
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
        phase_cleanup(ctx)

    _print_summary(ctx, t0)


if __name__ == "__main__":
    main()
