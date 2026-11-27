"""Crucible API — Credential management routes.

Blueprint: /api/credentials/<project_id>
Provides CRUD for credential vaults and credentials, bulk import,
spray configuration, passphrase verification, and credential file generation.

Security:
- Master passphrase NEVER stored on disk
- Secrets NEVER returned to the UI (always masked)
- Credential files written as 0600 to /tmp/
- Full audit trail for every operation
"""

import base64
import json
import logging
import os
import re
import tempfile
import threading
from datetime import datetime
from pathlib import Path

from flask import Blueprint, request, jsonify, session

from routes._helpers import require_project, get_ext
from services.utils import now_iso as _now_iso

log = logging.getLogger("crucible.credentials")

credentials_bp = Blueprint("credentials", __name__, url_prefix="/api/credentials")

# ── Validation constants ──────────────────────────────────────────────────

_VALID_CRED_TYPES = {"password", "ntlm_hash", "ssh_key", "kerberos_ticket"}
_VALID_SOURCES = {
    "user_provided", "captured_hydra", "captured_responder",
    "captured_plaintext", "captured_default", "captured_dredge",
    "captured_secretsdump", "captured_kerberoast",
}
_VALID_OS_TAGS = {
    "windows", "redhat", "ubuntu", "linux_other",
    "macos", "network_device",
}
_VALID_PROTOCOLS = {
    "smb", "ssh", "winrm", "rdp", "ldap", "ftp", "http",
    "mysql", "mssql", "postgresql", "vnc", "redis",
    "elasticsearch", "telnet", "ipmi", "kerberos",
}
_VALID_ADDED_BY = {
    "wizard", "settings", "cred_tab", "ss3", "dredge",
    "api", "import", "tool_capture",
}

_SPRAY_DEFAULTS = {
    "enabled": True,
    "cross_protocol": True,
    "protocols": {
        "ssh":    {"max_attempts": 3, "delay_seconds": 2,  "lockout_window": 300},
        "smb":    {"max_attempts": 5, "delay_seconds": 30, "lockout_window": 1800},
        "rdp":    {"max_attempts": 3, "delay_seconds": 30, "lockout_window": 1800},
        "winrm":  {"max_attempts": 3, "delay_seconds": 30, "lockout_window": 1800},
        "ftp":    {"max_attempts": 5, "delay_seconds": 1,  "lockout_window": 60},
        "http":   {"max_attempts": 10, "delay_seconds": 1, "lockout_window": 60},
        "vnc":    {"max_attempts": 5, "delay_seconds": 2,  "lockout_window": 300},
        "mysql":  {"max_attempts": 5, "delay_seconds": 2,  "lockout_window": 300},
        "mssql":  {"max_attempts": 5, "delay_seconds": 2,  "lockout_window": 300},
        "postgresql": {"max_attempts": 5, "delay_seconds": 2, "lockout_window": 300},
        "telnet": {"max_attempts": 3, "delay_seconds": 2,  "lockout_window": 300},
        "ipmi":   {"max_attempts": 5, "delay_seconds": 1,  "lockout_window": 60},
    },
}

# ── In-memory vault key cache ─────────────────────────────────────────────
# Maps project_id -> CredentialCrypto instance
# Cleared on shutdown or manual lock

_vault_cache = {}
_vault_lock = threading.Lock()


def _get_crypto(project_id):
    """Get the cached CredentialCrypto for a project, or None if locked."""
    with _vault_lock:
        return _vault_cache.get(project_id)


def _set_crypto(project_id, crypto):
    """Cache a CredentialCrypto instance for a project."""
    with _vault_lock:
        _vault_cache[project_id] = crypto


def _clear_crypto(project_id):
    """Clear and zero the cached crypto for a project."""
    with _vault_lock:
        crypto = _vault_cache.pop(project_id, None)
        if crypto:
            crypto.clear()


def clear_all_vaults():
    """Clear all cached vaults. Called on shutdown."""
    with _vault_lock:
        for crypto in _vault_cache.values():
            try:
                crypto.clear()
            except Exception:
                pass
        _vault_cache.clear()


def _require_unlocked(project_id):
    """Check if the vault is unlocked. Returns (crypto, error_response) tuple."""
    crypto = _get_crypto(project_id)
    if crypto is None:
        return None, (jsonify({"error": "Vault is locked. Unlock with passphrase first."}), 423)
    return crypto, None


def _require_session():
    """Require an authenticated web session."""
    if not session.get("authenticated"):
        return jsonify({"error": "Authentication required"}), 401
    import _auth
    if not _auth._validate_session_token(session.get("session_token")):
        return jsonify({"error": "Session expired"}), 401
    return None


# ═══════════════════════════════════════════════════════════════════════════
#  Vault Management
# ═══════════════════════════════════════════════════════════════════════════


@credentials_bp.route("/<project_id>/vault/create", methods=["POST"])
def vault_create(project_id):
    """Create a new credential vault with a master passphrase."""
    auth_err = _require_session()
    if auth_err:
        return auth_err

    project = require_project(project_id)
    project_dir = project.get("project_dir", "")
    if not project_dir:
        return jsonify({"error": "No project directory"}), 400

    body = request.get_json(silent=True) or {}
    passphrase = body.get("passphrase", "")
    if not passphrase or not isinstance(passphrase, str):
        return jsonify({"error": "Master passphrase is required"}), 400
    if len(passphrase) < 8:
        return jsonify({"error": "Master passphrase must be at least 8 characters"}), 400

    from models.credentials import get_vault, create_vault
    existing = get_vault(project_dir)
    if existing:
        return jsonify({"error": "Vault already exists for this project"}), 409

    from credential_crypto import CredentialCrypto
    crypto = CredentialCrypto(passphrase)
    verify = crypto.generate_verification()

    vault_id = create_vault(project_dir, crypto.salt, verify)
    _set_crypto(project_id, crypto)

    log.info("Vault created for project %s (vault_id=%d)", project_id, vault_id)
    return jsonify({"vault_id": vault_id, "status": "created"}), 201


@credentials_bp.route("/<project_id>/vault/unlock", methods=["POST"])
def vault_unlock(project_id):
    """Unlock a vault with the master passphrase."""
    auth_err = _require_session()
    if auth_err:
        return auth_err

    project = require_project(project_id)
    project_dir = project.get("project_dir", "")
    if not project_dir:
        return jsonify({"error": "No project directory"}), 400

    body = request.get_json(silent=True) or {}
    passphrase = body.get("passphrase", "")
    if not passphrase:
        return jsonify({"error": "Passphrase is required"}), 400

    from models.credentials import get_vault, update_vault_access
    vault = get_vault(project_dir)
    if not vault:
        return jsonify({"error": "No vault exists for this project"}), 404

    from credential_crypto import CredentialCrypto
    crypto = CredentialCrypto(passphrase, salt=vault["master_salt"])
    if not crypto.verify_passphrase(vault["master_verify"]):
        crypto.clear()
        log.warning("Failed vault unlock attempt for project %s", project_id)
        return jsonify({"error": "Invalid passphrase"}), 401

    _set_crypto(project_id, crypto)
    update_vault_access(project_dir)

    log.info("Vault unlocked for project %s", project_id)
    return jsonify({"status": "unlocked"}), 200


@credentials_bp.route("/<project_id>/vault/lock", methods=["POST"])
def vault_lock(project_id):
    """Lock the vault — clear the key from memory."""
    auth_err = _require_session()
    if auth_err:
        return auth_err

    _clear_crypto(project_id)
    log.info("Vault locked for project %s", project_id)
    return jsonify({"status": "locked"}), 200


@credentials_bp.route("/<project_id>/vault/status", methods=["GET"])
def vault_status(project_id):
    """Check if a vault exists and whether it is unlocked."""
    auth_err = _require_session()
    if auth_err:
        return auth_err

    project = require_project(project_id)
    project_dir = project.get("project_dir", "")

    from models.credentials import get_vault, count_credentials
    vault = get_vault(project_dir) if project_dir else None
    unlocked = _get_crypto(project_id) is not None

    result = {
        "exists": vault is not None,
        "unlocked": unlocked,
        "credential_count": count_credentials(project_dir) if project_dir else 0,
    }
    if vault:
        result["created"] = vault.get("created", "")
        result["last_accessed"] = vault.get("last_accessed", "")
    return jsonify(result), 200


# ═══════════════════════════════════════════════════════════════════════════
#  Credential CRUD
# ═══════════════════════════════════════════════════════════════════════════


@credentials_bp.route("/<project_id>", methods=["GET"])
def list_creds(project_id):
    """List credentials (secrets always masked)."""
    auth_err = _require_session()
    if auth_err:
        return auth_err

    project = require_project(project_id)
    project_dir = project.get("project_dir", "")

    source_filter = request.args.get("source")
    cred_type_filter = request.args.get("cred_type")

    from models.credentials import list_credentials
    creds = list_credentials(project_dir,
                             source_filter=source_filter,
                             cred_type_filter=cred_type_filter)
    return jsonify({"credentials": creds}), 200


@credentials_bp.route("/<project_id>", methods=["POST"])
def add_cred(project_id):
    """Add a credential to the vault."""
    auth_err = _require_session()
    if auth_err:
        return auth_err

    project = require_project(project_id)
    project_dir = project.get("project_dir", "")

    crypto, err = _require_unlocked(project_id)
    if err:
        return err

    body = request.get_json(silent=True) or {}

    # Validate required fields
    cred_type = (body.get("cred_type") or "").strip().lower()
    if cred_type not in _VALID_CRED_TYPES:
        return jsonify({"error": f"cred_type must be one of: {', '.join(sorted(_VALID_CRED_TYPES))}"}), 400

    username = (body.get("username") or "").strip()
    if not username:
        return jsonify({"error": "username is required"}), 400
    if len(username) > 256:
        return jsonify({"error": "username too long (max 256)"}), 400

    secret = body.get("secret", "")
    if not secret or not isinstance(secret, str):
        return jsonify({"error": "secret is required"}), 400

    source = (body.get("source") or "user_provided").strip().lower()
    if source not in _VALID_SOURCES:
        source = "user_provided"

    # Optional fields
    domain = (body.get("domain") or "").strip() or None
    os_tag = (body.get("os_tag") or "").strip().lower() or None
    if os_tag and os_tag not in _VALID_OS_TAGS:
        os_tag = None

    target_ip = (body.get("target_ip") or "").strip() or None
    protocol = (body.get("protocol") or "").strip().lower() or None
    if protocol and protocol not in _VALID_PROTOCOLS:
        return jsonify({"error": f"protocol must be one of: {', '.join(sorted(_VALID_PROTOCOLS))}"}), 400

    notes = (body.get("notes") or "").strip() or None
    spray_eligible = 1 if body.get("spray_eligible", True) else 0
    added_by = (body.get("added_by") or "cred_tab").strip()
    if added_by not in _VALID_ADDED_BY:
        added_by = "cred_tab"

    # Encrypt the secret
    enc = crypto.encrypt(secret)

    from models.credentials import add_credential
    try:
        cred_id = add_credential(
            project_dir,
            source=source,
            cred_type=cred_type,
            username=username,
            secret_enc=enc["ciphertext"],
            secret_nonce=enc["nonce"],
            secret_tag=enc["tag"],
            domain=domain,
            os_tag=os_tag,
            target_ip=target_ip,
            protocol=protocol,
            added_by=added_by,
            notes=notes,
            spray_eligible=spray_eligible,
        )
    except Exception as exc:
        if "UNIQUE constraint" in str(exc):
            return jsonify({"error": "Duplicate credential (same user/domain/type/protocol/target)"}), 409
        log.exception("Failed to add credential for project %s", project_id)
        return jsonify({"error": "Failed to add credential"}), 500

    log.info("Credential added: id=%d project=%s user=%s type=%s",
             cred_id, project_id, username, cred_type)
    return jsonify({"id": cred_id, "status": "added"}), 201


@credentials_bp.route("/<project_id>/<int:cred_id>", methods=["PUT"])
def update_cred(project_id, cred_id):
    """Update a credential (re-encrypt if secret changes)."""
    auth_err = _require_session()
    if auth_err:
        return auth_err

    project = require_project(project_id)
    project_dir = project.get("project_dir", "")

    from models.credentials import get_credential, update_credential
    existing = get_credential(project_dir, cred_id)
    if not existing:
        return jsonify({"error": "Credential not found"}), 404

    body = request.get_json(silent=True) or {}
    updates = {}

    # Fields that can be updated without re-encryption
    for field in ("os_tag", "target_ip", "protocol", "domain",
                  "notes", "spray_eligible", "source"):
        if field in body:
            val = body[field]
            if field == "spray_eligible":
                updates[field] = 1 if val else 0
            elif field == "os_tag":
                val = (val or "").strip().lower() or None
                if val and val not in _VALID_OS_TAGS:
                    continue
                updates[field] = val
            elif field == "protocol":
                val = (val or "").strip().lower() or None
                if val and val not in _VALID_PROTOCOLS:
                    return jsonify({"error": f"Invalid protocol: {val}"}), 400
                updates[field] = val
            elif field == "source":
                val = (val or "").strip().lower()
                if val in _VALID_SOURCES:
                    updates[field] = val
            else:
                updates[field] = (val or "").strip() if isinstance(val, str) else val

    # If secret is being changed, re-encrypt
    if "secret" in body and body["secret"]:
        crypto, err = _require_unlocked(project_id)
        if err:
            return err
        enc = crypto.encrypt(body["secret"])
        updates["secret_enc"] = enc["ciphertext"]
        updates["secret_nonce"] = enc["nonce"]
        updates["secret_tag"] = enc["tag"]

    if "username" in body:
        username = (body["username"] or "").strip()
        if username:
            updates["username"] = username

    if not updates:
        return jsonify({"error": "No valid fields to update"}), 400

    ok = update_credential(project_dir, cred_id, **updates)
    if not ok:
        return jsonify({"error": "Update failed"}), 500

    log.info("Credential updated: id=%d project=%s", cred_id, project_id)
    return jsonify({"status": "updated"}), 200


@credentials_bp.route("/<project_id>/<int:cred_id>", methods=["DELETE"])
def delete_cred(project_id, cred_id):
    """Delete a credential."""
    auth_err = _require_session()
    if auth_err:
        return auth_err

    project = require_project(project_id)
    project_dir = project.get("project_dir", "")

    from models.credentials import delete_credential
    ok = delete_credential(project_dir, cred_id)
    if not ok:
        return jsonify({"error": "Credential not found"}), 404

    log.info("Credential deleted: id=%d project=%s", cred_id, project_id)
    return jsonify({"status": "deleted"}), 200


# ═══════════════════════════════════════════════════════════════════════════
#  Bulk Import
# ═══════════════════════════════════════════════════════════════════════════


@credentials_bp.route("/<project_id>/import", methods=["POST"])
def import_creds(project_id):
    """Import credentials from CSV or JSON file upload."""
    auth_err = _require_session()
    if auth_err:
        return auth_err

    project = require_project(project_id)
    project_dir = project.get("project_dir", "")

    crypto, err = _require_unlocked(project_id)
    if err:
        return err

    # Accept file upload or JSON body
    imported = 0
    errors = []

    if request.content_type and "multipart/form-data" in request.content_type:
        f = request.files.get("file")
        if not f:
            return jsonify({"error": "No file uploaded"}), 400

        filename = (f.filename or "").lower()
        content = f.read().decode("utf-8", errors="replace")

        if filename.endswith(".csv"):
            imported, errors = _import_csv(project_dir, crypto, content)
        elif filename.endswith(".json"):
            imported, errors = _import_json(project_dir, crypto, content)
        else:
            return jsonify({"error": "Unsupported file type. Use .csv or .json"}), 400
    else:
        body = request.get_json(silent=True) or {}
        creds = body.get("credentials", [])
        if not isinstance(creds, list):
            return jsonify({"error": "credentials must be a list"}), 400
        imported, errors = _import_list(project_dir, crypto, creds)

    log.info("Credential import: project=%s imported=%d errors=%d",
             project_id, imported, len(errors))
    return jsonify({
        "imported": imported,
        "errors": errors[:50],
    }), 200


def _import_csv(project_dir, crypto, content):
    """Parse CSV content and import credentials."""
    import csv
    import io

    reader = csv.DictReader(io.StringIO(content))
    imported = 0
    errors = []

    for i, row in enumerate(reader):
        try:
            result = _import_single(project_dir, crypto, {
                "username": row.get("username", ""),
                "secret": row.get("secret") or row.get("password") or row.get("hash", ""),
                "cred_type": row.get("cred_type") or row.get("type", "password"),
                "domain": row.get("domain", ""),
                "os_tag": row.get("os_tag", ""),
                "target_ip": row.get("target_ip") or row.get("ip", ""),
                "protocol": row.get("protocol", ""),
                "notes": row.get("notes", ""),
                "spray_eligible": row.get("spray_eligible", "true").lower() in ("true", "1", "yes"),
            })
            if result:
                imported += 1
            else:
                errors.append(f"Row {i+1}: duplicate or invalid")
        except Exception as exc:
            errors.append(f"Row {i+1}: {exc}")

    return imported, errors


def _import_json(project_dir, crypto, content):
    """Parse JSON content and import credentials."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        return 0, [f"Invalid JSON: {exc}"]

    creds = data if isinstance(data, list) else data.get("credentials", [])
    if not isinstance(creds, list):
        return 0, ["Expected a list of credentials"]

    return _import_list(project_dir, crypto, creds)


def _import_list(project_dir, crypto, creds):
    """Import a list of credential dicts."""
    imported = 0
    errors = []

    for i, cred in enumerate(creds):
        if not isinstance(cred, dict):
            errors.append(f"Item {i}: not a dict")
            continue
        try:
            result = _import_single(project_dir, crypto, cred)
            if result:
                imported += 1
            else:
                errors.append(f"Item {i}: duplicate or invalid")
        except Exception as exc:
            errors.append(f"Item {i}: {exc}")

    return imported, errors


def _import_single(project_dir, crypto, cred):
    """Import a single credential. Returns cred_id or None."""
    username = (cred.get("username") or "").strip()
    secret = cred.get("secret") or cred.get("password") or cred.get("hash", "")
    if not username or not secret:
        return None

    cred_type = (cred.get("cred_type") or cred.get("type") or "password").strip().lower()
    if cred_type not in _VALID_CRED_TYPES:
        cred_type = "password"

    enc = crypto.encrypt(str(secret))

    from models.credentials import add_credential
    try:
        cred_id = add_credential(
            project_dir,
            source="user_provided",
            cred_type=cred_type,
            username=username,
            secret_enc=enc["ciphertext"],
            secret_nonce=enc["nonce"],
            secret_tag=enc["tag"],
            domain=(cred.get("domain") or "").strip() or None,
            os_tag=(cred.get("os_tag") or "").strip().lower() or None,
            target_ip=(cred.get("target_ip") or cred.get("ip") or "").strip() or None,
            protocol=(cred.get("protocol") or "").strip().lower() or None,
            added_by="import",
            notes=(cred.get("notes") or "").strip() or None,
            spray_eligible=1 if cred.get("spray_eligible", True) else 0,
        )
        return cred_id
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════
#  Credential File Generation
# ═══════════════════════════════════════════════════════════════════════════


@credentials_bp.route("/<project_id>/generate-cred-file", methods=["POST"])
def generate_cred_file(project_id):
    """Generate an encrypted credential file for tools (SS3, etc.).

    Returns the file path and the env var name for the decryption key.
    The file is written as 0600 to /tmp/.
    """
    auth_err = _require_session()
    if auth_err:
        return auth_err

    project = require_project(project_id)
    project_dir = project.get("project_dir", "")

    crypto, err = _require_unlocked(project_id)
    if err:
        return err

    from models.credentials import list_credentials_raw
    creds = list_credentials_raw(project_dir)
    if not creds:
        return jsonify({"error": "No credentials in vault"}), 404

    output_path = f"/tmp/ss3_creds_{project_id}.json"

    # Build the credential file
    cred_file_data = {
        "schema_version": "1.0",
        "engagement_id": project_id,
        "created": _now_iso(),
        "encryption": {
            "algorithm": "AES-256-GCM",
            "kdf": "argon2id",
            "note": "secret_enc fields are base64-encoded ciphertext; "
                    "decrypt with SS3_CRED_KEY env var",
        },
        "global_credentials": [],
        "per_host_overrides": {},
    }

    for c in creds:
        entry = {
            "id": c["id"],
            "cred_type": c["cred_type"],
            "os_tag": c.get("os_tag"),
            "username": c["username"],
            "secret_enc": base64.b64encode(c["secret_enc"]).decode() if isinstance(c["secret_enc"], bytes) else c["secret_enc"],
            "secret_nonce": base64.b64encode(c["secret_nonce"]).decode() if isinstance(c["secret_nonce"], bytes) else c["secret_nonce"],
            "secret_tag": base64.b64encode(c["secret_tag"]).decode() if isinstance(c["secret_tag"], bytes) else c["secret_tag"],
            "domain": c.get("domain"),
            "protocol": c.get("protocol"),
            "source": c["source"],
            "spray_eligible": bool(c.get("spray_eligible", 0)),
        }

        target_ip = c.get("target_ip")
        if target_ip:
            if target_ip not in cred_file_data["per_host_overrides"]:
                cred_file_data["per_host_overrides"][target_ip] = []
            cred_file_data["per_host_overrides"][target_ip].append(entry)
        else:
            cred_file_data["global_credentials"].append(entry)

    # Write file with restrictive permissions
    fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(cred_file_data, f, indent=2)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise

    log.info("Credential file generated: %s (project=%s, creds=%d)",
             output_path, project_id, len(creds))

    return jsonify({
        "file_path": output_path,
        "cred_count": len(creds),
        "env_var": "SS3_CRED_KEY",
        "key_b64": crypto.key_b64,
    }), 200


# ═══════════════════════════════════════════════════════════════════════════
#  Spray Configuration
# ═══════════════════════════════════════════════════════════════════════════


@credentials_bp.route("/<project_id>/spray-config", methods=["GET"])
def get_spray_config(project_id):
    """Get spray thresholds for this project."""
    auth_err = _require_session()
    if auth_err:
        return auth_err

    project = require_project(project_id)
    project_dir = project.get("project_dir", "")

    config = _load_spray_config(project_dir)
    return jsonify(config), 200


@credentials_bp.route("/<project_id>/spray-config", methods=["PUT"])
def set_spray_config(project_id):
    """Update spray thresholds for this project."""
    auth_err = _require_session()
    if auth_err:
        return auth_err

    project = require_project(project_id)
    project_dir = project.get("project_dir", "")

    body = request.get_json(silent=True) or {}

    config = _load_spray_config(project_dir)

    if "enabled" in body:
        config["enabled"] = bool(body["enabled"])
    if "cross_protocol" in body:
        config["cross_protocol"] = bool(body["cross_protocol"])
    if "protocols" in body and isinstance(body["protocols"], dict):
        for proto, settings in body["protocols"].items():
            if proto in config["protocols"] and isinstance(settings, dict):
                for key in ("max_attempts", "delay_seconds", "lockout_window"):
                    if key in settings:
                        val = settings[key]
                        if isinstance(val, (int, float)) and val >= 0:
                            config["protocols"][proto][key] = int(val)

    _save_spray_config(project_dir, config)
    log.info("Spray config updated for project %s", project_id)
    return jsonify(config), 200


def _load_spray_config(project_dir):
    """Load spray config from project dir, or return defaults."""
    config_path = Path(project_dir) / "spray_config.json"
    if config_path.exists():
        try:
            return json.loads(config_path.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return dict(_SPRAY_DEFAULTS)


def _save_spray_config(project_dir, config):
    """Save spray config to project dir."""
    config_path = Path(project_dir) / "spray_config.json"
    try:
        config_path.write_text(json.dumps(config, indent=2))
    except OSError as exc:
        log.error("Failed to save spray config: %s", exc)


# ═══════════════════════════════════════════════════════════════════════════
#  Passphrase Verification
# ═══════════════════════════════════════════════════════════════════════════


@credentials_bp.route("/<project_id>/passphrase/verify", methods=["POST"])
def verify_passphrase(project_id):
    """Verify the master passphrase without unlocking."""
    auth_err = _require_session()
    if auth_err:
        return auth_err

    project = require_project(project_id)
    project_dir = project.get("project_dir", "")

    body = request.get_json(silent=True) or {}
    passphrase = body.get("passphrase", "")
    if not passphrase:
        return jsonify({"error": "Passphrase is required"}), 400

    from models.credentials import get_vault
    vault = get_vault(project_dir)
    if not vault:
        return jsonify({"error": "No vault exists"}), 404

    from credential_crypto import CredentialCrypto
    crypto = CredentialCrypto(passphrase, salt=vault["master_salt"])
    valid = crypto.verify_passphrase(vault["master_verify"])
    crypto.clear()

    return jsonify({"valid": valid}), 200


# ═══════════════════════════════════════════════════════════════════════════
#  Credential Capture from Tools
# ═══════════════════════════════════════════════════════════════════════════


@credentials_bp.route("/<project_id>/from-capture", methods=["POST"])
def from_capture(project_id):
    """Ingest a captured credential from a managed tool.

    Called by the token parser when __CRUCIBLE_CREDENTIAL__ is received,
    or by tools directly via the API.
    """
    auth_err = _require_session()
    if auth_err:
        return auth_err

    project = require_project(project_id)
    project_dir = project.get("project_dir", "")

    crypto, err = _require_unlocked(project_id)
    if err:
        return err

    body = request.get_json(silent=True) or {}

    username = (body.get("username") or "").strip()
    secret = body.get("secret", "")
    if not username or not secret:
        return jsonify({"error": "username and secret are required"}), 400

    source = (body.get("source") or "captured_plaintext").strip().lower()
    if source not in _VALID_SOURCES:
        source = "captured_plaintext"
    if source == "user_provided":
        source = "captured_plaintext"

    cred_type = (body.get("cred_type") or "password").strip().lower()
    if cred_type not in _VALID_CRED_TYPES:
        cred_type = "password"

    enc = crypto.encrypt(str(secret))

    from models.credentials import add_credential
    try:
        cred_id = add_credential(
            project_dir,
            source=source,
            cred_type=cred_type,
            username=username,
            secret_enc=enc["ciphertext"],
            secret_nonce=enc["nonce"],
            secret_tag=enc["tag"],
            domain=(body.get("domain") or "").strip() or None,
            os_tag=(body.get("os_tag") or "").strip().lower() or None,
            target_ip=(body.get("captured_from_ip") or body.get("target_ip") or "").strip() or None,
            protocol=(body.get("protocol") or "").strip().lower() or None,
            added_by="tool_capture",
            notes=(body.get("notes") or "").strip() or None,
            spray_eligible=1 if body.get("spray_eligible", True) else 0,
        )
    except Exception as exc:
        if "UNIQUE constraint" in str(exc):
            return jsonify({"status": "duplicate", "message": "Credential already exists"}), 200
        log.exception("Failed to ingest captured credential for project %s", project_id)
        return jsonify({"error": "Failed to ingest credential"}), 500

    # Emit socket event for real-time UI update
    sio = get_ext("socketio")
    if sio:
        from services.utils import project_room as _room
        sio.emit("new_credential", {
            "id": cred_id,
            "username": username,
            "cred_type": cred_type,
            "source": source,
            "captured_from_ip": body.get("captured_from_ip", ""),
            "ts": _now_iso(),
        }, room=_room(project_id))

    log.info("Captured credential ingested: id=%d project=%s user=%s source=%s",
             cred_id, project_id, username, source)
    return jsonify({"id": cred_id, "status": "captured"}), 201
