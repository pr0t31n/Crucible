"""Credential management service for Crucible.

Thread-safe, file-backed credential storage with optional AES-256-GCM
encryption (Argon2id KDF).  Degrades gracefully to plaintext storage
when the cryptography / argon2-cffi packages are not installed.
"""

import base64
import json
import logging
import os
import threading
import uuid

from services.utils import now_iso as _now_iso

log = logging.getLogger("crucible.services.credential_manager")

_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Optional crypto imports — degrade gracefully
# ---------------------------------------------------------------------------
_HAS_CRYPTO = False
_HAS_ARGON2 = False
_CRYPTO_WARN_LOGGED = False

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAS_CRYPTO = True
except ImportError:
    pass

try:
    import argon2
    _HAS_ARGON2 = True
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_CRED_FILE = "credentials.json"
_SENSITIVE_FIELDS = ("password", "hash", "key")
_ARGON2_TIME_COST = 3
_ARGON2_MEMORY_COST = 65536
_ARGON2_PARALLELISM = 4
_ARGON2_HASH_LEN = 32
_ARGON2_SALT_LEN = 16
_AES_KEY_LEN = 32  # 256-bit
_AES_NONCE_LEN = 12


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _store_path(proj_dir):
    return os.path.join(proj_dir, _CRED_FILE)


def _empty_store():
    return {
        "master_hash": None,
        "salt": None,
        "credentials": [],
        "schema_version": "1.0",
    }


def _load_store(proj_dir):
    path = _store_path(proj_dir)
    if not os.path.exists(path):
        return _empty_store()
    with open(path, "r") as fh:
        return json.load(fh)


def _save_store(proj_dir, store):
    path = _store_path(proj_dir)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(store, fh, indent=2)
    os.replace(tmp, path)


def _derive_key(passphrase, salt_bytes):
    """Derive a 256-bit AES key from *passphrase* using Argon2id."""
    if not _HAS_ARGON2:
        return None
    raw = argon2.low_level.hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt_bytes,
        time_cost=_ARGON2_TIME_COST,
        memory_cost=_ARGON2_MEMORY_COST,
        parallelism=_ARGON2_PARALLELISM,
        hash_len=_AES_KEY_LEN,
        type=argon2.low_level.Type.ID,
    )
    return raw


def _warn_no_crypto():
    global _CRYPTO_WARN_LOGGED
    if not _CRYPTO_WARN_LOGGED:
        log.warning(
            "cryptography and/or argon2-cffi not installed — "
            "credentials will be stored WITHOUT encryption"
        )
        _CRYPTO_WARN_LOGGED = True


def _encrypt_field(value, key):
    """Encrypt *value* with AES-256-GCM.  Returns a base64 string."""
    if not _HAS_CRYPTO or key is None:
        _warn_no_crypto()
        return value
    nonce = os.urandom(_AES_NONCE_LEN)
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, value.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode("ascii")


def _decrypt_field(b64_str, key):
    """Decrypt a base64 AES-256-GCM ciphertext.  Returns plaintext string."""
    if not _HAS_CRYPTO or key is None:
        return b64_str
    raw = base64.b64decode(b64_str)
    nonce = raw[:_AES_NONCE_LEN]
    ct = raw[_AES_NONCE_LEN:]
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, None).decode("utf-8")


def _get_salt(store):
    s = store.get("salt")
    if s is None:
        return None
    return base64.b64decode(s)


def _build_credential(data):
    cred = {
        "id": str(uuid.uuid4()),
        "username": data.get("username", ""),
        "password_encrypted": data.get("password", ""),
        "hash_encrypted": data.get("hash", ""),
        "hash_type": data.get("hash_type", ""),
        "domain": data.get("domain", ""),
        "host": data.get("host", ""),
        "port": data.get("port", 0),
        "protocol": data.get("protocol", ""),
        "source_tool": data.get("source_tool", ""),
        "source_finding_id": data.get("source_finding_id", ""),
        "verified": False,
        "verified_protocols": [],
        "captured_at": _now_iso(),
        "notes": data.get("notes", ""),
    }
    return cred


def _encrypt_sensitive(cred, key):
    for field in _SENSITIVE_FIELDS:
        enc_key = f"{field}_encrypted"
        if enc_key in cred and cred[enc_key]:
            cred[enc_key] = _encrypt_field(cred[enc_key], key)


def _decrypt_sensitive(cred, key):
    out = dict(cred)
    for field in _SENSITIVE_FIELDS:
        enc_key = f"{field}_encrypted"
        if enc_key in out and out[enc_key]:
            try:
                out[enc_key] = _decrypt_field(out[enc_key], key)
            except Exception:
                log.debug("Failed to decrypt field %s on credential %s",
                          enc_key, out.get("id", "?"))
    return out


def _find_cred(store, cred_id):
    for c in store["credentials"]:
        if c["id"] == cred_id:
            return c
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def store_credential(proj_dir, data):
    """Store a new credential.  Returns the credential dict (with id).

    Dual-writes to credentials.json (legacy) and credentials.db (new).
    """
    with _lock:
        store = _load_store(proj_dir)
        cred = _build_credential(data)

        salt_bytes = _get_salt(store)
        if store.get("master_hash") and salt_bytes and _HAS_CRYPTO and _HAS_ARGON2:
            # Master passphrase is set but we don't have the plaintext here.
            # Sensitive fields stay as-is; caller can re-encrypt via
            # update_credential with the passphrase later.
            pass
        elif not _HAS_CRYPTO or not _HAS_ARGON2:
            _warn_no_crypto()

        store["credentials"].append(cred)
        _save_store(proj_dir, store)

    # Dual-write to credentials.db if vault is unlocked
    _db_store_credential(proj_dir, data)

    return cred


def _db_store_credential(proj_dir, data):
    """Write a captured credential to credentials.db if the vault is unlocked."""
    username = (data.get("username") or "").strip()
    secret = data.get("secret") or data.get("password") or ""
    if not username or not secret:
        return

    try:
        from routes.credentials import _vault_cache, _vault_lock
        from models.project import list_projects
    except ImportError:
        return

    # Find project_id by directory
    crypto = None
    try:
        projects = list_projects()
        for proj in projects:
            pd = proj.get("project_dir") or proj.get("engagement_dir", "")
            if pd and str(pd).rstrip("/") == str(proj_dir).rstrip("/"):
                pid = proj.get("id")
                if pid:
                    with _vault_lock:
                        crypto = _vault_cache.get(pid)
                    break
    except Exception:
        return

    if crypto is None:
        return

    source = (data.get("source") or "captured_plaintext").strip().lower()
    if source == "user_provided":
        source = "captured_plaintext"

    cred_type = (data.get("cred_type") or "password").strip().lower()
    valid_types = {"password", "ntlm_hash", "ssh_key", "kerberos_ticket"}
    if cred_type not in valid_types:
        cred_type = "password"

    enc = crypto.encrypt(str(secret))

    try:
        from models.credentials import add_credential
        add_credential(
            proj_dir,
            source=source,
            cred_type=cred_type,
            username=username,
            secret_enc=enc["ciphertext"],
            secret_nonce=enc["nonce"],
            secret_tag=enc["tag"],
            domain=(data.get("domain") or "").strip() or None,
            os_tag=(data.get("os_tag") or "").strip().lower() or None,
            target_ip=(data.get("host") or data.get("captured_from_ip") or "").strip() or None,
            protocol=(data.get("protocol") or "").strip().lower() or None,
            added_by="tool_capture",
            spray_eligible=1,
        )
    except Exception as exc:
        log.debug("_db_store_credential: %s", exc)


def get_credentials(proj_dir, passphrase=None):
    """List all credentials.  Decrypt sensitive fields when *passphrase* given."""
    with _lock:
        store = _load_store(proj_dir)
        creds = list(store["credentials"])

    if passphrase is not None and _HAS_CRYPTO and _HAS_ARGON2:
        salt_bytes = _get_salt(store)
        if salt_bytes:
            key = _derive_key(passphrase, salt_bytes)
            return [_decrypt_sensitive(c, key) for c in creds]

    return creds


def get_credential(proj_dir, cred_id):
    """Return one credential by id (sensitive fields stay encrypted)."""
    with _lock:
        store = _load_store(proj_dir)
        cred = _find_cred(store, cred_id)
        if cred is None:
            return None
        return dict(cred)


def verify_credential(proj_dir, cred_id, protocol, host, port):
    """Mark a credential as verified for a protocol/host/port.

    Dual-writes to credentials.json (legacy) and credentials.db (new).
    """
    with _lock:
        store = _load_store(proj_dir)
        cred = _find_cred(store, cred_id)
        if cred is None:
            return None
        entry = {
            "protocol": protocol,
            "host": host,
            "port": port,
            "ts": _now_iso(),
        }
        if "verified_protocols" not in cred:
            cred["verified_protocols"] = []
        cred["verified_protocols"].append(entry)
        cred["verified"] = True
        _save_store(proj_dir, store)

    # Dual-write to credentials.db
    try:
        from models.credentials import update_verified as _db_verify
        _db_verify(proj_dir, int(cred_id), host or "", protocol or "",
                    "authenticated")
    except Exception:
        pass

    return dict(cred)


def delete_credential(proj_dir, cred_id):
    """Remove a credential.  Returns True if found and deleted."""
    with _lock:
        store = _load_store(proj_dir)
        before = len(store["credentials"])
        store["credentials"] = [
            c for c in store["credentials"] if c["id"] != cred_id
        ]
        if len(store["credentials"]) == before:
            return False
        _save_store(proj_dir, store)
        return True


def update_credential(proj_dir, cred_id, updates):
    """Update fields on a credential.  Returns the updated credential or None."""
    with _lock:
        store = _load_store(proj_dir)
        cred = _find_cred(store, cred_id)
        if cred is None:
            return None
        for k, v in updates.items():
            if k == "id":
                continue
            cred[k] = v
        _save_store(proj_dir, store)
        return dict(cred)


def decrypt_credential(proj_dir, cred_id, passphrase):
    """Decrypt and return one credential's sensitive fields."""
    with _lock:
        store = _load_store(proj_dir)
        cred = _find_cred(store, cred_id)
        if cred is None:
            return None

    if not _HAS_CRYPTO or not _HAS_ARGON2:
        return dict(cred)

    salt_bytes = _get_salt(store)
    if salt_bytes is None:
        return dict(cred)

    key = _derive_key(passphrase, salt_bytes)
    return _decrypt_sensitive(cred, key)


def set_master_passphrase(proj_dir, passphrase):
    """Set or change the master passphrase.  Stores an argon2id hash."""
    with _lock:
        store = _load_store(proj_dir)

        if not _HAS_ARGON2:
            log.warning("argon2-cffi not installed — cannot set master passphrase")
            return False

        salt = os.urandom(_ARGON2_SALT_LEN)
        ph = argon2.PasswordHasher(
            time_cost=_ARGON2_TIME_COST,
            memory_cost=_ARGON2_MEMORY_COST,
            parallelism=_ARGON2_PARALLELISM,
            hash_len=_ARGON2_HASH_LEN,
            type=argon2.low_level.Type.ID,
        )
        hashed = ph.hash(passphrase)

        old_salt = _get_salt(store)
        old_key = None
        new_key = _derive_key(passphrase, salt)

        if old_salt and store.get("master_hash") and _HAS_CRYPTO:
            try:
                old_ph = argon2.PasswordHasher()
                old_ph.verify(store["master_hash"], passphrase)
                old_key = _derive_key(passphrase, old_salt)
            except Exception:
                old_key = None

        if old_key and new_key and _HAS_CRYPTO:
            for cred in store["credentials"]:
                for field in _SENSITIVE_FIELDS:
                    enc_key = f"{field}_encrypted"
                    if enc_key in cred and cred[enc_key]:
                        try:
                            plain = _decrypt_field(cred[enc_key], old_key)
                            cred[enc_key] = _encrypt_field(plain, new_key)
                        except Exception:
                            pass
        elif new_key and _HAS_CRYPTO:
            for cred in store["credentials"]:
                _encrypt_sensitive(cred, new_key)

        store["master_hash"] = hashed
        store["salt"] = base64.b64encode(salt).decode("ascii")
        _save_store(proj_dir, store)
    return True


def check_passphrase(proj_dir, passphrase):
    """Verify *passphrase* against the stored argon2id hash."""
    with _lock:
        store = _load_store(proj_dir)

    if not _HAS_ARGON2:
        log.warning("argon2-cffi not installed — cannot verify passphrase")
        return False

    stored_hash = store.get("master_hash")
    if not stored_hash:
        return False

    try:
        ph = argon2.PasswordHasher()
        return ph.verify(stored_hash, passphrase)
    except argon2.exceptions.VerifyMismatchError:
        return False
    except Exception:
        log.exception("Passphrase verification error")
        return False
