"""Credential encryption — AES-256-GCM with Argon2id key derivation.

Master passphrase is NEVER stored on disk.  The derived key lives in
process memory only and is cleared on shutdown (or explicit .clear()).

Dependencies: argon2-cffi, cryptography
"""

import base64
import ctypes
import hmac
import hashlib
import json
import logging
import os
import stat
from datetime import datetime, timezone

log = logging.getLogger("crucible.credential_crypto")

# ── Argon2id parameters (plan §15) ─────────────────────────────────────────
_TIME_COST = 3
_MEMORY_COST = 65536       # 64 MiB
_PARALLELISM = 4
_HASH_LEN = 32             # AES-256 key length
_SALT_LEN = 16             # bytes
_NONCE_LEN = 12            # GCM nonce

# Known plaintext used for passphrase verification HMAC.
# Arbitrary fixed value — never changes, never secret.
_VERIFY_PLAINTEXT = b"crucible-credential-vault-verify-v1"


# ── Base64 helpers ──────────────────────────────────────────────────────────

def b64e(data: bytes) -> str:
    """Base64-encode bytes to a UTF-8 string."""
    return base64.b64encode(data).decode("utf-8")


def b64d(data: str) -> bytes:
    """Base64-decode a UTF-8 string to bytes."""
    return base64.b64decode(data.encode("utf-8"))


# ── Core class ──────────────────────────────────────────────────────────────

class CredentialCrypto:
    """AES-256-GCM credential encryption backed by an Argon2id-derived key."""

    def __init__(self, master_passphrase: str, salt: bytes = None):
        """Derive AES-256 key from *master_passphrase* using Argon2id.

        If *salt* is ``None`` a fresh 16-byte random salt is generated
        (use this when creating a new vault).  Pass the stored salt when
        reopening an existing vault.
        """
        from argon2.low_level import hash_secret_raw, Type

        if salt is None:
            salt = os.urandom(_SALT_LEN)
        if len(salt) != _SALT_LEN:
            raise ValueError(f"Salt must be {_SALT_LEN} bytes, got {len(salt)}")

        self.salt: bytes = salt
        self._key: bytes = hash_secret_raw(
            secret=master_passphrase.encode("utf-8"),
            salt=salt,
            time_cost=_TIME_COST,
            memory_cost=_MEMORY_COST,
            parallelism=_PARALLELISM,
            hash_len=_HASH_LEN,
            type=Type.ID,
        )

    # ── Encrypt / Decrypt ───────────────────────────────────────────────

    def encrypt(self, plaintext: str) -> dict:
        """Encrypt *plaintext* with AES-256-GCM.

        Returns ``{"ciphertext": bytes, "nonce": bytes, "tag": bytes}``.
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        nonce = os.urandom(_NONCE_LEN)
        aes = AESGCM(self._key)
        # AESGCM.encrypt returns ciphertext || tag (last 16 bytes)
        ct_with_tag = aes.encrypt(nonce, plaintext.encode("utf-8"), None)
        ciphertext = ct_with_tag[:-16]
        tag = ct_with_tag[-16:]
        return {"ciphertext": ciphertext, "nonce": nonce, "tag": tag}

    def decrypt(self, ciphertext: bytes, nonce: bytes, tag: bytes) -> str:
        """Decrypt a credential secret.  Raises on auth failure."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        aes = AESGCM(self._key)
        # Reconstruct ciphertext||tag as AESGCM.decrypt expects
        plaintext = aes.decrypt(nonce, ciphertext + tag, None)
        return plaintext.decode("utf-8")

    # ── Passphrase verification ─────────────────────────────────────────

    def generate_verification(self) -> bytes:
        """HMAC-SHA256 of a fixed plaintext with the derived key.

        Store this blob in ``credential_vault.master_verify`` so the
        passphrase can be validated on next open without exposing any
        actual credential.
        """
        return hmac.new(self._key, _VERIFY_PLAINTEXT, hashlib.sha256).digest()

    def verify_passphrase(self, stored_verify: bytes) -> bool:
        """Return ``True`` if the derived key matches *stored_verify*."""
        computed = self.generate_verification()
        return hmac.compare_digest(computed, stored_verify)

    # ── Credential file generation ──────────────────────────────────────

    def generate_cred_file(self, credentials: list, engagement_id: str,
                           output_path: str):
        """Write an encrypted credential file for SS3 / downstream tools.

        The file contains AES-256-GCM ciphertext blobs (base64).  The
        decryption key is passed via the ``SS3_CRED_KEY`` env var — it is
        NOT stored in the file.

        *credentials* is a list of dicts, each with at least:
            cred_type, os_tag, username, domain, protocol, source,
            spray_eligible, secret_enc (bytes), secret_nonce (bytes),
            secret_tag (bytes)
        These are written as-is (already encrypted) with base64 encoding.

        File permissions are set to 0600.
        """
        global_creds = []
        host_overrides = []

        for cred in credentials:
            entry = {
                "id": cred.get("id"),
                "cred_type": cred.get("cred_type", "password"),
                "os_tag": cred.get("os_tag"),
                "username": cred.get("username", ""),
                "secret_enc": b64e(cred["secret_enc"]) if isinstance(cred["secret_enc"], bytes) else cred["secret_enc"],
                "secret_nonce": b64e(cred["secret_nonce"]) if isinstance(cred["secret_nonce"], bytes) else cred["secret_nonce"],
                "secret_tag": b64e(cred["secret_tag"]) if isinstance(cred["secret_tag"], bytes) else cred["secret_tag"],
                "domain": cred.get("domain"),
                "protocol": cred.get("protocol"),
                "source": cred.get("source", "user_provided"),
                "spray_eligible": bool(cred.get("spray_eligible", False)),
            }
            if cred.get("target_ip"):
                entry["target_ip"] = cred["target_ip"]
                host_overrides.append(entry)
            else:
                global_creds.append(entry)

        payload = {
            "schema_version": "1.0",
            "engagement_id": engagement_id,
            "created": datetime.now(timezone.utc).isoformat(),
            "encryption": {
                "algorithm": "AES-256-GCM",
                "kdf": "argon2id",
                "note": ("secret_enc fields are base64-encoded ciphertext; "
                         "decrypt with SS3_CRED_KEY env var"),
            },
            "global_credentials": global_creds,
            "host_overrides": host_overrides,
        }

        # Write atomically via tmp then rename
        tmp_path = output_path + ".tmp"
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(payload, fh, indent=2)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        os.replace(tmp_path, output_path)
        # Ensure final perms even if umask interfered with the tmp
        os.chmod(output_path, stat.S_IRUSR | stat.S_IWUSR)
        log.info("Credential file written: %s (%d global, %d per-host)",
                 output_path, len(global_creds), len(host_overrides))

    # ── Key export (for env-var delivery to tools) ──────────────────────

    @property
    def key_b64(self) -> str:
        """Return the derived key base64-encoded for passing via env var."""
        return b64e(self._key)

    # ── Cleanup ─────────────────────────────────────────────────────────

    def clear(self):
        """Best-effort zeroing of the derived key in memory."""
        if self._key:
            try:
                buf = (ctypes.c_char * len(self._key)).from_buffer_copy(self._key)
                ctypes.memset(ctypes.addressof(buf), 0, len(self._key))
            except Exception:
                pass
            self._key = b"\x00" * _HASH_LEN
        log.debug("Credential key cleared from memory")

    def __del__(self):
        self.clear()
