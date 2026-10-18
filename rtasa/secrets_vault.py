"""
Encryption-at-rest for the role key store (Sec. IV-A: "Each of n custodian
roles R_i holds RSA and signing key pairs in a role key store that only
authenticated members can use").

The paper's own prototype keeps that promise entirely at the application
layer -- the FastAPI routers refuse to hand out a role's private key
material to anyone but that authenticated role. This module extends the
same promise to the *storage* layer: the bytes actually written to disk
(SQLite today) are useless without a separate master key, the
Key-Encryption-Key (KEK) below, so a stolen database file alone does not
hand over any role's RSA/ECDSA private keys or TOTP seed.

This is deliberately the smallest realistic step up from the paper's own
documented simplification ("Role keys are stored in JSON/SQLite, not an
HSM" -- see README's "Why a few things are simplified" section) rather
than a new mechanism: it reuses AES-256-GCM, the exact primitive the paper
already specifies for layer E (eq. 2), as an envelope cipher around the
key-store's sensitive fields instead of around a message. An HSM or a
cloud KMS would be the next step beyond this for a real production
deployment; this module is the local, dependency-free middle ground.

Master key sourcing (checked in this order):
  1. RTASA_MASTER_KEY env var -- base64-encoded 32 bytes. This is how a
     real deployment should supply it: injected by a secrets manager
     (Vault, AWS/GCP/Azure KMS-wrapped env injection, Kubernetes secret),
     never committed to source control or the database alongside the data
     it protects.
  2. A local key file (default ./.rtasa_master.key, overridable via
     RTASA_MASTER_KEY_FILE), created on first use with 0600 permissions.
     This exists purely so the prototype runs out of the box with no
     setup step; a loud one-time warning is printed when it is created or
     used, precisely so this convenience is never mistaken for a
     production posture.
"""

from __future__ import annotations

import base64
import os
import stat
import sys
import threading
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MASTER_KEY_LEN = 32  # AES-256
GCM_NONCE_LEN = 12

_lock = threading.Lock()
_cached_key: Optional[bytes] = None
_warned = False


def _default_key_file() -> Path:
    return Path(os.environ.get("RTASA_MASTER_KEY_FILE", "./.rtasa_master.key"))


def _warn_dev_key(path: Path, created: bool) -> None:
    global _warned
    if _warned:
        return
    _warned = True
    action = "Generated a new" if created else "Loaded the local"
    print(
        f"[rtasa.secrets_vault] WARNING: {action} master key at '{path}'.\n"
        f"  This file-based key is a development/demo convenience ONLY. A real\n"
        f"  deployment must set RTASA_MASTER_KEY (base64, 32 bytes) from a secrets\n"
        f"  manager instead -- never let the key that protects the role key store\n"
        f"  live next to the database it protects.",
        file=sys.stderr,
    )


def load_master_key() -> bytes:
    """Load (and cache) the 32-byte AES-256 KEK. Thread-safe, read once per
    process. Tests that need isolation should call `reset_cache()` and set
    RTASA_MASTER_KEY_FILE to a fresh temp path."""
    global _cached_key
    with _lock:
        if _cached_key is not None:
            return _cached_key

        env_key = os.environ.get("RTASA_MASTER_KEY")
        if env_key:
            key = base64.b64decode(env_key)
            if len(key) != MASTER_KEY_LEN:
                raise ValueError(
                    f"RTASA_MASTER_KEY must decode to {MASTER_KEY_LEN} bytes, got {len(key)}"
                )
            _cached_key = key
            return key

        path = _default_key_file()
        if path.exists():
            key = base64.b64decode(path.read_text().strip())
            if len(key) != MASTER_KEY_LEN:
                raise ValueError(f"master key file '{path}' is corrupt (wrong length)")
            _warn_dev_key(path, created=False)
        else:
            key = os.urandom(MASTER_KEY_LEN)
            path.write_text(base64.b64encode(key).decode("ascii"))
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600 -- owner read/write only
            _warn_dev_key(path, created=True)

        _cached_key = key
        return key


def reset_cache() -> None:
    """Test-only: forget the cached key so a later `load_master_key()` call
    re-reads the environment/file (e.g. after pointing RTASA_MASTER_KEY_FILE
    at a fresh temp directory)."""
    global _cached_key, _warned
    with _lock:
        _cached_key = None
        _warned = False


def seal(plaintext: bytes, aad: bytes, master_key: Optional[bytes] = None) -> bytes:
    """AES-256-GCM encrypt `plaintext`, bound to `aad` (role_id + field name,
    so a ciphertext cannot be silently swapped between roles or fields --
    the same binding discipline the paper uses for `id` in eq. 2/5).
    Returns nonce || ciphertext-with-tag."""
    key = master_key if master_key is not None else load_master_key()
    nonce = os.urandom(GCM_NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + ct


def unseal(blob: bytes, aad: bytes, master_key: Optional[bytes] = None) -> bytes:
    key = master_key if master_key is not None else load_master_key()
    nonce, ct = blob[:GCM_NONCE_LEN], blob[GCM_NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, ct, aad)


def seal_str(plaintext: str, aad: bytes) -> str:
    """Convenience for text columns: base64 the sealed blob."""
    return base64.b64encode(seal(plaintext.encode("utf-8"), aad)).decode("ascii")


def unseal_str(blob_b64: str, aad: bytes) -> str:
    return unseal(base64.b64decode(blob_b64), aad).decode("utf-8")
