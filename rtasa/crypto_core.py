"""
Layer E -- hybrid payload encryption.

Implements eq. (2) of the paper:

    C = AES-GCM_ke(M; nu, id)

The session key K (sampled in `issuance.py` from Z_q, Sec. IV-B) is never
used directly as the AES key. It is first passed through HKDF (RFC 5869,
[32]) to derive a 256-bit encryption key ke, binding the record id into the
"info" parameter so that ke is cryptographically tied to this one record.
AES-256-GCM then encrypts M, binding the record id a second time as
Associated Authenticated Data (AAD) per the paper's "(nu, id)" notation,
where nu is the GCM nonce.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

AES_KEY_LEN = 32  # AES-256
GCM_NONCE_LEN = 12  # 96-bit nonce, the NIST SP 800-38D recommendation


class IntegrityError(Exception):
    """Raised when the GCM tag fails to verify -- i.e. K (hence ke) was wrong
    or C/AAD was tampered with. This is the mechanism by which Table III's
    "Recover with k-1 shares" check is rejected (the GCM tag detects a wrong
    key rather than silently producing garbage plaintext)."""


def derive_ke(session_key_int: int, record_id: str) -> bytes:
    """HKDF-derive the AES-256-GCM key ke from the Shamir-shared session key K.

    K is reduced from Z_q to a 32-byte big-endian string before being used as
    HKDF input key material, and the record id is bound into `info` so that
    the same K used for two different records would still yield different
    ke (defence in depth beyond the GCM AAD binding).
    """
    ikm = session_key_int.to_bytes(32, "big")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_LEN,
        salt=None,
        info=b"RTASA-ke|" + record_id.encode("utf-8"),
    )
    return hkdf.derive(ikm)


@dataclass(frozen=True)
class Ciphertext:
    nonce: bytes
    ciphertext: bytes  # includes the 16-byte GCM tag, per the `cryptography` AESGCM API
    record_id: str

    def to_dict(self) -> dict:
        return {
            "nonce": self.nonce.hex(),
            "ciphertext": self.ciphertext.hex(),
            "record_id": self.record_id,
        }

    @staticmethod
    def from_dict(d: dict) -> "Ciphertext":
        return Ciphertext(
            nonce=bytes.fromhex(d["nonce"]),
            ciphertext=bytes.fromhex(d["ciphertext"]),
            record_id=d["record_id"],
        )


def encrypt_record(message: bytes, ke: bytes, record_id: str) -> Ciphertext:
    """C = AES-GCM_ke(M; nu, id)  -- eq. (2)."""
    nonce = os.urandom(GCM_NONCE_LEN)
    aesgcm = AESGCM(ke)
    aad = record_id.encode("utf-8")
    ct = aesgcm.encrypt(nonce, message, aad)
    return Ciphertext(nonce=nonce, ciphertext=ct, record_id=record_id)


def decrypt_record(ct: Ciphertext, ke: bytes) -> bytes:
    """Inverse of `encrypt_record`. Raises IntegrityError if `ke` (and hence
    the reconstructed K) was wrong, or if the ciphertext/id was tampered with.
    """
    aesgcm = AESGCM(ke)
    aad = ct.record_id.encode("utf-8")
    try:
        return aesgcm.decrypt(ct.nonce, ct.ciphertext, aad)
    except InvalidTag as exc:
        raise IntegrityError(
            "GCM tag verification failed -- wrong session key or tampered ciphertext"
        ) from exc
