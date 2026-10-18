"""
Layer A -- role-bound share wrapping.

Implements eq. (5):

    Z_i = OAEP_pk_i(x_i || y_i || id)

Wrapping a share under role R_i's RSA public key is what makes "which role
may use this share" a cryptographic fact rather than a database flag: only
the holder of sk_i can ever recover (x_i, y_i), and binding the record id
into the plaintext stops a share for one record being replayed as if it
were a share for another (Table III, "Share replayed under another id").
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from functools import lru_cache

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .curve import Q
from .shamir import Share

RSA_KEY_SIZE_BITS = 2048
RSA_PUBLIC_EXPONENT = 65537

# y_i lives in Z_q, q ~ 256 bits -> pack into 32 bytes. x_i is a small public
# role index -> pack into 2 bytes. id is a UTF-8 string of bounded length so
# that (2 + 32 + len(id)) stays under the 2048-bit OAEP-SHA256 plaintext
# limit (190 bytes; see MAX_ID_LEN below).
_X_LEN = 2
_Y_LEN = 32
MAX_ID_LEN = 150  # keeps 2 + 32 + 150 = 184 <= 190-byte OAEP-SHA256 limit for a 2048-bit key


class ShareUnwrapError(Exception):
    """Raised when OAEP decoding fails, or the unwrapped id does not match
    the record the caller expected (replay across records), or another
    role's private key was used (Table III, several rows)."""


def generate_role_rsa_keypair() -> "rsa.RSAPrivateKey":
    return rsa.generate_private_key(public_exponent=RSA_PUBLIC_EXPONENT, key_size=RSA_KEY_SIZE_BITS)


# Parsing a PEM-encoded RSA key is not free -- in this environment, loading
# a 2048-bit private key from PEM costs ~35-40ms (dominated by OpenSSL's
# own key validation, not anything RTASA does). A role's key pair is fixed
# once it's created, so re-parsing the same PEM bytes on every single
# wrap/unwrap call -- which `RoleIdentity.rsa_private()` / `.rsa_public()`
# used to do -- turns "a cheap RSA-OAEP operation" into "tens of
# milliseconds of redundant ASN.1 parsing," and that cost was swamping the
# benchmark in scripts/benchmark_latency.py with something that has
# nothing to do with RTASA's actual per-operation cost. PEM bytes are
# immutable and a natural cache key, so parsing happens once per distinct
# key and is reused after that.
@lru_cache(maxsize=512)
def _load_private_cached(pem: bytes):
    return serialization.load_pem_private_key(pem, password=None)


@lru_cache(maxsize=512)
def _load_public_cached(pem: bytes):
    return serialization.load_pem_public_key(pem)


def _oaep() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def wrap_bytes(plaintext: bytes, public_key: "rsa.RSAPublicKey") -> bytes:
    """Generic RSA-OAEP wrap for small payloads -- used for the per-role
    embedding key kappa_i, which the paper has D send to R_i "encrypted
    under pk_i" alongside (but separately from) the embedded share Z_i
    (Sec. IV-B, around eq. 6)."""
    return public_key.encrypt(plaintext, _oaep())


def unwrap_bytes(ciphertext: bytes, private_key: "rsa.RSAPrivateKey") -> bytes:
    try:
        return private_key.decrypt(ciphertext, _oaep())
    except (ValueError, InvalidKey) as exc:
        raise ShareUnwrapError("OAEP decoding failed -- wrong key or corrupted ciphertext") from exc


def wrap_share(share: Share, public_key: "rsa.RSAPublicKey") -> bytes:
    """Z_i = OAEP_pk_i(x_i || y_i || id)  -- eq. (5)."""
    if len(share.record_id.encode("utf-8")) > MAX_ID_LEN:
        raise ValueError(f"record_id too long for OAEP payload (max {MAX_ID_LEN} bytes)")
    plaintext = (
        struct.pack(">H", share.role_index)
        + share.value.to_bytes(_Y_LEN, "big")
        + share.record_id.encode("utf-8")
    )
    return public_key.encrypt(plaintext, _oaep())


def unwrap_share(ciphertext: bytes, private_key: "rsa.RSAPrivateKey", expected_record_id: str) -> Share:
    """Inverse of `wrap_share`. Raises ShareUnwrapError if OAEP decoding
    fails (wrong key -- i.e. "opened with another role's key"), or if the
    embedded id does not match `expected_record_id` (replay across ids)."""
    try:
        plaintext = private_key.decrypt(ciphertext, _oaep())
    except (ValueError, InvalidKey) as exc:
        raise ShareUnwrapError("OAEP decoding failed -- wrong key or corrupted ciphertext") from exc

    if len(plaintext) < _X_LEN + _Y_LEN:
        raise ShareUnwrapError("unwrapped plaintext too short to be a valid share")

    x_i = struct.unpack(">H", plaintext[:_X_LEN])[0]
    y_i = int.from_bytes(plaintext[_X_LEN:_X_LEN + _Y_LEN], "big")
    record_id = plaintext[_X_LEN + _Y_LEN:].decode("utf-8", errors="strict")

    if record_id != expected_record_id:
        raise ShareUnwrapError(
            f"id binding mismatch: share was issued for '{record_id}', "
            f"not '{expected_record_id}' (eq. 5 replay protection)"
        )
    if y_i >= Q:
        raise ShareUnwrapError("unwrapped y_i is out of range for Z_q")

    return Share(role_index=x_i, value=y_i, record_id=record_id)


@dataclass(frozen=True)
class RSAKeyPairPEM:
    private_pem: bytes
    public_pem: bytes

    @staticmethod
    def generate() -> "RSAKeyPairPEM":
        key = generate_role_rsa_keypair()
        priv = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return RSAKeyPairPEM(private_pem=priv, public_pem=pub)

    def load_private(self):
        return _load_private_cached(self.private_pem)

    def load_public(self):
        return _load_public_cached(self.public_pem)
