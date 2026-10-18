"""
Role identities, key material, and the credential-and-OTP authentication /
policy check that gates both issuance and recovery (Sec. IV-A, IV-B,
"After credential-and-OTP authentication and a policy check, D samples...").

Each role R_i (and the data owner D, and a requester Q) is represented by a
`RoleIdentity` holding:
  * an RSA-2048 keypair, used to OAEP-wrap/unwrap Shamir shares (eq. 5)
  * an ECDSA/P-256 keypair, used to sign audit-log entries and (for
    custodian roles) checkpoint countersignatures (Sec. IV-C)
  * an Argon2id passphrase hash, standing in for the paper's "credential"
    check -- Argon2id (RFC 9106) is the current OWASP-recommended choice
    for this exact job: a memory-hard KDF that resists GPU/ASIC-accelerated
    guessing far better than a pure-iteration scheme
  * a TOTP secret (RFC 6238), standing in for the paper's "OTP" factor,
    provisioned to a real authenticator app via `provisioning_uri()`
    rather than ever computed by the server in a production deployment
    (see `current_otp()` and app/routers/roles.py's demo-mode gating)

This auth layer is still intentionally small and auditable, consistent
with the paper's own ~340-line reference prototype (Sec. V-A) -- the
hardening below (Argon2id, lockout, real OTP provisioning, encryption of
the stored key material in app/persistence.py) strengthens exactly the two
mechanisms the paper names ("credential-and-OTP authentication" and "a
role key store that only authenticated members can use") rather than
introducing anything outside them. A production deployment would still
swap the role key store itself for an HSM or cloud KMS -- out of scope
here, as it is for the paper's own prototype (Sec. V-A).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import argon2
from ecdsa import SigningKey, VerifyingKey

from .audit_log import generate_signing_key
from .curve import CURVE
from .rsa_wrap import RSAKeyPairPEM

TOTP_STEP_SECONDS = 30
TOTP_DIGITS = 6
TOTP_SECRET_LEN = 20  # 160 bits, the RFC 4226-recommended HOTP secret length

# Credential (passphrase) policy -- NIST SP 800-63B's current guidance
# favors length over forced complexity rules and a check against known-weak
# secrets over periodic rotation; this is a small, deliberately conservative
# version of that rather than an arbitrary complexity rule set.
MIN_PASSPHRASE_LENGTH = 12
_COMMON_PASSPHRASES = {
    "password123", "password1234", "letmeinletmein", "qwertyqwerty",
    "admin12345678", "changeme12345", "welcome123456", "123456789012",
    "passwordpassword", "iloveyou123456",
}

# Failed-attempt lockout on the credential-and-OTP gate (brute-force
# defense; the paper does not specify one, but leaving the gate itself
# unthrottled would undercut it in any real deployment).
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 60

_argon2_hasher = argon2.PasswordHasher()

# A conventional (not cryptographically chained) security-event logger for
# authentication failures and lockouts. Deliberately kept separate from
# `rtasa.audit_log.AuditLog`, the paper's signed hash-chained layer L: every
# entry appended there is signed by the acting role's own private key
# (sigma_t = Sign_sk_actor(H_t), eq. 7), which is exactly what a *failed*
# authentication attempt cannot produce -- whoever just failed to prove they
# are 'custodian_1' does not hold custodian_1's signing key, so an entry
# claiming to be theirs could not be verified as theirs. Diluting layer L's
# clean actor-signed invariant to also hold unauthenticated claims would
# undercut the exact guarantee G4 relies on. Recording failed/locked-out
# attempts here instead is standard practice for any production identity
# system, and app/main.py wires this logger to a JSON-lines file
# (RTASA_SECURITY_LOG) so they are still durably recorded, just outside the
# signed chain.
security_logger = logging.getLogger("rtasa.security")


class AuthenticationError(Exception):
    """Raised when a credential or OTP check fails (policy gate, Sec. IV-A/B/D)."""


class AccountLockedError(AuthenticationError):
    """Raised instead of AuthenticationError once a role has accumulated
    MAX_FAILED_ATTEMPTS consecutive failures -- callers that only catch
    AuthenticationError still handle this safely (it IS one), but
    app/routers/* catch it first to answer 429 instead of 401."""


class AuthorizationError(Exception):
    """Raised when an authenticated party is not entitled to the action
    they requested (the "policy check")."""


class WeakPassphraseError(ValueError):
    """Raised by `RoleIdentity.create` when a passphrase fails the minimum
    credential policy below."""


def validate_passphrase_strength(passphrase: str) -> None:
    if len(passphrase) < MIN_PASSPHRASE_LENGTH:
        raise WeakPassphraseError(
            f"passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters"
        )
    if passphrase.lower() in _COMMON_PASSPHRASES:
        raise WeakPassphraseError("passphrase is too common/predictable")


def hotp(secret: bytes, counter: int, digits: int = TOTP_DIGITS) -> str:
    """RFC 4226 HOTP, used as the basis for our TOTP (RFC 6238-style, with
    counter = floor(time / step)). Implemented locally so the prototype
    has no dependency beyond the standard library for the OTP factor."""
    msg = struct.pack(">Q", counter)
    digest = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code_int).zfill(digits)


def totp_now(secret: bytes, step: int = TOTP_STEP_SECONDS, when: Optional[float] = None) -> str:
    when = time.time() if when is None else when
    return hotp(secret, counter=int(when // step))


def totp_verify(secret: bytes, code: str, step: int = TOTP_STEP_SECONDS, skew: int = 1) -> bool:
    """Accepts a code from the current step or up to `skew` steps either
    side, the usual TOTP clock-skew allowance."""
    now_counter = int(time.time() // step)
    for delta in range(-skew, skew + 1):
        if hmac.compare_digest(hotp(secret, now_counter + delta), code):
            return True
    return False


@dataclass
class RoleIdentity:
    role_id: str
    display_name: str
    rsa_keys: RSAKeyPairPEM
    signing_key_pem: str          # ECDSA/P-256 private key, PEM (PKCS8-like via ecdsa's PEM)
    verifying_key_pem: str
    passphrase_hash: str          # Argon2id hash (self-contained: algorithm, salt, params)
    totp_secret: str              # base64, raw HOTP/TOTP secret bytes
    evaluation_point: Optional[int] = None  # x_i, for custodian roles that hold Shamir shares
    is_custodian: bool = False
    failed_attempts: int = 0
    locked_until: float = 0.0
    email: Optional[str] = None   # delivery address for the email-OTP login flow (app/auth.py)

    # -- key accessors -----------------------------------------------------

    def rsa_public(self):
        return self.rsa_keys.load_public()

    def rsa_private(self):
        return self.rsa_keys.load_private()

    def signing_key(self) -> SigningKey:
        return SigningKey.from_pem(self.signing_key_pem)

    def verifying_key(self) -> VerifyingKey:
        return VerifyingKey.from_pem(self.verifying_key_pem)

    # -- authentication ------------------------------------------------

    def check_passphrase(self, passphrase: str) -> bool:
        try:
            return _argon2_hasher.verify(self.passphrase_hash, passphrase)
        except argon2.exceptions.VerifyMismatchError:
            return False
        except argon2.exceptions.VerificationError:
            return False

    def check_otp(self, code: str) -> bool:
        secret = base64.b64decode(self.totp_secret)
        return totp_verify(secret, code)

    def current_otp(self) -> str:
        """Convenience for the demo/tests: in a real deployment this would
        be computed on the custodian's own device/authenticator app, never
        exposed by the keystore itself. The HTTP endpoint that wraps this
        (app/routers/roles.py) is gated behind demo mode for exactly that
        reason -- see app/security_config.py."""
        secret = base64.b64decode(self.totp_secret)
        return totp_now(secret)

    def provisioning_uri(self, issuer: str = "RTASA") -> str:
        """An otpauth:// URI (the de facto standard Google/Microsoft/1Password
        authenticator apps all accept) for enrolling this role's TOTP secret
        on a real device -- scanned once, at role creation, the way a
        production deployment would actually hand out the paper's "OTP"
        factor instead of ever disclosing a live code from the server."""
        secret_b32 = base64.b32encode(base64.b64decode(self.totp_secret)).decode("ascii").rstrip("=")
        label = f"{issuer}:{self.role_id}"
        return (
            f"otpauth://totp/{label}?secret={secret_b32}&issuer={issuer}"
            f"&digits={TOTP_DIGITS}&period={TOTP_STEP_SECONDS}&algorithm=SHA1"
        )

    def authenticate(self, passphrase: str, otp_code: str) -> None:
        """Credential-and-OTP authentication (Sec. IV-B/D), with a
        failed-attempt lockout layered on top: MAX_FAILED_ATTEMPTS
        consecutive failures locks the role out for LOCKOUT_SECONDS. A
        currently-locked role is refused before either factor is even
        checked, so lockout cannot be used to distinguish a right
        passphrase from a right OTP (no extra oracle)."""
        now = time.time()
        if now < self.locked_until:
            remaining = int(self.locked_until - now) + 1
            security_logger.warning(
                "auth_rejected_locked", extra={"role_id": self.role_id, "remaining_s": remaining}
            )
            raise AccountLockedError(
                f"'{self.role_id}' is temporarily locked after repeated failed "
                f"authentication attempts -- try again in {remaining}s"
            )

        passphrase_ok = self.check_passphrase(passphrase)
        otp_ok = self.check_otp(otp_code) if passphrase_ok else False

        if passphrase_ok and otp_ok:
            self.failed_attempts = 0
            return

        self.failed_attempts += 1
        if self.failed_attempts >= MAX_FAILED_ATTEMPTS:
            self.locked_until = now + LOCKOUT_SECONDS
            self.failed_attempts = 0
            security_logger.error(
                "auth_locked_out",
                extra={"role_id": self.role_id, "lockout_s": LOCKOUT_SECONDS},
            )
            raise AccountLockedError(
                f"'{self.role_id}' locked for {LOCKOUT_SECONDS}s after "
                f"{MAX_FAILED_ATTEMPTS} consecutive failed authentication attempts"
            )

        reason = "bad_passphrase" if not passphrase_ok else "bad_or_expired_otp"
        security_logger.warning(
            "auth_failed",
            extra={"role_id": self.role_id, "reason": reason, "attempt": self.failed_attempts},
        )
        if not passphrase_ok:
            raise AuthenticationError(f"'{self.role_id}': bad passphrase")
        raise AuthenticationError(f"'{self.role_id}': bad or expired OTP code")

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["rsa_keys"] = {
            "private_pem": base64.b64encode(self.rsa_keys.private_pem).decode("ascii"),
            "public_pem": base64.b64encode(self.rsa_keys.public_pem).decode("ascii"),
        }
        return d

    @staticmethod
    def from_dict(d: dict) -> "RoleIdentity":
        d = dict(d)
        rk = d["rsa_keys"]
        d["rsa_keys"] = RSAKeyPairPEM(
            private_pem=base64.b64decode(rk["private_pem"]),
            public_pem=base64.b64decode(rk["public_pem"]),
        )
        return RoleIdentity(**d)

    @staticmethod
    def create(
        role_id: str,
        display_name: str,
        passphrase: str,
        is_custodian: bool = False,
        evaluation_point: Optional[int] = None,
        email: Optional[str] = None,
    ) -> "RoleIdentity":
        validate_passphrase_strength(passphrase)
        pw_hash = _argon2_hasher.hash(passphrase)
        totp_secret = os.urandom(TOTP_SECRET_LEN)
        sk = generate_signing_key()
        vk = sk.verifying_key
        return RoleIdentity(
            role_id=role_id,
            display_name=display_name,
            rsa_keys=RSAKeyPairPEM.generate(),
            signing_key_pem=sk.to_pem().decode("ascii"),
            verifying_key_pem=vk.to_pem().decode("ascii"),
            passphrase_hash=pw_hash,
            totp_secret=base64.b64encode(totp_secret).decode("ascii"),
            evaluation_point=evaluation_point,
            is_custodian=is_custodian,
            email=email,
        )


@dataclass
class RoleKeyStore:
    """A role key store that only authenticated members can use (Sec.
    IV-A: "a role key store that only authenticated members can use").
    Persisted via app/persistence.py with the sensitive fields sealed
    under a master key (rtasa/secrets_vault.py) -- a production deployment
    would use an HSM or a cloud KMS instead, out of scope here as it is
    for the paper's own prototype (Sec. V-A)."""

    roles: dict = field(default_factory=dict)  # role_id -> RoleIdentity

    def add(self, identity: RoleIdentity) -> None:
        self.roles[identity.role_id] = identity

    def get(self, role_id: str) -> RoleIdentity:
        try:
            return self.roles[role_id]
        except KeyError as exc:
            raise AuthorizationError(f"unknown role '{role_id}'") from exc

    def custodians(self) -> dict:
        return {rid: r for rid, r in self.roles.items() if r.is_custodian}

    def save(self, path: Path) -> None:
        serializable = {rid: r.to_dict() for rid, r in self.roles.items()}
        path.write_text(json.dumps(serializable, indent=2))

    @staticmethod
    def load(path: Path) -> "RoleKeyStore":
        data = json.loads(path.read_text())
        store = RoleKeyStore()
        for d in data.values():
            store.add(RoleIdentity.from_dict(d))
        return store
