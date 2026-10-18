"""
Enterprise security hardening on top of the paper's own credential-and-OTP
gate (Sec. IV-A/B/D) and role key store: Argon2id passphrase hashing,
failed-attempt lockout, TOTP provisioning (and the standalone authenticator
simulator that consumes it), and AES-256-GCM encryption-at-rest of the
sensitive key-store fields.
"""

from __future__ import annotations

import base64
import time

import pytest

from rtasa import secrets_vault
from rtasa.keystore import (
    AccountLockedError,
    AuthenticationError,
    MAX_FAILED_ATTEMPTS,
    RoleIdentity,
    WeakPassphraseError,
    totp_now,
    validate_passphrase_strength,
)
from scripts.authenticator import secret_from_uri


# -- Argon2id credential hashing --------------------------------------------

def test_passphrase_is_not_stored_in_cleartext_or_as_pbkdf2():
    role = RoleIdentity.create("r1", "Role One", "correct-horse-battery")
    assert "correct-horse-battery" not in role.passphrase_hash
    assert role.passphrase_hash.startswith("$argon2id$")


def test_correct_passphrase_verifies_wrong_does_not():
    role = RoleIdentity.create("r1", "Role One", "correct-horse-battery")
    assert role.check_passphrase("correct-horse-battery") is True
    assert role.check_passphrase("wrong-horse-battery!") is False


def test_weak_passphrase_rejected_at_creation():
    with pytest.raises(WeakPassphraseError):
        RoleIdentity.create("r1", "Role One", "short")  # < 12 chars
    with pytest.raises(WeakPassphraseError):
        RoleIdentity.create("r1", "Role One", "Welcome123456")  # len OK, blocklisted (case-insensitive)
    with pytest.raises(WeakPassphraseError):
        validate_passphrase_strength("welcome123456")  # exact blocklist entry


def test_strong_passphrase_accepted():
    validate_passphrase_strength("correct-horse-battery-staple")  # should not raise


# -- failed-attempt lockout --------------------------------------------------

def test_lockout_after_max_failed_attempts():
    role = RoleIdentity.create("r1", "Role One", "correct-horse-battery")
    bad_otp = "000000"

    for _ in range(MAX_FAILED_ATTEMPTS - 1):
        with pytest.raises(AuthenticationError):
            role.authenticate("correct-horse-battery", bad_otp)
        assert role.locked_until == 0.0  # not locked yet

    # the MAX_FAILED_ATTEMPTS-th failure trips the lockout
    with pytest.raises(AccountLockedError):
        role.authenticate("correct-horse-battery", bad_otp)
    assert role.locked_until > time.time()

    # even the *correct* OTP is refused while locked (lockout checked first)
    with pytest.raises(AccountLockedError):
        role.authenticate("correct-horse-battery", role.current_otp())


def test_lockout_clears_after_window_and_successful_auth_resets_counter():
    role = RoleIdentity.create("r1", "Role One", "correct-horse-battery")
    for _ in range(MAX_FAILED_ATTEMPTS):
        try:
            role.authenticate("correct-horse-battery", "000000")
        except (AuthenticationError, AccountLockedError):
            pass
    assert role.locked_until > 0.0

    # simulate the lockout window having elapsed
    role.locked_until = 0.0
    role.authenticate("correct-horse-battery", role.current_otp())  # should not raise
    assert role.failed_attempts == 0


def test_account_locked_error_is_an_authentication_error():
    # callers that only catch AuthenticationError (the paper's own
    # exception for "credential-and-OTP authentication" failing) still
    # handle a lockout safely -- it IS one.
    assert issubclass(AccountLockedError, AuthenticationError)


# -- TOTP provisioning & the standalone authenticator simulator -------------

def test_provisioning_uri_round_trips_through_the_authenticator_script():
    role = RoleIdentity.create("custodian_1", "Custodian 1", "correct-horse-battery")
    uri = role.provisioning_uri()
    assert uri.startswith("otpauth://totp/RTASA:custodian_1?")

    secret_from_server = base64.b64decode(role.totp_secret)
    secret_from_script = secret_from_uri(uri)
    assert secret_from_script == secret_from_server

    # a code the "authenticator device" (scripts/authenticator.py) computes
    # from only the provisioning URI is one the server actually accepts
    now = time.time()
    code = totp_now(secret_from_script, when=now)
    assert role.check_otp(code) is True


# -- encryption-at-rest (rtasa/secrets_vault.py) -----------------------------

@pytest.fixture
def fixed_master_key():
    return b"\x11" * 32


def test_seal_unseal_round_trip(fixed_master_key):
    plaintext = b"-----BEGIN RSA PRIVATE KEY-----\nnot a real key\n-----END-----"
    blob = secrets_vault.seal(plaintext, aad=b"role1|rsa_private_pem", master_key=fixed_master_key)
    assert blob != plaintext
    assert plaintext not in blob
    recovered = secrets_vault.unseal(blob, aad=b"role1|rsa_private_pem", master_key=fixed_master_key)
    assert recovered == plaintext


def test_unseal_fails_with_wrong_aad_or_wrong_key(fixed_master_key):
    blob = secrets_vault.seal(b"secret-bytes", aad=b"role1|totp_secret", master_key=fixed_master_key)
    with pytest.raises(Exception):
        secrets_vault.unseal(blob, aad=b"role2|totp_secret", master_key=fixed_master_key)  # AAD mismatch
    with pytest.raises(Exception):
        secrets_vault.unseal(blob, aad=b"role1|totp_secret", master_key=b"\x22" * 32)  # wrong key


def test_seal_str_unseal_str_round_trip(fixed_master_key, monkeypatch):
    original = "-----BEGIN EC PRIVATE KEY-----\nfoo\n-----END EC PRIVATE KEY-----"
    # seal_str/unseal_str use the module-level load_master_key(), so
    # exercise the env-var sourcing path explicitly (never touches a file).
    monkeypatch.setenv("RTASA_MASTER_KEY", base64.b64encode(fixed_master_key).decode("ascii"))
    secrets_vault.reset_cache()
    try:
        sealed = secrets_vault.seal_str(original, aad=b"role1|signing_key_pem")
        recovered = secrets_vault.unseal_str(sealed, aad=b"role1|signing_key_pem")
        assert recovered == original
    finally:
        secrets_vault.reset_cache()


def test_master_key_file_is_created_with_owner_only_permissions(tmp_path, monkeypatch):
    import os
    import stat

    key_file = tmp_path / "master.key"
    monkeypatch.setenv("RTASA_MASTER_KEY_FILE", str(key_file))
    monkeypatch.delenv("RTASA_MASTER_KEY", raising=False)
    secrets_vault.reset_cache()
    try:
        key = secrets_vault.load_master_key()
        assert len(key) == 32
        assert key_file.exists()
        mode = stat.S_IMODE(os.stat(key_file).st_mode)
        assert mode == stat.S_IRUSR | stat.S_IWUSR  # 0600

        # loading again returns the *same* key (persisted, not regenerated)
        secrets_vault.reset_cache()
        assert secrets_vault.load_master_key() == key
    finally:
        secrets_vault.reset_cache()
