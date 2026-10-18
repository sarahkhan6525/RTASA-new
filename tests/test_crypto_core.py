from __future__ import annotations

import os

import pytest

from rtasa.crypto_core import IntegrityError, decrypt_record, derive_ke, encrypt_record


def test_encrypt_decrypt_round_trip():
    ke = derive_ke(session_key_int=12345, record_id="rec-1")
    ct = encrypt_record(b"hello RTASA", ke, "rec-1")
    assert decrypt_record(ct, ke) == b"hello RTASA"


def test_wrong_key_rejected_by_gcm_tag():
    """eq. (2): the GCM tag is what makes a wrong K detectable (Table III,
    'Recover with k-1 shares' relies on exactly this)."""
    ke_right = derive_ke(session_key_int=111, record_id="rec-2")
    ke_wrong = derive_ke(session_key_int=222, record_id="rec-2")
    ct = encrypt_record(b"payload", ke_right, "rec-2")
    with pytest.raises(IntegrityError):
        decrypt_record(ct, ke_wrong)


def test_tampered_ciphertext_rejected():
    ke = derive_ke(session_key_int=999, record_id="rec-3")
    ct = encrypt_record(b"payload", ke, "rec-3")
    tampered = ct.ciphertext[:-1] + bytes([ct.ciphertext[-1] ^ 0x01])
    from dataclasses import replace

    bad_ct = replace(ct, ciphertext=tampered)
    with pytest.raises(IntegrityError):
        decrypt_record(bad_ct, ke)


def test_different_record_id_breaks_aad_binding():
    """id is bound as AAD (eq. 2) -- decrypting under a different id must fail."""
    ke = derive_ke(session_key_int=42, record_id="rec-a")
    ct = encrypt_record(b"payload", ke, "rec-a")
    from dataclasses import replace

    relabeled = replace(ct, record_id="rec-b")
    with pytest.raises(IntegrityError):
        decrypt_record(relabeled, ke)


def test_ke_depends_on_record_id():
    """Defence in depth beyond AAD: the same K must not yield the same ke
    for two different records."""
    k = int.from_bytes(os.urandom(32), "big")
    ke1 = derive_ke(k, "rec-x")
    ke2 = derive_ke(k, "rec-y")
    assert ke1 != ke2
