"""
Reproduces Table III of the paper -- the seven functional checks run
against the full issuance -> recovery pipeline (Sec. V-B). Each test name
and docstring points at the Table III row and the mechanism (column 2)
that is supposed to catch it.
"""

from __future__ import annotations

import os

import numpy as np
import pytest

from rtasa.audit_log import AuditLog, CheckpointWitnessStore
from rtasa.crypto_core import IntegrityError, decrypt_record, derive_ke, encrypt_record
from rtasa.issuance import issue_record
from rtasa.keystore import AuthorizationError
from rtasa.recovery import approve_share, recover_record, request_recovery
from rtasa.rsa_wrap import ShareUnwrapError, unwrap_share, wrap_share
from rtasa.shamir import ShareVerificationError, reconstruct_secret, split_secret

from conftest import otp_for


def _issue(keystore, audit_log, custodian_role_ids, cover_images, record_id="rec-1", entitled=("requester_q",)):
    owner = keystore.get("owner")
    return issue_record(
        keystore=keystore,
        audit_log=audit_log,
        owner_role_id="owner",
        owner_passphrase="owner-pass-123",
        owner_otp=owner.current_otp(),
        record_id=record_id,
        message=b"Record contents that must stay confidential.",
        custodian_role_ids=custodian_role_ids,
        threshold=2,
        cover_images=cover_images,
        entitled_requesters=entitled,
    )


def test_recover_with_any_k_approving_roles(keystore, custodian_role_ids, cover_images):
    """Table III row 1: recover with any k approving roles -> Lagrange + GCM succeed."""
    audit_log = AuditLog()
    record = _issue(keystore, audit_log, custodian_role_ids, cover_images)

    for subset in (custodian_role_ids[:2], custodian_role_ids[1:], [custodian_role_ids[0], custodian_role_ids[2]]):
        req = request_recovery(
            keystore=keystore, audit_log=audit_log, record=record,
            requester_role_id="requester_q", requester_passphrase="requester-pass",
            requester_otp=keystore.get("requester_q").current_otp(),
        )
        for rid in subset:
            approve_share(
                keystore=keystore, audit_log=audit_log, record=record,
                custodian_role_id=rid, custodian_passphrase=f"{rid}-pass",
                custodian_otp=keystore.get(rid).current_otp(), request=req,
            )
        message = recover_record(
            keystore=keystore, audit_log=audit_log, witness_store=None, record=record,
            requester_role_id="requester_q", requester_passphrase="requester-pass",
            requester_otp=keystore.get("requester_q").current_otp(), approvals=req.approvals,
        )
        assert message == b"Record contents that must stay confidential."


def test_recover_with_k_minus_1_shares_is_refused_by_the_pipeline(keystore, custodian_role_ids, cover_images):
    """The orchestration layer fails fast (fewer than k approvals) rather
    than attempting a doomed reconstruction. See the next test for the
    paper's actual enforcement mechanism (the GCM tag)."""
    audit_log = AuditLog()
    record = _issue(keystore, audit_log, custodian_role_ids, cover_images)
    req = request_recovery(
        keystore=keystore, audit_log=audit_log, record=record,
        requester_role_id="requester_q", requester_passphrase="requester-pass",
        requester_otp=keystore.get("requester_q").current_otp(),
    )
    approve_share(
        keystore=keystore, audit_log=audit_log, record=record,
        custodian_role_id=custodian_role_ids[0], custodian_passphrase=f"{custodian_role_ids[0]}-pass",
        custodian_otp=keystore.get(custodian_role_ids[0]).current_otp(), request=req,
    )
    with pytest.raises(ShareVerificationError):
        recover_record(
            keystore=keystore, audit_log=audit_log, witness_store=None, record=record,
            requester_role_id="requester_q", requester_passphrase="requester-pass",
            requester_otp=keystore.get("requester_q").current_otp(), approvals=req.approvals,
        )


def test_recover_with_k_minus_1_shares_the_gcm_tag_rejects_the_wrong_key():
    """Table III row 2, the paper's actual mechanism: interpolating with
    k-1 of a (k, n) sharing yields a value other than K, and AES-GCM's tag
    is what rejects the resulting wrong ke -- this is demonstrated here at
    the E + T layer directly, bypassing the pipeline's fail-fast count
    check above."""
    from rtasa.curve import Q
    import secrets

    secret = secrets.randbelow(Q)
    shares, _ = split_secret(secret, threshold=3, role_indices=[1, 2, 3, 4, 5], record_id="rec-x")
    wrong_key = reconstruct_secret(shares[:2])  # only k-1 = 2 of k = 3
    assert wrong_key != secret

    ke_right = derive_ke(secret, "rec-x")
    ct = encrypt_record(b"payload", ke_right, "rec-x")
    ke_wrong = derive_ke(wrong_key, "rec-x")
    with pytest.raises(IntegrityError):
        decrypt_record(ct, ke_wrong)


def test_corrupted_share_value_fails_feldman_check(keystore, custodian_role_ids, cover_images):
    """Table III row 3: a corrupted share value fails the Feldman check (eq. 4)."""
    audit_log = AuditLog()
    record = _issue(keystore, audit_log, custodian_role_ids, cover_images)

    # Corrupt the share by swapping in a bit-flipped kappa so the extracted
    # ciphertext Z_i decodes to garbage before it ever reaches the Feldman
    # check... instead, more directly: corrupt the commitments themselves,
    # which is equivalent to "the share no longer matches what was published".
    import dataclasses
    from rtasa.curve import G

    bad_commitments = dataclasses.replace(
        record.commitments, points=tuple(p + G for p in record.commitments.points)
    )
    record.commitments = bad_commitments

    req = request_recovery(
        keystore=keystore, audit_log=audit_log, record=record,
        requester_role_id="requester_q", requester_passphrase="requester-pass",
        requester_otp=keystore.get("requester_q").current_otp(),
    )
    with pytest.raises(ShareVerificationError):
        approve_share(
            keystore=keystore, audit_log=audit_log, record=record,
            custodian_role_id=custodian_role_ids[0], custodian_passphrase=f"{custodian_role_ids[0]}-pass",
            custodian_otp=keystore.get(custodian_role_ids[0]).current_otp(), request=req,
        )


def test_embedded_bit_flipped_in_carrier_fails_oaep_decoding(keystore, custodian_role_ids, cover_images):
    """Table III row 4: a flipped embedded bit corrupts the extracted
    RSA-OAEP ciphertext Z_i, which then fails OAEP decoding."""
    audit_log = AuditLog()
    record = _issue(keystore, audit_log, custodian_role_ids, cover_images)

    rid = custodian_role_ids[0]
    carrier = record.carrier_for(rid)
    # Positions are chosen by a kappa-seeded permutation (eq. 6), not
    # sequentially, so flip every pixel's LSB to guarantee at least one
    # embedded bit is corrupted regardless of where the embedder put them.
    flat = carrier.stego_image.reshape(-1)
    flat ^= 1

    req = request_recovery(
        keystore=keystore, audit_log=audit_log, record=record,
        requester_role_id="requester_q", requester_passphrase="requester-pass",
        requester_otp=keystore.get("requester_q").current_otp(),
    )
    with pytest.raises((ShareUnwrapError, ShareVerificationError)):
        approve_share(
            keystore=keystore, audit_log=audit_log, record=record,
            custodian_role_id=rid, custodian_passphrase=f"{rid}-pass",
            custodian_otp=keystore.get(rid).current_otp(), request=req,
        )


def test_share_opened_with_another_roles_key_fails(keystore, custodian_role_ids, cover_images):
    """Table III row 5: swap two custodians' carriers so each tries to
    open the other's share -- OAEP decoding fails under the wrong key."""
    audit_log = AuditLog()
    record = _issue(keystore, audit_log, custodian_role_ids, cover_images)

    rid_a, rid_b = custodian_role_ids[0], custodian_role_ids[1]
    record.carriers[rid_a], record.carriers[rid_b] = record.carriers[rid_b], record.carriers[rid_a]

    req = request_recovery(
        keystore=keystore, audit_log=audit_log, record=record,
        requester_role_id="requester_q", requester_passphrase="requester-pass",
        requester_otp=keystore.get("requester_q").current_otp(),
    )
    with pytest.raises(ShareUnwrapError):
        approve_share(
            keystore=keystore, audit_log=audit_log, record=record,
            custodian_role_id=rid_a, custodian_passphrase=f"{rid_a}-pass",
            custodian_otp=keystore.get(rid_a).current_otp(), request=req,
        )


def test_share_replayed_under_another_id_is_rejected(keystore, custodian_role_ids, cover_images):
    """Table III row 6: a share wrapped for one record's id must not be
    accepted as a share of a different record (eq. 5's id binding)."""
    rid = custodian_role_ids[0]
    role = keystore.get(rid)
    from rtasa.shamir import Share

    share = Share(role_index=role.evaluation_point, value=777, record_id="rec-original")
    wrapped = wrap_share(share, role.rsa_public())
    with pytest.raises(ShareUnwrapError):
        unwrap_share(wrapped, role.rsa_private(), expected_record_id="rec-different")


def test_unentitled_requester_is_refused_by_policy_check(keystore, custodian_role_ids, cover_images):
    """Table III row 7: an unentitled requester is refused by the policy check."""
    audit_log = AuditLog()
    record = _issue(keystore, audit_log, custodian_role_ids, cover_images, entitled=("requester_q",))

    with pytest.raises(AuthorizationError):
        request_recovery(
            keystore=keystore, audit_log=audit_log, record=record,
            requester_role_id="outsider", requester_passphrase="outsider-pass",
            requester_otp=keystore.get("outsider").current_otp(),
        )
