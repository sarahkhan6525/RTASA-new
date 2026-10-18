"""
A live, click-to-run reproduction of Table III (the paper's seven
functional/adversarial checks, Sec. V-B) plus one Table IV row (an
insider editing their own audit entry, Sec. IV-C/V-B) and two extra
hardening checks the implementation adds on top of the paper
(credential lockout; a basic wrong-passphrase rejection).

Every check below runs against a *disposable* keystore, record, and
audit log built fresh inside this one function call -- never the real
`RTASASystem` the live demo/portals use. That matters for a demo: a
button here can be clicked over and over without any risk of locking
out a real custodian, corrupting a real record, or writing a fake
entry into the real audit trail.

`run_security_battery()` returns a flat list of result dicts; callers
group them by `group` for display.
"""

from __future__ import annotations

import copy
import dataclasses

from carriers.generate_carriers import make_synthetic_cover

from .audit_log import AuditLog, CheckpointWitnessStore
from .curve import Q
from .issuance import issue_record
from .keystore import (
    AccountLockedError,
    AuthenticationError,
    AuthorizationError,
    RoleIdentity,
    RoleKeyStore,
)
from .recovery import approve_share, recover_record, request_recovery
from .rsa_wrap import ShareUnwrapError, unwrap_bytes, unwrap_share, wrap_share
from .shamir import Share, ShareVerificationError, require_valid_share
from .stego import extract

_IMG = 160  # small synthetic cover -- plenty of capacity for a 2048-bit
            # RSA-OAEP payload, and fast to generate/embed/extract for a
            # button click rather than the 768x512 "paper-scale" covers


def _r(id_, label, mechanism, group, expect, passed, detail):
    return {
        "id": id_,
        "label": label,
        "mechanism": mechanism,
        "group": group,
        "expect": expect,
        "passed": bool(passed),
        "detail": detail,
    }


def run_security_battery() -> list[dict]:
    results: list[dict] = []
    T3 = "Table III -- functional & adversarial checks"
    HARDEN = "Additional hardening (beyond the paper's own tests)"
    T4 = "Table IV -- log tampering"

    # -- disposable (k, n) = (2, 3) system, one record -------------------
    keystore = RoleKeyStore()
    owner = RoleIdentity.create("sectest-owner", "Security-Test Owner", "sectest-owner-pass-7f2a")
    keystore.add(owner)
    custodians = []
    for i in range(1, 4):
        c = RoleIdentity.create(
            f"sectest-cust-{i}", f"Security-Test Custodian {i}",
            f"sectest-cust-{i}-pass-9d3e", is_custodian=True, evaluation_point=i,
        )
        keystore.add(c)
        custodians.append(c)
    requester_q = RoleIdentity.create("sectest-requester-q", "Entitled Requester", "sectest-req-q-pass-4b1c")
    keystore.add(requester_q)
    outsider = RoleIdentity.create("sectest-outsider", "Unentitled Requester", "sectest-outsider-pass-6e8f")
    keystore.add(outsider)

    audit_log = AuditLog(checkpoint_interval=1000)
    witness_store = CheckpointWitnessStore()
    cover_images = {
        c.role_id: make_synthetic_cover(seed=i, height=_IMG, width=_IMG)
        for i, c in enumerate(custodians)
    }

    record_id = "sectest-record-1"
    message = b"Security Testing tab demo payload -- not a real record."
    try:
        record = issue_record(
            keystore=keystore, audit_log=audit_log,
            owner_role_id=owner.role_id, owner_passphrase="sectest-owner-pass-7f2a",
            owner_otp=owner.current_otp(), record_id=record_id, message=message,
            custodian_role_ids=[c.role_id for c in custodians], threshold=2,
            cover_images=cover_images, entitled_requesters={requester_q.role_id},
        )
    except Exception as exc:  # the whole battery is meaningless without this -- surface it plainly
        return [_r("setup", "Build the disposable test record", "issue_record (eq. 2-6)", T3, "succeeds", False, f"Could not set up the scratch record: {exc}")]

    # -- 1. Recover with any k approving roles (Lagrange + GCM, eq. 9) ---
    try:
        req = request_recovery(
            keystore=keystore, audit_log=audit_log, record=record,
            requester_role_id=requester_q.role_id, requester_passphrase="sectest-req-q-pass-4b1c",
            requester_otp=requester_q.current_otp(),
        )
        for c in custodians[:2]:
            approve_share(
                keystore=keystore, audit_log=audit_log, record=record,
                custodian_role_id=c.role_id,
                custodian_passphrase=f"sectest-cust-{c.evaluation_point}-pass-9d3e",
                custodian_otp=c.current_otp(), request=req,
            )
        recovered = recover_record(
            keystore=keystore, audit_log=audit_log, witness_store=witness_store, record=record,
            requester_role_id=requester_q.role_id, requester_passphrase="sectest-req-q-pass-4b1c",
            requester_otp=requester_q.current_otp(), approvals=req.approvals,
        )
        ok = recovered == message
        results.append(_r(
            "recover_any_k", "Recover with any k approving roles", "Lagrange interpolation (eq. 9) + GCM tag",
            T3, "succeeds", ok,
            "Recovered plaintext matched the protected record exactly." if ok else "Recovered bytes did not match the original -- unexpected.",
        ))
    except Exception as exc:
        results.append(_r("recover_any_k", "Recover with any k approving roles", "Lagrange interpolation (eq. 9) + GCM tag", T3, "succeeds", False, f"Unexpected error: {exc}"))

    # -- 2. Recover with k-1 shares -> GCM/threshold must reject ---------
    try:
        req2 = request_recovery(
            keystore=keystore, audit_log=audit_log, record=record,
            requester_role_id=requester_q.role_id, requester_passphrase="sectest-req-q-pass-4b1c",
            requester_otp=requester_q.current_otp(),
        )
        approve_share(
            keystore=keystore, audit_log=audit_log, record=record,
            custodian_role_id=custodians[0].role_id,
            custodian_passphrase="sectest-cust-1-pass-9d3e",
            custodian_otp=custodians[0].current_otp(), request=req2,
        )
        try:
            recover_record(
                keystore=keystore, audit_log=audit_log, witness_store=witness_store, record=record,
                requester_role_id=requester_q.role_id, requester_passphrase="sectest-req-q-pass-4b1c",
                requester_otp=requester_q.current_otp(), approvals=req2.approvals,
            )
            results.append(_r("recover_k_minus_1", "Recover with k − 1 shares", "threshold check ahead of eq. 9", T3, "refused", False, "Recovery unexpectedly succeeded with only k − 1 shares."))
        except ShareVerificationError as exc:
            results.append(_r("recover_k_minus_1", "Recover with k − 1 shares", "threshold check ahead of eq. 9", T3, "refused", True, f"Correctly refused: {exc}"))
    except Exception as exc:
        results.append(_r("recover_k_minus_1", "Recover with k − 1 shares", "threshold check ahead of eq. 9", T3, "refused", False, f"Unexpected error: {exc}"))

    # -- 3. Corrupted share value -> Feldman check (eq. 4) must reject ---
    try:
        c = custodians[2]
        carrier = record.carrier_for(c.role_id)
        kappa = unwrap_bytes(carrier.wrapped_kappa, c.rsa_private())
        wrapped_bytes = extract(carrier.stego_image, carrier.payload_len_bytes, kappa, record.record_id)
        share = unwrap_share(wrapped_bytes, c.rsa_private(), expected_record_id=record.record_id)
        corrupted = dataclasses.replace(share, value=(share.value + 1) % Q)
        try:
            require_valid_share(corrupted, record.commitments)
            results.append(_r("corrupted_share", "Corrupted share value", "Feldman check (eq. 4)", T3, "refused", False, "A corrupted share unexpectedly passed the Feldman check."))
        except ShareVerificationError as exc:
            results.append(_r("corrupted_share", "Corrupted share value", "Feldman check (eq. 4)", T3, "refused", True, f"Correctly refused: {exc}"))
    except Exception as exc:
        results.append(_r("corrupted_share", "Corrupted share value", "Feldman check (eq. 4)", T3, "refused", False, f"Unexpected error: {exc}"))

    # -- 4. Embedded bit flipped in the carrier -> OAEP decoding fails ---
    try:
        c = custodians[0]
        carrier = record.carrier_for(c.role_id)
        kappa = unwrap_bytes(carrier.wrapped_kappa, c.rsa_private())
        tampered_image = carrier.stego_image.copy()
        tampered_image ^= 1  # flip every pixel's LSB -- guarantees every embedded bit is wrong
        try:
            corrupted_bytes = extract(tampered_image, carrier.payload_len_bytes, kappa, record.record_id)
            unwrap_share(corrupted_bytes, c.rsa_private(), expected_record_id=record.record_id)
            results.append(_r("embedded_bit_flip", "Embedded bit flipped in carrier", "OAEP decoding", T3, "refused", False, "A tampered carrier image unexpectedly unwrapped to a valid share."))
        except ShareUnwrapError as exc:
            results.append(_r("embedded_bit_flip", "Embedded bit flipped in carrier", "OAEP decoding", T3, "refused", True, f"Correctly refused: {exc}"))
    except Exception as exc:
        results.append(_r("embedded_bit_flip", "Embedded bit flipped in carrier", "OAEP decoding", T3, "refused", False, f"Unexpected error: {exc}"))

    # -- 5. Share opened with another role's key -> OAEP decoding fails --
    try:
        c = custodians[0]
        wrong_key_role = custodians[1]
        carrier = record.carrier_for(c.role_id)
        try:
            unwrap_bytes(carrier.wrapped_kappa, wrong_key_role.rsa_private())
            results.append(_r("wrong_role_key", "Share opened with another role's key", "OAEP decoding", T3, "refused", False, "Unwrapping with the wrong role's private key unexpectedly succeeded."))
        except ShareUnwrapError as exc:
            results.append(_r("wrong_role_key", "Share opened with another role's key", "OAEP decoding", T3, "refused", True, f"Correctly refused: {exc}"))
    except Exception as exc:
        results.append(_r("wrong_role_key", "Share opened with another role's key", "OAEP decoding", T3, "refused", False, f"Unexpected error: {exc}"))

    # -- 6. Share replayed under another record id -> id binding (eq. 5) --
    try:
        c = custodians[0]
        fake_share = Share(role_index=c.evaluation_point, value=1234567, record_id="sectest-OTHER-record")
        wrapped_for_other_record = wrap_share(fake_share, c.rsa_public())
        try:
            unwrap_share(wrapped_for_other_record, c.rsa_private(), expected_record_id=record.record_id)
            results.append(_r("replayed_share", "Share replayed under another id", "id binding in (5)", T3, "refused", False, "A share wrapped for a different record id was unexpectedly accepted."))
        except ShareUnwrapError as exc:
            results.append(_r("replayed_share", "Share replayed under another id", "id binding in (5)", T3, "refused", True, f"Correctly refused: {exc}"))
    except Exception as exc:
        results.append(_r("replayed_share", "Share replayed under another id", "id binding in (5)", T3, "refused", False, f"Unexpected error: {exc}"))

    # -- 7. Unentitled requester -> policy check refuses, logs the refusal --
    try:
        entries_before = len(audit_log.entries)
        try:
            request_recovery(
                keystore=keystore, audit_log=audit_log, record=record,
                requester_role_id=outsider.role_id, requester_passphrase="sectest-outsider-pass-6e8f",
                requester_otp=outsider.current_otp(),
            )
            results.append(_r("unentitled_requester", "Unentitled requester", "policy check", T3, "refused", False, "An unentitled requester was unexpectedly allowed to request recovery."))
        except AuthorizationError as exc:
            logged = len(audit_log.entries) > entries_before and audit_log.entries[-1].event_type == "recovery_refused"
            detail = f"Correctly refused: {exc}" + (" (and a 'recovery_refused' audit entry was logged)" if logged else "")
            results.append(_r("unentitled_requester", "Unentitled requester", "policy check", T3, "refused", True, detail))
    except Exception as exc:
        results.append(_r("unentitled_requester", "Unentitled requester", "policy check", T3, "refused", False, f"Unexpected error: {exc}"))

    # -- 8. Wrong passphrase -> authentication must reject ----------------
    try:
        try:
            request_recovery(
                keystore=keystore, audit_log=audit_log, record=record,
                requester_role_id=requester_q.role_id, requester_passphrase="definitely-the-wrong-passphrase",
                requester_otp=requester_q.current_otp(),
            )
            results.append(_r("wrong_passphrase", "Wrong passphrase", "credential-and-OTP authentication (Sec. IV-B/D)", HARDEN, "refused", False, "A wrong passphrase was unexpectedly accepted."))
        except AuthenticationError as exc:
            results.append(_r("wrong_passphrase", "Wrong passphrase", "credential-and-OTP authentication (Sec. IV-B/D)", HARDEN, "refused", True, f"Correctly refused: {exc}"))
    except Exception as exc:
        results.append(_r("wrong_passphrase", "Wrong passphrase", "credential-and-OTP authentication (Sec. IV-B/D)", HARDEN, "refused", False, f"Unexpected error: {exc}"))

    # -- 9. Five consecutive failures -> account lockout (brute-force) ---
    try:
        lockout_role = RoleIdentity.create("sectest-lockout-role", "Lockout Test Role", "sectest-lockout-pass-3c9a")
        keystore.add(lockout_role)
        locked = False
        attempt_that_locked = None
        for attempt in range(1, 7):
            try:
                lockout_role.authenticate("wrong-passphrase-on-purpose", "000000")
            except AccountLockedError:
                locked = True
                attempt_that_locked = attempt
                break
            except AuthenticationError:
                continue
        if locked:
            results.append(_r("account_lockout", "Five consecutive failed attempts", "failed-attempt lockout (MAX_FAILED_ATTEMPTS=5)", HARDEN, "locked out", True, f"Locked out on attempt {attempt_that_locked}, as expected."))
        else:
            results.append(_r("account_lockout", "Five consecutive failed attempts", "failed-attempt lockout (MAX_FAILED_ATTEMPTS=5)", HARDEN, "locked out", False, "6 failed attempts in a row did not trigger a lockout."))
    except Exception as exc:
        results.append(_r("account_lockout", "Five consecutive failed attempts", "failed-attempt lockout (MAX_FAILED_ATTEMPTS=5)", HARDEN, "locked out", False, f"Unexpected error: {exc}"))

    # -- 10. Table IV: insider edits their own entry, re-signs nothing ---
    try:
        if not audit_log.entries:
            raise RuntimeError("no audit entries to tamper with")
        tampered_entries = copy.deepcopy(audit_log.entries)
        target = tampered_entries[-1]
        tampered_data = dict(target.data)
        tampered_data["__tampered__"] = "security-tests tab: edited without re-signing"
        tampered_entries[-1] = dataclasses.replace(target, data=tampered_data)

        scratch_log = AuditLog(checkpoint_interval=audit_log.checkpoint_interval)
        scratch_log.entries = tampered_entries
        scratch_log.checkpoints = audit_log.checkpoints

        actor_keys = {rid: role.verifying_key() for rid, role in keystore.roles.items()}
        custodian_keys = {rid: role.verifying_key() for rid, role in keystore.custodians().items()}
        tampered_result = scratch_log.verify(actor_keys, custodian_keys, witness_store)
        detected = not tampered_result.ok
        detail = (
            f"Correctly detected: {'; '.join(tampered_result.problems)}" if detected
            else "The tampered entry was NOT detected -- unexpected."
        )
        results.append(_r("audit_tamper", "Insider edits own entry, re-signs nothing", "hash chain + ECDSA signature (Sec. IV-C)", T4, "detected", detected, detail))
    except Exception as exc:
        results.append(_r("audit_tamper", "Insider edits own entry, re-signs nothing", "hash chain + ECDSA signature (Sec. IV-C)", T4, "detected", False, f"Unexpected error: {exc}"))

    return results
