"""
Section IV-D -- Recovery.

    "Q sends a signed request, and after the policy check each approving
    custodian i in A extracts and decrypts its share (eq. 8), checks it
    against (4), re-wraps it under Q's key, signs it, and logs the
    approval. With |A| >= k valid shares, Q interpolates (eq. 9), derives
    ke, and decrypts C, and the GCM tag confirms integrity. No custodian
    sees another custodian's share."

Three entry points mirror the three actors in that paragraph:

  * `request_recovery`  -- Q's signed request (+ the policy / entitlement
    check: Table III's "Unentitled requester -> Policy check -> Refused").
  * `approve_share`     -- one custodian's half of eq. (8): extract Z_i
    from its own carrier, unwrap with its own sk_i, Feldman-check it
    against the published commitments, then re-wrap it under Q's public
    key (never revealing (x_i, y_i) to anyone but Q).
  * `recover_record`    -- Q collects >= k approvals, unwraps each with
    its own sk_Q, re-verifies the Feldman check, reconstructs K by
    Lagrange interpolation (eq. 9), derives ke, and decrypts C. A
    reconstruction also triggers a checkpoint (Sec. IV-C: "...and at each
    reconstruction all n custodians countersign and retain the head").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

from .audit_log import AuditLog, CheckpointWitnessStore
from .crypto_core import decrypt_record, derive_ke
from .keystore import AuthorizationError, RoleKeyStore
from .records import Record
from .rsa_wrap import unwrap_bytes, unwrap_share, wrap_share
from .shamir import ShareVerificationError, reconstruct_secret, require_valid_share


@dataclass
class RecoveryRequest:
    record_id: str
    requester_role_id: str
    approvals: list = field(default_factory=list)   # list[bytes] -- Z_i' wrapped under Q's key
    approving_roles: list = field(default_factory=list)


def request_recovery(
    *,
    keystore: RoleKeyStore,
    audit_log: AuditLog,
    record: Record,
    requester_role_id: str,
    requester_passphrase: str,
    requester_otp: str,
) -> RecoveryRequest:
    requester = keystore.get(requester_role_id)
    requester.authenticate(requester_passphrase, requester_otp)

    # Policy check (Table III: "Unentitled requester -> Policy check -> Refused")
    if record.entitled_requesters and requester_role_id not in record.entitled_requesters:
        audit_log.append(
            "recovery_refused",
            requester_role_id,
            {"record_id": record.record_id, "reason": "unentitled requester"},
            requester.signing_key(),
        )
        raise AuthorizationError(
            f"'{requester_role_id}' is not entitled to request recovery of '{record.record_id}'"
        )

    audit_log.append(
        "recovery_requested",
        requester_role_id,
        {"record_id": record.record_id},
        requester.signing_key(),
    )
    return RecoveryRequest(record_id=record.record_id, requester_role_id=requester_role_id)


def approve_share(
    *,
    keystore: RoleKeyStore,
    audit_log: AuditLog,
    record: Record,
    custodian_role_id: str,
    custodian_passphrase: str,
    custodian_otp: str,
    request: RecoveryRequest,
) -> bytes:
    """One custodian's half of eq. (8) plus the re-wrap step. Returns
    Z_i' = OAEP_pkQ(x_i || y_i || id), appends it to `request.approvals`,
    and also returns it so a caller that wants to simulate attacks
    (flipped bit, wrong key, replay, corrupted share -- Table III) can
    intercept/mutate it before it reaches `recover_record`.
    """
    custodian = keystore.get(custodian_role_id)
    custodian.authenticate(custodian_passphrase, custodian_otp)

    if custodian_role_id not in record.custodian_role_ids:
        raise AuthorizationError(f"'{custodian_role_id}' does not hold a share of '{record.record_id}'")

    # Guard against a double approval from the same custodian (a double
    # click, a retried network request, two open tabs) -- without this,
    # `request.approving_roles`/`approvals` could reach `record.threshold`
    # with fewer *distinct* custodians than the paper's |A| >= k actually
    # requires, and `reconstruct_secret` (rtasa/shamir.py) would later
    # reject the duplicate share index with a bare ValueError that nothing
    # downstream was catching -- a confusing 500 instead of a clean 403
    # at the point the mistake actually happened.
    if custodian_role_id in request.approving_roles:
        raise AuthorizationError(
            f"'{custodian_role_id}' has already approved this recovery request for '{record.record_id}'"
        )

    carrier = record.carrier_for(custodian_role_id)

    # (x_i, y_i) = OAEP^-1_sk_i( Extract(G_i; kappa_i) )   -- eq. (8)
    kappa_i = unwrap_bytes(carrier.wrapped_kappa, custodian.rsa_private())

    from .stego import extract  # local import, see note in issuance.py

    wrapped_share = extract(carrier.stego_image, carrier.payload_len_bytes, kappa_i, record.record_id)
    share = unwrap_share(wrapped_share, custodian.rsa_private(), expected_record_id=record.record_id)

    # checks it against (4)
    require_valid_share(share, record.commitments)

    requester = keystore.get(request.requester_role_id)
    rewrapped = wrap_share(share, requester.rsa_public())

    audit_log.append(
        "share_approved",
        custodian_role_id,
        {"record_id": record.record_id, "requester": request.requester_role_id},
        custodian.signing_key(),
    )

    request.approvals.append(rewrapped)
    request.approving_roles.append(custodian_role_id)
    return rewrapped


def recover_record(
    *,
    keystore: RoleKeyStore,
    audit_log: AuditLog,
    witness_store: Optional[CheckpointWitnessStore],
    record: Record,
    requester_role_id: str,
    requester_passphrase: str,
    requester_otp: str,
    approvals: Optional[Iterable[bytes]] = None,
) -> bytes:
    """With |A| >= k valid shares, interpolate K (eq. 9), derive ke, and
    decrypt C. `approvals` defaults to whatever `approve_share` calls have
    accumulated via the `RecoveryRequest` object, but can be overridden by
    a caller/test that wants to feed in a tampered or truncated set."""
    requester = keystore.get(requester_role_id)
    requester.authenticate(requester_passphrase, requester_otp)

    requester_private_key = requester.rsa_private()
    shares = []
    for wrapped in approvals:
        share = unwrap_share(wrapped, requester_private_key, expected_record_id=record.record_id)
        require_valid_share(share, record.commitments)  # re-check (4) before trusting it
        shares.append(share)

    if len(shares) < record.threshold:
        raise ShareVerificationError(
            f"only {len(shares)} valid shares, need {record.threshold} (eq. 9 needs |A| >= k)"
        )

    # Any k valid shares suffice (Table III: "Recover with any k approving
    # roles") -- use exactly the threshold, even if more were approved.
    session_key = reconstruct_secret(shares[: record.threshold])
    ke = derive_ke(session_key, record.record_id)
    message = decrypt_record(record.ciphertext, ke)  # GCM tag confirms integrity

    audit_log.append(
        "record_recovered",
        requester_role_id,
        {"record_id": record.record_id, "shares_used": len(shares)},
        requester.signing_key(),
    )

    if witness_store is not None:
        custodian_keys = {
            rid: keystore.get(rid).signing_key() for rid in record.custodian_role_ids
        }
        audit_log.checkpoint(custodian_keys, witness_store=witness_store)

    return message
