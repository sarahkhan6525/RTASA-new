"""
Section IV-B -- Issuance.

    "After credential-and-OTP authentication and a policy check, D samples
    K uniformly from Z_q, ..., derives ke with HKDF, and encrypts with
    AES-256-GCM, binding id as associated data (eq. 2). K is split with
    Shamir's (k, n) scheme (eq. 3) ... D publishes Feldman commitments ...
    Each share is wrapped under its role's key with RSA-OAEP (eq. 5) ...
    Zi is embedded by LSB matching at pixel positions selected by a
    per-role key kappa_i, which is sent to Ri encrypted under pki (eq. 6),
    and Gi is stored among ordinary images of the same source."

This module wires rtasa.crypto_core, rtasa.shamir, rtasa.rsa_wrap, and
rtasa.stego together into that single pipeline, logging every step to the
audit log (layer L) as it goes.
"""

from __future__ import annotations

import os
import secrets
from typing import Iterable

import numpy as np

from .audit_log import AuditLog, link_commitment
from .crypto_core import encrypt_record, derive_ke
from .curve import Q
from .keystore import RoleKeyStore
from .records import Record, RoleCarrier
from .rsa_wrap import wrap_bytes, wrap_share
from .shamir import split_secret

KAPPA_LEN = 32


def issue_record(
    *,
    keystore: RoleKeyStore,
    audit_log: AuditLog,
    owner_role_id: str,
    owner_passphrase: str,
    owner_otp: str,
    record_id: str,
    message: bytes,
    custodian_role_ids: Iterable[str],
    threshold: int,
    cover_images: dict,
    entitled_requesters: Iterable[str] = (),
    link_salt: bytes = None,
) -> Record:
    """Run the full issuance pipeline for one record and return the
    resulting `Record` (ciphertext + commitments + one stego carrier per
    custodian role). Raises AuthenticationError / AuthorizationError from
    `rtasa.keystore` if the credential-and-OTP / policy check fails."""

    owner = keystore.get(owner_role_id)
    owner.authenticate(owner_passphrase, owner_otp)  # "credential-and-OTP authentication"

    custodian_role_ids = list(custodian_role_ids)
    if len(custodian_role_ids) < threshold:
        raise ValueError("fewer custodian roles than the threshold k")
    for rid in custodian_role_ids:
        role = keystore.get(rid)
        if not role.is_custodian or role.evaluation_point is None:
            raise ValueError(f"role '{rid}' is not a custodian with an evaluation point x_i")
        if rid not in cover_images:
            raise ValueError(f"no cover image supplied for custodian role '{rid}'")

    audit_log.append(
        "issuance_started",
        owner_role_id,
        {"record_id": record_id, "threshold": threshold, "custodians": custodian_role_ids},
        owner.signing_key(),
    )

    # K uniform in Z_q  (Sec. IV-B)
    session_key = secrets.randbelow(Q)

    # C = AES-GCM_ke(M; nu, id)   -- eq. (2)
    ke = derive_ke(session_key, record_id)
    ciphertext = encrypt_record(message, ke, record_id)

    # Shamir split + Feldman commitments  -- eq. (3), (4)
    role_points = [keystore.get(rid).evaluation_point for rid in custodian_role_ids]
    shares, commitments = split_secret(session_key, threshold, role_points, record_id)
    shares_by_role = dict(zip(custodian_role_ids, shares))

    audit_log.append(
        "commitments_published",
        owner_role_id,
        {
            "record_id": record_id,
            "feldman_commitments": commitments.to_hex_list(),
            "threshold": threshold,
        },
        owner.signing_key(),
    )

    link_salt = link_salt if link_salt is not None else os.urandom(16)
    record = Record(
        record_id=record_id,
        ciphertext=ciphertext,
        commitments=commitments,
        threshold=threshold,
        custodian_role_ids=tuple(custodian_role_ids),
        entitled_requesters=set(entitled_requesters),
        owner_role_id=owner_role_id,
    )

    for rid in custodian_role_ids:
        role = keystore.get(rid)
        share = shares_by_role[rid]

        # Zi = OAEP_pki(xi || yi || id)   -- eq. (5)
        wrapped_share = wrap_share(share, role.rsa_public())

        # kappa_i generated per record, sent to Ri encrypted under pk_i
        kappa_i = os.urandom(KAPPA_LEN)
        wrapped_kappa = wrap_bytes(kappa_i, role.rsa_public())

        # Gi = Embed(Ii, Zi; kappa_i)   -- eq. (6)
        from .stego import embed  # local import avoids a hard numpy/PIL dependency at module load

        cover = cover_images[rid]
        stego_image = embed(cover, wrapped_share, kappa_i, record_id)

        record.carriers[rid] = RoleCarrier(
            role_id=rid,
            stego_image=stego_image,
            wrapped_kappa=wrapped_kappa,
            payload_len_bytes=len(wrapped_share),
        )

        carrier_digest = _digest_image(stego_image)
        commitment_hex = link_commitment(rid, record_id, carrier_digest, link_salt)
        audit_log.append(
            "share_issued",
            owner_role_id,
            {
                "record_id": record_id,
                # the *actual* role<->carrier mapping is never logged in
                # the clear -- only this salted commitment is (Sec. IV-C)
                "link_commitment": commitment_hex,
            },
            owner.signing_key(),
        )

    return record


def _digest_image(image: np.ndarray) -> str:
    import hashlib

    return hashlib.sha256(image.tobytes()).hexdigest()
