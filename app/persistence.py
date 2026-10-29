"""
Round-trips an `rtasa.system.RTASASystem` to and from the SQLAlchemy models
in `app/models.py`. This is a full-snapshot save/load (simple and correct
for the prototype's scale -- Sec. V-A's own evaluation used 40 records per
(k, n) setting, not a high-volume production log), not an incremental
diff, so every mutating endpoint in `app/main.py` just calls `save_system`
again after it changes anything.
"""

from __future__ import annotations

import numpy as np
from sqlalchemy.orm import Session

from rtasa.audit_log import AuditEntry, AuditLog, Checkpoint, CheckpointWitnessStore
from rtasa.crypto_core import Ciphertext
from rtasa.keystore import RoleIdentity, RoleKeyStore
from rtasa.records import Record, RoleCarrier
from rtasa.recovery import RecoveryRequest
from rtasa.rsa_wrap import RSAKeyPairPEM
from rtasa.secrets_vault import seal, seal_str, unseal, unseal_str
from rtasa.shamir import FeldmanCommitments
from rtasa.system import RTASASystem

from . import models

# Field-level Associated Authenticated Data for each sealed column: binds a
# ciphertext to the exact (role_id, field) it came from, so a ciphertext
# cannot be silently swapped between roles or between e.g. rsa_private_pem
# and signing_key_pem -- the same binding discipline the paper's own eq.
# (2)/(5) use for `id` (see rtasa/secrets_vault.py).


def _aad(role_id: str, field_name: str) -> bytes:
    return f"{role_id}|{field_name}".encode("utf-8")


def save_system(db: Session, system: RTASASystem) -> None:
    for role in system.keystore.roles.values():
        row = db.get(models.RoleRow, role.role_id) or models.RoleRow(role_id=role.role_id)
        row.display_name = role.display_name
        row.email = role.email
        row.is_custodian = 1 if role.is_custodian else 0
        row.evaluation_point = role.evaluation_point
        # Private key material and the TOTP seed are sealed (AES-256-GCM)
        # under the deployment's master key before they ever reach the
        # database -- "a role key store that only authenticated members
        # can use" (Sec. IV-A), enforced at the storage layer too, not
        # just by the app-level checks above. Public keys and the
        # already-one-way Argon2id hash are not secrets, so they stay as-is.
        row.rsa_private_pem = seal(role.rsa_keys.private_pem, _aad(role.role_id, "rsa_private_pem"))
        row.rsa_public_pem = role.rsa_keys.public_pem
        row.signing_key_pem = seal_str(role.signing_key_pem, _aad(role.role_id, "signing_key_pem"))
        row.verifying_key_pem = role.verifying_key_pem
        row.passphrase_hash = role.passphrase_hash
        row.totp_secret = seal_str(role.totp_secret, _aad(role.role_id, "totp_secret"))
        row.failed_attempts = role.failed_attempts
        row.locked_until = role.locked_until
        db.merge(row)

    for record in system.records.values():
        rrow = db.get(models.RecordRow, record.record_id) or models.RecordRow(record_id=record.record_id)
        rrow.owner_role_id = record.owner_role_id
        rrow.threshold = record.threshold
        rrow.custodian_role_ids = list(record.custodian_role_ids)
        rrow.entitled_requesters = list(record.entitled_requesters)
        rrow.ciphertext_nonce = record.ciphertext.nonce.hex()
        rrow.ciphertext_blob = record.ciphertext.ciphertext.hex()
        rrow.commitments_json = record.commitments.to_hex_list()
        rrow.link_salt = ""
        db.merge(rrow)

        for role_id, carrier in record.carriers.items():
            existing = (
                db.query(models.CarrierRow)
                .filter_by(record_id=record.record_id, role_id=role_id)
                .one_or_none()
            )
            crow = existing or models.CarrierRow(record_id=record.record_id, role_id=role_id)
            h, w = carrier.stego_image.shape
            crow.image_height, crow.image_width = h, w
            crow.image_bytes = carrier.stego_image.tobytes()
            crow.wrapped_kappa = carrier.wrapped_kappa
            crow.payload_len_bytes = carrier.payload_len_bytes
            db.merge(crow)

    for entry in system.audit_log.entries:
        erow = db.get(models.AuditEntryRow, entry.seq) or models.AuditEntryRow(seq=entry.seq)
        erow.event_type = entry.event_type
        erow.actor_id = entry.actor_id
        erow.data_json = entry.data
        erow.timestamp = entry.timestamp
        erow.prev_hash = entry.prev_hash.hex()
        erow.entry_hash = entry.entry_hash.hex()
        erow.signature = entry.signature.hex()
        db.merge(erow)

    for cp in system.audit_log.checkpoints:
        cprow = db.get(models.CheckpointRow, cp.seq) or models.CheckpointRow(seq=cp.seq)
        cprow.head_hash = cp.head_hash.hex()
        cprow.countersignatures_json = {k: v.hex() for k, v in cp.countersignatures.items()}
        db.merge(cprow)

    # Pending/in-progress recovery requests -- previously never persisted,
    # so a backend restart silently dropped them (and their approvals-so-
    # far) even though everything above survived. Approvals are stored
    # hex-encoded, same convention as RecordRow's ciphertext fields above:
    # they're RSA-OAEP-wrapped shares (ciphertext under the requester's own
    # public key), not plaintext secrets needing the seal()/seal_str()
    # treatment RoleRow's private key material gets.
    for request_id, req in system.recovery_requests.items():
        rqrow = db.get(models.RecoveryRequestRow, request_id) or models.RecoveryRequestRow(
            request_id=request_id
        )
        rqrow.record_id = req.record_id
        rqrow.requester_role_id = req.requester_role_id
        rqrow.approvals_json = [a.hex() for a in req.approvals]
        rqrow.approving_roles_json = list(req.approving_roles)
        db.merge(rqrow)

    db.commit()


def load_system(db: Session) -> RTASASystem:
    system = RTASASystem()

    for rrow in db.query(models.RoleRow).all():
        identity = RoleIdentity(
            role_id=rrow.role_id,
            display_name=rrow.display_name,
            email=rrow.email,
            rsa_keys=RSAKeyPairPEM(
                private_pem=unseal(rrow.rsa_private_pem, _aad(rrow.role_id, "rsa_private_pem")),
                public_pem=rrow.rsa_public_pem,
            ),
            signing_key_pem=unseal_str(rrow.signing_key_pem, _aad(rrow.role_id, "signing_key_pem")),
            verifying_key_pem=rrow.verifying_key_pem,
            passphrase_hash=rrow.passphrase_hash,
            totp_secret=unseal_str(rrow.totp_secret, _aad(rrow.role_id, "totp_secret")),
            evaluation_point=rrow.evaluation_point,
            is_custodian=bool(rrow.is_custodian),
            failed_attempts=rrow.failed_attempts,
            locked_until=rrow.locked_until,
        )
        system.keystore.add(identity)

    for erow in db.query(models.AuditEntryRow).order_by(models.AuditEntryRow.seq).all():
        system.audit_log.entries.append(
            AuditEntry(
                seq=erow.seq,
                event_type=erow.event_type,
                actor_id=erow.actor_id,
                data=erow.data_json,
                timestamp=erow.timestamp,
                prev_hash=bytes.fromhex(erow.prev_hash),
                entry_hash=bytes.fromhex(erow.entry_hash),
                signature=bytes.fromhex(erow.signature),
            )
        )

    for cprow in db.query(models.CheckpointRow).order_by(models.CheckpointRow.seq).all():
        cp = Checkpoint(
            seq=cprow.seq,
            head_hash=bytes.fromhex(cprow.head_hash),
            countersignatures={k: bytes.fromhex(v) for k, v in cprow.countersignatures_json.items()},
        )
        system.audit_log.checkpoints.append(cp)
        system.witness_store.record(cp)

    # Ordered by record_id (which embeds a millisecond timestamp -- see
    # frontend/src/pages/ProtectRecord.tsx's `rec-${Date.now()}`), so
    # `system.records` is populated in the same chronological order after
    # a restart as it was during the live session. Without this, a plain
    # unordered query result decides dict iteration order, and
    # app/routers/dashboard.py's `records[-1]` "latest record" pick can
    # land on an arbitrary record instead of the actual most recent one.
    for rrow in db.query(models.RecordRow).order_by(models.RecordRow.record_id).all():
        commitments = FeldmanCommitments.from_hex_list(
            rrow.commitments_json, threshold=rrow.threshold, record_id=rrow.record_id
        )
        record = Record(
            record_id=rrow.record_id,
            owner_role_id=rrow.owner_role_id or "",
            ciphertext=Ciphertext(
                nonce=bytes.fromhex(rrow.ciphertext_nonce),
                ciphertext=bytes.fromhex(rrow.ciphertext_blob),
                record_id=rrow.record_id,
            ),
            commitments=commitments,
            threshold=rrow.threshold,
            custodian_role_ids=tuple(rrow.custodian_role_ids),
            entitled_requesters=set(rrow.entitled_requesters),
        )
        for crow in rrow.carriers:
            image = np.frombuffer(crow.image_bytes, dtype=np.uint8).reshape(
                crow.image_height, crow.image_width
            )
            record.carriers[crow.role_id] = RoleCarrier(
                role_id=crow.role_id,
                stego_image=image,
                wrapped_kappa=crow.wrapped_kappa,
                payload_len_bytes=crow.payload_len_bytes,
            )
        system.records[record.record_id] = record

    for rqrow in db.query(models.RecoveryRequestRow).order_by(models.RecoveryRequestRow.request_id).all():
        req = RecoveryRequest(
            record_id=rqrow.record_id,
            requester_role_id=rqrow.requester_role_id,
        )
        req.approvals = [bytes.fromhex(a) for a in rqrow.approvals_json]
        req.approving_roles = list(rqrow.approving_roles_json)
        system.recovery_requests[rqrow.request_id] = req

    return system
