from __future__ import annotations

import copy
import dataclasses

from fastapi import APIRouter, Depends, HTTPException

from rtasa.audit_log import AuditLog
from rtasa.system import RTASASystem

from .. import schemas
from ..deps import get_system

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/log", response_model=list)
def get_log(system: RTASASystem = Depends(get_system)):
    return [
        schemas.AuditEntryOut(
            seq=e.seq, event_type=e.event_type, actor_id=e.actor_id,
            data=e.data, timestamp=e.timestamp, entry_hash=e.entry_hash.hex(),
        )
        for e in system.audit_log.entries
    ]


@router.get("/verify", response_model=schemas.AuditVerifyResponse)
def verify(system: RTASASystem = Depends(get_system)):
    """Full RTASA verification: hash-chain linkage + per-entry ECDSA
    signatures + checkpoint-vs-witness comparison (Sec. IV-C)."""
    result = system.verify_audit_log()
    return schemas.AuditVerifyResponse(ok=result.ok, problems=result.problems)


@router.post("/tamper-demo", response_model=schemas.TamperDemoResponse)
def tamper_demo(system: RTASASystem = Depends(get_system)):
    """A live reproduction of Table IV's "insider edits their own entry"
    row -- for the web UI's demo, not a real mutation. Builds a *separate*
    in-memory `AuditLog` whose entries are a deep copy of the real log's,
    edits one entry's `data` the way a log-host attacker could (no access
    to anyone's private signing key), and verifies that scratch copy. The
    live `system.audit_log` is never touched or persisted -- this can be
    clicked repeatedly without affecting the real audit trail.
    """
    if not system.audit_log.entries:
        raise HTTPException(409, "no audit log entries yet -- issue or recover a record first")

    tampered_entries = copy.deepcopy(system.audit_log.entries)
    target = tampered_entries[-1]
    tampered_data = dict(target.data)
    tampered_data["__tampered__"] = "an attacker without actor's private key edited this field"
    tampered_entries[-1] = dataclasses.replace(target, data=tampered_data)
    # entry_hash and signature are deliberately left as they were -- an
    # attacker who can edit the stored row but does not hold the acting
    # role's ECDSA private key cannot produce a matching H_t/signature for
    # the edited content (that's exactly what `verify` below catches).

    scratch_log = AuditLog(checkpoint_interval=system.audit_log.checkpoint_interval)
    scratch_log.entries = tampered_entries
    scratch_log.checkpoints = system.audit_log.checkpoints  # shared, read-only here

    actor_keys = {rid: role.verifying_key() for rid, role in system.keystore.roles.items()}
    custodian_keys = {
        rid: role.verifying_key() for rid, role in system.keystore.custodians().items()
    }

    clean_result = system.verify_audit_log()
    tampered_result = scratch_log.verify(actor_keys, custodian_keys, system.witness_store)

    return schemas.TamperDemoResponse(
        clean_verify=schemas.AuditVerifyResponse(ok=clean_result.ok, problems=clean_result.problems),
        tampered_verify=schemas.AuditVerifyResponse(ok=tampered_result.ok, problems=tampered_result.problems),
        what_was_tampered=(
            f"entry seq={target.seq} ({target.event_type} by '{target.actor_id}'): "
            "added a field to its data without re-signing"
        ),
    )
