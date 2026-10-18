"""Read-only aggregation endpoints for the product-style frontend
(`frontend/`). These compute real numbers from the live `RTASASystem` --
no stored/fabricated statistics, nothing cached from the paper. They add
no new state and perform no cryptographic operations of their own; they
just summarize what the existing routers already track in memory."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from rtasa.system import RTASASystem

from ..deps import get_system

router = APIRouter(tags=["dashboard"])


@router.get("/records")
def list_records(system: RTASASystem = Depends(get_system)):
    out = []
    for record in system.records.values():
        out.append(
            {
                "record_id": record.record_id,
                "owner_role_id": record.owner_role_id,
                "threshold": record.threshold,
                "n": len(record.custodian_role_ids),
                "custodian_role_ids": list(record.custodian_role_ids),
                "entitled_requesters": sorted(record.entitled_requesters),
            }
        )
    return out


@router.get("/recovery/requests")
def list_recovery_requests(system: RTASASystem = Depends(get_system)):
    out = []
    for request_id, req in system.recovery_requests.items():
        record = system.records.get(req.record_id)
        threshold = record.threshold if record else None
        approvals = len(req.approvals)
        out.append(
            {
                "request_id": request_id,
                "record_id": req.record_id,
                "requester_role_id": req.requester_role_id,
                "approving_roles": list(req.approving_roles),
                "approvals_so_far": approvals,
                "threshold": threshold,
                "threshold_met": threshold is not None and approvals >= threshold,
            }
        )
    return out


@router.get("/dashboard/summary")
def dashboard_summary(system: RTASASystem = Depends(get_system)):
    custodians = system.keystore.custodians()
    verify_result = system.verify_audit_log()

    records = list(system.records.values())
    # "current" threshold shown on the dashboard = the most recently issued
    # record's (k, n) -- there's no single global threshold, each record
    # picks its own at issuance time (Sec. IV-B).
    latest = records[-1] if records else None

    pending = 0
    for req in system.recovery_requests.values():
        record = system.records.get(req.record_id)
        if record is not None and len(req.approvals) < record.threshold:
            pending += 1

    return {
        "protected_records": len(records),
        "active_custodians": len(custodians),
        "threshold": {"k": latest.threshold, "n": len(latest.custodian_role_ids)} if latest else None,
        "pending_requests": pending,
        "audit_integrity_ok": verify_result.ok,
        "audit_problems": verify_result.problems,
        "audit_entries": len(system.audit_log.entries),
    }
