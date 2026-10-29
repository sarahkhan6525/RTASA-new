from __future__ import annotations

import base64
import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from rtasa.keystore import AccountLockedError, AuthenticationError, AuthorizationError
from rtasa.rsa_wrap import ShareUnwrapError
from rtasa.shamir import ShareVerificationError
from rtasa.system import RTASASystem

from .. import email_otp, schemas
from ..deps import get_db, get_system, persist

_logger = logging.getLogger("rtasa.notifications")

router = APIRouter(prefix="/recovery", tags=["recovery"])


@router.post("/request", response_model=dict)
def start_recovery(
    body: schemas.StartRecoveryRequest,
    system: RTASASystem = Depends(get_system),
    db: Session = Depends(get_db),
):
    if body.record_id not in system.records:
        raise HTTPException(404, f"record '{body.record_id}' not found")
    if body.request_id in system.recovery_requests:
        raise HTTPException(409, f"request_id '{body.request_id}' already in use")
    try:
        system.start_recovery(
            body.request_id,
            record_id=body.record_id,
            requester_role_id=body.requester_role_id,
            requester_passphrase=body.requester_passphrase,
            requester_otp=body.requester_otp,
        )
    except AccountLockedError as exc:
        raise HTTPException(429, str(exc)) from exc
    except AuthenticationError as exc:
        raise HTTPException(401, str(exc)) from exc
    except AuthorizationError as exc:
        raise HTTPException(403, str(exc)) from exc
    persist(db, system)

    # Best-effort notification to every custodian on this record -- the
    # in-app pending-requests list (Custodian portal) is the reliable path;
    # this is a convenience on top, so a failed send must never fail the
    # recovery-request call itself.
    record = system.records[body.record_id]
    requester = system.keystore.get(body.requester_role_id)
    for custodian_id in record.custodian_role_ids:
        try:
            custodian = system.keystore.get(custodian_id)
        except AuthorizationError:
            continue
        if not custodian.email:
            continue
        try:
            email_otp.send_recovery_notification(
                to_email=custodian.email,
                custodian_name=custodian.display_name,
                record_id=body.record_id,
                requester_name=requester.display_name,
                requester_role_id=body.requester_role_id,
                requester_email=requester.email,
            )
        except Exception as exc:  # noqa: BLE001 -- never let a notification failure break the request
            _logger.warning("recovery notification email failed for %s: %s", custodian_id, exc)

    return {"request_id": body.request_id, "status": "requested"}


@router.post("/approve", response_model=schemas.ApproveResponse)
def approve(
    body: schemas.ApproveRequest,
    system: RTASASystem = Depends(get_system),
    db: Session = Depends(get_db),
):
    if body.request_id not in system.recovery_requests:
        raise HTTPException(404, f"recovery request '{body.request_id}' not found")
    try:
        system.approve(
            body.request_id,
            custodian_role_id=body.custodian_role_id,
            custodian_passphrase=body.custodian_passphrase,
            custodian_otp=body.custodian_otp,
        )
    except AccountLockedError as exc:
        raise HTTPException(429, str(exc)) from exc
    except AuthenticationError as exc:
        raise HTTPException(401, str(exc)) from exc
    except AuthorizationError as exc:
        # Also covers a custodian double-approving the same request
        # (rtasa/recovery.py's approve_share now rejects that as an
        # AuthorizationError) -- surfaced here as a clean 403 rather than
        # letting a duplicate share slip through to recover_record.
        raise HTTPException(403, str(exc)) from exc
    except (ShareUnwrapError, ShareVerificationError) as exc:
        raise HTTPException(400, str(exc)) from exc

    persist(db, system)
    req = system.recovery_requests[body.request_id]
    return schemas.ApproveResponse(
        request_id=body.request_id,
        custodian_role_id=body.custodian_role_id,
        approvals_so_far=len(req.approvals),
    )


@router.post("/recover", response_model=schemas.RecoverResponse)
def recover(
    body: schemas.RecoverRequest,
    system: RTASASystem = Depends(get_system),
    db: Session = Depends(get_db),
):
    if body.request_id not in system.recovery_requests:
        raise HTTPException(404, f"recovery request '{body.request_id}' not found")
    req = system.recovery_requests[body.request_id]
    try:
        message = system.recover(
            body.request_id,
            requester_passphrase=body.requester_passphrase,
            requester_otp=body.requester_otp,
        )
    except AccountLockedError as exc:
        raise HTTPException(429, str(exc)) from exc
    except AuthenticationError as exc:
        raise HTTPException(401, str(exc)) from exc
    except (ShareUnwrapError, ShareVerificationError) as exc:
        raise HTTPException(400, str(exc)) from exc
    except ValueError as exc:
        # Defense in depth: rtasa/shamir.py's reconstruct_secret raises a
        # bare ValueError if it's ever handed duplicate share indices.
        # approve_share now refuses a duplicate approval before it can
        # reach this point, so this should be unreachable in practice --
        # but if it ever does happen, a clean 400 beats an unhandled 500.
        raise HTTPException(400, str(exc)) from exc

    persist(db, system)
    return schemas.RecoverResponse(
        record_id=req.record_id, message_base64=base64.b64encode(message).decode("ascii")
    )
