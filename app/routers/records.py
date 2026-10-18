from __future__ import annotations

import base64
import io

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from PIL import Image
from sqlalchemy.orm import Session

from carriers.generate_carriers import make_synthetic_cover
from rtasa.keystore import AccountLockedError, AuthenticationError
from rtasa.system import RTASASystem

from .. import schemas
from ..deps import get_db, get_system, persist

router = APIRouter(prefix="/records", tags=["records"])


@router.post("/issue", response_model=schemas.IssueRecordResponse)
def issue(
    body: schemas.IssueRecordRequest,
    system: RTASASystem = Depends(get_system),
    db: Session = Depends(get_db),
):
    if body.record_id in system.records:
        raise HTTPException(409, f"record '{body.record_id}' already exists")
    try:
        message = base64.b64decode(body.message_base64)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(422, f"message_base64 is not valid base64: {exc}") from exc

    # One fresh synthetic cover per custodian per record -- "Gi is stored
    # among ordinary images of the same source" (Sec. IV-B). A production
    # deployment would draw from a real pool of innocuous images instead.
    cover_images = {
        rid: make_synthetic_cover(seed=hash((body.record_id, rid)) & 0xFFFFFFFF)
        for rid in body.custodian_role_ids
    }

    try:
        record = system.issue(
            owner_role_id=body.owner_role_id,
            owner_passphrase=body.owner_passphrase,
            owner_otp=body.owner_otp,
            record_id=body.record_id,
            message=message,
            custodian_role_ids=body.custodian_role_ids,
            threshold=body.threshold,
            cover_images=cover_images,
            entitled_requesters=body.entitled_requesters,
        )
    except AccountLockedError as exc:
        raise HTTPException(429, str(exc)) from exc
    except AuthenticationError as exc:
        raise HTTPException(401, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc

    persist(db, system)
    return schemas.IssueRecordResponse(
        record_id=record.record_id,
        threshold=record.threshold,
        custodian_role_ids=list(record.custodian_role_ids),
        feldman_commitments=record.commitments.to_hex_list(),
    )


@router.get("/{record_id}")
def get_record(record_id: str, system: RTASASystem = Depends(get_system)):
    record = system.records.get(record_id)
    if record is None:
        raise HTTPException(404, f"record '{record_id}' not found")
    return {
        "record_id": record.record_id,
        "threshold": record.threshold,
        "custodian_role_ids": list(record.custodian_role_ids),
        "entitled_requesters": sorted(record.entitled_requesters),
    }


@router.get("/{record_id}/carrier/{role_id}")
def get_carrier_image(record_id: str, role_id: str, system: RTASASystem = Depends(get_system)):
    """Serves the actual stego carrier G_i (eq. 6, layer S) for one
    custodian role, straight from memory -- not a mockup. This exists for
    the web UI (`webui/`) so a demo can show the embedded share really is
    just an ordinary-looking PNG, not a separate "secret file." Read-only;
    never exposes kappa_i or the wrapped share itself, only the carrier
    image a custodian would see."""
    record = system.records.get(record_id)
    if record is None:
        raise HTTPException(404, f"record '{record_id}' not found")
    try:
        carrier = record.carrier_for(role_id)
    except KeyError:
        raise HTTPException(404, f"role '{role_id}' holds no carrier for '{record_id}'")

    buf = io.BytesIO()
    Image.fromarray(carrier.stego_image, mode="L").save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")
