from __future__ import annotations

import base64
import io
import logging

import qrcode
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from rtasa.keystore import AuthorizationError, WeakPassphraseError
from rtasa.system import RTASASystem

from .. import email_otp, schemas
from ..deps import get_db, get_system, persist
from ..security_config import DEMO_MODE

router = APIRouter(prefix="/roles", tags=["roles"])
_logger = logging.getLogger("rtasa.notifications")


@router.post("", response_model=schemas.CreateRoleResponse)
def create_role(
    body: schemas.CreateRoleRequest,
    system: RTASASystem = Depends(get_system),
    db: Session = Depends(get_db),
):
    if body.role_id in system.keystore.roles:
        raise HTTPException(409, f"role '{body.role_id}' already exists")
    if body.is_custodian and (body.evaluation_point is None or body.evaluation_point == 0):
        raise HTTPException(422, "custodian roles need a nonzero evaluation_point (x_i)")

    try:
        identity = system.create_role(
            body.role_id, body.display_name, body.passphrase,
            is_custodian=body.is_custodian, evaluation_point=body.evaluation_point,
            email=body.email,
        )
    except WeakPassphraseError as exc:
        raise HTTPException(422, str(exc)) from exc
    persist(db, system)

    # Best-effort -- role creation above has already succeeded and been
    # persisted; a failed/unconfigured email must never undo that or surface
    # as an error here. The in-app amber credentials panel (Owner Portal) is
    # the reliable fallback either way.
    if body.notify_email and body.email:
        try:
            email_otp.send_role_credentials(
                to_email=body.email,
                display_name=body.display_name,
                role_label="Custodian" if body.is_custodian else "Requester",
                passphrase=body.passphrase,
            )
        except Exception as exc:  # noqa: BLE001
            _logger.warning("role-credentials email failed for %s: %s", body.role_id, exc)

    return schemas.CreateRoleResponse(
        role_id=identity.role_id,
        display_name=identity.display_name,
        email=identity.email,
        is_custodian=identity.is_custodian,
        evaluation_point=identity.evaluation_point,
    )


@router.get("", response_model=list)
def list_roles(system: RTASASystem = Depends(get_system)):
    return [
        {
            "role_id": r.role_id,
            "display_name": r.display_name,
            "email": r.email,
            "is_custodian": r.is_custodian,
            "evaluation_point": r.evaluation_point,
        }
        for r in system.keystore.roles.values()
    ]


@router.get("/{role_id}/otp", response_model=schemas.OTPResponse)
def get_current_otp(role_id: str, system: RTASASystem = Depends(get_system)):
    """Demo-mode-only convenience endpoint -- see `schemas.OTPResponse.note`.
    Answers 403 outright when RTASA_DEMO_MODE=0 (the enterprise-hardened
    posture): nobody, including the server operator, can ask the API for a
    live code there -- only a device enrolled via the provisioning endpoint
    below can produce one."""
    if not DEMO_MODE:
        raise HTTPException(
            403,
            "disabled outside demo mode (RTASA_DEMO_MODE=0) -- in an enterprise deployment, "
            "OTP codes are generated only on the role holder's own enrolled device, never "
            "disclosed by the server. See GET /roles/{role_id}/otp/provisioning.",
        )
    try:
        role = system.keystore.get(role_id)
    except AuthorizationError as exc:
        raise HTTPException(404, str(exc)) from exc
    return schemas.OTPResponse(role_id=role_id, otp=role.current_otp())


@router.get("/{role_id}/otp/provisioning", response_model=schemas.OTPProvisioningResponse)
def get_otp_provisioning(role_id: str, system: RTASASystem = Depends(get_system)):
    """Returns an otpauth:// URI + QR code for enrolling this role's TOTP
    secret on a real authenticator device -- available in both demo and
    enterprise mode, since it's how a production deployment would actually
    hand out the paper's 'OTP' factor (see `schemas.OTPProvisioningResponse.
    note` for the handling caveat)."""
    try:
        role = system.keystore.get(role_id)
    except AuthorizationError as exc:
        raise HTTPException(404, str(exc)) from exc

    uri = role.provisioning_uri()
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("ascii")

    return schemas.OTPProvisioningResponse(role_id=role_id, otpauth_uri=uri, qr_png_base64=qr_b64)
