"""
Portal login endpoints -- the email-OTP front door described in
app/auth.py's module docstring. Separate from the paper's own
credential-and-OTP gate on issuance/approval/recovery, which is untouched.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from rtasa.keystore import AuthorizationError
from rtasa.system import RTASASystem

from .. import email_otp
from ..auth import issue_session_token
from ..deps import get_db, get_system

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    email: str
    passphrase: str


class LoginResponse(BaseModel):
    role_id: str
    display_name: str
    email_hint: str
    sent: bool = True


class VerifyRequest(BaseModel):
    role_id: str
    code: str


class VerifyResponse(BaseModel):
    token: str
    role_id: str
    display_name: str
    is_custodian: bool
    expires_in: int


def _mask_email(addr: str) -> str:
    if "@" not in addr:
        return "***"
    name, _, domain = addr.partition("@")
    visible = name[:2]
    return f"{visible}{'*' * max(len(name) - 2, 1)}@{domain}"


@router.post("/login", response_model=LoginResponse)
def login(
    body: LoginRequest,
    system: RTASASystem = Depends(get_system),
):
    """Looks a role up by its registered email (not by the internal
    role_id -- a real person signing in knows their own email, not a
    generated id like 'doctor-5gss'). If more than one role happens to
    share an email, the one whose passphrase actually matches wins."""
    email_norm = body.email.strip().lower()
    candidates = [
        r for r in system.keystore.roles.values()
        if (r.email or "").strip().lower() == email_norm
    ]
    if not candidates:
        raise HTTPException(404, f"no role is registered with email '{body.email}'")

    role = next((r for r in candidates if r.check_passphrase(body.passphrase)), None)
    if role is None:
        raise HTTPException(401, "bad passphrase")

    try:
        email_otp.send_login_otp(role.role_id, role.display_name, role.email)
    except email_otp.EmailNotConfiguredError as exc:
        raise HTTPException(503, str(exc)) from exc
    except email_otp.EmailSendError as exc:
        raise HTTPException(502, str(exc)) from exc

    return LoginResponse(
        role_id=role.role_id, display_name=role.display_name, email_hint=_mask_email(role.email)
    )


@router.post("/verify", response_model=VerifyResponse)
def verify(
    body: VerifyRequest,
    system: RTASASystem = Depends(get_system),
):
    try:
        role = system.keystore.get(body.role_id)
    except AuthorizationError as exc:
        raise HTTPException(404, str(exc)) from exc

    if not email_otp.verify_login_otp(role.role_id, body.code):
        raise HTTPException(401, "bad or expired code")

    token = issue_session_token(
        role_id=role.role_id, display_name=role.display_name, is_custodian=role.is_custodian
    )
    from ..auth import SESSION_TTL_SECONDS

    return VerifyResponse(
        token=token,
        role_id=role.role_id,
        display_name=role.display_name,
        is_custodian=role.is_custodian,
        expires_in=SESSION_TTL_SECONDS,
    )
