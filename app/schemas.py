"""Pydantic request/response models for the RTASA REST API."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class CreateRoleRequest(BaseModel):
    role_id: str
    display_name: str
    email: Optional[str] = Field(
        default=None,
        description="Required to use the email-OTP login flow (app/auth.py). Optional here so "
        "older demo-mode flows that never collect an email keep working.",
    )
    passphrase: str = Field(
        ..., min_length=12,
        description="Credential factor (Sec. IV-A/B). Min 12 chars, NIST SP 800-63B style "
        "(length over forced complexity); also checked against a small common-passphrase "
        "blocklist server-side.",
    )
    is_custodian: bool = False
    evaluation_point: Optional[int] = Field(
        default=None, description="x_i, required and must be > 0 for custodian roles"
    )
    notify_email: bool = Field(
        default=False,
        description="If true and `email` is set, best-effort-emails this role's passphrase to "
        "it right after creation (app/email_otp.py's send_role_credentials) -- the Owner "
        "Portal sets this for every custodian/requester it creates, so that person actually "
        "learns their own sign-in passphrase instead of only the Owner seeing it.",
    )


class CreateRoleResponse(BaseModel):
    role_id: str
    display_name: str
    email: Optional[str] = None
    is_custodian: bool
    evaluation_point: Optional[int]


class OTPResponse(BaseModel):
    role_id: str
    otp: str
    note: str = (
        "Demo-mode-only convenience endpoint (RTASA_DEMO_MODE=1, the default). A real "
        "deployment would never let the server hand back a custodian's current OTP -- it "
        "would be generated on that custodian's own device/authenticator, exactly like the "
        "paper's credential-and-OTP authentication step (Sec. IV-B) assumes. Set "
        "RTASA_DEMO_MODE=0 and this endpoint always refuses; enroll a real device via "
        "GET /roles/{role_id}/otp/provisioning instead."
    )


class OTPProvisioningResponse(BaseModel):
    role_id: str
    otpauth_uri: str
    qr_png_base64: str
    note: str = (
        "Scan this once into an authenticator app (Google/Microsoft/1Password Authenticator, "
        "or run scripts/authenticator.py against otpauth_uri for testing) to enroll this "
        "role's TOTP secret on a real device -- the server never computes or stores a live "
        "code from this point on in an enterprise deployment (RTASA_DEMO_MODE=0). Treat this "
        "response itself as sensitive: anyone who sees it can enroll their own authenticator "
        "for this role, so in production it should only ever be shown once, immediately after "
        "role creation, over a channel the real role holder controls."
    )


class IssueRecordRequest(BaseModel):
    owner_role_id: str
    owner_passphrase: str
    owner_otp: str
    record_id: str
    message_base64: str
    custodian_role_ids: list
    threshold: int
    entitled_requesters: list = Field(default_factory=list)


class IssueRecordResponse(BaseModel):
    record_id: str
    threshold: int
    custodian_role_ids: list
    feldman_commitments: list
    carriers_written_to: list = Field(
        default_factory=list, description="Carrier PNG files saved under ./carrier_output/"
    )


class StartRecoveryRequest(BaseModel):
    request_id: str
    record_id: str
    requester_role_id: str
    requester_passphrase: str
    requester_otp: str


class ApproveRequest(BaseModel):
    request_id: str
    custodian_role_id: str
    custodian_passphrase: str
    custodian_otp: str


class ApproveResponse(BaseModel):
    request_id: str
    custodian_role_id: str
    approvals_so_far: int


class RecoverRequest(BaseModel):
    request_id: str
    requester_passphrase: str
    requester_otp: str


class RecoverResponse(BaseModel):
    record_id: str
    message_base64: str


class AuditEntryOut(BaseModel):
    seq: int
    event_type: str
    actor_id: str
    data: dict
    timestamp: float
    entry_hash: str


class AuditVerifyResponse(BaseModel):
    ok: bool
    problems: list


class TamperDemoResponse(BaseModel):
    clean_verify: AuditVerifyResponse
    tampered_verify: AuditVerifyResponse
    what_was_tampered: str
    note: str = (
        "Nothing was actually changed in the real log -- this verifies a "
        "scratch, in-memory copy with one entry's data edited the way an "
        "attacker with log-host access (but no signing keys) could, "
        "exactly Table IV's threat model."
    )


class SecurityTestResult(BaseModel):
    id: str
    label: str
    mechanism: str
    group: str
    expect: str
    passed: bool
    detail: str


class SecurityTestBattery(BaseModel):
    results: list[SecurityTestResult]
    note: str = (
        "Every check above runs against a disposable role store, record, and audit "
        "log built fresh for this one request -- never the real system. Safe to "
        "run repeatedly; it cannot lock out a real custodian or touch the real "
        "audit trail."
    )
