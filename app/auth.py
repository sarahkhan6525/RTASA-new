"""
Portal session tokens for the Owner/Custodian/Requester email-OTP login
flow (app/routers/auth.py). A role signs in with its passphrase and an
emailed one-time code (app/email_otp.py); once both check out, this module
issues a short-lived, signed token the frontend stores for the rest of the
browser tab's session (frontend/src/lib/session.ts).

This is deliberately separate from the paper's own credential-and-OTP gate
on issuance, approval, and recovery (rtasa/keystore.py), which this token
plays no part in and does not weaken -- it only identifies who is looking
at which portal.

Configuration (environment variable, same .env the SMTP settings live in):

    RTASA_SESSION_SECRET   the HMAC signing key for session tokens. If
                            unset, a random key is generated at process
                            start -- fine for local development, but it
                            means every server restart invalidates
                            existing sessions, so a real deployment should
                            set this explicitly.
"""

from __future__ import annotations

import os
import secrets
import time

import jwt

SESSION_TTL_SECONDS = 60 * 60 * 8  # 8 hours
_ALGORITHM = "HS256"

_env_secret = os.environ.get("RTASA_SESSION_SECRET", "").strip()
_SECRET = _env_secret if _env_secret else secrets.token_urlsafe(32)


class InvalidSessionError(Exception):
    """Raised when a session token is missing, malformed, expired, or
    signed with a different secret."""


def issue_session_token(role_id: str, display_name: str, is_custodian: bool) -> str:
    """Return a signed, time-limited session token for a role that has
    just completed passphrase + email-OTP login."""
    now = int(time.time())
    payload = {
        "role_id": role_id,
        "display_name": display_name,
        "is_custodian": is_custodian,
        "iat": now,
        "exp": now + SESSION_TTL_SECONDS,
    }
    return jwt.encode(payload, _SECRET, algorithm=_ALGORITHM)


def decode_session_token(token: str) -> dict:
    """Verify and decode a session token issued by `issue_session_token`.
    Raises `InvalidSessionError` if the token is missing, malformed,
    expired, or does not verify against this process's signing key."""
    try:
        return jwt.decode(token, _SECRET, algorithms=[_ALGORITHM])
    except jwt.PyJWTError as exc:
        raise InvalidSessionError(str(exc)) from exc
