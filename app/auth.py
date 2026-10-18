"""
Session login for the Owner / Custodian / Requester portals.

This is a *front-door* identity layer, separate from the paper's own
credential-and-OTP authentication that still gates every actual
cryptographic action (issuance, approval, recovery -- see
rtasa/keystore.py's `RoleIdentity.authenticate`, unchanged). Logging in
here just establishes "who is this browser tab acting as" so the frontend
can route to the right portal and stop asking the person to re-pick their
role from a dropdown; it does not itself unwrap any key material.

Two-step login, matching what a non-technical audience recognizes as
"email OTP sign-in":

    POST /auth/login   {role_id, passphrase}       -> checks the passphrase,
                                                        emails a 6-digit code
    POST /auth/verify  {role_id, code}              -> checks the code,
                                                        issues a session token

The session token is a signed JWT (HS256) carrying role_id / display_name
/ is_custodian / an expiry -- signed with a local secret, generated once
and cached the same way rtasa/secrets_vault.py caches its AES master key
(env var override, else an auto-created local file), so it survives
backend restarts but is never hardcoded or committed.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Optional

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

SESSION_TTL_SECONDS = 2 * 60 * 60  # 2 hours -- plenty for one sitting/demo
_ALGO = "HS256"

_cached_secret: Optional[bytes] = None


def _secret_path() -> Path:
    return Path(os.environ.get("RTASA_SESSION_SECRET_FILE", "./.rtasa_session_secret"))


def _load_or_create_secret() -> bytes:
    global _cached_secret
    if _cached_secret is not None:
        return _cached_secret

    env_secret = os.environ.get("RTASA_SESSION_SECRET")
    if env_secret:
        _cached_secret = env_secret.encode("utf-8")
        return _cached_secret

    path = _secret_path()
    if path.exists():
        _cached_secret = path.read_bytes()
        return _cached_secret

    secret = os.urandom(32)
    path.write_bytes(secret)
    try:
        path.chmod(0o600)
    except OSError:
        pass  # best-effort on platforms where chmod semantics differ
    _cached_secret = secret
    return _cached_secret


def issue_session_token(role_id: str, display_name: str, is_custodian: bool) -> str:
    now = int(time.time())
    payload = {
        "role_id": role_id,
        "display_name": display_name,
        "is_custodian": is_custodian,
        "iat": now,
        "exp": now + SESSION_TTL_SECONDS,
    }
    return jwt.encode(payload, _load_or_create_secret(), algorithm=_ALGO)


class SessionClaims:
    def __init__(self, role_id: str, display_name: str, is_custodian: bool):
        self.role_id = role_id
        self.display_name = display_name
        self.is_custodian = is_custodian


def decode_session_token(token: str) -> SessionClaims:
    try:
        payload = jwt.decode(token, _load_or_create_secret(), algorithms=[_ALGO])
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(401, "session expired -- please sign in again") from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(401, "invalid session token") from exc
    return SessionClaims(
        role_id=payload["role_id"],
        display_name=payload["display_name"],
        is_custodian=payload["is_custodian"],
    )


_bearer = HTTPBearer(auto_error=True)


def get_current_session(
    creds: HTTPAuthorizationCredentials = Depends(_bearer),
) -> SessionClaims:
    """FastAPI dependency: use on any endpoint that should only be callable
    by a signed-in portal session, e.g. `session: SessionClaims =
    Depends(get_current_session)`."""
    return decode_session_token(creds.credentials)
