"""
Enterprise-hardening configuration flags, kept in one small module so the
posture of a given deployment is visible at a glance.

RTASA_DEMO_MODE (default ON):
    When on, `GET /roles/{id}/otp` (app/routers/roles.py) will hand back a
    role's current TOTP code -- useful for a live thesis/demo walkthrough
    where nobody has a real authenticator app enrolled, exactly the
    tradeoff `RoleIdentity.current_otp()`'s own docstring describes. When
    off, that endpoint always answers 403: nobody, including the server
    operator, can ask the API for a live code. Use `GET
    /roles/{id}/otp/provisioning` once at role creation instead (an
    otpauth:// URI + QR code) to enroll the secret on a real device --
    Google/Microsoft/1Password Authenticator, or `scripts/authenticator.py`
    for testing -- and from then on only that device can produce codes.

    Flip this off (RTASA_DEMO_MODE=0) to see the system behave the way an
    actual enterprise deployment would: the "OTP" factor genuinely requires
    possessing a second, server-independent device, which is the entire
    point of a second factor.

RTASA_SECURITY_LOG (default ./security_events.log):
    Where failed-authentication / lockout events (rtasa.security logger)
    are written, as JSON lines. Deliberately a conventional log file, not
    part of the paper's signed audit chain -- see the comment above
    `security_logger` in rtasa/keystore.py for why.
"""

from __future__ import annotations

import os


def _flag(name: str, default: str) -> bool:
    return os.environ.get(name, default).strip().lower() not in ("0", "false", "off", "")


DEMO_MODE = _flag("RTASA_DEMO_MODE", "1")
SECURITY_LOG_PATH = os.environ.get("RTASA_SECURITY_LOG", "./security_events.log")
