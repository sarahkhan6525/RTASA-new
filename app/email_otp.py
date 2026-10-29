"""
Email-delivered one-time login codes for the new role-login flow
(app/auth.py / the Owner-Custodian-Requester portal split).

This is intentionally a *different* OTP mechanism from rtasa.keystore's
TOTP factor -- the paper's own issuance/approval/recovery endpoints keep
using authenticator-app TOTP codes exactly as before, untouched. This one
is a short random code generated here on the server, emailed to the
role's registered address, and checked back against what the server
stored -- the ordinary "email OTP" login pattern a non-technical audience
recognizes immediately, which is what was asked for for the sign-in step
of the new Owner/Custodian/Requester portals.

Configuration (environment variables -- put these in a local `.env` file
at the project root; see `.env.example`, and NEVER commit a real `.env`):

    SMTP_HOST       e.g. smtp.gmail.com
    SMTP_PORT       587 (STARTTLS, the default) or 465 (implicit TLS) --
                    if 587 fails with "Connection unexpectedly closed"
                    (common on networks that interfere with the STARTTLS
                    upgrade), switch to 465 instead
    SMTP_USERNAME   the sending Gmail address
    SMTP_PASSWORD   a Gmail "App Password" (NOT your real password --
                    generate one at https://myaccount.google.com/apppasswords,
                    requires 2-Step Verification to be turned on first)
    SMTP_FROM       optional, defaults to SMTP_USERNAME

If these aren't set, /auth/login returns a clear 503 instead of crashing,
so the rest of the app keeps working while email is being set up.
"""

from __future__ import annotations

import os
import secrets
import smtplib
import time
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Dict

from .security_config import DEMO_MODE

OTP_LENGTH = 6
OTP_TTL_SECONDS = 5 * 60
MAX_VERIFY_ATTEMPTS = 5


@dataclass
class _PendingOtp:
    code: str
    expires_at: float
    attempts: int = 0


# In-memory only -- a login code is short-lived (5 minutes) and doesn't
# need to survive a server restart, unlike everything in rtasa.db.
_pending: Dict[str, _PendingOtp] = {}


class EmailNotConfiguredError(Exception):
    """Raised when the role has no email on file, or the server has no
    SMTP credentials configured yet. Distinct from EmailSendError so the
    API can return a clear, different message for "not set up" vs
    "tried and failed"."""


class EmailSendError(Exception):
    """Raised when SMTP is configured but the actual send attempt failed
    (bad credentials, network/port blocked, etc)."""


def _smtp_configured() -> bool:
    return bool(
        os.environ.get("SMTP_HOST")
        and os.environ.get("SMTP_USERNAME")
        and os.environ.get("SMTP_PASSWORD")
    )


def _send_via_smtp(msg: EmailMessage) -> None:
    """Shared connect-login-send for all three email kinds below. Port 465
    is "implicit TLS" (encrypted from the very first byte, via SMTP_SSL);
    every other port (587 by default) is "STARTTLS" (connects in the
    clear, then upgrades). Some networks -- hotel/campus wifi, some
    antivirus/firewall software doing SSL inspection -- interfere with the
    STARTTLS upgrade step specifically and drop the connection mid-handshake
    (smtplib surfaces that as "Connection unexpectedly closed"), while
    leaving a straight TLS-from-the-start connection on 465 alone. Picking
    the right one by port means a user who hits that on 587 can work around
    it just by changing SMTP_PORT=465 in their .env, with no code change."""
    host = os.environ["SMTP_HOST"]
    port = int(os.environ.get("SMTP_PORT", "587"))
    username = os.environ["SMTP_USERNAME"]
    password = os.environ["SMTP_PASSWORD"]

    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=15) as server:
            server.login(username, password)
            server.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=15) as server:
            server.starttls()
            server.login(username, password)
            server.send_message(msg)


def send_login_otp(role_id: str, display_name: str, to_email: str) -> None:
    """Generates a fresh 6-digit code, remembers it for this role_id, and
    emails it. Raises EmailNotConfiguredError / EmailSendError instead of
    ever silently doing nothing -- except the DEMO_MODE fallback just
    below, which mirrors the existing GET /roles/{id}/otp escape hatch for
    the TOTP factor (security_config.py): with no SMTP configured, a real
    deployment (DEMO_MODE=0) still hard-stops here, but a local/demo run
    prints the code to the server's own terminal instead of blocking sign-in
    entirely on setting up a mail server."""
    if not to_email:
        raise EmailNotConfiguredError(
            f"role '{role_id}' has no email on file -- it can't use the email login flow"
        )
    if not _smtp_configured():
        if DEMO_MODE:
            code = "".join(secrets.choice("0123456789") for _ in range(OTP_LENGTH))
            _pending[role_id] = _PendingOtp(code=code, expires_at=time.time() + OTP_TTL_SECONDS)
            print(
                f"[demo-mode email-OTP fallback -- SMTP not configured] "
                f"{role_id} <{to_email}> code = {code}",
                flush=True,
            )
            return
        raise EmailNotConfiguredError(
            "email sending isn't configured on this server yet -- set SMTP_HOST / "
            "SMTP_USERNAME / SMTP_PASSWORD in a .env file at the project root (see "
            ".env.example) and restart the backend"
        )

    code = "".join(secrets.choice("0123456789") for _ in range(OTP_LENGTH))
    _pending[role_id] = _PendingOtp(code=code, expires_at=time.time() + OTP_TTL_SECONDS)

    msg = EmailMessage()
    msg["Subject"] = f"Your RTASA sign-in code: {code}"
    msg["From"] = os.environ.get("SMTP_FROM", os.environ["SMTP_USERNAME"])
    msg["To"] = to_email
    msg.set_content(
        f"Hi {display_name},\n\n"
        f"Your one-time RTASA sign-in code is: {code}\n\n"
        f"It expires in {OTP_TTL_SECONDS // 60} minutes. If you didn't request this, "
        f"you can safely ignore this email.\n"
    )

    try:
        _send_via_smtp(msg)
    except Exception as exc:  # noqa: BLE001 -- surface *any* SMTP failure clearly, never swallow it
        if DEMO_MODE:
            # SMTP *is* configured here, but the live attempt still failed
            # (network blocking outbound mail, a transient Gmail hiccup,
            # etc). The code above was already generated and is sitting in
            # _pending regardless of whether the email made it out, so in
            # DEMO_MODE this is recoverable, not fatal: print it the same
            # way the "SMTP not configured at all" branch above does, and
            # let sign-in proceed, instead of leaving the only copy of a
            # valid code trapped in memory with no way to read it. A real
            # deployment (DEMO_MODE=0) still raises below -- there, a
            # failed send must surface as a failure, not be papered over.
            print(
                f"[demo-mode email-OTP fallback -- send failed ({exc})] "
                f"{role_id} <{to_email}> code = {code}",
                flush=True,
            )
            return
        raise EmailSendError(f"could not send the sign-in email: {exc}") from exc


def send_recovery_notification(
    *,
    to_email: str,
    custodian_name: str,
    record_id: str,
    requester_name: str,
    requester_role_id: str | None = None,
    requester_email: str | None = None,
) -> None:
    """Best-effort FYI email -- carries no code, just tells a custodian a
    request is waiting on them, who it's from, and how to reach them.
    Called from app/routers/recovery.py right after a request is created;
    failures here are caught and logged by the caller, never allowed to fail
    the recovery-request API call itself, since the in-app notification (the
    Custodian portal's own pending-requests list) is the reliable path and
    this is a convenience on top."""
    if not to_email or not _smtp_configured():
        return

    who_lines = f"  Name:  {requester_name}\n"
    if requester_role_id:
        who_lines += f"  Role:  {requester_role_id} (requester)\n"
    if requester_email:
        who_lines += f"  Email: {requester_email}\n"

    msg = EmailMessage()
    msg["Subject"] = f"RTASA: a request needs your approval ({record_id})"
    msg["From"] = os.environ.get("SMTP_FROM", os.environ["SMTP_USERNAME"])
    msg["To"] = to_email
    msg.set_content(
        f"Hi {custodian_name},\n\n"
        f"The following requester has asked for access to record '{record_id}', which you "
        f"hold a share of:\n\n"
        f"{who_lines}\n"
        f"Please sign in to your RTASA Custodian portal to review and approve or decline.\n\n"
        f"(This is an informational notice only -- it contains no sign-in code. Log in "
        f"normally with your email and passphrase.)\n"
    )

    _send_via_smtp(msg)


def send_role_credentials(
    *, to_email: str, display_name: str, role_label: str, passphrase: str
) -> None:
    """Best-effort FYI email sent once, right when the Owner creates a new
    custodian/requester role (app/routers/roles.py, when the caller opts in
    via CreateRoleRequest.notify_email). Separate concern from the sign-in
    OTP above: this carries the role's actual passphrase, the one thing a
    real, separate person would otherwise have no way to learn, since
    today nothing else hands it to them automatically -- the Owner Portal
    previously only ever showed it to the Owner, once, in the UI.

    Deliberately doesn't raise on failure the way send_login_otp does --
    role creation itself must still succeed even if this email bounces;
    the caller wraps this in try/except and logs a warning instead."""
    if not to_email or not _smtp_configured():
        return

    msg = EmailMessage()
    msg["Subject"] = f"Your RTASA {role_label} account"
    msg["From"] = os.environ.get("SMTP_FROM", os.environ["SMTP_USERNAME"])
    msg["To"] = to_email
    msg.set_content(
        f"Hi {display_name},\n\n"
        f"You've been added to RTASA as a {role_label}.\n\n"
        f"Sign in with:\n"
        f"  Email:      {to_email}\n"
        f"  Passphrase: {passphrase}\n\n"
        f"On the sign-in page, choose \"I am a {role_label}\", enter the email and "
        f"passphrase above, then enter the one-time code that gets sent to this "
        f"inbox to finish signing in.\n\n"
        f"Keep this passphrase -- you'll need it again each time you sign in, "
        f"and to approve or request access once you're in.\n"
    )

    _send_via_smtp(msg)


def verify_login_otp(role_id: str, code: str) -> bool:
    """One-time: a correct verify (or running out of attempts/expiry)
    consumes the pending code so it can't be reused."""
    pending = _pending.get(role_id)
    if pending is None:
        return False
    if time.time() > pending.expires_at:
        del _pending[role_id]
        return False
    pending.attempts += 1
    if pending.attempts > MAX_VERIFY_ATTEMPTS:
        del _pending[role_id]
        return False
    if secrets.compare_digest(pending.code, code):
        del _pending[role_id]
        return True
    return False
