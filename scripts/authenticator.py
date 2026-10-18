#!/usr/bin/env python3
"""
A tiny simulated TOTP authenticator device.

Models exactly what `RoleIdentity.current_otp()`'s own docstring points
to -- "the custodian's own device/authenticator app" -- for testing the
enterprise-hardened posture (RTASA_DEMO_MODE=0) without a real phone. This
script runs entirely offline: it takes only the otpauth:// URI (or a raw
base32 secret) a role was enrolled with via
`GET /roles/{role_id}/otp/provisioning`, and prints the live 6-digit code,
exactly what Google/Microsoft/1Password Authenticator would show. It never
talks to the RTASA server, and the server never talks to it -- that
separation is the entire point of the "OTP" factor in "credential-and-OTP
authentication" (Sec. IV-B/D). Reuses `rtasa.keystore.totp_now`, the same
RFC 6238-style implementation the server itself verifies against, so a
code this script prints is a code the server will actually accept.

Usage:

    python scripts/authenticator.py "otpauth://totp/RTASA:custodian_1?secret=...."
    python scripts/authenticator.py --secret JBSWY3DPEHPK3PXP   # raw base32 secret
    python scripts/authenticator.py --once "otpauth://..."       # one code, then exit
"""

from __future__ import annotations

import argparse
import base64
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rtasa.keystore import TOTP_STEP_SECONDS, totp_now  # noqa: E402


def secret_from_uri(uri: str) -> bytes:
    parsed = urlparse(uri)
    if parsed.scheme != "otpauth":
        raise ValueError(f"not an otpauth:// URI: {uri!r}")
    qs = parse_qs(parsed.query)
    if "secret" not in qs:
        raise ValueError("otpauth URI has no 'secret' parameter")
    return _b32decode(qs["secret"][0])


def _b32decode(b32: str) -> bytes:
    padding = "=" * (-len(b32) % 8)
    return base64.b32decode(b32.upper() + padding)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("uri", nargs="?", help="otpauth:// provisioning URI")
    parser.add_argument("--secret", help="raw base32 TOTP secret, instead of a full URI")
    parser.add_argument("--once", action="store_true", help="print one code and exit")
    args = parser.parse_args()

    if not args.uri and not args.secret:
        parser.error("supply either an otpauth:// URI or --secret")

    secret = _b32decode(args.secret) if args.secret else secret_from_uri(args.uri)

    try:
        while True:
            now = time.time()
            code = totp_now(secret, when=now)
            remaining = TOTP_STEP_SECONDS - int(now) % TOTP_STEP_SECONDS
            print(f"{code}   (valid for {remaining}s)")
            if args.once:
                return 0
            time.sleep(1)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
