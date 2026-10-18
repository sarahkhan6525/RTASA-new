"""
RTASA backend -- FastAPI service wrapping the five-layer prototype
described in the paper (role-based threshold-access hybrid encryption and
steganography with a tamper-evident, custodian-witnessed audit log).

Run locally with:

    uvicorn app.main:app --reload

Then open http://127.0.0.1:8000/docs for interactive Swagger UI.
"""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv

# Must run before any of this project's own modules are imported below --
# security_config.py and email_otp.py both read os.environ at import/call
# time, so SMTP_*/RTASA_* values from a local .env (see .env.example) need
# to already be in the process environment by then.
#
# Resolved relative to this file (not the current working directory) so it
# finds the project-root .env regardless of where `python cli.py serve` /
# `uvicorn` was launched from, and override=True so a stale/blank SMTP_*
# value left over in the shell's own environment from an earlier run can't
# silently shadow a freshly-edited .env.
_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=_ENV_PATH, override=True)

# One-line, startup-time, non-secret status print -- so "email isn't
# configured" in the browser has an immediate, obvious answer in this
# terminal instead of another round of guessing: did .env get found at all,
# and which of the three required SMTP_* values (if any) are still missing.
# Never prints the password itself, only whether it's present.
import os as _os  # local import; only needed for this diagnostic block

if not _ENV_PATH.exists():
    print(f"[RTASA] no .env file found at {_ENV_PATH} -- email-OTP login will stay disabled "
          f"until you create one (copy .env.example to .env there).", flush=True)
else:
    _missing = [
        name for name in ("SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD")
        if not _os.environ.get(name)
    ]
    if _missing:
        print(f"[RTASA] .env found at {_ENV_PATH}, but still missing: {', '.join(_missing)} "
              f"-- email-OTP login will refuse until all three are filled in.", flush=True)
    else:
        print(f"[RTASA] .env found at {_ENV_PATH} -- SMTP_HOST/SMTP_USERNAME/SMTP_PASSWORD "
              f"are all set, sending as {_os.environ.get('SMTP_USERNAME')!r}.", flush=True)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .db import SessionLocal, init_db
from .persistence import load_system
from .routers import audit, auth, dashboard, records, recovery, roles, security_tests
from .security_config import DEMO_MODE, SECURITY_LOG_PATH


class _JSONLFormatter(logging.Formatter):
    """One JSON object per line -- auth_failed / auth_locked_out /
    auth_rejected_locked events from rtasa.keystore.security_logger,
    deliberately separate from the paper's signed audit chain (see the
    comment above `security_logger` in rtasa/keystore.py)."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "time": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "event": record.getMessage(),
        }
        for key in ("role_id", "reason", "attempt", "remaining_s", "lockout_s"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        return json.dumps(payload)


def _configure_security_logging() -> None:
    logger = logging.getLogger("rtasa.security")
    if logger.handlers:
        return  # already configured (e.g. app reloaded, or tests imported main twice)
    handler = logging.FileHandler(SECURITY_LOG_PATH)
    handler.setFormatter(_JSONLFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    _configure_security_logging()
    init_db()
    db = SessionLocal()
    try:
        app.state.system = load_system(db)
    finally:
        db.close()
    yield


app = FastAPI(
    title="RTASA",
    description=(
        "Role-Based Threshold-Access Hybrid Encryption and Steganography "
        "with Tamper-Evident Audit Trails -- reference backend for the paper's prototype."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(auth.router)
app.include_router(roles.router)
app.include_router(records.router)
app.include_router(recovery.router)
app.include_router(audit.router)
app.include_router(dashboard.router)
app.include_router(security_tests.router)

# Local-only, demo-grade CORS so the React dev server (frontend/, Vite's
# default http://localhost:5173) can call this API directly in dev.
# Read-only / local-dev convenience, not a hardened production policy.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Demo web UI (webui/index.html) -- same origin as the API, so it calls
# /roles, /records/..., etc. directly with no CORS setup needed. Purely a
# presentation layer over the routers above; it holds none of its own
# state and performs no cryptography itself.
_WEBUI_DIR = Path(__file__).resolve().parent.parent / "webui"
if _WEBUI_DIR.is_dir():
    app.mount("/ui", StaticFiles(directory=str(_WEBUI_DIR), html=True), name="ui")


@app.get("/", tags=["meta"])
def root():
    return {
        "name": "RTASA",
        "layers": {
            "E": "AES-256-GCM payload encryption (eq. 2)",
            "A": "Role-bound RSA-OAEP share wrapping (eq. 5)",
            "T": "Feldman-verifiable Shamir (k, n) secret sharing (eq. 3, 4, 9)",
            "S": "LSB-matching steganographic embedding (eq. 6)",
            "L": "Signed, custodian-witnessed, hash-chained audit log (eq. 7, Sec. IV-C)",
        },
        "docs": "/docs",
        "ui": "/ui/" if _WEBUI_DIR.is_dir() else None,
        "security": {
            "demo_mode": DEMO_MODE,
            "note": (
                "demo_mode=true means GET /roles/{id}/otp will hand back a live TOTP code, "
                "for a walkthrough with no real authenticator enrolled. Set RTASA_DEMO_MODE=0 "
                "for an enterprise-hardened posture: that endpoint then always 403s, and the "
                "OTP factor can only come from a real device enrolled via "
                "GET /roles/{id}/otp/provisioning."
            ),
        },
    }
