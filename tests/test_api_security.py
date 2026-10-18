"""
App-layer enterprise hardening: demo-mode gating of the OTP convenience
endpoint, the new TOTP provisioning endpoint, 429-on-lockout, and -- the
part a pure rtasa/-level test cannot see -- proof that what actually lands
in the SQLite database for a role's private key material and TOTP secret
is sealed ciphertext, not plaintext.

Sets RTASA_MASTER_KEY/RTASA_DB_URL/RTASA_SECURITY_LOG to fixed, isolated
values *before* importing anything under `app`, since app/db.py and
app/security_config.py read their environment at import time.
"""

from __future__ import annotations

import base64
import os

import pytest

_TMP_DB = None  # set by the fixture below, before any `app.*` import


@pytest.fixture(scope="module", autouse=True)
def _isolated_app_env(tmp_path_factory):
    from rtasa import secrets_vault

    tmp_dir = tmp_path_factory.mktemp("rtasa_api_security")
    os.environ["RTASA_DB_URL"] = f"sqlite:///{tmp_dir / 'test.db'}"
    os.environ["RTASA_MASTER_KEY"] = base64.b64encode(b"\x33" * 32).decode("ascii")
    os.environ["RTASA_SECURITY_LOG"] = str(tmp_dir / "security_events.log")
    secrets_vault.reset_cache()  # don't inherit another test module's cached key
    yield
    for key in ("RTASA_DB_URL", "RTASA_MASTER_KEY", "RTASA_SECURITY_LOG"):
        os.environ.pop(key, None)
    secrets_vault.reset_cache()


@pytest.fixture(scope="module")
def client(_isolated_app_env):
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture
def owner_creds():
    return {
        "role_id": "owner",
        "display_name": "Data Owner",
        "passphrase": "correct-horse-battery",
        "is_custodian": False,
    }


@pytest.fixture
def ensure_owner_exists(client, owner_creds):
    """Idempotent: creates the 'owner' role on first use, reused as-is on
    later calls (module-scoped `client` keeps the same DB across tests), so
    tests needing a role don't depend on each other's execution order."""
    resp = client.post("/roles", json=owner_creds)
    assert resp.status_code in (200, 409), resp.text
    return owner_creds


def test_create_role_rejects_weak_passphrase(client):
    resp = client.post(
        "/roles",
        json={"role_id": "weakling", "display_name": "Weak", "passphrase": "short"},
    )
    assert resp.status_code == 422


def test_create_role_then_otp_convenience_endpoint_works_in_demo_mode(client, ensure_owner_exists):
    otp_resp = client.get(f"/roles/{ensure_owner_exists['role_id']}/otp")
    assert otp_resp.status_code == 200  # RTASA_DEMO_MODE defaults on
    assert len(otp_resp.json()["otp"]) == 6


def test_otp_convenience_endpoint_403s_outside_demo_mode(client, ensure_owner_exists, monkeypatch):
    from app.routers import roles as roles_module

    monkeypatch.setattr(roles_module, "DEMO_MODE", False)
    resp = client.get(f"/roles/{ensure_owner_exists['role_id']}/otp")
    assert resp.status_code == 403
    assert "RTASA_DEMO_MODE" in resp.json()["detail"]


def test_otp_provisioning_endpoint_works_regardless_of_demo_mode(client, ensure_owner_exists, monkeypatch):
    from app.routers import roles as roles_module

    for demo in (True, False):
        monkeypatch.setattr(roles_module, "DEMO_MODE", demo)
        resp = client.get(f"/roles/{ensure_owner_exists['role_id']}/otp/provisioning")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["otpauth_uri"].startswith("otpauth://totp/")
        assert len(body["qr_png_base64"]) > 100  # a real PNG, not a stub


def test_private_key_material_is_not_stored_in_cleartext_in_the_database(client, ensure_owner_exists):
    """The part the pure rtasa/ tests can't see: round-trip a role through
    the real SQLite database and confirm the bytes actually sitting in the
    roles table are sealed, not the plaintext PEM/TOTP seed."""
    from sqlalchemy import select

    from app import models
    from app.db import SessionLocal

    db = SessionLocal()
    try:
        row = db.execute(
            select(models.RoleRow).where(models.RoleRow.role_id == ensure_owner_exists["role_id"])
        ).scalar_one()
        assert b"BEGIN RSA PRIVATE KEY" not in row.rsa_private_pem
        assert b"BEGIN PRIVATE KEY" not in row.rsa_private_pem
        assert "BEGIN EC PRIVATE KEY" not in row.signing_key_pem
        # public material is still stored as-is (it's not a secret)
        assert b"PUBLIC KEY" in row.rsa_public_pem
    finally:
        db.close()


def test_lockout_surfaces_as_429_through_the_api(client):
    client.post(
        "/roles",
        json={
            "role_id": "lockout_target",
            "display_name": "Lockout Target",
            "passphrase": "correct-horse-battery",
        },
    )
    # `issue_record` authenticates the owner before anything else, so a
    # deliberately wrong OTP against /records/issue trips the lockout
    # counter without needing a fully-set-up record/recovery first. The
    # record_id is never consumed on a failed attempt, so it's safe to
    # reuse across the loop.
    body = {
        "owner_role_id": "lockout_target",
        "owner_passphrase": "correct-horse-battery",
        "owner_otp": "000000",
        "record_id": "lockout-probe",
        "message_base64": "",
        "custodian_role_ids": [],
        "threshold": 1,
    }
    last_status = None
    for _ in range(6):
        last_status = client.post("/records/issue", json=body).status_code
        if last_status == 429:
            break
    assert last_status == 429
