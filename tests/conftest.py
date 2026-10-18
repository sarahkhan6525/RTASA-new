from __future__ import annotations

import numpy as np
import pytest

from rtasa.keystore import RoleIdentity, RoleKeyStore


@pytest.fixture
def keystore():
    ks = RoleKeyStore()
    owner = RoleIdentity.create("owner", "Data Owner", "owner-pass-123")
    ks.add(owner)
    for i, rid in enumerate(["custodian_1", "custodian_2", "custodian_3"], start=1):
        ks.add(
            RoleIdentity.create(
                rid, rid, f"{rid}-pass", is_custodian=True, evaluation_point=i
            )
        )
    requester = RoleIdentity.create("requester_q", "Requester Q", "requester-pass")
    ks.add(requester)
    other = RoleIdentity.create("outsider", "Outsider", "outsider-pass")
    ks.add(other)
    return ks


@pytest.fixture
def custodian_role_ids():
    return ["custodian_1", "custodian_2", "custodian_3"]


@pytest.fixture
def cover_images(custodian_role_ids):
    rng = np.random.default_rng(1234)
    return {
        rid: rng.integers(0, 256, size=(512, 768), dtype=np.uint8)
        for rid in custodian_role_ids
    }


def otp_for(keystore, role_id: str) -> str:
    return keystore.get(role_id).current_otp()
