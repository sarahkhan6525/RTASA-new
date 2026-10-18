from __future__ import annotations

import pytest

from rtasa.rsa_wrap import (
    MAX_ID_LEN,
    ShareUnwrapError,
    generate_role_rsa_keypair,
    unwrap_share,
    wrap_share,
)
from rtasa.shamir import Share


@pytest.fixture(scope="module")
def keypair_a():
    return generate_role_rsa_keypair()


@pytest.fixture(scope="module")
def keypair_b():
    return generate_role_rsa_keypair()


def test_wrap_unwrap_round_trip(keypair_a):
    share = Share(role_index=1, value=123456789, record_id="rec-1")
    z = wrap_share(share, keypair_a.public_key())
    out = unwrap_share(z, keypair_a, expected_record_id="rec-1")
    assert out == share


def test_wrong_private_key_fails(keypair_a, keypair_b):
    """Table III: 'Share opened with another role's key' -> OAEP decoding fails."""
    share = Share(role_index=1, value=42, record_id="rec-1")
    z = wrap_share(share, keypair_a.public_key())
    with pytest.raises(ShareUnwrapError):
        unwrap_share(z, keypair_b, expected_record_id="rec-1")


def test_replayed_share_under_different_id_rejected(keypair_a):
    """Table III: 'Share replayed under another id' -> id binding in eq. (5) rejects it."""
    share = Share(role_index=1, value=42, record_id="rec-1")
    z = wrap_share(share, keypair_a.public_key())
    with pytest.raises(ShareUnwrapError):
        unwrap_share(z, keypair_a, expected_record_id="rec-2")


def test_id_too_long_rejected(keypair_a):
    share = Share(role_index=1, value=1, record_id="x" * (MAX_ID_LEN + 1))
    with pytest.raises(ValueError):
        wrap_share(share, keypair_a.public_key())
