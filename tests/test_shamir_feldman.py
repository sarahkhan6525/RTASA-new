from __future__ import annotations

import dataclasses

import pytest
import secrets

from rtasa.curve import Q
from rtasa.shamir import (
    ShareVerificationError,
    require_valid_share,
    reconstruct_secret,
    split_secret,
    verify_share,
)


@pytest.mark.parametrize("k,n", [(2, 3), (3, 5), (5, 7)])
def test_any_k_shares_reconstruct(k, n):
    """eq. (9): any k of n shares reconstruct K."""
    secret = secrets.randbelow(Q)
    shares, commitments = split_secret(secret, k, list(range(1, n + 1)), "rec")
    for s in shares:
        assert verify_share(s, commitments)

    # try a few different k-subsets
    assert reconstruct_secret(shares[:k]) == secret
    assert reconstruct_secret(shares[-k:]) == secret


@pytest.mark.parametrize("k,n", [(2, 3), (3, 5)])
def test_fewer_than_k_shares_give_wrong_secret(k, n):
    """Table III: 'Recover with k-1 shares' must NOT silently succeed --
    Lagrange interpolation with too few points yields a value other than K
    (which the AES-GCM tag then rejects, tested in test_end_to_end.py)."""
    secret = secrets.randbelow(Q)
    shares, _ = split_secret(secret, k, list(range(1, n + 1)), "rec")
    wrong = reconstruct_secret(shares[: k - 1])
    assert wrong != secret


def test_corrupted_share_fails_feldman_check():
    secret = secrets.randbelow(Q)
    shares, commitments = split_secret(secret, 2, [1, 2, 3], "rec")
    corrupted = dataclasses.replace(shares[0], value=(shares[0].value + 1) % Q)
    assert not verify_share(corrupted, commitments)
    with pytest.raises(ShareVerificationError):
        require_valid_share(corrupted, commitments)


def test_share_from_different_record_fails_check():
    secret = secrets.randbelow(Q)
    shares_a, commitments_a = split_secret(secret, 2, [1, 2, 3], "rec-a")
    shares_b, commitments_b = split_secret(secret, 2, [1, 2, 3], "rec-b")
    # a share for record "rec-a" must not verify against "rec-b"'s commitments
    assert not verify_share(shares_a[0], commitments_b)


def test_rejects_zero_evaluation_point():
    with pytest.raises(ValueError):
        split_secret(5, 2, [0, 1, 2], "rec")


def test_rejects_duplicate_evaluation_points():
    with pytest.raises(ValueError):
        split_secret(5, 2, [1, 1, 2], "rec")


def test_rejects_bad_threshold():
    with pytest.raises(ValueError):
        split_secret(5, 5, [1, 2, 3], "rec")  # k > n
