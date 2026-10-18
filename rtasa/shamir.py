"""
Layer T -- Shamir's (k, n) threshold secret sharing with Feldman
verifiability, over Z_q where q is the order of the P-256 group
(`rtasa.curve.Q`).

Implements:
  eq. (3)  f(x) = K + a1 x + ... + a_{k-1} x^{k-1}  mod q
  eq. (4)  Feldman commitments  C_j = a_j G,  y_i G = sum_j x_i^j C_j
  eq. (9)  Lagrange reconstruction K = sum_j y_j * prod_{m != j} x_m/(x_m-x_j) mod q

A role R_i's public evaluation point x_i is fixed and public (never 0, since
f(0) = K must stay secret). D (the dealer) also publishes the Feldman
commitments C_j in the audit log (Sec. IV-B) so that any custodian, or Q at
recovery time, can check a share without learning K.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Iterable

from ecdsa.ellipticcurve import Point

from .curve import G, Q


class ShareVerificationError(Exception):
    """Raised when a share fails the Feldman check (eq. 4) -- i.e. it was
    corrupted, forged, or belongs to a different polynomial/record."""


@dataclass(frozen=True)
class Share:
    role_index: int          # the public evaluation point x_i (x_i != 0)
    value: int               # y_i = f(x_i) mod q
    record_id: str           # which record this share belongs to


@dataclass(frozen=True)
class FeldmanCommitments:
    """C_0 .. C_{k-1}, with C_0 = K*G (so C_0 also acts as a commitment to
    the secret itself, letting anyone confirm which K a set of shares is
    for, without learning K)."""
    points: tuple           # tuple[Point, ...]
    threshold: int
    record_id: str

    def to_hex_list(self) -> list:
        return [f"{p.x()}:{p.y()}" for p in self.points]

    @staticmethod
    def from_hex_list(hexes: list, threshold: int, record_id: str) -> "FeldmanCommitments":
        from .curve import CURVE

        points = []
        for h in hexes:
            xs, ys = h.split(":")
            points.append(Point(CURVE.curve, int(xs), int(ys)))
        return FeldmanCommitments(points=tuple(points), threshold=threshold, record_id=record_id)


def _random_scalar() -> int:
    """A uniformly random element of Z_q, using a CSPRNG (secrets module)."""
    return secrets.randbelow(Q - 1) + 1


def split_secret(
    secret_k: int,
    threshold: int,
    role_indices: Iterable[int],
    record_id: str,
) -> tuple:
    """Split `secret_k` into Shamir shares for the given custodian role
    indices (the public x_i points), under a degree-(threshold-1) random
    polynomial, eq. (3). Returns (shares, commitments).

    `secret_k` must already be reduced into [0, q). `threshold` is k;
    `len(role_indices)` is n (n >= k).
    """
    role_indices = list(role_indices)
    if any(x == 0 for x in role_indices):
        raise ValueError("a role's evaluation point x_i must not be 0 (0 would leak K)")
    if len(set(role_indices)) != len(role_indices):
        raise ValueError("role evaluation points x_i must be distinct")
    if threshold < 1 or threshold > len(role_indices):
        raise ValueError("threshold k must satisfy 1 <= k <= n")

    secret_k %= Q
    # a_0 = K, a_1 .. a_{k-1} random in Z_q  (eq. 3)
    coefficients = [secret_k] + [_random_scalar() for _ in range(threshold - 1)]

    def f(x: int) -> int:
        acc = 0
        for power, a_j in enumerate(coefficients):
            acc = (acc + a_j * pow(x, power, Q)) % Q
        return acc

    shares = tuple(
        Share(role_index=x_i, value=f(x_i), record_id=record_id) for x_i in role_indices
    )

    commitment_points = tuple(a_j * G for a_j in coefficients)
    commitments = FeldmanCommitments(
        points=commitment_points, threshold=threshold, record_id=record_id
    )
    return shares, commitments


def verify_share(share: Share, commitments: FeldmanCommitments) -> bool:
    """Feldman check, eq. (4):  y_i * G  ==  sum_{j=0}^{k-1} x_i^j * C_j

    Returns True/False rather than raising, so callers (recovery.py) can
    decide how to log a failed check (Table III: "Corrupted share value").
    """
    if share.record_id != commitments.record_id:
        return False
    lhs = share.value * G
    rhs = None
    for j, c_j in enumerate(commitments.points):
        term = pow(share.role_index, j, Q) * c_j
        rhs = term if rhs is None else rhs + term
    return lhs == rhs


def require_valid_share(share: Share, commitments: FeldmanCommitments) -> None:
    if not verify_share(share, commitments):
        raise ShareVerificationError(
            f"share from role x={share.role_index} failed the Feldman check (eq. 4)"
        )


def _lagrange_coefficient(x_j: int, other_xs: Iterable) -> int:
    num, den = 1, 1
    for x_m in other_xs:
        if x_m == x_j:
            continue
        num = (num * x_m) % Q
        den = (den * (x_m - x_j)) % Q
    return (num * pow(den, -1, Q)) % Q


def reconstruct_secret(shares: Iterable) -> int:
    """Lagrange interpolation at x=0, eq. (9):

        K = sum_{j in A} y_j * prod_{m != j} x_m / (x_m - x_j)   mod q

    Requires >= k *verified* shares (callers must have already run
    `require_valid_share` on each one -- this function does not re-check
    Feldman commitments, since a quorum of custodians already vouched for
    them during the approval step, Sec. IV-D).
    """
    shares = list(shares)
    if not shares:
        raise ValueError("need at least one share to reconstruct")
    xs = [s.role_index for s in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate role indices among shares supplied for reconstruction")

    secret = 0
    for s in shares:
        lj = _lagrange_coefficient(s.role_index, xs)
        secret = (secret + s.value * lj) % Q
    return secret
