"""
Elliptic-curve constants shared by the threshold-sharing (T) and audit-log (L)
layers.

RTASA samples the session key K uniformly from Z_q, where q is the order of
the NIST P-256 group (paper, Sec. IV-B, eq. (3); FIPS PUB 186-5 [31]). The
same group is reused for:

  * Feldman verifiable-secret-sharing commitments  C_j = a_j * G   (eq. 4)
  * ECDSA-over-P-256 signatures on audit-log entries               (Sec IV-C)

Using one curve for both keeps the prototype small, exactly as the paper's
~340-line reference implementation does (Sec. V-A).
"""

from __future__ import annotations

from ecdsa import NIST256p
from ecdsa.ellipticcurve import Point

#: The P-256 generator point G.
G: Point = NIST256p.generator

#: q = order of the P-256 group. The session key K and every Shamir share
#: live in Z_q (eq. 3). This is a ~256-bit prime, so it is *not* the same
#: thing as the curve's underlying field prime p -- q is the subgroup order.
Q: int = NIST256p.order

#: Convenience curve handle (needed by ecdsa.SigningKey / VerifyingKey).
CURVE = NIST256p


def point_to_bytes(point: Point) -> bytes:
    """Fixed-width (x, y) encoding of a curve point, used when a commitment
    needs to be hashed or stored in the audit log."""
    x = point.x()
    y = point.y()
    return x.to_bytes(32, "big") + y.to_bytes(32, "big")


def scalar_mod_q(value: int) -> int:
    """Reduce an arbitrary integer into Z_q."""
    return value % Q
