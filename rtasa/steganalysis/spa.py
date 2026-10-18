"""
Sample Pair Analysis (SPA) -- Dumitrescu, Wu & Wang, "Detection of LSB
Steganography via Sample Pair Analysis" (IEEE Trans. Signal Processing,
2003), cited by the paper alongside RS analysis as [36] (Sec. V-D).

Verified directly against the authors' own preprint (S. Dumitrescu's
faculty page, https://www.ece.mcmaster.ca/~sorina/papers/LSBfinalTSP.pdf)
rather than reconstructed from memory. Quoting the parts this module
implements:

  Sec. II: "a sample pair means a two-tuple (s_i, s_j)." This module uses
  horizontally-adjacent pixel pairs, matching the paper's own experiments
  ("all pairs of 4-connected pixels," Sec. V) and this package's existing
  `rs_analysis.py` convention.

  C_0: "the submultiset of P that consists of the sample pairs whose
  values differ by [0] in the first (b-1) bits (i.e. by right shifting
  one bit and then measuring the difference)" -- i.e. floor(u/2) ==
  floor(v/2).

  Sec. VII: "X is the multiset of pairs (u, v) in P such that v is even
  and u < v, or v is odd and u > v; Y is the multiset of pairs (u, v) in
  P such that v is even and u > v, or v is odd and u < v."

  Appendix D, Eq. (35): "0.5|C0|p^2 + (2|X'| - |P|)p + |Y'| - |X'| = 0".
  The paper uses primes for the quantities computed from the object
  actually being analyzed (as opposed to the unprimed quantities used
  earlier in the derivation to relate things to the *original*, pre-
  embedding image, which isn't available to a detector). For detection
  there is only the object in hand, so X' and Y' below are exactly X and
  Y above, computed on the image being tested.

  Root selection: "The smaller root of quadratic equation (5) (or
  equation (6)) is the estimated value of p" -- Eq. (35) is that same
  family of quadratic, so the same rule applies.

One honestly-flagged caveat: the fetched preprint prints Eq. (35)'s
leading coefficient as 0.5|C0|, while its closely related Eq. (6) (the
general m=0 case) has a 1/4 in the corresponding position; the preprint
is watermarked "DRAFT" and the extraction could not fully resolve
whether that's an intentional difference from Appendix D's own derivation
(rescaling the m=0 formula) or a transcription slip. We use 0.5|C0|
exactly as Eq. (35) itself states it -- it is the equation actually
labelled as the n=2 special case -- rather than silently "correcting" it
against a different equation's coefficient.
"""

from __future__ import annotations

import numpy as np

_EPS = 1e-12


def _pair_counts(image: np.ndarray) -> tuple:
    """Returns (|P|, |C0|, |X|, |Y|) for all horizontally-adjacent pixel
    pairs (u, v) in `image`."""
    if image.dtype != np.uint8 or image.ndim != 2:
        raise ValueError("image must be a 2-D uint8 grayscale array")

    u = image[:, :-1].astype(np.int32).reshape(-1)
    v = image[:, 1:].astype(np.int32).reshape(-1)

    total = u.size
    c0 = int(np.count_nonzero((u // 2) == (v // 2)))

    v_even = (v % 2) == 0
    x_mask = (v_even & (u < v)) | (~v_even & (u > v))
    y_mask = (v_even & (u > v)) | (~v_even & (u < v))

    return total, c0, int(np.count_nonzero(x_mask)), int(np.count_nonzero(y_mask))


def estimate_embedding_rate(image: np.ndarray) -> float:
    """SPA's estimate of the LSB-replacement embedding rate p in [0, 1],
    via the n=2 special case, Eq. (35): 0.5|C0| p^2 + (2|X| - |P|) p +
    (|Y| - |X|) = 0, taking the smaller real root clamped into [0, 1].

    Near 0 for a cover image or an LSB-*matching* stego image (matching
    does not introduce the structural bias SPA looks for); grows with the
    LSB-*replacement* embedding rate.
    """
    total, c0, x, y = _pair_counts(image)
    if total == 0:
        return 0.0

    a = 0.5 * c0
    b = 2.0 * x - total
    c = float(y - x)

    if abs(a) < _EPS:
        # Degenerate (no C0 pairs at all, e.g. a tiny or pathological
        # image): fall back to the linear relation bp + c = 0.
        if abs(b) < _EPS:
            return 0.0
        root = -c / b
        return float(min(1.0, max(0.0, root)))

    discriminant = b * b - 4 * a * c
    if discriminant < 0:
        # Noise can push the quadratic just past having a real root for a
        # near-zero true rate; report "no detectable embedding" rather
        # than a complex number.
        return 0.0

    sqrt_disc = discriminant ** 0.5
    root1 = (-b - sqrt_disc) / (2 * a)
    root2 = (-b + sqrt_disc) / (2 * a)
    smaller, larger = sorted((root1, root2))

    # "The smaller root ... is the estimated value of p" -- but prefer a
    # root that actually lands in [0, 1]; a wildly out-of-range smaller
    # root on noisy/small images is a sign the larger one is the sensible
    # estimate, which is a standard practical fallback for this method.
    if 0.0 <= smaller <= 1.0:
        return float(smaller)
    if 0.0 <= larger <= 1.0:
        return float(larger)
    return float(min(1.0, max(0.0, smaller)))
