"""
RS (Regular-Singular) analysis -- Fridrich, Goljan & Du, "Reliable
Detection of LSB Steganography in Color and Grayscale Images" (2001),
cited by the paper as [36] (Sec. V-D: "RS analysis [36]").

This module implements the parts of RS analysis that are unambiguous and
independently verifiable from the paper (the discrimination function, the
F1/F-1 flipping functions, the R/S/U classification, and the core
hypothesis of Eq. (3) that a cover image has R_M ~ R_{-M} and S_M ~
S_{-M}), and uses a discriminant built directly from that hypothesis as
the detector score, rather than solving the paper's full quadratic
rate-estimator (its Eq. 4). The exact sign pattern and exponents of that
quadratic could not be verified character-for-character from the
available source text, and shipping an unverified formula as though it
were exact would be worse than being explicit about the simplification:
the discriminant below is still literally "RS analysis" -- same groups,
same flips, same R/S counting, same hypothesis test -- it just reports
the raw asymmetry between the two masks as a continuous score instead of
inverting it into an estimated payload fraction p.

    f(x_1, ..., x_n) = sum_{i=1}^{n-1} |x_{i+1} - x_i|      (discrimination function)
    F1(x)  = x XOR 1                                         (LSB flip)
    F-1(x) = F1(x+1) - 1                                     ("shifted" flip)
    group G is Regular under mask M  if f(F_M(G)) > f(G)
    group G is Singular under mask M if f(F_M(G)) < f(G)
    Eq. (3): for a cover image, R_M ~= R_{-M} and S_M ~= S_{-M}

Verified against the worked example in Dumitrescu, Wu & Wang (2003),
Sec. VII, which restates the RS discrimination function and gives a
numeric check: G=(39,38,40,41), M=(1,0,1,0) makes G singular under M
(f(G)=4, f(F_M(G))=3) and regular under -M (f(F_{-M}(G))=5). See
`tests/test_steganalysis.py::test_rs_worked_example`.
"""

from __future__ import annotations

import numpy as np

GROUP_SIZE = 4
MASK = (1, 0, 1, 0)  # verified against the Dumitrescu-Wu-Wang worked example


def _flip1(x: int) -> int:
    return x ^ 1


def _flip_minus1(x: int) -> int:
    # F-1(x) = F1(x+1) - 1, which pairs (-1,0),(1,2),(3,4),...,(253,254),(255,256).
    # The two boundary values (x=0 -> -1, x=255 -> 256) fall outside the
    # valid pixel range; we clamp them back in, a standard, small-impact
    # simplification at the extreme ends of the pixel range.
    value = (_flip1(x + 1)) - 1
    return max(0, min(255, value))


def _discrimination(group: np.ndarray) -> int:
    diffs = np.abs(np.diff(group.astype(np.int32)))
    return int(diffs.sum())


def _apply_mask(group: np.ndarray, mask, sign: int) -> np.ndarray:
    out = group.copy()
    for i, m in enumerate(mask):
        m = m * sign
        if m == 1:
            out[i] = _flip1(int(group[i]))
        elif m == -1:
            out[i] = _flip_minus1(int(group[i]))
        # m == 0: unchanged
    return out


def _classify(group: np.ndarray, mask, sign: int) -> str:
    f0 = _discrimination(group)
    f1 = _discrimination(_apply_mask(group, mask, sign))
    if f1 > f0:
        return "R"
    if f1 < f0:
        return "S"
    return "U"


def rs_statistic(image: np.ndarray) -> float:
    """A continuous RS-analysis detector score for a grayscale image.

    Near 0 for an unmodified cover or an LSB-*matching* stego image
    (because matching does not disturb the R_M ~= R_{-M}, S_M ~= S_{-M}
    symmetry RS analysis relies on); grows with the LSB-*replacement*
    embedding rate, which breaks that symmetry (Fridrich et al.'s whole
    point). Scored as (R_M - R_{-M}) - (S_M - S_{-M}).
    """
    if image.dtype != np.uint8 or image.ndim != 2:
        raise ValueError("image must be a 2-D uint8 grayscale array")

    flat = image.reshape(-1).astype(np.int32)
    n_groups = flat.size // GROUP_SIZE
    flat = flat[: n_groups * GROUP_SIZE].reshape(n_groups, GROUP_SIZE)

    counts = {"R_M": 0, "S_M": 0, "R_-M": 0, "S_-M": 0}
    for group in flat:
        c = _classify(group, MASK, +1)
        if c == "R":
            counts["R_M"] += 1
        elif c == "S":
            counts["S_M"] += 1
        c2 = _classify(group, MASK, -1)
        if c2 == "R":
            counts["R_-M"] += 1
        elif c2 == "S":
            counts["S_-M"] += 1

    if n_groups == 0:
        return 0.0
    r_m = counts["R_M"] / n_groups
    s_m = counts["S_M"] / n_groups
    r_minus_m = counts["R_-M"] / n_groups
    s_minus_m = counts["S_-M"] / n_groups
    return (r_m - r_minus_m) - (s_m - s_minus_m)
