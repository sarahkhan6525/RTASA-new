"""
RS (Regular/Singular) analysis (Fridrich, Goljan & Du, 2001 [36]) --
Sec. V-D's first structural steganalysis detector.

The method partitions an image into small groups of pixels and, for each
group, checks whether a fixed "flipping" perturbation makes the group
*more* or *less* locally smooth (its discrimination value). For a natural
image, flipping a group's LSBs with F1 and with its mirror-image flip F(-1)
disturbs smoothness in roughly symmetric proportions (as many groups become
smoother as rougher, under either flip). LSB *replacement* breaks that
symmetry in a detectable, rate-dependent way; LSB *matching* (RTASA's own
embedder, `rtasa/stego.py`) does not, because it does not consistently pick
one flip direction over the other -- which is exactly the qualitative
picture Sec. V-D / Fig. 3 reports.

`test_rs_worked_example_discrimination_and_flips` /
`..._classification` in `tests/test_steganalysis.py` cross-check
`_discrimination`, `_flip1`, `_flip_minus1`, `_apply_mask`, and `_classify`
directly against the numeric example in Dumitrescu, Wu & Wang (2003),
Sec. VII (G = (39, 38, 40, 41), mask M = (1, 0, 1, 0)) -- run that test
after changing anything here.
"""

from __future__ import annotations

import numpy as np

DEFAULT_MASK = (1, 0, 1, 0)


def _flip1(x: int) -> int:
    """F1: the standard LSB flip, pairing 2k <-> 2k+1."""
    return x + 1 if x % 2 == 0 else x - 1


def _flip_minus1(x: int) -> int:
    """F(-1): the shifted flip, pairing 2k-1 <-> 2k (i.e. F1 shifted by
    one value), used as the "mirror" perturbation against which F1's
    effect is compared."""
    return x - 1 if x % 2 == 0 else x + 1


def _discrimination(g) -> int:
    """f(G): the group's "roughness" -- the sum of absolute differences
    between consecutive pixels. Smaller is smoother."""
    arr = np.asarray(g, dtype=np.int64)
    return int(np.sum(np.abs(np.diff(arr))))


def _apply_mask(g, mask, direction: int):
    """Apply F1 (direction=+1) or F(-1) (direction=-1) to every position
    of `g` where `mask` is 1, leaving masked-out positions untouched."""
    arr = np.asarray(g, dtype=np.int64).copy()
    flip = _flip1 if direction == 1 else _flip_minus1
    for i, m in enumerate(mask):
        if m:
            arr[i] = flip(int(arr[i]))
    return arr


def _classify(g, mask, direction: int) -> str:
    """"R" (regular) if the flip increases roughness, "S" (singular) if it
    decreases it, "U" (unusable) if roughness is unchanged."""
    before = _discrimination(g)
    after = _discrimination(_apply_mask(g, mask, direction))
    if after > before:
        return "R"
    if after < before:
        return "S"
    return "U"


def rs_statistic(image: np.ndarray, mask=DEFAULT_MASK) -> float:
    """The image-level RS statistic: (R_M% - S_M%) - (R_(-M)% - S_(-M)%)
    over all non-overlapping groups of `len(mask)` pixels, scanned
    row-major. Near 0 for an unmodified cover and for LSB matching;
    grows in magnitude under LSB replacement as the embedding rate rises.
    """
    arr = np.asarray(image)
    flat = arr.reshape(-1)
    n = len(mask)
    num_groups = flat.size // n
    if num_groups == 0:
        return 0.0
    groups = flat[: num_groups * n].reshape(num_groups, n)

    r_m = s_m = r_mm = s_mm = 0
    for group in groups:
        c_plus = _classify(group, mask, 1)
        if c_plus == "R":
            r_m += 1
        elif c_plus == "S":
            s_m += 1
        c_minus = _classify(group, mask, -1)
        if c_minus == "R":
            r_mm += 1
        elif c_minus == "S":
            s_mm += 1

    r_m_pct = r_m / num_groups
    s_m_pct = s_m / num_groups
    r_mm_pct = r_mm / num_groups
    s_mm_pct = s_mm / num_groups
    return (r_m_pct - s_m_pct) - (r_mm_pct - s_mm_pct)
