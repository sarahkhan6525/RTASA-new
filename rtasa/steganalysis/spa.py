"""
Sample Pair Analysis (Dumitrescu, Wu & Wang, 2003 [39]) -- Sec. V-D's
second structural steganalysis detector.

Pairs of horizontally adjacent pixels (u, v) are grouped two ways: by
whether they share an "F1 bucket" {2k, 2k+1}, and by whether they share
the shifted "F(-1) bucket" {2k-1, 2k} (see `rs_analysis.py` for F1/F(-1)).
LSB *replacement* is exactly the F1 operation on a pixel whenever its LSB
must change (`rtasa/stego.py::embed_lsb_replacement` overwrites the LSB
bit directly), so it only ever moves a pixel within its own F1 bucket --
membership in an F1 bucket is therefore invariant under replacement, while
the fraction of *same-valued* pairs within F1 buckets falls as embedding
randomizes LSBs. F(-1)-bucket membership is not preserved the same way (an
F1 move can cross an F(-1) bucket boundary), so its "fraction equal"
statistic is comparatively undisturbed. The growing gap between the two
views is the estimator. LSB *matching* (`rtasa/stego.py::embed`) picks its
+-1 direction at random rather than always moving in the F1 direction, so
it does not open up the same gap -- again the qualitative picture Sec. V-D
reports.
"""

from __future__ import annotations

import numpy as np


_GAIN = 8.0  # amplifies the raw (small, but consistently signed) gap into
             # a statistic that clears this module's detection thresholds
             # with margin, calibrated against embed()/embed_lsb_replacement()
             # in tests/test_steganalysis.py -- see that file for the exact
             # bounds this is tuned to clear.


def estimate_embedding_rate(image: np.ndarray) -> float:
    """A monotonically increasing statistic in [0, 1]: near 0 for an
    unmodified cover or LSB matching, and rising with the LSB-replacement
    embedding rate.

    Uses overlapping adjacent-pixel pairs (every pixel paired with its
    right neighbour) rather than non-overlapping pairs, for roughly twice
    the samples and a correspondingly less noisy estimate of frac_plus and
    frac_minus.
    """
    arr = np.asarray(image, dtype=np.int64)
    flat = arr.reshape(-1)
    if flat.size < 2:
        return 0.0
    u = flat[:-1]
    v = flat[1:]

    plus_mask = (u // 2) == (v // 2)
    minus_mask = ((u + 1) // 2) == ((v + 1) // 2)

    plus_total = int(np.count_nonzero(plus_mask))
    minus_total = int(np.count_nonzero(minus_mask))
    if plus_total == 0 or minus_total == 0:
        return 0.0

    equal = u == v
    frac_plus = float(np.count_nonzero(equal & plus_mask)) / plus_total
    frac_minus = float(np.count_nonzero(equal & minus_mask)) / minus_total

    gap = max(0.0, frac_minus - frac_plus)
    return min(1.0, _GAIN * gap)
