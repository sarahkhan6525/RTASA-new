"""
SPAM-inspired pixel-difference features for a *learned* steganalysis
detector -- the paper's Sec. V-D cites SPAM (Subtractive Pixel Adjacency
Matrix, Pevny, Bas & Fridrich, "Steganalysis by Subtractive Pixel
Adjacency Matrix," 2010) as the feature set feeding the shrinkage Fisher
LDA classifier behind its Fig. 3 AUC numbers.

Honesty note on scope, in the same spirit as this package's RS module:
the published SPAM feature set is an order-3 Markov chain over pixel
*difference* sequences, in all 8 directions, with differences truncated
to [-T, T] (T=3 or 4) and folded by sign-symmetry -- 2 * (2T+1)^3 =
686 features for T=3. That exact construction was not re-derived and
verified against the primary source the way RS's and SPA's formulas
were (see `rs_analysis.py`, `spa.py`); reproducing its precise truncation
and symmetry-folding rules from memory would carry exactly the fidelity
risk this project has deliberately avoided elsewhere.

What's implemented here instead is a clearly smaller, order-1 reduction
that is unambiguously *in the same family* as SPAM -- a Markov transition
matrix over the signed difference between horizontally- and vertically-
adjacent pixels, truncated to [-T, T] and estimated as empirical
transition frequencies -- rather than the full order-3, 8-direction,
symmetry-folded construction. It is still "a SPAM-style feature vector
capturing local pixel-difference statistics," and it is what
`evaluate.py`'s shrinkage-LDA detector is trained on; it is not claimed
to be a byte-for-byte reproduction of Pevny-Bas-Fridrich's 686-dimensional
feature vector, and `evaluate.py`'s report says so next to the AUC numbers
it produces.
"""

from __future__ import annotations

import numpy as np

TRUNCATION = 2  # T: differences are clipped to [-T, T], as in SPAM. Kept
                 # small (SPAM itself typically uses T=3-4) because this
                 # module's evaluation harness trains on a few dozen
                 # synthetic images -- a larger T blows up the feature
                 # count (2*(2T+1)^2) relative to that sample size and
                 # shrinkage LDA starts overfitting rather than detecting
                 # anything real. See `evaluate.py`'s module docstring for
                 # how this trade-off shows up in the reported AUCs.
_BINS = 2 * TRUNCATION + 1  # number of distinct (clipped) difference values


def _diff_sequence(image: np.ndarray, axis: int) -> np.ndarray:
    """Signed differences between adjacent pixels along `axis` (0 = rows
    i.e. vertical neighbors, 1 = columns i.e. horizontal neighbors),
    clipped to [-TRUNCATION, TRUNCATION]."""
    arr = image.astype(np.int32)
    if axis == 1:
        diffs = arr[:, 1:] - arr[:, :-1]
    else:
        diffs = arr[1:, :] - arr[:-1, :]
    return np.clip(diffs, -TRUNCATION, TRUNCATION)


def _markov_transition_features(diffs: np.ndarray) -> np.ndarray:
    """A first-order Markov transition matrix over the clipped difference
    sequence (row i, col j = empirical P(d_{t+1}=j | d_t=i)), flattened to
    a `_BINS * _BINS`-length feature vector. This is the order-1 analogue
    of SPAM's order-3 transition-probability features: it captures how
    one local pixel-difference tends to follow another, which is exactly
    the kind of short-range dependency that LSB *replacement* disturbs
    (and LSB matching, by construction, mostly preserves)."""
    shifted = TRUNCATION  # map [-T, T] -> [0, 2T] for indexing
    counts = np.zeros((_BINS, _BINS), dtype=np.float64)
    for row in diffs:
        if row.size < 2:
            continue
        a = row[:-1] + shifted
        b = row[1:] + shifted
        np.add.at(counts, (a, b), 1.0)
    row_sums = counts.sum(axis=1, keepdims=True)
    row_sums[row_sums == 0] = 1.0  # avoid div-by-zero on an all-zero row
    probs = counts / row_sums
    return probs.reshape(-1)


def spam_features(image: np.ndarray) -> np.ndarray:
    """A SPAM-style feature vector for `image`: the concatenation of the
    horizontal and vertical order-1 Markov transition features, length
    `2 * (2*TRUNCATION + 1)**2`. See the module docstring for exactly how
    this differs from the published order-3, 8-direction SPAM construction.
    """
    if image.dtype != np.uint8 or image.ndim != 2:
        raise ValueError("image must be a 2-D uint8 grayscale array")

    horizontal = _markov_transition_features(_diff_sequence(image, axis=1))
    vertical = _markov_transition_features(_diff_sequence(image, axis=0))
    return np.concatenate([horizontal, vertical])


def feature_dimension() -> int:
    return 2 * _BINS * _BINS
