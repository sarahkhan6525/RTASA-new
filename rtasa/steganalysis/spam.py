"""
A reduced SPAM (Subtractive Pixel Adjacency Matrix) feature set (Pevny,
Bas & Fridrich, 2010 [40]) -- Sec. V-D's third, learned detector, fed to
a shrinkage Fisher linear discriminant in `evaluate.py`.

The full SPAM feature set builds second-order Markov transition matrices
of truncated pixel-difference ("residual") pairs across 8 directions
(horizontal, vertical, and both diagonals, each scanned forwards and
backwards) and is of order 2 (triples of consecutive residuals), giving
686 features. This module uses only 2 directions (horizontal, vertical)
and order 1 (pairs of consecutive residuals, not triples), which is
enough to pick up the same kind of local-correlation disturbance at a
much smaller feature count and without extra dependencies.

Note: the reduced feature count here is NOT why this detector's AUC
diverges from the paper's reported numbers when run on this repo's
synthetic cover images (see `evaluate.py`'s printed caveat for the
measured evidence) -- a from-scratch implementation of the full
order-2, 8-direction, 686-feature construction was tested and showed
the same divergence, so the gap tracks the small, synthetic training
set the learned detector is fit on, not this module's simplification.
"""

from __future__ import annotations

import numpy as np

TRUNCATION = 3  # T: residuals are clipped to [-T, T]
_BINS = 2 * TRUNCATION + 1


def _residuals(arr: np.ndarray, axis: int) -> np.ndarray:
    diff = np.diff(arr.astype(np.int16), axis=axis)
    return np.clip(diff, -TRUNCATION, TRUNCATION)


def _transition_histogram(residual: np.ndarray, axis: int) -> np.ndarray:
    """Normalized co-occurrence histogram of adjacent residual pairs along
    `axis`, flattened to a fixed-length vector of size _BINS**2."""
    a = np.take(residual, range(residual.shape[axis] - 1), axis=axis)
    b = np.take(residual, range(1, residual.shape[axis]), axis=axis)
    idx_a = (a + TRUNCATION).reshape(-1)
    idx_b = (b + TRUNCATION).reshape(-1)
    hist = np.zeros((_BINS, _BINS), dtype=np.float64)
    np.add.at(hist, (idx_a, idx_b), 1.0)
    total = hist.sum()
    if total > 0:
        hist /= total
    return hist.reshape(-1)


def spam_features(image: np.ndarray) -> np.ndarray:
    """Fixed-length (2 * _BINS**2 = 98) feature vector: normalized
    horizontal and vertical second-order residual co-occurrence
    histograms, concatenated."""
    arr = np.asarray(image, dtype=np.int16)
    horizontal = _residuals(arr, axis=1)
    vertical = _residuals(arr, axis=0)
    return np.concatenate([
        _transition_histogram(horizontal, axis=1),
        _transition_histogram(vertical, axis=0),
    ])
