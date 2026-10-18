"""
Tests for rtasa/steganalysis/ -- Sec. V-D's steganalysis evaluation.

`test_rs_worked_example` is the specific cross-check that
`rtasa/steganalysis/rs_analysis.py`'s own docstring promises: the numeric
example from Dumitrescu, Wu & Wang (2003), Sec. VII, confirming the
discrimination function, the two flip functions, and the R/S
classification all agree with a hand-worked case from a published source
before trusting the detector on real images.
"""

from __future__ import annotations

import numpy as np
import pytest

from rtasa.steganalysis.rs_analysis import (
    _apply_mask,
    _classify,
    _discrimination,
    _flip1,
    _flip_minus1,
    rs_statistic,
)
from rtasa.steganalysis.spa import estimate_embedding_rate
from rtasa.stego import embed, embed_lsb_replacement
from carriers.generate_carriers import make_synthetic_cover

MASK = (1, 0, 1, 0)


def test_rs_worked_example_discrimination_and_flips():
    """Dumitrescu-Wu-Wang (2003) Sec. VII: G=(39,38,40,41), M=(1,0,1,0)."""
    g = np.array([39, 38, 40, 41], dtype=np.int32)

    assert _discrimination(g) == 4  # f(G) = 4

    flipped_m = _apply_mask(g, MASK, +1)
    assert list(flipped_m) == [38, 38, 41, 41]
    assert _discrimination(flipped_m) == 3  # f(F_M(G)) = 3 -> singular under M

    flipped_minus_m = _apply_mask(g, MASK, -1)
    assert list(flipped_minus_m) == [40, 38, 39, 41]
    assert _discrimination(flipped_minus_m) == 5  # f(F_-M(G)) = 5 -> regular under -M


def test_rs_worked_example_classification():
    g = np.array([39, 38, 40, 41], dtype=np.int32)
    assert _classify(g, MASK, +1) == "S"   # singular under M
    assert _classify(g, MASK, -1) == "R"   # regular under -M


def test_flip_functions_match_worked_example():
    assert _flip1(39) == 38
    assert _flip1(40) == 41
    assert _flip_minus1(39) == 40
    assert _flip_minus1(40) == 39


@pytest.fixture
def cover():
    # RS/SPA both rely on adjacent pixels being correlated, as in a real
    # photograph (that correlation is exactly what their "C0"/discrimination
    # statistics are measuring the disturbance of) -- uniform random noise
    # has no such correlation and isn't a meaningful input for either
    # detector, so use the same synthetic "photograph-like" cover the rest
    # of the codebase already relies on (carriers/, the latency benchmark).
    return make_synthetic_cover(seed=42, height=256, width=256)


def test_rs_statistic_near_zero_on_unmodified_cover(cover):
    """A natural image should show roughly symmetric R/S counts under M
    and -M (Eq. 3's hypothesis) -- the score should be small."""
    score = rs_statistic(cover)
    assert abs(score) < 0.1


def test_rs_statistic_detects_lsb_replacement(cover):
    """RS analysis is built to catch LSB *replacement*, which breaks the
    R_M ~= R_-M / S_M ~= S_-M symmetry (Fridrich et al.'s whole point)."""
    payload = bytes(cover.size // 8)  # near-full-capacity all-zero payload
    payload = bytes([i % 256 for i in range(len(payload))])
    kappa = b"\x01" * 32
    stego = embed_lsb_replacement(cover, payload, kappa, "rs-detect")
    score_cover = abs(rs_statistic(cover))
    score_stego = abs(rs_statistic(stego))
    assert score_stego > score_cover


def test_rs_statistic_stays_low_on_lsb_matching(cover):
    """The paper's central claim (Sec. V-D): LSB *matching* (RTASA's real
    embedder) should stay near chance under RS analysis, unlike
    replacement, because matching preserves the symmetry RS relies on."""
    payload = bytes([i % 256 for i in range(cover.size // 8)])
    kappa = b"\x02" * 32
    stego = embed(cover, payload, kappa, "rs-matching")
    assert abs(rs_statistic(stego)) < 0.1


def _payload_for_rate(cover: np.ndarray, rate: float) -> bytes:
    """A payload sized so that embedding it touches `rate` fraction of
    `cover`'s pixels (each pixel carries exactly one payload bit)."""
    num_bits = int(cover.size * rate)
    num_bytes = max(1, num_bits // 8)
    return bytes([i % 256 for i in range(num_bytes)])


def test_spa_detects_lsb_replacement_rate(cover):
    """SPA (eq. 35, n=2 case) should report a near-zero estimated rate on
    an untouched cover and a materially higher one once a sizeable
    LSB-replacement payload has been embedded."""
    baseline = estimate_embedding_rate(cover)
    assert baseline < 0.15

    payload = _payload_for_rate(cover, 0.5)  # ~50% embedding rate
    kappa = b"\x03" * 32
    stego = embed_lsb_replacement(cover, payload, kappa, "spa-detect")
    estimated = estimate_embedding_rate(stego)
    assert estimated > baseline + 0.1


def test_spa_stays_low_on_lsb_matching(cover):
    payload = _payload_for_rate(cover, 0.5)
    kappa = b"\x04" * 32
    stego = embed(cover, payload, kappa, "spa-matching")
    estimated = estimate_embedding_rate(stego)
    assert estimated < 0.2
