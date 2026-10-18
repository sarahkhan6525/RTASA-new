from __future__ import annotations

import os

import numpy as np
import pytest

from rtasa.stego import CapacityError, embed, embedding_stats, extract


@pytest.fixture
def cover():
    rng = np.random.default_rng(7)
    return rng.integers(0, 256, size=(512, 768), dtype=np.uint8)


def test_embed_extract_round_trip(cover):
    payload = os.urandom(256)  # a 2048-bit RSA-OAEP ciphertext's size
    kappa = os.urandom(32)
    stego = embed(cover, payload, kappa, "rec-1")
    assert extract(stego, len(payload), kappa, "rec-1") == payload


def test_bit_flip_breaks_extraction(cover):
    """Table III: 'Embedded bit flipped in carrier' -> downstream OAEP
    decoding fails. Flip one embedded bit and confirm the payload differs."""
    payload = os.urandom(256)
    kappa = os.urandom(32)
    stego = embed(cover, payload, kappa, "rec-1")

    from rtasa.stego import _select_positions

    flat = stego.reshape(-1)
    positions = _select_positions(flat.size, len(payload) * 8, kappa, "rec-1")
    pos = positions[0]
    flat[pos] = (int(flat[pos]) + 1) % 256  # corrupt exactly one embedded bit

    recovered = extract(stego, len(payload), kappa, "rec-1")
    assert recovered != payload


def test_wrong_kappa_does_not_recover_payload(cover):
    payload = os.urandom(256)
    kappa = os.urandom(32)
    stego = embed(cover, payload, kappa, "rec-1")
    wrong = extract(stego, len(payload), os.urandom(32), "rec-1")
    assert wrong != payload


def test_wrong_record_id_does_not_recover_payload(cover):
    payload = os.urandom(256)
    kappa = os.urandom(32)
    stego = embed(cover, payload, kappa, "rec-1")
    wrong = extract(stego, len(payload), kappa, "rec-2")
    assert wrong != payload


def test_capacity_error_when_payload_too_big():
    tiny_cover = np.zeros((4, 4), dtype=np.uint8)  # 16 pixels = 2 bytes capacity
    with pytest.raises(CapacityError):
        embed(tiny_cover, os.urandom(256), os.urandom(16), "rec-1")


def test_matching_changes_fewer_than_half_the_touched_pixels_statistically(cover):
    """Sanity check on imperceptibility (Sec. V-D): payload-sized embed
    should change only a small fraction of pixels and keep PSNR high."""
    payload = os.urandom(256)
    kappa = os.urandom(32)
    stego = embed(cover, payload, kappa, "rec-1")
    stats = embedding_stats(cover, stego)
    assert stats.changed_fraction < 0.01
    assert stats.psnr_db > 50
