"""
Layer S -- LSB-matching steganography.

Implements eq. (6):

    G_i = Embed(I_i, Z_i; kappa_i)

The paper deliberately picks LSB *matching* rather than LSB *replacement*
(Sec. IV-B): with replacement, the pixel's LSB is simply overwritten with
the payload bit, which leaves a statistical fingerprint that structural
detectors such as RS analysis / sample-pair analysis (SPA) catch reliably
(Fridrich et al. [36]; Sec. V-D, Fig. 3 shows SPA reaching AUC 0.86 against
replacement at 0.1 bpp). With matching, whenever the LSB must change the
pixel is randomly incremented *or* decremented by 1 (never deterministically
+1), which keeps the pixel-value histogram close to the cover's and defeats
those structural detectors (RTASA stays at or near chance, AUC <= 0.53, in
the paper's own evaluation).

Pixel positions are not embedded sequentially: they are selected by a
pseudo-random, key-dependent permutation of the carrier's pixel indices,
derived from the per-role key kappa_i that D sends to R_i encrypted under
pk_i (eq. 6 and surrounding text). Only someone holding kappa_i can find
where Z_i lives in the carrier.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

import numpy as np

PSNR_SATURATION = 100.0  # reported as "infinite" PSNR when images are identical


class CapacityError(Exception):
    """Raised when the payload (in bits) does not fit in the cover image."""


class ExtractionError(Exception):
    """Raised when extraction parameters (kappa, payload length, image
    shape) could not possibly match how the payload was embedded."""


class _KeyedCSPRNG:
    """Deterministic, keyed pseudorandom stream for a single (kappa,
    record_id, purpose) triple, built from HMAC-SHA256 in counter mode --
    a standard hash-based PRF/DRBG construction.

    This replaces an earlier version that seeded Python's `random.Random`
    (a non-cryptographic Mersenne Twister, whose internal state is
    reconstructible from a few hundred outputs) from only the first 64
    bits of SHA-256(kappa_i || record_id) -- a 64-bit seed is within reach
    of a well-resourced brute-force search, well short of the 256 bits of
    entropy kappa_i (eq. 6) actually carries. Here the full kappa_i is
    used directly as the HMAC key, so recovering the position/direction
    stream requires breaking HMAC-SHA256, not guessing a 64-bit seed.
    `purpose` domain-separates the position-selection stream (eq. 6) from
    the +-1 direction-choice stream used by LSB matching, replacing the
    previous ad hoc XOR-constant separation.
    """

    def __init__(self, kappa: bytes, record_id: str, purpose: bytes) -> None:
        self._key = kappa
        self._info = record_id.encode("utf-8") + b"|" + purpose
        self._counter = 0
        self._buffer = b""

    def _refill(self) -> None:
        block = hmac.new(
            self._key, self._info + self._counter.to_bytes(4, "big"), hashlib.sha256
        ).digest()
        self._counter += 1
        self._buffer += block

    def _bytes(self, n: int) -> bytes:
        while len(self._buffer) < n:
            self._refill()
        out, self._buffer = self._buffer[:n], self._buffer[n:]
        return out

    def randrange(self, start: int, stop: int) -> int:
        """Uniform integer in [start, stop), via rejection sampling so the
        result carries no modulo bias (the usual `x % span` pitfall)."""
        span = stop - start
        if span <= 0:
            raise ValueError("empty range")
        nbytes = (span.bit_length() // 8) + 2  # headroom for the rejection step
        limit = 1 << (nbytes * 8)
        threshold = limit - (limit % span)
        while True:
            val = int.from_bytes(self._bytes(nbytes), "big")
            if val < threshold:
                return start + (val % span)

    def random(self) -> float:
        """Uniform float in [0, 1) at 53 bits of precision, matching the
        precision `random.Random.random()` provides."""
        val = int.from_bytes(self._bytes(7), "big") >> 3
        return val / float(1 << 53)


def _select_positions(num_pixels: int, count: int, kappa: bytes, record_id: str) -> list:
    """`count` distinct pseudo-random positions in [0, num_pixels), keyed by
    kappa and the record id.

    This is a *partial* Fisher-Yates shuffle, implemented with a sparse
    dict standing in for the "array" instead of materializing and
    shuffling a `range(num_pixels)` list. A payload is a couple thousand
    bits (a wrapped RSA-OAEP share) against a cover of a few hundred
    thousand pixels, so `count << num_pixels`; a full shuffle does
    O(num_pixels) work to answer an O(count) question, which is the
    difference between sub-millisecond and multi-hundred-millisecond
    embeds on a 768x512 cover. This produces a uniformly random selection
    of `count` distinct positions, deterministically from the seed --
    exactly what embed/extract need to agree with each other -- without
    being byte-for-byte the same permutation `random.Random.shuffle`
    would produce (nothing depends on that).
    """
    if count > num_pixels:
        raise CapacityError(
            f"payload needs {count} pixels but the cover only has {num_pixels}"
        )
    rng = _KeyedCSPRNG(kappa, record_id, b"positions")
    swapped = {}
    positions = []
    for i in range(count):
        j = rng.randrange(i, num_pixels)
        vi = swapped.get(i, i)
        vj = swapped.get(j, j)
        swapped[i] = vj
        swapped[j] = vi
        positions.append(vj)
    return positions


def _bytes_to_bits(data: bytes) -> list:
    bits = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def _bits_to_bytes(bits: list) -> bytes:
    if len(bits) % 8 != 0:
        raise ExtractionError("extracted bit count is not a whole number of bytes")
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i:i + 8]:
            byte = (byte << 1) | b
        out.append(byte)
    return bytes(out)


def embed(cover: np.ndarray, payload: bytes, kappa: bytes, record_id: str) -> np.ndarray:
    """LSB-matching embed of `payload` into a grayscale `cover` image
    (2-D uint8 numpy array), eq. (6). Returns a new stego image; `cover`
    is left untouched.
    """
    if cover.dtype != np.uint8 or cover.ndim != 2:
        raise ValueError("cover must be a 2-D uint8 grayscale array")

    stego = cover.copy()
    flat = stego.reshape(-1)
    bits = _bytes_to_bits(payload)
    positions = _select_positions(flat.size, len(bits), kappa, record_id)

    rng = _KeyedCSPRNG(kappa, record_id, b"direction")
    for pos, bit in zip(positions, bits):
        value = int(flat[pos])
        if (value & 1) == bit:
            continue  # already matches -- LSB matching never touches pixels that don't need it
        if value == 0:
            flat[pos] = 1
        elif value == 255:
            flat[pos] = 254
        else:
            flat[pos] = value + 1 if rng.random() < 0.5 else value - 1

    return stego


def embed_lsb_replacement(cover: np.ndarray, payload: bytes, kappa: bytes, record_id: str) -> np.ndarray:
    """LSB *replacement* embed -- deterministically overwrites each
    selected pixel's LSB with the payload bit, unlike `embed` (LSB
    matching), which randomizes the direction of change when a bit must
    flip. RTASA itself never uses this function; it exists only for
    `rtasa/steganalysis/` and `scripts/run_steganalysis.py`, which need a
    *known-detectable* baseline to confirm RS analysis and SPA (Sec. V-D)
    are actually working before trusting that they report "chance" against
    the real LSB-matching embedder. Uses the identical position-selection
    as `embed` so the two are a fair, like-for-like comparison.
    """
    if cover.dtype != np.uint8 or cover.ndim != 2:
        raise ValueError("cover must be a 2-D uint8 grayscale array")

    stego = cover.copy()
    flat = stego.reshape(-1)
    bits = _bytes_to_bits(payload)
    positions = _select_positions(flat.size, len(bits), kappa, record_id)

    for pos, bit in zip(positions, bits):
        flat[pos] = (int(flat[pos]) & 0xFE) | bit

    return stego


def extract(stego: np.ndarray, payload_len_bytes: int, kappa: bytes, record_id: str) -> bytes:
    """Inverse of `embed`: recover `payload_len_bytes` bytes from `stego`
    using the same per-role key and record id used to embed them."""
    if stego.dtype != np.uint8 or stego.ndim != 2:
        raise ValueError("stego must be a 2-D uint8 grayscale array")

    flat = stego.reshape(-1)
    num_bits = payload_len_bytes * 8
    positions = _select_positions(flat.size, num_bits, kappa, record_id)
    bits = [int(flat[pos]) & 1 for pos in positions]
    return _bits_to_bytes(bits)


@dataclass(frozen=True)
class EmbeddingStats:
    changed_pixels: int
    total_pixels: int
    psnr_db: float

    @property
    def changed_fraction(self) -> float:
        return self.changed_pixels / self.total_pixels


def embedding_stats(cover: np.ndarray, stego: np.ndarray) -> EmbeddingStats:
    """Reports the two numbers the paper uses to characterize imperceptibility
    (Sec. V-D): the fraction of pixels changed, and PSNR in dB."""
    cover_i = cover.astype(np.int32)
    stego_i = stego.astype(np.int32)
    diff = cover_i - stego_i
    changed = int(np.count_nonzero(diff))
    mse = float(np.mean(diff.astype(np.float64) ** 2))
    psnr = PSNR_SATURATION if mse == 0 else 10.0 * np.log10((255.0 ** 2) / mse)
    return EmbeddingStats(changed_pixels=changed, total_pixels=cover.size, psnr_db=float(psnr))
