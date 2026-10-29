"""
Synthetic "photograph-like" grayscale cover generation (Sec. V-A), standing
in for the Kodak image suite [38] since those images are not redistributable.

RS analysis and SPA (`rtasa/steganalysis/rs_analysis.py`, `.../spa.py`) both
work by measuring how embedding disturbs the local correlation between
neighbouring pixels. Uniform random noise has no such correlation and isn't
a meaningful input for either detector -- a cover needs the same kind of
local smoothness a real photograph has. This module builds that by
low-pass filtering Gaussian noise, which gives each pixel's value strong
local correlation with its neighbours without depending on any particular
real image.
"""

from __future__ import annotations

import numpy as np
from PIL import Image, ImageFilter


def make_synthetic_cover(
    seed: int,
    height: int = 512,
    width: int = 768,
    blur_radius: float = 2.0,
) -> np.ndarray:
    """Return a deterministic (height, width) uint8 grayscale array with
    photograph-like local pixel correlation.

    Same `seed` always reproduces the same image, so paired cover/stego
    comparisons and cross-validation folds are reproducible across runs.
    """
    rng = np.random.default_rng(seed)
    noise = rng.normal(loc=128.0, scale=60.0, size=(height, width))
    base = np.clip(noise, 0, 255).astype(np.uint8)
    blurred = Image.fromarray(base, mode="L").filter(ImageFilter.GaussianBlur(radius=blur_radius))
    return np.asarray(blurred, dtype=np.uint8)
