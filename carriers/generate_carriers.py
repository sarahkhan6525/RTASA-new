"""
Synthetic grayscale carrier images, standing in for the 24 Kodak images
(768 x 512, grayscale) the paper uses as covers (Sec. V-A, [38]). The
actual Kodak suite is not redistributable from here, so this generates
photograph-like covers (smooth low-frequency gradients plus texture noise,
which is what makes LSB-matching's +-1 changes imperceptible in the first
place) of the same size and bit depth, good enough to embed into and to
measure PSNR / changed-pixel-fraction against (Sec. V-D).

Run directly to populate ./carriers/generated/ with a small set of covers:

    python -m carriers.generate_carriers
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
from PIL import Image

DEFAULT_HEIGHT = 512
DEFAULT_WIDTH = 768


def make_synthetic_cover(seed: int, height: int = DEFAULT_HEIGHT, width: int = DEFAULT_WIDTH) -> np.ndarray:
    """A deterministic, photograph-like grayscale cover: a handful of
    smooth 2-D sinusoids (standing in for natural low-frequency image
    content) plus Gaussian sensor-noise-like texture, clipped to uint8.
    Deterministic in `seed` so tests and the demo can regenerate the exact
    same cover without shipping binary fixtures.
    """
    rng = np.random.default_rng(seed)
    yy, xx = np.meshgrid(np.linspace(0, 1, height), np.linspace(0, 1, width), indexing="ij")

    base = np.zeros((height, width), dtype=np.float64)
    num_components = 5
    for _ in range(num_components):
        fx = rng.uniform(0.5, 4.0)
        fy = rng.uniform(0.5, 4.0)
        phase = rng.uniform(0, 2 * np.pi)
        amp = rng.uniform(15, 45)
        base += amp * np.sin(2 * np.pi * (fx * xx + fy * yy) + phase)

    base += 128.0
    texture = rng.normal(loc=0.0, scale=6.0, size=(height, width))
    image = np.clip(base + texture, 0, 255).astype(np.uint8)
    return image


def save_covers(directory: Path, count: int = 24, height: int = DEFAULT_HEIGHT, width: int = DEFAULT_WIDTH) -> list:
    directory.mkdir(parents=True, exist_ok=True)
    paths = []
    for i in range(count):
        image = make_synthetic_cover(seed=i, height=height, width=width)
        path = directory / f"cover_{i:02d}.png"
        Image.fromarray(image, mode="L").save(path)
        paths.append(path)
    return paths


if __name__ == "__main__":
    out_dir = Path(__file__).parent / "generated"
    written = save_covers(out_dir)
    print(f"Wrote {len(written)} synthetic {DEFAULT_WIDTH}x{DEFAULT_HEIGHT} grayscale covers to {out_dir}")
