"""
In-memory / on-disk representation of one issued record and its per-role
steganographic carriers.

A `Record` bundles everything D produces during issuance (Sec. IV-B) that
is needed later for recovery (Sec. IV-D): the AES-GCM ciphertext, the
Feldman commitments to K's sharing polynomial, and -- per custodian role --
the stego carrier image Gi plus the RSA-OAEP-wrapped per-role embedding key
kappa_i that only that role's private key can open.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np
from PIL import Image

from .crypto_core import Ciphertext
from .shamir import FeldmanCommitments


@dataclass
class RoleCarrier:
    role_id: str
    stego_image: np.ndarray           # G_i -- the carrier with Z_i embedded (eq. 6)
    wrapped_kappa: bytes              # kappa_i, RSA-OAEP-wrapped under pk_i
    payload_len_bytes: int            # len(Z_i); needed to know how many bits to extract


@dataclass
class Record:
    record_id: str
    ciphertext: Ciphertext
    commitments: FeldmanCommitments
    threshold: int
    custodian_role_ids: tuple
    carriers: dict = field(default_factory=dict)      # role_id -> RoleCarrier
    entitled_requesters: set = field(default_factory=set)  # policy check (G1 scope, Sec IV-A)
    owner_role_id: str = ""  # D in Sec. IV-A; tracked so a portal can list "my records"

    def carrier_for(self, role_id: str) -> RoleCarrier:
        return self.carriers[role_id]

    def save_carrier_images(self, directory: Path) -> None:
        """Write each custodian's stego carrier to disk as a lossless PNG
        (lossy recompression would flip LSBs and destroy the embedded
        share -- the paper flags exactly this fragility in Sec. VI)."""
        directory.mkdir(parents=True, exist_ok=True)
        for role_id, carrier in self.carriers.items():
            Image.fromarray(carrier.stego_image, mode="L").save(
                directory / f"{self.record_id}__{role_id}.png"
            )

    @staticmethod
    def load_carrier_image(path: Path) -> np.ndarray:
        img = Image.open(path).convert("L")
        return np.array(img, dtype=np.uint8)
