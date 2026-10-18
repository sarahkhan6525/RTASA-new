"""
Reproduces Section V-C's latency evaluation (Fig. 2): median issuance and
recovery latency for a 1 MiB record across several (k, n) threshold
settings, against a "plain hybrid encryption" baseline -- AES-GCM with a
single RSA-OAEP key wrap, i.e. layers E + A only, no T/S/L.

Methodology, matching Sec. V-A/V-C as closely as a different machine
allows:

    * (k, n) in {(2,3), (3,5), (5,7), (7,10)} -- the paper's own range.
    * `--trials` repetitions after `--warmup` discarded warm-up runs
      (defaults: 300 / 20, exactly as Sec. V-A states).
    * Reports the median, and the 90th percentile for recovery (the paper
      calls out "recovery stays below 25 ms at the 90th percentile" for
      ten custodians, Sec. V-C).

The paper is explicit that its own absolute numbers come from "a shared
two-vCPU Xeon virtual machine (2.1 GHz)" and are partly pure-Python
elliptic-curve arithmetic (Sec. V-A, VI) -- so treat the *shape* of the
result (recovery cost rising with k, S dominating issuance, T+A
dominating recovery, both staying a small multiple of the plain-hybrid
baseline) as what should reproduce, not the exact millisecond figures.

Usage:

    python -m scripts.benchmark_latency                      # full, paper-scale run
    python -m scripts.benchmark_latency --trials 30 --warmup 5 --quick   # fast sanity check
"""

from __future__ import annotations

import argparse
import os
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

import rtasa.keystore as keystore_module
from carriers.generate_carriers import make_synthetic_cover
from rtasa.audit_log import AuditLog, CheckpointWitnessStore
from rtasa.crypto_core import decrypt_record, encrypt_record
from rtasa.issuance import issue_record
from rtasa.keystore import RoleIdentity, RoleKeyStore
from rtasa.recovery import approve_share, recover_record, request_recovery
from rtasa.rsa_wrap import generate_role_rsa_keypair, unwrap_bytes, wrap_bytes

ONE_MIB = 1024 * 1024
SETTINGS = [(2, 3), (3, 5), (5, 7), (7, 10)]

# The paper's Sec. V-C latency figures time the cryptographic pipeline only
# -- eq. (2)-(9): AES-GCM, Shamir splitting, Feldman commitments, RSA-OAEP
# wrapping, LSB embedding, and reconstruction (Fig. 2's breakdown is
# E / A / T / S / L, with L being audit-log signing, not authentication).
# Credential-and-OTP authentication (Sec. IV-B/D) is a session-level gate a
# real deployment pays once, not once per record -- but this prototype's
# `RoleIdentity.authenticate()` deliberately re-checks an expensive,
# memory-hard Argon2id passphrase hash on every call (the enterprise
# hardening in rtasa/keystore.py), which would otherwise swamp this
# benchmark with a cost the paper never measures and that has nothing to
# do with RTASA's cryptography. Argon2id bakes its cost parameters into
# the stored hash itself, so we lower them on the *hasher used to create*
# the benchmark's own roles below (time_cost=1, minimal memory) -- every
# later `authenticate()` call in the timed loop verifies against that same
# cheap hash and is cheap too. This only affects roles created by this
# benchmark process; nothing else in the codebase (the FastAPI backend,
# the demo, the tests) is touched.
keystore_module._argon2_hasher = keystore_module.argon2.PasswordHasher(
    time_cost=1, memory_cost=8, parallelism=1
)


@dataclass
class Sample:
    issuance_ms: list = field(default_factory=list)
    recovery_ms: list = field(default_factory=list)


def _percentile(values: list, pct: float) -> float:
    values = sorted(values)
    idx = min(len(values) - 1, max(0, round((pct / 100.0) * (len(values) - 1))))
    return values[idx]


def _ms(seconds: float) -> float:
    return seconds * 1000.0


# -- plain-hybrid baseline: E + A only, no T/S/L ---------------------------

def benchmark_plain_hybrid(message: bytes, trials: int, warmup: int) -> Sample:
    key = generate_role_rsa_keypair()
    pub, priv = key.public_key(), key
    sample = Sample()
    for i in range(warmup + trials):
        record_id = f"baseline-{i}"
        t0 = time.perf_counter()
        aes_key = os.urandom(32)
        ct = encrypt_record(message, aes_key, record_id)
        wrapped = wrap_bytes(aes_key, pub)
        t1 = time.perf_counter()

        aes_key_back = unwrap_bytes(wrapped, priv)
        recovered = decrypt_record(ct, aes_key_back)
        t2 = time.perf_counter()
        assert recovered == message

        if i >= warmup:
            sample.issuance_ms.append(_ms(t1 - t0))
            sample.recovery_ms.append(_ms(t2 - t1))
    return sample


# -- full RTASA pipeline ----------------------------------------------------

def _build_roles(k: int, n: int) -> tuple:
    keystore = RoleKeyStore()
    owner = RoleIdentity.create("owner", "Owner", "owner-passphrase-1")
    keystore.add(owner)
    custodians = []
    for i in range(1, n + 1):
        role = RoleIdentity.create(
            f"custodian_{i}", f"custodian_{i}", f"custodian-passphrase-{i}",
            is_custodian=True, evaluation_point=i,
        )
        keystore.add(role)
        custodians.append(role)
    requester = RoleIdentity.create("requester_q", "Requester Q", "requester-passphrase-1")
    keystore.add(requester)
    return keystore, owner, custodians, requester


def benchmark_rtasa(k: int, n: int, message: bytes, trials: int, warmup: int) -> Sample:
    keystore, owner, custodians, requester = _build_roles(k, n)
    cover_images = {c.role_id: make_synthetic_cover(seed=i) for i, c in enumerate(custodians)}

    sample = Sample()
    for i in range(warmup + trials):
        record_id = f"bench-{k}-{n}-{i}"
        audit_log = AuditLog(checkpoint_interval=10 ** 9)  # effectively off, see note below
        witness_store = CheckpointWitnessStore()

        # OTPs are generated fresh, right at the point of use -- a code is
        # only valid for a short window, so caching one across a slow setup
        # step (RSA keygen for large n, etc.) is asking for a spurious
        # "expired OTP" failure that has nothing to do with the benchmark.
        t0 = time.perf_counter()
        record = issue_record(
            keystore=keystore, audit_log=audit_log, owner_role_id="owner",
            owner_passphrase="owner-passphrase-1", owner_otp=owner.current_otp(), record_id=record_id,
            message=message, custodian_role_ids=[c.role_id for c in custodians],
            threshold=k, cover_images=cover_images, entitled_requesters={"requester_q"},
        )
        t1 = time.perf_counter()

        req = request_recovery(
            keystore=keystore, audit_log=audit_log, record=record,
            requester_role_id="requester_q", requester_passphrase="requester-passphrase-1",
            requester_otp=requester.current_otp(),
        )
        for role in custodians[:k]:
            approve_share(
                keystore=keystore, audit_log=audit_log, record=record,
                custodian_role_id=role.role_id, custodian_passphrase=f"custodian-passphrase-{role.evaluation_point}",
                custodian_otp=role.current_otp(), request=req,
            )
        recovered = recover_record(
            keystore=keystore, audit_log=audit_log, witness_store=witness_store, record=record,
            requester_role_id="requester_q", requester_passphrase="requester-passphrase-1",
            requester_otp=requester.current_otp(), approvals=req.approvals,
        )
        t2 = time.perf_counter()
        assert recovered == message

        if i >= warmup:
            sample.issuance_ms.append(_ms(t1 - t0))
            sample.recovery_ms.append(_ms(t2 - t1))

    return sample


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--trials", type=int, default=300, help="trials per (k,n) setting, after warmup (paper: 300)")
    parser.add_argument("--warmup", type=int, default=20, help="warm-up runs discarded before timing (paper: 20)")
    parser.add_argument("--quick", action="store_true", help="only run (2,3) and (7,10) -- for a fast sanity check")
    parser.add_argument("--out", type=str, default="benchmark_latency.png", help="output chart path")
    args = parser.parse_args()

    settings = [SETTINGS[0], SETTINGS[-1]] if args.quick else SETTINGS
    message = os.urandom(ONE_MIB)

    print(f"Baseline: AES-GCM + single RSA-OAEP wrap (layers E+A only), "
          f"{args.trials} trials after {args.warmup} warm-up runs")
    baseline = benchmark_plain_hybrid(message, args.trials, args.warmup)
    base_issue = statistics.median(baseline.issuance_ms)
    base_recover = statistics.median(baseline.recovery_ms)
    print(f"  median issuance  = {base_issue:.3f} ms   (paper: 0.29 ms)")
    print(f"  median recovery  = {base_recover:.3f} ms   (paper: 0.76 ms)")

    print()
    print(f"{'(k, n)':<10}{'median issuance (ms)':<24}{'median recovery (ms)':<24}{'p90 recovery (ms)':<20}")
    results = []
    for k, n in settings:
        print(f"Running (k,n)=({k},{n}): {args.trials} trials after {args.warmup} warm-up runs...", flush=True)
        sample = benchmark_rtasa(k, n, message, args.trials, args.warmup)
        med_i = statistics.median(sample.issuance_ms)
        med_r = statistics.median(sample.recovery_ms)
        p90_r = _percentile(sample.recovery_ms, 90)
        print(f"{f'({k},{n})':<10}{med_i:<24.3f}{med_r:<24.3f}{p90_r:<20.3f}")
        results.append((k, n, med_i, med_r, p90_r))

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        labels = [f"({k},{n})" for k, n, *_ in results]
        issuance_vals = [r[2] for r in results]
        recovery_vals = [r[3] for r in results]

        fig, ax = plt.subplots(figsize=(7, 4.5))
        x = range(len(labels))
        ax.plot(x, issuance_vals, marker="o", label="Issuance (I)", color="#2563eb")
        ax.plot(x, recovery_vals, marker="s", label="Recovery (R)", color="#dc2626")
        ax.axhline(base_issue, linestyle="--", color="#2563eb", alpha=0.5, label="plain-hybrid issuance")
        ax.axhline(base_recover, linestyle="--", color="#dc2626", alpha=0.5, label="plain-hybrid recovery")
        ax.set_xticks(list(x))
        ax.set_xticklabels(labels)
        ax.set_xlabel("(k, n) threshold setting")
        ax.set_ylabel("Median latency (ms)")
        ax.set_title("RTASA latency vs. plain hybrid encryption (1 MiB record)")
        ax.legend()
        fig.tight_layout()
        out_path = Path(args.out)
        fig.savefig(out_path, dpi=150)
        print(f"\nWrote chart to {out_path.resolve()}")
    except ImportError:
        print("\n(matplotlib not installed -- skipping chart; table above still reproduces Fig. 2's numbers)")


if __name__ == "__main__":
    main()
