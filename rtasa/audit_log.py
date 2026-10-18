"""
Layer L -- signed, custodian-witnessed, tamper-evident audit log.

Implements Sec. IV-C:

  eq. (7)  H_t = SHA256(H_{t-1} || E_t || T_t)
           sigma_t = Sign_sk_actor(H_t)          (ECDSA over P-256)

  Checkpointing: every Delta entries, and at each reconstruction, all n
  custodians countersign and *independently retain* the current head H_t
  (like certificate-transparency witnessed logs [37]). A rewrite or
  truncation before a checkpoint then conflicts with a head an honest
  custodian already holds elsewhere; only entries after the last checkpoint
  are exposed -- the "designed window" the paper's Table IV accepts
  (truncation after the last checkpoint is the one attack RTASA does not
  catch, by design).

Two verifiers are provided:

  * `verify_plain_chain`  -- only checks hash linkage (what a "bare hash
    chain" per Schneier & Kelsey [5] gives you). This exists purely so
    `tests/test_log_tampering.py` can reproduce the "Plain chain" column of
    Table IV for comparison.
  * `AuditLog.verify`     -- the full RTASA check: hash linkage + per-entry
    ECDSA signatures + comparison against independently-retained checkpoint
    witnesses. This reproduces the "RTASA" column of Table IV.

The "independently retained" checkpoint witnesses are modelled by
`CheckpointWitnessStore`: a plain Python object that a test or the FastAPI
layer keeps *separately* from whatever `AuditLog` instance represents "what
is stored on the (untrusted) log host." That separation is exactly the
point: the log host's own copy of a checkpoint is just more data it could
tamper with, but an honest custodian's own retained copy is not reachable
by the log host.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Optional

from ecdsa import BadSignatureError, SigningKey, VerifyingKey

from .curve import CURVE

GENESIS_HASH = hashlib.sha256(b"RTASA-GENESIS").digest()
DEFAULT_CHECKPOINT_INTERVAL = 8  # Delta, matches the paper's Sec. V-B evaluation setup


def generate_signing_key() -> SigningKey:
    return SigningKey.generate(curve=CURVE)


def link_commitment(role_id: str, record_id: str, carrier_digest: str, salt: bytes) -> str:
    """Salted hash commitment to a role-to-carrier link (Sec. IV-C:
    "Role-to-carrier links appear only as salted hash commitments"). The
    audit log stores only this commitment, never the plaintext
    role<->carrier mapping, so a log reader cannot tell which stego image
    belongs to which custodian role without also knowing `salt` (held by
    the dealer/system, not published)."""
    h = hashlib.sha256()
    h.update(salt)
    h.update(role_id.encode("utf-8"))
    h.update(record_id.encode("utf-8"))
    h.update(carrier_digest.encode("utf-8"))
    return h.hexdigest()


def _canonical_bytes(event_type: str, actor_id: str, data: dict, seq: int) -> bytes:
    payload = {"seq": seq, "event_type": event_type, "actor_id": actor_id, "data": data}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class AuditEntry:
    seq: int
    event_type: str
    actor_id: str
    data: dict
    timestamp: float
    prev_hash: bytes
    entry_hash: bytes          # H_t, eq. (7)
    signature: bytes           # sigma_t = Sign_sk_actor(H_t)

    def recompute_hash(self) -> bytes:
        body = _canonical_bytes(self.event_type, self.actor_id, self.data, self.seq)
        ts = f"{self.timestamp:.6f}".encode("ascii")
        return hashlib.sha256(self.prev_hash + body + ts).digest()

    def to_dict(self) -> dict:
        return {
            "seq": self.seq,
            "event_type": self.event_type,
            "actor_id": self.actor_id,
            "data": self.data,
            "timestamp": self.timestamp,
            "prev_hash": self.prev_hash.hex(),
            "entry_hash": self.entry_hash.hex(),
            "signature": self.signature.hex(),
        }

    @staticmethod
    def from_dict(d: dict) -> "AuditEntry":
        return AuditEntry(
            seq=d["seq"],
            event_type=d["event_type"],
            actor_id=d["actor_id"],
            data=d["data"],
            timestamp=d["timestamp"],
            prev_hash=bytes.fromhex(d["prev_hash"]),
            entry_hash=bytes.fromhex(d["entry_hash"]),
            signature=bytes.fromhex(d["signature"]),
        )


@dataclass
class Checkpoint:
    seq: int                         # sequence number of the entry this checkpoint covers
    head_hash: bytes
    countersignatures: dict          # custodian_id -> signature bytes

    def to_dict(self) -> dict:
        return {
            "seq": self.seq,
            "head_hash": self.head_hash.hex(),
            "countersignatures": {k: v.hex() for k, v in self.countersignatures.items()},
        }


class CheckpointWitnessStore:
    """Models what an *honest* custodian keeps out-of-band: a copy of every
    checkpoint head, held independently of the (possibly compromised) log
    host's own storage. A real deployment would keep one such store per
    custodian, off the log host; the prototype keeps one logical copy since
    the checkpoint already requires all n custodians to agree before it is
    recorded (Sec. IV-C)."""

    def __init__(self) -> None:
        self._by_seq: dict = {}

    def record(self, checkpoint: Checkpoint) -> None:
        self._by_seq[checkpoint.seq] = checkpoint

    def get(self, seq: int) -> Optional[Checkpoint]:
        return self._by_seq.get(seq)

    def all_seqs(self) -> list:
        return sorted(self._by_seq.keys())


@dataclass
class VerificationResult:
    ok: bool
    problems: list = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.ok


class AuditLog:
    def __init__(self, checkpoint_interval: int = DEFAULT_CHECKPOINT_INTERVAL) -> None:
        self.entries: list = []
        self.checkpoints: list = []
        self.checkpoint_interval = checkpoint_interval

    @property
    def head(self) -> bytes:
        return self.entries[-1].entry_hash if self.entries else GENESIS_HASH

    def append(
        self,
        event_type: str,
        actor_id: str,
        data: dict,
        signing_key: SigningKey,
    ) -> AuditEntry:
        """Append entry E_t, compute H_t (eq. 7), and sign it with the
        acting party's own key -- sigma_t = Sign_sk_actor(H_t)."""
        seq = len(self.entries) + 1
        prev_hash = self.head
        timestamp = time.time()
        body = _canonical_bytes(event_type, actor_id, data, seq)
        ts_bytes = f"{timestamp:.6f}".encode("ascii")
        entry_hash = hashlib.sha256(prev_hash + body + ts_bytes).digest()
        signature = signing_key.sign_deterministic(entry_hash, hashfunc=hashlib.sha256)

        entry = AuditEntry(
            seq=seq,
            event_type=event_type,
            actor_id=actor_id,
            data=data,
            timestamp=timestamp,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
            signature=signature,
        )
        self.entries.append(entry)
        return entry

    def due_for_checkpoint(self) -> bool:
        return len(self.entries) > 0 and len(self.entries) % self.checkpoint_interval == 0

    def checkpoint(
        self,
        custodian_signing_keys: dict,
        witness_store: Optional[CheckpointWitnessStore] = None,
    ) -> Checkpoint:
        """All n custodians countersign the current head (Sec. IV-C). The
        resulting Checkpoint is appended to `self.checkpoints` (part of the
        tamperable log) *and*, if a `witness_store` is supplied, recorded
        there too -- modelling custodians keeping their own copy."""
        head = self.head
        seq = len(self.entries)
        countersigs = {
            custodian_id: sk.sign_deterministic(head, hashfunc=hashlib.sha256)
            for custodian_id, sk in custodian_signing_keys.items()
        }
        cp = Checkpoint(seq=seq, head_hash=head, countersignatures=countersigs)
        self.checkpoints.append(cp)
        if witness_store is not None:
            witness_store.record(cp)
        return cp

    # -- verification -----------------------------------------------------

    def verify(
        self,
        actor_public_keys: dict,
        custodian_public_keys: dict,
        witness_store: CheckpointWitnessStore,
    ) -> VerificationResult:
        """Full RTASA verification: hash-chain linkage + per-entry ECDSA
        signatures + checkpoint-vs-witness comparison. `actor_public_keys`
        maps actor_id -> VerifyingKey for whoever may append entries;
        `custodian_public_keys` maps custodian_id -> VerifyingKey for
        whoever may countersign checkpoints."""
        problems = []
        prev_hash = GENESIS_HASH

        for entry in self.entries:
            if entry.prev_hash != prev_hash:
                problems.append(
                    f"entry seq={entry.seq}: prev_hash link broken "
                    f"(expected {prev_hash.hex()[:12]}, found {entry.prev_hash.hex()[:12]})"
                )
            recomputed = entry.recompute_hash()
            if recomputed != entry.entry_hash:
                problems.append(
                    f"entry seq={entry.seq}: stored hash does not match recomputed H_t "
                    "(content was edited without a consistent recompute)"
                )

            pub = actor_public_keys.get(entry.actor_id)
            if pub is None:
                problems.append(f"entry seq={entry.seq}: unknown actor '{entry.actor_id}'")
            else:
                try:
                    pub.verify(entry.signature, entry.entry_hash, hashfunc=hashlib.sha256)
                except BadSignatureError:
                    problems.append(
                        f"entry seq={entry.seq}: ECDSA signature does not verify under "
                        f"{entry.actor_id}'s public key (forged or edited-without-resigning, "
                        "or resigned by someone without that private key)"
                    )
            prev_hash = entry.entry_hash  # chain continues from the *stored* hash either way

        # Checkpoint self-consistency: a stored checkpoint must actually
        # match what is currently sitting in the log at that position. This
        # closes the loophole where an attacker edits+re-signs an entry
        # *at* a checkpointed position but leaves the (also tamperable)
        # stored Checkpoint record referring to the old hash -- that would
        # otherwise look fine against the witness copy while silently
        # disagreeing with the log's own entries.
        entries_by_seq = {e.seq: e for e in self.entries}
        for stored_cp in self.checkpoints:
            entry_at_seq = entries_by_seq.get(stored_cp.seq)
            if entry_at_seq is not None and entry_at_seq.entry_hash != stored_cp.head_hash:
                problems.append(
                    f"checkpoint at seq={stored_cp.seq}: recorded head "
                    f"{stored_cp.head_hash.hex()[:12]} does not match the log's own "
                    f"entry at that position ({entry_at_seq.entry_hash.hex()[:12]})"
                )

        # Checkpoint-vs-witness comparison: catches a rewrite/truncation that
        # is otherwise internally self-consistent (correct links, correct
        # signatures -- e.g. an insider editing their own entry and
        # re-signing it, or truncating entries before the last checkpoint).
        stored_by_seq = {cp.seq: cp for cp in self.checkpoints}
        for witnessed_seq in witness_store.all_seqs():
            witnessed_cp = witness_store.get(witnessed_seq)
            stored_cp = stored_by_seq.get(witnessed_seq)
            if stored_cp is None:
                problems.append(
                    f"checkpoint at seq={witnessed_seq} is missing from the log "
                    "(truncated before a witnessed checkpoint)"
                )
                continue
            if stored_cp.head_hash != witnessed_cp.head_hash:
                problems.append(
                    f"checkpoint at seq={witnessed_seq}: log's head "
                    f"{stored_cp.head_hash.hex()[:12]} disagrees with the independently "
                    f"retained custodian copy {witnessed_cp.head_hash.hex()[:12]}"
                )
            # also re-verify the countersignatures themselves are intact
            for custodian_id, pub in custodian_public_keys.items():
                sig = witnessed_cp.countersignatures.get(custodian_id)
                if sig is None:
                    continue
                try:
                    pub.verify(sig, witnessed_cp.head_hash, hashfunc=hashlib.sha256)
                except BadSignatureError:
                    problems.append(
                        f"checkpoint at seq={witnessed_seq}: countersignature by "
                        f"'{custodian_id}' does not verify"
                    )

        # Also flag a log that is *shorter* than the last witnessed checkpoint
        # expects, even if that checkpoint's own entry happens to still be
        # present (covers truncation of everything strictly between two
        # checkpoints while keeping the checkpoint entries themselves).
        if witness_store.all_seqs():
            last_witnessed = max(witness_store.all_seqs())
            if len(self.entries) < last_witnessed:
                problems.append(
                    f"log has only {len(self.entries)} entries but a checkpoint at "
                    f"seq={last_witnessed} was independently witnessed"
                )

        return VerificationResult(ok=not problems, problems=problems)


def verify_plain_chain(entries: list) -> VerificationResult:
    """What a bare hash chain (no signatures, no checkpoints) can check:
    pure linkage, recomputed from whatever the log host currently stores.
    This is deliberately weak -- it exists to reproduce the "Plain chain"
    column of Table IV, which a log host that recomputes hashes after an
    edit, or an insider with no key-based signature requirement at all,
    defeats trivially."""
    problems = []
    prev_hash = GENESIS_HASH
    for entry in entries:
        if entry.prev_hash != prev_hash:
            problems.append(f"entry seq={entry.seq}: prev_hash link broken")
        if entry.recompute_hash() != entry.entry_hash:
            problems.append(f"entry seq={entry.seq}: stored hash != recomputed hash")
        prev_hash = entry.entry_hash
    return VerificationResult(ok=not problems, problems=problems)
