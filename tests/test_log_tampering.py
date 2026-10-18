"""
Reproduces Table IV of the paper: seven log attacks, checked against both
a "plain hash chain" (eq. 7 linkage only, no signatures, no checkpoints --
`verify_plain_chain`) and the full RTASA verifier (`AuditLog.verify`).

The paper runs each attack 200 times on randomized 64-entry logs. These
tests are deterministic, structural reproductions of the same seven
attacks (not a 200-trial statistical study) -- each one is run against a
handful of different tamper positions to confirm the result holds
generally, not just for one lucky index.
"""

from __future__ import annotations

import copy
import hashlib

import pytest

from rtasa.audit_log import AuditLog, CheckpointWitnessStore, generate_signing_key, verify_plain_chain

NUM_ENTRIES = 64
CHECKPOINT_INTERVAL = 8


def _fresh_log():
    actors = {aid: generate_signing_key() for aid in ["D", "R1", "R2", "R3"]}
    custodians = {cid: actors[cid] for cid in ["R1", "R2", "R3"]}
    log = AuditLog(checkpoint_interval=CHECKPOINT_INTERVAL)
    witness = CheckpointWitnessStore()
    for i in range(NUM_ENTRIES):
        actor = "D" if i % 4 == 0 else "R1"
        log.append("event", actor, {"i": i}, actors[actor])
        if log.due_for_checkpoint():
            log.checkpoint(custodians, witness_store=witness)
    pubkeys = {aid: sk.verifying_key for aid, sk in actors.items()}
    custodian_pub = {cid: sk.verifying_key for cid, sk in custodians.items()}
    return log, witness, actors, pubkeys, custodian_pub


def _rtasa_detects(log, pubkeys, custodian_pub, witness) -> bool:
    return not log.verify(pubkeys, custodian_pub, witness).ok


def _plain_detects(log) -> bool:
    return not verify_plain_chain(log.entries).ok


@pytest.mark.parametrize("edit_index", [5, 20, 40])
def test_edit_entry_no_recomputation(edit_index):
    log, witness, actors, pubkeys, cpub = _fresh_log()
    log.entries[edit_index].data = {"tampered": True}
    assert _plain_detects(log) is True
    assert _rtasa_detects(log, pubkeys, cpub, witness) is True


@pytest.mark.parametrize("edit_index", [5, 20, 40])
def test_edit_entry_host_recomputes_chain(edit_index):
    """Attacker edits one entry's content and recomputes every hash from
    there on (so linkage is perfect), but cannot re-sign entries it does
    not hold the key for -- RTASA's per-entry signature check still
    catches it; a plain hash chain cannot."""
    log, witness, actors, pubkeys, cpub = _fresh_log()

    entry = log.entries[edit_index]
    entry.data = {"tampered": True}
    entry.entry_hash = entry.recompute_hash()
    # signature is now stale (it was computed over the OLD entry_hash) --
    # the attacker has no key to fix it.
    prev_hash = entry.entry_hash
    for e in log.entries[edit_index + 1:]:
        e.prev_hash = prev_hash
        e.entry_hash = e.recompute_hash()
        # likewise: these signatures are now stale too
        prev_hash = e.entry_hash

    assert _plain_detects(log) is False  # linkage is self-consistent
    assert _rtasa_detects(log, pubkeys, cpub, witness) is True  # signatures broke


def test_insider_edits_own_entry_and_resigns():
    """The insider controls one actor's real signing key, so they can
    produce a *validly signed* edited entry. To avoid breaking any
    downstream entry's signature, the edit targets the very last entry in
    the log, at a position that was already checkpointed -- exactly the
    scenario the checkpoint-witness mechanism exists for (Sec. IV-C)."""
    log, witness, actors, pubkeys, cpub = _fresh_log()
    assert NUM_ENTRIES % CHECKPOINT_INTERVAL == 0  # last entry is itself checkpointed

    last = log.entries[-1]
    insider_key = actors[last.actor_id]  # insider legitimately holds this key
    last.data = {"tampered": True}
    last.entry_hash = last.recompute_hash()
    last.signature = insider_key.sign_deterministic(last.entry_hash, hashfunc=hashlib.sha256)

    # Whether or not the insider also patches the stored Checkpoint record
    # to match, the comparison against the independently-retained witness
    # copy (or the log's own now-inconsistent checkpoint) gives it away.
    assert _plain_detects(log) is False  # hash+signature are both "valid" in isolation
    assert _rtasa_detects(log, pubkeys, cpub, witness) is True


def test_insider_edit_also_caught_when_checkpoint_record_is_patched_to_match():
    log, witness, actors, pubkeys, cpub = _fresh_log()
    last = log.entries[-1]
    insider_key = actors[last.actor_id]
    last.data = {"tampered": True}
    last.entry_hash = last.recompute_hash()
    last.signature = insider_key.sign_deterministic(last.entry_hash, hashfunc=hashlib.sha256)
    log.checkpoints[-1].head_hash = last.entry_hash  # attacker "fixes up" the stored checkpoint too

    assert _rtasa_detects(log, pubkeys, cpub, witness) is True  # now disagrees with the witness copy


@pytest.mark.parametrize("insert_index", [5, 20, 40])
def test_insert_forged_entry_recompute(insert_index):
    """A forged entry claims to be from a real actor but is signed with a
    freshly generated (attacker-controlled) key -- it cannot pass
    signature verification under that actor's real, known public key."""
    log, witness, actors, pubkeys, cpub = _fresh_log()

    forger_key = generate_signing_key()  # NOT any real actor's key
    forged = copy.deepcopy(log.entries[insert_index])
    forged.actor_id = "D"  # impersonating a real actor -- set *before* hashing
    forged.data = {"forged": True}
    forged.prev_hash = log.entries[insert_index - 1].entry_hash if insert_index > 0 else forged.prev_hash
    forged.entry_hash = forged.recompute_hash()
    forged.signature = forger_key.sign_deterministic(forged.entry_hash, hashfunc=hashlib.sha256)

    log.entries.insert(insert_index, forged)
    # recompute the chain forward so linkage stays consistent
    prev_hash = forged.entry_hash
    for e in log.entries[insert_index + 1:]:
        e.prev_hash = prev_hash
        e.entry_hash = e.recompute_hash()
        prev_hash = e.entry_hash

    assert _plain_detects(log) is False  # linkage looks fine
    assert _rtasa_detects(log, pubkeys, cpub, witness) is True  # forged signature does not


@pytest.mark.parametrize("delete_index", [5, 20, 40])
def test_delete_entry_no_recomputation(delete_index):
    log, witness, actors, pubkeys, cpub = _fresh_log()
    del log.entries[delete_index]  # downstream prev_hash now points at a hash that no longer precedes it
    assert _plain_detects(log) is True
    assert _rtasa_detects(log, pubkeys, cpub, witness) is True


def test_truncate_before_last_checkpoint():
    log, witness, actors, pubkeys, cpub = _fresh_log()
    last_checkpoint_seq = max(witness.all_seqs())
    assert last_checkpoint_seq == NUM_ENTRIES  # sanity: log ends on a checkpoint boundary here
    # Drop everything from well before the final checkpoint onward.
    cutoff = last_checkpoint_seq - CHECKPOINT_INTERVAL - 3
    log.entries = log.entries[:cutoff]
    log.checkpoints = [cp for cp in log.checkpoints if cp.seq <= cutoff]

    assert _plain_detects(log) is False  # the remaining prefix is perfectly self-consistent
    assert _rtasa_detects(log, pubkeys, cpub, witness) is True  # missing a witnessed checkpoint


def test_truncate_after_last_checkpoint_is_the_designed_blind_spot():
    """Table IV: this is the one attack RTASA does *not* catch -- entries
    added after the last checkpoint have not been witnessed yet, so
    nothing external disagrees with a truncation that only drops them."""
    log, witness, actors, pubkeys, cpub = _fresh_log()

    # Append a few more, un-checkpointed entries, then drop them again.
    extra_signer = actors["R1"]
    for i in range(3):
        log.append("event", "R1", {"extra": i}, extra_signer)
    last_checkpoint_seq = max(witness.all_seqs())
    log.entries = log.entries[:last_checkpoint_seq]  # truncate back to the last checkpoint

    assert _plain_detects(log) is False
    assert _rtasa_detects(log, pubkeys, cpub, witness) is False  # designed gap, matches Table IV
