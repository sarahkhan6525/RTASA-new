from __future__ import annotations

import copy

from rtasa.audit_log import AuditLog, CheckpointWitnessStore, generate_signing_key


def _build_log(num_entries=20, checkpoint_interval=8):
    actors = {aid: generate_signing_key() for aid in ["D", "R1", "R2", "R3"]}
    custodians = {cid: actors[cid] for cid in ["R1", "R2", "R3"]}
    log = AuditLog(checkpoint_interval=checkpoint_interval)
    witness = CheckpointWitnessStore()
    for i in range(num_entries):
        actor = "D" if i % 5 == 0 else "R1"
        log.append("event", actor, {"i": i}, actors[actor])
        if log.due_for_checkpoint():
            log.checkpoint(custodians, witness_store=witness)
    pubkeys = {aid: sk.verifying_key for aid, sk in actors.items()}
    custodian_pub = {cid: sk.verifying_key for cid, sk in custodians.items()}
    return log, witness, pubkeys, custodian_pub


def test_clean_log_verifies():
    log, witness, pubkeys, cpub = _build_log()
    result = log.verify(pubkeys, cpub, witness)
    assert result.ok, result.problems


def test_hash_chain_links_entries():
    log, *_ = _build_log(num_entries=5, checkpoint_interval=100)
    for i in range(1, len(log.entries)):
        assert log.entries[i].prev_hash == log.entries[i - 1].entry_hash


def test_checkpoint_recorded_every_delta_entries():
    log, witness, *_ = _build_log(num_entries=17, checkpoint_interval=8)
    assert [cp.seq for cp in log.checkpoints] == [8, 16]
    assert witness.all_seqs() == [8, 16]


def test_entry_hash_matches_recompute():
    log, *_ = _build_log(num_entries=5, checkpoint_interval=100)
    for entry in log.entries:
        assert entry.recompute_hash() == entry.entry_hash
