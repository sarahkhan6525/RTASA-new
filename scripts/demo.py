"""
End-to-end console walkthrough of RTASA, in two parts:

  Part 1 -- reproduces the paper's own toy example (Sec. IV-D) over the
            small field Z_17 / the order-17 subgroup of Z*_103, so the
            numbers in the console output can be checked by hand against
            the paper.

  Part 2 -- runs the real pipeline (real P-256 field, real AES-256-GCM,
            RSA-2048-OAEP, LSB-matching embedding into a synthetic
            768x512 grayscale cover, and the signed/checkpointed audit
            log) end to end for a (k, n) = (2, 3) record, printing each
            step with the Fig. 1 layer tag (E / A / T / S / L) it
            realizes, then shows what the audit log catches when an
            entry is tampered with afterward.

Run with:

    python -m scripts.demo
"""

from __future__ import annotations

import textwrap

import numpy as np

from carriers.generate_carriers import make_synthetic_cover
from rtasa.audit_log import AuditLog, CheckpointWitnessStore
from rtasa.crypto_core import derive_ke, encrypt_record
from rtasa.issuance import issue_record
from rtasa.keystore import RoleKeyStore
from rtasa.recovery import approve_share, recover_record, request_recovery
from rtasa.stego import embedding_stats


def _header(title: str) -> None:
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def _step(tag: str, text: str) -> None:
    print(f"[{tag}] {text}")


# --------------------------------------------------------------------------
# Part 1: the paper's toy example (Sec. IV-D), small field, by hand
# --------------------------------------------------------------------------

def toy_example() -> None:
    _header("PART 1 -- paper's toy (k, n) = (2, 3) example, Sec. IV-D")
    p, order, g = 103, 17, 64  # order-17 subgroup of Z*_103, generator g = 64
    a0, a1 = 6, 5              # f(x) = 6 + 5x mod 17  ==>  K = f(0) = 6

    def f(x: int) -> int:
        return (a0 + a1 * x) % order

    shares = {x: f(x) for x in (1, 2, 3)}
    print(f"f(x) = {a0} + {a1}x (mod {order}); K = f(0) = {a0}")
    print(f"shares: " + ", ".join(f"({x}, {y})" for x, y in shares.items()))

    c0 = pow(g, a0, p)
    c1 = pow(g, a1, p)
    print(f"Feldman commitments: C0 = g^{a0} mod {p} = {c0}, C1 = g^{a1} mod {p} = {c1}")

    def check(x: int, y: int) -> bool:
        lhs = pow(g, y, p)
        rhs = (c0 * pow(c1, x, p)) % p
        return lhs == rhs

    for x, y in shares.items():
        print(f"  check share ({x}, {y}): g^y mod {p} = {pow(g, y, p)}, "
              f"C0*C1^{x} mod {p} = {(c0 * pow(c1, x, p)) % p} -> {'PASS' if check(x, y) else 'FAIL'}")

    corrupted_y = 12
    print(f"  check CORRUPTED share (1, {corrupted_y}): "
          f"{'PASS' if check(1, corrupted_y) else 'FAIL (as expected)'}")

    # Lagrange interpolation at x=0 from shares (1, 11) and (2, 16)
    x1, y1 = 1, shares[1]
    x2, y2 = 2, shares[2]
    inv = pow(x2 - x1, -1, order)
    recovered = (y1 * x2 * inv - y2 * x1 * inv) % order
    print(f"  Lagrange from shares 1,2 -> K = {recovered} (expected {a0})")


# --------------------------------------------------------------------------
# Part 2: the real pipeline, end to end
# --------------------------------------------------------------------------

def real_pipeline_demo() -> None:
    _header("PART 2 -- full RTASA pipeline, (k, n) = (2, 3), real crypto")

    keystore = RoleKeyStore()
    from rtasa.keystore import RoleIdentity

    owner = RoleIdentity.create("hospital_registrar", "Hospital Registrar (D)", "registrar-pass-1")
    keystore.add(owner)

    custodians = []
    for i, (rid, name) in enumerate(
        [("chief_physician", "Chief Physician"), ("compliance_officer", "Compliance Officer"),
         ("it_security_lead", "IT Security Lead")],
        start=1,
    ):
        role = RoleIdentity.create(rid, name, f"{rid}-pass-1", is_custodian=True, evaluation_point=i)
        keystore.add(role)
        custodians.append(role)

    requester = RoleIdentity.create("auditor_q", "External Auditor (Q)", "auditor-pass-1")
    keystore.add(requester)

    audit_log = AuditLog(checkpoint_interval=8)
    witness_store = CheckpointWitnessStore()

    record_id = "patient-record-00417"
    message = b"Patient 00417: diagnosis, treatment plan, and billing codes."

    cover_images = {
        role.role_id: make_synthetic_cover(seed=i) for i, role in enumerate(custodians)
    }

    print(textwrap.dedent(f"""
        Scenario: {owner.display_name} issues one confidential record.
        Custodians (n=3): {', '.join(c.display_name for c in custodians)}
        Threshold: k=2 of n=3 custodians must approve before recovery.
        Entitled requester: {requester.display_name}
    """).strip())

    _step("E+T+A+S", "Issuing record: AES-GCM encrypt -> Shamir split + Feldman commit "
                      "-> RSA-OAEP wrap per role -> LSB-matching embed per role (eq. 2-6)")
    record = issue_record(
        keystore=keystore,
        audit_log=audit_log,
        owner_role_id=owner.role_id,
        owner_passphrase="registrar-pass-1",
        owner_otp=owner.current_otp(),
        record_id=record_id,
        message=message,
        custodian_role_ids=[c.role_id for c in custodians],
        threshold=2,
        cover_images=cover_images,
        entitled_requesters={requester.role_id},
    )
    print(f"      -> record '{record.record_id}' issued; "
          f"{len(record.carriers)} stego carriers produced.")

    for rid, carrier in record.carriers.items():
        stats = embedding_stats(cover_images[rid], carrier.stego_image)
        print(f"      -> [{rid}] carrier: {stats.changed_pixels} px changed "
              f"({100 * stats.changed_fraction:.3f}%), PSNR = {stats.psnr_db:.1f} dB "
              "(cf. paper's 1.6% / 66.2 dB at its own payload/cover size, Sec. V-D)")

    _step("L", "D published Feldman commitments and a salted carrier-link commitment "
               "to the audit log for every custodian (Sec. IV-C).")

    print()
    _step("A", f"'{requester.display_name}' sends a signed recovery request.")
    req = request_recovery(
        keystore=keystore, audit_log=audit_log, record=record,
        requester_role_id=requester.role_id, requester_passphrase="auditor-pass-1",
        requester_otp=requester.current_otp(),
    )

    approving = custodians[:2]  # exactly k=2 of the n=3 custodians approve
    for role in approving:
        _step("T+A+L", f"'{role.display_name}' extracts its share from its own carrier, "
                        "Feldman-checks it (eq. 4), re-wraps it under Q's key, signs its approval.")
        approve_share(
            keystore=keystore, audit_log=audit_log, record=record,
            custodian_role_id=role.role_id, custodian_passphrase=f"{role.role_id}-pass-1",
            custodian_otp=role.current_otp(), request=req,
        )

    _step("T+E+L", "Requester interpolates K from the 2 approved shares (eq. 9), "
                   "derives ke, and lets AES-GCM's tag confirm integrity.")
    recovered = recover_record(
        keystore=keystore, audit_log=audit_log, witness_store=witness_store, record=record,
        requester_role_id=requester.role_id, requester_passphrase="auditor-pass-1",
        requester_otp=requester.current_otp(), approvals=req.approvals,
    )
    print(f"      -> recovered message: {recovered!r}")
    assert recovered == message, "recovered message did not match the original!"

    print()
    actor_keys = {rid: r.verifying_key() for rid, r in keystore.roles.items()}
    custodian_keys = {c.role_id: c.verifying_key() for c in custodians}
    result = audit_log.verify(actor_keys, custodian_keys, witness_store)
    _step("L", f"Clean-log verification: {'OK' if result.ok else 'TAMPERED: ' + str(result.problems)}")

    _header("PART 3 -- what happens if someone edits the log afterward")
    tampered_entry = audit_log.entries[1]
    print(f"Before: entry seq={tampered_entry.seq} data={tampered_entry.data}")
    tampered_entry.data = {"record_id": record_id, "threshold": 999, "custodians": "ALL OF THEM"}
    print(f"After:  entry seq={tampered_entry.seq} data={tampered_entry.data}  (edited, NOT re-signed)")
    result2 = audit_log.verify(actor_keys, custodian_keys, witness_store)
    _step("L", f"Re-verification: {'OK' if result2.ok else 'TAMPER DETECTED:'}")
    for p in result2.problems:
        print(f"      - {p}")


if __name__ == "__main__":
    toy_example()
    real_pipeline_demo()
    print()
    print("Demo complete. See tests/ for the full Table III / Table IV reproduction,")
    print("and app/main.py for the FastAPI backend (`uvicorn app.main:app --reload`).")
