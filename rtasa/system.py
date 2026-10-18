"""
`RTASASystem` is the single in-process facade over the five layers: it
owns the role key store (A), the current set of issued records (E + T +
S), the audit log and checkpoint witnesses (L), and exposes exactly the
three operations Fig. 1 describes -- issue, request/approve recovery, and
recover -- as plain Python calls. Both `scripts/demo.py` and the FastAPI
app in `app/` sit on top of this one class so the cryptographic pipeline
is exercised identically whether it is driven from the CLI, from pytest,
or over HTTP.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

from .audit_log import AuditLog, CheckpointWitnessStore
from .issuance import issue_record
from .keystore import RoleIdentity, RoleKeyStore
from .records import Record
from .recovery import RecoveryRequest, approve_share, recover_record, request_recovery


@dataclass
class RTASASystem:
    keystore: RoleKeyStore = field(default_factory=RoleKeyStore)
    audit_log: AuditLog = field(default_factory=AuditLog)
    witness_store: CheckpointWitnessStore = field(default_factory=CheckpointWitnessStore)
    records: dict = field(default_factory=dict)              # record_id -> Record
    recovery_requests: dict = field(default_factory=dict)    # request_id -> RecoveryRequest

    # -- roles --------------------------------------------------------

    def create_role(
        self,
        role_id: str,
        display_name: str,
        passphrase: str,
        is_custodian: bool = False,
        evaluation_point: Optional[int] = None,
        email: Optional[str] = None,
    ) -> RoleIdentity:
        identity = RoleIdentity.create(
            role_id, display_name, passphrase,
            is_custodian=is_custodian, evaluation_point=evaluation_point, email=email,
        )
        self.keystore.add(identity)
        return identity

    # -- issuance -------------------------------------------------------

    def issue(
        self,
        *,
        owner_role_id: str,
        owner_passphrase: str,
        owner_otp: str,
        record_id: str,
        message: bytes,
        custodian_role_ids: Iterable[str],
        threshold: int,
        cover_images: dict,
        entitled_requesters: Iterable[str] = (),
    ) -> Record:
        record = issue_record(
            keystore=self.keystore,
            audit_log=self.audit_log,
            owner_role_id=owner_role_id,
            owner_passphrase=owner_passphrase,
            owner_otp=owner_otp,
            record_id=record_id,
            message=message,
            custodian_role_ids=custodian_role_ids,
            threshold=threshold,
            cover_images=cover_images,
            entitled_requesters=entitled_requesters,
        )
        self.records[record_id] = record
        if self.audit_log.due_for_checkpoint():
            self._checkpoint()
        return record

    # -- recovery -------------------------------------------------------

    def start_recovery(
        self, request_id: str, *, record_id: str, requester_role_id: str,
        requester_passphrase: str, requester_otp: str,
    ) -> RecoveryRequest:
        record = self.records[record_id]
        req = request_recovery(
            keystore=self.keystore,
            audit_log=self.audit_log,
            record=record,
            requester_role_id=requester_role_id,
            requester_passphrase=requester_passphrase,
            requester_otp=requester_otp,
        )
        self.recovery_requests[request_id] = req
        return req

    def approve(
        self, request_id: str, *, custodian_role_id: str,
        custodian_passphrase: str, custodian_otp: str,
    ) -> bytes:
        req = self.recovery_requests[request_id]
        record = self.records[req.record_id]
        wrapped = approve_share(
            keystore=self.keystore,
            audit_log=self.audit_log,
            record=record,
            custodian_role_id=custodian_role_id,
            custodian_passphrase=custodian_passphrase,
            custodian_otp=custodian_otp,
            request=req,
        )
        return wrapped

    def recover(
        self, request_id: str, *, requester_passphrase: str, requester_otp: str,
    ) -> bytes:
        req = self.recovery_requests[request_id]
        record = self.records[req.record_id]
        message = recover_record(
            keystore=self.keystore,
            audit_log=self.audit_log,
            witness_store=self.witness_store,
            record=record,
            requester_role_id=req.requester_role_id,
            requester_passphrase=requester_passphrase,
            requester_otp=requester_otp,
            approvals=req.approvals,
        )
        return message

    # -- audit ------------------------------------------------------------

    def _checkpoint(self) -> None:
        custodian_keys = {
            rid: role.signing_key()
            for rid, role in self.keystore.custodians().items()
        }
        self.audit_log.checkpoint(custodian_keys, witness_store=self.witness_store)

    def verify_audit_log(self):
        actor_keys = {rid: role.verifying_key() for rid, role in self.keystore.roles.items()}
        custodian_keys = {
            rid: role.verifying_key() for rid, role in self.keystore.custodians().items()
        }
        return self.audit_log.verify(actor_keys, custodian_keys, self.witness_store)
