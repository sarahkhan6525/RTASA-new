"""SQLAlchemy ORM models backing the RTASA FastAPI service.

These tables are a durability layer around the pure-Python cryptographic
core in `rtasa/` -- none of `rtasa/*.py` imports SQLAlchemy, so the five
layers stay independently testable (see `tests/`) without a database.
This module only has to be able to round-trip a `rtasa.system.RTASASystem`
to and from rows; `app/persistence.py` does the actual conversion.
"""

from __future__ import annotations

from sqlalchemy import JSON, Float, ForeignKey, Integer, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


class RoleRow(Base):
    __tablename__ = "roles"

    role_id: Mapped[str] = mapped_column(String, primary_key=True)
    display_name: Mapped[str] = mapped_column(String)
    email: Mapped[str] = mapped_column(String, nullable=True)  # for email-OTP login (app/auth.py)
    is_custodian: Mapped[bool] = mapped_column(Integer)  # 0/1
    evaluation_point: Mapped[int] = mapped_column(Integer, nullable=True)
    # rsa_private_pem, signing_key_pem, and totp_secret hold AES-256-GCM-sealed
    # bytes/base64 (rtasa/secrets_vault.py), not plaintext -- see app/persistence.py.
    rsa_private_pem: Mapped[bytes] = mapped_column(LargeBinary)
    rsa_public_pem: Mapped[bytes] = mapped_column(LargeBinary)
    signing_key_pem: Mapped[str] = mapped_column(String)
    verifying_key_pem: Mapped[str] = mapped_column(String)
    passphrase_hash: Mapped[str] = mapped_column(String)  # Argon2id, self-contained salt
    totp_secret: Mapped[str] = mapped_column(String)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[float] = mapped_column(Float, default=0.0)


class RecordRow(Base):
    __tablename__ = "records"

    record_id: Mapped[str] = mapped_column(String, primary_key=True)
    owner_role_id: Mapped[str] = mapped_column(String, nullable=True)
    threshold: Mapped[int] = mapped_column(Integer)
    custodian_role_ids: Mapped[list] = mapped_column(JSON)
    entitled_requesters: Mapped[list] = mapped_column(JSON)
    ciphertext_nonce: Mapped[str] = mapped_column(String)
    ciphertext_blob: Mapped[str] = mapped_column(String)
    commitments_json: Mapped[list] = mapped_column(JSON)
    link_salt: Mapped[str] = mapped_column(String)

    carriers: Mapped[list["CarrierRow"]] = relationship(
        "CarrierRow", back_populates="record", cascade="all, delete-orphan"
    )


class CarrierRow(Base):
    __tablename__ = "carriers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    record_id: Mapped[str] = mapped_column(ForeignKey("records.record_id"))
    role_id: Mapped[str] = mapped_column(String)
    image_width: Mapped[int] = mapped_column(Integer)
    image_height: Mapped[int] = mapped_column(Integer)
    image_bytes: Mapped[bytes] = mapped_column(LargeBinary)       # raw uint8 pixel bytes
    wrapped_kappa: Mapped[bytes] = mapped_column(LargeBinary)
    payload_len_bytes: Mapped[int] = mapped_column(Integer)

    record: Mapped["RecordRow"] = relationship("RecordRow", back_populates="carriers")


class AuditEntryRow(Base):
    __tablename__ = "audit_entries"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_type: Mapped[str] = mapped_column(String)
    actor_id: Mapped[str] = mapped_column(String)
    data_json: Mapped[dict] = mapped_column(JSON)
    timestamp: Mapped[float] = mapped_column(Float)
    prev_hash: Mapped[str] = mapped_column(String)
    entry_hash: Mapped[str] = mapped_column(String)
    signature: Mapped[str] = mapped_column(String)


class CheckpointRow(Base):
    __tablename__ = "checkpoints"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True)
    head_hash: Mapped[str] = mapped_column(String)
    countersignatures_json: Mapped[dict] = mapped_column(JSON)
