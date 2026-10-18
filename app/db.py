"""SQLAlchemy engine/session setup for the RTASA backend.

Per the project notes this backend is built with FastAPI + SQLAlchemy.
Storage is a local SQLite file (no cloud dependency, consistent with the
project's "local execution only" selection criterion) at `./rtasa.db`,
overridable via the RTASA_DB_URL environment variable.
"""

from __future__ import annotations

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

DB_URL = os.environ.get("RTASA_DB_URL", "sqlite:///./rtasa.db")

engine = create_engine(DB_URL, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def init_db() -> None:
    from . import models  # noqa: F401  (ensure models are registered on Base)

    Base.metadata.create_all(bind=engine)
    _migrate_add_missing_columns()


def _migrate_add_missing_columns() -> None:
    """Lightweight, dependency-free migration: `create_all` only creates
    tables that don't exist yet, it never ALTERs an existing table. This
    project has no Alembic (kept deliberately simple for a prototype), so
    when a new nullable column is added to a model after a `rtasa.db`
    already exists on disk (e.g. `roles.email`, added for the email-OTP
    login flow), add it here by hand. Safe to run every startup: it only
    adds a column if it's actually missing."""
    if not DB_URL.startswith("sqlite"):
        return
    with engine.connect() as conn:
        existing_roles_cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(roles)").fetchall()}
        if existing_roles_cols and "email" not in existing_roles_cols:
            conn.exec_driver_sql("ALTER TABLE roles ADD COLUMN email VARCHAR")
            conn.commit()

        existing_records_cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(records)").fetchall()}
        if existing_records_cols and "owner_role_id" not in existing_records_cols:
            conn.exec_driver_sql("ALTER TABLE records ADD COLUMN owner_role_id VARCHAR")
            conn.commit()


def get_session() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
