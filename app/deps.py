"""Shared FastAPI dependencies: a DB session per request, and access to the
single in-process `RTASASystem` the app keeps in `app.state` (loaded from
the database at startup, re-saved after every mutating call)."""

from __future__ import annotations

from fastapi import Request
from sqlalchemy.orm import Session

from rtasa.system import RTASASystem

from .db import SessionLocal


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_system(request: Request) -> RTASASystem:
    return request.app.state.system


def persist(db: Session, system: RTASASystem) -> None:
    from .persistence import save_system

    save_system(db, system)
