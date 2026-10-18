"""A live, click-to-run battery reproducing Table III's adversarial
checks and one Table IV row, for the frontend's "Security Testing" tab.
Runs entirely against a disposable scratch system (see
`rtasa.security_tests`) -- it never touches the real, live
`RTASASystem` this process also serves, so it is safe to call as many
times as a demo needs without any risk to real records, custodians, or
the real audit log."""

from __future__ import annotations

from fastapi import APIRouter

from rtasa.security_tests import run_security_battery

from .. import schemas

router = APIRouter(prefix="/security-tests", tags=["security-tests"])


@router.post("/run", response_model=schemas.SecurityTestBattery)
def run():
    results = run_security_battery()
    return schemas.SecurityTestBattery(results=results)
