from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class BreakGlassRecord:
    reason: str
    human: str
    created_at: int
    expires_at: int
    target: str
    audit_log_path: str


@dataclass(frozen=True)
class BreakGlassValidation:
    ok: bool
    reason: str


def validate_breakglass(record: BreakGlassRecord | None, target: str, now: int | None = None) -> BreakGlassValidation:
    if record is None:
        return BreakGlassValidation(False, "missing-breakglass")
    now = int(time.time()) if now is None else now
    if not record.reason.strip():
        return BreakGlassValidation(False, "missing-reason")
    if not record.human.strip():
        return BreakGlassValidation(False, "missing-human-confirmation")
    if record.target != target:
        return BreakGlassValidation(False, "target-mismatch")
    if record.expires_at < now:
        return BreakGlassValidation(False, "expired")
    if not record.audit_log_path.startswith("/"):
        return BreakGlassValidation(False, "audit-log-not-absolute")
    return BreakGlassValidation(True, "ok")


def audit_line(record: BreakGlassRecord, action: str) -> str:
    payload = asdict(record) | {"action": action}
    return canonical_json_line(payload)


def canonical_json_line(payload: dict[str, object]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
