from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HeartbeatStatus:
    ok: bool
    reason: str
    age_seconds: int | None


def heartbeat_status(last_seen: int | None, now: int, max_age_seconds: int) -> HeartbeatStatus:
    if last_seen is None:
        return HeartbeatStatus(False, "no-data", None)
    age = now - last_seen
    if age > max_age_seconds:
        return HeartbeatStatus(False, "stale", age)
    return HeartbeatStatus(True, "ok", age)
