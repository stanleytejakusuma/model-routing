from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class MutationRequest:
    action_type: str
    exact_action: str
    cwd: str
    repo_id: str
    host: str
    target: str
    is_capital: bool
    is_read_only: bool
    risk_class: str


@dataclass(frozen=True)
class MutationDecision:
    allowed: bool
    reason: str


def evaluate_mutation(
    request: MutationRequest,
    signed_intent: Any | None,
    breakglass: Any | None,
) -> MutationDecision:
    if request.is_read_only:
        return MutationDecision(True, "read-only")

    if request.is_capital:
        if getattr(signed_intent, "ok", False):
            return MutationDecision(True, "opus-signed-intent")
        if getattr(breakglass, "ok", False):
            return MutationDecision(True, "breakglass")
        return MutationDecision(False, "missing-capital-intent")

    return MutationDecision(True, "non-capital")
