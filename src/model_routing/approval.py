"""Capital-action approval loop (INERT — not armed).

Connects a blocked capital action to a signed intent through two separated sides
so the Ed25519 private key never leaves the gatekeeper host:

  request side  (no key): classify -> independent Opus review -> ApprovalPackage
  gatekeeper side (key) : re-check Opus approval + REQUIRE human confirmation -> sign

Design invariants:
  * fail-closed: the default Opus reviewer REJECTS (it is an unwired placeholder).
  * the gatekeeper signs only when BOTH the Opus review approved AND a human
    confirmation is given for THIS exact request_id (the trigger-gate: a human
    authorizes every irreversible capital action).
  * the real Opus reviewer (an independent opus-verifier subagent) MUST replace
    `placeholder_opus_reviewer` before arming.

Nothing here installs, deploys, or performs a live capital action.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from model_routing.classifier import CommandClassification
from model_routing.lifecycle import (
    ApprovalDecision,
    ApprovalRequest,
    build_approval_request,
    build_signing_request,
    gatekeeper_sign_action,
)

# A reviewer takes the approval request and returns an independent decision.
OpusReviewer = Callable[[ApprovalRequest], ApprovalDecision]
# A confirmer is shown the request + review and returns the human's yes/no.
HumanConfirmer = Callable[[ApprovalRequest, ApprovalDecision], bool]


@dataclass(frozen=True)
class ApprovalPackage:
    request: ApprovalRequest
    approval: ApprovalDecision

    @property
    def approved(self) -> bool:
        return self.approval.approved


@dataclass(frozen=True)
class HumanConfirmationToken:
    confirmed: bool
    operator: str
    confirmed_at: int
    request_id: str


@dataclass(frozen=True)
class ApprovalOutcome:
    ok: bool
    reason: str
    signed_intent: Optional[dict[str, Any]] = None
    approval: Optional[ApprovalDecision] = None
    human_token: Optional[HumanConfirmationToken] = None


def placeholder_opus_reviewer(request: ApprovalRequest) -> ApprovalDecision:
    """UNWIRED placeholder. Rejects by default (fail-closed). The real reviewer
    spawns an independent opus-verifier subagent that reviews the raw action +
    dependency-expanded context and returns approve/reject. Replace before arming."""
    return ApprovalDecision(
        approved=False,
        verifier_identity="placeholder-opus-reviewer",
        verifier_version="UNWIRED",
        approved_at=int(time.time()),
        defects=("opus-reviewer-not-wired: replace placeholder_opus_reviewer before arming",),
    )


def auto_deny_confirmer(request: ApprovalRequest, approval: ApprovalDecision) -> bool:
    """Default human confirmer: denies. Real use wires an interactive prompt on the
    gatekeeper host that shows the §13 confirmation detail and reads an explicit yes."""
    return False


def build_approval_package(
    classification: CommandClassification,
    *,
    policy_version: str,
    opus_reviewer: OpusReviewer = placeholder_opus_reviewer,
    rollback_path: str = "No automatic rollback; stop and return to the human operator.",
    tree_sha: str = "",
    parent_sha: str = "",
    state_repo: str = "",
    now: int | None = None,
) -> ApprovalPackage:
    """Request side (NO signing key). Build the request and run the independent
    Opus review. Returns the package including the review verdict; if the reviewer
    rejected, `package.approved` is False and no signature is possible downstream."""
    request = build_approval_request(
        classification,
        rollback_path=rollback_path,
        policy_version=policy_version,
        tree_sha=tree_sha,
        parent_sha=parent_sha,
        state_repo=state_repo,
        now=now,
    )
    approval = opus_reviewer(request)
    return ApprovalPackage(request=request, approval=approval)


def gatekeeper_sign_authorized(
    package: ApprovalPackage,
    *,
    private_key_path: Path,
    human_confirmer: HumanConfirmer = auto_deny_confirmer,
    operator: str,
    gatekeeper_user: str | None = None,
    now: int | None = None,
    expires_at: int | None = None,
) -> ApprovalOutcome:
    """Gatekeeper side (HOLDS the key, runs on the gatekeeper host). Signs ONLY when both the
    Opus review approved AND the human confirms for this exact request. Otherwise
    refuses (fail-closed)."""
    now = int(time.time()) if now is None else now

    if not package.approval.approved:
        return ApprovalOutcome(False, "opus-rejected", approval=package.approval)

    confirmed = bool(human_confirmer(package.request, package.approval))
    if not confirmed:
        return ApprovalOutcome(False, "human-declined", approval=package.approval)

    human_token = HumanConfirmationToken(
        confirmed=True,
        operator=operator,
        confirmed_at=now,
        request_id=package.request.request_id,
    )

    # Bind belt-and-suspenders: the confirmation must be for THIS request.
    if human_token.request_id != package.request.request_id:
        return ApprovalOutcome(False, "human-token-request-mismatch", approval=package.approval)

    signing_request = build_signing_request(
        package.request,
        package.approval,
        expires_at=expires_at,
    )
    signed_intent = gatekeeper_sign_action(
        signing_request,
        private_key_path,
        gatekeeper_user=gatekeeper_user,
    )
    return ApprovalOutcome(
        ok=True,
        reason="signed",
        signed_intent=signed_intent,
        approval=package.approval,
        human_token=human_token,
    )
