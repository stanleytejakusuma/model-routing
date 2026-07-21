from __future__ import annotations

import secrets
import time
from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from model_routing.classifier import CommandClassification, classify_tool_call
from model_routing.intents import IntentRecord, NonceStore, VerificationResult, canonical_json, sign_intent, verify_intent, verify_peek
from model_routing.registry import CapitalRegistry


DEFAULT_ROLLBACK_PATH = "No automatic rollback; stop and return to the human operator."


@dataclass(frozen=True)
class DetectedAction:
    classification: CommandClassification
    event: dict[str, Any]
    requires_approval: bool


@dataclass(frozen=True)
class ApprovalRequest:
    request_id: str
    action_type: str
    exact_action: str
    cwd: str
    repo_id: str
    host: str
    target: str
    risk_class: str
    rollback_path: str
    policy_version: str
    tree_sha: str
    parent_sha: str
    created_at: int
    nonce: str
    verifier_requirements: tuple[str, ...]
    state_repo: str = ""


@dataclass(frozen=True)
class ApprovalDecision:
    approved: bool
    verifier_identity: str
    verifier_version: str
    approved_at: int
    defects: tuple[str, ...] = ()


@dataclass(frozen=True)
class SigningRequest:
    approval_request: ApprovalRequest
    approval: ApprovalDecision
    action_intent: IntentRecord


@dataclass(frozen=True)
class GateDecision:
    ok: bool
    stage: str
    reason: str
    classification: CommandClassification | None = None


def detect_capital_action(
    tool_name: str,
    payload: dict[str, Any],
    cwd: Path,
    registry: CapitalRegistry,
    host: str = "local",
) -> DetectedAction:
    classification = classify_tool_call(tool_name, payload, cwd, registry, host=host)
    event = {
        "tool_name": tool_name,
        "tool_input": dict(payload),
        "cwd": classification.cwd,
        "host": classification.host,
    }
    return DetectedAction(
        classification=classification,
        event=event,
        requires_approval=classification.is_capital and not classification.is_read_only,
    )


def build_approval_request(
    classification: CommandClassification,
    *,
    rollback_path: str = DEFAULT_ROLLBACK_PATH,
    policy_version: str,
    tree_sha: str = "",
    parent_sha: str = "",
    state_repo: str = "",
    now: int | None = None,
    nonce: str | None = None,
) -> ApprovalRequest:
    created_at = int(time.time()) if now is None else now
    request_nonce = nonce or secrets.token_urlsafe(24)
    payload = {
        "action_type": classification.action_type,
        "exact_action": classification.exact_action,
        "cwd": classification.cwd,
        "repo_id": _repo_id(classification),
        "host": classification.host,
        "target": classification.target,
        "risk_class": classification.risk_class,
        "policy_version": policy_version,
        "tree_sha": tree_sha,
        "parent_sha": parent_sha,
        "state_repo": state_repo,
        "created_at": created_at,
        "nonce": request_nonce,
    }
    request_id = sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    return ApprovalRequest(
        request_id=request_id,
        action_type=classification.action_type,
        exact_action=classification.exact_action,
        cwd=classification.cwd,
        repo_id=_repo_id(classification),
        host=classification.host,
        target=classification.target,
        risk_class=classification.risk_class,
        rollback_path=rollback_path,
        policy_version=policy_version,
        tree_sha=tree_sha,
        parent_sha=parent_sha,
        created_at=created_at,
        nonce=request_nonce,
        verifier_requirements=(
            "independent-opus-verifier",
            "exact-action-binding",
            "rollback-path-reviewed",
            "human-confirmation-required-before-live-use",
        ),
        state_repo=state_repo,
    )


def build_signing_request(
    approval_request: ApprovalRequest,
    approval: ApprovalDecision,
    *,
    nonce: str | None = None,
    expires_at: int | None = None,
) -> SigningRequest:
    if not approval.approved:
        defects = ",".join(approval.defects) if approval.defects else "no-defects-provided"
        raise PermissionError(f"opus-approval-rejected:{defects}")
    intent_nonce = nonce or secrets.token_urlsafe(24)
    expiry = expires_at if expires_at is not None else approval.approved_at + 300
    action_intent = IntentRecord(
        action_type=approval_request.action_type,
        exact_action=approval_request.exact_action,
        cwd=approval_request.cwd,
        repo_id=approval_request.repo_id,
        host=approval_request.host,
        target=approval_request.target,
        risk_class=approval_request.risk_class,
        rollback_path=approval_request.rollback_path,
        verifier_identity=approval.verifier_identity,
        verifier_version=approval.verifier_version,
        policy_version=approval_request.policy_version,
        tree_sha=approval_request.tree_sha,
        parent_sha=approval_request.parent_sha,
        timestamp=approval.approved_at,
        nonce=intent_nonce,
        expires_at=expiry,
        state_repo=approval_request.state_repo,
    )
    return SigningRequest(approval_request=approval_request, approval=approval, action_intent=action_intent)


def gatekeeper_sign_action(
    signing_request: SigningRequest,
    private_key_path: Path,
    gatekeeper_user: str | None = None,
) -> dict[str, Any]:
    return sign_intent(signing_request.action_intent, private_key_path, gatekeeper_user=gatekeeper_user)


def attach_signed_intent(event: dict[str, Any], signed_intent: dict[str, Any]) -> dict[str, Any]:
    attached = dict(event)
    attached["signed_intent"] = signed_intent
    return attached


def local_pretooluse_check(
    event: dict[str, Any],
    registry: CapitalRegistry,
    public_key_path: Path,
    *,
    now: int | None = None,
    gatekeeper_user: str | None = None,
) -> GateDecision:
    classification = _classify_event(event, registry)
    if classification.is_read_only or not classification.is_capital:
        return GateDecision(True, "local-classify", "not-capital-mutation", classification)

    signed_intent = event.get("signed_intent")
    if not isinstance(signed_intent, dict):
        return GateDecision(False, "local-peek", "missing-capital-intent", classification)

    result = verify_peek(
        signed_intent,
        public_key_path,
        _expected_from_classification(classification),
        now=now,
        gatekeeper_user=gatekeeper_user,
    )
    return _decision_from_verification(result, "local-peek", classification, invalid_prefix="invalid-capital-intent")


def authoritative_broker_check(
    event: dict[str, Any],
    registry: CapitalRegistry,
    public_key_path: Path,
    nonce_store: NonceStore,
    *,
    now: int | None = None,
    gatekeeper_user: str | None = None,
) -> GateDecision:
    classification = _classify_event(event, registry)
    if classification.is_read_only or not classification.is_capital:
        return GateDecision(True, "authoritative-classify", "not-capital-mutation", classification)

    signed_intent = event.get("signed_intent")
    if not isinstance(signed_intent, dict):
        return GateDecision(False, "authoritative-consume", "missing-capital-intent", classification)

    result = verify_intent(
        signed_intent,
        public_key_path,
        nonce_store,
        _expected_from_classification(classification),
        now=now,
        gatekeeper_user=gatekeeper_user,
    )
    return _decision_from_verification(result, "authoritative-consume", classification, invalid_prefix="invalid-capital-intent")


def authoritative_prereceive_check(
    signed_intent: dict[str, Any],
    public_key_path: Path,
    nonce_store: NonceStore,
    *,
    repo_id: str,
    ref_name: str,
    new_sha: str,
    host: str = "gatekeeper",
    now: int | None = None,
    gatekeeper_user: str | None = None,
) -> GateDecision:
    result = verify_intent(
        signed_intent,
        public_key_path,
        nonce_store,
        {
            "action_type": "git-push",
            "repo_id": repo_id,
            "target": ref_name,
            "tree_sha": new_sha,
            "host": host,
        },
        now=now,
        gatekeeper_user=gatekeeper_user,
    )
    return _decision_from_verification(result, "authoritative-pre-receive", None, invalid_prefix="invalid-git-intent")


def approval_request_payload(approval_request: ApprovalRequest) -> dict[str, Any]:
    return asdict(approval_request)


def _classify_event(event: dict[str, Any], registry: CapitalRegistry) -> CommandClassification:
    tool_name = str(event.get("tool_name", ""))
    payload = event.get("tool_input", {})
    if not isinstance(payload, dict):
        payload = {}
    cwd = Path(str(event.get("cwd") or payload.get("cwd") or "."))
    return classify_tool_call(tool_name, payload, cwd, registry, host=str(event.get("host", "local")))


def _expected_from_classification(classification: CommandClassification) -> dict[str, str]:
    return {
        "action_type": classification.action_type,
        "exact_action": classification.exact_action,
        "cwd": classification.cwd,
        "repo_id": _repo_id(classification),
        "host": classification.host,
        "target": classification.target,
        "risk_class": classification.risk_class,
    }


def _repo_id(classification: CommandClassification) -> str:
    return classification.repo_id or "unknown"


def _decision_from_verification(
    result: VerificationResult,
    stage: str,
    classification: CommandClassification | None,
    *,
    invalid_prefix: str,
) -> GateDecision:
    if result.ok:
        return GateDecision(True, stage, "ok", classification)
    return GateDecision(False, stage, f"{invalid_prefix}:{result.reason}", classification)
