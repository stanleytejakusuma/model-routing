from __future__ import annotations

import base64
import json
import os
import pwd
import stat
import time
from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, load_ssh_public_key

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only in minimal Python environments.
    InvalidSignature = Exception
    Ed25519PrivateKey = None  # type: ignore[assignment]
    Ed25519PublicKey = None  # type: ignore[assignment]
    load_pem_private_key = None  # type: ignore[assignment]
    load_pem_public_key = None  # type: ignore[assignment]
    load_ssh_public_key = None  # type: ignore[assignment]
    CRYPTOGRAPHY_AVAILABLE = False


DEFAULT_GATEKEEPER_USER = "model-routing-gatekeeper"
SIGNATURE_ALG = "ed25519"


@dataclass(frozen=True)
class IntentRecord:
    action_type: str
    exact_action: str
    cwd: str
    repo_id: str
    host: str
    target: str
    risk_class: str
    rollback_path: str
    verifier_identity: str
    verifier_version: str
    policy_version: str
    tree_sha: str
    parent_sha: str
    timestamp: int
    nonce: str
    expires_at: int
    state_repo: str = ""


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    reason: str


class NonceStore:
    """Directory-backed nonce store where O_EXCL file creation is the commit."""

    def __init__(self, path: Path):
        self.path = path

    def seen(self, nonce: str) -> bool:
        return self._nonce_path(nonce).exists()

    def mark_seen(self, nonce: str) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({"nonce_sha256": sha256(nonce.encode("utf-8")).hexdigest(), "seen_at": int(time.time())})
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        try:
            fd = os.open(self._nonce_path(nonce), flags, 0o600)
        except FileExistsError:
            return False
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
        return True

    def _nonce_path(self, nonce: str) -> Path:
        nonce_id = sha256(nonce.encode("utf-8")).hexdigest()
        return self.path / nonce_id


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def ensure_key_outside_workspace(key_path: Path, workspace_root: Path, key_role: str = "private") -> None:
    key = key_path.expanduser().resolve(strict=False)
    root = workspace_root.expanduser().resolve(strict=False)
    if key == root or str(key).startswith(f"{root}/"):
        raise ValueError(f"{key_role} key must live outside the agent-writable workspace")


def require_key_custody(key_path: Path, gatekeeper_user: str | None = None) -> None:
    expected_user = gatekeeper_user or os.environ.get("MODEL_ROUTING_GATEKEEPER_USER") or DEFAULT_GATEKEEPER_USER
    try:
        expected_uid = pwd.getpwnam(expected_user).pw_uid
    except KeyError as exc:
        raise ValueError("key-custody:missing-gatekeeper-user") from exc

    st = key_path.stat()
    if stat.S_IMODE(st.st_mode) != 0o600:
        raise ValueError("key-custody:mode-not-600")
    if st.st_uid != expected_uid:
        raise ValueError("key-custody:owner-mismatch")


def _read_key_bytes(key_path: Path) -> bytes:
    key = key_path.read_bytes()
    if not key.strip():
        raise ValueError("key-empty")
    return key


def _load_private_key(private_key_path: Path, gatekeeper_user: str | None) -> Any:
    require_key_custody(private_key_path, gatekeeper_user)
    if not CRYPTOGRAPHY_AVAILABLE:
        raise RuntimeError("ed25519-stub:cryptography-unavailable")
    loaded = load_pem_private_key(_read_key_bytes(private_key_path), password=None)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise ValueError("private-key-not-ed25519")
    return loaded


def _load_public_key(public_key_path: Path, gatekeeper_user: str | None) -> Any:
    # Public keys are NOT secret: they must be readable by the local hook (agent
    # user) and the gatekeeper-side broker. Custody (owner + 0600) is enforced
    # on the PRIVATE key only. gatekeeper_user kept for signature compatibility.
    _ = gatekeeper_user
    if not CRYPTOGRAPHY_AVAILABLE:
        raise RuntimeError("ed25519-stub:cryptography-unavailable")
    key_bytes = _read_key_bytes(public_key_path)
    try:
        loaded = load_pem_public_key(key_bytes)
    except ValueError:
        loaded = load_ssh_public_key(key_bytes)
    if not isinstance(loaded, Ed25519PublicKey):
        raise ValueError("public-key-not-ed25519")
    return loaded


def _signature(payload: dict[str, Any], private_key_path: Path, gatekeeper_user: str | None) -> str:
    signature = _load_private_key(private_key_path, gatekeeper_user).sign(canonical_json(payload).encode("utf-8"))
    return base64.b64encode(signature).decode("ascii")


def sign_intent(intent: IntentRecord, private_key_path: Path, gatekeeper_user: str | None = None) -> dict[str, Any]:
    payload = asdict(intent)
    return {"payload": payload, "signature": _signature(payload, private_key_path, gatekeeper_user), "signature_alg": SIGNATURE_ALG}


def _verify_signed_payload(
    signed_intent: dict[str, Any],
    public_key_path: Path,
    expected: dict[str, str],
    now: int,
    gatekeeper_user: str | None = None,
) -> tuple[VerificationResult, dict[str, Any] | None]:
    payload = signed_intent.get("payload")
    if not isinstance(payload, dict):
        return VerificationResult(False, "missing-payload"), None
    if signed_intent.get("signature_alg") != SIGNATURE_ALG:
        return VerificationResult(False, "bad-signature-alg"), None

    for key, value in expected.items():
        if payload.get(key) != value:
            return VerificationResult(False, f"binding-mismatch:{key}"), None

    try:
        signature = base64.b64decode(str(signed_intent.get("signature", "")), validate=True)
        public_key = _load_public_key(public_key_path, gatekeeper_user)
        public_key.verify(signature, canonical_json(payload).encode("utf-8"))
    except InvalidSignature:
        return VerificationResult(False, "bad-signature"), None
    except (OSError, ValueError, RuntimeError) as exc:
        reason = str(exc) or exc.__class__.__name__
        return VerificationResult(False, reason), None

    if int(payload.get("expires_at", 0)) < now:
        return VerificationResult(False, "expired"), None

    return VerificationResult(True, "ok"), payload


def verify_peek(
    signed_intent: dict[str, Any],
    public_key_path: Path,
    expected: dict[str, str],
    now: int | None = None,
    gatekeeper_user: str | None = None,
) -> VerificationResult:
    """Verify signature, binding, expiry, and nonce presence without committing it."""

    now = int(time.time()) if now is None else now
    result, payload = _verify_signed_payload(signed_intent, public_key_path, expected, now, gatekeeper_user)
    if not result.ok or payload is None:
        return result

    nonce = str(payload.get("nonce", ""))
    if not nonce:
        return VerificationResult(False, "missing-nonce")
    return VerificationResult(True, "ok")


def verify_intent(
    signed_intent: dict[str, Any],
    public_key_path: Path,
    nonce_store: NonceStore,
    expected: dict[str, str],
    now: int | None = None,
    gatekeeper_user: str | None = None,
) -> VerificationResult:
    now = int(time.time()) if now is None else now
    result, payload = _verify_signed_payload(signed_intent, public_key_path, expected, now, gatekeeper_user)
    if not result.ok or payload is None:
        return result

    nonce = str(payload.get("nonce", ""))
    if not nonce:
        return VerificationResult(False, "missing-nonce")
    if not nonce_store.mark_seen(nonce):
        return VerificationResult(False, "nonce-replay")
    return VerificationResult(True, "ok")
