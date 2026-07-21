from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class ConfirmationPayload:
    exact_action: str
    verifier_identity: str
    risk_class: str
    rollback_path: str
    live_target: str
    changed_since_last_approval: str

    def to_display_dict(self) -> dict[str, str]:
        return asdict(self)
