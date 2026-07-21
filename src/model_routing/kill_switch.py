from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class KillSwitchState:
    non_capital_routing_disabled: bool
    capital_gate_disabled: bool
    capital_bypass_requires_breakglass: bool

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "KillSwitchState":
        return cls(
            non_capital_routing_disabled=env.get("DISABLE_MODEL_ROUTING") == "1",
            capital_gate_disabled=False,
            capital_bypass_requires_breakglass=True,
        )
