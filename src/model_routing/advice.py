from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from model_routing.registry import CapitalRegistry


EVM_ADDRESS_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
TX_PAYLOAD_RE = re.compile(r"\b0x[a-fA-F0-9]{64,}\b")
AMOUNT_RE = re.compile(r"(?:\$\s*\d+(?:[,\d]*)(?:\.\d+)?|\b\d+(?:[,\d]*)(?:\.\d+)?\s*(?:USD|USDC|USDT|SOL|ETH|BTC)\b)", re.I)


@dataclass(frozen=True)
class AdviceScanResult:
    detected: bool
    label: str | None
    kinds: tuple[str, ...]
    payload: dict[str, object]


def scan_advice(text: str, cwd: Path, registry: CapitalRegistry) -> AdviceScanResult:
    kinds: list[str] = []
    if EVM_ADDRESS_RE.search(text):
        kinds.append("evm-address")
    if TX_PAYLOAD_RE.search(text):
        kinds.append("tx-payload")
    if AMOUNT_RE.search(text):
        kinds.append("amount")

    in_capital_context = registry.classify_path(cwd).is_capital
    if not in_capital_context:
        in_capital_context = any(registry.is_capital_address(match.group(0)) for match in EVM_ADDRESS_RE.finditer(text))

    if not kinds or not in_capital_context:
        return AdviceScanResult(False, None, tuple(kinds), {"status": "clear", "kinds": tuple(kinds)})

    payload = {
        "status": "UNVERIFIED",
        "label": "UNVERIFIED advice",
        "message": "Capital-action-shaped advice is not an Opus-signed intent.",
        "kinds": tuple(kinds),
    }
    return AdviceScanResult(True, "UNVERIFIED advice", tuple(kinds), payload)
