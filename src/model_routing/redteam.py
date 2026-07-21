from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class RecallCase:
    case_id: str
    should_block: bool
    blocked: bool


@dataclass(frozen=True)
class RecallResult:
    known_bad: int
    detected_bad: int
    known_good: int
    allowed_good: int
    false_negative: int
    false_positive: int
    misses: tuple[str, ...]

    @property
    def recall(self) -> float:
        if self.known_bad == 0:
            return 1.0
        return self.detected_bad / self.known_bad

    @property
    def precision(self) -> float:
        blocked_total = self.detected_bad + self.false_positive
        if blocked_total == 0:
            return 1.0
        return self.detected_bad / blocked_total

    def pass_required_threshold(self, threshold: float) -> bool:
        return self.recall >= threshold


def calculate_recall(cases: Iterable[RecallCase]) -> RecallResult:
    known_bad = 0
    detected_bad = 0
    known_good = 0
    allowed_good = 0
    false_negative = 0
    false_positive = 0
    misses: list[str] = []
    for case in cases:
        if case.should_block:
            known_bad += 1
            if case.blocked:
                detected_bad += 1
            else:
                false_negative += 1
                misses.append(case.case_id)
            continue
        known_good += 1
        if case.blocked:
            false_positive += 1
            misses.append(case.case_id)
        else:
            allowed_good += 1
    return RecallResult(
        known_bad=known_bad,
        detected_bad=detected_bad,
        known_good=known_good,
        allowed_good=allowed_good,
        false_negative=false_negative,
        false_positive=false_positive,
        misses=tuple(misses),
    )
