"""Security score (0-100) and letter grade derived from a scan result."""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Tuple

from aegis.core.models import CheckStatus, Severity

if TYPE_CHECKING:  # pragma: no cover
    from aegis.core.models import ScanResult

# Points deducted per finding, and the maximum a single category may cost, so one
# noisy category cannot zero the score on its own.
_PENALTY = {Severity.CRITICAL: 30, Severity.HIGH: 12, Severity.MEDIUM: 5, Severity.LOW: 1, Severity.INFO: 0}
_CATEGORY_CAP = 45


def security_score(result: "ScanResult") -> Tuple[int, str]:
    per_cat = defaultdict(int)
    for f in result.findings:
        per_cat[f.category] += _PENALTY[f.severity]
    penalty = sum(min(v, _CATEGORY_CAP) for v in per_cat.values())
    # Failed hardening checks without a matching finding still cost a little.
    failed_checks = sum(1 for c in result.checks if c.status == CheckStatus.FAIL)
    penalty += min(failed_checks, 10) // 2
    if any(f.severity == Severity.CRITICAL for f in result.findings):
        penalty = max(penalty, 51)  # any active critical threat caps the grade at F/D
    score = max(0, 100 - penalty)
    return score, grade_for(score)


def grade_for(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 65:
        return "C"
    if score >= 50:
        return "D"
    return "F"
