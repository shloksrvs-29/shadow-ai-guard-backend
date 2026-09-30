"""
Combines regex-engine and NER-engine findings into a single allow/block
verdict, based on the configured minimum blocking severity.
"""
from __future__ import annotations

from app.config import get_settings
from app.models.schemas import AnalyzeResponse, Decision, Finding, Severity

_SEVERITY_ORDER = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2}


def _highest_severity(findings: list[Finding]) -> Severity | None:
    if not findings:
        return None
    return max((f.severity for f in findings), key=lambda s: _SEVERITY_ORDER[s])


def decide(findings: list[Finding], request_id: str, latency_ms: float) -> AnalyzeResponse:
    settings = get_settings()
    threshold = _SEVERITY_ORDER[Severity(settings.block_on_severity)]

    highest = _highest_severity(findings)
    should_block = highest is not None and _SEVERITY_ORDER[highest] >= threshold

    if should_block:
        categories = sorted({f.category.value for f in findings if _SEVERITY_ORDER[f.severity] >= threshold})
        message = (
            f"Submission blocked: detected {', '.join(categories)}. "
            "This content was not sent to the AI platform. If this looks wrong, "
            "contact your security team."
        )
        decision = Decision.BLOCK
    else:
        message = "No sensitive content detected above policy threshold. Submission allowed."
        decision = Decision.ALLOW

    return AnalyzeResponse(
        decision=decision,
        findings=findings,
        highest_severity=highest,
        message=message,
        request_id=request_id,
        latency_ms=latency_ms,
    )
