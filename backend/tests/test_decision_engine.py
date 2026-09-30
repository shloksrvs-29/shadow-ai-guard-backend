from app.models.schemas import Category, Finding, Severity
from app.policy.decision_engine import decide


def _finding(severity: Severity) -> Finding:
    return Finding(
        engine="regex", category=Category.API_KEY, severity=severity,
        matched_text="ab**cd", start=0, end=6, confidence=0.9, explanation="test",
    )


def test_allows_when_no_findings():
    result = decide([], request_id="r1", latency_ms=1.0)
    assert result.decision.value == "allow"


def test_blocks_on_high_severity():
    result = decide([_finding(Severity.HIGH)], request_id="r2", latency_ms=1.0)
    assert result.decision.value == "block"


def test_allows_low_severity_below_default_threshold():
    # default block_on_severity is "medium", so a single LOW finding should not block
    result = decide([_finding(Severity.LOW)], request_id="r3", latency_ms=1.0)
    assert result.decision.value == "allow"
