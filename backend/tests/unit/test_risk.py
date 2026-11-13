"""Risk summary behaviour."""

from __future__ import annotations

from app.core.enums import Confidence, FindingCategory, FindingStatus, Severity
from app.detection.model import RawFinding
from app.services.risk import calculate_risk


def finding(
    severity: Severity,
    confidence: Confidence = Confidence.high,
    status: FindingStatus = FindingStatus.open,
) -> RawFinding:
    item = RawFinding(
        rule_id="DS-TEST-001",
        title="test finding",
        description="d",
        severity=severity,
        confidence=confidence,
        category=FindingCategory.cryptography,
        analysis_engine="test",
        impact="i",
        remediation="r",
    )
    item.metadata["status"] = status
    # The risk calculator reads `status` from the object when present.
    object.__setattr__(item, "status", status) if False else None
    return item


class _Row:
    """A minimal stand-in for an ORM finding row."""

    def __init__(self, severity, confidence, status=FindingStatus.open, rule_id="DS-TEST-001"):
        self.severity = severity
        self.confidence = confidence
        self.status = status
        self.rule_id = rule_id
        self.title = "test"
        self.category = "cryptography"


class TestRiskScore:
    def test_empty_scan_scores_zero_and_warns(self) -> None:
        risk = calculate_risk([])
        assert risk.score == 0.0
        assert risk.band == "minimal"
        assert any("does not demonstrate" in caveat for caveat in risk.caveats)

    def test_informational_findings_do_not_score(self) -> None:
        risk = calculate_risk([_Row(Severity.info, Confidence.high)] * 10)
        assert risk.score == 0.0
        assert risk.scored_findings == 0

    def test_confidence_scales_the_contribution(self) -> None:
        high = calculate_risk([_Row(Severity.critical, Confidence.high)])
        low = calculate_risk([_Row(Severity.critical, Confidence.low)])
        assert high.score > low.score

    def test_a_critical_finding_raises_the_band(self) -> None:
        """A single serious issue must not be averaged away."""
        risk = calculate_risk([_Row(Severity.critical, Confidence.high)])
        assert risk.band == "elevated"
        assert any("raised" in caveat for caveat in risk.caveats)

    def test_false_positive_contributes_nothing(self) -> None:
        risk = calculate_risk(
            [_Row(Severity.critical, Confidence.high, FindingStatus.false_positive)]
        )
        assert risk.score == 0.0
        assert risk.scored_findings == 0

    def test_accepted_risk_is_discounted(self) -> None:
        accepted = calculate_risk(
            [_Row(Severity.high, Confidence.high, FindingStatus.accepted_risk)]
        )
        open_finding = calculate_risk([_Row(Severity.high, Confidence.high)])
        assert accepted.score < open_finding.score

    def test_confirmed_finding_weighs_more(self) -> None:
        confirmed = calculate_risk([_Row(Severity.high, Confidence.high, FindingStatus.confirmed)])
        open_finding = calculate_risk([_Row(Severity.high, Confidence.high)])
        assert confirmed.score > open_finding.score

    def test_score_saturates(self) -> None:
        many = calculate_risk([_Row(Severity.critical, Confidence.high)] * 100)
        assert many.score <= 100.0

    def test_method_does_not_claim_cvss(self) -> None:
        risk = calculate_risk([_Row(Severity.low, Confidence.high)])
        assert "not a CVSS score" in risk.method

    def test_coverage_records_incomplete_analyzers(self) -> None:
        class _Execution:
            def __init__(self, analyzer, status, error=None):
                self.analyzer = analyzer
                self.status = status
                self.error = error

        from app.core.enums import AnalyzerStatus

        risk = calculate_risk(
            [_Row(Severity.medium, Confidence.high)],
            executions=[
                _Execution("manifest-analyzer", AnalyzerStatus.completed),
                _Execution("source-analyzer", AnalyzerStatus.unavailable, "JADX not installed"),
            ],
        )
        assert risk.coverage["complete"] is False
        assert "source-analyzer" in str(risk.coverage["analyzers_incomplete"])
        assert any("source-analyzer" in caveat for caveat in risk.caveats)

    def test_top_contributors_are_ranked(self) -> None:
        risk = calculate_risk(
            [
                _Row(Severity.low, Confidence.high, rule_id="LOW"),
                _Row(Severity.critical, Confidence.high, rule_id="CRIT"),
            ]
        )
        assert risk.top_contributors[0]["rule_id"] == "CRIT"
