"""Explainable application risk summary.

This is deliberately **not** called a CVSS score.  CVSS describes a single
vulnerability assessed against a defined metric vector; nothing here performs
that assessment.  What this module produces is a weighted summary of what the
scan found, together with the arithmetic that produced it, so a reader can
check the result rather than trust it.

Design rules
------------
* A heuristic finding contributes less than a confirmed one, via the confidence
  multiplier.
* Informational findings contribute nothing to the score; they are context.
* The score saturates, so volume has diminishing returns: the difference
  between forty and eighty low-severity findings is small.  Volume still
  counts, though -- many medium findings can exceed a single critical one,
  because the score describes the application, not one issue.
* Severity sets a floor on the band.  A critical finding with at least medium
  confidence always lands in "elevated" or above, so a single serious issue
  cannot be averaged away by a quiet scan.
* A clean scan is never reported as "secure".  Absence of findings from the
  analyzers that ran is not evidence of absence of vulnerabilities, and the
  summary says so, listing what did not run.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from typing import Any

from app.core.enums import AnalyzerStatus, Confidence, FindingStatus, Severity

# Base weights per severity.  The ratios matter more than the absolute values.
SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.critical: 40.0,
    Severity.high: 20.0,
    Severity.medium: 8.0,
    Severity.low: 2.0,
    Severity.info: 0.0,
}

CONFIDENCE_MULTIPLIER: dict[Confidence, float] = {
    Confidence.high: 1.0,
    Confidence.medium: 0.6,
    Confidence.low: 0.3,
}

# A reviewer's verdict overrides the detector's.
STATUS_MULTIPLIER: dict[FindingStatus, float] = {
    FindingStatus.open: 1.0,
    FindingStatus.confirmed: 1.25,
    FindingStatus.false_positive: 0.0,
    FindingStatus.accepted_risk: 0.25,
    FindingStatus.resolved: 0.0,
}

# Score at which the curve reaches ~63% of its range; tuned so that a single
# critical finding lands in "high" and a handful of lows stays in "low".
SATURATION_CONSTANT = 85.0

BANDS: tuple[tuple[float, str, str], ...] = (
    (0.0, "minimal", "No scored findings were produced by the analyzers that ran."),
    (1.0, "low", "Findings are limited to low severity or low confidence issues."),
    (25.0, "moderate", "Findings of medium severity are present and should be triaged."),
    (50.0, "elevated", "High severity findings are present."),
    (75.0, "high", "Critical or multiple high severity findings are present."),
)


@dataclass(slots=True)
class RiskContribution:
    rule_id: str
    title: str
    severity: str
    confidence: str
    status: str
    weight: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RiskSummary:
    score: float
    band: str
    band_description: str
    raw_weight: float
    scored_findings: int
    severity_counts: dict[str, int] = field(default_factory=dict)
    confidence_counts: dict[str, int] = field(default_factory=dict)
    category_counts: dict[str, int] = field(default_factory=dict)
    top_contributors: list[dict[str, Any]] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    caveats: list[str] = field(default_factory=list)
    method: str = (
        "Weighted sum of findings (severity weight x confidence multiplier x review "
        "status multiplier), mapped onto 0-100 by score = 100 x (1 - exp(-weight/85)). "
        "Informational findings carry zero weight. This is a DroidScope risk summary, "
        "not a CVSS score."
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _band_for(score: float) -> tuple[str, str]:
    band, description = BANDS[0][1], BANDS[0][2]
    for threshold, name, text in BANDS:
        if score >= threshold:
            band, description = name, text
    return band, description


def calculate_risk(
    findings: list[Any],
    *,
    executions: list[Any] | None = None,
    profile: str | None = None,
) -> RiskSummary:
    """Summarise scan risk.

    ``findings`` may be ORM ``Finding`` rows or :class:`RawFinding` objects;
    only ``severity``, ``confidence``, ``status``, ``rule_id``, ``title`` and
    ``category`` are read.
    """
    severity_counts: dict[str, int] = {s.value: 0 for s in Severity}
    confidence_counts: dict[str, int] = {c.value: 0 for c in Confidence}
    category_counts: dict[str, int] = {}
    contributions: list[RiskContribution] = []
    raw_weight = 0.0
    scored = 0

    for finding in findings:
        severity = _as_enum(getattr(finding, "severity", None), Severity, Severity.info)
        confidence = _as_enum(getattr(finding, "confidence", None), Confidence, Confidence.low)
        status = _as_enum(
            getattr(finding, "status", FindingStatus.open), FindingStatus, FindingStatus.open
        )
        category = str(getattr(finding, "category", None) or "uncategorised")
        category = getattr(category, "value", category)

        severity_counts[severity.value] = severity_counts.get(severity.value, 0) + 1
        confidence_counts[confidence.value] = confidence_counts.get(confidence.value, 0) + 1
        category_counts[category] = category_counts.get(category, 0) + 1

        weight = (
            SEVERITY_WEIGHT[severity]
            * CONFIDENCE_MULTIPLIER[confidence]
            * STATUS_MULTIPLIER.get(status, 1.0)
        )
        if weight <= 0:
            continue
        scored += 1
        raw_weight += weight
        contributions.append(
            RiskContribution(
                rule_id=str(getattr(finding, "rule_id", "")),
                title=str(getattr(finding, "title", ""))[:160],
                severity=severity.value,
                confidence=confidence.value,
                status=status.value,
                weight=round(weight, 2),
            )
        )

    score = round(100.0 * (1.0 - math.exp(-raw_weight / SATURATION_CONSTANT)), 1)
    band, band_description = _band_for(score)
    band, band_description, floor_note = _apply_severity_floor(band, band_description, findings)

    coverage, caveats = _coverage(executions or [], profile)
    if not scored:
        caveats.insert(
            0,
            "No scored findings were produced. A completed scan does not demonstrate "
            "that the application is secure: it shows only that the rules which ran "
            "did not match.",
        )

    if floor_note:
        caveats.insert(0, floor_note)

    contributions.sort(key=lambda item: item.weight, reverse=True)
    return RiskSummary(
        score=score,
        band=band,
        band_description=band_description,
        raw_weight=round(raw_weight, 2),
        scored_findings=scored,
        severity_counts=severity_counts,
        confidence_counts=confidence_counts,
        category_counts=dict(sorted(category_counts.items(), key=lambda kv: -kv[1])),
        top_contributors=[item.to_dict() for item in contributions[:10]],
        coverage=coverage,
        caveats=caveats,
    )


def _coverage(executions: list[Any], profile: str | None) -> tuple[dict[str, Any], list[str]]:
    """Describe which analyzers ran, so the score can be read in context."""
    completed: list[str] = []
    missing: list[dict[str, str]] = []

    for execution in executions:
        name = str(getattr(execution, "analyzer", "unknown"))
        status = _as_enum(getattr(execution, "status", None), AnalyzerStatus, AnalyzerStatus.failed)
        if status == AnalyzerStatus.completed:
            completed.append(name)
        else:
            missing.append(
                {
                    "analyzer": name,
                    "status": status.value,
                    "reason": str(getattr(execution, "error", "") or "")[:300],
                }
            )

    caveats: list[str] = []
    for entry in missing:
        caveats.append(
            f"{entry['analyzer']} did not complete ({entry['status']}), so issues it "
            "would detect are not represented in this score"
            + (f": {entry['reason']}" if entry["reason"] else "")
        )
    caveats.append(
        "Static analysis cannot observe runtime behaviour. Findings describe code and "
        "configuration as shipped, not what the application does when executed."
    )

    return (
        {
            "profile": profile,
            "analyzers_completed": sorted(completed),
            "analyzers_incomplete": missing,
            "complete": not missing,
        },
        caveats,
    )


def _as_enum(value: Any, enum_cls, default):  # noqa: ANN001
    if isinstance(value, enum_cls):
        return value
    if value is None:
        return default
    try:
        return enum_cls(str(getattr(value, "value", value)))
    except ValueError:
        return default


# A single serious finding sets a minimum band regardless of the weighted total.
SEVERITY_BAND_FLOOR: dict[Severity, str] = {
    Severity.critical: "elevated",
    Severity.high: "moderate",
}
BAND_ORDER: tuple[str, ...] = ("minimal", "low", "moderate", "elevated", "high")


def _apply_severity_floor(
    band: str, description: str, findings: list[Any]
) -> tuple[str, str, str | None]:
    """Raise the band when a serious, non-dismissed finding is present."""
    floor: str | None = None
    trigger: Any = None
    for finding in findings:
        severity = _as_enum(getattr(finding, "severity", None), Severity, Severity.info)
        confidence = _as_enum(getattr(finding, "confidence", None), Confidence, Confidence.low)
        status = _as_enum(
            getattr(finding, "status", FindingStatus.open), FindingStatus, FindingStatus.open
        )
        if status in {FindingStatus.false_positive, FindingStatus.resolved}:
            continue
        if confidence == Confidence.low:
            continue
        candidate = SEVERITY_BAND_FLOOR.get(severity)
        if candidate and (floor is None or BAND_ORDER.index(candidate) > BAND_ORDER.index(floor)):
            floor, trigger = candidate, finding

    if floor is None or BAND_ORDER.index(band) >= BAND_ORDER.index(floor):
        return band, description, None

    rule_id = str(getattr(trigger, "rule_id", "")) if trigger is not None else ""
    severity = _as_enum(getattr(trigger, "severity", None), Severity, Severity.high)
    note = (
        f"The risk band was raised from {band!r} to {floor!r} because a "
        f"{severity.value} severity finding is present ({rule_id}). A single serious "
        "issue determines the band even when the weighted total is low."
    )
    return floor, f"Band set by the presence of a {severity.value} severity finding.", note
