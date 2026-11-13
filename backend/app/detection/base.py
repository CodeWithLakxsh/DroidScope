"""Detection rule contracts.

Two kinds of rule exist:

``StructuralRule``
    Python logic over parsed structures (the manifest model, ELF headers,
    certificate data).  Used where a verdict depends on platform behaviour --
    e.g. whether an exported component is actually reachable given its target
    SDK and permission protection level.

``PatternRule``
    A declarative rule loaded from ``rules/**/*.yaml`` that matches regular
    expressions against decompiled source, smali or resources, with required
    and excluded context so a single keyword does not produce a finding on its
    own.

Both produce :class:`~app.detection.model.RawFinding`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from app.core.enums import Confidence, FindingCategory, Severity
from app.detection.model import RawFinding


@dataclass(slots=True)
class RuleMetadata:
    """Documented, versioned description of a detection rule."""

    id: str
    name: str
    description: str
    category: FindingCategory
    severity: Severity
    confidence: Confidence
    engine: str
    impact: str
    remediation: str
    version: str = "1"
    cwe_ids: list[str] = field(default_factory=list)
    masvs_controls: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    verification: str | None = None
    limitations: str | None = None
    # Analyzer versions this rule is known to be valid for.
    supported_analyzers: list[str] = field(default_factory=list)
    enabled_by_default: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "engine": self.engine,
            "version": self.version,
            "cwe_ids": list(self.cwe_ids),
            "masvs_controls": list(self.masvs_controls),
            "references": list(self.references),
            "impact": self.impact,
            "remediation": self.remediation,
            "verification": self.verification,
            "limitations": self.limitations,
            "enabled_by_default": self.enabled_by_default,
        }


class Rule(ABC):
    """Base class for every detection rule."""

    meta: RuleMetadata

    @abstractmethod
    def evaluate(self, context: Any) -> Iterable[RawFinding]:
        """Yield findings for the supplied analysis context."""

    # -- helper used by concrete rules -------------------------------------
    def finding(
        self,
        *,
        title: str | None = None,
        description: str | None = None,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
        **kwargs: Any,
    ) -> RawFinding:
        meta = self.meta
        return RawFinding(
            rule_id=meta.id,
            rule_version=meta.version,
            title=title or meta.name,
            description=description or meta.description,
            severity=severity or meta.severity,
            confidence=confidence or meta.confidence,
            category=meta.category,
            analysis_engine=meta.engine,
            impact=kwargs.pop("impact", meta.impact),
            remediation=kwargs.pop("remediation", meta.remediation),
            cwe_ids=list(meta.cwe_ids),
            masvs_controls=list(meta.masvs_controls),
            references=list(meta.references),
            verification=kwargs.pop("verification", meta.verification),
            limitations=kwargs.pop("limitations", meta.limitations),
            **kwargs,
        )
