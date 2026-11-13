"""The normalised finding model shared by every analyzer.

An analyzer never writes to the database directly: it returns
:class:`RawFinding` objects and the normalisation layer assigns identities,
deduplicates and persists them.  Keeping this model free of ORM types lets
rules be unit tested without a database.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from app.core.enums import Confidence, FindingCategory, Severity
from app.core.redaction import fingerprint_value, mask_value


@dataclass(slots=True)
class Evidence:
    """A single piece of supporting evidence.

    ``snippet`` is always safe to display.  When the evidence contains a
    credential, the detector sets ``sensitive=True`` and passes the plaintext as
    ``raw_value``; normalisation then stores only a mask plus a fingerprint
    unless raw retention is explicitly enabled.
    """

    description: str
    snippet: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    kind: str = "code"  # code | manifest | resource | binary | runtime | network | metadata
    sensitive: bool = False
    raw_value: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def masked_snippet(self) -> str | None:
        if not self.sensitive:
            return self.snippet
        if self.raw_value and self.snippet:
            return self.snippet.replace(self.raw_value, mask_value(self.raw_value))
        if self.raw_value:
            return mask_value(self.raw_value)
        return self.snippet

    def value_fingerprint(self) -> str | None:
        return fingerprint_value(self.raw_value) if self.raw_value else None


@dataclass(slots=True)
class RawFinding:
    """A finding as produced by an analyzer, before persistence."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    category: FindingCategory
    analysis_engine: str
    impact: str
    remediation: str
    cwe_ids: list[str] = field(default_factory=list)
    masvs_controls: list[str] = field(default_factory=list)
    affected_component: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    evidence: list[Evidence] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    verification: str | None = None
    limitations: str | None = None
    rule_version: str = "1"
    metadata: dict[str, Any] = field(default_factory=dict)

    def fingerprint(self) -> str:
        """Stable identity used to correlate the finding across scans.

        Deliberately excludes line numbers: a code shift must not present an
        unchanged issue as a brand new one when diffing two APK versions.
        """
        parts = [
            self.rule_id,
            self.affected_component or "",
            self.file_path or "",
        ]
        for item in self.evidence:
            fp = item.value_fingerprint()
            if fp:
                parts.append(fp)
            elif item.sensitive:
                parts.append("sensitive")
            else:
                parts.append((item.snippet or item.description or "")[:160])
        return hashlib.sha256("␟".join(parts).encode()).hexdigest()[:40]
