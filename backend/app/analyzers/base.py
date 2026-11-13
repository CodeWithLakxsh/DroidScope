"""Analyzer contract.

Every analyzer implements the same small interface so the pipeline can run them
uniformly, record what happened, and continue when one fails:

* :meth:`Analyzer.check_prerequisites` reports whether the analyzer can run at
  all in this environment, with a human readable reason when it cannot;
* :meth:`Analyzer.run` performs the work and returns a structured result;
* an analyzer never raises for an expected condition -- a missing tool, a
  timeout or a parser failure becomes a result with the corresponding status, so
  the scan records the truth rather than losing it.

Analyzers are deliberately decoupled from HTTP and from the database.  They
receive an :class:`AnalysisInput` and return an :class:`AnalyzerResult`; the
service layer persists it.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.capabilities import Capability
from app.core.config import Settings
from app.core.enums import AnalyzerStatus, ScanProfile
from app.core.errors import AnalyzerTimeout, ToolUnavailableError
from app.core.logging import get_logger
from app.detection.model import RawFinding
from app.schemas.apk import ApkMetadata
from app.storage.artifacts import ArtifactStore

logger = get_logger(__name__)


@dataclass(slots=True)
class ArtifactRef:
    """An artifact an analyzer produced and placed in the store."""

    kind: str
    storage_key: str
    size_bytes: int = 0
    entry_count: int = 0
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AnalysisInput:
    """Normalised input handed to every analyzer."""

    scan_id: str
    apk_id: str
    apk_path: Path
    sha256: str
    profile: ScanProfile
    settings: Settings
    store: ArtifactStore
    workspace: Path
    capabilities: dict[str, Capability]
    metadata: ApkMetadata
    manifest_xml: str | None = None
    # Data published by earlier analyzers in the same scan, e.g. the decompiled
    # source tree path or the ELF inspection results.
    shared: dict[str, Any] = field(default_factory=dict)

    def capability(self, name: str) -> Capability | None:
        return self.capabilities.get(name)

    def has_capability(self, name: str) -> bool:
        cap = self.capabilities.get(name)
        return bool(cap and cap.available)

    def tool_path(self, name: str) -> Path | None:
        cap = self.capabilities.get(name)
        if cap and cap.available and cap.path:
            return Path(cap.path)
        return None

    def scratch_dir(self, name: str) -> Path:
        path = self.workspace / name
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        return path


@dataclass(slots=True)
class AnalyzerResult:
    """What an analyzer produced, including why it did not produce findings."""

    analyzer: str
    status: AnalyzerStatus
    version: str = "1"
    findings: list[RawFinding] = field(default_factory=list)
    artifacts: list[ArtifactRef] = field(default_factory=list)
    indicators: list[dict[str, Any]] = field(default_factory=list)
    # Published to later analyzers through AnalysisInput.shared.
    shared: dict[str, Any] = field(default_factory=dict)
    detail: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    duration_seconds: float = 0.0
    # Known gaps in this analyzer's coverage for this APK, surfaced in reports.
    limitations: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status == AnalyzerStatus.completed


class Analyzer(ABC):
    """Base class for all analyzers."""

    #: Stable identifier, recorded against every finding and execution.
    name: str = "analyzer"
    #: Bumped when the analyzer's behaviour changes in a way that affects results.
    version: str = "1"
    #: Capability names from :mod:`app.core.capabilities` that must be available.
    required_capabilities: tuple[str, ...] = ()
    #: Scan profiles that include this analyzer.
    profiles: tuple[ScanProfile, ...] = (
        ScanProfile.quick,
        ScanProfile.standard,
        ScanProfile.full,
    )
    #: Human readable description used by the API and documentation.
    description: str = ""

    def applies_to(self, profile: ScanProfile) -> bool:
        return profile in self.profiles

    async def check_prerequisites(self, data: AnalysisInput) -> tuple[bool, str | None]:
        """Report whether this analyzer can run, and why not when it cannot."""
        missing = [
            name for name in self.required_capabilities if not data.has_capability(name)
        ]
        if missing:
            hints = []
            for name in missing:
                cap = data.capability(name)
                hint = cap.install_hint if cap and cap.install_hint else None
                hints.append(f"{name}" + (f" ({hint})" if hint else ""))
            return False, "required tooling unavailable: " + "; ".join(hints)
        return True, None

    @abstractmethod
    async def analyze(self, data: AnalysisInput) -> AnalyzerResult:
        """Perform the analysis.  Called only after prerequisites pass."""

    async def run(self, data: AnalysisInput) -> AnalyzerResult:
        """Execute the analyzer, converting expected failures into a status."""
        started = time.monotonic()
        available, reason = await self.check_prerequisites(data)
        if not available:
            logger.info("analyzer.unavailable", analyzer=self.name, reason=reason)
            return AnalyzerResult(
                analyzer=self.name,
                version=self.version,
                status=AnalyzerStatus.unavailable,
                error=reason,
                duration_seconds=round(time.monotonic() - started, 3),
                limitations=[f"{self.name} did not run: {reason}"],
            )

        try:
            result = await self.analyze(data)
        except AnalyzerTimeout as exc:
            logger.warning("analyzer.timeout", analyzer=self.name, error=str(exc))
            return AnalyzerResult(
                analyzer=self.name,
                version=self.version,
                status=AnalyzerStatus.timed_out,
                error=str(exc),
                detail=exc.details,
                duration_seconds=round(time.monotonic() - started, 3),
                limitations=[f"{self.name} exceeded its time budget and was stopped"],
            )
        except ToolUnavailableError as exc:
            return AnalyzerResult(
                analyzer=self.name,
                version=self.version,
                status=AnalyzerStatus.unavailable,
                error=str(exc),
                duration_seconds=round(time.monotonic() - started, 3),
                limitations=[f"{self.name} did not run: {exc}"],
            )
        except Exception as exc:  # noqa: BLE001 - an analyzer must not kill the scan
            logger.exception("analyzer.failed", analyzer=self.name)
            return AnalyzerResult(
                analyzer=self.name,
                version=self.version,
                status=AnalyzerStatus.failed,
                error=f"{type(exc).__name__}: {exc}",
                duration_seconds=round(time.monotonic() - started, 3),
                limitations=[f"{self.name} failed and produced no results"],
            )

        result.analyzer = self.name
        result.version = self.version
        if result.duration_seconds == 0.0:
            result.duration_seconds = round(time.monotonic() - started, 3)
        return result
