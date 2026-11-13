"""Scan pipeline.

Runs the analyzers for a profile against one APK, normalises their findings and
persists everything: the findings with evidence, a per-analyzer execution
record, the artifacts produced, the network indicators, the capability snapshot
and the explainable risk summary.

Two properties matter here:

* **Failures are recorded, not swallowed.**  An analyzer that could not run
  leaves an execution row saying why, that row feeds the coverage section of the
  risk summary, and the report repeats it.  A scan with half its analyzers
  unavailable never looks like a clean scan.
* **Secrets are masked before they reach the database.**  Normalisation stores
  a mask plus a salted fingerprint; the plaintext is kept only when a
  deployment explicitly opts in.
"""

from __future__ import annotations

import asyncio
import shutil
import tempfile
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.analyzers.base import AnalysisInput, Analyzer, AnalyzerResult
from app.analyzers.registry import build_analyzers
from app.core.capabilities import Capability, collect_capabilities
from app.core.config import Settings, get_settings
from app.core.enums import AnalyzerStatus, JobStatus, ScanProfile, Severity
from app.core.errors import NotFoundError
from app.core.logging import get_logger
from app.detection.model import RawFinding
from app.detection.registry import load_builtin_rules, registry
from app.models import (
    AnalyzerExecution,
    ApkArtifact,
    CapabilitySnapshot,
    DetectionRuleState,
    Finding,
    FindingEvidence,
    NetworkObservation,
    Scan,
    ScanArtifact,
)
from app.schemas.apk import ApkMetadata
from app.services.risk import calculate_risk
from app.storage.artifacts import ArtifactStore, get_artifact_store

logger = get_logger(__name__)

ProgressCallback = Callable[[float, str], Awaitable[None]]


@dataclass(slots=True)
class PipelineOutcome:
    scan_id: str
    status: JobStatus
    findings: int
    severity_counts: dict[str, int]
    risk: dict[str, Any]
    executions: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    error: str | None = None
    duration_seconds: float = 0.0


class CancellationCheck:
    """Polls the scan row so a cancel request takes effect between analyzers."""

    def __init__(self, session: AsyncSession, scan_id: str) -> None:
        self.session = session
        self.scan_id = scan_id

    async def requested(self) -> bool:
        result = await self.session.execute(
            select(Scan.cancel_requested).where(Scan.id == self.scan_id)
        )
        return bool(result.scalar_one_or_none())


class ScanPipeline:
    """Executes a scan end to end."""

    def __init__(
        self,
        session: AsyncSession,
        *,
        settings: Settings | None = None,
        store: ArtifactStore | None = None,
    ) -> None:
        self.session = session
        self.settings = settings or get_settings()
        self.store = store or get_artifact_store(self.settings)
        load_builtin_rules()

    async def run(
        self, scan_id: str, *, progress: ProgressCallback | None = None
    ) -> PipelineOutcome:
        started = time.monotonic()
        scan = await self.session.get(Scan, scan_id)
        if scan is None:
            raise NotFoundError(f"scan {scan_id} does not exist")
        apk = await self.session.get(ApkArtifact, scan.apk_id)
        if apk is None:
            raise NotFoundError("the APK for this scan is no longer available")

        await self._apply_rule_overrides()

        scan.status = JobStatus.running
        scan.started_at = datetime.now(UTC)
        scan.stage = "preparing"
        scan.progress = 0.02
        await self.session.commit()

        workspace = Path(
            tempfile.mkdtemp(prefix=f"droidscope-{scan_id[:8]}-", dir=self.settings.tmp_dir)
        )
        cancellation = CancellationCheck(self.session, scan_id)
        outcome: PipelineOutcome

        try:
            outcome = await self._execute(scan, apk, workspace, cancellation, progress, started)
        except Exception as exc:  # noqa: BLE001 - must always land in a terminal state
            logger.exception("pipeline.failed", scan_id=scan_id)
            scan.status = JobStatus.failed
            scan.error = f"{type(exc).__name__}: {exc}"
            scan.finished_at = datetime.now(UTC)
            scan.duration_seconds = round(time.monotonic() - started, 3)
            await self.session.commit()
            outcome = PipelineOutcome(
                scan_id=scan_id,
                status=JobStatus.failed,
                findings=0,
                severity_counts={},
                risk={},
                error=scan.error,
                duration_seconds=scan.duration_seconds,
            )
        finally:
            shutil.rmtree(workspace, ignore_errors=True)

        return outcome

    # -- internals ---------------------------------------------------------
    async def _execute(
        self,
        scan: Scan,
        apk: ApkArtifact,
        workspace: Path,
        cancellation: CancellationCheck,
        progress: ProgressCallback | None,
        started: float,
    ) -> PipelineOutcome:
        profile = ScanProfile(scan.profile)
        apk_path = self.store.path_for(apk.storage_key)
        if not apk_path.is_file():
            raise NotFoundError("the stored APK file is missing from artifact storage")

        capabilities = {cap.name: cap for cap in await collect_capabilities(self.settings)}
        await self._record_capabilities(scan.id, capabilities)

        metadata = ApkMetadata.model_validate(apk.apk_metadata or {})
        manifest_xml = await self._load_manifest_xml(apk, apk_path, metadata)

        analyzers = build_analyzers(profile)
        shared: dict[str, Any] = {}
        all_findings: list[RawFinding] = []
        limitations: list[str] = []
        executions: list[dict[str, Any]] = []
        cancelled = False

        total_steps = max(len(analyzers), 1)
        for index, analyzer in enumerate(analyzers):
            if await cancellation.requested():
                cancelled = True
                break

            stage = analyzer.name
            fraction = 0.05 + (index / total_steps) * 0.85
            await self._update_progress(scan, fraction, stage, progress)

            data = AnalysisInput(
                scan_id=scan.id,
                apk_id=apk.id,
                apk_path=apk_path,
                sha256=apk.sha256,
                profile=profile,
                settings=self.settings,
                store=self.store,
                workspace=workspace,
                capabilities=capabilities,
                metadata=metadata,
                manifest_xml=manifest_xml,
                shared=shared,
            )

            result = await self._run_with_timeout(analyzer, data)
            shared.update(result.shared or {})

            await self._record_execution(scan.id, result)
            executions.append(
                {
                    "analyzer": result.analyzer,
                    "status": result.status.value,
                    "findings": len(result.findings),
                    "duration_seconds": result.duration_seconds,
                    "error": result.error,
                }
            )
            all_findings.extend(result.findings)
            limitations.extend(result.limitations)

            await self._record_artifacts(scan.id, result)
            await self._record_indicators(scan.id, result)
            await self.session.commit()

        await self._update_progress(scan, 0.92, "normalising findings", progress)
        persisted = await self._persist_findings(scan, apk, all_findings)

        severity_counts = {severity.value: 0 for severity in Severity}
        for finding in persisted:
            severity_counts[finding.severity.value] = (
                severity_counts.get(finding.severity.value, 0) + 1
            )

        execution_rows = (
            (
                await self.session.execute(
                    select(AnalyzerExecution).where(AnalyzerExecution.scan_id == scan.id)
                )
            )
            .scalars()
            .all()
        )
        risk = calculate_risk(persisted, executions=execution_rows, profile=profile.value)

        scan.findings_total = len(persisted)
        scan.severity_counts = severity_counts
        scan.risk = risk.to_dict()
        scan.limitations = sorted(set(limitations))
        scan.environment = {
            "profile": profile.value,
            "analyzers": executions,
            "tool_versions": {
                name: capability.version
                for name, capability in sorted(capabilities.items())
                if capability.available and capability.version
            },
            "tools_unavailable": [
                name
                for name, capability in sorted(capabilities.items())
                if not capability.available
            ],
            "rules_loaded": len(registry),
        }
        scan.status = JobStatus.cancelled if cancelled else JobStatus.completed
        scan.stage = "cancelled" if cancelled else "completed"
        scan.progress = 1.0
        scan.finished_at = datetime.now(UTC)
        scan.duration_seconds = round(time.monotonic() - started, 3)
        await self.session.commit()

        await self._update_progress(scan, 1.0, scan.stage, progress)
        logger.info(
            "pipeline.completed",
            scan_id=scan.id,
            status=scan.status.value,
            findings=len(persisted),
            duration=scan.duration_seconds,
        )

        return PipelineOutcome(
            scan_id=scan.id,
            status=scan.status,
            findings=len(persisted),
            severity_counts=severity_counts,
            risk=scan.risk,
            executions=executions,
            limitations=scan.limitations,
            duration_seconds=scan.duration_seconds,
        )

    async def _run_with_timeout(self, analyzer: Analyzer, data: AnalysisInput) -> AnalyzerResult:
        try:
            return await asyncio.wait_for(
                analyzer.run(data), timeout=self.settings.analyzer_timeout_seconds
            )
        except TimeoutError:
            logger.warning("pipeline.analyzer_timeout", analyzer=analyzer.name)
            return AnalyzerResult(
                analyzer=analyzer.name,
                version=analyzer.version,
                status=AnalyzerStatus.timed_out,
                error=(
                    f"{analyzer.name} exceeded the configured analyzer timeout of "
                    f"{self.settings.analyzer_timeout_seconds}s"
                ),
                limitations=[
                    f"{analyzer.name} was stopped at its time limit; its findings are "
                    "absent from this scan"
                ],
            )

    async def _load_manifest_xml(
        self, apk: ApkArtifact, apk_path: Path, metadata: ApkMetadata
    ) -> str | None:
        key = metadata.manifest_storage_key
        if key and self.store.exists(key):
            return self.store.read_text(key)
        # Decode on demand when the upload path did not retain it.
        try:
            from app.analyzers.apk.metadata import ApkMetadataExtractor

            extraction = ApkMetadataExtractor().extract(apk_path)
            return extraction.manifest_xml
        except Exception as exc:  # noqa: BLE001
            logger.warning("pipeline.manifest_reload_failed", error=str(exc))
            return None

    async def _apply_rule_overrides(self) -> None:
        rows = (await self.session.execute(select(DetectionRuleState))).scalars().all()
        disabled = [row.rule_id for row in rows if not row.enabled]
        overrides = {row.rule_id: row.severity_override for row in rows if row.severity_override}
        registry.apply_overrides(disabled=disabled, severity_overrides=overrides)

    async def _record_capabilities(self, scan_id: str, capabilities: dict[str, Capability]) -> None:
        import platform

        self.session.add(
            CapabilitySnapshot(
                scan_id=scan_id,
                capabilities=[cap.public_dict() for cap in capabilities.values()],
                host={
                    "system": platform.system(),
                    "release": platform.release(),
                    "machine": platform.machine(),
                    "python": platform.python_version(),
                },
            )
        )
        await self.session.commit()

    async def _record_execution(self, scan_id: str, result: AnalyzerResult) -> None:
        now = datetime.now(UTC)
        self.session.add(
            AnalyzerExecution(
                scan_id=scan_id,
                analyzer=result.analyzer,
                analyzer_version=result.version,
                status=result.status,
                started_at=now,
                finished_at=now,
                duration_seconds=result.duration_seconds,
                findings_count=len(result.findings),
                error=result.error,
                detail={
                    **(result.detail or {}),
                    "limitations": result.limitations,
                },
            )
        )

    async def _record_artifacts(self, scan_id: str, result: AnalyzerResult) -> None:
        for artifact in result.artifacts:
            existing = await self.session.execute(
                select(ScanArtifact).where(
                    ScanArtifact.scan_id == scan_id, ScanArtifact.kind == artifact.kind
                )
            )
            row = existing.scalar_one_or_none()
            if row is not None:
                row.storage_key = artifact.storage_key
                row.size_bytes = artifact.size_bytes
                row.entry_count = artifact.entry_count
                row.detail = artifact.detail
                continue
            self.session.add(
                ScanArtifact(
                    scan_id=scan_id,
                    kind=artifact.kind,
                    storage_key=artifact.storage_key,
                    size_bytes=artifact.size_bytes,
                    entry_count=artifact.entry_count,
                    produced_by=result.analyzer,
                    detail=artifact.detail,
                )
            )

    async def _record_indicators(self, scan_id: str, result: AnalyzerResult) -> None:
        for indicator in result.indicators:
            self.session.add(
                NetworkObservation(
                    scan_id=scan_id,
                    indicator_type=str(indicator.get("indicator_type", "url"))[:24],
                    value=str(indicator.get("value", ""))[:2048],
                    scheme=(indicator.get("scheme") or None),
                    host=(indicator.get("host") or None),
                    port=indicator.get("port"),
                    scope=str(indicator.get("scope", "unknown"))[:24],
                    source="static",
                    source_file=(indicator.get("source_file") or None),
                    context=(indicator.get("context") or None),
                    occurrences=int(indicator.get("occurrences", 1)),
                    detail=indicator.get("detail") or {},
                )
            )

    async def _persist_findings(
        self, scan: Scan, apk: ApkArtifact, findings: list[RawFinding]
    ) -> list[Finding]:
        """Normalise and store findings, deduplicating by fingerprint."""
        seen: dict[str, Finding] = {}
        rows: list[Finding] = []

        for raw in findings:
            if not registry.is_enabled(raw.rule_id):
                continue
            severity = registry.severity_for(raw.rule_id, raw.severity)
            fingerprint = raw.fingerprint()
            if fingerprint in seen:
                continue

            row = Finding(
                scan_id=scan.id,
                apk_id=apk.id,
                rule_id=raw.rule_id,
                rule_version=raw.rule_version,
                title=raw.title[:300],
                description=raw.description,
                severity=severity,
                confidence=raw.confidence,
                category=str(getattr(raw.category, "value", raw.category)),
                cwe_ids=list(raw.cwe_ids),
                masvs_controls=list(raw.masvs_controls),
                references=list(raw.references),
                affected_component=(raw.affected_component or None),
                file_path=(raw.file_path or None),
                line_number=raw.line_number,
                impact=raw.impact,
                remediation=raw.remediation,
                verification=raw.verification,
                limitations=raw.limitations,
                analysis_engine=raw.analysis_engine,
                fingerprint=fingerprint,
                finding_metadata=raw.metadata or {},
            )
            self.session.add(row)
            await self.session.flush()

            for position, evidence in enumerate(raw.evidence):
                self.session.add(
                    FindingEvidence(
                        finding_id=row.id,
                        position=position,
                        kind=evidence.kind,
                        description=evidence.description,
                        # Masked at the boundary: the raw value never reaches
                        # the column unless retention is explicitly enabled.
                        snippet=evidence.masked_snippet(),
                        file_path=evidence.file_path,
                        line_number=evidence.line_number,
                        sensitive=evidence.sensitive,
                        value_fingerprint=evidence.value_fingerprint(),
                        raw_value=(
                            evidence.raw_value
                            if evidence.sensitive and not self.settings.redact_secrets_in_reports
                            else None
                        ),
                        evidence_metadata=evidence.metadata or {},
                    )
                )

            seen[fingerprint] = row
            rows.append(row)

        await self.session.commit()
        return rows

    async def _update_progress(
        self, scan: Scan, fraction: float, stage: str, progress: ProgressCallback | None
    ) -> None:
        scan.progress = round(min(max(fraction, 0.0), 1.0), 3)
        scan.stage = stage
        await self.session.commit()
        if progress is not None:
            await progress(scan.progress, stage)
