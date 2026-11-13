"""Scan lifecycle: creation, reuse, cancellation and querying."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.enums import JobStatus, ScanProfile
from app.core.errors import ConflictError, NotFoundError
from app.core.logging import get_logger
from app.jobs.queue import JobQueue
from app.models import AnalyzerExecution, ApkArtifact, AuditEvent, Finding, Scan

logger = get_logger(__name__)

SCAN_JOB_TYPE = "scan.run"


@dataclass(slots=True)
class ScanCreation:
    scan: Scan
    reused: bool
    job_id: str | None = None


def compute_dedup_key(sha256: str, profile: ScanProfile, config: dict) -> str:
    """Identity of "the same analysis of the same file"."""
    payload = json.dumps(
        {"sha256": sha256, "profile": profile.value, "config": config or {}},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()


class ScanService:
    def __init__(self, session: AsyncSession, *, settings: Settings | None = None) -> None:
        self.session = session
        self.settings = settings or get_settings()

    async def create(
        self,
        apk_id: str,
        *,
        profile: ScanProfile = ScanProfile.standard,
        config: dict | None = None,
        reuse: bool | None = None,
        actor: str = "local",
    ) -> ScanCreation:
        apk = await self.session.get(ApkArtifact, apk_id)
        if apk is None:
            raise NotFoundError(f"APK {apk_id} does not exist")

        config = config or {}
        dedup_key = compute_dedup_key(apk.sha256, profile, config)
        allow_reuse = self.settings.reuse_identical_scans if reuse is None else reuse

        if allow_reuse:
            existing = await self._find_reusable(dedup_key)
            if existing is not None:
                logger.info("scan.reused", scan_id=existing.id, apk_id=apk_id)
                return ScanCreation(scan=existing, reused=True)

        # An identical scan already in flight is returned rather than duplicated.
        in_flight = await self._find_in_flight(dedup_key)
        if in_flight is not None:
            return ScanCreation(scan=in_flight, reused=True)

        scan = Scan(
            apk_id=apk.id,
            profile=profile,
            status=JobStatus.queued,
            config=config,
            dedup_key=dedup_key,
            severity_counts={},
            risk={},
            limitations=[],
            environment={},
        )
        self.session.add(scan)
        await self.session.flush()

        queue = JobQueue(self.session)
        job = await queue.enqueue(
            SCAN_JOB_TYPE,
            {"scan_id": scan.id, "apk_id": apk.id, "profile": profile.value},
            priority=50 if profile == ScanProfile.quick else 100,
        )
        self.session.add(
            AuditEvent(
                actor=actor,
                action="scan.create",
                resource_type="scan",
                resource_id=scan.id,
                detail={"apk_id": apk.id, "profile": profile.value, "job_id": job.id},
            )
        )
        await self.session.commit()
        logger.info("scan.created", scan_id=scan.id, apk_id=apk.id, profile=profile.value)
        return ScanCreation(scan=scan, reused=False, job_id=job.id)

    async def _find_reusable(self, dedup_key: str) -> Scan | None:
        """A completed scan with the same identity whose results are still present."""
        result = await self.session.execute(
            select(Scan)
            .where(Scan.dedup_key == dedup_key, Scan.status == JobStatus.completed)
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def _find_in_flight(self, dedup_key: str) -> Scan | None:
        result = await self.session.execute(
            select(Scan)
            .where(
                Scan.dedup_key == dedup_key,
                Scan.status.in_([JobStatus.queued, JobStatus.running]),
            )
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def get(self, scan_id: str) -> Scan | None:
        return await self.session.get(Scan, scan_id)

    async def require(self, scan_id: str) -> Scan:
        scan = await self.get(scan_id)
        if scan is None:
            raise NotFoundError(f"scan {scan_id} does not exist")
        return scan

    async def cancel(self, scan_id: str, *, actor: str = "local") -> Scan:
        scan = await self.require(scan_id)
        if JobStatus(scan.status).terminal:
            raise ConflictError(
                f"scan is already {scan.status.value} and cannot be cancelled"
            )
        scan.cancel_requested = True
        if scan.status == JobStatus.queued:
            # Nothing has started, so finish it immediately.
            scan.status = JobStatus.cancelled
            scan.stage = "cancelled"
            scan.finished_at = datetime.now(UTC)
        self.session.add(
            AuditEvent(
                actor=actor,
                action="scan.cancel",
                resource_type="scan",
                resource_id=scan.id,
                detail={"previous_status": scan.status.value},
            )
        )
        await self.session.commit()
        logger.info("scan.cancel_requested", scan_id=scan_id)
        return scan

    async def executions(self, scan_id: str) -> list[AnalyzerExecution]:
        result = await self.session.execute(
            select(AnalyzerExecution)
            .where(AnalyzerExecution.scan_id == scan_id)
            .order_by(AnalyzerExecution.started_at)
        )
        return list(result.scalars().all())

    async def dashboard_statistics(self) -> dict:
        """Statistics computed from stored results; never fabricated."""
        apk_total = (
            await self.session.execute(select(func.count()).select_from(ApkArtifact))
        ).scalar_one()

        status_rows = (
            await self.session.execute(
                select(Scan.status, func.count()).group_by(Scan.status)
            )
        ).all()
        by_status = {str(getattr(s, "value", s)): int(c) for s, c in status_rows}

        severity_rows = (
            await self.session.execute(
                select(Finding.severity, func.count()).group_by(Finding.severity)
            )
        ).all()
        by_severity = {str(getattr(s, "value", s)): int(c) for s, c in severity_rows}

        category_rows = (
            await self.session.execute(
                select(Finding.category, func.count())
                .group_by(Finding.category)
                .order_by(func.count().desc())
                .limit(12)
            )
        ).all()

        findings_total = (
            await self.session.execute(select(func.count()).select_from(Finding))
        ).scalar_one()

        return {
            "apks_total": int(apk_total),
            "scans_total": sum(by_status.values()),
            "scans_by_status": by_status,
            "findings_total": int(findings_total),
            "findings_by_severity": by_severity,
            "findings_by_category": [
                {"category": str(getattr(c, "value", c)), "count": int(n)}
                for c, n in category_rows
            ],
        }
