"""Durable job queue.

A database-backed queue keeps local development dependency free while still
surviving a worker restart, and gives the same semantics on SQLite and
PostgreSQL. Claiming is a conditional UPDATE, so two workers cannot take the
same job even without row locks.

Redis is supported for production coordination, where it provides a wake-up
signal; the database remains the source of truth for job state so a lost Redis
message can never lose a job.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import JobStatus
from app.core.logging import get_logger
from app.database.base import new_id, utcnow
from app.models import Job

logger = get_logger(__name__)

# A job whose worker stopped heartbeating for this long is considered orphaned
# and is returned to the queue.
STALE_LOCK_SECONDS = 900


class JobQueue:
    def __init__(self, session: AsyncSession, *, worker_id: str | None = None) -> None:
        self.session = session
        self.worker_id = worker_id or f"worker-{new_id()[:8]}"

    async def enqueue(
        self,
        job_type: str,
        payload: dict[str, Any],
        *,
        priority: int = 100,
        max_attempts: int = 1,
        delay_seconds: float = 0.0,
    ) -> Job:
        job = Job(
            job_type=job_type,
            payload=payload,
            priority=priority,
            max_attempts=max_attempts,
            available_at=utcnow() + timedelta(seconds=delay_seconds),
        )
        self.session.add(job)
        await self.session.commit()
        logger.info("job.enqueued", job_id=job.id, job_type=job_type)
        return job

    async def claim(self, *, job_types: list[str] | None = None) -> Job | None:
        """Atomically claim the next runnable job, or return None."""
        await self.release_stale()

        query = (
            select(Job.id)
            .where(Job.status == JobStatus.queued, Job.available_at <= utcnow())
            .order_by(Job.priority.asc(), Job.created_at.asc())
            .limit(10)
        )
        if job_types:
            query = query.where(Job.job_type.in_(job_types))

        candidate_ids = (await self.session.execute(query)).scalars().all()
        for job_id in candidate_ids:
            # Conditional update: only the worker that flips the status wins.
            result = await self.session.execute(
                update(Job)
                .where(Job.id == job_id, Job.status == JobStatus.queued)
                .values(
                    status=JobStatus.running,
                    locked_by=self.worker_id,
                    locked_at=utcnow(),
                    heartbeat_at=utcnow(),
                    attempts=Job.attempts + 1,
                )
            )
            await self.session.commit()
            if result.rowcount:
                job = await self.session.get(Job, job_id)
                logger.info("job.claimed", job_id=job_id, worker=self.worker_id)
                return job
        return None

    async def heartbeat(self, job_id: str) -> None:
        await self.session.execute(
            update(Job).where(Job.id == job_id).values(heartbeat_at=utcnow())
        )
        await self.session.commit()

    async def complete(self, job_id: str, *, status: JobStatus, error: str | None = None) -> None:
        await self.session.execute(
            update(Job)
            .where(Job.id == job_id)
            .values(status=status, error=error, finished_at=utcnow(), locked_by=None)
        )
        await self.session.commit()
        logger.info("job.finished", job_id=job_id, status=status.value)

    async def fail_or_retry(self, job: Job, error: str) -> JobStatus:
        """Retry when attempts remain, otherwise mark the job failed."""
        if job.attempts < job.max_attempts:
            await self.session.execute(
                update(Job)
                .where(Job.id == job.id)
                .values(
                    status=JobStatus.queued,
                    error=error,
                    locked_by=None,
                    locked_at=None,
                    # Back off so a deterministic failure does not spin.
                    available_at=utcnow() + timedelta(seconds=30 * job.attempts),
                )
            )
            await self.session.commit()
            logger.warning("job.retry", job_id=job.id, attempt=job.attempts, error=error[:200])
            return JobStatus.queued
        await self.complete(job.id, status=JobStatus.failed, error=error)
        return JobStatus.failed

    async def release_stale(self) -> int:
        """Return jobs whose worker stopped heartbeating to the queue."""
        cutoff = datetime.now(UTC) - timedelta(seconds=STALE_LOCK_SECONDS)
        result = await self.session.execute(
            update(Job)
            .where(
                Job.status == JobStatus.running,
                or_(Job.heartbeat_at.is_(None), Job.heartbeat_at < cutoff),
            )
            .values(status=JobStatus.queued, locked_by=None, locked_at=None)
        )
        await self.session.commit()
        if result.rowcount:
            logger.warning("job.released_stale", count=result.rowcount)
        return int(result.rowcount or 0)

    async def pending_count(self) -> int:
        result = await self.session.execute(
            select(Job).where(Job.status.in_([JobStatus.queued, JobStatus.running]))
        )
        return len(result.scalars().all())
