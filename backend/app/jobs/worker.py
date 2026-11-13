"""Background worker.

Runs in its own process (``droidscope worker``) so that decompilation, which is
CPU and memory heavy, never happens inside an HTTP request handler.  Several
workers can run concurrently against the same database; claiming is atomic.
"""

from __future__ import annotations

import asyncio
import contextlib
import signal
from typing import Any

from app.core.config import Settings, get_settings
from app.core.enums import JobStatus
from app.core.logging import configure_logging, get_logger
from app.database.session import create_all, session_scope
from app.jobs.queue import JobQueue
from app.models import Job
from app.services.pipeline import ScanPipeline
from app.services.scan_service import SCAN_JOB_TYPE

logger = get_logger(__name__)

HEARTBEAT_INTERVAL = 30.0


class Worker:
    def __init__(self, *, settings: Settings | None = None, worker_id: str | None = None) -> None:
        self.settings = settings or get_settings()
        self.worker_id = worker_id
        self._stopping = asyncio.Event()
        self._active: set[asyncio.Task] = set()

    def request_stop(self) -> None:
        logger.info("worker.stop_requested")
        self._stopping.set()

    async def run(self, *, once: bool = False, max_jobs: int | None = None) -> int:
        """Process jobs until stopped.  Returns the number of jobs handled."""
        configure_logging(self.settings)
        self.settings.ensure_directories()
        await create_all()

        processed = 0
        concurrency = max(1, self.settings.analysis_concurrency)
        logger.info(
            "worker.started",
            concurrency=concurrency,
            poll_interval=self.settings.worker_poll_interval_seconds,
        )

        while not self._stopping.is_set():
            if max_jobs is not None and processed >= max_jobs:
                break

            if len(self._active) >= concurrency:
                await self._wait_for_slot()
                continue

            job = await self._claim()
            if job is None:
                if once:
                    break
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(
                        self._stopping.wait(),
                        timeout=self.settings.worker_poll_interval_seconds,
                    )
                continue

            processed += 1
            task = asyncio.create_task(self._process(job.id, job.job_type, dict(job.payload)))
            self._active.add(task)
            task.add_done_callback(self._active.discard)

        if self._active:
            logger.info("worker.draining", active=len(self._active))
            await asyncio.gather(*self._active, return_exceptions=True)
        logger.info("worker.stopped", processed=processed)
        return processed

    async def _wait_for_slot(self) -> None:
        if not self._active:
            return
        await asyncio.wait(self._active, return_when=asyncio.FIRST_COMPLETED)

    async def _claim(self) -> Job | None:
        async with session_scope(self.settings) as session:
            queue = JobQueue(session, worker_id=self.worker_id)
            job = await queue.claim(job_types=[SCAN_JOB_TYPE])
            if job is None:
                return None
            # Detach a plain copy; the session closes when the scope exits.
            session.expunge(job)
            return job

    async def _process(self, job_id: str, job_type: str, payload: dict[str, Any]) -> None:
        heartbeat = asyncio.create_task(self._heartbeat(job_id))
        try:
            if job_type == SCAN_JOB_TYPE:
                await self._run_scan(job_id, payload)
            else:
                logger.warning("worker.unknown_job_type", job_type=job_type, job_id=job_id)
                async with session_scope(self.settings) as session:
                    await JobQueue(session).complete(
                        job_id, status=JobStatus.failed, error=f"unknown job type {job_type!r}"
                    )
        except Exception as exc:  # noqa: BLE001 - a job must not kill the worker
            logger.exception("worker.job_failed", job_id=job_id)
            async with session_scope(self.settings) as session:
                queue = JobQueue(session, worker_id=self.worker_id)
                job = await session.get(Job, job_id)
                if job is not None:
                    await queue.fail_or_retry(job, f"{type(exc).__name__}: {exc}")
        finally:
            heartbeat.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await heartbeat

    async def _run_scan(self, job_id: str, payload: dict[str, Any]) -> None:
        scan_id = payload.get("scan_id")
        if not scan_id:
            async with session_scope(self.settings) as session:
                await JobQueue(session).complete(
                    job_id, status=JobStatus.failed, error="job payload has no scan_id"
                )
            return

        async with session_scope(self.settings) as session:
            pipeline = ScanPipeline(session, settings=self.settings)
            outcome = await pipeline.run(scan_id)

        async with session_scope(self.settings) as session:
            queue = JobQueue(session, worker_id=self.worker_id)
            status = (
                JobStatus.completed
                if outcome.status in {JobStatus.completed, JobStatus.cancelled}
                else JobStatus.failed
            )
            await queue.complete(job_id, status=status, error=outcome.error)

    async def _heartbeat(self, job_id: str) -> None:
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            try:
                async with session_scope(self.settings) as session:
                    await JobQueue(session).heartbeat(job_id)
            except Exception as exc:  # noqa: BLE001
                logger.debug("worker.heartbeat_failed", job_id=job_id, error=str(exc))


async def run_worker(*, once: bool = False, max_jobs: int | None = None) -> int:
    worker = Worker()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, worker.request_stop)
    return await worker.run(once=once, max_jobs=max_jobs)
