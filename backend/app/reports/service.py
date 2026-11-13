"""Report generation service."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.enums import JobStatus, ReportFormat
from app.core.errors import CapabilityUnavailableError, NotFoundError
from app.core.logging import get_logger
from app.models import ApkArtifact, Report, Scan
from app.reports.builder import build_report_document
from app.reports.html import render_html
from app.reports.sarif import render_sarif
from app.storage.artifacts import ArtifactStore, get_artifact_store, sanitize_filename

logger = get_logger(__name__)

MEDIA_TYPES = {
    ReportFormat.pdf: "application/pdf",
    ReportFormat.html: "text/html; charset=utf-8",
    ReportFormat.json: "application/json",
    ReportFormat.sarif: "application/sarif+json",
}


class ReportService:
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

    async def generate(
        self,
        scan_id: str,
        report_format: ReportFormat,
        *,
        include_evidence: bool = True,
        redact_secrets: bool | None = None,
        include_informational: bool = True,
    ) -> Report:
        scan = await self.session.get(Scan, scan_id)
        if scan is None:
            raise NotFoundError(f"scan {scan_id} does not exist")
        apk = await self.session.get(ApkArtifact, scan.apk_id)

        report = Report(
            scan_id=scan_id,
            report_format=report_format,
            status=JobStatus.running,
            options={
                "include_evidence": include_evidence,
                "redact_secrets": redact_secrets,
                "include_informational": include_informational,
            },
        )
        self.session.add(report)
        await self.session.flush()

        try:
            document = await build_report_document(
                self.session,
                scan_id,
                include_evidence=include_evidence,
                redact_secrets=redact_secrets,
                include_informational=include_informational,
                settings=self.settings,
            )
            payload, extension = self._render(document, report_format)
        except CapabilityUnavailableError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.exception("report.failed", scan_id=scan_id, format=report_format.value)
            report.status = JobStatus.failed
            report.error = f"{type(exc).__name__}: {exc}"
            report.completed_at = datetime.now(UTC)
            await self.session.commit()
            raise

        base = (apk.package_name if apk and apk.package_name else "droidscope")
        filename = sanitize_filename(
            f"droidscope-{base}-{scan_id[:8]}.{extension}", default=f"report.{extension}"
        )
        stored = self.store.write_bytes(self.store.report_key(report.id, filename), payload)

        report.status = JobStatus.completed
        report.storage_key = stored.storage_key
        report.filename = filename
        report.size_bytes = stored.size_bytes
        report.sha256 = hashlib.sha256(payload).hexdigest()
        report.completed_at = datetime.now(UTC)
        await self.session.commit()

        logger.info(
            "report.generated",
            report_id=report.id,
            scan_id=scan_id,
            format=report_format.value,
            size=stored.size_bytes,
        )
        return report

    def _render(self, document: dict, report_format: ReportFormat) -> tuple[bytes, str]:
        if report_format == ReportFormat.json:
            return json.dumps(document, indent=2, default=str).encode(), "json"
        if report_format == ReportFormat.sarif:
            return json.dumps(render_sarif(document), indent=2, default=str).encode(), "sarif.json"
        if report_format == ReportFormat.html:
            return render_html(document).encode(), "html"
        if report_format == ReportFormat.pdf:
            try:
                from app.reports.pdf import render_pdf
            except ImportError as exc:
                raise CapabilityUnavailableError(
                    "PDF reports require reportlab, which is not installed. "
                    "Install it with: pip install reportlab, or export HTML or JSON instead."
                ) from exc
            return render_pdf(document), "pdf"
        raise NotFoundError(f"unsupported report format {report_format}")

    async def get(self, report_id: str) -> Report:
        report = await self.session.get(Report, report_id)
        if report is None:
            raise NotFoundError(f"report {report_id} does not exist")
        return report

    async def read_payload(self, report: Report) -> bytes:
        if not report.storage_key or not self.store.exists(report.storage_key):
            raise NotFoundError("the generated report file is no longer available")
        return self.store.read_bytes(report.storage_key)
