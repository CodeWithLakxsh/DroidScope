"""Report generation and download endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_api_key, session_dependency, settings_dependency
from app.core.config import Settings
from app.models import Report
from app.reports.service import MEDIA_TYPES, ReportService
from app.schemas.api import ReportCreateRequest, ReportOut

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post(
    "",
    response_model=ReportOut,
    status_code=201,
    summary="Generate a report",
    description=(
        "Renders a report from stored scan data. Secret evidence is redacted by "
        "default; disabling redaction requires the server setting to permit it."
    ),
)
async def create_report(
    payload: ReportCreateRequest,
    session: AsyncSession = Depends(session_dependency),
    settings: Settings = Depends(settings_dependency),
    _auth: str = Depends(require_api_key),
) -> ReportOut:
    service = ReportService(session, settings=settings)
    report = await service.generate(
        payload.scan_id,
        payload.report_format,
        include_evidence=payload.include_evidence,
        redact_secrets=payload.redact_secrets,
        include_informational=payload.include_informational,
    )
    return ReportOut.model_validate(report)


@router.get("", response_model=list[ReportOut], summary="List generated reports")
async def list_reports(
    scan_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    session: AsyncSession = Depends(session_dependency),
) -> list[ReportOut]:
    query = select(Report).order_by(Report.created_at.desc()).limit(limit)
    if scan_id:
        query = query.where(Report.scan_id == scan_id)
    rows = (await session.execute(query)).scalars().all()
    return [ReportOut.model_validate(row) for row in rows]


@router.get("/{report_id}", response_model=ReportOut, summary="Get report metadata")
async def get_report(
    report_id: str, session: AsyncSession = Depends(session_dependency)
) -> ReportOut:
    report = await ReportService(session).get(report_id)
    return ReportOut.model_validate(report)


@router.get(
    "/{report_id}/download",
    summary="Download a generated report",
    response_class=Response,
)
async def download_report(
    report_id: str,
    session: AsyncSession = Depends(session_dependency),
    settings: Settings = Depends(settings_dependency),
) -> Response:
    service = ReportService(session, settings=settings)
    report = await service.get(report_id)
    payload = await service.read_payload(report)
    return Response(
        content=payload,
        media_type=MEDIA_TYPES.get(report.report_format, "application/octet-stream"),
        headers={
            "Content-Disposition": f'attachment; filename="{report.filename}"',
            "X-Content-Type-Options": "nosniff",
            # A report derived from an untrusted APK is never rendered inline
            # with script privileges.
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:",
        },
    )
