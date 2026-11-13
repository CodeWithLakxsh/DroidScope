"""Dashboard statistics, comparison and settings endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_api_key, session_dependency, settings_dependency
from app.core.capabilities import collect_capabilities
from app.core.config import Settings
from app.core.errors import NotFoundError
from app.models import Comparison, SettingEntry
from app.schemas.api import (
    CompareRequest,
    CompareResponse,
    SettingsOut,
    SettingsUpdateRequest,
)
from app.services.compare import CompareService
from app.services.scan_service import ScanService

router = APIRouter(tags=["analysis"])

SETTINGS_KEY = "runtime"


@router.get("/dashboard", summary="Dashboard statistics computed from stored results")
async def dashboard(session: AsyncSession = Depends(session_dependency)) -> dict:
    from sqlalchemy import desc

    from app.models import Scan

    statistics = await ScanService(session).dashboard_statistics()
    recent = (
        (
            await session.execute(
                select(Scan).order_by(desc(Scan.created_at)).limit(10)
            )
        )
        .scalars()
        .all()
    )
    statistics["recent_scans"] = [
        {
            "id": scan.id,
            "apk_id": scan.apk_id,
            "profile": str(getattr(scan.profile, "value", scan.profile)),
            "status": str(getattr(scan.status, "value", scan.status)),
            "findings_total": scan.findings_total,
            "severity_counts": scan.severity_counts or {},
            "risk_score": (scan.risk or {}).get("score"),
            "risk_band": (scan.risk or {}).get("band"),
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "duration_seconds": scan.duration_seconds,
        }
        for scan in recent
    ]
    return statistics


@router.post("/compare", response_model=CompareResponse, status_code=201, summary="Compare two APKs")
async def compare(
    payload: CompareRequest,
    session: AsyncSession = Depends(session_dependency),
    _auth: str = Depends(require_api_key),
) -> CompareResponse:
    comparison = await CompareService(session).compare(
        payload.baseline_apk_id,
        payload.updated_apk_id,
        baseline_scan_id=payload.baseline_scan_id,
        updated_scan_id=payload.updated_scan_id,
    )
    return CompareResponse.model_validate(comparison)


@router.get(
    "/compare/{comparison_id}",
    response_model=CompareResponse,
    summary="Get a stored comparison",
)
async def get_comparison(
    comparison_id: str, session: AsyncSession = Depends(session_dependency)
) -> CompareResponse:
    comparison = await session.get(Comparison, comparison_id)
    if comparison is None:
        raise NotFoundError(f"comparison {comparison_id} does not exist")
    return CompareResponse.model_validate(comparison)


@router.get("/settings", response_model=SettingsOut, summary="Effective settings")
async def get_settings_endpoint(
    session: AsyncSession = Depends(session_dependency),
    settings: Settings = Depends(settings_dependency),
) -> SettingsOut:
    overrides = await _load_overrides(session)
    capabilities = {cap.name: cap.available for cap in await collect_capabilities(settings)}
    merged = {
        "analysis_concurrency": settings.analysis_concurrency,
        "max_upload_bytes": settings.max_upload_bytes,
        "analyzer_timeout_seconds": settings.analyzer_timeout_seconds,
        "scan_timeout_seconds": settings.scan_timeout_seconds,
        "decompile_timeout_seconds": settings.decompile_timeout_seconds,
        "artifact_retention_days": settings.artifact_retention_days,
        "reuse_identical_scans": settings.reuse_identical_scans,
        "redact_secrets_in_reports": settings.redact_secrets_in_reports,
        "dynamic_analysis_enabled": settings.dynamic_analysis_enabled,
        "dynamic_allow_physical_devices": settings.dynamic_allow_physical_devices,
        "log_level": settings.log_level.value,
        **overrides,
    }
    return SettingsOut(**merged, tools=capabilities)


@router.patch("/settings", response_model=SettingsOut, summary="Update runtime settings")
async def update_settings(
    payload: SettingsUpdateRequest,
    session: AsyncSession = Depends(session_dependency),
    settings: Settings = Depends(settings_dependency),
    _auth: str = Depends(require_api_key),
) -> SettingsOut:
    """Persist a runtime overlay.

    Only operational values are adjustable. Tool paths are deliberately not
    settable through the API: a writable executable path would be a command
    execution primitive.
    """
    overrides = await _load_overrides(session)
    updates = payload.model_dump(exclude_none=True)
    overrides.update(updates)

    entry = await session.get(SettingEntry, SETTINGS_KEY)
    if entry is None:
        entry = SettingEntry(key=SETTINGS_KEY, value=overrides)
        session.add(entry)
    else:
        entry.value = overrides
    await session.commit()

    return await get_settings_endpoint(session=session, settings=settings)


async def _load_overrides(session: AsyncSession) -> dict:
    entry = await session.get(SettingEntry, SETTINGS_KEY)
    return dict(entry.value) if entry and entry.value else {}
