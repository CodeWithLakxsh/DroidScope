"""APK upload and retrieval endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, Query, Request, UploadFile
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    Pagination,
    actor_from,
    pagination,
    require_api_key,
    session_dependency,
    settings_dependency,
    store_dependency,
)
from app.core.config import Settings
from app.core.errors import ApkValidationError, NotFoundError
from app.core.logging import get_logger
from app.models import ApkArtifact, Scan
from app.schemas.api import ApkDetail, ApkSummary, ApkUploadResponse, Page
from app.services.apk_service import ApkService
from app.storage.artifacts import ArtifactStore

logger = get_logger(__name__)
router = APIRouter(prefix="/apks", tags=["apks"])

ICON_CONTENT_TYPES = {
    "png": "image/png",
    "webp": "image/webp",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
}


@router.post(
    "",
    response_model=ApkUploadResponse,
    status_code=201,
    summary="Upload an APK for analysis",
    description=(
        "Streams the upload to disk, validates the archive against hostile-archive "
        "limits, extracts metadata and stores the file content-addressed by SHA-256. "
        "Uploading a file already present returns the existing record."
    ),
)
async def upload_apk(
    request: Request,
    file: UploadFile = File(..., description="The APK file"),
    session: AsyncSession = Depends(session_dependency),
    settings: Settings = Depends(settings_dependency),
    _auth: str = Depends(require_api_key),
) -> ApkUploadResponse:
    if not file.filename:
        raise ApkValidationError("the upload has no filename")

    service = ApkService(session, settings=settings)
    result = await service.ingest_stream(
        file.file, filename=file.filename, actor=actor_from(request)
    )
    detail = await _to_detail(session, result.apk)
    return ApkUploadResponse(
        apk=detail,
        created=result.created,
        message=(
            "APK stored and metadata extracted"
            if result.created
            else "an APK with this SHA-256 was already stored; the existing record is returned"
        ),
    )


@router.get("", response_model=Page[ApkSummary], summary="List uploaded APKs")
async def list_apks(
    page: Pagination = Depends(pagination),
    search: str | None = Query(default=None, description="Match package name, label or SHA-256"),
    session: AsyncSession = Depends(session_dependency),
) -> Page[ApkSummary]:
    query = select(ApkArtifact)
    count_query = select(func.count()).select_from(ApkArtifact)

    if search:
        pattern = f"%{search.strip()}%"
        condition = (
            ApkArtifact.package_name.ilike(pattern)
            | ApkArtifact.app_label.ilike(pattern)
            | ApkArtifact.sha256.ilike(pattern)
            | ApkArtifact.original_filename.ilike(pattern)
        )
        query = query.where(condition)
        count_query = count_query.where(condition)

    total = (await session.execute(count_query)).scalar_one()
    rows = (
        (
            await session.execute(
                query.order_by(ApkArtifact.created_at.desc())
                .limit(page.limit)
                .offset(page.offset)
            )
        )
        .scalars()
        .all()
    )

    items = [await _to_summary(session, apk) for apk in rows]
    return Page[ApkSummary](items=items, total=int(total), limit=page.limit, offset=page.offset)


@router.get("/{apk_id}", response_model=ApkDetail, summary="Get APK metadata")
async def get_apk(
    apk_id: str, session: AsyncSession = Depends(session_dependency)
) -> ApkDetail:
    apk = await session.get(ApkArtifact, apk_id)
    if apk is None:
        raise NotFoundError(f"APK {apk_id} does not exist")
    return await _to_detail(session, apk)


@router.get(
    "/{apk_id}/icon",
    summary="Get the application icon",
    responses={200: {"content": {"image/png": {}}}, 404: {"description": "No icon stored"}},
)
async def get_icon(
    apk_id: str,
    session: AsyncSession = Depends(session_dependency),
    store: ArtifactStore = Depends(store_dependency),
) -> Response:
    apk = await session.get(ApkArtifact, apk_id)
    if apk is None or not apk.icon_storage_key:
        raise NotFoundError("no icon was extracted for this APK")
    suffix = apk.icon_storage_key.rsplit(".", 1)[-1].lower()
    data = store.read_bytes(apk.icon_storage_key, max_bytes=4 * 1024 * 1024)
    return Response(
        content=data,
        media_type=ICON_CONTENT_TYPES.get(suffix, "application/octet-stream"),
        headers={"Cache-Control": "public, max-age=86400", "X-Content-Type-Options": "nosniff"},
    )


@router.get("/{apk_id}/manifest", summary="Get the decoded AndroidManifest.xml")
async def get_manifest(
    apk_id: str,
    session: AsyncSession = Depends(session_dependency),
    store: ArtifactStore = Depends(store_dependency),
) -> Response:
    apk = await session.get(ApkArtifact, apk_id)
    if apk is None:
        raise NotFoundError(f"APK {apk_id} does not exist")
    key = (apk.apk_metadata or {}).get("manifest_storage_key")
    if not key or not store.exists(key):
        raise NotFoundError("the decoded manifest is not available for this APK")
    return Response(
        content=store.read_text(key, max_bytes=8 * 1024 * 1024),
        media_type="application/xml",
        headers={"X-Content-Type-Options": "nosniff"},
    )


# -- helpers -----------------------------------------------------------------
async def _scan_context(session: AsyncSession, apk_id: str) -> tuple[int, Scan | None]:
    count = (
        await session.execute(
            select(func.count()).select_from(Scan).where(Scan.apk_id == apk_id)
        )
    ).scalar_one()
    latest = (
        await session.execute(
            select(Scan).where(Scan.apk_id == apk_id).order_by(Scan.created_at.desc()).limit(1)
        )
    ).scalar_one_or_none()
    return int(count), latest


async def _to_summary(session: AsyncSession, apk: ApkArtifact) -> ApkSummary:
    count, latest = await _scan_context(session, apk.id)
    return ApkSummary(
        id=apk.id,
        sha256=apk.sha256,
        file_size=apk.file_size,
        original_filename=apk.original_filename,
        package_name=apk.package_name,
        app_label=apk.app_label,
        version_name=apk.version_name,
        version_code=apk.version_code,
        min_sdk=apk.min_sdk,
        target_sdk=apk.target_sdk,
        created_at=apk.created_at,
        has_icon=bool(apk.icon_storage_key),
        scan_count=count,
        latest_scan_id=latest.id if latest else None,
        latest_scan_status=latest.status if latest else None,
    )


async def _to_detail(session: AsyncSession, apk: ApkArtifact) -> ApkDetail:
    summary = await _to_summary(session, apk)
    metadata = dict(apk.apk_metadata or {})
    # Storage keys are internal; clients use the dedicated endpoints instead.
    metadata.pop("manifest_storage_key", None)
    return ApkDetail(
        **summary.model_dump(),
        sha1=apk.sha1,
        md5=apk.md5,
        compile_sdk=apk.compile_sdk,
        metadata_error=apk.metadata_error,
        validation=apk.validation or {},
        apk_metadata=metadata,
    )
