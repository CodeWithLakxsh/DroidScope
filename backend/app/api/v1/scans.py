"""Scan lifecycle, findings, artifacts and code browsing endpoints."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

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
from app.core.enums import Confidence, FindingStatus, JobStatus, ScanProfile, Severity
from app.core.errors import NotFoundError, ValidationError
from app.core.logging import get_logger
from app.models import (
    ApkArtifact,
    Finding,
    FindingReview,
    NetworkObservation,
    Scan,
    ScanArtifact,
)
from app.schemas.api import (
    AnalyzerExecutionOut,
    ArtifactOut,
    FindingDetail,
    FindingReviewRequest,
    FindingSummary,
    IndicatorOut,
    Page,
    ScanCreateRequest,
    ScanCreateResponse,
    ScanDetail,
    ScanSummary,
    SourceFileResponse,
    SourceTreeResponse,
    TreeEntry,
)
from app.services.scan_service import ScanService
from app.storage.artifacts import ArtifactStore

logger = get_logger(__name__)
router = APIRouter(tags=["scans"])

MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024
BROWSABLE_ARTIFACTS = {"decompiled-sources", "decoded-resources"}


# --- scans ------------------------------------------------------------------
@router.post("/scans", response_model=ScanCreateResponse, status_code=201, summary="Queue a scan")
async def create_scan(
    request: Request,
    payload: ScanCreateRequest,
    session: AsyncSession = Depends(session_dependency),
    settings: Settings = Depends(settings_dependency),
    _auth: str = Depends(require_api_key),
) -> ScanCreateResponse:
    service = ScanService(session, settings=settings)
    creation = await service.create(
        payload.apk_id,
        profile=payload.profile,
        config=payload.config,
        reuse=payload.reuse_existing,
        actor=actor_from(request),
    )
    summary = await _scan_summary(session, creation.scan)
    return ScanCreateResponse(
        scan=summary,
        reused=creation.reused,
        message=(
            "an existing scan with identical inputs was reused"
            if creation.reused
            else "scan queued for background execution"
        ),
    )


@router.get("/scans", response_model=Page[ScanSummary], summary="List scans")
async def list_scans(
    page: Pagination = Depends(pagination),
    status: JobStatus | None = Query(default=None),
    apk_id: str | None = Query(default=None),
    profile: ScanProfile | None = Query(default=None),
    session: AsyncSession = Depends(session_dependency),
) -> Page[ScanSummary]:
    query = select(Scan)
    count_query = select(func.count()).select_from(Scan)
    for condition in (
        Scan.status == status if status else None,
        Scan.apk_id == apk_id if apk_id else None,
        Scan.profile == profile if profile else None,
    ):
        if condition is not None:
            query = query.where(condition)
            count_query = count_query.where(condition)

    total = (await session.execute(count_query)).scalar_one()
    rows = (
        (
            await session.execute(
                query.order_by(Scan.created_at.desc()).limit(page.limit).offset(page.offset)
            )
        )
        .scalars()
        .all()
    )
    items = [await _scan_summary(session, scan) for scan in rows]
    return Page[ScanSummary](items=items, total=int(total), limit=page.limit, offset=page.offset)


@router.get("/scans/{scan_id}", response_model=ScanDetail, summary="Get scan detail")
async def get_scan(
    scan_id: str, session: AsyncSession = Depends(session_dependency)
) -> ScanDetail:
    scan = await _require_scan(session, scan_id)
    summary = await _scan_summary(session, scan)
    executions = await ScanService(session).executions(scan_id)
    artifacts = (
        (await session.execute(select(ScanArtifact).where(ScanArtifact.scan_id == scan_id)))
        .scalars()
        .all()
    )
    return ScanDetail(
        **summary.model_dump(),
        risk=scan.risk or {},
        limitations=list(scan.limitations or []),
        environment=scan.environment or {},
        config=scan.config or {},
        executions=[AnalyzerExecutionOut.model_validate(e) for e in executions],
        artifacts=sorted({a.kind for a in artifacts}),
    )


@router.post("/scans/{scan_id}/cancel", response_model=ScanSummary, summary="Cancel a scan")
async def cancel_scan(
    request: Request,
    scan_id: str,
    session: AsyncSession = Depends(session_dependency),
    _auth: str = Depends(require_api_key),
) -> ScanSummary:
    scan = await ScanService(session).cancel(scan_id, actor=actor_from(request))
    return await _scan_summary(session, scan)


@router.get(
    "/scans/{scan_id}/findings",
    response_model=Page[FindingSummary],
    summary="List findings for a scan",
)
async def list_scan_findings(
    scan_id: str,
    page: Pagination = Depends(pagination),
    severity: list[Severity] | None = Query(default=None),
    confidence: list[Confidence] | None = Query(default=None),
    status: list[FindingStatus] | None = Query(default=None),
    category: str | None = Query(default=None),
    engine: str | None = Query(default=None),
    rule_id: str | None = Query(default=None),
    cwe: str | None = Query(default=None),
    masvs: str | None = Query(default=None),
    file_path: str | None = Query(default=None),
    search: str | None = Query(default=None),
    sort: str = Query(default="severity", pattern="^(severity|created_at|rule_id|title)$"),
    session: AsyncSession = Depends(session_dependency),
) -> Page[FindingSummary]:
    await _require_scan(session, scan_id)
    query = select(Finding).where(Finding.scan_id == scan_id)
    count_query = select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id)

    conditions = []
    if severity:
        conditions.append(Finding.severity.in_(severity))
    if confidence:
        conditions.append(Finding.confidence.in_(confidence))
    if status:
        conditions.append(Finding.status.in_(status))
    if category:
        conditions.append(Finding.category == category)
    if engine:
        conditions.append(Finding.analysis_engine == engine)
    if rule_id:
        conditions.append(Finding.rule_id == rule_id)
    if file_path:
        conditions.append(Finding.file_path.ilike(f"%{file_path}%"))
    if search:
        pattern = f"%{search.strip()}%"
        conditions.append(
            Finding.title.ilike(pattern)
            | Finding.description.ilike(pattern)
            | Finding.affected_component.ilike(pattern)
        )
    for condition in conditions:
        query = query.where(condition)
        count_query = count_query.where(condition)

    total = (await session.execute(count_query)).scalar_one()
    rows = (
        (await session.execute(query.order_by(*_ordering(sort))))
        .scalars()
        .all()
    )

    # CWE and MASVS live in JSON columns; filtering them portably across SQLite
    # and PostgreSQL is done in Python on the already-narrowed set.
    if cwe:
        rows = [row for row in rows if cwe in (row.cwe_ids or [])]
    if masvs:
        rows = [row for row in rows if masvs in (row.masvs_controls or [])]
    if cwe or masvs:
        total = len(rows)

    window = rows[page.offset : page.offset + page.limit]
    return Page[FindingSummary](
        items=[FindingSummary.model_validate(row) for row in window],
        total=int(total),
        limit=page.limit,
        offset=page.offset,
    )


@router.get(
    "/scans/{scan_id}/indicators",
    response_model=Page[IndicatorOut],
    summary="Network indicators extracted from the APK",
)
async def list_indicators(
    scan_id: str,
    page: Pagination = Depends(pagination),
    scope: str | None = Query(default=None),
    indicator_type: str | None = Query(default=None),
    session: AsyncSession = Depends(session_dependency),
) -> Page[IndicatorOut]:
    await _require_scan(session, scan_id)
    query = select(NetworkObservation).where(NetworkObservation.scan_id == scan_id)
    count_query = (
        select(func.count())
        .select_from(NetworkObservation)
        .where(NetworkObservation.scan_id == scan_id)
    )
    if scope:
        query = query.where(NetworkObservation.scope == scope)
        count_query = count_query.where(NetworkObservation.scope == scope)
    if indicator_type:
        query = query.where(NetworkObservation.indicator_type == indicator_type)
        count_query = count_query.where(NetworkObservation.indicator_type == indicator_type)

    total = (await session.execute(count_query)).scalar_one()
    rows = (
        (
            await session.execute(
                query.order_by(NetworkObservation.occurrences.desc())
                .limit(page.limit)
                .offset(page.offset)
            )
        )
        .scalars()
        .all()
    )
    return Page[IndicatorOut](
        items=[IndicatorOut.model_validate(row) for row in rows],
        total=int(total),
        limit=page.limit,
        offset=page.offset,
    )


@router.get(
    "/scans/{scan_id}/artifacts",
    response_model=list[ArtifactOut],
    summary="Artifacts produced by a scan",
)
async def list_artifacts(
    scan_id: str, session: AsyncSession = Depends(session_dependency)
) -> list[ArtifactOut]:
    await _require_scan(session, scan_id)
    rows = (
        (await session.execute(select(ScanArtifact).where(ScanArtifact.scan_id == scan_id)))
        .scalars()
        .all()
    )
    return [ArtifactOut.model_validate(row) for row in rows]


@router.get(
    "/scans/{scan_id}/tree",
    response_model=SourceTreeResponse,
    summary="Browse the decompiled source tree",
)
async def source_tree(
    scan_id: str,
    artifact: str = Query(default="decompiled-sources"),
    prefix: str = Query(default="", description="Limit the listing to this subtree"),
    limit: int = Query(default=5000, ge=1, le=50000),
    session: AsyncSession = Depends(session_dependency),
    store: ArtifactStore = Depends(store_dependency),
) -> SourceTreeResponse:
    await _require_scan(session, scan_id)
    if artifact not in BROWSABLE_ARTIFACTS:
        raise ValidationError(
            f"artifact {artifact!r} is not browsable; expected one of "
            + ", ".join(sorted(BROWSABLE_ARTIFACTS))
        )
    row = await _artifact_row(session, scan_id, artifact)

    # Prefer the precomputed index when it matches the requested artifact.
    entries: list[dict[str, Any]] = []
    if artifact == "decompiled-sources":
        index_row = await _artifact_row(session, scan_id, "source-tree-index", required=False)
        if index_row is not None and store.exists(index_row.storage_key):
            entries = json.loads(store.read_text(index_row.storage_key)).get("entries", [])

    if not entries:
        entries = _walk(store.path_for(row.storage_key), limit=limit)

    if prefix:
        normalised = prefix.strip("/")
        entries = [e for e in entries if e["path"].startswith(normalised)]

    truncated = len(entries) > limit
    return SourceTreeResponse(
        scan_id=scan_id,
        artifact=artifact,
        entries=[TreeEntry(**entry) for entry in entries[:limit]],
        truncated=truncated,
    )


@router.get(
    "/scans/{scan_id}/file",
    response_model=SourceFileResponse,
    summary="Read one file from a scan artifact",
)
async def source_file(
    scan_id: str,
    path: str = Query(..., description="Path relative to the artifact root"),
    artifact: str = Query(default="decompiled-sources"),
    session: AsyncSession = Depends(session_dependency),
    store: ArtifactStore = Depends(store_dependency),
) -> SourceFileResponse:
    await _require_scan(session, scan_id)
    if artifact not in BROWSABLE_ARTIFACTS:
        raise ValidationError(f"artifact {artifact!r} is not browsable")
    row = await _artifact_row(session, scan_id, artifact)

    root = store.path_for(row.storage_key)
    # Resolve and re-check: a crafted ../ path must not escape the artifact.
    candidate = (root / path.lstrip("/")).resolve()
    if root not in candidate.parents and candidate != root:
        raise ValidationError("the requested path is outside the artifact")
    if not candidate.is_file():
        raise NotFoundError(f"{path} is not a file in this artifact")

    size = candidate.stat().st_size
    truncated = size > MAX_SOURCE_FILE_BYTES
    with open(candidate, "rb") as handle:
        raw = handle.read(MAX_SOURCE_FILE_BYTES)
    content = raw.decode("utf-8", errors="replace")

    findings = (
        (
            await session.execute(
                select(Finding).where(
                    Finding.scan_id == scan_id, Finding.file_path.ilike(f"%{path.lstrip('/')}")
                )
            )
        )
        .scalars()
        .all()
    )

    return SourceFileResponse(
        path=path,
        language=_language_for(candidate.suffix),
        content=content,
        size_bytes=size,
        truncated=truncated,
        findings=[FindingSummary.model_validate(f) for f in findings],
    )


@router.get(
    "/scans/{scan_id}/export",
    summary="Export the full scan result as JSON",
    response_class=StreamingResponse,
)
async def export_scan(
    scan_id: str,
    session: AsyncSession = Depends(session_dependency),
) -> StreamingResponse:
    from app.reports.builder import build_report_document

    scan = await _require_scan(session, scan_id)
    document = await build_report_document(session, scan.id)
    payload = json.dumps(document, indent=2, default=str)
    return StreamingResponse(
        iter([payload.encode()]),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="droidscope-{scan_id[:12]}.json"'
        },
    )


# --- findings ---------------------------------------------------------------
findings_router = APIRouter(prefix="/findings", tags=["findings"])


@findings_router.get("/{finding_id}", response_model=FindingDetail, summary="Get a finding")
async def get_finding(
    finding_id: str, session: AsyncSession = Depends(session_dependency)
) -> FindingDetail:
    result = await session.execute(
        select(Finding)
        .where(Finding.id == finding_id)
        .options(selectinload(Finding.evidence), selectinload(Finding.reviews))
    )
    finding = result.scalar_one_or_none()
    if finding is None:
        raise NotFoundError(f"finding {finding_id} does not exist")
    return FindingDetail.model_validate(finding)


@findings_router.patch(
    "/{finding_id}/review",
    response_model=FindingDetail,
    summary="Record a triage decision",
)
async def review_finding(
    request: Request,
    finding_id: str,
    payload: FindingReviewRequest,
    session: AsyncSession = Depends(session_dependency),
    _auth: str = Depends(require_api_key),
) -> FindingDetail:
    result = await session.execute(
        select(Finding)
        .where(Finding.id == finding_id)
        .options(selectinload(Finding.evidence), selectinload(Finding.reviews))
    )
    finding = result.scalar_one_or_none()
    if finding is None:
        raise NotFoundError(f"finding {finding_id} does not exist")

    previous = finding.status
    finding.status = payload.status
    session.add(
        FindingReview(
            finding_id=finding.id,
            previous_status=previous,
            new_status=payload.status,
            note=payload.note,
            reviewer=payload.reviewer or actor_from(request),
        )
    )
    await session.commit()
    await session.refresh(finding, attribute_names=["reviews", "evidence"])
    logger.info(
        "finding.reviewed",
        finding_id=finding_id,
        previous=previous.value,
        new=payload.status.value,
    )
    return FindingDetail.model_validate(finding)


# --- helpers ----------------------------------------------------------------
def _ordering(sort: str):  # noqa: ANN202
    if sort == "severity":
        # SQL cannot order by the semantic rank of a string column directly, so
        # order by a CASE expression that encodes it.
        from sqlalchemy import case

        ranking = case(
            {
                Severity.critical.value: 5,
                Severity.high.value: 4,
                Severity.medium.value: 3,
                Severity.low.value: 2,
                Severity.info.value: 1,
            },
            value=Finding.severity,
            else_=0,
        )
        return (ranking.desc(), Finding.rule_id.asc())
    if sort == "created_at":
        return (Finding.created_at.desc(),)
    if sort == "title":
        return (Finding.title.asc(),)
    return (Finding.rule_id.asc(),)


async def _require_scan(session: AsyncSession, scan_id: str) -> Scan:
    scan = await session.get(Scan, scan_id)
    if scan is None:
        raise NotFoundError(f"scan {scan_id} does not exist")
    return scan


async def _artifact_row(
    session: AsyncSession, scan_id: str, kind: str, *, required: bool = True
) -> ScanArtifact:
    row = (
        await session.execute(
            select(ScanArtifact).where(
                ScanArtifact.scan_id == scan_id, ScanArtifact.kind == kind
            )
        )
    ).scalar_one_or_none()
    if row is None and required:
        raise NotFoundError(
            f"this scan has no {kind!r} artifact; the analyzer that produces it did "
            "not run or did not complete"
        )
    return row  # type: ignore[return-value]


async def _scan_summary(session: AsyncSession, scan: Scan) -> ScanSummary:
    apk = await session.get(ApkArtifact, scan.apk_id)
    return ScanSummary(
        id=scan.id,
        apk_id=scan.apk_id,
        profile=scan.profile,
        status=scan.status,
        progress=scan.progress,
        stage=scan.stage,
        created_at=scan.created_at,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        duration_seconds=scan.duration_seconds,
        findings_total=scan.findings_total,
        severity_counts=scan.severity_counts or {},
        error=scan.error,
        package_name=apk.package_name if apk else None,
        app_label=apk.app_label if apk else None,
    )


def _walk(root, *, limit: int) -> list[dict[str, Any]]:  # noqa: ANN001
    entries: list[dict[str, Any]] = []
    if not root.is_dir():
        return entries
    for path in sorted(root.rglob("*")):
        if len(entries) >= limit:
            break
        if path.is_symlink():
            continue
        relative = str(path.relative_to(root))
        if path.is_dir():
            entries.append({"path": relative, "type": "directory", "size": 0})
        elif path.is_file():
            entries.append(
                {
                    "path": relative,
                    "type": "file",
                    "size": path.stat().st_size,
                    "language": _language_for(path.suffix),
                }
            )
    return entries


def _language_for(suffix: str) -> str:
    return {
        ".java": "java",
        ".kt": "kotlin",
        ".smali": "smali",
        ".xml": "xml",
        ".json": "json",
        ".properties": "properties",
        ".txt": "plaintext",
        ".js": "javascript",
        ".html": "html",
    }.get(suffix.lower(), "plaintext")
