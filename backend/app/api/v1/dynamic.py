"""Device discovery and dynamic analysis endpoints."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.analyzers.dynamic.devices import DeviceManager
from app.analyzers.dynamic.frida_scripts import describe_modules
from app.analyzers.dynamic.session import DynamicAnalysisService
from app.api.deps import (
    Pagination,
    actor_from,
    pagination,
    require_api_key,
    session_dependency,
    settings_dependency,
)
from app.core.config import Settings
from app.core.enums import SessionStatus
from app.core.errors import NotFoundError
from app.core.logging import get_logger
from app.core.process import resolve_executable
from app.models import DynamicSession, RuntimeEvent
from app.schemas.api import (
    DeviceListResponse,
    DeviceOut,
    DynamicSessionCreateRequest,
    DynamicSessionOut,
    Page,
    RuntimeEventOut,
)

logger = get_logger(__name__)
router = APIRouter(tags=["dynamic analysis"])


@router.get("/devices", response_model=DeviceListResponse, summary="List connected devices")
async def list_devices(settings: Settings = Depends(settings_dependency)) -> DeviceListResponse:
    manager = DeviceManager(settings)
    devices, messages = await manager.list_devices()
    return DeviceListResponse(
        devices=[DeviceOut(**device.to_dict()) for device in devices],
        adb_available=manager.adb_path() is not None,
        frida_available=resolve_executable(settings.frida_path, names=("frida",)) is not None,
        emulator_available=resolve_executable(None, names=("emulator",)) is not None,
        message=" ".join(messages) if messages else None,
    )


@router.get("/dynamic/modules", summary="Available instrumentation modules")
async def instrumentation_modules() -> dict:
    return {
        "modules": describe_modules(),
        "note": (
            "All modules are observational. DroidScope does not ship modules that "
            "bypass certificate validation, root detection or biometric checks."
        ),
    }


@router.post(
    "/dynamic/sessions",
    response_model=DynamicSessionOut,
    status_code=201,
    summary="Create a dynamic analysis session",
    description=(
        "Installs and runs the application on an explicitly selected device. Requires "
        "dynamic analysis to be enabled on the server and an explicit authorisation "
        "flag in the request."
    ),
)
async def create_session(
    request: Request,
    payload: DynamicSessionCreateRequest,
    session: AsyncSession = Depends(session_dependency),
    settings: Settings = Depends(settings_dependency),
    _auth: str = Depends(require_api_key),
) -> DynamicSessionOut:
    service = DynamicAnalysisService(session, settings=settings)
    row = await service.create_session(
        apk_id=payload.apk_id,
        device_serial=payload.device_serial,
        modules=payload.modules or None,
        duration_seconds=payload.duration_seconds,
        authorised=payload.authorised,
        actor=actor_from(request),
    )
    # The session runs in the background; the client polls for completion.
    asyncio.create_task(_run_session_background(row.id, settings))
    return DynamicSessionOut.model_validate(row)


async def _run_session_background(session_id: str, settings: Settings) -> None:
    from app.database.session import session_scope

    try:
        async with session_scope(settings) as session:
            await DynamicAnalysisService(session, settings=settings).run_session(session_id)
    except Exception as exc:  # noqa: BLE001
        logger.exception("dynamic.background_failed", session_id=session_id, error=str(exc))


@router.get(
    "/dynamic/sessions",
    response_model=Page[DynamicSessionOut],
    summary="List dynamic analysis sessions",
)
async def list_sessions(
    page: Pagination = Depends(pagination),
    apk_id: str | None = Query(default=None),
    session: AsyncSession = Depends(session_dependency),
) -> Page[DynamicSessionOut]:
    from sqlalchemy import func

    query = select(DynamicSession).order_by(DynamicSession.created_at.desc())
    count_query = select(func.count()).select_from(DynamicSession)
    if apk_id:
        query = query.where(DynamicSession.apk_id == apk_id)
        count_query = count_query.where(DynamicSession.apk_id == apk_id)

    total = (await session.execute(count_query)).scalar_one()
    rows = (await session.execute(query.limit(page.limit).offset(page.offset))).scalars().all()
    return Page[DynamicSessionOut](
        items=[DynamicSessionOut.model_validate(row) for row in rows],
        total=int(total),
        limit=page.limit,
        offset=page.offset,
    )


@router.get(
    "/dynamic/sessions/{session_id}",
    response_model=DynamicSessionOut,
    summary="Get a dynamic analysis session",
)
async def get_session(
    session_id: str, session: AsyncSession = Depends(session_dependency)
) -> DynamicSessionOut:
    row = await session.get(DynamicSession, session_id)
    if row is None:
        raise NotFoundError(f"session {session_id} does not exist")
    return DynamicSessionOut.model_validate(row)


@router.post(
    "/dynamic/sessions/{session_id}/stop",
    response_model=DynamicSessionOut,
    summary="Stop a running session",
)
async def stop_session(
    session_id: str,
    session: AsyncSession = Depends(session_dependency),
    _auth: str = Depends(require_api_key),
) -> DynamicSessionOut:
    row = await session.get(DynamicSession, session_id)
    if row is None:
        raise NotFoundError(f"session {session_id} does not exist")
    if row.status in {SessionStatus.stopped, SessionStatus.failed}:
        return DynamicSessionOut.model_validate(row)
    row.status = SessionStatus.stopping
    await session.commit()
    return DynamicSessionOut.model_validate(row)


@router.get(
    "/dynamic/sessions/{session_id}/events",
    response_model=Page[RuntimeEventOut],
    summary="Runtime events captured during a session",
)
async def session_events(
    session_id: str,
    page: Pagination = Depends(pagination),
    event_type: str | None = Query(default=None),
    search: str | None = Query(default=None),
    session: AsyncSession = Depends(session_dependency),
) -> Page[RuntimeEventOut]:
    from sqlalchemy import func

    row = await session.get(DynamicSession, session_id)
    if row is None:
        raise NotFoundError(f"session {session_id} does not exist")

    query = select(RuntimeEvent).where(RuntimeEvent.session_id == session_id)
    count_query = (
        select(func.count()).select_from(RuntimeEvent).where(RuntimeEvent.session_id == session_id)
    )
    if event_type:
        query = query.where(RuntimeEvent.event_type == event_type)
        count_query = count_query.where(RuntimeEvent.event_type == event_type)
    if search:
        pattern = f"%{search}%"
        condition = RuntimeEvent.summary.ilike(pattern) | RuntimeEvent.api.ilike(pattern)
        query = query.where(condition)
        count_query = count_query.where(condition)

    total = (await session.execute(count_query)).scalar_one()
    rows = (
        (
            await session.execute(
                query.order_by(RuntimeEvent.observed_at).limit(page.limit).offset(page.offset)
            )
        )
        .scalars()
        .all()
    )
    return Page[RuntimeEventOut](
        items=[RuntimeEventOut.model_validate(r) for r in rows],
        total=int(total),
        limit=page.limit,
        offset=page.offset,
    )
