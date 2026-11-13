"""Health, capability and rule metadata endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app import __version__
from app.analyzers.registry import PROFILE_DESCRIPTIONS, all_analyzers
from app.api.deps import session_dependency, settings_dependency
from app.core.capabilities import analyzer_availability, collect_capabilities
from app.core.config import Settings
from app.database.session import healthcheck
from app.detection.registry import load_builtin_rules, registry
from app.jobs.queue import JobQueue
from app.schemas.api import (
    CapabilitiesResponse,
    CapabilityOut,
    HealthResponse,
    RuleOut,
)

router = APIRouter(tags=["system"])


@router.get("/health", response_model=HealthResponse, summary="Service health")
async def health(session: AsyncSession = Depends(session_dependency)) -> HealthResponse:
    database_ok = await healthcheck()
    pending: int | None = None
    if database_ok:
        try:
            pending = await JobQueue(session).pending_count()
        except Exception:  # noqa: BLE001 - health must not fail on a counting error
            pending = None
    return HealthResponse(
        status="ok" if database_ok else "degraded",
        database=database_ok,
        version=__version__,
        queue_pending=pending,
    )


@router.get(
    "/capabilities",
    response_model=CapabilitiesResponse,
    summary="Installed tooling and what it enables",
)
async def capabilities(
    settings: Settings = Depends(settings_dependency),
) -> CapabilitiesResponse:
    discovered = await collect_capabilities(settings)
    caps = {cap.name: cap for cap in discovered}
    load_builtin_rules()
    return CapabilitiesResponse(
        capabilities=[CapabilityOut(**cap.public_dict()) for cap in discovered],
        analyzers=analyzer_availability(caps),
        profiles={
            profile.value: description
            for profile, description in PROFILE_DESCRIPTIONS.items()
        },
        rules_loaded=len(registry),
        version=__version__,
    )


@router.get("/analyzers", summary="Analyzers and the profiles that include them")
async def analyzers() -> list[dict]:
    return [
        {
            "name": analyzer.name,
            "version": analyzer.version,
            "description": analyzer.description,
            "required_capabilities": list(analyzer.required_capabilities),
            "profiles": [profile.value for profile in analyzer.profiles],
        }
        for analyzer in all_analyzers()
    ]


@router.get("/rules", response_model=list[RuleOut], summary="Loaded detection rules")
async def rules() -> list[RuleOut]:
    load_builtin_rules()
    return [
        RuleOut(
            id=meta.id,
            name=meta.name,
            description=meta.description,
            category=meta.category.value,
            severity=meta.severity,
            confidence=meta.confidence,
            engine=meta.engine,
            version=meta.version,
            cwe_ids=meta.cwe_ids,
            masvs_controls=meta.masvs_controls,
            references=meta.references,
            enabled=registry.is_enabled(meta.id),
        )
        for meta in sorted(registry.metadata(), key=lambda m: m.id)
    ]
