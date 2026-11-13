"""Shared API dependencies: sessions, auth, pagination."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass

from fastapi import Depends, Header, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.errors import AuthorizationError
from app.database.session import get_session
from app.storage.artifacts import ArtifactStore, get_artifact_store


async def session_dependency() -> AsyncIterator[AsyncSession]:
    async for session in get_session():
        yield session


def settings_dependency() -> Settings:
    return get_settings()


def store_dependency() -> ArtifactStore:
    return get_artifact_store()


@dataclass(slots=True)
class Pagination:
    limit: int
    offset: int


def pagination(
    limit: int = Query(default=50, ge=1, le=500, description="Maximum items to return"),
    offset: int = Query(default=0, ge=0, description="Items to skip"),
) -> Pagination:
    return Pagination(limit=limit, offset=offset)


async def require_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    settings: Settings = Depends(settings_dependency),
) -> str:
    """Authenticate a mutating request when the deployment requires it.

    A single-user local install runs without authentication; a shared
    deployment sets DROIDSCOPE_API_KEY and DROIDSCOPE_REQUIRE_AUTH.
    """
    if not settings.require_auth:
        return "local"
    expected = settings.api_key
    if not expected:
        raise AuthorizationError(
            "authentication is required but no API key is configured on the server"
        )
    if not x_api_key or not _constant_time_equals(x_api_key, expected):
        raise AuthorizationError("a valid X-API-Key header is required")
    return "api-key"


def _constant_time_equals(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left.encode(), right.encode())


def actor_from(request: Request) -> str:
    """Identify the caller for audit records without storing personal data."""
    return request.headers.get("X-DroidScope-Actor", "local")[:128]
