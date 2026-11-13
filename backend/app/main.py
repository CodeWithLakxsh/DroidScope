"""DroidScope FastAPI application."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import __version__
from app.api.v1 import apks, dynamic, health, misc, reports, scans
from app.core.config import get_settings
from app.core.errors import DroidScopeError
from app.core.logging import configure_logging, get_logger
from app.database.session import create_all, dispose_engine
from app.detection.registry import load_builtin_rules, registry

logger = get_logger(__name__)

DESCRIPTION = """
DroidScope analyses Android application packages and produces evidence-backed
security findings.

**What this API does**

* validates and stores uploaded APKs, rejecting hostile archives;
* runs static analysis profiles in a background worker;
* returns findings with supporting evidence, CWE and OWASP MASVS mappings, and
  an explainable application risk summary;
* generates PDF, HTML, JSON and SARIF reports.

**What it does not do**

* contact endpoints extracted from an application;
* execute an uploaded APK on the host;
* run dynamic analysis unless it is explicitly enabled and authorised per session.
"""


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings)
    settings.ensure_directories()
    await create_all()
    load_builtin_rules()
    logger.info(
        "application.started",
        version=__version__,
        environment=settings.environment.value,
        rules=len(registry),
        data_dir=str(settings.data_dir),
    )
    yield
    await dispose_engine()
    logger.info("application.stopped")


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="DroidScope",
        description=DESCRIPTION,
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        contact={"name": "DroidScope", "url": "https://github.com/droidscope/droidscope"},
        license_info={"name": "Apache-2.0", "url": "https://www.apache.org/licenses/LICENSE-2.0"},
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "X-API-Key", "X-DroidScope-Actor"],
        max_age=600,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):  # noqa: ANN001, ANN202
        started = time.perf_counter()
        response = await call_next(request)
        duration_ms = (time.perf_counter() - started) * 1000
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Response-Time-Ms"] = f"{duration_ms:.1f}"
        if request.url.path.startswith("/api"):
            response.headers["Cache-Control"] = "no-store"
        return response

    _register_exception_handlers(app)

    prefix = settings.api_prefix
    app.include_router(health.router, prefix=prefix)
    app.include_router(apks.router, prefix=prefix)
    app.include_router(scans.router, prefix=prefix)
    app.include_router(scans.findings_router, prefix=prefix)
    app.include_router(reports.router, prefix=prefix)
    app.include_router(dynamic.router, prefix=prefix)
    app.include_router(misc.router, prefix=prefix)

    @app.get("/", include_in_schema=False)
    async def root() -> dict:
        return {
            "name": "DroidScope",
            "version": __version__,
            "documentation": "/docs",
            "api": prefix,
        }

    return app


def _register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(DroidScopeError)
    async def handle_domain_error(request: Request, exc: DroidScopeError) -> JSONResponse:
        if exc.http_status >= 500:
            logger.error(
                "api.error", code=exc.code, message=exc.message, path=request.url.path
            )
        else:
            logger.info(
                "api.rejected", code=exc.code, message=exc.message, path=request.url.path
            )
        return JSONResponse(
            status_code=exc.http_status,
            content={
                "error": {"code": exc.code, "message": exc.message, "details": exc.details}
            },
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "request_validation_error",
                    "message": "the request did not match the expected schema",
                    "details": {"errors": exc.errors()[:20]},
                }
            },
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_exception(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": f"http_{exc.status_code}",
                    "message": str(exc.detail),
                    "details": {},
                }
            },
        )

    @app.exception_handler(Exception)
    async def handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
        # Never leak an internal path or stack trace to a client.
        logger.exception("api.unhandled", path=request.url.path)
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "internal_error",
                    "message": "an unexpected error occurred; see the server logs",
                    "details": {},
                }
            },
        )


app = create_app()
