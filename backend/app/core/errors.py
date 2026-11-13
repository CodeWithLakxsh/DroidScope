"""Domain errors.

Errors raised by the service and analyzer layers are translated into structured
API responses by the FastAPI exception handlers.  Messages must never contain
absolute host filesystem paths.
"""

from __future__ import annotations


class DroidScopeError(Exception):
    """Base error for all application specific failures."""

    code = "internal_error"
    http_status = 500

    def __init__(self, message: str, *, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ValidationError(DroidScopeError):
    code = "validation_error"
    http_status = 422


class NotFoundError(DroidScopeError):
    code = "not_found"
    http_status = 404


class ConflictError(DroidScopeError):
    code = "conflict"
    http_status = 409


class AuthorizationError(DroidScopeError):
    code = "forbidden"
    http_status = 403


class ApkValidationError(ValidationError):
    """The uploaded file is not a usable APK, or is hostile."""

    code = "apk_validation_error"
    http_status = 400


class ArchiveSecurityError(ApkValidationError):
    """The archive violates an archive safety limit."""

    code = "archive_security_error"


class ToolUnavailableError(DroidScopeError):
    """A required external tool is not installed or not usable."""

    code = "tool_unavailable"
    http_status = 503


class AnalyzerError(DroidScopeError):
    code = "analyzer_error"


class AnalyzerTimeout(AnalyzerError):
    code = "analyzer_timeout"


class CapabilityUnavailableError(DroidScopeError):
    """The requested capability is not available in this deployment."""

    code = "capability_unavailable"
    http_status = 503
