"""API request and response schemas.

These are the public contract.  They deliberately never expose internal
filesystem paths or storage keys: a client refers to artifacts by scan id and
artifact kind, and the server resolves the location.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import (
    AnalyzerStatus,
    Confidence,
    FindingStatus,
    JobStatus,
    ReportFormat,
    ScanProfile,
    Severity,
)

T = TypeVar("T")


class ApiModel(BaseModel):
    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        # Responses use the serialization aliases, so clients see "metadata"
        # and "format" rather than the internal column names.
        serialize_by_alias=True,
    )


class ErrorDetail(ApiModel):
    code: str = Field(description="Stable machine-readable error code")
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class ErrorResponse(ApiModel):
    error: ErrorDetail


class Page[T](ApiModel):
    items: list[T]
    total: int
    limit: int
    offset: int

    @property
    def has_more(self) -> bool:
        return self.offset + len(self.items) < self.total


# --- capabilities -----------------------------------------------------------
class CapabilityOut(ApiModel):
    name: str
    available: bool
    kind: str
    version: str | None = None
    detail: str | None = None
    install_hint: str | None = None
    required_for: list[str] = Field(default_factory=list)
    optional: bool = True


class CapabilitiesResponse(ApiModel):
    capabilities: list[CapabilityOut]
    analyzers: dict[str, bool]
    profiles: dict[str, str]
    rules_loaded: int
    version: str


class HealthResponse(ApiModel):
    status: Literal["ok", "degraded"]
    database: bool
    version: str
    queue_pending: int | None = None


# --- APKs -------------------------------------------------------------------
class CertificateOut(ApiModel):
    subject: str | None = None
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    signature_algorithm: str | None = None
    public_key_algorithm: str | None = None
    key_size_bits: int | None = None
    sha256_fingerprint: str | None = None
    is_self_signed: bool | None = None


class ApkSummary(ApiModel):
    id: str
    sha256: str
    file_size: int
    original_filename: str
    package_name: str | None = None
    app_label: str | None = None
    version_name: str | None = None
    version_code: int | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    created_at: datetime
    has_icon: bool = False
    scan_count: int = 0
    latest_scan_id: str | None = None
    latest_scan_status: JobStatus | None = None


class ApkDetail(ApkSummary):
    sha1: str | None = None
    md5: str | None = None
    compile_sdk: int | None = None
    metadata_error: str | None = None
    validation: dict[str, Any] = Field(default_factory=dict)
    apk_metadata: dict[str, Any] = Field(default_factory=dict)


class ApkUploadResponse(ApiModel):
    apk: ApkDetail
    created: bool = Field(description="False when an APK with the same SHA-256 was already stored")
    message: str


# --- scans ------------------------------------------------------------------
class ScanCreateRequest(ApiModel):
    apk_id: str
    profile: ScanProfile = ScanProfile.standard
    config: dict[str, Any] = Field(default_factory=dict)
    reuse_existing: bool | None = Field(
        default=None,
        description="Reuse a completed scan with identical inputs. Defaults to the server setting.",
    )


class AnalyzerExecutionOut(ApiModel):
    analyzer: str
    analyzer_version: str
    status: AnalyzerStatus
    duration_seconds: float | None = None
    findings_count: int
    error: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)


class ScanSummary(ApiModel):
    id: str
    apk_id: str
    profile: ScanProfile
    status: JobStatus
    progress: float
    stage: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_seconds: float | None = None
    findings_total: int
    severity_counts: dict[str, int] = Field(default_factory=dict)
    error: str | None = None
    package_name: str | None = None
    app_label: str | None = None


class ScanDetail(ScanSummary):
    risk: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    environment: dict[str, Any] = Field(default_factory=dict)
    config: dict[str, Any] = Field(default_factory=dict)
    executions: list[AnalyzerExecutionOut] = Field(default_factory=list)
    artifacts: list[str] = Field(default_factory=list)


class ScanCreateResponse(ApiModel):
    scan: ScanSummary
    reused: bool
    message: str


# --- findings ---------------------------------------------------------------
class EvidenceOut(ApiModel):
    kind: str
    description: str
    snippet: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    sensitive: bool = False
    # Present only when the value was retained; masked output is the default.
    value_fingerprint: str | None = None
    # serialization_alias only: a plain alias="metadata" would make Pydantic read
    # SQLAlchemy's reserved MetaData attribute off the ORM row instead of this
    # column, which fails validation.
    evidence_metadata: dict[str, Any] = Field(default_factory=dict, serialization_alias="metadata")


class FindingReviewOut(ApiModel):
    previous_status: FindingStatus
    new_status: FindingStatus
    note: str | None = None
    reviewer: str | None = None
    created_at: datetime


class FindingSummary(ApiModel):
    id: str
    scan_id: str
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    category: str
    status: FindingStatus
    analysis_engine: str
    affected_component: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    masvs_controls: list[str] = Field(default_factory=list)


class FindingDetail(FindingSummary):
    description: str
    impact: str
    remediation: str
    verification: str | None = None
    limitations: str | None = None
    references: list[str] = Field(default_factory=list)
    rule_version: str
    fingerprint: str
    created_at: datetime
    evidence: list[EvidenceOut] = Field(default_factory=list)
    reviews: list[FindingReviewOut] = Field(default_factory=list)
    finding_metadata: dict[str, Any] = Field(default_factory=dict, serialization_alias="metadata")


class FindingReviewRequest(ApiModel):
    status: FindingStatus
    note: str | None = Field(default=None, max_length=4000)
    reviewer: str | None = Field(default=None, max_length=128)


# --- indicators -------------------------------------------------------------
class IndicatorOut(ApiModel):
    id: str
    indicator_type: str
    value: str
    scope: str
    scheme: str | None = None
    host: str | None = None
    port: int | None = None
    source: str
    source_file: str | None = None
    context: str | None = None
    occurrences: int


# --- artifacts and code browsing -------------------------------------------
class ArtifactOut(ApiModel):
    kind: str
    size_bytes: int
    entry_count: int
    produced_by: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)


class TreeEntry(ApiModel):
    path: str
    type: Literal["file", "directory"]
    size: int = 0
    language: str | None = None


class SourceTreeResponse(ApiModel):
    scan_id: str
    artifact: str
    entries: list[TreeEntry]
    truncated: bool = False


class SourceFileResponse(ApiModel):
    path: str
    language: str
    content: str
    size_bytes: int
    truncated: bool = False
    findings: list[FindingSummary] = Field(default_factory=list)


# --- comparison -------------------------------------------------------------
class CompareRequest(ApiModel):
    baseline_apk_id: str
    updated_apk_id: str
    baseline_scan_id: str | None = None
    updated_scan_id: str | None = None


class CompareResponse(ApiModel):
    id: str
    baseline_apk_id: str
    updated_apk_id: str
    summary: dict[str, Any]
    result: dict[str, Any]
    created_at: datetime


# --- reports ----------------------------------------------------------------
class ReportCreateRequest(ApiModel):
    scan_id: str
    report_format: ReportFormat = Field(default=ReportFormat.pdf, alias="format")
    include_evidence: bool = True
    redact_secrets: bool | None = None
    include_informational: bool = True


class ReportOut(ApiModel):
    id: str
    scan_id: str
    report_format: ReportFormat = Field(serialization_alias="format")
    status: JobStatus
    filename: str | None = None
    size_bytes: int | None = None
    sha256: str | None = None
    error: str | None = None
    created_at: datetime
    completed_at: datetime | None = None


# --- devices and dynamic analysis ------------------------------------------
class DeviceOut(ApiModel):
    serial: str
    state: str
    is_emulator: bool
    model: str | None = None
    manufacturer: str | None = None
    android_version: str | None = None
    sdk_int: int | None = None
    abi: str | None = None
    rooted: bool | None = None
    frida_server_running: bool | None = None
    notes: list[str] = Field(default_factory=list)


class DeviceListResponse(ApiModel):
    devices: list[DeviceOut]
    adb_available: bool
    frida_available: bool
    emulator_available: bool
    message: str | None = None


class DynamicSessionCreateRequest(ApiModel):
    apk_id: str
    device_serial: str
    modules: list[str] = Field(default_factory=list)
    duration_seconds: int = Field(default=120, ge=10, le=3600)
    # Explicit, per-session authorisation. The server refuses without it.
    authorised: bool = Field(
        default=False,
        description=(
            "Must be true. Confirms you are authorised to install and execute this "
            "application on the selected device."
        ),
    )


class RuntimeEventOut(ApiModel):
    id: str
    observed_at: datetime
    event_type: str
    module: str
    process: str | None = None
    api: str | None = None
    severity: str | None = None
    summary: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)


class DynamicSessionOut(ApiModel):
    id: str
    apk_id: str
    device_serial: str
    status: str
    modules: list[str] = Field(default_factory=list)
    device_info: dict[str, Any] = Field(default_factory=dict)
    capability_report: dict[str, Any] = Field(default_factory=dict)
    events_count: int
    error: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    stopped_at: datetime | None = None


# --- settings ---------------------------------------------------------------
class SettingsOut(ApiModel):
    analysis_concurrency: int
    max_upload_bytes: int
    analyzer_timeout_seconds: int
    scan_timeout_seconds: int
    decompile_timeout_seconds: int
    artifact_retention_days: int
    reuse_identical_scans: bool
    redact_secrets_in_reports: bool
    dynamic_analysis_enabled: bool
    dynamic_allow_physical_devices: bool
    log_level: str
    # Tool locations are reported as availability only; paths are never exposed
    # and cannot be set through the API.
    tools: dict[str, bool] = Field(default_factory=dict)


class SettingsUpdateRequest(ApiModel):
    analysis_concurrency: int | None = Field(default=None, ge=1, le=16)
    analyzer_timeout_seconds: int | None = Field(default=None, ge=30, le=7200)
    decompile_timeout_seconds: int | None = Field(default=None, ge=30, le=7200)
    artifact_retention_days: int | None = Field(default=None, ge=1, le=3650)
    reuse_identical_scans: bool | None = None
    redact_secrets_in_reports: bool | None = None
    dynamic_analysis_enabled: bool | None = None
    dynamic_allow_physical_devices: bool | None = None


class RuleOut(ApiModel):
    id: str
    name: str
    description: str
    category: str
    severity: Severity
    confidence: Confidence
    engine: str
    version: str
    cwe_ids: list[str] = Field(default_factory=list)
    masvs_controls: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    enabled: bool = True
