"""SQLAlchemy ORM models.

Design notes
------------
* Large artifacts (decompiled sources, decoded resources, extracted binaries)
  are *never* stored in table rows.  ``ScanArtifact`` records a logical key that
  the artifact store resolves to a path on disk.
* Findings carry a ``fingerprint`` that is stable across scans so that the diff
  engine can correlate "same issue" without relying on line numbers.
* Secret evidence stores a mask plus a salted fingerprint; the plaintext is only
  persisted when a deployment explicitly opts in.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import (
    AnalyzerStatus,
    Confidence,
    FindingStatus,
    JobStatus,
    ReportFormat,
    ScanProfile,
    SessionStatus,
    Severity,
)
from app.database.base import Base, IdMixin, StrEnumType, TimestampMixin, utcnow


class Application(Base, IdMixin, TimestampMixin):
    """A logical Android application, identified by its package name."""

    __tablename__ = "applications"

    package_name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    label: Mapped[str | None] = mapped_column(String(255))

    apks: Mapped[list[ApkArtifact]] = relationship(
        back_populates="application", cascade="all, delete-orphan"
    )


class ApkArtifact(Base, IdMixin, TimestampMixin):
    """An uploaded APK file and the metadata extracted from it."""

    __tablename__ = "apk_artifacts"

    application_id: Mapped[str | None] = mapped_column(
        ForeignKey("applications.id", ondelete="SET NULL"), index=True
    )

    sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    sha1: Mapped[str | None] = mapped_column(String(40))
    md5: Mapped[str | None] = mapped_column(String(32))
    file_size: Mapped[int] = mapped_column(BigInteger)
    # Sanitised for display only; the stored object is keyed by sha256.
    original_filename: Mapped[str] = mapped_column(String(255))
    storage_key: Mapped[str] = mapped_column(String(512))

    package_name: Mapped[str | None] = mapped_column(String(255), index=True)
    app_label: Mapped[str | None] = mapped_column(String(255))
    version_name: Mapped[str | None] = mapped_column(String(128))
    version_code: Mapped[int | None] = mapped_column(BigInteger)
    min_sdk: Mapped[int | None] = mapped_column(Integer)
    target_sdk: Mapped[int | None] = mapped_column(Integer)
    compile_sdk: Mapped[int | None] = mapped_column(Integer)

    # Full normalised metadata document (components, permissions, certificates,
    # native libraries, dex entries ...).  Schema: app.schemas.apk.ApkMetadata
    apk_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    validation: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    icon_storage_key: Mapped[str | None] = mapped_column(String(512))
    metadata_error: Mapped[str | None] = mapped_column(Text)

    application: Mapped[Application | None] = relationship(back_populates="apks")
    scans: Mapped[list[Scan]] = relationship(back_populates="apk", cascade="all, delete-orphan")


class Scan(Base, IdMixin, TimestampMixin):
    """One analysis run over one APK with one configuration."""

    __tablename__ = "scans"

    apk_id: Mapped[str] = mapped_column(
        ForeignKey("apk_artifacts.id", ondelete="CASCADE"), index=True
    )
    profile: Mapped[ScanProfile] = mapped_column(
        StrEnumType(ScanProfile, 16), default=ScanProfile.standard
    )
    status: Mapped[JobStatus] = mapped_column(
        StrEnumType(JobStatus, 16), default=JobStatus.queued, index=True
    )
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    stage: Mapped[str | None] = mapped_column(String(128))

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_seconds: Mapped[float | None] = mapped_column(Float)

    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # Which analyzers were requested vs. actually executed, and tool versions.
    environment: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # Explainable risk summary (see app.services.risk).
    risk: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    limitations: Mapped[list[Any]] = mapped_column(JSON, default=list)

    error: Mapped[str | None] = mapped_column(Text)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    # sha256(apk sha256 + normalised config) -- used to reuse completed scans.
    dedup_key: Mapped[str] = mapped_column(String(64), index=True)

    findings_total: Mapped[int] = mapped_column(Integer, default=0)
    severity_counts: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    apk: Mapped[ApkArtifact] = relationship(back_populates="scans")
    findings: Mapped[list[Finding]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    executions: Mapped[list[AnalyzerExecution]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    artifacts: Mapped[list[ScanArtifact]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class AnalyzerExecution(Base, IdMixin):
    """Per-analyzer execution record: the audit trail of what actually ran."""

    __tablename__ = "analyzer_executions"

    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    analyzer: Mapped[str] = mapped_column(String(64))
    analyzer_version: Mapped[str] = mapped_column(String(32), default="1")
    status: Mapped[AnalyzerStatus] = mapped_column(StrEnumType(AnalyzerStatus, 16))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_seconds: Mapped[float | None] = mapped_column(Float)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="executions")


class Finding(Base, IdMixin, TimestampMixin):
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_scan_severity", "scan_id", "severity"),
        Index("ix_findings_fingerprint", "fingerprint"),
    )

    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    apk_id: Mapped[str] = mapped_column(
        ForeignKey("apk_artifacts.id", ondelete="CASCADE"), index=True
    )

    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    rule_version: Mapped[str] = mapped_column(String(16), default="1")
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(StrEnumType(Severity, 16), index=True)
    confidence: Mapped[Confidence] = mapped_column(StrEnumType(Confidence, 16), index=True)
    category: Mapped[str] = mapped_column(String(64), index=True)

    cwe_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    masvs_controls: Mapped[list[Any]] = mapped_column(JSON, default=list)
    references: Mapped[list[Any]] = mapped_column(JSON, default=list)

    affected_component: Mapped[str | None] = mapped_column(String(512))
    file_path: Mapped[str | None] = mapped_column(String(1024))
    line_number: Mapped[int | None] = mapped_column(Integer)

    impact: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text)
    verification: Mapped[str | None] = mapped_column(Text)
    limitations: Mapped[str | None] = mapped_column(Text)

    analysis_engine: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[FindingStatus] = mapped_column(
        StrEnumType(FindingStatus, 24), default=FindingStatus.open, index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(64))
    risk_contribution: Mapped[float] = mapped_column(Float, default=0.0)
    finding_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="findings")
    evidence: Mapped[list[FindingEvidence]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", order_by="FindingEvidence.position"
    )
    reviews: Mapped[list[FindingReview]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", order_by="FindingReview.created_at"
    )


class FindingEvidence(Base, IdMixin):
    __tablename__ = "finding_evidence"

    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True
    )
    position: Mapped[int] = mapped_column(Integer, default=0)
    kind: Mapped[str] = mapped_column(String(32), default="code")
    description: Mapped[str] = mapped_column(Text)
    # Already masked when ``sensitive`` is set.
    snippet: Mapped[str | None] = mapped_column(Text)
    file_path: Mapped[str | None] = mapped_column(String(1024))
    line_number: Mapped[int | None] = mapped_column(Integer)
    sensitive: Mapped[bool] = mapped_column(Boolean, default=False)
    value_fingerprint: Mapped[str | None] = mapped_column(String(64))
    raw_value: Mapped[str | None] = mapped_column(Text)
    evidence_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    finding: Mapped[Finding] = relationship(back_populates="evidence")


class FindingReview(Base, IdMixin):
    """Append-only review history for a finding's triage state."""

    __tablename__ = "finding_reviews"

    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True
    )
    previous_status: Mapped[FindingStatus] = mapped_column(StrEnumType(FindingStatus, 24))
    new_status: Mapped[FindingStatus] = mapped_column(StrEnumType(FindingStatus, 24))
    note: Mapped[str | None] = mapped_column(Text)
    reviewer: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )

    finding: Mapped[Finding] = relationship(back_populates="reviews")


class ScanArtifact(Base, IdMixin):
    """Pointer to a stored analysis artifact (decompiled tree, extracted file)."""

    __tablename__ = "scan_artifacts"
    __table_args__ = (UniqueConstraint("scan_id", "kind", name="uq_scan_artifacts_scan_id_kind"),)

    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(64))
    storage_key: Mapped[str] = mapped_column(String(512))
    size_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    entry_count: Mapped[int] = mapped_column(Integer, default=0)
    produced_by: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="artifacts")


class NetworkObservation(Base, IdMixin):
    """A network indicator extracted statically, or observed at runtime."""

    __tablename__ = "network_observations"

    scan_id: Mapped[str | None] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    session_id: Mapped[str | None] = mapped_column(
        ForeignKey("dynamic_sessions.id", ondelete="CASCADE"), index=True
    )
    indicator_type: Mapped[str] = mapped_column(String(24), index=True)  # url|domain|ip|endpoint
    value: Mapped[str] = mapped_column(String(2048))
    scheme: Mapped[str | None] = mapped_column(String(16))
    host: Mapped[str | None] = mapped_column(String(512), index=True)
    port: Mapped[int | None] = mapped_column(Integer)
    # public | private | loopback | link-local | documentation | reserved | unknown
    scope: Mapped[str] = mapped_column(String(24), default="unknown")
    source: Mapped[str] = mapped_column(String(32), default="static")
    source_file: Mapped[str | None] = mapped_column(String(1024))
    context: Mapped[str | None] = mapped_column(Text)
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DynamicSession(Base, IdMixin, TimestampMixin):
    __tablename__ = "dynamic_sessions"

    apk_id: Mapped[str] = mapped_column(
        ForeignKey("apk_artifacts.id", ondelete="CASCADE"), index=True
    )
    device_serial: Mapped[str] = mapped_column(String(128))
    device_info: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[SessionStatus] = mapped_column(
        StrEnumType(SessionStatus, 16), default=SessionStatus.created
    )
    modules: Mapped[list[Any]] = mapped_column(JSON, default=list)
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)
    pid: Mapped[int | None] = mapped_column(Integer)
    events_count: Mapped[int] = mapped_column(Integer, default=0)
    # Honest record of which instrumentation actually attached.
    capability_report: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    events: Mapped[list[RuntimeEvent]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )


class RuntimeEvent(Base, IdMixin):
    __tablename__ = "runtime_events"
    __table_args__ = (Index("ix_runtime_events_session_ts", "session_id", "observed_at"),)

    session_id: Mapped[str] = mapped_column(
        ForeignKey("dynamic_sessions.id", ondelete="CASCADE"), index=True
    )
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    event_type: Mapped[str] = mapped_column(String(48), index=True)
    module: Mapped[str] = mapped_column(String(48))
    process: Mapped[str | None] = mapped_column(String(255))
    api: Mapped[str | None] = mapped_column(String(512))
    severity: Mapped[str | None] = mapped_column(String(16))
    summary: Mapped[str | None] = mapped_column(Text)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    session: Mapped[DynamicSession] = relationship(back_populates="events")


class Report(Base, IdMixin):
    __tablename__ = "reports"

    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    report_format: Mapped[ReportFormat] = mapped_column(StrEnumType(ReportFormat, 8))
    status: Mapped[JobStatus] = mapped_column(StrEnumType(JobStatus, 16), default=JobStatus.queued)
    storage_key: Mapped[str | None] = mapped_column(String(512))
    filename: Mapped[str | None] = mapped_column(String(255))
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    sha256: Mapped[str | None] = mapped_column(String(64))
    options: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Comparison(Base, IdMixin):
    __tablename__ = "comparisons"

    baseline_apk_id: Mapped[str] = mapped_column(
        ForeignKey("apk_artifacts.id", ondelete="CASCADE"), index=True
    )
    updated_apk_id: Mapped[str] = mapped_column(
        ForeignKey("apk_artifacts.id", ondelete="CASCADE"), index=True
    )
    baseline_scan_id: Mapped[str | None] = mapped_column(String(32))
    updated_scan_id: Mapped[str | None] = mapped_column(String(32))
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Job(Base, IdMixin):
    """Durable job queue row.

    A database backed queue keeps local development dependency free while still
    surviving a worker restart; Redis is used for coordination in production.
    """

    __tablename__ = "jobs"
    __table_args__ = (Index("ix_jobs_status_available", "status", "available_at"),)

    job_type: Mapped[str] = mapped_column(String(48), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[JobStatus] = mapped_column(String(16), default=JobStatus.queued, index=True)
    priority: Mapped[int] = mapped_column(Integer, default=100)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=1)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    locked_by: Mapped[str | None] = mapped_column(String(128))
    locked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DetectionRuleState(Base):
    """Operator controlled state for a detection rule."""

    __tablename__ = "detection_rule_states"

    rule_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    rule_version: Mapped[str] = mapped_column(String(16), default="1")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    severity_override: Mapped[str | None] = mapped_column(String(16))
    notes: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class CapabilitySnapshot(Base, IdMixin):
    """Recorded tool availability at the time of a scan."""

    __tablename__ = "capability_snapshots"

    scan_id: Mapped[str | None] = mapped_column(String(32), index=True)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    capabilities: Mapped[list[Any]] = mapped_column(JSON, default=list)
    host: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class AuditEvent(Base, IdMixin):
    __tablename__ = "audit_events"

    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    actor: Mapped[str] = mapped_column(String(128), default="local")
    action: Mapped[str] = mapped_column(String(64), index=True)
    resource_type: Mapped[str | None] = mapped_column(String(48))
    resource_id: Mapped[str | None] = mapped_column(String(64), index=True)
    outcome: Mapped[str] = mapped_column(String(24), default="success")
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class SettingEntry(Base):
    """Runtime-adjustable settings overlay (see app.services.settings_service)."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
