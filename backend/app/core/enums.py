"""Shared domain enumerations."""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @property
    def weight(self) -> float:
        return _SEVERITY_WEIGHT[self]


_SEVERITY_RANK = {
    Severity.critical: 5,
    Severity.high: 4,
    Severity.medium: 3,
    Severity.low: 2,
    Severity.info: 1,
}

_SEVERITY_WEIGHT = {
    Severity.critical: 10.0,
    Severity.high: 6.0,
    Severity.medium: 3.0,
    Severity.low: 1.0,
    Severity.info: 0.0,
}


class Confidence(StrEnum):
    """How strongly the evidence supports the finding.

    ``high``   - the evidence is conclusive on its own (e.g. a manifest flag).
    ``medium`` - the pattern is reliable but context could change the verdict.
    ``low``    - heuristic; a reviewer must confirm it.
    """

    high = "high"
    medium = "medium"
    low = "low"

    @property
    def multiplier(self) -> float:
        return {Confidence.high: 1.0, Confidence.medium: 0.65, Confidence.low: 0.35}[self]


class FindingStatus(StrEnum):
    open = "open"
    confirmed = "confirmed"
    false_positive = "false_positive"
    accepted_risk = "accepted_risk"
    resolved = "resolved"


class ScanProfile(StrEnum):
    quick = "quick"
    standard = "standard"
    full = "full"


class JobStatus(StrEnum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"
    timed_out = "timed_out"

    @property
    def terminal(self) -> bool:
        return self in {
            JobStatus.completed,
            JobStatus.failed,
            JobStatus.cancelled,
            JobStatus.timed_out,
        }


class AnalyzerStatus(StrEnum):
    completed = "completed"
    skipped = "skipped"
    failed = "failed"
    timed_out = "timed_out"
    unavailable = "unavailable"


class FindingCategory(StrEnum):
    component_security = "android-component-security"
    manifest_configuration = "manifest-configuration"
    permissions = "permissions"
    cryptography = "cryptography"
    network_security = "network-security"
    webview_security = "webview-security"
    data_storage = "data-storage"
    secrets = "hardcoded-secrets"
    authentication = "authentication"
    native_code = "native-code"
    malware_indicator = "malware-indicator"
    obfuscation = "obfuscation"
    logging = "sensitive-logging"
    firebase = "firebase-configuration"
    runtime_behaviour = "runtime-behaviour"


class SessionStatus(StrEnum):
    created = "created"
    preparing = "preparing"
    running = "running"
    stopping = "stopping"
    stopped = "stopped"
    failed = "failed"


class ReportFormat(StrEnum):
    pdf = "pdf"
    html = "html"
    json = "json"
    sarif = "sarif"
