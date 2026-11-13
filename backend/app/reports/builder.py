"""Report document assembly.

Builds one canonical document from stored scan data; every renderer (PDF, HTML,
JSON, SARIF) consumes it, so the formats cannot drift apart.

The document always carries the facts that make a report checkable: when it was
produced, which scan it describes, the APK's SHA-256, the versions of the tools
that ran, which analyzers did not complete, and the limitations each analyzer
reported. Secret evidence is redacted unless the caller explicitly opts out and
the deployment permits it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app import __version__
from app.core.config import Settings, get_settings
from app.core.enums import Severity
from app.core.errors import NotFoundError
from app.core.redaction import redact_text
from app.models import (
    AnalyzerExecution,
    ApkArtifact,
    CapabilitySnapshot,
    Finding,
    NetworkObservation,
    Scan,
)

SEVERITY_ORDER = [
    Severity.critical,
    Severity.high,
    Severity.medium,
    Severity.low,
    Severity.info,
]


async def build_report_document(
    session: AsyncSession,
    scan_id: str,
    *,
    include_evidence: bool = True,
    redact_secrets: bool | None = None,
    include_informational: bool = True,
    settings: Settings | None = None,
) -> dict[str, Any]:
    settings = settings or get_settings()
    redact = settings.redact_secrets_in_reports if redact_secrets is None else redact_secrets

    scan = await session.get(Scan, scan_id)
    if scan is None:
        raise NotFoundError(f"scan {scan_id} does not exist")
    apk = await session.get(ApkArtifact, scan.apk_id)
    if apk is None:
        raise NotFoundError("the APK for this scan is no longer available")

    findings = (
        (
            await session.execute(
                select(Finding)
                .where(Finding.scan_id == scan_id)
                .options(selectinload(Finding.evidence))
            )
        )
        .scalars()
        .all()
    )
    if not include_informational:
        findings = [f for f in findings if f.severity != Severity.info]
    findings = sorted(
        findings,
        key=lambda f: (-Severity(f.severity).rank, f.rule_id, f.file_path or ""),
    )

    executions = (
        (
            await session.execute(
                select(AnalyzerExecution).where(AnalyzerExecution.scan_id == scan_id)
            )
        )
        .scalars()
        .all()
    )
    indicators = (
        (
            await session.execute(
                select(NetworkObservation)
                .where(NetworkObservation.scan_id == scan_id)
                .order_by(NetworkObservation.occurrences.desc())
                .limit(250)
            )
        )
        .scalars()
        .all()
    )
    snapshot = (
        await session.execute(
            select(CapabilitySnapshot).where(CapabilitySnapshot.scan_id == scan_id).limit(1)
        )
    ).scalar_one_or_none()

    metadata = apk.apk_metadata or {}
    severity_counts = {s.value: 0 for s in SEVERITY_ORDER}
    for finding in findings:
        severity_counts[finding.severity.value] = severity_counts.get(finding.severity.value, 0) + 1

    return {
        "report": {
            "generated_at": datetime.now(UTC).isoformat(),
            "generator": f"DroidScope {__version__}",
            "scan_id": scan.id,
            "apk_sha256": apk.sha256,
            "redaction_applied": redact,
            "evidence_included": include_evidence,
            "informational_included": include_informational,
        },
        "application": {
            "package_name": apk.package_name,
            "label": apk.app_label,
            "version_name": apk.version_name,
            "version_code": apk.version_code,
            "min_sdk": apk.min_sdk,
            "target_sdk": apk.target_sdk,
            "compile_sdk": apk.compile_sdk,
            "file_name": apk.original_filename,
            "file_size": apk.file_size,
            "sha256": apk.sha256,
            "sha1": apk.sha1,
            "md5": apk.md5,
            "certificates": metadata.get("certificates", []),
            "signature_schemes": metadata.get("signature_schemes", []),
            "abis": metadata.get("abis", []),
            "dex_files": metadata.get("dex_files", []),
            "native_libraries": metadata.get("native_libraries", [])[:50],
            "permissions": metadata.get("requested_permissions", []),
            "components": metadata.get("components", []),
            "application_flags": metadata.get("application_flags", {}),
            "metadata_partial": bool(metadata.get("partial")),
            "metadata_errors": metadata.get("parse_errors", []),
        },
        "scan": {
            "id": scan.id,
            "profile": str(getattr(scan.profile, "value", scan.profile)),
            "status": str(getattr(scan.status, "value", scan.status)),
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
            "duration_seconds": scan.duration_seconds,
            "findings_total": len(findings),
            "severity_counts": severity_counts,
            "error": scan.error,
        },
        "risk": scan.risk or {},
        "methodology": _methodology(scan, executions),
        "scope_and_limitations": _limitations(scan, executions),
        "environment": {
            "tool_versions": (scan.environment or {}).get("tool_versions", {}),
            "tools_unavailable": (scan.environment or {}).get("tools_unavailable", []),
            "rules_loaded": (scan.environment or {}).get("rules_loaded"),
            "host": snapshot.host if snapshot else {},
            "capabilities": snapshot.capabilities if snapshot else [],
        },
        "analyzers": [
            {
                "analyzer": e.analyzer,
                "version": e.analyzer_version,
                "status": str(getattr(e.status, "value", e.status)),
                "duration_seconds": e.duration_seconds,
                "findings": e.findings_count,
                "error": e.error,
                "limitations": (e.detail or {}).get("limitations", []),
            }
            for e in sorted(executions, key=lambda x: x.analyzer)
        ],
        "findings": [
            _finding_document(finding, include_evidence=include_evidence, redact=redact)
            for finding in findings
        ],
        "indicators": [
            {
                "type": i.indicator_type,
                "value": i.value,
                "scope": i.scope,
                "host": i.host,
                "scheme": i.scheme,
                "source_file": i.source_file,
                "occurrences": i.occurrences,
            }
            for i in indicators
        ],
        "permission_analysis": _permission_analysis(metadata),
    }


def _finding_document(finding: Finding, *, include_evidence: bool, redact: bool) -> dict[str, Any]:
    document: dict[str, Any] = {
        "finding_id": finding.id,
        "scan_id": finding.scan_id,
        "rule_id": finding.rule_id,
        "rule_version": finding.rule_version,
        "title": finding.title,
        "description": finding.description,
        "severity": str(getattr(finding.severity, "value", finding.severity)),
        "confidence": str(getattr(finding.confidence, "value", finding.confidence)),
        "category": finding.category,
        "cwe_ids": list(finding.cwe_ids or []),
        "masvs_controls": list(finding.masvs_controls or []),
        "affected_component": finding.affected_component,
        "file_path": finding.file_path,
        "line_number": finding.line_number,
        "impact": finding.impact,
        "remediation": finding.remediation,
        "verification": finding.verification,
        "limitations": finding.limitations,
        "references": list(finding.references or []),
        "analysis_engine": finding.analysis_engine,
        "status": str(getattr(finding.status, "value", finding.status)),
        "fingerprint": finding.fingerprint,
        "evidence": [],
    }
    if not include_evidence:
        return document

    for evidence in finding.evidence:
        snippet = evidence.snippet or ""
        if redact:
            # The snippet is already masked for values the detector marked
            # sensitive; this catches credentials in surrounding context.
            snippet = redact_text(snippet)
        document["evidence"].append(
            {
                "kind": evidence.kind,
                "description": evidence.description,
                "snippet": snippet,
                "file_path": evidence.file_path,
                "line_number": evidence.line_number,
                "sensitive": evidence.sensitive,
                "value_fingerprint": evidence.value_fingerprint,
            }
        )
    return document


def _methodology(scan: Scan, executions: list[AnalyzerExecution]) -> dict[str, Any]:
    return {
        "approach": (
            "DroidScope performed static analysis of the submitted APK. The archive was "
            "validated, its manifest and resources decoded, its DEX decompiled to Java "
            "and disassembled to smali, its native libraries parsed, and the results "
            "evaluated against versioned detection rules. No part of the application "
            "was executed."
        ),
        "profile": str(getattr(scan.profile, "value", scan.profile)),
        "analyzers_run": sorted(
            e.analyzer for e in executions if str(getattr(e.status, "value", e.status)) == "completed"
        ),
        "rule_sources": [
            "structural manifest rules evaluated against the parsed manifest model",
            "declarative pattern rules with required and excluded context",
            "secret detection combining provider formats with entropy analysis",
            "ELF hardening inspection and YARA content matching",
        ],
        "standards": (
            "Findings reference CWE identifiers and OWASP MASVS v2 controls where a "
            "mapping is defensible. Mappings are recorded per rule and are not inferred "
            "automatically."
        ),
    }


def _limitations(scan: Scan, executions: list[AnalyzerExecution]) -> dict[str, Any]:
    incomplete = [
        {
            "analyzer": e.analyzer,
            "status": str(getattr(e.status, "value", e.status)),
            "reason": e.error,
        }
        for e in executions
        if str(getattr(e.status, "value", e.status)) != "completed"
    ]
    statements = list(scan.limitations or [])
    statements.append(
        "Static analysis describes the application as shipped. It cannot observe "
        "runtime behaviour, server-side controls, or code loaded after installation."
    )
    if incomplete:
        statements.append(
            "The following analyzers did not complete, so issues they would detect are "
            "not represented: "
            + ", ".join(f"{item['analyzer']} ({item['status']})" for item in incomplete)
        )
    statements.append(
        "A completed scan with no findings is not evidence that the application is "
        "secure; it shows only that the rules which ran did not match."
    )
    return {
        "statements": sorted(set(statements)),
        "analyzers_incomplete": incomplete,
        "scan_complete": not incomplete,
    }


def _permission_analysis(metadata: dict[str, Any]) -> dict[str, Any]:
    permissions = metadata.get("requested_permissions", []) or []
    dangerous = [p for p in permissions if p.get("is_dangerous")]
    special = [
        p
        for p in permissions
        if p.get("protection_level") and "special" in str(p["protection_level"])
    ]
    return {
        "total": len(permissions),
        "dangerous_count": len(dangerous),
        "dangerous": [p.get("name") for p in dangerous],
        "special": [p.get("name") for p in special],
        "all": [
            {
                "name": p.get("name"),
                "protection_level": p.get("protection_level"),
                "is_dangerous": bool(p.get("is_dangerous")),
                "max_sdk_version": p.get("max_sdk_version"),
            }
            for p in permissions
        ],
    }
