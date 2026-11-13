"""APK version comparison.

Findings are correlated by their fingerprint, which excludes line numbers, so
shifting code does not present an unchanged issue as a new one. Everything else
is a structured set difference over the parsed metadata.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFoundError, ValidationError
from app.core.logging import get_logger
from app.models import ApkArtifact, Comparison, Finding, Scan

logger = get_logger(__name__)


def _diff(baseline: set[str], updated: set[str]) -> dict[str, list[str]]:
    return {
        "added": sorted(updated - baseline),
        "removed": sorted(baseline - updated),
        "unchanged": sorted(baseline & updated),
    }


def _component_key(component: dict[str, Any]) -> str:
    return f"{component.get('kind')}:{component.get('name')}"


class CompareService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def compare(
        self,
        baseline_apk_id: str,
        updated_apk_id: str,
        *,
        baseline_scan_id: str | None = None,
        updated_scan_id: str | None = None,
    ) -> Comparison:
        if baseline_apk_id == updated_apk_id:
            raise ValidationError("the baseline and updated APK must be different")

        baseline = await self.session.get(ApkArtifact, baseline_apk_id)
        updated = await self.session.get(ApkArtifact, updated_apk_id)
        if baseline is None or updated is None:
            raise NotFoundError("one or both APKs do not exist")

        base_meta = baseline.apk_metadata or {}
        new_meta = updated.apk_metadata or {}

        permissions = _diff(
            {p["name"] for p in base_meta.get("requested_permissions", [])},
            {p["name"] for p in new_meta.get("requested_permissions", [])},
        )
        components = _diff(
            {_component_key(c) for c in base_meta.get("components", [])},
            {_component_key(c) for c in new_meta.get("components", [])},
        )
        exported = _diff(
            {_component_key(c) for c in base_meta.get("components", []) if c.get("exported")},
            {_component_key(c) for c in new_meta.get("components", []) if c.get("exported")},
        )
        libraries = _diff(
            {lib["path"] for lib in base_meta.get("native_libraries", [])},
            {lib["path"] for lib in new_meta.get("native_libraries", [])},
        )
        dex = _diff(
            {d["name"] for d in base_meta.get("dex_files", [])},
            {d["name"] for d in new_meta.get("dex_files", [])},
        )

        base_fingerprints = {c.get("sha256_fingerprint") for c in base_meta.get("certificates", [])}
        new_fingerprints = {c.get("sha256_fingerprint") for c in new_meta.get("certificates", [])}
        signing_changed = base_fingerprints != new_fingerprints

        baseline_scan = await self._resolve_scan(baseline.id, baseline_scan_id)
        updated_scan = await self._resolve_scan(updated.id, updated_scan_id)
        findings_diff = await self._compare_findings(baseline_scan, updated_scan)

        sdk_changes = {
            field: {"baseline": getattr(baseline, field), "updated": getattr(updated, field)}
            for field in ("min_sdk", "target_sdk", "compile_sdk")
            if getattr(baseline, field) != getattr(updated, field)
        }

        flag_changes: dict[str, Any] = {}
        base_flags = base_meta.get("application_flags", {}) or {}
        new_flags = new_meta.get("application_flags", {}) or {}
        for key in sorted(set(base_flags) | set(new_flags)):
            if base_flags.get(key) != new_flags.get(key):
                flag_changes[key] = {
                    "baseline": base_flags.get(key),
                    "updated": new_flags.get(key),
                }

        result = {
            "baseline": _apk_descriptor(baseline),
            "updated": _apk_descriptor(updated),
            "permissions": permissions,
            "components": components,
            "exported_components": exported,
            "native_libraries": libraries,
            "dex_files": dex,
            "sdk_changes": sdk_changes,
            "application_flag_changes": flag_changes,
            "signing": {
                "changed": signing_changed,
                "baseline_fingerprints": sorted(f for f in base_fingerprints if f),
                "updated_fingerprints": sorted(f for f in new_fingerprints if f),
                "note": (
                    "A changed signing certificate means the update cannot be installed "
                    "over the previous version, and may indicate a different publisher."
                    if signing_changed
                    else "The signing certificate is unchanged."
                ),
            },
            "findings": findings_diff,
            "scans": {
                "baseline_scan_id": baseline_scan.id if baseline_scan else None,
                "updated_scan_id": updated_scan.id if updated_scan else None,
                "comparable": bool(baseline_scan and updated_scan),
                "note": (
                    "Finding comparison requires a completed scan of both APKs."
                    if not (baseline_scan and updated_scan)
                    else "Findings correlated by fingerprint, which ignores line numbers."
                ),
            },
        }

        summary = {
            "permissions_added": len(permissions["added"]),
            "permissions_removed": len(permissions["removed"]),
            "components_added": len(components["added"]),
            "components_removed": len(components["removed"]),
            "exported_added": len(exported["added"]),
            "native_libraries_added": len(libraries["added"]),
            "signing_changed": signing_changed,
            "findings_new": len(findings_diff.get("new", [])),
            "findings_resolved": len(findings_diff.get("resolved", [])),
            "findings_unchanged": len(findings_diff.get("unchanged", [])),
            "version_change": (f"{baseline.version_name or '?'} → {updated.version_name or '?'}"),
        }

        comparison = Comparison(
            baseline_apk_id=baseline.id,
            updated_apk_id=updated.id,
            baseline_scan_id=baseline_scan.id if baseline_scan else None,
            updated_scan_id=updated_scan.id if updated_scan else None,
            summary=summary,
            result=result,
        )
        self.session.add(comparison)
        await self.session.commit()
        logger.info("compare.completed", comparison_id=comparison.id, **summary)
        return comparison

    async def _resolve_scan(self, apk_id: str, scan_id: str | None) -> Scan | None:
        if scan_id:
            scan = await self.session.get(Scan, scan_id)
            if scan is None or scan.apk_id != apk_id:
                raise ValidationError(f"scan {scan_id} does not belong to APK {apk_id}")
            return scan
        from app.core.enums import JobStatus

        return (
            await self.session.execute(
                select(Scan)
                .where(Scan.apk_id == apk_id, Scan.status == JobStatus.completed)
                .order_by(Scan.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()

    async def _compare_findings(
        self, baseline_scan: Scan | None, updated_scan: Scan | None
    ) -> dict[str, Any]:
        if not baseline_scan or not updated_scan:
            return {"new": [], "resolved": [], "unchanged": [], "available": False}

        base_rows = (
            (await self.session.execute(select(Finding).where(Finding.scan_id == baseline_scan.id)))
            .scalars()
            .all()
        )
        new_rows = (
            (await self.session.execute(select(Finding).where(Finding.scan_id == updated_scan.id)))
            .scalars()
            .all()
        )
        base_by_fp = {row.fingerprint: row for row in base_rows}
        new_by_fp = {row.fingerprint: row for row in new_rows}

        def descriptor(row: Finding) -> dict[str, Any]:
            return {
                "finding_id": row.id,
                "rule_id": row.rule_id,
                "title": row.title,
                "severity": str(getattr(row.severity, "value", row.severity)),
                "confidence": str(getattr(row.confidence, "value", row.confidence)),
                "file_path": row.file_path,
                "fingerprint": row.fingerprint,
            }

        return {
            "available": True,
            "new": [descriptor(r) for fp, r in new_by_fp.items() if fp not in base_by_fp],
            "resolved": [descriptor(r) for fp, r in base_by_fp.items() if fp not in new_by_fp],
            "unchanged": [descriptor(r) for fp, r in new_by_fp.items() if fp in base_by_fp],
        }


def _apk_descriptor(apk: ApkArtifact) -> dict[str, Any]:
    return {
        "apk_id": apk.id,
        "package_name": apk.package_name,
        "version_name": apk.version_name,
        "version_code": apk.version_code,
        "sha256": apk.sha256,
        "file_size": apk.file_size,
        "min_sdk": apk.min_sdk,
        "target_sdk": apk.target_sdk,
    }
