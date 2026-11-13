"""End-to-end pipeline tests against real, built fixture APKs.

The decisive assertion is the comparison between the two fixtures: the
vulnerable application must produce the expected findings, and the secure
application - which uses the *same APIs correctly* - must not. A rule that
fires on both is matching keywords, not detecting a weakness.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.enums import JobStatus, ScanProfile
from app.services.apk_service import ApkService
from app.services.pipeline import ScanPipeline
from app.services.scan_service import ScanService

pytestmark = pytest.mark.asyncio


async def run_scan(session, apk_path: Path, profile: ScanProfile = ScanProfile.standard):
    ingest = await ApkService(session).ingest_file(apk_path)
    creation = await ScanService(session).create(ingest.apk.id, profile=profile, reuse=False)
    outcome = await ScanPipeline(session).run(creation.scan.id)
    return ingest.apk, outcome


async def findings_for(session, scan_id: str) -> list:
    from sqlalchemy import select

    from app.models import Finding

    result = await session.execute(select(Finding).where(Finding.scan_id == scan_id))
    return list(result.scalars().all())


class TestVulnerableFixture:
    async def test_quick_profile_completes(self, session, vulnerable_apk) -> None:
        _apk, outcome = await run_scan(session, vulnerable_apk, ScanProfile.quick)
        assert outcome.status == JobStatus.completed
        assert outcome.findings > 0

    async def test_metadata_is_extracted(self, session, vulnerable_apk) -> None:
        apk, _outcome = await run_scan(session, vulnerable_apk, ScanProfile.quick)
        assert apk.package_name == "com.droidscope.vulnerable"
        assert apk.version_name == "1.4.2"
        assert apk.version_code == 42
        assert apk.min_sdk == 21
        assert apk.target_sdk == 28
        assert apk.sha256 and len(apk.sha256) == 64
        metadata = apk.apk_metadata
        assert metadata["application_flags"]["debuggable"] is True
        assert len(metadata["components"]) >= 6
        assert metadata["certificates"], "the fixture is signed, so a certificate is expected"

    @pytest.mark.parametrize(
        "rule_id",
        [
            "DS-MANIFEST-001",  # exported component
            "DS-MANIFEST-002",  # exported provider
            "DS-MANIFEST-003",  # debuggable
            "DS-MANIFEST-004",  # backup
            "DS-MANIFEST-005",  # cleartext
            "DS-MANIFEST-006",  # user CA trust
            "DS-MANIFEST-007",  # weak custom permission
        ],
    )
    async def test_expected_manifest_rules_fire(self, session, vulnerable_apk, rule_id) -> None:
        _apk, outcome = await run_scan(session, vulnerable_apk, ScanProfile.quick)
        findings = await findings_for(session, outcome.scan_id)
        assert rule_id in {finding.rule_id for finding in findings}

    @pytest.mark.parametrize(
        "rule_id",
        [
            "DS-CRYPTO-001",  # MD5 on a password
            "DS-CRYPTO-003",  # DES
            "DS-CRYPTO-004",  # ECB
            "DS-CRYPTO-009",  # hardcoded key
            "DS-NETWORK-001",  # permissive TrustManager
            "DS-NETWORK-002",  # hostname verification disabled
            "DS-WEBVIEW-001",  # JavaScript interface
            "DS-WEBVIEW-002",  # universal file access
            "DS-WEBVIEW-004",  # SSL errors ignored
            "DS-STORAGE-001",  # world readable
            "DS-STORAGE-005",  # SQL concatenation
            "DS-SECRET-001",  # provider credential
            "DS-SECRET-002",  # entropy-based credential
        ],
    )
    async def test_expected_source_rules_fire(self, session, vulnerable_apk, rule_id) -> None:
        """Requires JADX; skipped automatically when it is unavailable."""
        _apk, outcome = await run_scan(session, vulnerable_apk, ScanProfile.standard)
        executions = {item["analyzer"]: item["status"] for item in outcome.executions}
        if executions.get("source-analyzer") != "completed":
            pytest.skip("the source analyzer did not complete (JADX unavailable)")
        findings = await findings_for(session, outcome.scan_id)
        assert rule_id in {finding.rule_id for finding in findings}

    async def test_secret_evidence_is_masked(self, session, vulnerable_apk) -> None:
        """The plaintext of a detected credential must never reach the database."""
        from sqlalchemy import select

        from app.models import FindingEvidence

        _apk, outcome = await run_scan(session, vulnerable_apk, ScanProfile.standard)
        rows = (
            (
                await session.execute(
                    select(FindingEvidence).where(FindingEvidence.sensitive.is_(True))
                )
            )
            .scalars()
            .all()
        )
        if not rows:
            pytest.skip("no sensitive evidence was produced (JADX unavailable)")

        for row in rows:
            assert row.raw_value is None, "raw secret values must not be stored by default"
            assert row.value_fingerprint, "a fingerprint is needed to correlate across scans"
            assert "•" in (row.snippet or ""), "the snippet should carry a mask"
        # No unmasked credential may appear in any stored snippet. The fixture's
        # values are generated at build time, so this asserts the *shape* is
        # absent rather than one specific string.
        import re

        unmasked = re.compile(r"AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xoxb-\d{10}-")
        for row in rows:
            assert not unmasked.search(row.snippet or ""), (
                f"an unmasked credential reached the database: {row.snippet!r}"
            )

    async def test_risk_summary_is_explainable(self, session, vulnerable_apk) -> None:
        _apk, outcome = await run_scan(session, vulnerable_apk, ScanProfile.quick)
        risk = outcome.risk
        assert 0 <= risk["score"] <= 100
        assert risk["band"] in {"minimal", "low", "moderate", "elevated", "high"}
        assert "CVSS" not in risk["method"] or "not a CVSS" in risk["method"]
        assert risk["caveats"], "a risk summary must state its caveats"
        assert risk["coverage"]["analyzers_completed"]


class TestSecureFixture:
    """The secure fixture uses the same APIs correctly and must stay quiet."""

    async def test_completes_without_high_severity_findings(self, session, secure_apk) -> None:
        _apk, outcome = await run_scan(session, secure_apk, ScanProfile.standard)
        assert outcome.status == JobStatus.completed
        assert outcome.severity_counts.get("critical", 0) == 0, (
            f"the secure fixture produced critical findings: {outcome.severity_counts}"
        )
        assert outcome.severity_counts.get("high", 0) == 0, (
            f"the secure fixture produced high findings: {outcome.severity_counts}"
        )

    @pytest.mark.parametrize(
        "rule_id",
        [
            "DS-MANIFEST-002",  # provider is not exported
            "DS-MANIFEST-003",  # not debuggable
            "DS-MANIFEST-004",  # backup disabled
            "DS-MANIFEST-005",  # cleartext blocked
            "DS-MANIFEST-006",  # user CAs only in debug-overrides
            "DS-CRYPTO-001",  # no MD5 on credentials
            "DS-CRYPTO-003",  # no DES
            "DS-CRYPTO-004",  # no ECB
            "DS-CRYPTO-009",  # no hardcoded key
            "DS-NETWORK-001",  # no permissive TrustManager
            "DS-NETWORK-002",  # hostname verification intact
            "DS-STORAGE-001",  # no world-readable mode
            "DS-STORAGE-005",  # parameter binding used
            "DS-CODE-006",  # zip traversal guarded
            "DS-SECRET-001",  # no embedded credentials
        ],
    )
    async def test_rules_do_not_fire_on_correct_code(self, session, secure_apk, rule_id) -> None:
        _apk, outcome = await run_scan(session, secure_apk, ScanProfile.standard)
        findings = await findings_for(session, outcome.scan_id)
        matched = [f for f in findings if f.rule_id == rule_id]
        assert not matched, (
            f"{rule_id} fired on the secure fixture, which uses the API correctly: "
            f"{[f.title for f in matched]}"
        )

    async def test_remaining_exported_surface_is_low_or_informational(
        self, session, secure_apk
    ) -> None:
        """The secure fixture still has a legitimate exported surface.

        Two components are exported because they must be: the launcher
        activity, and the activity that handles verified https App Links. Both
        are genuinely reachable from outside the application, so reporting them
        is correct - the launcher as informational, the deep-link handler at low
        severity with "validate the incoming Intent" guidance. What must not
        appear is anything above low, since every other component is either
        unexported or guarded by a signature-level permission.
        """
        _apk, outcome = await run_scan(session, secure_apk, ScanProfile.quick)
        findings = await findings_for(session, outcome.scan_id)
        exported = [f for f in findings if f.rule_id == "DS-MANIFEST-001"]

        severities = {str(getattr(f.severity, "value", f.severity)) for f in exported}
        assert severities <= {"info", "low"}, (
            f"unexpected severities on the secure fixture: {severities}"
        )
        components = {(f.affected_component or "").rsplit(".", 1)[-1] for f in exported}
        assert components <= {"MainActivity", "DeepLinkActivity"}, (
            f"unexpected components reported as exported: {components}"
        )

    async def test_produces_no_findings_above_low(self, session, secure_apk) -> None:
        _apk, outcome = await run_scan(session, secure_apk, ScanProfile.standard)
        counts = outcome.severity_counts
        assert counts.get("critical", 0) == 0
        assert counts.get("high", 0) == 0
        assert counts.get("medium", 0) == 0, (
            f"the secure fixture should produce nothing above low severity: {counts}"
        )


class TestScanReuse:
    async def test_identical_scan_is_reused(self, session, vulnerable_apk) -> None:
        ingest = await ApkService(session).ingest_file(vulnerable_apk)
        service = ScanService(session)
        first = await service.create(ingest.apk.id, profile=ScanProfile.quick)
        await ScanPipeline(session).run(first.scan.id)
        second = await service.create(ingest.apk.id, profile=ScanProfile.quick)
        assert second.reused
        assert second.scan.id == first.scan.id

    async def test_a_different_profile_is_not_reused(self, session, vulnerable_apk) -> None:
        ingest = await ApkService(session).ingest_file(vulnerable_apk)
        service = ScanService(session)
        first = await service.create(ingest.apk.id, profile=ScanProfile.quick)
        await ScanPipeline(session).run(first.scan.id)
        second = await service.create(ingest.apk.id, profile=ScanProfile.standard)
        assert not second.reused


class TestDuplicateUpload:
    async def test_same_bytes_reuse_the_record(self, session, vulnerable_apk) -> None:
        service = ApkService(session)
        first = await service.ingest_file(vulnerable_apk)
        second = await service.ingest_file(vulnerable_apk)
        assert first.created is True
        assert second.created is False
        assert first.apk.id == second.apk.id
