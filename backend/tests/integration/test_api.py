"""API contract tests against the real application."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

pytestmark = pytest.mark.asyncio

API = "/api/v1"


@pytest.fixture
async def client() -> AsyncIterator[AsyncClient]:
    from app.database.session import create_all
    from app.detection.registry import load_builtin_rules
    from app.main import create_app

    await create_all()
    load_builtin_rules()
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


async def upload(client: AsyncClient, apk_path: Path) -> dict:
    with open(apk_path, "rb") as handle:
        response = await client.post(
            f"{API}/apks",
            files={"file": (apk_path.name, handle, "application/vnd.android.package-archive")},
        )
    assert response.status_code == 201, response.text
    return response.json()


class TestSystemEndpoints:
    async def test_health(self, client: AsyncClient) -> None:
        response = await client.get(f"{API}/health")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["database"] is True

    async def test_capabilities_reports_analyzers(self, client: AsyncClient) -> None:
        response = await client.get(f"{API}/capabilities")
        assert response.status_code == 200
        body = response.json()
        assert body["rules_loaded"] > 0
        assert "manifest-analyzer" in body["analyzers"]
        assert set(body["profiles"]) == {"quick", "standard", "full"}

    async def test_capabilities_do_not_leak_host_paths(self, client: AsyncClient) -> None:
        """A client must never learn the server's filesystem layout.

        The response schema omits the tool path entirely rather than masking
        it, so the assertion is that no absolute path appears anywhere in the
        serialised body.
        """
        response = await client.get(f"{API}/capabilities")
        body = response.json()

        for capability in body["capabilities"]:
            assert "path" not in capability, (
                "the capability schema must not carry a filesystem path"
            )

        serialised = response.text
        for fragment in ("/Users/", "/home/", "/opt/", "C:\\", "/usr/local/", "/private/"):
            assert fragment not in serialised, f"{fragment!r} leaked in the capabilities response"

    async def test_rules_listing(self, client: AsyncClient) -> None:
        body = (await client.get(f"{API}/rules")).json()
        assert len(body) >= 50
        rule = next(item for item in body if item["id"] == "DS-MANIFEST-003")
        assert rule["severity"] == "high"
        assert "CWE-489" in rule["cwe_ids"]

    async def test_openapi_is_served(self, client: AsyncClient) -> None:
        response = await client.get("/openapi.json")
        assert response.status_code == 200
        assert "/api/v1/scans" in response.json()["paths"]


class TestUploadValidation:
    async def test_uploads_a_real_apk(self, client: AsyncClient, vulnerable_apk: Path) -> None:
        body = await upload(client, vulnerable_apk)
        assert body["created"] is True
        assert body["apk"]["package_name"] == "com.droidscope.vulnerable"
        assert body["apk"]["validation"]["valid"] is True

    async def test_duplicate_upload_is_deduplicated(
        self, client: AsyncClient, vulnerable_apk: Path
    ) -> None:
        first = await upload(client, vulnerable_apk)
        second = await upload(client, vulnerable_apk)
        assert second["created"] is False
        assert second["apk"]["id"] == first["apk"]["id"]

    async def test_rejects_a_non_apk(self, client: AsyncClient) -> None:
        response = await client.post(
            f"{API}/apks", files={"file": ("evil.apk", b"not a zip at all", "application/zip")}
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "apk_validation_error"

    async def test_error_body_is_structured(self, client: AsyncClient) -> None:
        response = await client.post(
            f"{API}/apks", files={"file": ("evil.apk", b"nope", "application/zip")}
        )
        error = response.json()["error"]
        assert set(error) == {"code", "message", "details"}

    async def test_unknown_apk_returns_404(self, client: AsyncClient) -> None:
        response = await client.get(f"{API}/apks/doesnotexist")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "not_found"


class TestScanWorkflow:
    async def test_full_workflow(self, client: AsyncClient, vulnerable_apk: Path) -> None:
        """Upload, scan, inspect findings, review one, generate a report."""
        apk = (await upload(client, vulnerable_apk))["apk"]

        created = await client.post(
            f"{API}/scans",
            json={"apk_id": apk["id"], "profile": "quick", "reuse_existing": False},
        )
        assert created.status_code == 201
        scan_id = created.json()["scan"]["id"]

        # The API queues work for a worker; run the pipeline directly here.
        from app.database.session import session_scope
        from app.services.pipeline import ScanPipeline

        async with session_scope() as session:
            outcome = await ScanPipeline(session).run(scan_id)
        assert outcome.status.value == "completed"

        detail = (await client.get(f"{API}/scans/{scan_id}")).json()
        assert detail["status"] == "completed"
        assert detail["findings_total"] > 0
        assert detail["risk"]["score"] > 0
        assert detail["executions"]

        findings = (await client.get(f"{API}/scans/{scan_id}/findings")).json()
        assert findings["total"] == detail["findings_total"]

        # Filtering narrows the set.
        high = (
            await client.get(f"{API}/scans/{scan_id}/findings", params={"severity": "high"})
        ).json()
        assert all(item["severity"] == "high" for item in high["items"])

        finding_id = findings["items"][0]["id"]
        full = (await client.get(f"{API}/findings/{finding_id}")).json()
        assert full["impact"] and full["remediation"]
        assert "metadata" in full

        reviewed = await client.patch(
            f"{API}/findings/{finding_id}/review",
            json={"status": "false_positive", "note": "not applicable here"},
        )
        assert reviewed.status_code == 200
        assert reviewed.json()["status"] == "false_positive"
        assert reviewed.json()["reviews"][0]["new_status"] == "false_positive"

        report = await client.post(f"{API}/reports", json={"scan_id": scan_id, "format": "json"})
        assert report.status_code == 201
        report_id = report.json()["id"]

        download = await client.get(f"{API}/reports/{report_id}/download")
        assert download.status_code == 200
        assert download.headers["content-type"].startswith("application/json")
        assert b"droidscope" in download.content.lower()

    async def test_scan_for_unknown_apk_is_rejected(self, client: AsyncClient) -> None:
        response = await client.post(f"{API}/scans", json={"apk_id": "nope", "profile": "quick"})
        assert response.status_code == 404

    async def test_invalid_profile_is_rejected(
        self, client: AsyncClient, vulnerable_apk: Path
    ) -> None:
        apk = (await upload(client, vulnerable_apk))["apk"]
        response = await client.post(
            f"{API}/scans", json={"apk_id": apk["id"], "profile": "nonsense"}
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "request_validation_error"


class TestDashboardAndSettings:
    async def test_dashboard_counts_are_real(
        self, client: AsyncClient, vulnerable_apk: Path
    ) -> None:
        empty = (await client.get(f"{API}/dashboard")).json()
        assert empty["apks_total"] == 0
        assert empty["findings_total"] == 0

        await upload(client, vulnerable_apk)
        populated = (await client.get(f"{API}/dashboard")).json()
        assert populated["apks_total"] == 1

    async def test_settings_round_trip(self, client: AsyncClient) -> None:
        original = (await client.get(f"{API}/settings")).json()
        assert "tools" in original

        updated = await client.patch(f"{API}/settings", json={"analysis_concurrency": 4})
        assert updated.status_code == 200
        assert updated.json()["analysis_concurrency"] == 4

    async def test_settings_cannot_set_a_tool_path(self, client: AsyncClient) -> None:
        """A writable executable path would be a command execution primitive."""
        response = await client.patch(
            f"{API}/settings", json={"jadx_path": "/tmp/evil", "analysis_concurrency": 2}
        )
        assert response.status_code == 200
        assert "jadx_path" not in response.json()


class TestDeviceEndpoints:
    async def test_devices_endpoint_is_honest_when_none_connected(
        self, client: AsyncClient
    ) -> None:
        body = (await client.get(f"{API}/devices")).json()
        assert "devices" in body
        if not body["devices"]:
            assert body["message"], "the API should explain why no devices are listed"

    async def test_dynamic_session_requires_authorisation(
        self, client: AsyncClient, vulnerable_apk: Path
    ) -> None:
        apk = (await upload(client, vulnerable_apk))["apk"]
        response = await client.post(
            f"{API}/dynamic/sessions",
            json={
                "apk_id": apk["id"],
                "device_serial": "emulator-5554",
                "modules": [],
                "duration_seconds": 30,
                "authorised": False,
            },
        )
        # Disabled by default, and refused without explicit authorisation.
        assert response.status_code in {400, 422, 503}

    async def test_instrumentation_modules_are_read_only(self, client: AsyncClient) -> None:
        body = (await client.get(f"{API}/dynamic/modules")).json()
        names = {module["name"] for module in body["modules"]}
        assert "crypto-api" in names
        # No bypass modules are shipped.
        assert not any(
            keyword in name for name in names for keyword in ("unpin", "bypass", "disable")
        )


class TestSecurityHeaders:
    async def test_security_headers_are_set(self, client: AsyncClient) -> None:
        response = await client.get(f"{API}/health")
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["cache-control"] == "no-store"

    async def test_path_traversal_in_file_endpoint_is_refused(
        self, client: AsyncClient, vulnerable_apk: Path
    ) -> None:
        apk = (await upload(client, vulnerable_apk))["apk"]
        created = await client.post(f"{API}/scans", json={"apk_id": apk["id"], "profile": "quick"})
        scan_id = created.json()["scan"]["id"]
        response = await client.get(
            f"{API}/scans/{scan_id}/file",
            params={"path": "../../../../etc/passwd", "artifact": "decompiled-sources"},
        )
        assert response.status_code in {400, 404, 422}
        assert b"root:" not in response.content
