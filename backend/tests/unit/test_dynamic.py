"""Dynamic analysis logic that can be verified without a device.

The parts that need live hardware - installing, launching and attaching Frida -
are covered by the fixtures below only in terms of *decision making*: which
device is usable, what the capability report should say, and what the
instrumentation script contains. Running a session against a real device
remains unverified and is recorded as such in docs/DEVELOPMENT_STATUS.md.
"""

from __future__ import annotations

import pytest

from app.analyzers.dynamic.devices import Device, DeviceManager
from app.analyzers.dynamic.frida_scripts import (
    DEFAULT_MODULES,
    MODULES,
    build_script,
    describe_modules,
)
from app.core.errors import ToolUnavailableError

# Applied per-class: the module also contains synchronous tests.
async_test = pytest.mark.asyncio


def make_device(**overrides) -> Device:
    defaults = {
        "serial": "emulator-5554",
        "state": "device",
        "is_emulator": True,
        "model": "sdk_gphone64_arm64",
        "android_version": "14",
        "sdk_int": 34,
        "abi": "arm64-v8a",
        "rooted": True,
        "frida_server_running": True,
    }
    defaults.update(overrides)
    return Device(**defaults)


@async_test
class TestDeviceSelection:
    async def test_refuses_an_unknown_device(self, settings) -> None:
        manager = DeviceManager(settings)
        with pytest.raises(ToolUnavailableError, match="not connected"):
            await manager.require_usable("no-such-device")

    async def test_physical_devices_are_refused_by_default(self, settings, monkeypatch) -> None:
        """Hardware is never selected implicitly."""
        settings.dynamic_allow_physical_devices = False
        manager = DeviceManager(settings)
        physical = make_device(serial="R58N12ABCDE", is_emulator=False)

        async def fake_get(serial: str):
            return physical if serial == physical.serial else None

        monkeypatch.setattr(manager, "get_device", fake_get)
        with pytest.raises(ToolUnavailableError, match="[Pp]hysical devices are disabled"):
            await manager.require_usable(physical.serial)

    async def test_physical_devices_allowed_when_enabled(self, settings, monkeypatch) -> None:
        settings.dynamic_allow_physical_devices = True
        manager = DeviceManager(settings)
        physical = make_device(serial="R58N12ABCDE", is_emulator=False)

        async def fake_get(serial: str):
            return physical

        monkeypatch.setattr(manager, "get_device", fake_get)
        assert (await manager.require_usable(physical.serial)) is physical

    async def test_unauthorised_device_is_refused(self, settings, monkeypatch) -> None:
        manager = DeviceManager(settings)
        device = make_device(state="unauthorized")

        async def fake_get(serial: str):
            return device

        monkeypatch.setattr(manager, "get_device", fake_get)
        with pytest.raises(ToolUnavailableError, match="unauthorized"):
            await manager.require_usable(device.serial)

    async def test_reports_why_no_devices_are_listed(self, settings) -> None:
        """An empty list must come with an explanation, not silence."""
        devices, messages = await DeviceManager(settings).list_devices()
        if not devices:
            assert messages, "the manager should explain why nothing was found"
            assert any("emulator" in message or "adb" in message for message in messages)


@async_test
class TestCapabilityReport:
    """The report must state what will not work *before* a session starts."""

    def _report(self, session_service, device: Device) -> dict:
        return session_service._capability_report(device)

    async def test_rooted_device_with_frida_is_instrumentable(self, session, settings) -> None:
        from app.analyzers.dynamic.session import DynamicAnalysisService

        service = DynamicAnalysisService(session, settings=settings)
        report = self._report(service, make_device())
        # Depends on the frida CLI being present on this host.
        assert report["install_and_launch"] is True
        assert report["log_capture"] is True
        assert report["network_capture"] is False, "TLS capture is not implemented"

    async def test_unrooted_device_reports_the_blocker(self, session, settings) -> None:
        from app.analyzers.dynamic.session import DynamicAnalysisService

        service = DynamicAnalysisService(session, settings=settings)
        report = self._report(service, make_device(rooted=False, frida_server_running=False))
        assert report["instrumentation_possible"] is False
        blockers = " ".join(report["blockers"])
        assert "not rooted" in blockers
        assert "frida-server" in blockers

    async def test_notes_explain_the_read_only_posture(self, session, settings) -> None:
        from app.analyzers.dynamic.session import DynamicAnalysisService

        service = DynamicAnalysisService(session, settings=settings)
        notes = " ".join(self._report(service, make_device())["notes"])
        assert "read-only" in notes
        assert "not decrypted" in notes


@async_test
class TestSessionAuthorisation:
    async def test_disabled_by_default(self, session, settings, vulnerable_apk) -> None:
        from app.analyzers.dynamic.session import DynamicAnalysisService
        from app.core.errors import CapabilityUnavailableError
        from app.services.apk_service import ApkService

        ingest = await ApkService(session, settings=settings).ingest_file(vulnerable_apk)
        settings.dynamic_analysis_enabled = False
        service = DynamicAnalysisService(session, settings=settings)

        with pytest.raises(CapabilityUnavailableError, match="disabled"):
            await service.create_session(
                apk_id=ingest.apk.id,
                device_serial="emulator-5554",
                authorised=True,
            )

    async def test_requires_explicit_authorisation(self, session, settings, vulnerable_apk) -> None:
        from app.analyzers.dynamic.session import DynamicAnalysisService
        from app.core.errors import ValidationError
        from app.services.apk_service import ApkService

        ingest = await ApkService(session, settings=settings).ingest_file(vulnerable_apk)
        settings.dynamic_analysis_enabled = True
        service = DynamicAnalysisService(session, settings=settings)

        with pytest.raises(ValidationError, match="authorisation"):
            await service.create_session(
                apk_id=ingest.apk.id,
                device_serial="emulator-5554",
                authorised=False,
            )


class TestInstrumentationModules:
    def test_default_modules_exist(self) -> None:
        assert set(DEFAULT_MODULES) <= set(MODULES)

    def test_every_module_is_described(self) -> None:
        described = {module["name"] for module in describe_modules()}
        assert described == set(MODULES)

    def test_no_security_bypass_module_is_shipped(self) -> None:
        """DroidScope deliberately ships no control-defeat instrumentation."""
        everything = " ".join(
            module.name + module.description + module.script for module in MODULES.values()
        ).lower()
        for forbidden in ("unpin", "bypass", "defeat", "disable ssl", "sslunpinning"):
            assert forbidden not in everything, f"{forbidden!r} appears in a shipped module"

    def test_script_composes_requested_modules(self) -> None:
        script = build_script(["crypto-api", "network-api"], package_name="com.example")
        assert "module: crypto-api" in script
        assert "module: network-api" in script
        assert "module: file-access" not in script

    def test_prelude_is_always_present(self) -> None:
        script = build_script(["file-access"])
        assert "function emit(" in script
        assert "function safeHook(" in script

    def test_unknown_module_is_ignored(self) -> None:
        script = build_script(["crypto-api", "does-not-exist"])
        assert "module: crypto-api" in script

    def test_method_trace_receives_the_package_prefix(self) -> None:
        script = build_script(["method-trace"], package_name="com.example.app")
        assert "com.example.app" in script
        assert "__PACKAGE_PREFIX__" not in script

    def test_crypto_module_does_not_capture_key_material(self) -> None:
        """Key bytes must never be emitted - only the algorithm and length."""
        script = MODULES["crypto-api"].script
        assert "key_length_bytes" in script
        assert "key.toString()" not in script

    def test_storage_module_records_keys_not_values(self) -> None:
        script = MODULES["file-access"].script
        assert "value_length" in script
        assert "value: value" not in script
