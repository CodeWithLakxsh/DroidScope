"""Dynamic analysis session management.

A session installs an application on an explicitly chosen device, launches it,
attaches read-only Frida instrumentation and records what it observes. It is
opt-in at three levels: the deployment must enable dynamic analysis, the caller
must pass an explicit authorisation flag, and the device must be selected by
serial.

What this cannot do, and says so rather than pretending:

* attach to a third-party release build on a stock, non-rooted device -- that
  requires root, a debuggable build, or repackaging with frida-gadget;
* decrypt TLS without an operator-configured proxy and trust anchor.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.analyzers.dynamic.devices import Device, DeviceManager
from app.analyzers.dynamic.frida_scripts import DEFAULT_MODULES, build_script
from app.core.config import Settings, get_settings
from app.core.enums import SessionStatus
from app.core.errors import (
    CapabilityUnavailableError,
    NotFoundError,
    ToolUnavailableError,
    ValidationError,
)
from app.core.logging import get_logger
from app.core.process import resolve_executable, run_command
from app.core.redaction import redact_text
from app.models import ApkArtifact, AuditEvent, DynamicSession, RuntimeEvent
from app.storage.artifacts import ArtifactStore, get_artifact_store

logger = get_logger(__name__)

ADB_TIMEOUT = 120.0
INSTALL_TIMEOUT = 300.0
MAX_EVENTS = 20000


@dataclass(slots=True)
class SessionOutcome:
    session_id: str
    status: SessionStatus
    events: int
    capability_report: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class DynamicAnalysisService:
    def __init__(
        self,
        session: AsyncSession,
        *,
        settings: Settings | None = None,
        store: ArtifactStore | None = None,
    ) -> None:
        self.session = session
        self.settings = settings or get_settings()
        self.store = store or get_artifact_store(self.settings)
        self.devices = DeviceManager(self.settings)

    # -- creation ----------------------------------------------------------
    async def create_session(
        self,
        *,
        apk_id: str,
        device_serial: str,
        modules: list[str] | None = None,
        duration_seconds: int = 120,
        authorised: bool = False,
        actor: str = "local",
    ) -> DynamicSession:
        if not self.settings.dynamic_analysis_enabled:
            raise CapabilityUnavailableError(
                "Dynamic analysis is disabled. It installs and executes the uploaded "
                "application on a device, so it must be enabled explicitly with "
                "DROIDSCOPE_DYNAMIC_ANALYSIS_ENABLED=true and pointed at an isolated "
                "test device."
            )
        if not authorised:
            raise ValidationError(
                "dynamic analysis requires explicit authorisation: set 'authorised' to "
                "true to confirm you may install and run this application on the "
                "selected device"
            )

        apk = await self.session.get(ApkArtifact, apk_id)
        if apk is None:
            raise NotFoundError(f"APK {apk_id} does not exist")

        device = await self.devices.require_usable(device_serial)
        selected = list(modules or DEFAULT_MODULES)

        session_row = DynamicSession(
            apk_id=apk.id,
            device_serial=device.serial,
            device_info=device.to_dict(),
            status=SessionStatus.created,
            modules=selected,
            config={"duration_seconds": duration_seconds},
            capability_report=self._capability_report(device),
        )
        self.session.add(session_row)
        self.session.add(
            AuditEvent(
                actor=actor,
                action="dynamic.session.create",
                resource_type="dynamic_session",
                resource_id=session_row.id,
                detail={
                    "apk_id": apk.id,
                    "device": device.serial,
                    "is_emulator": device.is_emulator,
                    "modules": selected,
                    "authorised": True,
                },
            )
        )
        await self.session.commit()
        logger.info(
            "dynamic.session_created",
            session_id=session_row.id,
            device=device.serial,
            modules=selected,
        )
        return session_row

    def _capability_report(self, device: Device) -> dict[str, Any]:
        """State plainly what will and will not work on this device."""
        frida_cli = resolve_executable(self.settings.frida_path, names=("frida",))
        instrumentation_possible = bool(
            frida_cli and (device.frida_server_running or device.rooted)
        )
        blockers: list[str] = []
        if not frida_cli:
            blockers.append(
                "The frida CLI is not installed on this host (pip install frida-tools)."
            )
        if device.frida_server_running is False:
            blockers.append(
                "frida-server is not running on the device. Push a frida-server build "
                "matching the device ABI and the host frida version, then start it."
            )
        if device.rooted is False:
            blockers.append(
                "The device is not rooted. Instrumenting a third-party release build "
                "needs root, a debuggable build, or an APK repackaged with "
                "frida-gadget."
            )
        return {
            "install_and_launch": True,
            "log_capture": True,
            "instrumentation_possible": instrumentation_possible,
            "network_capture": False,
            "blockers": blockers,
            "notes": [
                "Instrumentation modules are read-only: they observe API calls and do "
                "not bypass authentication, certificate validation or biometric checks.",
                "TLS payloads are not decrypted. Capturing them requires an "
                "operator-configured proxy and a trust anchor installed on the test "
                "device, which DroidScope does not do automatically.",
            ],
        }

    # -- execution ---------------------------------------------------------
    async def run_session(self, session_id: str) -> SessionOutcome:
        row = await self.session.get(DynamicSession, session_id)
        if row is None:
            raise NotFoundError(f"session {session_id} does not exist")
        apk = await self.session.get(ApkArtifact, row.apk_id)
        if apk is None:
            raise NotFoundError("the APK for this session is no longer available")

        adb = self.devices.adb_path()
        if adb is None:
            raise ToolUnavailableError("adb is not installed")

        apk_path = self.store.path_for(apk.storage_key)
        duration = int((row.config or {}).get("duration_seconds", 120))
        package = apk.package_name

        row.status = SessionStatus.preparing
        row.started_at = datetime.now(UTC)
        await self.session.commit()

        events: list[dict[str, Any]] = []
        try:
            await self._install(adb, row.device_serial, apk_path)
            if not package:
                raise ValidationError(
                    "the package name could not be determined, so the application "
                    "cannot be launched"
                )

            row.status = SessionStatus.running
            await self.session.commit()

            events = await self._observe(
                adb=adb,
                serial=row.device_serial,
                package=package,
                modules=list(row.modules or []),
                duration=duration,
                capability=row.capability_report or {},
            )
            row.status = SessionStatus.stopped
        except Exception as exc:  # noqa: BLE001 - record the failure on the session
            logger.exception("dynamic.session_failed", session_id=session_id)
            row.status = SessionStatus.failed
            row.error = f"{type(exc).__name__}: {exc}"
        finally:
            row.stopped_at = datetime.now(UTC)
            await self._persist_events(row, events)
            await self._cleanup(adb, row.device_serial, package)
            await self.session.commit()

        return SessionOutcome(
            session_id=row.id,
            status=SessionStatus(row.status),
            events=row.events_count,
            capability_report=row.capability_report or {},
            error=row.error,
        )

    async def _install(self, adb: Path, serial: str, apk_path: Path) -> None:
        result = await run_command(
            [adb, "-s", serial, "install", "-r", "-t", "-g", str(apk_path)],
            timeout=INSTALL_TIMEOUT,
        )
        combined = f"{result.stdout}\n{result.stderr}"
        if "Success" not in combined:
            raise ToolUnavailableError(f"installation failed: {combined.strip()[-400:]}")
        logger.info("dynamic.installed", serial=serial)

    async def _observe(
        self,
        *,
        adb: Path,
        serial: str,
        package: str,
        modules: list[str],
        duration: int,
        capability: dict[str, Any],
    ) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []

        # Clear the log so captured output belongs to this session only.
        await run_command([adb, "-s", serial, "logcat", "-c"], timeout=ADB_TIMEOUT)

        if capability.get("instrumentation_possible") and modules:
            events.extend(
                await self._run_frida(
                    serial=serial, package=package, modules=modules, duration=duration
                )
            )
        else:
            await run_command(
                [adb, "-s", serial, "shell", "monkey", "-p", package, "-c",
                 "android.intent.category.LAUNCHER", "1"],
                timeout=ADB_TIMEOUT,
            )
            events.append(
                {
                    "event_type": "instrumentation",
                    "module": "session",
                    "summary": (
                        "Frida instrumentation was unavailable; the application was "
                        "launched and only log output was captured. "
                        + " ".join(capability.get("blockers", []))
                    ),
                    "severity": "info",
                    "data": {"blockers": capability.get("blockers", [])},
                }
            )
            await asyncio.sleep(min(duration, 60))

        events.extend(await self._collect_logs(adb, serial, package))
        return events

    async def _run_frida(
        self, *, serial: str, package: str, modules: list[str], duration: int
    ) -> list[dict[str, Any]]:
        """Attach Frida and collect posted messages for the session duration."""
        try:
            import frida
        except ImportError as exc:
            return [
                {
                    "event_type": "instrumentation",
                    "module": "session",
                    "summary": f"the frida Python bindings are unavailable: {exc}",
                    "severity": "warning",
                    "data": {},
                }
            ]

        collected: list[dict[str, Any]] = []
        loop = asyncio.get_running_loop()

        def on_message(message: dict, _data) -> None:  # noqa: ANN001
            if message.get("type") == "error":
                collected.append(
                    {
                        "event_type": "instrumentation",
                        "module": "frida",
                        "summary": redact_text(str(message.get("description", "script error"))),
                        "severity": "warning",
                        "data": {"stack": str(message.get("stack", ""))[:1000]},
                    }
                )
                return
            payload = message.get("payload") or {}
            if not isinstance(payload, dict) or not payload.get("droidscope"):
                return
            if len(collected) >= MAX_EVENTS:
                return
            collected.append(
                {
                    "event_type": str(payload.get("type", "event")),
                    "module": str(payload.get("type", "frida")),
                    "api": str(payload.get("api", ""))[:500],
                    "summary": redact_text(str(payload.get("summary", ""))[:1000]),
                    "severity": str((payload.get("data") or {}).get("severity", "info")),
                    "data": payload.get("data") or {},
                }
            )

        def attach_and_run() -> None:
            device = frida.get_device(serial, timeout=30)
            pid = device.spawn([package])
            session = device.attach(pid)
            script = session.create_script(build_script(modules, package_name=package))
            script.on("message", on_message)
            script.load()
            device.resume(pid)
            # Block in the worker thread for the session duration.
            import time

            time.sleep(duration)
            try:
                session.detach()
            except Exception:  # noqa: BLE001
                pass

        try:
            await loop.run_in_executor(None, attach_and_run)
        except Exception as exc:  # noqa: BLE001 - frida raises many device errors
            collected.append(
                {
                    "event_type": "instrumentation",
                    "module": "session",
                    "summary": f"Frida attach failed: {exc}",
                    "severity": "warning",
                    "data": {"error": str(exc)},
                }
            )
        return collected

    async def _collect_logs(self, adb: Path, serial: str, package: str) -> list[dict[str, Any]]:
        try:
            result = await run_command(
                [adb, "-s", serial, "logcat", "-d", "-v", "time"], timeout=ADB_TIMEOUT
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("dynamic.logcat_failed", error=str(exc))
            return []

        events: list[dict[str, Any]] = []
        for line in result.stdout.splitlines():
            if package and package not in line:
                continue
            events.append(
                {
                    "event_type": "log",
                    "module": "logcat",
                    "summary": redact_text(line.strip()[:1000]),
                    "severity": "info",
                    "data": {},
                }
            )
            if len(events) >= 500:
                break
        return events

    async def _persist_events(self, row: DynamicSession, events: list[dict[str, Any]]) -> None:
        now = datetime.now(UTC)
        for event in events[:MAX_EVENTS]:
            self.session.add(
                RuntimeEvent(
                    session_id=row.id,
                    observed_at=now,
                    event_type=str(event.get("event_type", "event"))[:48],
                    module=str(event.get("module", "session"))[:48],
                    process=row.device_serial,
                    api=(event.get("api") or None),
                    severity=str(event.get("severity", "info"))[:16],
                    summary=event.get("summary"),
                    data=event.get("data") or {},
                )
            )
        row.events_count = min(len(events), MAX_EVENTS)

        if events:
            stored = self.store.write_text(
                f"dynamic/{row.id}/events.json", json.dumps(events[:MAX_EVENTS], indent=2)
            )
            row.config = {**(row.config or {}), "events_artifact": stored.storage_key}

    async def _cleanup(self, adb: Path, serial: str, package: str | None) -> None:
        if not package:
            return
        try:
            await run_command(
                [adb, "-s", serial, "shell", "am", "force-stop", package], timeout=ADB_TIMEOUT
            )
            await run_command([adb, "-s", serial, "uninstall", package], timeout=ADB_TIMEOUT)
        except Exception as exc:  # noqa: BLE001
            logger.debug("dynamic.cleanup_failed", error=str(exc))
