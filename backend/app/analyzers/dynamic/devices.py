"""Device discovery over ADB.

Deliberate constraints:

* a physical device is never selected implicitly -- the API requires an explicit
  serial, and physical devices are excluded entirely unless the deployment
  enables them;
* every property read is a plain ``adb shell getprop``, which changes nothing on
  the device;
* Frida availability is *checked*, not assumed: the frida-server process is
  probed, and what fails is reported rather than hidden.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from app.core.config import Settings, get_settings
from app.core.errors import ToolUnavailableError
from app.core.logging import get_logger
from app.core.process import resolve_executable, run_command

logger = get_logger(__name__)

ADB_TIMEOUT = 20.0
EMULATOR_SERIAL = re.compile(r"^emulator-\d+$")


@dataclass(slots=True)
class Device:
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
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DeviceManager:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def adb_path(self) -> Path | None:
        return resolve_executable(self.settings.adb_path, names=("adb",))

    async def list_devices(self, *, include_properties: bool = True) -> tuple[list[Device], list[str]]:
        """Return discovered devices and any messages explaining gaps."""
        messages: list[str] = []
        adb = self.adb_path()
        if adb is None:
            return [], [
                "adb was not found. Install the Android SDK platform-tools to enable "
                "device discovery and dynamic analysis."
            ]

        try:
            result = await run_command([adb, "devices", "-l"], timeout=ADB_TIMEOUT)
        except Exception as exc:  # noqa: BLE001
            logger.warning("devices.adb_failed", error=str(exc))
            return [], [f"adb could not be queried: {exc}"]

        devices: list[Device] = []
        for line in result.stdout.splitlines()[1:]:
            line = line.strip()
            if not line or line.startswith("*"):
                continue
            parts = line.split()
            serial, state = parts[0], parts[1] if len(parts) > 1 else "unknown"
            is_emulator = bool(EMULATOR_SERIAL.match(serial)) or serial.startswith("emulator")

            device = Device(serial=serial, state=state, is_emulator=is_emulator)

            if state == "unauthorized":
                device.notes.append(
                    "The device has not authorised this host. Accept the USB debugging "
                    "prompt on the device, then refresh."
                )
            elif state != "device":
                device.notes.append(f"The device is in state {state!r} and cannot be used.")
            elif include_properties:
                await self._populate(adb, device)

            if not is_emulator and not self.settings.dynamic_allow_physical_devices:
                device.notes.append(
                    "Physical devices are disabled in this deployment. Set "
                    "DROIDSCOPE_DYNAMIC_ALLOW_PHYSICAL_DEVICES=true to permit them, and "
                    "only use hardware you are authorised to test."
                )
            devices.append(device)

        if not devices:
            messages.append(
                "No devices are connected. Start an emulator (emulator -avd <name>) or "
                "connect a device with USB debugging enabled."
            )
        return devices, messages

    async def get_device(self, serial: str) -> Device | None:
        devices, _ = await self.list_devices()
        for device in devices:
            if device.serial == serial:
                return device
        return None

    async def _populate(self, adb: Path, device: Device) -> None:
        properties = {
            "model": "ro.product.model",
            "manufacturer": "ro.product.manufacturer",
            "android_version": "ro.build.version.release",
            "sdk_int": "ro.build.version.sdk",
            "abi": "ro.product.cpu.abi",
            "build_tags": "ro.build.tags",
            "debuggable": "ro.debuggable",
        }
        values: dict[str, str] = {}
        for key, prop in properties.items():
            try:
                result = await run_command(
                    [adb, "-s", device.serial, "shell", "getprop", prop], timeout=ADB_TIMEOUT
                )
                values[key] = result.stdout.strip()
            except Exception as exc:  # noqa: BLE001
                logger.debug("devices.getprop_failed", serial=device.serial, prop=prop, error=str(exc))

        device.model = values.get("model") or None
        device.manufacturer = values.get("manufacturer") or None
        device.android_version = values.get("android_version") or None
        device.abi = values.get("abi") or None
        try:
            device.sdk_int = int(values.get("sdk_int", "")) if values.get("sdk_int") else None
        except ValueError:
            device.sdk_int = None

        device.rooted = await self._check_root(adb, device.serial)
        device.frida_server_running = await self._check_frida(adb, device.serial)

        if values.get("build_tags") == "test-keys":
            device.notes.append(
                "The build is signed with test-keys, typical of an emulator or a "
                "development image."
            )
        if device.rooted is False:
            device.notes.append(
                "Root access is unavailable. Frida instrumentation of a third-party "
                "application requires either root, a frida-gadget-repackaged APK, or a "
                "debuggable build."
            )
        if device.frida_server_running is False and device.rooted:
            device.notes.append(
                "frida-server is not running. Push a matching frida-server binary to the "
                "device and start it before creating an instrumentation session."
            )

    async def _check_root(self, adb: Path, serial: str) -> bool | None:
        try:
            result = await run_command(
                [adb, "-s", serial, "shell", "which", "su"], timeout=ADB_TIMEOUT
            )
            if result.stdout.strip():
                return True
            # An emulator image often has a root-capable adbd instead of `su`.
            whoami = await run_command(
                [adb, "-s", serial, "shell", "id"], timeout=ADB_TIMEOUT
            )
            return "uid=0" in whoami.stdout
        except Exception as exc:  # noqa: BLE001
            logger.debug("devices.root_check_failed", serial=serial, error=str(exc))
            return None

    async def _check_frida(self, adb: Path, serial: str) -> bool | None:
        try:
            result = await run_command(
                [adb, "-s", serial, "shell", "ps", "-A"], timeout=ADB_TIMEOUT
            )
            output = result.stdout
            if not output.strip():
                result = await run_command([adb, "-s", serial, "shell", "ps"], timeout=ADB_TIMEOUT)
                output = result.stdout
            return "frida-server" in output or "frida_server" in output
        except Exception as exc:  # noqa: BLE001
            logger.debug("devices.frida_check_failed", serial=serial, error=str(exc))
            return None

    async def require_usable(self, serial: str) -> Device:
        device = await self.get_device(serial)
        if device is None:
            raise ToolUnavailableError(f"device {serial!r} is not connected")
        if device.state != "device":
            raise ToolUnavailableError(
                f"device {serial!r} is in state {device.state!r} and cannot be used"
            )
        if not device.is_emulator and not self.settings.dynamic_allow_physical_devices:
            raise ToolUnavailableError(
                "physical devices are disabled in this deployment; enable them "
                "explicitly and only for hardware you are authorised to test"
            )
        return device
