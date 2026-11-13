"""External tool discovery and capability reporting.

Every analyzer that depends on an external program declares a capability here.
The result drives ``droidscope doctor``, the ``/capabilities`` endpoint and the
per-scan record of which analyzers could actually run.  Nothing in this module
fabricates availability: a tool is reported available only after its binary has
been located and, where cheap, executed to read its version.
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import platform
import shutil
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.core.process import run_command

logger = get_logger(__name__)

VERSION_PROBE_TIMEOUT = 25.0


@dataclass(slots=True)
class Capability:
    name: str
    available: bool
    kind: str  # "python" | "executable" | "sdk" | "service"
    version: str | None = None
    path: str | None = None
    required_for: list[str] = field(default_factory=list)
    detail: str | None = None
    install_hint: str | None = None
    optional: bool = True

    def to_dict(self) -> dict:
        data = asdict(self)
        # Host paths are useful locally but must not leak to API clients; the
        # API layer strips them via ``public_dict``.
        return data

    def public_dict(self) -> dict:
        data = self.to_dict()
        data["path"] = Path(self.path).name if self.path else None
        return data


def _brew_hint(formula: str, *, cask: bool = False) -> str:
    kind = "install --cask" if cask else "install"
    return f"macOS: brew {kind} {formula}"


async def _probe_version(
    path: Path, args: list[str], *, parse_first_line: bool = True
) -> str | None:
    try:
        result = await run_command([path, *args], timeout=VERSION_PROBE_TIMEOUT)
    except Exception as exc:  # noqa: BLE001 - probing must never break discovery
        logger.debug("capability.version_probe_failed", tool=path.name, error=str(exc))
        return None
    text = (result.stdout or result.stderr).strip()
    if not text:
        return None
    return text.splitlines()[0].strip() if parse_first_line else text


def _python_module(name: str) -> tuple[bool, str | None]:
    if importlib.util.find_spec(name) is None:
        return False, None
    try:
        module = __import__(name)
        version = getattr(module, "__version__", None)
        return True, str(version) if version else None
    except Exception as exc:  # noqa: BLE001
        logger.debug("capability.import_failed", module=name, error=str(exc))
        return False, None


async def _executable_capability(
    name: str,
    settings_path: Path | None,
    search_names: tuple[str, ...],
    *,
    version_args: list[str],
    required_for: list[str],
    install_hint: str,
    optional: bool = True,
) -> Capability:
    located: Path | None = None
    if settings_path and Path(settings_path).is_file():
        located = Path(settings_path)
    else:
        for candidate in search_names:
            found = shutil.which(candidate)
            if found:
                located = Path(found)
                break
    if located is None:
        return Capability(
            name=name,
            available=False,
            kind="executable",
            required_for=required_for,
            install_hint=install_hint,
            detail="executable not found on PATH",
            optional=optional,
        )
    version = await _probe_version(located, version_args)
    return Capability(
        name=name,
        available=True,
        kind="executable",
        version=version,
        path=str(located),
        required_for=required_for,
        install_hint=install_hint,
        optional=optional,
    )


async def _ghidra_capability(settings: Settings) -> Capability:
    hint = _brew_hint("ghidra", cask=True) + " (or download from ghidra-sre.org)"
    home = settings.ghidra_home
    candidates: list[Path] = []
    if home:
        candidates.append(Path(home).expanduser())
    runner = shutil.which("ghidraRun") or shutil.which("analyzeHeadless")
    if runner:
        # brew exposes bin/ghidraRun which is a shim into the install directory.
        resolved = Path(runner).resolve()
        candidates.extend([resolved.parent.parent, resolved.parent])
    candidates.extend(
        [
            Path("/opt/homebrew/Cellar/ghidra"),
            Path("/Applications/ghidra"),
            Path.home() / "ghidra",
        ]
    )

    for candidate in candidates:
        if not candidate.exists():
            continue
        headless = _find_headless(candidate)
        if headless:
            version = _read_ghidra_version(headless)
            return Capability(
                name="ghidra",
                available=True,
                kind="executable",
                version=version,
                path=str(headless),
                required_for=["native-ghidra-analyzer"],
                install_hint=hint,
                detail="analyzeHeadless located; decompilation runs in an isolated worker",
            )
    return Capability(
        name="ghidra",
        available=False,
        kind="executable",
        required_for=["native-ghidra-analyzer"],
        install_hint=hint,
        detail="analyzeHeadless not found; ELF inspection still runs without Ghidra",
    )


def _find_headless(root: Path) -> Path | None:
    direct = root / "support" / "analyzeHeadless"
    if direct.is_file():
        return direct
    if root.is_dir():
        try:
            for child in sorted(root.iterdir(), reverse=True):
                if not child.is_dir():
                    continue
                nested = child / "support" / "analyzeHeadless"
                if nested.is_file():
                    return nested
                deeper = child / "libexec" / "support" / "analyzeHeadless"
                if deeper.is_file():
                    return deeper
        except PermissionError:  # pragma: no cover
            return None
    return None


def _read_ghidra_version(headless: Path) -> str | None:
    props = headless.parent.parent / "Ghidra" / "application.properties"
    if props.is_file():
        for line in props.read_text(errors="replace").splitlines():
            if line.startswith("application.version="):
                return line.split("=", 1)[1].strip()
    return None


def _android_sdk_capability(settings: Settings) -> Capability:
    hint = "Install Android Studio or the command line tools, then set DROIDSCOPE_ANDROID_SDK_ROOT"
    candidates = [
        settings.android_sdk_root,
        os.environ.get("ANDROID_SDK_ROOT"),
        os.environ.get("ANDROID_HOME"),
        Path.home() / "Library" / "Android" / "sdk",
        Path.home() / "Android" / "Sdk",
        Path("/usr/local/lib/android/sdk"),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        root = Path(candidate).expanduser()
        if (root / "platform-tools").is_dir() or (root / "emulator").is_dir():
            components = [
                name
                for name in ("platform-tools", "emulator", "build-tools", "platforms")
                if (root / name).is_dir()
            ]
            return Capability(
                name="android-sdk",
                available=True,
                kind="sdk",
                path=str(root),
                required_for=["dynamic-analysis", "fixture-build"],
                detail="components: " + ", ".join(components),
                install_hint=hint,
            )
    return Capability(
        name="android-sdk",
        available=False,
        kind="sdk",
        required_for=["dynamic-analysis", "fixture-build"],
        install_hint=hint,
        detail="no SDK root containing platform-tools/emulator was found",
    )


async def _emulator_capability(settings: Settings) -> Capability:
    sdk = _android_sdk_capability(settings)
    hint = "Create an AVD with avdmanager, or launch one from Android Studio"
    emulator = shutil.which("emulator")
    if emulator is None and sdk.available and sdk.path:
        candidate = Path(sdk.path) / "emulator" / "emulator"
        if candidate.is_file():
            emulator = str(candidate)
    if emulator is None:
        return Capability(
            name="android-emulator",
            available=False,
            kind="executable",
            required_for=["dynamic-analysis"],
            install_hint=hint,
            detail="emulator binary not found",
        )
    avds: list[str] = []
    try:
        result = await run_command([emulator, "-list-avds"], timeout=VERSION_PROBE_TIMEOUT)
        avds = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except Exception as exc:  # noqa: BLE001
        logger.debug("capability.emulator_list_failed", error=str(exc))
    return Capability(
        name="android-emulator",
        available=True,
        kind="executable",
        path=emulator,
        required_for=["dynamic-analysis"],
        install_hint=hint,
        detail=(f"{len(avds)} AVD(s) defined: " + ", ".join(avds[:6]))
        if avds
        else "no AVDs defined",
    )


def _yara_capability() -> Capability:
    available, version = _python_module("yara")
    hint = "pip install yara-python  (" + _brew_hint("yara") + " for the CLI)"
    if available:
        return Capability(
            name="yara",
            available=True,
            kind="python",
            version=version,
            required_for=["yara-analyzer"],
            install_hint=hint,
            detail="yara-python bindings importable",
        )
    cli = shutil.which("yara")
    return Capability(
        name="yara",
        available=False,
        kind="python",
        required_for=["yara-analyzer"],
        install_hint=hint,
        detail=(
            "yara-python is not importable; the yara CLI was found but DroidScope "
            "uses the Python bindings"
            if cli
            else "yara-python is not installed; YARA scanning is skipped"
        ),
    )


async def collect_capabilities(settings: Settings | None = None) -> list[Capability]:
    """Discover every external dependency.  Probes run concurrently."""
    settings = settings or get_settings()

    androguard_ok, androguard_version = _python_module("androguard")
    pyelftools_ok, _ = _python_module("elftools")
    reportlab_ok, reportlab_version = _python_module("reportlab")

    executable_specs = [
        (
            "jadx",
            settings.jadx_path,
            ("jadx",),
            ["--version"],
            ["source-decompilation", "source-analyzers"],
            _brew_hint("jadx"),
        ),
        (
            "apktool",
            settings.apktool_path,
            ("apktool",),
            ["--version"],
            ["resource-decoding", "smali-browsing"],
            _brew_hint("apktool"),
        ),
        (
            "adb",
            settings.adb_path,
            ("adb",),
            ["version"],
            ["dynamic-analysis", "device-discovery"],
            _brew_hint("android-platform-tools", cask=True),
        ),
        (
            "frida",
            settings.frida_path,
            ("frida",),
            ["--version"],
            ["runtime-instrumentation"],
            "pip install frida-tools",
        ),
        (
            "mitmproxy",
            settings.mitmproxy_path,
            ("mitmdump", "mitmproxy"),
            ["--version"],
            ["network-capture"],
            _brew_hint("mitmproxy"),
        ),
        (
            "java",
            None,
            ("java",),
            ["-version"],
            ["jadx", "apktool", "ghidra"],
            _brew_hint("openjdk@17"),
        ),
    ]

    tasks = [
        _executable_capability(
            name,
            configured,
            names,
            version_args=version_args,
            required_for=required_for,
            install_hint=hint,
            optional=name not in {"java"},
        )
        for name, configured, names, version_args, required_for, hint in executable_specs
    ]
    tasks.append(_ghidra_capability(settings))
    tasks.append(_emulator_capability(settings))

    discovered = await asyncio.gather(*tasks, return_exceptions=True)

    capabilities: list[Capability] = [
        Capability(
            name="python",
            available=sys.version_info >= (3, 12),
            kind="python",
            version=platform.python_version(),
            path=sys.executable,
            required_for=["backend", "cli"],
            optional=False,
            detail=f"{platform.system()} {platform.machine()}",
        ),
        Capability(
            name="androguard",
            available=androguard_ok,
            kind="python",
            version=androguard_version,
            required_for=["apk-metadata", "manifest-analyzer", "dex-analysis"],
            install_hint="pip install androguard",
            optional=False,
            detail="primary APK/DEX parser" if androguard_ok else "metadata extraction unavailable",
        ),
        Capability(
            name="pyelftools",
            available=pyelftools_ok,
            kind="python",
            required_for=["native-analyzer"],
            install_hint="pip install pyelftools",
            detail="ELF header, symbol and hardening inspection",
        ),
        Capability(
            name="reportlab",
            available=reportlab_ok,
            kind="python",
            version=reportlab_version,
            required_for=["pdf-reports"],
            install_hint="pip install reportlab",
            detail="PDF report rendering",
        ),
        _yara_capability(),
    ]

    for item in discovered:
        if isinstance(item, Capability):
            capabilities.append(item)
        else:  # pragma: no cover - discovery must not raise
            logger.warning("capability.discovery_failed", error=str(item))

    capabilities.append(_android_sdk_capability(settings))
    return sorted(capabilities, key=lambda cap: cap.name)


async def capability_map(settings: Settings | None = None) -> dict[str, Capability]:
    return {cap.name: cap for cap in await collect_capabilities(settings)}


def analyzer_availability(caps: dict[str, Capability]) -> dict[str, bool]:
    """Translate raw tool availability into per-analyzer availability."""

    def ok(name: str) -> bool:
        cap = caps.get(name)
        return bool(cap and cap.available)

    return {
        "apk-metadata": ok("androguard"),
        "manifest-analyzer": ok("androguard"),
        "network-indicator-analyzer": True,
        "secret-analyzer": True,
        "source-analyzer": ok("jadx") and ok("java"),
        "resource-analyzer": ok("apktool") and ok("java"),
        "native-analyzer": ok("pyelftools"),
        "native-ghidra-analyzer": ok("ghidra") and ok("java"),
        "yara-analyzer": ok("yara"),
        "dynamic-analysis": ok("adb"),
        "runtime-instrumentation": ok("frida") and ok("adb"),
        "network-capture": ok("mitmproxy"),
        "pdf-reports": ok("reportlab"),
    }
