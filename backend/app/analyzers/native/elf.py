"""ELF inspection for bundled native libraries.

This is a genuine, self-contained inspection built on pyelftools: architecture,
symbols, dependencies and the linker/compiler hardening flags.  It runs whether
or not Ghidra is installed -- when Ghidra is absent DroidScope reports exactly
this, and never implies that decompilation took place.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from app.core.logging import get_logger

logger = get_logger(__name__)

MAX_LIBRARY_BYTES = 256 * 1024 * 1024
MAX_SYMBOLS = 400
MAX_STRINGS_PER_CATEGORY = 25
MIN_STRING_LENGTH = 6

MACHINE_NAMES = {
    "EM_ARM": "ARM 32-bit",
    "EM_AARCH64": "ARM 64-bit",
    "EM_386": "x86 32-bit",
    "EM_X86_64": "x86-64",
    "EM_MIPS": "MIPS",
    "EM_RISCV": "RISC-V",
}

# Categories of embedded string worth surfacing to an analyst.
STRING_CATEGORIES: dict[str, re.Pattern[bytes]] = {
    "root detection": re.compile(
        rb"(?i)(/system/bin/su|/system/xbin/su|magisk|supersu|busybox|/sbin/su|"
        rb"test-keys|ro\.debuggable|ro\.secure)"
    ),
    "debugger and emulator checks": re.compile(
        rb"(?i)(ptrace|TracerPid|/proc/self/status|goldfish|ranchu|qemu|"
        rb"ro\.kernel\.qemu|generic_x86|isDebuggerConnected)"
    ),
    "shell and process execution": re.compile(
        rb"(?i)(/system/bin/sh|/bin/sh|execve|popen|system\(|/proc/self/maps)"
    ),
    "network endpoints": re.compile(rb"(?i)(https?://[A-Za-z0-9.\-]{4,120})"),
    # Acronyms are matched case-sensitively and on word boundaries: a
    # case-insensitive "RSA" matches inside "ampersand".
    "cryptographic references": re.compile(
        rb"(\bAES(?:-(?:128|192|256))?\b|\bRSA\b|\bHMAC\b|\bSHA-?(?:1|256|512)\b"
        rb"|\bPBKDF2\b|EVP_[A-Za-z_]+|(?i:OpenSSL|BoringSSL|libsodium|mbedtls))"
    ),
    "packing and obfuscation": re.compile(
        rb"(?i)(UPX!|\.upx|jiagu|bangcle|ijiami|secneo|dexprotector|VirboxProtector)"
    ),
}

PRINTABLE_STRING = re.compile(rb"[\x20-\x7e]{%d,256}" % MIN_STRING_LENGTH)


@dataclass(slots=True)
class HardeningReport:
    """Linker and compiler mitigations detected in the binary."""

    relro: str = "unknown"  # none | partial | full | unknown
    stack_canary: bool | None = None
    nx: bool | None = None
    pie: bool | None = None
    fortify: bool | None = None
    rpath: list[str] = field(default_factory=list)
    runpath: list[str] = field(default_factory=list)
    text_relocations: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ElfAnalysis:
    path: str
    abi: str
    size_bytes: int
    architecture: str = "unknown"
    machine: str = "unknown"
    bits: int | None = None
    endianness: str | None = None
    elf_type: str | None = None
    entry_point: int | None = None
    stripped: bool | None = None
    build_id: str | None = None
    soname: str | None = None
    imported_symbols: list[str] = field(default_factory=list)
    exported_symbols: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    jni_functions: list[str] = field(default_factory=list)
    hardening: dict[str, Any] = field(default_factory=dict)
    suspicious_strings: dict[str, list[str]] = field(default_factory=dict)
    symbol_counts: dict[str, int] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ElfInspector:
    """Inspect ELF shared objects without executing them."""

    def inspect_apk_libraries(self, apk_path: Path, workspace: Path) -> list[ElfAnalysis]:
        results: list[ElfAnalysis] = []
        extract_dir = workspace / "native"
        extract_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

        try:
            with zipfile.ZipFile(apk_path) as archive:
                entries = [
                    info
                    for info in archive.infolist()
                    if not info.is_dir()
                    and info.filename.startswith("lib/")
                    and info.filename.endswith(".so")
                ]
                for info in entries:
                    abi = info.filename.split("/")[1] if "/" in info.filename else "unknown"
                    if info.file_size > MAX_LIBRARY_BYTES:
                        results.append(
                            ElfAnalysis(
                                path=info.filename,
                                abi=abi,
                                size_bytes=info.file_size,
                                error="library exceeds the maximum inspectable size",
                            )
                        )
                        continue
                    # Flatten the name so extraction cannot nest directories.
                    safe_name = info.filename.replace("/", "_")
                    target = extract_dir / safe_name
                    try:
                        with archive.open(info) as src, open(target, "wb") as dst:
                            dst.write(src.read())
                    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                        results.append(
                            ElfAnalysis(
                                path=info.filename,
                                abi=abi,
                                size_bytes=info.file_size,
                                error=f"entry could not be extracted: {exc}",
                            )
                        )
                        continue
                    analysis = self.inspect(target, display_path=info.filename, abi=abi)
                    analysis.size_bytes = info.file_size
                    results.append(analysis)
        except (OSError, zipfile.BadZipFile) as exc:
            logger.warning("elf.archive_unreadable", error=str(exc))
        return results

    def inspect(
        self, path: Path, *, display_path: str | None = None, abi: str = "unknown"
    ) -> ElfAnalysis:
        analysis = ElfAnalysis(
            path=display_path or path.name,
            abi=abi,
            size_bytes=path.stat().st_size if path.is_file() else 0,
        )
        try:
            from elftools.common.exceptions import ELFError
            from elftools.elf.elffile import ELFFile
        except ImportError as exc:  # pragma: no cover - guarded by capabilities
            analysis.error = f"pyelftools unavailable: {exc}"
            return analysis

        try:
            with open(path, "rb") as handle:
                elf = ELFFile(handle)
                self._read_header(elf, analysis)
                self._read_dynamic(elf, analysis)
                self._read_symbols(elf, analysis)
                self._read_hardening(elf, analysis)
            analysis.suspicious_strings = self._extract_strings(path)
        except ELFError as exc:
            analysis.error = f"not a valid ELF object: {exc}"
        except (OSError, ValueError, KeyError, AttributeError) as exc:
            analysis.error = f"{type(exc).__name__}: {exc}"
        return analysis

    # -- sections ----------------------------------------------------------
    @staticmethod
    def _read_header(elf, analysis: ElfAnalysis) -> None:  # noqa: ANN001
        header = elf.header
        machine = header["e_machine"]
        analysis.machine = machine
        analysis.architecture = MACHINE_NAMES.get(machine, machine)
        analysis.elf_type = header["e_type"]
        analysis.entry_point = header["e_entry"]
        analysis.bits = elf.elfclass
        analysis.endianness = "little" if elf.little_endian else "big"

    def _read_dynamic(self, elf, analysis: ElfAnalysis) -> None:  # noqa: ANN001
        dynamic = elf.get_section_by_name(".dynamic")
        if dynamic is None or not hasattr(dynamic, "iter_tags"):
            return
        hardening = analysis.hardening.setdefault("_raw", {})
        for tag in dynamic.iter_tags():
            entry = tag.entry.d_tag
            if entry == "DT_NEEDED":
                analysis.dependencies.append(str(tag.needed))
            elif entry == "DT_SONAME":
                analysis.soname = str(getattr(tag, "soname", "") or "")
            elif entry == "DT_RPATH":
                hardening.setdefault("rpath", []).append(str(getattr(tag, "rpath", "")))
            elif entry == "DT_RUNPATH":
                hardening.setdefault("runpath", []).append(str(getattr(tag, "runpath", "")))
            elif entry == "DT_BIND_NOW":
                hardening["bind_now"] = True
            elif entry == "DT_FLAGS":
                hardening["flags"] = int(tag.entry.d_val)
            elif entry == "DT_FLAGS_1":
                hardening["flags_1"] = int(tag.entry.d_val)
            elif entry == "DT_TEXTREL":
                hardening["textrel"] = True

    def _read_symbols(self, elf, analysis: ElfAnalysis) -> None:  # noqa: ANN001
        from elftools.elf.sections import SymbolTableSection

        imported: list[str] = []
        exported: list[str] = []
        jni: list[str] = []
        has_symtab = False

        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            if section.name == ".symtab":
                has_symtab = True
            if section.name not in {".dynsym", ".symtab"}:
                continue
            for symbol in section.iter_symbols():
                name = symbol.name
                if not name:
                    continue
                info = symbol["st_info"]
                shndx = symbol["st_shndx"]
                if shndx == "SHN_UNDEF":
                    imported.append(name)
                elif info["bind"] in {"STB_GLOBAL", "STB_WEAK"} and info["type"] == "STT_FUNC":
                    exported.append(name)
                    if name.startswith("Java_") or name in {"JNI_OnLoad", "JNI_OnUnload"}:
                        jni.append(name)

        analysis.symbol_counts = {
            "imported": len(set(imported)),
            "exported": len(set(exported)),
            "jni": len(set(jni)),
        }
        analysis.imported_symbols = sorted(set(imported))[:MAX_SYMBOLS]
        analysis.exported_symbols = sorted(set(exported))[:MAX_SYMBOLS]
        analysis.jni_functions = sorted(set(jni))[:MAX_SYMBOLS]
        analysis.stripped = not has_symtab

    def _read_hardening(self, elf, analysis: ElfAnalysis) -> None:  # noqa: ANN001
        raw = analysis.hardening.get("_raw", {})
        report = HardeningReport()

        has_relro_segment = False
        stack_executable: bool | None = None
        for segment in elf.iter_segments():
            seg_type = segment.header.p_type
            if seg_type == "PT_GNU_RELRO":
                has_relro_segment = True
            elif seg_type == "PT_GNU_STACK":
                stack_executable = bool(segment.header.p_flags & 0x1)  # PF_X

        bind_now = bool(raw.get("bind_now")) or bool(int(raw.get("flags", 0)) & 0x8)  # DF_BIND_NOW
        bind_now = bind_now or bool(int(raw.get("flags_1", 0)) & 0x1)  # DF_1_NOW
        if has_relro_segment and bind_now:
            report.relro = "full"
        elif has_relro_segment:
            report.relro = "partial"
        else:
            report.relro = "none"

        # NX: an absent PT_GNU_STACK on Android means the loader applies the
        # default, which is non-executable; only an explicit executable flag is
        # reported as missing NX.
        report.nx = True if stack_executable is None else not stack_executable

        symbols = set(analysis.imported_symbols) | set(analysis.exported_symbols)
        report.stack_canary = any(
            name in symbols
            for name in ("__stack_chk_fail", "__stack_chk_guard", "__stack_smash_handler")
        )
        report.fortify = any(name.endswith("_chk") for name in symbols)
        report.pie = analysis.elf_type in {"ET_DYN"}
        report.rpath = raw.get("rpath", [])
        report.runpath = raw.get("runpath", [])
        report.text_relocations = bool(raw.get("textrel"))

        analysis.hardening = report.to_dict()

    @staticmethod
    def _extract_strings(path: Path) -> dict[str, list[str]]:
        try:
            data = path.read_bytes()
        except OSError:
            return {}
        categorised: dict[str, list[str]] = {}
        for category, pattern in STRING_CATEGORIES.items():
            matches: list[str] = []
            seen: set[str] = set()
            for match in pattern.finditer(data):
                # Expand to the printable run that *contains* the match, so the
                # reported string is the one that actually matched rather than
                # an unrelated neighbouring string.
                value = _containing_run(data, match.start(), match.end()).strip()[:160]
                if value in seen:
                    continue
                seen.add(value)
                matches.append(value)
                if len(matches) >= MAX_STRINGS_PER_CATEGORY:
                    break
            if matches:
                categorised[category] = matches
        return categorised


def _containing_run(data: bytes, start: int, end: int, *, max_span: int = 256) -> str:
    """Return the printable byte run surrounding ``data[start:end]``."""
    left = start
    limit = max(start - max_span, 0)
    while left > limit and 0x20 <= data[left - 1] <= 0x7E:
        left -= 1
    right = end
    ceiling = min(end + max_span, len(data))
    while right < ceiling and 0x20 <= data[right] <= 0x7E:
        right += 1
    return data[left:right].decode("utf-8", errors="replace")
