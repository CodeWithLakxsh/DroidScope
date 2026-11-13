"""APK validation and hostile-archive defences.

An uploaded APK is untrusted input that will be handed to several third-party
parsers.  Everything in this module runs *before* that happens.

Checks performed
----------------
1. The file begins with a local ZIP header and the central directory parses.
2. The archive looks like an APK: it contains ``AndroidManifest.xml`` and at
   least one ``classes*.dex`` or native library.
3. Entry count, total uncompressed size and per-entry compression ratio are
   bounded (zip bomb defence).
4. Entry names are rejected if absolute, traversing (``..``), containing NUL or
   backslashes, or if the entry is a symlink (unix mode ``S_IFLNK``).
5. Only stored/deflated entries are accepted; exotic compression methods that
   some parsers mishandle are refused.

Extraction uses the validated entry list and re-verifies the destination path
after resolution, so a crafted name cannot escape the target directory.
"""

from __future__ import annotations

import stat
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from app.core.config import Settings, get_settings
from app.core.errors import ApkValidationError, ArchiveSecurityError
from app.core.logging import get_logger

logger = get_logger(__name__)

ZIP_LOCAL_HEADER = b"PK\x03\x04"
ZIP_EMPTY_ARCHIVE = b"PK\x05\x06"
DEX_MAGIC = b"dex\n"

# zipfile constants for the compression methods we accept.
ALLOWED_COMPRESSION = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
COMPRESSION_NAMES = {
    zipfile.ZIP_STORED: "stored",
    zipfile.ZIP_DEFLATED: "deflate",
    zipfile.ZIP_BZIP2: "bzip2",
    zipfile.ZIP_LZMA: "lzma",
}

REQUIRED_ENTRY = "AndroidManifest.xml"
# Entries that may never be written to disk during extraction.
DANGEROUS_NAMES = {".", "..", ""}


@dataclass(slots=True)
class ArchiveEntry:
    name: str
    compressed_size: int
    uncompressed_size: int
    compression: int
    crc: int
    is_dir: bool
    external_attr: int

    @property
    def ratio(self) -> float:
        if self.compressed_size <= 0:
            return 0.0 if self.uncompressed_size == 0 else float("inf")
        return self.uncompressed_size / self.compressed_size

    @property
    def is_symlink(self) -> bool:
        return stat.S_ISLNK(self.external_attr >> 16)


@dataclass(slots=True)
class ApkValidationResult:
    valid: bool
    file_size: int
    entry_count: int
    total_uncompressed: int
    dex_files: list[str] = field(default_factory=list)
    native_libraries: list[str] = field(default_factory=list)
    has_manifest: bool = False
    has_signature_block: bool = False
    signature_schemes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    checks: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "file_size": self.file_size,
            "entry_count": self.entry_count,
            "total_uncompressed": self.total_uncompressed,
            "dex_files": self.dex_files,
            "native_libraries": self.native_libraries[:200],
            "native_library_count": len(self.native_libraries),
            "has_manifest": self.has_manifest,
            "has_signature_block": self.has_signature_block,
            "signature_schemes": self.signature_schemes,
            "warnings": self.warnings,
            "checks": self.checks,
        }


def _reject(message: str, **details) -> None:
    raise ArchiveSecurityError(message, details=details)


def check_entry_name(name: str) -> None:
    """Reject entry names that are unsafe to materialise on disk."""
    if "\x00" in name:
        _reject("archive entry name contains a NUL byte")
    if "\\" in name:
        _reject("archive entry name contains a backslash path separator", entry=name[:120])
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        _reject("archive entry name is absolute", entry=name[:120])
    parts = PurePosixPath(name).parts
    if any(part == ".." for part in parts):
        _reject("archive entry name traverses outside the archive root", entry=name[:120])


def read_magic(path: Path, length: int = 4) -> bytes:
    with open(path, "rb") as handle:
        return handle.read(length)


def validate_apk(path: Path, settings: Settings | None = None) -> ApkValidationResult:
    """Validate an APK on disk.  Raises :class:`ApkValidationError` on rejection."""
    settings = settings or get_settings()
    path = Path(path)

    if not path.is_file():
        raise ApkValidationError("uploaded file is missing")

    file_size = path.stat().st_size
    if file_size == 0:
        raise ApkValidationError("uploaded file is empty")
    if file_size > settings.max_upload_bytes:
        raise ApkValidationError(
            f"file is larger than the configured limit of {settings.max_upload_bytes} bytes",
            details={"file_size": file_size, "limit": settings.max_upload_bytes},
        )

    magic = read_magic(path)
    if magic == ZIP_EMPTY_ARCHIVE:
        raise ApkValidationError("archive contains no entries")
    if magic != ZIP_LOCAL_HEADER:
        raise ApkValidationError(
            "file is not a ZIP archive (an APK must start with a local ZIP header)",
            details={"magic": magic.hex()},
        )

    result = ApkValidationResult(
        valid=False, file_size=file_size, entry_count=0, total_uncompressed=0
    )
    result.checks["magic"] = "pass"

    try:
        with zipfile.ZipFile(path) as archive:
            try:
                bad = archive.testzip()
            except (RuntimeError, NotImplementedError) as exc:
                # Encrypted or unsupported-compression entries land here.
                raise ApkValidationError(
                    f"archive cannot be read: {exc}", details={"reason": str(exc)}
                ) from exc
            if bad is not None:
                result.warnings.append(f"CRC mismatch for entry {bad[:120]!r}")
                result.checks["crc"] = "warn"
            else:
                result.checks["crc"] = "pass"

            infos = archive.infolist()
            result.entry_count = len(infos)
            if not infos:
                raise ApkValidationError("archive contains no entries")
            if len(infos) > settings.max_archive_entries:
                _reject(
                    "archive declares more entries than the configured limit",
                    entry_count=len(infos),
                    limit=settings.max_archive_entries,
                )
            result.checks["entry_count"] = "pass"

            entries = _inspect_entries(infos, settings, result)
            result.checks["entry_names"] = "pass"
            result.checks["compression"] = "pass"
            result.checks["decompression_limits"] = "pass"

            _check_apk_shape(archive, entries, result)
    except zipfile.BadZipFile as exc:
        raise ApkValidationError(
            f"archive is malformed: {exc}", details={"reason": str(exc)}
        ) from exc

    result.valid = True
    return result


def _inspect_entries(
    infos: list[zipfile.ZipInfo], settings: Settings, result: ApkValidationResult
) -> list[ArchiveEntry]:
    entries: list[ArchiveEntry] = []
    total = 0
    names: set[str] = set()

    for info in infos:
        check_entry_name(info.filename)
        entry = ArchiveEntry(
            name=info.filename,
            compressed_size=info.compress_size,
            uncompressed_size=info.file_size,
            compression=info.compress_type,
            crc=info.CRC,
            is_dir=info.is_dir(),
            external_attr=info.external_attr,
        )

        if entry.is_symlink:
            _reject(
                "archive contains a symbolic link entry, which is not permitted",
                entry=entry.name[:120],
            )
        if entry.compression not in ALLOWED_COMPRESSION:
            _reject(
                "archive entry uses an unsupported compression method",
                entry=entry.name[:120],
                method=COMPRESSION_NAMES.get(entry.compression, str(entry.compression)),
            )
        if entry.name in names:
            # Duplicate names are a known APK-confusion trick; the behaviour
            # depends on which parser reads the archive, so flag it loudly.
            result.warnings.append(f"duplicate archive entry: {entry.name[:120]!r}")
        names.add(entry.name)

        total += entry.uncompressed_size
        if total > settings.max_uncompressed_bytes:
            _reject(
                "archive expands beyond the configured decompression limit",
                total_uncompressed=total,
                limit=settings.max_uncompressed_bytes,
            )
        # A highly compressible large entry is the classic zip bomb shape.
        if (
            entry.uncompressed_size > 16 * 1024 * 1024
            and entry.ratio > settings.max_compression_ratio
        ):
            _reject(
                "archive entry exceeds the maximum permitted compression ratio",
                entry=entry.name[:120],
                ratio=round(entry.ratio, 1),
                limit=settings.max_compression_ratio,
            )
        entries.append(entry)

    result.total_uncompressed = total
    return entries


def _check_apk_shape(
    archive: zipfile.ZipFile, entries: list[ArchiveEntry], result: ApkValidationResult
) -> None:
    """Confirm the archive is structurally an APK, not merely a ZIP file."""
    names = {entry.name for entry in entries}

    result.has_manifest = REQUIRED_ENTRY in names
    if not result.has_manifest:
        raise ApkValidationError(
            "archive does not contain AndroidManifest.xml, so it is not an APK",
            details={"entry_count": len(entries)},
        )
    result.checks["manifest_present"] = "pass"

    result.dex_files = sorted(
        name for name in names if name.startswith("classes") and name.endswith(".dex")
    )
    result.native_libraries = sorted(
        name for name in names if name.startswith("lib/") and name.endswith(".so")
    )

    if not result.dex_files and not result.native_libraries:
        raise ApkValidationError(
            "archive contains neither a DEX file nor a native library",
            details={"entry_count": len(entries)},
        )
    result.checks["code_present"] = "pass"

    # Verify the first DEX really is a DEX rather than a renamed file.
    if result.dex_files:
        with archive.open(result.dex_files[0]) as handle:
            header = handle.read(8)
        if not header.startswith(DEX_MAGIC):
            raise ApkValidationError(
                f"{result.dex_files[0]} does not carry a DEX magic header",
                details={"magic": header[:8].hex()},
            )
        result.checks["dex_magic"] = "pass"

    v1 = [
        n
        for n in names
        if n.startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC"))
    ]
    if v1:
        result.signature_schemes.append("v1-jar")
    # v2/v3 signatures live in the APK Signing Block, which sits between the
    # last entry and the central directory; detect it by its magic string.
    if _has_apk_signing_block(archive):
        result.signature_schemes.append("v2+-signing-block")
    result.has_signature_block = bool(result.signature_schemes)
    if not result.has_signature_block:
        result.warnings.append(
            "no APK signature was detected; an unsigned APK cannot be installed by Android"
        )
    result.checks["signature_presence"] = "pass" if result.has_signature_block else "warn"

    if len(result.dex_files) > 1:
        result.warnings.append(f"multidex archive with {len(result.dex_files)} DEX files")


def _has_apk_signing_block(archive: zipfile.ZipFile) -> bool:
    """Look for the 'APK Sig Block 42' magic used by signature schemes v2/v3."""
    try:
        handle = archive.fp
        if handle is None:  # pragma: no cover
            return False
        position = handle.tell()
        handle.seek(0)
        data = handle.read()
        handle.seek(position)
        return b"APK Sig Block 42" in data
    except (OSError, ValueError):  # pragma: no cover
        return False


def safe_extract(
    source: Path,
    destination: Path,
    *,
    settings: Settings | None = None,
    members: list[str] | None = None,
    max_total_bytes: int | None = None,
) -> list[str]:
    """Extract an archive safely and return the list of written members.

    Every destination path is re-validated after resolution, directories are
    created explicitly, and nothing is extracted through a symlinked parent.
    """
    settings = settings or get_settings()
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    budget = max_total_bytes if max_total_bytes is not None else settings.max_uncompressed_bytes

    written: list[str] = []
    total = 0
    with zipfile.ZipFile(source) as archive:
        wanted = members if members is not None else [i.filename for i in archive.infolist()]
        for name in wanted:
            try:
                info = archive.getinfo(name)
            except KeyError:
                continue
            check_entry_name(info.filename)
            if stat.S_ISLNK(info.external_attr >> 16):
                _reject("refusing to extract a symbolic link entry", entry=info.filename[:120])

            target = (destination / info.filename).resolve()
            if destination not in target.parents and target != destination:
                _reject(
                    "archive entry resolves outside the extraction root", entry=info.filename[:120]
                )

            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
                continue

            total += info.file_size
            if total > budget:
                _reject("extraction exceeded the permitted total size", limit=budget)

            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if target.parent.is_symlink():  # pragma: no cover - defensive
                _reject("extraction target parent is a symbolic link", entry=info.filename[:120])
            with archive.open(info) as src, open(target, "wb") as dst:
                remaining = info.file_size
                while remaining > 0:
                    chunk = src.read(min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    dst.write(chunk)
                    remaining -= len(chunk)
            target.chmod(0o600)
            written.append(info.filename)
    return written
