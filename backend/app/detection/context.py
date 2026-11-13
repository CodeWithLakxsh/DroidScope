"""Analysis contexts handed to detection rules.

A context is a read-only view over already-extracted data.  Rules never touch
the filesystem, the database or subprocesses directly, which is what makes them
cheap to unit test.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.analyzers.manifest.network_security_config import NetworkSecurityConfig
from app.core.logging import get_logger
from app.schemas.apk import ApkMetadata

logger = get_logger(__name__)

MAX_SOURCE_FILE_BYTES = 4 * 1024 * 1024
TEXT_SUFFIXES = {
    ".java", ".kt", ".smali", ".xml", ".json", ".properties", ".txt", ".js",
    ".html", ".yaml", ".yml", ".ini", ".cfg", ".graphql", ".sql", ".plist",
}


@dataclass(slots=True)
class ManifestContext:
    """Everything a manifest rule may inspect."""

    metadata: ApkMetadata
    manifest_xml: str | None = None
    network_security_config: NetworkSecurityConfig | None = None
    # Set when a source tree is available, so rules can soften a verdict that
    # would require code inspection to confirm.
    source_available: bool = False
    manifest_path: str = "AndroidManifest.xml"

    def manifest_line_of(self, needle: str) -> int | None:
        """Best-effort line number for a component or attribute in the manifest."""
        if not self.manifest_xml or not needle:
            return None
        short = needle.rsplit(".", 1)[-1]
        for index, line in enumerate(self.manifest_xml.splitlines(), start=1):
            if needle in line or (short and short in line):
                return index
        return None


@dataclass(slots=True)
class SourceFile:
    """A single decompiled or decoded file."""

    relative_path: str
    language: str  # java | kotlin | smali | resource | other
    text: str

    def lines(self) -> list[str]:
        return self.text.splitlines()

    def line_of_offset(self, offset: int) -> int:
        return self.text.count("\n", 0, offset) + 1

    def line_text(self, line_number: int) -> str:
        lines = self.text.splitlines()
        if 1 <= line_number <= len(lines):
            return lines[line_number - 1]
        return ""


class SourceIndex:
    """Lazy index over a decompiled source tree.

    Files are read on demand and cached only while a rule pass is running, so a
    large APK never has its whole source tree resident in memory at once.
    """

    def __init__(self, root: Path, *, max_file_bytes: int = MAX_SOURCE_FILE_BYTES) -> None:
        self.root = Path(root)
        self.max_file_bytes = max_file_bytes
        self._paths: list[Path] = []
        self._indexed = False
        self.skipped_large_files = 0
        self.total_bytes = 0

    def _ensure_index(self) -> None:
        if self._indexed:
            return
        if self.root.is_dir():
            for path in sorted(self.root.rglob("*")):
                if not path.is_file() or path.is_symlink():
                    continue
                if path.suffix.lower() not in TEXT_SUFFIXES:
                    continue
                size = path.stat().st_size
                if size > self.max_file_bytes:
                    self.skipped_large_files += 1
                    continue
                self.total_bytes += size
                self._paths.append(path)
        self._indexed = True

    @property
    def file_count(self) -> int:
        self._ensure_index()
        return len(self._paths)

    @staticmethod
    def language_for(path: Path) -> str:
        return {
            ".java": "java",
            ".kt": "kotlin",
            ".smali": "smali",
            ".xml": "resource",
            ".json": "resource",
            ".properties": "resource",
        }.get(path.suffix.lower(), "other")

    def iter_files(self, *, languages: set[str] | None = None) -> Iterator[SourceFile]:
        self._ensure_index()
        for path in self._paths:
            language = self.language_for(path)
            if languages and language not in languages:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:  # pragma: no cover
                logger.debug("source_index.read_failed", path=path.name, error=str(exc))
                continue
            yield SourceFile(
                relative_path=str(path.relative_to(self.root)),
                language=language,
                text=text,
            )

    def read(self, relative_path: str) -> str | None:
        candidate = (self.root / relative_path).resolve()
        if self.root.resolve() not in candidate.parents:
            return None
        if not candidate.is_file():
            return None
        return candidate.read_text(encoding="utf-8", errors="replace")

    def tree(self, *, max_entries: int = 20000) -> list[dict[str, Any]]:
        """Flat listing used by the API to build the code-explorer tree."""
        entries: list[dict[str, Any]] = []
        if not self.root.is_dir():
            return entries
        for path in sorted(self.root.rglob("*")):
            if len(entries) >= max_entries:
                break
            if path.is_symlink():
                continue
            relative = str(path.relative_to(self.root))
            if path.is_dir():
                entries.append({"path": relative, "type": "directory", "size": 0})
            elif path.is_file():
                entries.append(
                    {
                        "path": relative,
                        "type": "file",
                        "size": path.stat().st_size,
                        "language": self.language_for(path),
                    }
                )
        return entries


@dataclass(slots=True)
class SourceContext:
    """Context for rules that match against decompiled code and resources."""

    index: SourceIndex
    metadata: ApkMetadata
    # Package prefix of the application, used to tell first-party code from
    # bundled third-party libraries.
    app_package_path: str | None = None
    decompiler: str = "jadx"
    partial: bool = False
    notes: list[str] = field(default_factory=list)

    def is_third_party(self, relative_path: str) -> bool:
        """Heuristic: does this path belong to a well-known bundled library?"""
        normalised = relative_path.replace("\\", "/")
        return any(prefix in normalised for prefix in THIRD_PARTY_PREFIXES)


THIRD_PARTY_PREFIXES: tuple[str, ...] = (
    "androidx/",
    "android/support/",
    "com/google/android/gms/",
    "com/google/android/material/",
    "com/google/firebase/",
    "com/google/common/",
    "com/google/gson/",
    "com/google/protobuf/",
    "kotlin/",
    "kotlinx/",
    "okhttp3/",
    "okio/",
    "retrofit2/",
    "com/squareup/",
    "org/apache/",
    "org/jetbrains/",
    "io/reactivex/",
    "com/bumptech/glide/",
    "com/facebook/",
    "com/android/billingclient/",
    "j$/",
)


@dataclass(slots=True)
class NativeContext:
    """Context for rules over native (ELF) libraries."""

    libraries: list[dict[str, Any]] = field(default_factory=list)
    metadata: ApkMetadata | None = None
    ghidra_available: bool = False


@dataclass(slots=True)
class IndicatorContext:
    """Context for rules over extracted network indicators."""

    indicators: list[dict[str, Any]] = field(default_factory=list)
    metadata: ApkMetadata | None = None


def compile_patterns(patterns: list[str], *, flags: int = 0) -> list[re.Pattern[str]]:
    compiled: list[re.Pattern[str]] = []
    for pattern in patterns:
        try:
            compiled.append(re.compile(pattern, flags))
        except re.error as exc:
            logger.warning("pattern.invalid", pattern=pattern, error=str(exc))
    return compiled
