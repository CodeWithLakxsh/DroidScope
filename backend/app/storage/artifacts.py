"""Artifact storage abstraction.

Large analysis outputs (decompiled source trees, decoded resources, extracted
native libraries, generated reports) live on disk, not in the database.  Every
object is addressed by an opaque *storage key* -- a relative POSIX path beneath
the configured root.  Keys are validated so that a key derived from untrusted
input can never escape the root.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from app.core.config import Settings, get_settings
from app.core.errors import ValidationError
from app.core.logging import get_logger

logger = get_logger(__name__)

_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,127}$")
CHUNK_SIZE = 1024 * 1024


@dataclass(slots=True)
class StoredObject:
    storage_key: str
    size_bytes: int
    sha256: str


def sanitize_filename(name: str, *, default: str = "upload.apk") -> str:
    """Reduce an uploaded filename to something safe for display and storage.

    The result is never used to locate the stored object -- that is keyed by
    content hash -- but it is echoed back to clients and embedded in reports.
    """
    candidate = PurePosixPath(name.replace("\\", "/")).name
    candidate = candidate.replace("\x00", "")
    candidate = re.sub(r"[^A-Za-z0-9._\- ]", "_", candidate).strip(" ._")
    if not candidate or candidate in {".", ".."}:
        return default
    return candidate[:255]


class ArtifactStore:
    """Filesystem backed artifact store rooted at a single directory."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    # -- key handling ------------------------------------------------------
    def validate_key(self, key: str) -> str:
        if not key or key.startswith("/") or "\\" in key:
            raise ValidationError("invalid storage key")
        parts = PurePosixPath(key).parts
        if not parts or any(part in {"..", "."} for part in parts):
            raise ValidationError("invalid storage key")
        for part in parts:
            if not _SAFE_SEGMENT.match(part):
                raise ValidationError(f"invalid storage key segment: {part!r}")
        return "/".join(parts)

    def path_for(self, key: str) -> Path:
        """Resolve a key to an absolute path, guaranteed to be inside the root."""
        validated = self.validate_key(key)
        candidate = (self.root / validated).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise ValidationError("storage key escapes the artifact root")
        return candidate

    def exists(self, key: str) -> bool:
        return self.path_for(key).exists()

    def size_of(self, key: str) -> int:
        path = self.path_for(key)
        if path.is_file():
            return path.stat().st_size
        return sum(f.stat().st_size for f in path.rglob("*") if f.is_file())

    # -- writing -----------------------------------------------------------
    def write_stream(
        self, key: str, source: BinaryIO, *, max_bytes: int | None = None
    ) -> StoredObject:
        """Stream ``source`` to storage, hashing as it goes.

        The file is never fully buffered in memory, and the partial object is
        removed if the size limit is exceeded.
        """
        path = self.path_for(key)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        digest = hashlib.sha256()
        total = 0
        tmp_path = path.with_name(path.name + ".partial")
        try:
            with open(tmp_path, "wb") as handle:
                while True:
                    chunk = source.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    total += len(chunk)
                    if max_bytes is not None and total > max_bytes:
                        raise ValidationError(
                            f"object exceeds the maximum permitted size of {max_bytes} bytes"
                        )
                    digest.update(chunk)
                    handle.write(chunk)
            os.replace(tmp_path, path)
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise
        path.chmod(0o600)
        return StoredObject(
            storage_key=self.validate_key(key), size_bytes=total, sha256=digest.hexdigest()
        )

    def write_bytes(self, key: str, data: bytes) -> StoredObject:
        path = self.path_for(key)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(data)
        path.chmod(0o600)
        return StoredObject(
            storage_key=self.validate_key(key),
            size_bytes=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
        )

    def write_text(self, key: str, text: str) -> StoredObject:
        return self.write_bytes(key, text.encode("utf-8"))

    def adopt_file(self, key: str, source: Path, *, move: bool = True) -> StoredObject:
        """Place an already-written local file into the store."""
        path = self.path_for(key)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if move:
            shutil.move(str(source), path)
        else:
            shutil.copy2(source, path)
        path.chmod(0o600)
        return StoredObject(
            storage_key=self.validate_key(key),
            size_bytes=path.stat().st_size,
            sha256=self.sha256_of(key),
        )

    def adopt_directory(self, key: str, source: Path, *, move: bool = True) -> StoredObject:
        target = self.path_for(key)
        if target.exists():
            shutil.rmtree(target)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if move:
            shutil.move(str(source), target)
        else:
            shutil.copytree(source, target)
        return StoredObject(
            storage_key=self.validate_key(key), size_bytes=self.size_of(key), sha256=""
        )

    def ensure_directory(self, key: str) -> Path:
        path = self.path_for(key)
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        return path

    # -- reading -----------------------------------------------------------
    def read_bytes(self, key: str, *, max_bytes: int | None = None) -> bytes:
        path = self.path_for(key)
        if not path.is_file():
            raise ValidationError("artifact not found")
        if max_bytes is not None and path.stat().st_size > max_bytes:
            with open(path, "rb") as handle:
                return handle.read(max_bytes)
        return path.read_bytes()

    def read_text(self, key: str, *, max_bytes: int | None = None) -> str:
        return self.read_bytes(key, max_bytes=max_bytes).decode("utf-8", errors="replace")

    def sha256_of(self, key: str) -> str:
        digest = hashlib.sha256()
        with open(self.path_for(key), "rb") as handle:
            for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def delete(self, key: str) -> None:
        path = self.path_for(key)
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
        else:
            path.unlink(missing_ok=True)

    # -- key builders ------------------------------------------------------
    @staticmethod
    def apk_key(sha256: str) -> str:
        return f"apks/{sha256[:2]}/{sha256}.apk"

    @staticmethod
    def scan_key(scan_id: str, *parts: str) -> str:
        return "/".join(["scans", scan_id, *parts])

    @staticmethod
    def report_key(report_id: str, filename: str) -> str:
        return f"reports/{report_id}/{sanitize_filename(filename, default='report.bin')}"


_store: ArtifactStore | None = None


def get_artifact_store(settings: Settings | None = None) -> ArtifactStore:
    global _store
    if _store is None:
        settings = settings or get_settings()
        settings.ensure_directories()
        _store = ArtifactStore(settings.artifacts_dir)
    return _store


def reset_artifact_store() -> None:
    global _store
    _store = None
