"""APK ingestion.

The upload path is a trust boundary, so the order of operations matters:

1. stream the upload to a temporary file with a hard size cap, hashing as it
   goes -- the file is never held in memory;
2. validate the archive before any parser touches it;
3. only then extract metadata, which hands the file to androguard;
4. store the file under a content-addressed key, so a hostile filename never
   influences a path.

Duplicate uploads are detected by SHA-256 and reuse the existing record rather
than storing the same bytes twice.
"""

from __future__ import annotations

import hashlib
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.analyzers.apk.metadata import ApkMetadataExtractor
from app.analyzers.apk.validation import ApkValidationResult, validate_apk
from app.core.config import Settings, get_settings
from app.core.errors import ApkValidationError
from app.core.logging import get_logger
from app.models import ApkArtifact, Application, AuditEvent
from app.storage.artifacts import ArtifactStore, get_artifact_store, sanitize_filename

logger = get_logger(__name__)

CHUNK_SIZE = 1024 * 1024


@dataclass(slots=True)
class IngestResult:
    apk: ApkArtifact
    created: bool
    validation: ApkValidationResult | None = None


class ApkService:
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

    async def ingest_stream(
        self, source: BinaryIO, *, filename: str, actor: str = "local"
    ) -> IngestResult:
        """Validate and store an uploaded APK supplied as a byte stream."""
        safe_name = sanitize_filename(filename)
        self.settings.ensure_directories()

        # delete=False because the file is handed to validators and parsers
        # after this block closes it; the finally clause removes it.
        tmp_handle = tempfile.NamedTemporaryFile(  # noqa: SIM115
            delete=False, dir=self.settings.tmp_dir, suffix=".upload"
        )
        tmp_path = Path(tmp_handle.name)
        digest = hashlib.sha256()
        sha1 = hashlib.sha1()  # noqa: S324 - identity, not authentication
        md5 = hashlib.md5()  # noqa: S324 - identity, not authentication
        total = 0

        try:
            with tmp_handle:
                while True:
                    chunk = source.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > self.settings.max_upload_bytes:
                        raise ApkValidationError(
                            "upload exceeds the maximum permitted size",
                            details={
                                "limit_bytes": self.settings.max_upload_bytes,
                                "received_bytes": total,
                            },
                        )
                    digest.update(chunk)
                    sha1.update(chunk)
                    md5.update(chunk)
                    tmp_handle.write(chunk)

            sha256 = digest.hexdigest()
            existing = await self.get_by_sha256(sha256)
            if existing is not None:
                logger.info("apk.duplicate", sha256=sha256[:16], apk_id=existing.id)
                await self._audit(actor, "apk.upload.duplicate", existing.id, {"sha256": sha256})
                return IngestResult(apk=existing, created=False)

            # Validation happens before any third-party parser sees the file.
            validation = validate_apk(tmp_path, self.settings)

            extraction = ApkMetadataExtractor().extract(tmp_path, validation)
            metadata = extraction.metadata

            storage_key = self.store.apk_key(sha256)
            self.store.adopt_file(storage_key, tmp_path, move=True)

            manifest_key: str | None = None
            if extraction.manifest_xml:
                manifest_key = self.store.write_text(
                    f"apks/{sha256[:2]}/{sha256}.manifest.xml", extraction.manifest_xml
                ).storage_key
                metadata.manifest_storage_key = manifest_key

            icon_key: str | None = None
            if extraction.icon_bytes and extraction.icon_name:
                suffix = Path(extraction.icon_name).suffix.lower().lstrip(".") or "png"
                icon_key = self.store.write_bytes(
                    f"apks/{sha256[:2]}/{sha256}.icon.{suffix}", extraction.icon_bytes
                ).storage_key

            application = await self._ensure_application(metadata.package_name, metadata.app_label)

            apk = ApkArtifact(
                application_id=application.id if application else None,
                sha256=sha256,
                sha1=sha1.hexdigest(),
                md5=md5.hexdigest(),
                file_size=total,
                original_filename=safe_name,
                storage_key=storage_key,
                package_name=metadata.package_name,
                app_label=metadata.app_label,
                version_name=metadata.version_name,
                version_code=metadata.version_code,
                min_sdk=metadata.min_sdk,
                target_sdk=metadata.target_sdk,
                compile_sdk=metadata.compile_sdk,
                apk_metadata=metadata.model_dump(mode="json"),
                validation=validation.to_dict(),
                icon_storage_key=icon_key,
                metadata_error="; ".join(metadata.parse_errors) if metadata.parse_errors else None,
            )
            self.session.add(apk)
            await self.session.flush()
            await self._audit(
                actor,
                "apk.upload",
                apk.id,
                {
                    "sha256": sha256,
                    "size": total,
                    "package": metadata.package_name,
                    "partial_metadata": metadata.partial,
                },
            )
            await self.session.commit()

            logger.info(
                "apk.ingested",
                apk_id=apk.id,
                package=metadata.package_name,
                size=total,
                sha256=sha256[:16],
            )
            return IngestResult(apk=apk, created=True, validation=validation)
        finally:
            tmp_path.unlink(missing_ok=True)

    async def ingest_file(self, path: Path, *, actor: str = "local") -> IngestResult:
        with open(path, "rb") as handle:
            return await self.ingest_stream(handle, filename=path.name, actor=actor)

    async def get_by_sha256(self, sha256: str) -> ApkArtifact | None:
        result = await self.session.execute(select(ApkArtifact).where(ApkArtifact.sha256 == sha256))
        return result.scalar_one_or_none()

    async def get(self, apk_id: str) -> ApkArtifact | None:
        return await self.session.get(ApkArtifact, apk_id)

    async def _ensure_application(
        self, package_name: str | None, label: str | None
    ) -> Application | None:
        if not package_name:
            return None
        result = await self.session.execute(
            select(Application).where(Application.package_name == package_name)
        )
        application = result.scalar_one_or_none()
        if application is None:
            application = Application(package_name=package_name, label=label)
            self.session.add(application)
            await self.session.flush()
        elif label and not application.label:
            application.label = label
        return application

    async def _audit(self, actor: str, action: str, resource_id: str | None, detail: dict) -> None:
        self.session.add(
            AuditEvent(
                actor=actor,
                action=action,
                resource_type="apk",
                resource_id=resource_id,
                detail=detail,
            )
        )
