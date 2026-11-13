"""APK metadata extraction.

Androguard owns the hard parts (binary AXML decoding, resource resolution,
signature block parsing); this module drives it, converts the result into
:class:`~app.schemas.apk.ApkMetadata`, and degrades predictably when a parser
fails.  A failure is always recorded in ``parse_errors`` and never silently
turned into an "absent" value.
"""

from __future__ import annotations

import hashlib
import os
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.analyzers.apk.validation import ApkValidationResult
from app.analyzers.manifest.parser import ManifestParseError, ParsedManifest
from app.core.logging import get_logger
from app.schemas.apk import (
    ApkMetadata,
    CertificateInfo,
    DexEntry,
    NativeLibraryEntry,
)

logger = get_logger(__name__)

ABI_DIRECTORIES = {
    "armeabi-v7a": "ARM 32-bit",
    "arm64-v8a": "ARM 64-bit",
    "x86": "x86 32-bit",
    "x86_64": "x86 64-bit",
    "armeabi": "ARM 32-bit (legacy)",
    "mips": "MIPS",
    "riscv64": "RISC-V 64-bit",
}

MAX_ICON_BYTES = 2 * 1024 * 1024


def _silence_androguard_logging() -> None:
    """Androguard is extremely chatty on malformed input; keep our logs usable."""
    try:
        from loguru import logger as loguru_logger

        loguru_logger.disable("androguard")
    except Exception:  # noqa: BLE001 - optional dependency of androguard
        pass
    import logging

    for name in ("androguard", "androguard.axml", "androguard.apk", "androguard.core"):
        logging.getLogger(name).setLevel(logging.ERROR)


def load_androguard_apk(path: Path):  # noqa: ANN201 - androguard type is optional
    _silence_androguard_logging()
    try:
        from androguard.core.apk import APK  # androguard >= 4
    except ImportError:  # pragma: no cover - androguard < 4 layout
        from androguard.core.bytecodes.apk import APK  # type: ignore[no-redef]
    return APK(str(path))


@dataclass(slots=True)
class MetadataExtraction:
    metadata: ApkMetadata
    manifest_xml: str | None
    icon_bytes: bytes | None = None
    icon_name: str | None = None


class ApkMetadataExtractor:
    """Extract normalised metadata from an APK file."""

    name = "apk-metadata"
    version = "1"

    def extract(
        self, apk_path: Path, validation: ApkValidationResult | None = None
    ) -> MetadataExtraction:
        metadata = ApkMetadata()
        metadata.parser_version = self._androguard_version()
        manifest_xml: str | None = None
        icon_bytes: bytes | None = None
        icon_name: str | None = None

        apk = None
        try:
            apk = load_androguard_apk(apk_path)
        except Exception as exc:  # noqa: BLE001 - third-party parser on hostile input
            metadata.parse_errors.append(f"androguard could not open the APK: {exc}")
            metadata.partial = True
            logger.warning("metadata.androguard_open_failed", error=str(exc))

        if apk is not None:
            manifest_xml = self._decode_manifest(apk, metadata)
            if manifest_xml:
                self._apply_manifest(manifest_xml, metadata)
            self._apply_androguard_fallbacks(apk, metadata)
            self._apply_certificates(apk, metadata)
            icon_bytes, icon_name = self._extract_icon(apk, metadata)

        # The archive listing is parsed directly: it must work even when
        # androguard fails, and it is the authoritative view of file contents.
        self._apply_archive_contents(apk_path, metadata, validation)

        if metadata.package_name is None:
            metadata.partial = True
            if not metadata.parse_errors:
                metadata.parse_errors.append("package name could not be determined")
        return MetadataExtraction(
            metadata=metadata,
            manifest_xml=manifest_xml,
            icon_bytes=icon_bytes,
            icon_name=icon_name,
        )

    # -- internals ---------------------------------------------------------
    @staticmethod
    def _androguard_version() -> str | None:
        try:
            import androguard

            return getattr(androguard, "__version__", None)
        except Exception:  # noqa: BLE001
            return None

    def _decode_manifest(self, apk, metadata: ApkMetadata) -> str | None:  # noqa: ANN001
        try:
            axml = apk.get_android_manifest_axml()
            if axml is None:
                metadata.parse_errors.append("AndroidManifest.xml could not be decoded")
                return None
            raw = axml.get_xml()
            if isinstance(raw, bytes):
                return raw.decode("utf-8", errors="replace")
            return str(raw)
        except Exception as exc:  # noqa: BLE001
            metadata.parse_errors.append(f"AndroidManifest.xml decoding failed: {exc}")
            metadata.partial = True
            logger.warning("metadata.manifest_decode_failed", error=str(exc))
            return None

    def _apply_manifest(self, manifest_xml: str, metadata: ApkMetadata) -> None:
        try:
            parsed = ParsedManifest(manifest_xml)
        except ManifestParseError as exc:
            metadata.parse_errors.append(str(exc))
            metadata.partial = True
            return

        min_sdk, target_sdk, max_sdk = parsed.sdk_versions()
        metadata.package_name = parsed.package
        metadata.version_name = parsed.version_name()
        metadata.version_code = parsed.version_code()
        metadata.min_sdk = min_sdk
        metadata.target_sdk = target_sdk
        metadata.max_sdk = max_sdk
        metadata.compile_sdk = parsed.compile_sdk()
        metadata.install_location = parsed.install_location()
        metadata.shared_user_id = parsed.shared_user_id()
        metadata.app_label = parsed.application_label()
        metadata.application_flags = parsed.application_flags()
        metadata.requested_permissions = parsed.requested_permissions()
        metadata.declared_permissions = parsed.declared_permissions()
        metadata.components = parsed.components()
        metadata.metadata_entries = parsed.metadata_entries()
        metadata.features = parsed.features()
        metadata.queries = parsed.queries()
        metadata.icon_entry = parsed.icon_reference()

    def _apply_androguard_fallbacks(self, apk, metadata: ApkMetadata) -> None:  # noqa: ANN001
        """Fill gaps using androguard's resource-aware getters."""
        def safe(call, default=None):  # noqa: ANN001
            try:
                return call()
            except Exception:  # noqa: BLE001
                return default

        if not metadata.package_name:
            metadata.package_name = safe(apk.get_package)
        if not metadata.app_label:
            # Resolves @string/app_name against the resource table.
            label = safe(apk.get_app_name)
            metadata.app_label = label or None
        if metadata.version_name is None:
            metadata.version_name = safe(apk.get_androidversion_name)
        if metadata.version_code is None:
            code = safe(apk.get_androidversion_code)
            try:
                metadata.version_code = int(code) if code is not None else None
            except (TypeError, ValueError):
                metadata.version_code = None
        if metadata.min_sdk is None:
            metadata.min_sdk = _to_int(safe(apk.get_min_sdk_version))
        if metadata.target_sdk is None:
            metadata.target_sdk = _to_int(safe(apk.get_target_sdk_version))
        if metadata.max_sdk is None:
            metadata.max_sdk = _to_int(safe(apk.get_max_sdk_version))
        if not metadata.components:
            # Last resort: component names without attributes.  Marked partial
            # because export/permission state is unknown in this path.
            for kind, getter in (
                ("activity", apk.get_activities),
                ("service", apk.get_services),
                ("receiver", apk.get_receivers),
                ("provider", apk.get_providers),
            ):
                for name in safe(getter, []) or []:
                    metadata.components.append(
                        _minimal_component(kind, name)
                    )
            if metadata.components:
                metadata.partial = True
                metadata.parse_errors.append(
                    "component attributes were unavailable; export state is unknown"
                )

    def _apply_certificates(self, apk, metadata: ApkMetadata) -> None:  # noqa: ANN001
        schemes: list[str] = []
        try:
            if apk.is_signed_v1():
                schemes.append("v1")
            if apk.is_signed_v2():
                schemes.append("v2")
            if apk.is_signed_v3():
                schemes.append("v3")
        except Exception as exc:  # noqa: BLE001
            metadata.parse_errors.append(f"signature scheme detection failed: {exc}")
        metadata.signature_schemes = schemes

        certificates: list[CertificateInfo] = []
        try:
            raw_certs = apk.get_certificates()
        except Exception as exc:  # noqa: BLE001
            metadata.parse_errors.append(f"certificate parsing failed: {exc}")
            raw_certs = []

        for cert in raw_certs or []:
            try:
                certificates.append(_certificate_info(cert))
            except Exception as exc:  # noqa: BLE001
                metadata.parse_errors.append(f"a certificate could not be summarised: {exc}")
        metadata.certificates = certificates

    def _extract_icon(self, apk, metadata: ApkMetadata) -> tuple[bytes | None, str | None]:  # noqa: ANN001
        """Read the launcher icon, but only when it is a small raster/vector file."""
        try:
            icon_path = apk.get_app_icon()
        except Exception as exc:  # noqa: BLE001
            logger.debug("metadata.icon_lookup_failed", error=str(exc))
            return None, None
        if not icon_path:
            return None, None
        suffix = Path(icon_path).suffix.lower()
        if suffix not in {".png", ".webp", ".jpg", ".jpeg", ".xml"}:
            return None, None
        try:
            data = apk.get_file(icon_path)
        except Exception:  # noqa: BLE001
            return None, None
        if not data or len(data) > MAX_ICON_BYTES:
            return None, None
        # Adaptive icons are AXML vector drawables, which a browser cannot show.
        if suffix == ".xml":
            return None, icon_path
        metadata.icon_entry = icon_path
        return data, icon_path

    def _apply_archive_contents(
        self, apk_path: Path, metadata: ApkMetadata, validation: ApkValidationResult | None
    ) -> None:
        dex_entries: list[DexEntry] = []
        native: list[NativeLibraryEntry] = []
        abis: set[str] = set()
        asset_count = 0
        asset_bytes = 0
        resource_count = 0
        entry_count = 0

        try:
            with zipfile.ZipFile(apk_path) as archive:
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    entry_count += 1
                    name = info.filename
                    if name.startswith("classes") and name.endswith(".dex"):
                        dex_entries.append(
                            DexEntry(
                                name=name,
                                size_bytes=info.file_size,
                                sha256=_hash_entry(archive, info),
                            )
                        )
                    elif name.startswith("lib/") and name.endswith(".so"):
                        parts = name.split("/")
                        abi = parts[1] if len(parts) > 2 else "unknown"
                        abis.add(abi)
                        native.append(
                            NativeLibraryEntry(path=name, abi=abi, size_bytes=info.file_size)
                        )
                    elif name.startswith("assets/"):
                        asset_count += 1
                        asset_bytes += info.file_size
                    elif name.startswith("res/"):
                        resource_count += 1
        except (OSError, zipfile.BadZipFile) as exc:
            metadata.parse_errors.append(f"archive contents could not be listed: {exc}")
            metadata.partial = True
            return

        metadata.dex_files = sorted(dex_entries, key=lambda d: d.name)
        metadata.native_libraries = sorted(native, key=lambda n: n.path)
        metadata.abis = sorted(abis)
        metadata.entry_count = entry_count
        metadata.asset_summary = {
            "asset_files": asset_count,
            "asset_bytes": asset_bytes,
            "resource_files": resource_count,
            "abi_descriptions": {abi: ABI_DIRECTORIES.get(abi, "unknown ABI") for abi in sorted(abis)},
        }
        if validation and validation.signature_schemes and not metadata.signature_schemes:
            metadata.signature_schemes = validation.signature_schemes


def _minimal_component(kind: str, name: str):  # noqa: ANN201
    from app.schemas.apk import Component

    return Component(kind=kind, name=name, exported=False, exported_implied=True)


def _to_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _hash_entry(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> str | None:
    if info.file_size > 256 * 1024 * 1024:
        return None
    digest = hashlib.sha256()
    try:
        with archive.open(info) as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except Exception:  # noqa: BLE001
        return None
    return digest.hexdigest()


def _certificate_info(cert) -> CertificateInfo:  # noqa: ANN001 - asn1crypto x509.Certificate
    sha256_fp = hashlib.sha256(cert.dump()).hexdigest()
    sha1_fp = hashlib.sha1(cert.dump()).hexdigest()  # noqa: S324 - fingerprint, not a MAC
    subject = cert.subject.human_friendly if hasattr(cert, "subject") else None
    issuer = cert.issuer.human_friendly if hasattr(cert, "issuer") else None

    key_size = None
    public_key_algo = None
    try:
        public_key_algo = cert.public_key.algorithm
        key_size = cert.public_key.bit_size
    except Exception:  # noqa: BLE001
        pass

    not_before = not_after = None
    try:
        validity = cert["tbs_certificate"]["validity"]
        not_before = validity["not_before"].native.isoformat()
        not_after = validity["not_after"].native.isoformat()
    except Exception:  # noqa: BLE001
        pass

    serial = None
    try:
        serial = format(cert.serial_number, "x")
    except Exception:  # noqa: BLE001
        pass

    return CertificateInfo(
        subject=subject,
        issuer=issuer,
        serial_number=serial,
        not_before=not_before,
        not_after=not_after,
        signature_algorithm=getattr(cert, "signature_algo", None),
        public_key_algorithm=public_key_algo,
        key_size_bits=key_size,
        sha256_fingerprint=sha256_fp,
        sha1_fingerprint=sha1_fp,
        is_self_signed=(subject == issuer) if subject and issuer else None,
    )
