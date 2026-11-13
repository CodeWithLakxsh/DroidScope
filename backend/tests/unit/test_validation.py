"""APK validation and hostile-archive defences."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from app.analyzers.apk.validation import (
    check_entry_name,
    safe_extract,
    validate_apk,
)
from app.core.errors import ApkValidationError, ArchiveSecurityError


class TestEntryNames:
    @pytest.mark.parametrize(
        "name",
        [
            "../escape.txt",
            "a/../../escape.txt",
            "/absolute/path.txt",
            "C:windows.txt",
            "dir\\file.txt",
            "with\x00nul.txt",
        ],
    )
    def test_rejects_unsafe_names(self, name: str) -> None:
        with pytest.raises(ArchiveSecurityError):
            check_entry_name(name)

    @pytest.mark.parametrize(
        "name",
        ["classes.dex", "res/values/strings.xml", "lib/arm64-v8a/libfoo.so", "a.b.c"],
    )
    def test_accepts_normal_names(self, name: str) -> None:
        check_entry_name(name)


class TestValidateApk:
    def test_accepts_the_fixture_apk(self, vulnerable_apk: Path, settings) -> None:
        result = validate_apk(vulnerable_apk, settings)
        assert result.valid
        assert result.has_manifest
        assert "classes.dex" in result.dex_files
        assert result.signature_schemes  # the fixture is signed
        assert result.checks["dex_magic"] == "pass"

    def test_rejects_a_non_zip(self, tmp_path: Path, settings) -> None:
        path = tmp_path / "fake.apk"
        path.write_bytes(b"this is definitely not a zip archive")
        with pytest.raises(ApkValidationError, match="not a ZIP archive"):
            validate_apk(path, settings)

    def test_rejects_an_empty_file(self, tmp_path: Path, settings) -> None:
        path = tmp_path / "empty.apk"
        path.write_bytes(b"")
        with pytest.raises(ApkValidationError, match="empty"):
            validate_apk(path, settings)

    def test_rejects_a_zip_without_a_manifest(self, make_zip, settings) -> None:
        path = make_zip("plain.apk", {"hello.txt": b"hello"})
        with pytest.raises(ApkValidationError, match="AndroidManifest"):
            validate_apk(path, settings)

    def test_rejects_an_archive_with_no_code(self, make_zip, settings) -> None:
        path = make_zip("nocode.apk", {"AndroidManifest.xml": b"\x03\x00manifest"})
        with pytest.raises(ApkValidationError, match="neither a DEX file nor a native library"):
            validate_apk(path, settings)

    def test_rejects_a_renamed_file_posing_as_dex(self, make_zip, settings) -> None:
        path = make_zip(
            "fakedex.apk",
            {
                "AndroidManifest.xml": b"\x03\x00manifest",
                "classes.dex": b"PK\x03\x04 this is a zip, not a dex",
            },
        )
        with pytest.raises(ApkValidationError, match="DEX magic"):
            validate_apk(path, settings)

    def test_rejects_traversing_entry(self, tmp_path: Path, settings) -> None:
        path = tmp_path / "traversal.apk"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"\x03\x00manifest")
            archive.writestr("classes.dex", b"dex\n035\x00")
            archive.writestr("../../../etc/passwd", b"root:x:0:0")
        with pytest.raises(ArchiveSecurityError, match="traverses"):
            validate_apk(path, settings)

    def test_rejects_unsupported_compression(self, tmp_path: Path, settings) -> None:
        path = tmp_path / "lzma.apk"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"\x03\x00manifest")
            archive.writestr("classes.dex", b"dex\n035\x00")
            archive.writestr(
                zipfile.ZipInfo("payload.bin"), b"x" * 4096, compress_type=zipfile.ZIP_LZMA
            )
        with pytest.raises(ApkValidationError):
            validate_apk(path, settings)

    def test_rejects_a_zip_bomb_by_ratio(self, tmp_path: Path, settings) -> None:
        """A highly compressible large entry must be refused."""
        path = tmp_path / "bomb.apk"
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            archive.writestr("AndroidManifest.xml", b"\x03\x00manifest")
            archive.writestr("classes.dex", b"dex\n035\x00")
            # 64 MB of zeros compresses to a few kilobytes.
            archive.writestr("bomb.bin", b"\x00" * (64 * 1024 * 1024))
        with pytest.raises(ArchiveSecurityError, match="compression ratio"):
            validate_apk(path, settings)

    def test_rejects_total_expansion_over_limit(self, tmp_path: Path, settings) -> None:
        settings.max_uncompressed_bytes = 1024
        path = tmp_path / "big.apk"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"\x03\x00manifest")
            archive.writestr("classes.dex", b"dex\n035\x00")
            archive.writestr("data.bin", b"x" * 4096)
        with pytest.raises(ArchiveSecurityError, match="decompression limit"):
            validate_apk(path, settings)

    def test_rejects_too_many_entries(self, tmp_path: Path, settings) -> None:
        settings.max_archive_entries = 5
        path = tmp_path / "many.apk"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"\x03\x00manifest")
            archive.writestr("classes.dex", b"dex\n035\x00")
            for index in range(10):
                archive.writestr(f"file{index}.txt", b"x")
        with pytest.raises(ArchiveSecurityError, match="more entries"):
            validate_apk(path, settings)

    def test_rejects_an_oversized_file(self, tmp_path: Path, settings) -> None:
        settings.max_upload_bytes = 100
        path = tmp_path / "big.apk"
        path.write_bytes(b"PK\x03\x04" + b"x" * 500)
        with pytest.raises(ApkValidationError, match="larger than"):
            validate_apk(path, settings)

    def test_warns_about_duplicate_entries(self, tmp_path: Path, settings) -> None:
        path = tmp_path / "dupe.apk"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"\x03\x00manifest")
            archive.writestr("classes.dex", b"dex\n035\x00")
            archive.writestr("dup.txt", b"first")
            archive.writestr("dup.txt", b"second")
        result = validate_apk(path, settings)
        assert any("duplicate" in warning for warning in result.warnings)


class TestSafeExtract:
    def test_extracts_normal_entries(self, make_zip, tmp_path: Path, settings) -> None:
        archive = make_zip("ok.zip", {"a.txt": b"alpha", "dir/b.txt": b"beta"})
        destination = tmp_path / "out"
        written = safe_extract(archive, destination, settings=settings)
        assert sorted(written) == ["a.txt", "dir/b.txt"]
        assert (destination / "dir" / "b.txt").read_bytes() == b"beta"

    def test_refuses_to_escape_the_destination(self, tmp_path: Path, settings) -> None:
        archive = tmp_path / "evil.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr("../escape.txt", b"nope")
        with pytest.raises(ArchiveSecurityError):
            safe_extract(archive, tmp_path / "out", settings=settings)
        assert not (tmp_path / "escape.txt").exists()

    def test_enforces_a_total_size_budget(self, make_zip, tmp_path: Path, settings) -> None:
        archive = make_zip("big.zip", {"a.bin": b"x" * 5000})
        with pytest.raises(ArchiveSecurityError, match="permitted total size"):
            safe_extract(archive, tmp_path / "out", settings=settings, max_total_bytes=100)


class TestRuleDirectoryResolution:
    """A packaged install has no repository layout beside it.

    This was a real defect: `droidscope rules validate` inside the container
    image reported "0 valid, 0 invalid" and exited successfully, so a
    deployment that could not find its rules looked healthy while detecting
    nothing.
    """

    def test_finds_rules_in_a_checkout(self) -> None:
        from app.detection.pattern_rules import resolve_rules_dir

        assert (resolve_rules_dir() / "crypto").is_dir()

    def test_environment_variable_takes_precedence(self, tmp_path, monkeypatch) -> None:
        from app.core.config import reset_settings_cache
        from app.detection.pattern_rules import resolve_rules_dir

        custom = tmp_path / "custom-rules"
        custom.mkdir()
        monkeypatch.setenv("DROIDSCOPE_RULES_DIR", str(custom))
        reset_settings_cache()
        try:
            assert resolve_rules_dir() == custom
        finally:
            reset_settings_cache()

    def test_an_explicit_argument_wins(self, tmp_path) -> None:
        from app.detection.pattern_rules import resolve_rules_dir

        assert resolve_rules_dir(tmp_path) == tmp_path

    def test_missing_directory_yields_no_rules_rather_than_raising(self, tmp_path) -> None:
        from app.detection.pattern_rules import validate_rules_dir

        specs, errors = validate_rules_dir(tmp_path / "does-not-exist")
        assert specs == []
        assert errors == []

    def test_yara_directory_follows_the_rules_directory(self, tmp_path, monkeypatch) -> None:
        from app.analyzers.yara.analyzer import YaraRuleSet
        from app.core.config import reset_settings_cache

        monkeypatch.setenv("DROIDSCOPE_RULES_DIR", str(tmp_path))
        reset_settings_cache()
        try:
            assert YaraRuleSet().rules_dir == tmp_path / "yara"
        finally:
            reset_settings_cache()
