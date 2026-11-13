"""Shared pytest fixtures.

Each test gets its own data directory and SQLite database, so tests never share
state and can run in any order.
"""

from __future__ import annotations

import asyncio
import zipfile
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"
VULNERABLE_APK = FIXTURES_DIR / "vulnerable-app.apk"
SECURE_APK = FIXTURES_DIR / "secure-app.apk"


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(autouse=True)
def isolated_environment(tmp_path_factory, monkeypatch) -> Iterator[Path]:
    """Point every component at a per-test data directory."""
    data_dir = tmp_path_factory.mktemp("droidscope-data")
    monkeypatch.setenv("DROIDSCOPE_DATA_DIR", str(data_dir))
    monkeypatch.setenv("DROIDSCOPE_ENVIRONMENT", "test")
    monkeypatch.setenv("DROIDSCOPE_DATABASE_URL", f"sqlite+aiosqlite:///{data_dir / 'test.db'}")
    monkeypatch.setenv("DROIDSCOPE_LOG_LEVEL", "ERROR")

    from app.core.config import reset_settings_cache
    from app.storage.artifacts import reset_artifact_store

    reset_settings_cache()
    reset_artifact_store()

    yield data_dir

    async def dispose() -> None:
        from app.database.session import dispose_engine

        await dispose_engine()

    asyncio.run(dispose())
    reset_settings_cache()
    reset_artifact_store()


@pytest.fixture
def settings():
    from app.core.config import get_settings

    settings = get_settings()
    settings.ensure_directories()
    return settings


@pytest.fixture
async def session() -> AsyncIterator:
    from app.database.session import create_all, get_sessionmaker

    await create_all()
    maker = get_sessionmaker()
    async with maker() as session:
        yield session


@pytest.fixture(scope="session")
def vulnerable_apk() -> Path:
    if not VULNERABLE_APK.is_file():
        pytest.skip(
            "the vulnerable fixture APK has not been built; run "
            "scripts/development/build_fixture_apk.sh"
        )
    return VULNERABLE_APK


@pytest.fixture(scope="session")
def secure_apk() -> Path:
    if not SECURE_APK.is_file():
        pytest.skip(
            "the secure fixture APK has not been built; run "
            "scripts/development/build_fixture_apk.sh secure"
        )
    return SECURE_APK


# --- synthetic archives for validation tests -------------------------------


def _write_zip(path: Path, entries: dict[str, bytes], **kwargs) -> Path:
    with zipfile.ZipFile(path, "w", **kwargs) as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)
    return path


@pytest.fixture
def minimal_apk_bytes() -> bytes:
    """A structurally valid (if semantically empty) APK-shaped archive."""
    import io

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00placeholder")
        archive.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 64)
        archive.writestr("META-INF/CERT.RSA", b"not-a-real-signature")
    return buffer.getvalue()


@pytest.fixture
def make_zip(tmp_path):
    def factory(name: str, entries: dict[str, bytes], **kwargs) -> Path:
        return _write_zip(tmp_path / name, entries, **kwargs)

    return factory
