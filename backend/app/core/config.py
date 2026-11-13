"""Application configuration.

All settings are environment driven with secure defaults.  Values that point at
executables are validated as existing files to avoid turning a settings field
into an arbitrary command execution primitive.
"""

from __future__ import annotations

import os
import shutil
from enum import StrEnum
from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    development = "development"
    test = "test"
    production = "production"


class LogLevel(StrEnum):
    debug = "DEBUG"
    info = "INFO"
    warning = "WARNING"
    error = "ERROR"


DEFAULT_DATA_DIR = Path(os.environ.get("DROIDSCOPE_DATA_DIR", Path.home() / ".droidscope"))


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="DROIDSCOPE_",
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    environment: Environment = Environment.development
    log_level: LogLevel = LogLevel.info
    log_json: bool = False

    # --- paths -------------------------------------------------------------
    data_dir: Path = DEFAULT_DATA_DIR
    database_url: str = ""

    # --- api ---------------------------------------------------------------
    api_prefix: str = "/api/v1"
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])
    # When set, every mutating API call must present this key via X-API-Key.
    api_key: str | None = None
    require_auth: bool = False

    # --- uploads -----------------------------------------------------------
    max_upload_bytes: int = 512 * 1024 * 1024
    # Maximum total uncompressed size permitted when inspecting an archive.
    max_uncompressed_bytes: int = 4 * 1024 * 1024 * 1024
    # Maximum per-entry compression ratio before the archive is rejected.
    max_compression_ratio: float = 200.0
    max_archive_entries: int = 60_000

    # --- analysis ----------------------------------------------------------
    analysis_concurrency: int = 2
    analyzer_timeout_seconds: int = 900
    scan_timeout_seconds: int = 3600
    decompile_timeout_seconds: int = 1200
    ghidra_timeout_seconds: int = 1800
    artifact_retention_days: int = 30
    reuse_identical_scans: bool = True

    # --- tools (explicit overrides; discovery is used when unset) ----------
    jadx_path: Path | None = None
    apktool_path: Path | None = None
    adb_path: Path | None = None
    frida_path: Path | None = None
    # Directory holding the declarative detection rules. Unset means "discover
    # it", which matters for a packaged install where the repository layout is
    # not present next to the installed package.
    rules_dir: Path | None = None
    yara_rules_dir: Path | None = None
    ghidra_home: Path | None = None
    android_sdk_root: Path | None = None
    mitmproxy_path: Path | None = None

    # --- dynamic analysis --------------------------------------------------
    # Dynamic analysis is opt-in: it installs and launches an application on a
    # device and must never be enabled implicitly by a static scan profile.
    dynamic_analysis_enabled: bool = False
    dynamic_allow_physical_devices: bool = False
    dynamic_session_timeout_seconds: int = 600

    # --- jobs --------------------------------------------------------------
    queue_backend: str = "database"  # database | redis
    redis_url: str | None = None
    worker_poll_interval_seconds: float = 1.0

    # --- reports -----------------------------------------------------------
    redact_secrets_in_reports: bool = True
    report_organisation: str = "DroidScope"

    @field_validator(
        "jadx_path",
        "apktool_path",
        "adb_path",
        "frida_path",
        "mitmproxy_path",
        mode="after",
    )
    @classmethod
    def _validate_executable(cls, value: Path | None) -> Path | None:
        if value is None:
            return None
        resolved = Path(value).expanduser()
        if not resolved.is_absolute():
            located = shutil.which(str(resolved))
            if located is None:
                raise ValueError(f"tool path {value!r} could not be resolved to an executable")
            resolved = Path(located)
        if not resolved.is_file():
            raise ValueError(f"tool path {resolved} does not exist")
        if not os.access(resolved, os.X_OK):
            raise ValueError(f"tool path {resolved} is not executable")
        return resolved

    @field_validator("data_dir", mode="after")
    @classmethod
    def _expand_data_dir(cls, value: Path) -> Path:
        return Path(value).expanduser().resolve()

    @property
    def artifacts_dir(self) -> Path:
        return self.data_dir / "artifacts"

    @property
    def uploads_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def tmp_dir(self) -> Path:
        return self.data_dir / "tmp"

    @property
    def resolved_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite+aiosqlite:///{self.data_dir / 'droidscope.db'}"

    def ensure_directories(self) -> None:
        for path in (
            self.data_dir,
            self.artifacts_dir,
            self.uploads_dir,
            self.reports_dir,
            self.tmp_dir,
        ):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)


@lru_cache
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    get_settings.cache_clear()
