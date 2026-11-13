"""Apktool integration: resource decoding and smali disassembly."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from app.core.errors import AnalyzerTimeout
from app.core.logging import get_logger
from app.core.process import run_command

logger = get_logger(__name__)


@dataclass(slots=True)
class DecodeResult:
    succeeded: bool
    output_dir: Path | None
    smali_files: int = 0
    resource_files: int = 0
    total_bytes: int = 0
    duration_seconds: float = 0.0
    returncode: int | None = None
    error: str | None = None
    warnings: list[str] = field(default_factory=list)


class ApktoolAdapter:
    """Runs ``apktool d`` to recover smali and decoded resources."""

    def __init__(self, *, apktool_path: str | Path, timeout_seconds: int = 900) -> None:
        self.apktool_path = Path(apktool_path)
        self.timeout_seconds = timeout_seconds

    @property
    def available(self) -> bool:
        return self.apktool_path.is_file()

    async def decode(
        self, apk_path: Path, output_dir: Path, *, decode_sources: bool = True
    ) -> DecodeResult:
        # The child runs with its own cwd, so every path must be absolute.
        apk_path = Path(apk_path).resolve()
        output_dir = Path(output_dir).resolve()
        output_dir.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # apktool refuses to write into an existing directory without --force.
        command = [
            str(self.apktool_path),
            "d",
            str(apk_path),
            "--output",
            str(output_dir),
            "--force",
            # Framework files are fetched from the device otherwise; keep the
            # run offline and deterministic.
            "--no-debug-info",
        ]
        if not decode_sources:
            command.append("--no-src")

        try:
            result = await run_command(command, timeout=self.timeout_seconds, cwd=output_dir.parent)
        except AnalyzerTimeout as exc:
            counts = self._count(output_dir)
            return DecodeResult(
                succeeded=counts["smali"] > 0 or counts["resources"] > 0,
                output_dir=output_dir if counts["resources"] else None,
                smali_files=counts["smali"],
                resource_files=counts["resources"],
                total_bytes=counts["bytes"],
                error=str(exc),
            )

        counts = self._count(output_dir)
        succeeded = counts["smali"] > 0 or counts["resources"] > 0
        warnings = [
            line.strip()[:300]
            for line in (result.stderr or "").splitlines()
            if line.strip().lower().startswith(("w:", "warning", "error"))
        ][:15]

        if not succeeded:
            return DecodeResult(
                succeeded=False,
                output_dir=None,
                returncode=result.returncode,
                duration_seconds=result.duration_seconds,
                error=(
                    f"apktool exited with status {result.returncode} and produced no "
                    f"output: {(result.stderr or result.stdout)[-800:]}"
                ),
                warnings=warnings,
            )

        return DecodeResult(
            succeeded=True,
            output_dir=output_dir,
            smali_files=counts["smali"],
            resource_files=counts["resources"],
            total_bytes=counts["bytes"],
            duration_seconds=result.duration_seconds,
            returncode=result.returncode,
            warnings=warnings,
        )

    @staticmethod
    def _count(output_dir: Path) -> dict[str, int]:
        smali = resources = total_bytes = 0
        if not output_dir.is_dir():
            return {"smali": 0, "resources": 0, "bytes": 0}
        for path in output_dir.rglob("*"):
            if not path.is_file() or path.is_symlink():
                continue
            total_bytes += path.stat().st_size
            if path.suffix.lower() == ".smali":
                smali += 1
            else:
                resources += 1
        return {"smali": smali, "resources": resources, "bytes": total_bytes}
