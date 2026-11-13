"""JADX integration: DEX to Java decompilation."""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path

from app.core.errors import AnalyzerTimeout
from app.core.logging import get_logger
from app.core.process import ProcessResult, run_command

logger = get_logger(__name__)


@dataclass(slots=True)
class DecompileResult:
    succeeded: bool
    output_dir: Path | None
    java_files: int = 0
    resource_files: int = 0
    total_bytes: int = 0
    duration_seconds: float = 0.0
    partial: bool = False
    returncode: int | None = None
    error: str | None = None
    warnings: list[str] = field(default_factory=list)
    command: list[str] = field(default_factory=list)


class JadxAdapter:
    """Runs jadx to produce a Java source tree from an APK.

    jadx routinely exits non-zero while still producing usable output (it
    reports per-class decompilation errors that way), so success is judged by
    what landed on disk, not by the exit status alone.
    """

    def __init__(self, *, jadx_path: str | Path, timeout_seconds: int = 1200) -> None:
        self.jadx_path = Path(jadx_path)
        self.timeout_seconds = timeout_seconds

    @property
    def available(self) -> bool:
        return self.jadx_path.is_file() or shutil.which(str(self.jadx_path)) is not None

    async def decompile(
        self,
        apk_path: Path,
        output_dir: Path,
        *,
        threads: int = 2,
        include_resources: bool = True,
        show_bad_code: bool = True,
    ) -> DecompileResult:
        # The child runs with its own cwd, so every path must be absolute.
        apk_path = Path(apk_path).resolve()
        output_dir = Path(output_dir).resolve()
        output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        command = [
            str(self.jadx_path),
            "--output-dir",
            str(output_dir),
            "--threads-count",
            str(max(1, threads)),
            # Keep going when individual classes fail rather than aborting.
            "--no-debug-info",
            "--escape-unicode",
        ]
        if show_bad_code:
            command.append("--show-bad-code")
        if not include_resources:
            command.append("--no-res")
        command.append(str(apk_path))

        try:
            result: ProcessResult = await run_command(
                command,
                timeout=self.timeout_seconds,
                cwd=output_dir.parent,
            )
        except AnalyzerTimeout as exc:
            counts = self._count(output_dir)
            # A timeout can still leave a partially written, useful tree.
            return DecompileResult(
                succeeded=counts["java"] > 0,
                output_dir=output_dir if counts["java"] else None,
                java_files=counts["java"],
                resource_files=counts["resources"],
                total_bytes=counts["bytes"],
                partial=True,
                error=str(exc),
                command=command,
            )

        counts = self._count(output_dir)
        warnings = self._collect_warnings(result)
        succeeded = counts["java"] > 0

        if not succeeded:
            return DecompileResult(
                succeeded=False,
                output_dir=None,
                returncode=result.returncode,
                duration_seconds=result.duration_seconds,
                error=(
                    f"jadx exited with status {result.returncode} and produced no Java "
                    f"sources: {(result.stderr or result.stdout)[-800:]}"
                ),
                warnings=warnings,
                command=command,
            )

        return DecompileResult(
            succeeded=True,
            output_dir=output_dir,
            java_files=counts["java"],
            resource_files=counts["resources"],
            total_bytes=counts["bytes"],
            duration_seconds=result.duration_seconds,
            # Non-zero exit with output means some classes failed to decompile.
            partial=result.returncode != 0,
            returncode=result.returncode,
            warnings=warnings,
            command=command,
        )

    @staticmethod
    def _count(output_dir: Path) -> dict[str, int]:
        java = resources = total_bytes = 0
        if not output_dir.is_dir():
            return {"java": 0, "resources": 0, "bytes": 0}
        for path in output_dir.rglob("*"):
            if not path.is_file() or path.is_symlink():
                continue
            size = path.stat().st_size
            total_bytes += size
            if path.suffix.lower() in {".java", ".kt"}:
                java += 1
            else:
                resources += 1
        return {"java": java, "resources": resources, "bytes": total_bytes}

    @staticmethod
    def _collect_warnings(result: ProcessResult, limit: int = 15) -> list[str]:
        warnings: list[str] = []
        for line in (result.stderr or "").splitlines():
            lowered = line.lower()
            if "error" in lowered or "warn" in lowered:
                cleaned = line.strip()[:300]
                if cleaned and cleaned not in warnings:
                    warnings.append(cleaned)
            if len(warnings) >= limit:
                break
        return warnings
