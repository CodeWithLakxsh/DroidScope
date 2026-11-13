"""Safe subprocess execution.

Rules enforced here:

* commands are always argument vectors -- never a shell string, so values taken
  from an uploaded APK can never be interpreted by a shell;
* the executable must resolve to a real file before launch;
* every call has a timeout and the whole process group is killed on expiry;
* the child environment is minimal and network proxies are stripped;
* stdout/stderr are captured with a size cap so a chatty tool cannot exhaust
  worker memory.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import signal
import time
from dataclasses import dataclass
from pathlib import Path

from app.core.errors import AnalyzerTimeout, ToolUnavailableError
from app.core.logging import get_logger

logger = get_logger(__name__)

MAX_CAPTURE_BYTES = 8 * 1024 * 1024


@dataclass(slots=True)
class ProcessResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def resolve_executable(candidate: str | Path | None, *, names: tuple[str, ...] = ()) -> Path | None:
    """Resolve an explicit path, else search PATH for the given names."""
    if candidate:
        path = Path(candidate).expanduser()
        if path.is_file() and os.access(path, os.X_OK):
            return path
        located = shutil.which(str(candidate))
        if located:
            return Path(located)
    for name in names:
        located = shutil.which(name)
        if located:
            return Path(located)
    return None


def build_child_env(extra: dict[str, str] | None = None, *, allow_network: bool = False) -> dict[str, str]:
    """Construct a minimal environment for an analysis child process."""
    keep = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "JAVA_HOME", "USER")
    env = {key: os.environ[key] for key in keep if key in os.environ}
    env.setdefault("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
    # Static analysis tooling has no business reaching the network.
    if not allow_network:
        env["no_proxy"] = "*"
        env["NO_PROXY"] = "*"
        for var in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            env.pop(var, None)
    if extra:
        env.update(extra)
    return env


async def run_command(
    command: list[str | Path],
    *,
    timeout: float,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    allow_network: bool = False,
    check: bool = False,
    stdin_data: bytes | None = None,
) -> ProcessResult:
    """Run ``command`` without a shell and return its captured output."""
    if not command:
        raise ValueError("command must not be empty")

    argv = [str(part) for part in command]
    executable = Path(argv[0])
    if not executable.is_absolute():
        located = shutil.which(argv[0])
        if located is None:
            raise ToolUnavailableError(f"executable {argv[0]!r} was not found on PATH")
        argv[0] = located
    elif not executable.is_file():
        raise ToolUnavailableError(f"executable {executable.name!r} is not installed")

    child_env = build_child_env(env, allow_network=allow_network)
    started = time.monotonic()

    process = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE if stdin_data is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(cwd) if cwd else None,
        env=child_env,
        start_new_session=True,  # own process group, so a timeout kills children too
    )

    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            process.communicate(input=stdin_data), timeout=timeout
        )
    except TimeoutError:
        _terminate_group(process)
        try:
            await asyncio.wait_for(process.wait(), timeout=10)
        except TimeoutError:  # pragma: no cover - defensive
            pass
        duration = time.monotonic() - started
        logger.warning("process.timeout", tool=Path(argv[0]).name, timeout=timeout)
        raise AnalyzerTimeout(
            f"{Path(argv[0]).name} exceeded its {timeout:.0f}s timeout",
            details={"tool": Path(argv[0]).name, "timeout_seconds": timeout,
                     "duration_seconds": round(duration, 3)},
        ) from None
    except asyncio.CancelledError:
        _terminate_group(process)
        raise

    truncated = len(stdout_b) > MAX_CAPTURE_BYTES or len(stderr_b) > MAX_CAPTURE_BYTES
    result = ProcessResult(
        command=argv,
        returncode=process.returncode if process.returncode is not None else -1,
        stdout=stdout_b[:MAX_CAPTURE_BYTES].decode("utf-8", errors="replace"),
        stderr=stderr_b[:MAX_CAPTURE_BYTES].decode("utf-8", errors="replace"),
        duration_seconds=round(time.monotonic() - started, 3),
        truncated=truncated,
    )
    logger.debug(
        "process.completed",
        tool=Path(argv[0]).name,
        returncode=result.returncode,
        duration=result.duration_seconds,
    )
    if check and not result.ok:
        raise AnalyzerTimeout(
            f"{Path(argv[0]).name} exited with status {result.returncode}",
            details={"stderr": result.stderr[-2000:]},
        )
    return result


def _terminate_group(process: asyncio.subprocess.Process) -> None:
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):  # pragma: no cover
        try:
            process.kill()
        except ProcessLookupError:
            pass
