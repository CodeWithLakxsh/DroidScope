"""Ghidra headless integration.

Ghidra is heavyweight: a headless run on a sizeable library takes minutes and
several hundred megabytes of RAM.  It is therefore:

* optional -- every other native finding is produced without it;
* confined to the ``full`` profile and to one library per scan;
* executed in its own process group with a hard timeout;
* given a scratch project directory that is discarded afterwards.

The adapter reports honestly: ``ran: false`` with a reason whenever analysis did
not complete, and it never fabricates decompilation output.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from app.core.errors import AnalyzerTimeout
from app.core.logging import get_logger
from app.core.process import run_command

logger = get_logger(__name__)

# Emitted into the Ghidra project so the headless run produces structured output
# instead of requiring us to parse the human-readable log.
POST_SCRIPT = """# DroidScope headless export script (Ghidra Jython).
# Writes a JSON summary of the analysed program to the path given as argv[0].
import json

from ghidra.program.model.symbol import SourceType

args = getScriptArgs()
output_path = args[0] if args else "ghidra-summary.json"

program = currentProgram
listing = program.getListing()
function_manager = program.getFunctionManager()

functions = []
for function in function_manager.getFunctions(True):
    functions.append({
        "name": function.getName(),
        "entry_point": str(function.getEntryPoint()),
        "size": function.getBody().getNumAddresses(),
        "parameter_count": function.getParameterCount(),
        "is_thunk": function.isThunk(),
        "is_external": function.isExternal(),
        "calling_convention": str(function.getCallingConventionName()),
    })

externals = []
symbol_table = program.getSymbolTable()
for symbol in symbol_table.getExternalSymbols():
    externals.append(symbol.getName())

summary = {
    "program": program.getName(),
    "language": str(program.getLanguageID()),
    "compiler": str(program.getCompilerSpec().getCompilerSpecID()),
    "image_base": str(program.getImageBase()),
    "function_count": len(functions),
    "defined_data_count": listing.getNumDefinedData(),
    "instruction_count": listing.getNumInstructions(),
    "external_symbols": sorted(set(externals))[:500],
    "functions": sorted(functions, key=lambda f: -f["size"])[:400],
}

with open(output_path, "w") as handle:
    json.dump(summary, handle, indent=2)

print("DROIDSCOPE_GHIDRA_SUMMARY_WRITTEN " + output_path)
"""


class GhidraAdapter:
    """Drives ``analyzeHeadless`` for a single native library."""

    def __init__(self, *, headless_path: str | Path, timeout_seconds: int = 1800) -> None:
        self.headless_path = Path(headless_path)
        self.timeout_seconds = timeout_seconds

    @property
    def available(self) -> bool:
        return self.headless_path.is_file()

    async def analyze(
        self, *, library_path: Path, workspace: Path, display_path: str | None = None
    ) -> dict:
        display = display_path or library_path.name
        if not self.available:
            return {
                "ran": False,
                "reason": "analyzeHeadless was not found",
                "library": display,
            }
        if not library_path.is_file():
            return {
                "ran": False,
                "reason": "the extracted library file is missing",
                "library": display,
            }

        project_dir = workspace / "project"
        project_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        script_dir = workspace / "scripts"
        script_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        script_path = script_dir / "DroidScopeExport.py"
        script_path.write_text(POST_SCRIPT, encoding="utf-8")
        summary_path = workspace / "ghidra-summary.json"

        command = [
            str(self.headless_path),
            str(project_dir),
            "DroidScope",
            "-import",
            str(library_path),
            "-scriptPath",
            str(script_dir),
            "-postScript",
            script_path.name,
            str(summary_path),
            "-deleteProject",
            # Leave Ghidra a little less than our own timeout so it exits
            # cleanly and still writes the summary rather than being killed.
            "-analysisTimeoutPerFile",
            str(max(self.timeout_seconds - 60, 60)),
        ]

        try:
            result = await run_command(
                command,
                timeout=self.timeout_seconds,
                cwd=workspace,
                # Ghidra writes user settings and caches into its own directories.
                env={"GHIDRA_HOME": str(self.headless_path.parent.parent)},
            )
        except AnalyzerTimeout as exc:
            self._cleanup(project_dir)
            return {
                "ran": False,
                "reason": f"analysis exceeded the {self.timeout_seconds}s timeout",
                "library": display,
                "detail": exc.details,
            }

        if not summary_path.is_file():
            self._cleanup(project_dir)
            tail = (result.stderr or result.stdout)[-1500:]
            return {
                "ran": False,
                "reason": (
                    f"analyzeHeadless exited with status {result.returncode} without "
                    "writing a summary"
                ),
                "library": display,
                "output_tail": tail,
            }

        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            self._cleanup(project_dir)
            return {
                "ran": False,
                "reason": f"the summary produced by Ghidra could not be read: {exc}",
                "library": display,
            }

        self._cleanup(project_dir)
        summary.update(
            {
                "ran": True,
                "library": display,
                "duration_seconds": result.duration_seconds,
                "returncode": result.returncode,
            }
        )
        logger.info(
            "ghidra.completed",
            library=display,
            functions=summary.get("function_count"),
            duration=result.duration_seconds,
        )
        return summary

    @staticmethod
    def _cleanup(project_dir: Path) -> None:
        shutil.rmtree(project_dir, ignore_errors=True)
