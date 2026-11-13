"""Native library analyzer.

ELF inspection always runs when pyelftools is available.  Ghidra is an optional
enhancement used by the ``full`` profile: when it is absent the result says so
explicitly and the ELF findings stand on their own.  Nothing in this module
implies that decompilation happened when it did not.
"""

from __future__ import annotations

import json

from app.analyzers.base import AnalysisInput, Analyzer, AnalyzerResult, ArtifactRef
from app.analyzers.native.elf import ElfInspector
from app.core.enums import AnalyzerStatus, ScanProfile
from app.core.logging import get_logger
from app.detection.context import NativeContext
from app.detection.registry import registry
from app.integrations.ghidra import GhidraAdapter

logger = get_logger(__name__)


class NativeAnalyzer(Analyzer):
    name = "native-analyzer"
    version = "1"
    required_capabilities = ("pyelftools",)
    profiles = (ScanProfile.standard, ScanProfile.full)
    description = (
        "Inspects bundled ELF libraries: architecture, symbols, dependencies, "
        "hardening flags and embedded strings. Ghidra decompilation is attempted only "
        "on the full profile and only when Ghidra is installed."
    )

    async def analyze(self, data: AnalysisInput) -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name, status=AnalyzerStatus.completed)

        inspector = ElfInspector()
        analyses = inspector.inspect_apk_libraries(data.apk_path, data.scratch_dir("native"))

        if not analyses:
            result.detail = {"libraries": 0}
            result.limitations.append("the APK contains no bundled native libraries")
            return result

        libraries = [analysis.to_dict() for analysis in analyses]
        failed = [lib for lib in libraries if lib.get("error")]

        ghidra_report = await self._maybe_run_ghidra(data, analyses, result)

        context = NativeContext(
            libraries=libraries,
            metadata=data.metadata,
            ghidra_available=bool(ghidra_report and ghidra_report.get("available")),
        )
        for rule in registry.for_engine(self.name):
            try:
                result.findings.extend(rule.evaluate(context))
            except Exception as exc:  # noqa: BLE001
                logger.exception("native_rule.failed", rule=rule.meta.id)
                result.detail.setdefault("rule_errors", []).append(
                    f"{rule.meta.id}: {type(exc).__name__}: {exc}"
                )

        stored = data.store.write_text(
            data.store.scan_key(data.scan_id, "native", "libraries.json"),
            json.dumps({"libraries": libraries, "ghidra": ghidra_report}, indent=2),
        )
        result.artifacts.append(
            ArtifactRef(
                kind="native-analysis",
                storage_key=stored.storage_key,
                size_bytes=stored.size_bytes,
                entry_count=len(libraries),
            )
        )

        for lib in failed:
            result.limitations.append(f"{lib['path']} could not be inspected: {lib['error']}")
        result.detail = {
            **result.detail,
            "libraries": len(libraries),
            "libraries_failed": len(failed),
            "abis": sorted({lib.get("abi", "unknown") for lib in libraries}),
            "ghidra": ghidra_report,
        }
        result.shared = {"native_libraries": libraries}
        return result

    async def _maybe_run_ghidra(
        self,
        data: AnalysisInput,
        analyses,
        result: AnalyzerResult,  # noqa: ANN001
    ) -> dict:
        if data.profile != ScanProfile.full:
            return {
                "available": False,
                "ran": False,
                "reason": (
                    "Ghidra analysis runs only on the full profile; this scan used the "
                    f"{data.profile.value} profile"
                ),
            }

        capability = data.capability("ghidra")
        if not capability or not capability.available:
            reason = (
                "Ghidra is not installed, so no decompilation was performed. The ELF "
                "inspection above was produced by DroidScope's own parser."
            )
            result.limitations.append(reason)
            return {"available": False, "ran": False, "reason": reason}

        adapter = GhidraAdapter(
            headless_path=capability.path,
            timeout_seconds=data.settings.ghidra_timeout_seconds,
        )
        # Analyse the largest library of the primary ABI: a full-coverage run
        # over every library is not affordable inside a scan's time budget.
        candidates = [a for a in analyses if not a.error]
        if not candidates:
            return {"available": True, "ran": False, "reason": "no inspectable library"}
        target = max(candidates, key=lambda a: a.size_bytes)

        report = await adapter.analyze(
            library_path=data.scratch_dir("native") / target.path.replace("/", "_"),
            workspace=data.scratch_dir("ghidra"),
            display_path=target.path,
        )
        if report.get("ran"):
            stored = data.store.write_text(
                data.store.scan_key(data.scan_id, "native", "ghidra-report.json"),
                json.dumps(report, indent=2),
            )
            result.artifacts.append(
                ArtifactRef(
                    kind="ghidra-analysis",
                    storage_key=stored.storage_key,
                    size_bytes=stored.size_bytes,
                    detail={"library": target.path},
                )
            )
        else:
            result.limitations.append(
                f"Ghidra analysis did not complete for {target.path}: "
                f"{report.get('reason', 'unknown reason')}"
            )
        report["available"] = True
        report["library"] = target.path
        report["libraries_not_analysed"] = [a.path for a in candidates if a is not target]
        return report
