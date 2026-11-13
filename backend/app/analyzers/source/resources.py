"""Resource analyzer: apktool decoding for smali and decoded resources.

JADX gives readable Java; apktool gives smali and faithfully decoded resources.
Both are useful for different review tasks, so the standard profile produces
both and stores each as a browsable artifact.
"""

from __future__ import annotations

from app.analyzers.base import AnalysisInput, Analyzer, AnalyzerResult, ArtifactRef
from app.core.enums import AnalyzerStatus, ScanProfile
from app.core.logging import get_logger
from app.integrations.apktool import ApktoolAdapter

logger = get_logger(__name__)


class ResourceAnalyzer(Analyzer):
    name = "resource-analyzer"
    version = "1"
    required_capabilities = ("apktool", "java")
    profiles = (ScanProfile.standard, ScanProfile.full)
    description = (
        "Decodes resources and disassembles DEX to smali with apktool, producing a "
        "browsable artifact alongside the JADX output."
    )

    async def analyze(self, data: AnalysisInput) -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name, status=AnalyzerStatus.completed)

        adapter = ApktoolAdapter(
            apktool_path=data.tool_path("apktool") or "apktool",
            timeout_seconds=data.settings.analyzer_timeout_seconds,
        )
        output_dir = data.scratch_dir("apktool") / "decoded"
        decoded = await adapter.decode(data.apk_path, output_dir)

        if not decoded.succeeded or decoded.output_dir is None:
            result.status = AnalyzerStatus.failed
            result.error = decoded.error or "apktool produced no output"
            result.limitations.append(
                "apktool decoding failed, so smali disassembly and decoded resources "
                "are unavailable. JADX output and manifest analysis are unaffected."
            )
            result.detail = {"returncode": decoded.returncode}
            return result

        try:
            stored = data.store.adopt_directory(
                data.store.scan_key(data.scan_id, "decoded"), decoded.output_dir, move=True
            )
            result.artifacts.append(
                ArtifactRef(
                    kind="decoded-resources",
                    storage_key=stored.storage_key,
                    size_bytes=stored.size_bytes,
                    entry_count=decoded.smali_files + decoded.resource_files,
                    detail={"decoder": "apktool", "smali_files": decoded.smali_files},
                )
            )
            result.shared = {"decoded_root": stored.storage_key}
        except Exception as exc:  # noqa: BLE001
            logger.warning("resource.store_failed", error=str(exc))
            result.limitations.append(
                f"decoded resources could not be retained for browsing: {exc}"
            )

        result.detail = {
            "decoder": "apktool",
            "decoder_version": (
                data.capability("apktool").version if data.capability("apktool") else None
            ),
            "smali_files": decoded.smali_files,
            "resource_files": decoded.resource_files,
            "bytes": decoded.total_bytes,
            "duration_seconds": decoded.duration_seconds,
            "warnings": decoded.warnings[:10],
        }
        return result
