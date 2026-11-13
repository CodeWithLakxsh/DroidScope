"""Source analyzer: decompiles the APK and evaluates code rules.

Decompilation is the expensive part of a scan, so the tree is produced once and
shared with every rule engine that needs it (pattern rules, secret detection,
Firebase observations) through :class:`AnalysisInput.shared`.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.analyzers.base import AnalysisInput, Analyzer, AnalyzerResult, ArtifactRef
from app.core.enums import AnalyzerStatus, ScanProfile
from app.core.logging import get_logger
from app.detection.context import SourceContext, SourceIndex
from app.detection.registry import registry
from app.integrations.jadx import JadxAdapter

logger = get_logger(__name__)


class SourceAnalyzer(Analyzer):
    name = "source-analyzer"
    version = "1"
    required_capabilities = ("jadx", "java")
    profiles = (ScanProfile.standard, ScanProfile.full)
    description = (
        "Decompiles the APK with JADX and evaluates source pattern rules, secret "
        "detection and Firebase configuration observations against the result."
    )

    # Engines whose rules consume a SourceContext.
    SOURCE_ENGINES = ("source-analyzer", "secret-analyzer", "firebase-analyzer")

    async def analyze(self, data: AnalysisInput) -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name, status=AnalyzerStatus.completed)

        jadx_path = data.tool_path("jadx")
        adapter = JadxAdapter(
            jadx_path=jadx_path or "jadx",
            timeout_seconds=data.settings.decompile_timeout_seconds,
        )
        output_dir = data.scratch_dir("jadx")

        decompiled = await adapter.decompile(
            data.apk_path,
            output_dir,
            threads=max(1, min(4, data.settings.analysis_concurrency * 2)),
        )

        if not decompiled.succeeded or decompiled.output_dir is None:
            result.status = AnalyzerStatus.failed
            result.error = decompiled.error or "decompilation produced no sources"
            result.limitations.append(
                "JADX produced no Java sources, so no source-level rule could be "
                "evaluated. Manifest, indicator and native analysis are unaffected."
            )
            result.detail = {
                "decompiler": "jadx",
                "returncode": decompiled.returncode,
                "warnings": decompiled.warnings[:10],
            }
            return result

        # jadx writes "sources/" and "resources/" as siblings.  Index the whole
        # output directory so resource-scope rules (Firebase configuration,
        # strings.xml secrets, decoded XML) can see res/values as well as code.
        source_root = decompiled.output_dir
        if not (source_root / "sources").is_dir() and (source_root / "src").is_dir():
            source_root = source_root / "src"

        index = SourceIndex(source_root)
        context = SourceContext(
            index=index,
            metadata=data.metadata,
            app_package_path=(data.metadata.package_name or "").replace(".", "/") or None,
            decompiler="jadx",
            partial=decompiled.partial,
        )

        rules_evaluated = 0
        rule_errors: list[str] = []
        findings_by_engine: dict[str, int] = {}

        for engine in self.SOURCE_ENGINES:
            for rule in registry.for_engine(engine):
                try:
                    produced = list(rule.evaluate(context))
                except Exception as exc:  # noqa: BLE001 - isolate rule failures
                    logger.exception("source_rule.failed", rule=rule.meta.id)
                    rule_errors.append(f"{rule.meta.id}: {type(exc).__name__}: {exc}")
                    continue
                rules_evaluated += 1
                if produced:
                    findings_by_engine[engine] = findings_by_engine.get(engine, 0) + len(produced)
                    result.findings.extend(produced)

        artifact = self._store_sources(data, decompiled.output_dir, result)
        tree_key = self._store_tree(data, index, result)

        if decompiled.partial:
            result.limitations.append(
                "Some classes could not be decompiled; those classes were not covered "
                "by source rules. This is common with obfuscated or packed applications."
            )
        if index.skipped_large_files:
            result.limitations.append(
                f"{index.skipped_large_files} source files exceeded the per-file size "
                "limit and were not scanned"
            )

        result.detail = {
            "decompiler": "jadx",
            "decompiler_version": (
                data.capability("jadx").version if data.capability("jadx") else None
            ),
            "java_files": decompiled.java_files,
            "resource_files": decompiled.resource_files,
            "indexed_files": index.file_count,
            "bytes_decompiled": decompiled.total_bytes,
            "duration_seconds": decompiled.duration_seconds,
            "partial": decompiled.partial,
            "rules_evaluated": rules_evaluated,
            "rule_errors": rule_errors,
            "findings_by_engine": findings_by_engine,
            "warnings": decompiled.warnings[:10],
            "source_storage_key": artifact.storage_key if artifact else None,
            "tree_storage_key": tree_key,
        }
        result.shared = {
            "source_root": str(source_root),
            "source_storage_key": artifact.storage_key if artifact else None,
        }
        if rule_errors:
            result.error = f"{len(rule_errors)} rule(s) raised an error"
        return result

    def _store_sources(
        self, data: AnalysisInput, output_dir: Path, result: AnalyzerResult
    ) -> ArtifactRef | None:
        """Move the decompiled tree into the artifact store for later browsing."""
        try:
            key = data.store.scan_key(data.scan_id, "sources")
            stored = data.store.adopt_directory(key, output_dir, move=True)
        except Exception as exc:  # noqa: BLE001
            logger.warning("source.store_failed", error=str(exc))
            result.limitations.append(
                f"the decompiled source tree could not be retained for browsing: {exc}"
            )
            return None
        ref = ArtifactRef(
            kind="decompiled-sources",
            storage_key=stored.storage_key,
            size_bytes=stored.size_bytes,
            detail={"decompiler": "jadx"},
        )
        result.artifacts.append(ref)
        return ref

    def _store_tree(
        self, data: AnalysisInput, index: SourceIndex, result: AnalyzerResult
    ) -> str | None:
        """Persist a flat file listing so the UI can render the tree cheaply."""
        try:
            entries = index.tree()
        except OSError as exc:  # pragma: no cover
            logger.warning("source.tree_failed", error=str(exc))
            return None
        stored = data.store.write_text(
            data.store.scan_key(data.scan_id, "sources_index.json"),
            json.dumps({"entries": entries, "count": len(entries)}),
        )
        result.artifacts.append(
            ArtifactRef(
                kind="source-tree-index",
                storage_key=stored.storage_key,
                size_bytes=stored.size_bytes,
                entry_count=len(entries),
            )
        )
        return stored.storage_key
