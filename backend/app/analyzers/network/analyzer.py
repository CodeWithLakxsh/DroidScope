"""Network indicator analyzer."""

from __future__ import annotations

import json

from app.analyzers.base import AnalysisInput, Analyzer, AnalyzerResult, ArtifactRef
from app.analyzers.network.indicators import IndicatorExtractor, summarise
from app.core.enums import AnalyzerStatus
from app.core.logging import get_logger
from app.detection.context import IndicatorContext
from app.detection.registry import registry

logger = get_logger(__name__)


class IndicatorAnalyzer(Analyzer):
    name = "network-indicator-analyzer"
    version = "1"
    required_capabilities = ()
    description = (
        "Extracts URLs, domains and IP addresses from the APK and classifies each by "
        "routing scope. Extracted destinations are never contacted."
    )

    async def analyze(self, data: AnalysisInput) -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name, status=AnalyzerStatus.completed)
        extractor = IndicatorExtractor()
        indicators = extractor.extract_from_apk(data.apk_path)

        result.indicators = [indicator.to_dict() for indicator in indicators]
        summary = summarise(indicators)

        context = IndicatorContext(indicators=result.indicators, metadata=data.metadata)
        for rule in registry.for_engine(self.name):
            try:
                result.findings.extend(rule.evaluate(context))
            except Exception as exc:  # noqa: BLE001
                logger.exception("indicator_rule.failed", rule=rule.meta.id)
                result.detail.setdefault("rule_errors", []).append(
                    f"{rule.meta.id}: {type(exc).__name__}: {exc}"
                )

        stored = data.store.write_text(
            data.store.scan_key(data.scan_id, "indicators", "indicators.json"),
            json.dumps({"summary": summary, "indicators": result.indicators}, indent=2),
        )
        result.artifacts.append(
            ArtifactRef(
                kind="network-indicators",
                storage_key=stored.storage_key,
                size_bytes=stored.size_bytes,
                entry_count=len(indicators),
            )
        )

        if extractor.entries_skipped:
            result.limitations.append(
                f"{extractor.entries_skipped} archive entries were skipped because they "
                "exceeded the per-entry size limit or could not be read"
            )
        result.limitations.append(
            "Indicators are observations extracted from application contents. They are "
            "not evidence of malicious behaviour, and DroidScope does not contact them."
        )
        result.detail = {
            **result.detail,
            "summary": summary,
            "entries_scanned": extractor.entries_scanned,
            "entries_skipped": extractor.entries_skipped,
            "bytes_scanned": extractor.bytes_scanned,
        }
        return result
