"""YARA scanning subsystem.

Rules are validated and compiled once per scan, then applied to individual
archive entries with resource limits.  Each entry's path is exposed to the rules
as the ``entry_path`` external variable so a rule can scope itself (for example,
an embedded-payload rule that must not fire on the application's own
``classes.dex``).

A YARA match is reported as an *indicator*, never as family attribution: the
finding text states what matched and what that does and does not mean.
"""

from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.analyzers.base import Analyzer, AnalysisInput, AnalyzerResult, ArtifactRef
from app.core.enums import AnalyzerStatus, Confidence, FindingCategory, ScanProfile, Severity
from app.core.logging import get_logger
from app.detection.base import RuleMetadata
from app.detection.model import Evidence, RawFinding

logger = get_logger(__name__)

DEFAULT_RULES_DIR = Path(__file__).resolve().parents[4] / "rules" / "yara"
MAX_ENTRY_BYTES = 64 * 1024 * 1024
MAX_SCAN_ENTRIES = 3000
MATCH_TIMEOUT_SECONDS = 30
MAX_MATCH_STRINGS = 8

SEVERITY_BY_META = {
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "low": Severity.low,
    "info": Severity.info,
}
CONFIDENCE_BY_META = {
    "high": Confidence.high,
    "medium": Confidence.medium,
    "low": Confidence.low,
}
CATEGORY_BY_META = {
    "suspicious-behaviour": FindingCategory.malware_indicator,
    "obfuscation-indicator": FindingCategory.obfuscation,
    "known-malware": FindingCategory.malware_indicator,
    "embedded-payload": FindingCategory.malware_indicator,
    "native-indicator": FindingCategory.native_code,
}


@dataclass(slots=True)
class RuleSetReport:
    compiled: bool
    rule_count: int = 0
    files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class YaraRuleSet:
    """Loads, validates and compiles the YARA rule directory."""

    def __init__(self, rules_dir: Path | None = None) -> None:
        self.rules_dir = Path(rules_dir or DEFAULT_RULES_DIR)
        self.compiled: Any = None
        self.report = RuleSetReport(compiled=False)

    @staticmethod
    def available() -> bool:
        try:
            import yara  # noqa: F401
        except ImportError:
            return False
        return True

    def load(self) -> RuleSetReport:
        try:
            import yara
        except ImportError as exc:  # pragma: no cover - guarded by capabilities
            self.report.errors.append(f"yara-python is not installed: {exc}")
            return self.report

        if not self.rules_dir.is_dir():
            self.report.errors.append(f"rule directory {self.rules_dir.name} does not exist")
            return self.report

        sources: dict[str, str] = {}
        for path in sorted(self.rules_dir.rglob("*.yar*")):
            namespace = path.stem
            try:
                text = path.read_text(encoding="utf-8")
            except OSError as exc:
                self.report.errors.append(f"{path.name}: unreadable ({exc})")
                continue
            # Validate each file on its own so one bad file does not block the set.
            try:
                yara.compile(source=text, externals={"entry_path": ""})
            except yara.SyntaxError as exc:
                self.report.errors.append(f"{path.name}: {exc}")
                continue
            sources[namespace] = text
            self.report.files.append(path.name)

        if not sources:
            if not self.report.errors:
                self.report.errors.append("no YARA rule files were found")
            return self.report

        try:
            self.compiled = yara.compile(sources=sources, externals={"entry_path": ""})
        except yara.YaraError as exc:
            self.report.errors.append(f"rule set failed to compile: {exc}")
            return self.report

        self.report.compiled = True
        self.report.rule_count = sum(1 for _ in self.compiled)
        return self.report


class YaraAnalyzer(Analyzer):
    name = "yara-analyzer"
    version = "1"
    required_capabilities = ("yara",)
    profiles = (ScanProfile.standard, ScanProfile.full)
    description = (
        "Scans APK contents with a validated YARA rule set. Matches are reported as "
        "indicators requiring review, never as malware family attribution."
    )

    def __init__(self, rules_dir: Path | None = None) -> None:
        self.rules_dir = rules_dir

    async def analyze(self, data: AnalysisInput) -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name, status=AnalyzerStatus.completed)

        configured = data.settings.yara_rules_dir or self.rules_dir
        rule_set = YaraRuleSet(configured)
        report = rule_set.load()

        if not report.compiled:
            result.status = AnalyzerStatus.failed
            result.error = "; ".join(report.errors) or "YARA rules could not be compiled"
            result.limitations.append(
                "No YARA rules were applied because the rule set failed to compile: "
                + result.error
            )
            result.detail = {"rule_set": report.__dict__}
            return result

        for error in report.errors:
            result.limitations.append(f"YARA rule file skipped: {error}")

        matches, scanned, skipped = self._scan_archive(data.apk_path, rule_set)
        result.findings = [self._finding(match) for match in matches]

        stored = data.store.write_text(
            data.store.scan_key(data.scan_id, "yara", "matches.json"),
            json.dumps({"matches": matches, "rule_set": report.files}, indent=2),
        )
        result.artifacts.append(
            ArtifactRef(
                kind="yara-matches",
                storage_key=stored.storage_key,
                size_bytes=stored.size_bytes,
                entry_count=len(matches),
            )
        )
        if skipped:
            result.limitations.append(
                f"{skipped} archive entries were not scanned because they exceeded the "
                "per-entry size limit or could not be read"
            )
        result.detail = {
            "rules_compiled": report.rule_count,
            "rule_files": report.files,
            "rule_errors": report.errors,
            "entries_scanned": scanned,
            "entries_skipped": skipped,
            "matches": len(matches),
        }
        return result

    def _scan_archive(
        self, apk_path: Path, rule_set: YaraRuleSet
    ) -> tuple[list[dict[str, Any]], int, int]:
        import yara

        aggregated: dict[tuple[str, str], dict[str, Any]] = {}
        scanned = skipped = 0

        try:
            with zipfile.ZipFile(apk_path) as archive:
                for info in archive.infolist():
                    if info.is_dir() or scanned >= MAX_SCAN_ENTRIES:
                        continue
                    if info.file_size > MAX_ENTRY_BYTES:
                        skipped += 1
                        continue
                    try:
                        with archive.open(info) as handle:
                            payload = handle.read()
                    except (OSError, RuntimeError, zipfile.BadZipFile):
                        skipped += 1
                        continue
                    scanned += 1
                    try:
                        hits = rule_set.compiled.match(
                            data=payload,
                            externals={"entry_path": info.filename},
                            timeout=MATCH_TIMEOUT_SECONDS,
                        )
                    except yara.TimeoutError:
                        skipped += 1
                        logger.warning("yara.entry_timeout", entry=info.filename)
                        continue
                    except yara.Error as exc:
                        skipped += 1
                        logger.debug("yara.entry_failed", entry=info.filename, error=str(exc))
                        continue

                    for hit in hits:
                        key = (hit.rule, info.filename)
                        if key in aggregated:
                            continue
                        aggregated[key] = {
                            "rule": hit.rule,
                            "namespace": hit.namespace,
                            "entry": info.filename,
                            "entry_size": info.file_size,
                            "tags": list(hit.tags),
                            "meta": dict(hit.meta),
                            "strings": self._summarise_strings(hit),
                        }
        except (OSError, zipfile.BadZipFile) as exc:
            logger.warning("yara.archive_unreadable", error=str(exc))

        return list(aggregated.values()), scanned, skipped

    @staticmethod
    def _summarise_strings(hit) -> list[dict[str, Any]]:  # noqa: ANN001
        summary: list[dict[str, Any]] = []
        for string_match in getattr(hit, "strings", [])[:MAX_MATCH_STRINGS]:
            identifier = getattr(string_match, "identifier", "?")
            instances = getattr(string_match, "instances", [])
            for instance in instances[:2]:
                value = getattr(instance, "matched_data", b"")
                summary.append(
                    {
                        "identifier": identifier,
                        "offset": getattr(instance, "offset", None),
                        "matched": value.decode("utf-8", errors="replace")[:120]
                        if isinstance(value, bytes)
                        else str(value)[:120],
                    }
                )
        return summary

    def _finding(self, match: dict[str, Any]) -> RawFinding:
        meta = match.get("meta", {})
        severity = SEVERITY_BY_META.get(str(meta.get("severity", "info")).lower(), Severity.info)
        confidence = CONFIDENCE_BY_META.get(
            str(meta.get("confidence", "low")).lower(), Confidence.low
        )
        category = CATEGORY_BY_META.get(
            str(meta.get("category", "")).lower(), FindingCategory.malware_indicator
        )
        description = str(meta.get("description", "A YARA rule matched application content."))
        note = str(meta.get("note", "")).strip()

        rule_meta = RuleMetadata(
            id=f"DS-YARA-{match['rule']}",
            name=match["rule"],
            description=description,
            category=category,
            severity=severity,
            confidence=confidence,
            engine=self.name,
            impact=(
                "A YARA match records that specific content is present in the "
                "application. It is an indicator for review, not a determination that "
                "the application is malicious and not an attribution to any malware "
                "family."
                + (f" {note}" if note else "")
            ),
            remediation=(
                "Review the matched content in context. Confirm the capability is "
                "intentional and documented, and that any code or payload it refers to "
                "comes from a source you control."
            ),
            masvs_controls=["MASVS-RESILIENCE-1"],
            references=[str(meta["reference"])] if meta.get("reference") else [],
            limitations=(
                "YARA matches content, not behaviour. A match does not prove the "
                "matched capability is reachable or used, and an application can "
                "evade these rules through encryption or packing."
            ),
        )

        evidence = [
            Evidence(
                description=(
                    f"Rule {match['rule']} matched {match['entry']} "
                    f"({match['entry_size']} bytes)"
                ),
                file_path=match["entry"],
                kind="binary",
                metadata={"namespace": match.get("namespace"), "tags": match.get("tags", [])},
            )
        ]
        for item in match.get("strings", [])[:MAX_MATCH_STRINGS]:
            evidence.append(
                Evidence(
                    description=f"{item['identifier']} at offset {item['offset']}",
                    snippet=item["matched"],
                    file_path=match["entry"],
                    kind="binary",
                )
            )

        return RawFinding(
            rule_id=rule_meta.id,
            rule_version="1",
            title=f"YARA indicator: {description}",
            description=description,
            severity=severity,
            confidence=confidence,
            category=category,
            analysis_engine=self.name,
            impact=rule_meta.impact,
            remediation=rule_meta.remediation,
            masvs_controls=rule_meta.masvs_controls,
            references=rule_meta.references,
            limitations=rule_meta.limitations,
            affected_component=match["entry"],
            file_path=match["entry"],
            evidence=evidence,
            metadata={
                "yara_rule": match["rule"],
                "namespace": match.get("namespace"),
                "tags": match.get("tags", []),
            },
        )
