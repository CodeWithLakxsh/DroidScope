"""Declarative pattern rules loaded from ``rules/**/*.yaml``.

A pattern rule is a regular-expression matcher with context requirements.  The
context machinery exists because a bare keyword match is almost always a false
positive in Android code: ``MessageDigest.getInstance("MD5")`` is a finding in a
credential path and noise in a cache-key helper.  Each rule can therefore
declare:

``patterns``        at least one must match for the rule to trigger;
``require_all``     every expression must also appear somewhere in the file;
``require_any``     at least one must appear somewhere in the file;
``exclude``         if any matches the same line, the match is dropped;
``exclude_file``    if any matches anywhere in the file, the file is skipped;
``exclude_paths``   substrings of paths to ignore (bundled libraries, tests);
``confidence_rules`` raise or lower confidence when extra signals are present.

Rules are versioned and validated at load time.  ``droidscope rules validate``
runs the same validation, so a malformed rule fails fast instead of silently
never matching.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from app.core.enums import Confidence, FindingCategory, Severity
from app.core.logging import get_logger
from app.detection.base import Rule, RuleMetadata
from app.detection.context import SourceContext, SourceFile
from app.detection.model import Evidence, RawFinding
from app.detection.registry import registry

logger = get_logger(__name__)

DEFAULT_RULES_DIR = Path(__file__).resolve().parents[3] / "rules"
MAX_FINDINGS_PER_RULE = 60
MAX_MATCHES_PER_FILE = 5
SNIPPET_CONTEXT_CHARS = 220

LANGUAGE_SCOPES = {
    "java": {"java", "kotlin"},
    "kotlin": {"kotlin"},
    "smali": {"smali"},
    "code": {"java", "kotlin"},
    "resource": {"resource"},
    "any": {"java", "kotlin", "smali", "resource", "other"},
}


class RuleValidationError(Exception):
    """Raised when a rule file is structurally invalid."""


@dataclass(slots=True)
class ConfidenceAdjustment:
    patterns: list[re.Pattern[str]]
    confidence: Confidence
    reason: str
    scope: str = "file"  # file | line


@dataclass(slots=True)
class PatternRuleSpec:
    meta: RuleMetadata
    scope: str
    patterns: list[re.Pattern[str]]
    require_all: list[re.Pattern[str]] = field(default_factory=list)
    require_any: list[re.Pattern[str]] = field(default_factory=list)
    exclude: list[re.Pattern[str]] = field(default_factory=list)
    exclude_file: list[re.Pattern[str]] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    include_third_party: bool = False
    confidence_rules: list[ConfidenceAdjustment] = field(default_factory=list)
    max_findings: int = MAX_FINDINGS_PER_RULE
    group_by: str = "file"  # file | match
    source_file: str | None = None


def _compile(patterns: Iterable[str], *, rule_id: str, field_name: str) -> list[re.Pattern[str]]:
    compiled: list[re.Pattern[str]] = []
    for pattern in patterns:
        if not isinstance(pattern, str):
            raise RuleValidationError(
                f"{rule_id}: {field_name} entries must be strings, got {type(pattern).__name__}"
            )
        try:
            compiled.append(re.compile(pattern, re.MULTILINE))
        except re.error as exc:
            raise RuleValidationError(
                f"{rule_id}: invalid regular expression in {field_name}: {pattern!r} ({exc})"
            ) from exc
    return compiled


def _require(document: dict[str, Any], key: str, rule_file: Path) -> Any:
    if key not in document or document[key] in (None, ""):
        raise RuleValidationError(f"{rule_file.name}: missing required field {key!r}")
    return document[key]


def _enum(value: str, enum_cls, rule_id: str, field_name: str):  # noqa: ANN001
    try:
        return enum_cls(value)
    except ValueError as exc:
        valid = ", ".join(sorted(item.value for item in enum_cls))
        raise RuleValidationError(
            f"{rule_id}: {field_name}={value!r} is not valid (expected one of: {valid})"
        ) from exc


CWE_PATTERN = re.compile(r"^CWE-\d{1,4}$")
# MASVS v2 control identifiers, e.g. MASVS-CRYPTO-1.
MASVS_PATTERN = re.compile(
    r"^MASVS-(STORAGE|CRYPTO|AUTH|NETWORK|PLATFORM|CODE|RESILIENCE|PRIVACY)-\d$"
)


def parse_rule_document(document: dict[str, Any], rule_file: Path) -> PatternRuleSpec:
    """Validate a single rule document and build its spec."""
    if not isinstance(document, dict):
        raise RuleValidationError(f"{rule_file.name}: rule document must be a mapping")

    rule_id = str(_require(document, "id", rule_file))
    name = str(_require(document, "name", rule_file))
    category = _enum(str(_require(document, "category", rule_file)), FindingCategory, rule_id, "category")
    severity = _enum(str(_require(document, "severity", rule_file)), Severity, rule_id, "severity")
    confidence = _enum(
        str(_require(document, "confidence", rule_file)), Confidence, rule_id, "confidence"
    )

    cwe_ids = [str(item) for item in document.get("cwe", []) or []]
    for cwe in cwe_ids:
        if not CWE_PATTERN.match(cwe):
            raise RuleValidationError(
                f"{rule_id}: {cwe!r} is not a CWE identifier (expected the form CWE-123)"
            )
    masvs = [str(item) for item in document.get("masvs", []) or []]
    for control in masvs:
        if not MASVS_PATTERN.match(control):
            raise RuleValidationError(
                f"{rule_id}: {control!r} is not an OWASP MASVS v2 control identifier"
            )

    scope = str(document.get("scope", "code"))
    if scope not in LANGUAGE_SCOPES:
        raise RuleValidationError(
            f"{rule_id}: scope={scope!r} is not valid (expected one of: "
            f"{', '.join(sorted(LANGUAGE_SCOPES))})"
        )

    patterns = document.get("patterns") or []
    if not patterns:
        raise RuleValidationError(f"{rule_id}: at least one entry in 'patterns' is required")

    meta = RuleMetadata(
        id=rule_id,
        name=name,
        description=str(_require(document, "description", rule_file)),
        category=category,
        severity=severity,
        confidence=confidence,
        engine=str(document.get("engine", "source-analyzer")),
        impact=str(_require(document, "impact", rule_file)),
        remediation=str(_require(document, "remediation", rule_file)),
        version=str(document.get("version", "1")),
        cwe_ids=cwe_ids,
        masvs_controls=masvs,
        references=[str(item) for item in document.get("references", []) or []],
        verification=document.get("verification"),
        limitations=document.get("limitations"),
        enabled_by_default=bool(document.get("enabled", True)),
    )

    confidence_rules: list[ConfidenceAdjustment] = []
    for entry in document.get("confidence_rules", []) or []:
        if not isinstance(entry, dict):
            raise RuleValidationError(f"{rule_id}: confidence_rules entries must be mappings")
        adjustment = ConfidenceAdjustment(
            patterns=_compile(entry.get("when_any", []), rule_id=rule_id, field_name="when_any"),
            confidence=_enum(
                str(_require(entry, "set", rule_file)), Confidence, rule_id, "confidence_rules.set"
            ),
            reason=str(entry.get("reason", "additional corroborating signal present")),
            scope=str(entry.get("scope", "file")),
        )
        if not adjustment.patterns:
            raise RuleValidationError(f"{rule_id}: confidence_rules entry needs 'when_any'")
        confidence_rules.append(adjustment)

    return PatternRuleSpec(
        meta=meta,
        scope=scope,
        patterns=_compile(patterns, rule_id=rule_id, field_name="patterns"),
        require_all=_compile(document.get("require_all", []) or [], rule_id=rule_id, field_name="require_all"),
        require_any=_compile(document.get("require_any", []) or [], rule_id=rule_id, field_name="require_any"),
        exclude=_compile(document.get("exclude", []) or [], rule_id=rule_id, field_name="exclude"),
        exclude_file=_compile(
            document.get("exclude_file", []) or [], rule_id=rule_id, field_name="exclude_file"
        ),
        exclude_paths=[str(item) for item in document.get("exclude_paths", []) or []],
        include_third_party=bool(document.get("include_third_party", False)),
        confidence_rules=confidence_rules,
        max_findings=int(document.get("max_findings", MAX_FINDINGS_PER_RULE)),
        group_by=str(document.get("group_by", "file")),
        source_file=str(rule_file),
    )


class PatternRule(Rule):
    """A rule evaluated by matching expressions against decompiled sources."""

    def __init__(self, spec: PatternRuleSpec) -> None:
        self.spec = spec
        self.meta = spec.meta

    def __repr__(self) -> str:  # pragma: no cover
        return f"<PatternRule {self.meta.id}>"

    @property
    def languages(self) -> set[str]:
        return LANGUAGE_SCOPES[self.spec.scope]

    def evaluate(self, context: SourceContext) -> Iterator[RawFinding]:
        emitted = 0
        for source in context.index.iter_files(languages=self.languages):
            if emitted >= self.spec.max_findings:
                logger.debug("pattern_rule.capped", rule=self.meta.id, cap=self.spec.max_findings)
                return
            if self._skip_path(source.relative_path, context):
                continue
            findings = list(self.evaluate_file(source))
            for finding in findings:
                if emitted >= self.spec.max_findings:
                    return
                emitted += 1
                yield finding

    def _skip_path(self, relative_path: str, context: SourceContext) -> bool:
        normalised = relative_path.replace("\\", "/")
        if any(fragment in normalised for fragment in self.spec.exclude_paths):
            return True
        if not self.spec.include_third_party and context.is_third_party(normalised):
            return True
        return False

    def evaluate_file(self, source: SourceFile) -> Iterator[RawFinding]:
        """Evaluate one file.  Exposed separately so rules are unit testable."""
        text = source.text

        if any(pattern.search(text) for pattern in self.spec.exclude_file):
            return
        if self.spec.require_all and not all(
            pattern.search(text) for pattern in self.spec.require_all
        ):
            return
        if self.spec.require_any and not any(
            pattern.search(text) for pattern in self.spec.require_any
        ):
            return

        matches: list[tuple[re.Match[str], str]] = []
        for pattern in self.spec.patterns:
            for match in pattern.finditer(text):
                line_number = source.line_of_offset(match.start())
                line_text = source.line_text(line_number)
                if any(excluded.search(line_text) for excluded in self.spec.exclude):
                    continue
                matches.append((match, line_text))
                if len(matches) >= MAX_MATCHES_PER_FILE:
                    break
            if len(matches) >= MAX_MATCHES_PER_FILE:
                break

        if not matches:
            return

        confidence, reasons = self._resolve_confidence(text, matches)

        if self.spec.group_by == "file":
            yield self._build_finding(source, matches, confidence, reasons)
        else:
            for match, line_text in matches:
                yield self._build_finding(source, [(match, line_text)], confidence, reasons)

    def _resolve_confidence(
        self, text: str, matches: list[tuple[re.Match[str], str]]
    ) -> tuple[Confidence, list[str]]:
        confidence = self.meta.confidence
        reasons: list[str] = []
        for adjustment in self.spec.confidence_rules:
            haystacks = [text] if adjustment.scope == "file" else [line for _m, line in matches]
            if any(
                pattern.search(haystack)
                for pattern in adjustment.patterns
                for haystack in haystacks
            ):
                confidence = adjustment.confidence
                reasons.append(adjustment.reason)
        return confidence, reasons

    def _build_finding(
        self,
        source: SourceFile,
        matches: list[tuple[re.Match[str], str]],
        confidence: Confidence,
        reasons: list[str],
    ) -> RawFinding:
        first_match, first_line = matches[0]
        line_number = source.line_of_offset(first_match.start())

        evidence = [
            Evidence(
                description=f"Pattern matched at {source.relative_path}:{source.line_of_offset(match.start())}",
                snippet=self._snippet(line_text, match),
                file_path=source.relative_path,
                line_number=source.line_of_offset(match.start()),
                kind="code" if source.language in {"java", "kotlin", "smali"} else "resource",
                metadata={"matched_text": match.group(0)[:160]},
            )
            for match, line_text in matches
        ]
        for reason in reasons:
            evidence.append(
                Evidence(description=f"Confidence adjusted: {reason}", kind="code")
            )

        return self.finding(
            title=f"{self.meta.name} ({Path(source.relative_path).name})",
            confidence=confidence,
            affected_component=self._class_name(source.relative_path),
            file_path=source.relative_path,
            line_number=line_number,
            evidence=evidence,
            metadata={
                "match_count": len(matches),
                "language": source.language,
                "rule_source": Path(self.spec.source_file).name if self.spec.source_file else None,
            },
        )

    @staticmethod
    def _snippet(line_text: str, match: re.Match[str]) -> str:
        stripped = line_text.strip()
        if len(stripped) <= SNIPPET_CONTEXT_CHARS:
            return stripped
        matched = match.group(0)
        index = stripped.find(matched[:40])
        if index == -1:
            return stripped[:SNIPPET_CONTEXT_CHARS] + " ..."
        start = max(index - 60, 0)
        return ("... " if start else "") + stripped[start : start + SNIPPET_CONTEXT_CHARS] + " ..."

    @staticmethod
    def _class_name(relative_path: str) -> str:
        path = Path(relative_path)
        if path.suffix.lower() in {".java", ".kt", ".smali"}:
            return str(path.with_suffix("")).replace("/", ".").replace("\\", ".")
        return relative_path


def iter_rule_documents(rules_dir: Path) -> Iterator[tuple[dict[str, Any], Path]]:
    """Yield every rule document from every YAML file under ``rules_dir``."""
    if not rules_dir.is_dir():
        logger.warning("pattern_rules.directory_missing", path=str(rules_dir))
        return
    for path in sorted(rules_dir.rglob("*.y*ml")):
        if "yara" in path.parts:
            continue
        try:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise RuleValidationError(f"{path.name}: YAML could not be parsed: {exc}") from exc
        if loaded is None:
            continue
        documents = loaded.get("rules") if isinstance(loaded, dict) else loaded
        if isinstance(documents, dict):
            documents = [documents]
        if not isinstance(documents, list):
            raise RuleValidationError(
                f"{path.name}: expected a list of rules or a mapping with a 'rules' key"
            )
        for document in documents:
            yield document, path


def validate_rules_dir(rules_dir: Path | None = None) -> tuple[list[PatternRuleSpec], list[str]]:
    """Validate every rule file.  Returns (specs, errors)."""
    rules_dir = Path(rules_dir or DEFAULT_RULES_DIR)
    specs: list[PatternRuleSpec] = []
    errors: list[str] = []
    seen: dict[str, str] = {}

    try:
        documents = list(iter_rule_documents(rules_dir))
    except RuleValidationError as exc:
        return [], [str(exc)]

    for document, path in documents:
        try:
            spec = parse_rule_document(document, path)
        except RuleValidationError as exc:
            errors.append(str(exc))
            continue
        if spec.meta.id in seen:
            errors.append(
                f"{spec.meta.id}: duplicate rule id (also defined in {seen[spec.meta.id]})"
            )
            continue
        seen[spec.meta.id] = path.name
        specs.append(spec)
    return specs, errors


def load_pattern_rules(rules_dir: Path | None = None) -> list[PatternRule]:
    """Load, validate and register every pattern rule."""
    specs, errors = validate_rules_dir(rules_dir)
    for error in errors:
        logger.error("pattern_rules.invalid", detail=error)
    rules = [PatternRule(spec) for spec in specs]
    for rule in rules:
        registry.register(rule)
    logger.info("pattern_rules.loaded", count=len(rules), invalid=len(errors))
    return rules
