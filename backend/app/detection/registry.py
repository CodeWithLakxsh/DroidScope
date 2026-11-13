"""Rule registry.

Rules register themselves at import time.  The registry keeps them grouped by
engine so each analyzer can ask for exactly the rules it is able to evaluate,
and applies operator overrides (disable a rule, change its severity) loaded
from the database.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Iterator

from app.core.enums import Severity
from app.core.logging import get_logger
from app.detection.base import Rule, RuleMetadata

logger = get_logger(__name__)


class RuleRegistry:
    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}
        self._by_engine: dict[str, list[Rule]] = defaultdict(list)
        self._disabled: set[str] = set()
        self._severity_overrides: dict[str, Severity] = {}

    # -- registration ------------------------------------------------------
    def register(self, rule: Rule) -> Rule:
        rule_id = rule.meta.id
        if rule_id in self._rules:
            existing = self._rules[rule_id]
            if type(existing) is not type(rule):
                raise ValueError(f"duplicate rule id {rule_id!r}")
            return rule
        self._rules[rule_id] = rule
        self._by_engine[rule.meta.engine].append(rule)
        return rule

    def extend(self, rules: Iterable[Rule]) -> None:
        for rule in rules:
            self.register(rule)

    # -- overrides ---------------------------------------------------------
    def apply_overrides(
        self, disabled: Iterable[str] = (), severity_overrides: dict[str, str] | None = None
    ) -> None:
        self._disabled = set(disabled)
        self._severity_overrides = {
            rule_id: Severity(value)
            for rule_id, value in (severity_overrides or {}).items()
            if value in Severity.__members__.values() or value in {s.value for s in Severity}
        }

    def is_enabled(self, rule_id: str) -> bool:
        return rule_id not in self._disabled

    def severity_for(self, rule_id: str, default: Severity) -> Severity:
        return self._severity_overrides.get(rule_id, default)

    # -- lookup ------------------------------------------------------------
    def get(self, rule_id: str) -> Rule | None:
        return self._rules.get(rule_id)

    def for_engine(self, engine: str, *, include_disabled: bool = False) -> list[Rule]:
        rules = self._by_engine.get(engine, [])
        if include_disabled:
            return list(rules)
        return [rule for rule in rules if self.is_enabled(rule.meta.id)]

    def all_rules(self, *, include_disabled: bool = True) -> list[Rule]:
        rules = list(self._rules.values())
        if include_disabled:
            return rules
        return [rule for rule in rules if self.is_enabled(rule.meta.id)]

    def metadata(self) -> list[RuleMetadata]:
        return [rule.meta for rule in self._rules.values()]

    def engines(self) -> list[str]:
        return sorted(self._by_engine)

    def __len__(self) -> int:
        return len(self._rules)

    def __iter__(self) -> Iterator[Rule]:
        return iter(self._rules.values())


registry = RuleRegistry()


def register(rule: Rule) -> Rule:
    return registry.register(rule)


def load_builtin_rules() -> RuleRegistry:
    """Import every rule module so registration side effects happen once."""
    from app.detection.rules import (  # noqa: F401
        firebase_rules,
        manifest_rules,
        native_rules,
        network_rules,
        secret_rules,
    )
    from app.detection import pattern_rules

    pattern_rules.load_pattern_rules()
    return registry
