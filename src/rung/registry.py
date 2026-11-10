"""Rule registration.

Rules register themselves with the ``@rule`` decorator at import time. The engine calls
:func:`load_builtin_rules`, which imports every module in ``rung.probes`` - so adding a
rule (or a whole probe module) never requires touching the engine.
"""

from __future__ import annotations

import importlib
import pkgutil
import re
from collections.abc import Callable, Iterator

from rung.collect import RepoSnapshot
from rung.models import Check, Confidence, Dimension, Rule, Severity, Stage

_ID_RE = re.compile(r"^[A-Z]{2,5}\d{3}$")


class Registry:
    """An ordered collection of rules keyed by id."""

    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}

    def add(self, rule: Rule) -> Rule:
        if not _ID_RE.match(rule.id):
            raise ValueError(f"invalid rule id {rule.id!r}: expected e.g. 'DOC001'")
        if rule.weight <= 0:
            raise ValueError(f"{rule.id}: weight must be positive")
        existing = self._rules.get(rule.id)
        if existing is not None and existing.run is not rule.run:
            raise ValueError(f"duplicate rule id {rule.id!r}")
        self._rules[rule.id] = rule
        return rule

    def rule(
        self,
        *,
        id: str,  # noqa: A002 - mirrors the documented rule field name
        title: str,
        dimension: Dimension,
        stage: Stage,
        severity: Severity,
        confidence: Confidence = Confidence.high,
        description: str,
        remediation: str,
        weight: float = 1.0,
        tags: tuple[str, ...] = (),
    ) -> Callable[[Callable[[RepoSnapshot], Check]], Callable[[RepoSnapshot], Check]]:
        """Decorator: turn ``run(repo) -> Check`` into a registered :class:`Rule`."""

        def decorate(fn: Callable[[RepoSnapshot], Check]) -> Callable[[RepoSnapshot], Check]:
            self.add(
                Rule(
                    id=id,
                    title=title,
                    dimension=dimension,
                    stage=stage,
                    severity=severity,
                    confidence=confidence,
                    description=description,
                    remediation=remediation,
                    run=fn,
                    weight=weight,
                    tags=tags,
                )
            )
            return fn

        return decorate

    def get(self, rule_id: str) -> Rule:
        return self._rules[rule_id]

    def __contains__(self, rule_id: object) -> bool:
        return rule_id in self._rules

    def __iter__(self) -> Iterator[Rule]:
        """Rules in deterministic id order."""
        return iter(sorted(self._rules.values(), key=lambda r: r.id))

    def __len__(self) -> int:
        return len(self._rules)


#: The default registry holding all built-in rules.
REGISTRY = Registry()

#: Decorator bound to the default registry: ``@rule(id="DOC001", ...)``.
rule = REGISTRY.rule


def load_builtin_rules() -> Registry:
    """Import every ``rung.probes.*`` module so their rules register. Idempotent."""
    import rung.probes as probes

    for mod in sorted(pkgutil.iter_modules(probes.__path__), key=lambda m: m.name):
        if not mod.name.startswith("_"):
            importlib.import_module(f"{probes.__name__}.{mod.name}")
    return REGISTRY
