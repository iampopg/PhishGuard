from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from phishguard.models import Report, Severity


@dataclass
class Rule:
    id: str
    description: str
    action: str
    analyzer: str = ""
    severity_at_least: Severity = Severity.LOW
    title_contains: str = ""

    def matches(self, report: Report) -> bool:
        for ar in report.analyzers:
            for f in ar.findings:
                if self.analyzer and f.analyzer != self.analyzer:
                    continue
                if f.severity.weight < self.severity_at_least.weight:
                    continue
                if self.title_contains and self.title_contains.lower() not in f.title.lower():
                    continue
                return True
        return False


def evaluate_rules(report: Report, rules: List[Rule]) -> List[str]:
    actions: List[str] = []
    for rule in rules:
        if rule.matches(report) and rule.action not in actions:
            actions.append(rule.action)
    return actions
