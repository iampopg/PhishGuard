from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol

from phishguard.models import AnalyzerResult, Finding, ParsedEmail, Severity


@dataclass
class AnalysisContext:
    config: Any
    org_profile: Any = None
    intel: Any = None
    behavioral: Any = None
    ti: Any = None
    evidence: Any = None
    reputation: Any = None
    ai: Any = None
    mailbox_id: str = "default"
    extra: Dict[str, Any] = field(default_factory=dict)


class Analyzer(Protocol):
    name: str
    max_score: int

    def analyze(self, email: ParsedEmail, ctx: AnalysisContext) -> AnalyzerResult:
        ...


def make_finding(
    analyzer: str,
    title: str,
    detail: str,
    severity: Severity,
    score: int,
    evidence: Optional[Dict[str, Any]] = None,
) -> Finding:
    return Finding(
        analyzer=analyzer,
        title=title,
        detail=detail,
        severity=severity,
        score=score,
        evidence=evidence or {},
    )


def result(name: str, findings: List[Finding], max_score: int, metadata: Optional[Dict[str, Any]] = None) -> AnalyzerResult:
    total = sum(f.score for f in findings)
    if total > max_score:
        total = max_score
    if total < 0:
        total = 0
    return AnalyzerResult(name=name, score=total, findings=findings, metadata=metadata or {})
