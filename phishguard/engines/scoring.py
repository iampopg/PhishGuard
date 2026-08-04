from __future__ import annotations

from typing import List

from phishguard.models import AnalyzerResult, Verdict


def aggregate(
    results: List[AnalyzerResult],
    threshold_suspicious: int = 30,
    threshold_phishing: int = 60,
    threshold_malicious: int = 85,
) -> tuple[int, Verdict]:
    total = sum(r.score for r in results)
    if total > 100:
        total = 100
    if total < 0:
        total = 0

    if total >= threshold_malicious:
        verdict = Verdict.MALICIOUS
    elif total >= threshold_phishing:
        verdict = Verdict.PHISHING
    elif total >= threshold_suspicious:
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.SAFE
    return total, verdict


def recommended_actions(verdict: Verdict) -> List[str]:
    if verdict == Verdict.MALICIOUS:
        return ["quarantine", "notify_soc", "delete_if_confirmed"]
    if verdict == Verdict.PHISHING:
        return ["quarantine", "notify_soc", "train_user"]
    if verdict == Verdict.SUSPICIOUS:
        return ["review", "notify_soc"]
    return ["monitor"]
