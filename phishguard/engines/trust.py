from __future__ import annotations

from typing import Any, Dict, List

from phishguard.engines.base import AnalysisContext, make_finding, result
from phishguard.models import AnalyzerResult, ParsedEmail, Severity
from phishguard.reputation import REPUTATION_BAD, REPUTATION_SAFE, SenderReputationStore
from phishguard.util.text import registrable_domain

NAME = "trust"
MAX_SCORE = 40


def analyze(email: ParsedEmail, ctx: AnalysisContext) -> AnalyzerResult:
    findings: List = []
    store: SenderReputationStore = getattr(ctx, "reputation", None)
    sender_email = email.sender_email
    if not store or not sender_email:
        return result(NAME, findings, MAX_SCORE, {"enabled": store is not None})

    rep = store.reputation_of(sender_email)
    auth = email.auth
    auth_pass = auth.spf == "pass" and auth.dkim == "pass" and auth.dmarc == "pass"

    if rep == REPUTATION_SAFE:
        # Trust bonus only meaningful when authentication also passes; otherwise the
        # sender may be spoofed. Still give a partial benefit since they were allow-listed.
        score = -25 if auth_pass else -12
        findings.append(make_finding(
            NAME, "Sender is trusted (allow-listed)",
            f"Sender domain '{registrable_domain(sender_email)}' is marked safe; trust applied.",
            Severity.INFO, score,
            {"sender": sender_email, "auth_pass": auth_pass}))
    elif rep == REPUTATION_BAD:
        findings.append(make_finding(
            NAME, "Sender marked malicious",
            f"Sender '{registrable_domain(sender_email)}' is on the untrusted list; raising suspicion.",
            Severity.MEDIUM, 15,
            {"sender": sender_email}))

    return result(NAME, findings, MAX_SCORE, {"enabled": True, "reputation": rep})
