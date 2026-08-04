from __future__ import annotations

from phishguard.engines.base import AnalysisContext, make_finding, result
from phishguard.models import AnalyzerResult, ParsedEmail, Severity
from phishguard.util.text import is_lookalike, normalize_domain, registrable_domain

NAME = "org_context"
MAX_SCORE = 40


def analyze(email: ParsedEmail, ctx: AnalysisContext) -> AnalyzerResult:
    findings = []
    dom = registrable_domain(email.sender_domain)
    name = (email.sender_name or "").lower()

    for brand in ctx.org_profile.brand_keywords:
        if brand and brand in name:
            if not ctx.org_profile.is_trusted(dom):
                findings.append(make_finding(
                    NAME, "Brand name in display, external domain",
                    f"Display name contains brand '{brand}' but sender domain '{dom}' is not trusted.",
                    Severity.HIGH, 25, {"brand": brand, "display_name": email.sender_name, "domain": dom}))

    for target in ctx.org_profile.protected_domains:
        if is_lookalike(dom, target):
            findings.append(make_finding(
                NAME, "Impersonates your organization",
                f"Sender domain '{dom}' is a lookalike of your domain '{target}'.",
                Severity.CRITICAL, 35, {"domain": dom, "protected": target}))

    trusted = ctx.org_profile.is_trusted(dom)
    if trusted and email.envelope_from and normalize_domain(registrable_domain(email.envelope_from)) != dom:
        findings.append(make_finding(
            NAME, "Trusted domain, mismatched envelope",
            f"From domain '{dom}' is trusted but envelope sender differs.",
            Severity.LOW, 5, {}))

    return result(NAME, findings, MAX_SCORE, {})
