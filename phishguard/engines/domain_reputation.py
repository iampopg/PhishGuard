from __future__ import annotations

from phishguard.engines.base import AnalysisContext, make_finding, result
from phishguard.models import AnalyzerResult, ParsedEmail, Severity
from phishguard.util.text import is_lookalike, normalize_domain, registrable_domain

NAME = "domain_reputation"
MAX_SCORE = 50

DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "throwawaymail.com", "getnada.com", "yopmail.com", "trashmail.com",
    "dispostable.com", "fakeinbox.com", "maildrop.cc", "sharklasers.com",
}


def _domain_age_days(domain: str):
    try:
        import whois  # type: ignore
    except Exception:
        return None
    try:
        data = whois.whois(domain)
        created = data.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            from datetime import datetime, timezone
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            return (datetime.now(timezone.utc) - created).days
    except Exception:
        return None
    return None


def analyze(email: ParsedEmail, ctx: AnalysisContext) -> AnalyzerResult:
    findings = []
    dom = registrable_domain(email.sender_domain)
    if not dom:
        return result(NAME, findings, MAX_SCORE, {})

    for target in ctx.org_profile.protected_domains:
        if is_lookalike(dom, target):
            findings.append(make_finding(
                NAME, "Lookalike of your domain",
                f"Sender domain '{dom}' is a lookalike/typosquat of protected domain '{target}'.",
                Severity.CRITICAL, 35, {"domain": dom, "protected": target}))
            break

    for brand in ctx.org_profile.brand_domains:
        if is_lookalike(dom, brand):
            findings.append(make_finding(
                NAME, "Lookalike of known brand",
                f"Sender domain '{dom}' is a lookalike of brand domain '{brand}'.",
                Severity.HIGH, 25, {"domain": dom, "brand": brand}))
            break

    if dom in DISPOSABLE_DOMAINS:
        findings.append(make_finding(
            NAME, "Disposable/free email domain",
            f"Sender uses disposable domain '{dom}', suspicious for business/finance context.",
            Severity.MEDIUM, 10, {"domain": dom}))

    if not ctx.org_profile.is_trusted(dom):
        age = _domain_age_days(dom)
        if age is not None and age < 30:
            findings.append(make_finding(
                NAME, "Newly registered domain",
                f"Sender domain '{dom}' was registered {age} days ago.",
                Severity.HIGH, 20, {"domain": dom, "age_days": age}))

    return result(NAME, findings, MAX_SCORE, {"domain": dom})
