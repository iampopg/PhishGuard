from __future__ import annotations

from phishguard.engines.base import AnalysisContext, make_finding, result
from phishguard.models import AnalyzerResult, ParsedEmail, Severity

NAME = "behavioral"
MAX_SCORE = 40


def analyze(email: ParsedEmail, ctx: AnalysisContext) -> AnalyzerResult:
    store = getattr(ctx, "behavioral", None)
    findings = []
    if store is None:
        return result(NAME, findings, MAX_SCORE, {"enabled": False})

    recipient = email.receiver_email
    if not recipient:
        return result(NAME, findings, MAX_SCORE, {"enabled": True})

    if not store.known_sender_for_recipient(recipient, email.sender_email):
        if not store.known_domain_for_recipient(recipient, email.sender_domain):
            findings.append(make_finding(
                NAME, "First-time sender domain for recipient",
                f"Domain '{email.sender_domain}' has never emailed {recipient} before (BEC risk).",
                Severity.MEDIUM, 15, {"recipient": recipient, "domain": email.sender_domain}))
        else:
            findings.append(make_finding(
                NAME, "First-time sender for recipient",
                f"Address '{email.sender_email}' has never emailed {recipient} before.",
                Severity.LOW, 8, {"recipient": recipient, "sender": email.sender_email}))

    name = (email.sender_name or "").strip().lower()
    if name and not store.known_display_name_for_recipient(recipient, name):
        for vip in ctx.org_profile.vip_names:
            if vip and vip in name:
                findings.append(make_finding(
                    NAME, "Impersonated internal name, first contact",
                    f"Display name '{email.sender_name}' resembles internal VIP and is a first-time contact for {recipient}.",
                    Severity.HIGH, 20, {"recipient": recipient, "name": email.sender_name}))
                break

    return result(NAME, findings, MAX_SCORE, {"enabled": True})
