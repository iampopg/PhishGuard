from __future__ import annotations

from phishguard.engines.base import AnalysisContext, make_finding, result
from phishguard.models import AnalyzerResult, ParsedEmail, Severity
from phishguard.util.text import normalize_domain, registrable_domain

NAME = "header_analysis"
MAX_SCORE = 45


def analyze(email: ParsedEmail, ctx: AnalysisContext) -> AnalyzerResult:
    findings = []

    reply_dom = email.reply_to and registrable_domain(email.reply_to)
    from_dom = registrable_domain(email.sender_domain)
    if reply_dom and from_dom and normalize_domain(reply_dom) != normalize_domain(from_dom):
        findings.append(make_finding(
            NAME, "Reply-To domain mismatch",
            f"Reply-To domain '{reply_dom}' differs from From domain '{from_dom}'.",
            Severity.MEDIUM, 15, {"reply_to": reply_dom, "from": from_dom}))

    ret_dom = email.return_path and registrable_domain(email.return_path)
    if ret_dom and from_dom and normalize_domain(ret_dom) != normalize_domain(from_dom):
        findings.append(make_finding(
            NAME, "Return-Path/From domain mismatch",
            f"Return-Path domain '{ret_dom}' differs from From domain '{from_dom}'.",
            Severity.MEDIUM, 10, {"return_path": ret_dom, "from": from_dom}))

    all_auth_pass = email.auth.spf == "pass" and email.auth.dkim == "pass" and email.auth.dmarc == "pass"

    msg_id = email.raw_headers.get("Message-ID", "")
    if msg_id and "@" in msg_id:
        mid_dom = msg_id.split("@")[-1].rstrip(">").strip()
        mid_dom = registrable_domain(mid_dom)
        if mid_dom and from_dom and normalize_domain(mid_dom) != normalize_domain(from_dom):
            sev = Severity.INFO if all_auth_pass else Severity.LOW
            score = 2 if all_auth_pass else 8
            findings.append(make_finding(
                NAME, "Message-ID domain mismatch",
                f"Message-ID domain '{mid_dom}' differs from From domain '{from_dom}'.",
                sev, score, {"message_id_domain": mid_dom, "from": from_dom}))

    name = (email.sender_name or "").lower().strip()
    if name and from_dom:
        for vip in ctx.org_profile.vip_names:
            if vip and vip in name and ctx.org_profile.is_trusted(from_dom) is False:
                findings.append(make_finding(
                    NAME, "Display name impersonates internal VIP",
                    f"Sender display name '{email.sender_name}' resembles VIP '{vip}' but originates from external domain '{from_dom}'.",
                    Severity.HIGH, 25, {"vip": vip, "display_name": email.sender_name, "domain": from_dom}))

    has_body = bool((email.body_text or "").strip()) or bool((email.body_html or "").strip())
    if not email.subject or not has_body:
        findings.append(make_finding(
            NAME, "Sparse email structure",
            "Email has missing subject or empty body, common in automated/abusive sends.",
            Severity.LOW, 3, {}))

    return result(NAME, findings, MAX_SCORE, {})
