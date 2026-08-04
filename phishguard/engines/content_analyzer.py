from __future__ import annotations

import re
from html.parser import HTMLParser

from phishguard.engines.base import AnalysisContext, make_finding, result
from phishguard.models import AnalyzerResult, ParsedEmail, Severity
from phishguard.util.text import registrable_domain

NAME = "content_analyzer"
MAX_SCORE = 40

URGENCY = ["urgent", "immediately", "asap", "act now", "time-sensitive", "expires",
           "suspend", "verify now", "final notice", "limited time", "deadline"]
AUTHORITY = ["ceo", "director", "manager", "administrator", "security team", "compliance",
             "legal", "payroll", "it department", "bank", "irs", "tax"]
CREDENTIAL = ["password", "login", "sign in", "sign-in", "credential", "otp", "one-time code",
              "two-factor", "2fa", "confirm your account", "verify your account", "update your password"]
FINANCIAL = ["invoice", "wire transfer", "bank transfer", "payment", "account number",
             "routing number", "gift card", "bitcoin", "crypto", "reimburse"]
BRAND_KW = ["paypal", "microsoft", "apple", "google", "amazon", "dhl", "fedex", "ups",
            "netflix", "linkedin", "facebook", "instagram", "bank of america", "wells fargo"]

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.external_forms = 0

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "form":
            return
        d = dict(attrs)
        action = (d.get("action") or "").lower()
        if action and not action.startswith("#"):
            host = registrable_domain(action)
            if host:
                self.external_forms += 1


def analyze(email: ParsedEmail, ctx: AnalysisContext) -> AnalyzerResult:
    findings = []
    text = ((email.subject or "") + " " + (email.body_text or "")).lower()

    hits = 0
    matched = set()
    for kw in URGENCY + AUTHORITY + CREDENTIAL + FINANCIAL:
        if kw in text and kw not in matched:
            matched.add(kw)
            hits += 1

    if hits >= 4:
        sev = Severity.MEDIUM if hits < 7 else Severity.HIGH
        findings.append(make_finding(
            NAME, "Multiple social-engineering cues",
            f"Email contains {hits} urgency/authority/credential/financial phrases.",
            sev, min(20, 4 + hits * 2), {"matched_count": hits}))

    brand_count = sum(1 for b in BRAND_KW if b in text)
    if brand_count:
        findings.append(make_finding(
            NAME, "Brand impersonation language",
            f"Email references {brand_count} brand name(s): {', '.join(b for b in BRAND_KW if b in text)}.",
            Severity.MEDIUM, 12, {"brands": brand_count}))

    if any(p in text for p in CREDENTIAL):
        findings.append(make_finding(
            NAME, "Credential/OTP theft language",
            "Email requests passwords, login, or one-time codes.",
            Severity.MEDIUM, 12, {}))

    html = email.body_html or ""
    if html:
        fp = _FormParser()
        try:
            fp.feed(html)
        except Exception:
            pass
        if fp.external_forms:
            findings.append(make_finding(
                NAME, "External HTML form",
                f"Email HTML contains {fp.external_forms} form(s) posting to external sites (possible credential harvest).",
                Severity.HIGH, 18, {"forms": fp.external_forms}))

    blob = _BASE64_RE.search(email.body_text or "")
    if blob and len(blob.group(0)) > 80:
        findings.append(make_finding(
            NAME, "Obfuscated content",
            "Long base64 blob detected in body, common in encoded phishing payloads.",
            Severity.LOW, 6, {}))

    generic = any(g in text for g in ["dear customer", "dear user", "valued customer", "dear valued"])
    if generic and not email.body_text.strip().lower().startswith("hi") and not email.receiver_email:
        findings.append(make_finding(
            NAME, "Generic greeting",
            "Email uses a generic greeting with no personalization.",
            Severity.LOW, 4, {}))

    return result(NAME, findings, MAX_SCORE, {"phrase_hits": hits})
