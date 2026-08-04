from __future__ import annotations

from typing import Dict, Optional

from phishguard.engines.base import AnalysisContext, make_finding, result
from phishguard.models import AnalyzerResult, ParsedEmail, Severity
from phishguard.util.text import normalize_domain, registrable_domain

NAME = "header_auth"
MAX_SCORE = 60


def _parse_auth_results(raw: Dict[str, str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for key in ("spf", "dkim", "dmarc"):
        val = raw.get(key)
        if val:
            out[key] = val.lower()
    return out


def _dmarc_record_present(domain: str) -> Optional[bool]:
    try:
        import dns.resolver  # type: ignore
    except Exception:
        return None
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=3)
        for rdata in answers:
            txt = rdata.to_text()
            if "v=dmarc1" in txt.lower():
                return True
    except Exception:
        return False
    return False


def analyze(email: ParsedEmail, ctx: AnalysisContext) -> AnalyzerResult:
    findings = []
    auth = email.auth
    ar = _parse_auth_results(email.authentication_results)

    spf = ar.get("spf", auth.spf)
    dkim = ar.get("dkim", auth.dkim)
    dmarc = ar.get("dmarc", auth.dmarc)

    if spf in ("fail", "softfail", "none") and spf != "unknown":
        findings.append(make_finding(
            NAME, "SPF verification failed",
            f"SPF result '{spf}' for sender domain {email.sender_domain}.",
            Severity.HIGH, 25, {"spf": spf, "domain": email.sender_domain}))

    if dkim in ("fail", "none") and dkim != "unknown":
        findings.append(make_finding(
            NAME, "DKIM verification failed",
            f"DKIM result '{dkim}' for sender domain {email.sender_domain}.",
            Severity.MEDIUM, 15, {"dkim": dkim, "domain": email.sender_domain}))

    if dmarc in ("fail", "none") and dmarc != "unknown":
        findings.append(make_finding(
            NAME, "DMARC verification failed",
            f"DMARC result '{dmarc}' for sender domain {email.sender_domain}.",
            Severity.HIGH, 20, {"dmarc": dmarc, "domain": email.sender_domain}))
    elif dmarc == "unknown" and not ctx.org_profile.is_trusted(email.sender_domain):
        findings.append(make_finding(
            NAME, "No authentication results",
            "No SPF/DKIM/DMARC results present in headers; cannot verify sender authenticity.",
            Severity.LOW, 5, {"domain": email.sender_domain}))

    env_dom = email.envelope_from and registrable_domain(email.envelope_from)
    from_dom = registrable_domain(email.sender_domain)
    if env_dom and from_dom and normalize_domain(env_dom) != normalize_domain(from_dom):
        findings.append(make_finding(
            NAME, "Envelope/Header domain mismatch",
            f"Envelope sender domain '{env_dom}' differs from From domain '{from_dom}'.",
            Severity.MEDIUM, 15, {"envelope": env_dom, "from": from_dom}))

    if getattr(ctx.config, "dns_checks_enabled", False):
        present = _dmarc_record_present(email.sender_domain)
        if present is False:
            findings.append(make_finding(
                NAME, "No DMARC policy published",
                f"Domain {email.sender_domain} has no DMARC TXT record (v=DMARC1).",
                Severity.LOW, 5, {"domain": email.sender_domain}))

    metadata: Dict[str, object] = {"spf": spf, "dkim": dkim, "dmarc": dmarc}
    return result(NAME, findings, MAX_SCORE, metadata)
