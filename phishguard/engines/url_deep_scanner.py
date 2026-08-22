from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from phishguard.engines.base import AnalysisContext, make_finding, result
from phishguard.models import AnalyzerResult, ParsedEmail, Severity
from phishguard.util.text import is_lookalike, normalize_domain, registrable_domain

NAME = "url_deep_scanner"
MAX_SCORE = 50

_FORM_INDICATORS = ("password", "passwd", "pwd", "login", "signin", "sign-in",
                     "credential", "ssn", "credit-card", "card-number")
_SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "rb.gy", "cutt.ly",
    "is.gd", "buff.ly", "tiny.cc", "rebrand.ly", "shorturl.at",
}
_KNOWN_TRACKERS = {
    "sendpulse.net", "spsndr.com", "sendpul.se", "spsndr.net", "spsndr.ru",
    "mailchimp.com", "mandrillapp.com", "sendgrid.net", "exacttarget.com",
    "constantcontact.com", "campaignmonitor.com", "impincdn.net", "_feedback",
    "hubspotemail.net", "hubspotlinks.com", "pardot.com", "marketodesigner.com",
    "aweber.com", "getresponse.com", "klaviyo.com", "omnisend.com", "mailgun.org",
}
_TRACKER_SUFFIXES = ("spsndr.com", "sendpul.se", "sendpulse.net", "spsndr.net",
                     "spsndr.ru", "empretienda.com", "acumbamail.com")


def _is_known_tracker(domain: str) -> bool:
    if not domain:
        return False
    d = domain.lower()
    if d in _KNOWN_TRACKERS:
        return True
    return any(d.endswith(s) for s in _TRACKER_SUFFIXES)


def _fetch(ctx: AnalysisContext, url: str) -> Dict[str, Any]:
    """Best-effort fetch of a landing page. Returns a trace dict. Never raises."""
    import requests
    max_redirects = int(getattr(ctx.config, "url_deep_max_redirects", 5))
    timeout = int(getattr(ctx.config, "url_deep_timeout", 15))
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True,
                         headers={"User-Agent": "PhishGuard/1.0"})
        history = [h.headers.get("Location", "") for h in r.history]
        return {
            "ok": True,
            "status": r.status_code,
            "final_url": r.url,
            "redirects": history,
            "n_redirects": len(r.history),
            "content_type": r.headers.get("Content-Type", ""),
            "text": r.text[:20000],
        }
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def _looks_like_login(html: str) -> bool:
    if not html:
        return False
    low = html.lower()
    inputs = low.count("<input")
    if inputs < 2:
        return False
    forms = low.count("<form")
    if forms < 1:
        return False
    return any(ind in low for ind in _FORM_INDICATORS)


def analyze(email: ParsedEmail, ctx: AnalysisContext) -> AnalyzerResult:
    findings: List = []
    if not getattr(ctx.config, "url_deep_scan_enabled", True):
        return result(NAME, findings, MAX_SCORE, {"enabled": False})

    max_urls = 6
    for url in email.urls[:max_urls]:
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
        except Exception:
            continue
        if not host:
            continue

        # Resolve shorteners eagerly (cheap relative signal).
        if host in _SHORTENERS:
            findings.append(make_finding(
                NAME, "URL shortener resolved",
                f"URL '{url}' uses a shortening service; final destination hidden.",
                Severity.LOW, 2, {"url": url}))
            continue

        trace = _fetch(ctx, url)
        if not trace.get("ok"):
            findings.append(make_finding(
                NAME, "URL unreachable",
                f"Could not reach '{url}': {trace.get('error', 'unknown')}",
                Severity.INFO, 1, {"url": url}))
            continue

        chain = []
        if trace["n_redirects"] >= 3:
            findings.append(make_finding(
                NAME, "Excessive redirect chain",
                f"URL '{url}' crossed {trace['n_redirects']} redirects.",
                Severity.MEDIUM, 8, {"url": url, "redirects": trace["n_redirects"]}))
            chain.append("redirects")

        final_host = ""
        try:
            final_host = (urlparse(trace["final_url"]).hostname or "").lower()
        except Exception:
            pass
        orig_dom = registrable_domain(host)
        final_dom = registrable_domain(final_host)
        if orig_dom and final_dom and normalize_domain(orig_dom) != normalize_domain(final_dom) \
                and not _is_known_tracker(final_dom) and not _is_known_tracker(host):
            sev = Severity.HIGH if trace["n_redirects"] >= 2 else Severity.MEDIUM
            score = 15 if trace["n_redirects"] >= 2 else 8
            findings.append(make_finding(
                NAME, "Redirect crosses to different domain",
                f"URL '{url}' redirects from {orig_dom} to {final_dom}.",
                sev, score, {"url": url, "from": orig_dom, "to": final_dom}))
            chain.append("domain_change")

        for brand in ctx.org_profile.brand_domains:
            if final_dom and is_lookalike(final_dom, brand) and not ctx.org_profile.is_trusted(final_dom):
                findings.append(make_finding(
                    NAME, "Landing page impersonates brand (deep)",
                    f"Final domain '{final_dom}' is a lookalike of brand '{brand}'.",
                    Severity.CRITICAL, 20, {"url": url, "final_domain": final_dom, "brand": brand}))
                break

        if _looks_like_login(trace.get("text", "")) and not ctx.org_profile.is_trusted(final_dom):
            findings.append(make_finding(
                NAME, "Landing page resembles credential form",
                f"URL '{url}' hosts a page with a login/credential form at {final_dom}.",
                Severity.HIGH, 18, {"url": url, "final_domain": final_dom}))
            chain.append("credential_form")

    metadata: Dict[str, Any] = {"enabled": True, "scanned": min(len(email.urls), max_urls)}
    if not email.urls:
        metadata["scanned"] = 0
    return result(NAME, findings, MAX_SCORE, metadata)
