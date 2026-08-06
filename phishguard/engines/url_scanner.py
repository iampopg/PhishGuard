from __future__ import annotations

from html.parser import HTMLParser
from typing import Dict, List, Optional

from phishguard.engines.base import AnalysisContext, make_finding, result
from phishguard.models import AnalyzerResult, ParsedEmail, Severity
from phishguard.util.text import extract_urls, is_lookalike, normalize_domain, registrable_domain

NAME = "url_scanner"
MAX_SCORE = 60

SUSPICIOUS_TLDS = {
    "tk", "top", "xyz", "click", "country", "link", "gq", "ml", "ga", "cf",
    "ru", "cn", "info", "stream", "download", "loan", "racing", "win",
}
SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "rb.gy", "cutt.ly",
    "is.gd", "buff.ly", "tiny.cc", "rebrand.ly", "shorturl.at",
}


class _AnchorParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: List[Dict[str, str]] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            href = ""
            text = ""
            for k, v in attrs:
                if k.lower() == "href":
                    href = v or ""
            self.links.append({"href": href, "text": text})

    def handle_data(self, data):
        if self.links:
            self.links[-1]["text"] += data


def extract_anchors(html: str) -> List[Dict[str, str]]:
    if not html:
        return []
    p = _AnchorParser()
    try:
        p.feed(html)
    except Exception:
        return []
    return p.links


def _host_is_ip(host: str) -> bool:
    return host.strip("[]").replace(".", "").isdigit() or host.startswith("[")


def analyze(email: ParsedEmail, ctx: AnalysisContext) -> AnalyzerResult:
    findings = []
    urls = list(email.urls)
    anchors = extract_anchors(email.body_html)
    display_mismatch = False

    for a in anchors:
        href = a.get("href", "")
        text = a.get("text", "").strip()
        if not href or not text:
            continue
        text_urls = extract_urls(text)
        for tu in text_urls:
            th = registrable_domain(tu)
            hh = registrable_domain(href)
            if th and hh and normalize_domain(th) != normalize_domain(hh):
                display_mismatch = True
                findings.append(make_finding(
                    NAME, "Display text URL mismatches link",
                    f"Visible URL domain '{th}' differs from actual link domain '{hh}'.",
                    Severity.HIGH, 20, {"display": tu, "href": href}))

    seen = set()
    for url in urls:
        if url in seen:
            continue
        seen.add(url)
        host = registrable_domain(url)
        if not host:
            continue

        if _host_is_ip(host):
            findings.append(make_finding(
                NAME, "URL uses IP address",
                f"URL '{url}' points to an IP address instead of a domain.",
                Severity.HIGH, 20, {"url": url}))

        tld = host.split(".")[-1].lower() if "." in host else ""
        if tld in SUSPICIOUS_TLDS:
            findings.append(make_finding(
                NAME, "Suspicious TLD",
                f"URL host '{host}' uses frequently-abused TLD '.{tld}'.",
                Severity.LOW, 4, {"url": url, "tld": tld}))

        if host in SHORTENERS:
            findings.append(make_finding(
                NAME, "URL shortener",
                f"URL '{url}' uses a shortening service; final destination is hidden.",
                Severity.LOW, 2, {"url": url}))

        for brand in ctx.org_profile.brand_domains:
            if is_lookalike(host, brand):
                findings.append(make_finding(
                    NAME, "URL host impersonates brand",
                    f"URL host '{host}' is a lookalike of brand domain '{brand}'.",
                    Severity.HIGH, 25, {"url": url, "brand": brand}))

        intel = getattr(ctx, "intel", None)
        if intel is not None and hasattr(intel, "check_url"):
            try:
                verdict = intel.check_url(url)
                if verdict and verdict.get("malicious"):
                    findings.append(make_finding(
                        NAME, "Malicious URL (threat intel)",
                        f"URL '{url}' flagged by threat intelligence: {verdict.get('source')}.",
                        Severity.CRITICAL, 35, {"url": url, "source": verdict.get("source")}))
            except Exception:
                pass

    if display_mismatch is False and not urls:
        pass

    return result(NAME, findings, MAX_SCORE, {"url_count": len(urls)})


def recheck_url(url: str, ctx: AnalysisContext) -> Dict[str, object]:
    intel = getattr(ctx, "intel", None)
    if intel is not None and hasattr(intel, "check_url"):
        try:
            return intel.check_url(url) or {}
        except Exception:
            return {"error": "intel check failed"}
    return {"url": url, "status": "no_intel_configured"}
