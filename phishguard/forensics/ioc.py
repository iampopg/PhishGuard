from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List


_WALLET_RE = {
    "btc": re.compile(r"\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b"),
    "eth": re.compile(r"\b0x[0-9a-fA-F]{40}\b"),
    "ltc": re.compile(r"\b(ltc1|LM|ltc)[a-zA-HJ-NP-Z0-9]{25,62}\b"),
    "xmr": re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),
}

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


@dataclass
class IOCs:
    """Extracted observables from an email/message."""

    urls: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    sha256: List[str] = field(default_factory=list)
    md5: List[str] = field(default_factory=list)
    wallets: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "urls": self.urls,
            "domains": self.domains,
            "ips": self.ips,
            "emails": self.emails,
            "sha256": self.sha256,
            "md5": self.md5,
            "wallets": self.wallets,
            "counts": {
                "urls": len(self.urls),
                "domains": len(self.domains),
                "ips": len(self.ips),
                "emails": len(self.emails),
                "sha256": len(self.sha256),
                "wallets": len(self.wallets),
            },
        }


def _norm_domain(d: str) -> str:
    return (d or "").strip().lower().rstrip(".")


def _dedupe(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for i in items:
        key = (i or "").strip()
        if key and key not in seen:
            seen.add(key)
            out.append(key)
    return out


def extract_iocs(report: Dict[str, Any]) -> IOCs:
    """Extract observables from an analysis report (as produced by Report.to_dict)."""
    iocs = IOCs()
    if not report:
        return iocs

    for u in report.get("urls", []) or []:
        url = (u.get("url") if isinstance(u, dict) else u) or ""
        if url:
            iocs.urls.append(url)

    for att in report.get("attachments", []) or []:
        if not isinstance(att, dict):
            continue
        sha = att.get("sha256")
        md5 = att.get("md5")
        if sha:
            iocs.sha256.append(sha)
        if md5:
            iocs.md5.append(md5)

    sender = report.get("sender", {}) or {}
    for key in ("from", "display_name", "envelope_from"):
        v = sender.get(key)
        if isinstance(v, str) and "@" in v:
            iocs.emails.append(v)

    source = report.get("source", {}) or {}
    subject = source.get("subject") or ""

    blob = " ".join([
        subject or "",
        report.get("summary") or "",
        report.get("body_text") or "",
        report.get("body_html") or "",
    ])

    for m in _EMAIL_RE.findall(blob):
        if "@" in m:
            iocs.emails.append(m)

    seen_domains: Dict[str, None] = {}
    for url in iocs.urls:
        host = (url.split("://", 1)[-1].split("/", 1)[0].split("@")[-1].split(":")[0]).lower().rstrip(".")
        if host:
            seen_domains[host] = None
    iocs.domains = list(seen_domains.keys())

    for m in _IP_RE.findall(blob):
        iocs.ips.append(m)

    for currency, rx in _WALLET_RE.items():
        for m in rx.findall(blob):
            iocs.wallets.append({"currency": currency, "address": m})

    iocs.urls = _dedupe(iocs.urls)
    iocs.domains = _dedupe(iocs.domains)
    iocs.ips = _dedupe(iocs.ips)
    iocs.emails = _dedupe(iocs.emails)
    iocs.sha256 = _dedupe(iocs.sha256)
    iocs.md5 = _dedupe(iocs.md5)
    return iocs
