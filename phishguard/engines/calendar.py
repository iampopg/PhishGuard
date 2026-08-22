from __future__ import annotations

import re
from typing import Any, Dict, List

from phishguard.engines.base import AnalysisContext, make_finding, result
from phishguard.models import AnalyzerResult, ParsedEmail, Severity
from phishguard.util.text import is_lookalike, registrable_domain

NAME = "calendar"
MAX_SCORE = 40

_URGENCY = ["action required", "respond", "rsvp", "mandatory", "immediately",
            "deadline", "expire", "reminder:", "urgent"]
_URL_RE = re.compile(r"https?://[^\s\"'<>\)]+", re.IGNORECASE)


def _extract_links(text: str) -> List[str]:
    return [u.rstrip(".,);") for u in _URL_RE.findall(text or "")]


def _parse_ics(text: str) -> Dict[str, Any]:
    """Minimal RFC 5545 heuristic parser (no icalendar dependency required)."""
    fields: Dict[str, str] = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.split(";")[0].strip().upper()
        if key in ("SUMMARY", "DESCRIPTION", "LOCATION", "ORGANIZER", "STATUS",
                   "ATTENDEE", "URL", "DTSTART", "DTEND"):
            fields.setdefault(key, val.strip())
    return fields


def analyze(email: ParsedEmail, ctx: AnalysisContext) -> AnalyzerResult:
    findings: List = []

    ics_parts = []
    for att in email.attachments:
        fn = (att.filename or "").lower()
        ctype = (att.content_type or "").lower()
        if fn.endswith(".ics") or "calendar" in ctype or "ics" in fn:
            try:
                ics_parts.append(att.payload.decode("utf-8", "replace"))
            except Exception:
                ics_parts.append("")

    cal_text = ((email.body_text or "") + "\n" + (email.body_html or "")).lower()
    looks_like_calendar = (
        "calendar" in cal_text or "text/calendar" in cal_text
        or "vevent" in cal_text or "begin:vcalendar" in cal_text or ics_parts
    )

    if not looks_like_calendar:
        return result(NAME, findings, MAX_SCORE, {"enabled": True})

    if ics_parts:
        findings.append(make_finding(
            NAME, "Calendar invite attached",
            "Message carries an .ics calendar attachment, a common delivery for phishing events.",
            Severity.MEDIUM, 8, {}))

    combined = (email.body_text or "") + "\n" + (ics_parts[0] if ics_parts else "")
    ics_fields = _parse_ics(ics_parts[0]) if ics_parts else {}

    body_low = (email.body_text or "").lower()
    if any(u in body_low for u in _URGENCY):
        findings.append(make_finding(
            NAME, "Urgent calendar event",
            "Calendar invite uses urgent/time-pressure language to provoke quick action.",
            Severity.MEDIUM, 6, {}))

    link_domains = set()
    for url in _extract_links(email.body_text or "") + _extract_links(ics_fields.get("DESCRIPTION", "")):
        link_domains.add(registrable_domain(url))

    for dom in link_domains:
        if not dom:
            continue
        for target in ctx.org_profile.protected_domains:
            if is_lookalike(dom, target) and not ctx.org_profile.is_trusted(dom):
                findings.append(make_finding(
                    NAME, "Calendar link to lookalike domain",
                    f"Calendar event links to '{dom}', a lookalike of protected domain '{target}'.",
                    Severity.CRITICAL, 18, {"domain": dom, "protected": target}))
                break

    if ics_fields.get("SUMMARY"):
        findings.append(make_finding(
            NAME, "Calendar invite summary",
            f"Invite subject: {ics_fields['SUMMARY'][:120]}.",
            Severity.INFO, 0, {"summary": ics_fields["SUMMARY"]}))

    return result(NAME, findings, MAX_SCORE, {"enabled": True, "has_calendar": True})
