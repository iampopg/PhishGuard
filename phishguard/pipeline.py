from __future__ import annotations

from typing import Callable, Dict, List, Optional

from phishguard.engines.attachment_analyzer import analyze as attachment_analyze
from phishguard.engines.sandbox import analyze as sandbox_analyze
from phishguard.engines.content_analyzer import analyze as content_analyze
from phishguard.engines.domain_reputation import analyze as domain_analyze
from phishguard.engines.header_analysis import analyze as header_analysis_analyze
from phishguard.engines.header_auth import analyze as header_auth_analyze
from phishguard.engines.org_context import analyze as org_context_analyze
from phishguard.engines.scoring import aggregate, recommended_actions
from phishguard.engines.url_scanner import analyze as url_analyze
from phishguard.engines.url_deep_scanner import analyze as url_deep_analyze
from phishguard.engines.calendar import analyze as calendar_analyze
from phishguard.engines.qr_scanner import analyze as qr_analyze
from phishguard.engines.behavioral import analyze as behavioral_analyze
from phishguard.engines.trust import analyze as trust_analyze
from phishguard.engines.base import AnalysisContext
from phishguard.models import ParsedEmail, Report, new_report_id, now_iso
from phishguard.rules import DEFAULT_RULES, evaluate_rules

DEFAULT_ANALYZERS: List[Callable] = [
    header_auth_analyze,
    header_analysis_analyze,
    domain_analyze,
    org_context_analyze,
    trust_analyze,
    url_analyze,
    url_deep_analyze,
    content_analyze,
    attachment_analyze,
    calendar_analyze,
    qr_analyze,
    sandbox_analyze,
    behavioral_analyze,
]


def _thresholds(config) -> Dict[str, int]:
    return {
        "threshold_suspicious": getattr(config, "threshold_suspicious", 30),
        "threshold_phishing": getattr(config, "threshold_phishing", 60),
        "threshold_malicious": getattr(config, "threshold_malicious", 85),
    }


def analyze_email(
    parsed: ParsedEmail,
    ctx: AnalysisContext,
    analyzers: Optional[List[Callable]] = None,
    rules: Optional[List] = None,
    raw: Optional[bytes] = None,
) -> Report:
    analyzers = analyzers or DEFAULT_ANALYZERS
    rules = rules if rules is not None else DEFAULT_RULES

    results = [fn(parsed, ctx) for fn in analyzers]
    score, verdict = aggregate(results, **_thresholds(ctx.config))

    report = Report(
        report_id=new_report_id(),
        timestamp=now_iso(),
        source={
            "type": "email",
            "message_id": parsed.message_id,
            "subject": parsed.subject,
            "mailbox_id": ctx.mailbox_id,
        },
        verdict=verdict,
        risk_score=score,
        summary=_summary(results, verdict, score),
        sender={
            "from": parsed.sender_email,
            "from_domain": parsed.sender_domain,
            "envelope_from": parsed.envelope_from,
            "display_name": parsed.sender_name,
        },
        analyzers=results,
        urls=[{"url": u} for u in parsed.urls],
        attachments=parsed.attachments,
        recommended_actions=[],
        labels={"org": ctx.org_profile.protected_domains},
        raw_headers=parsed.raw_headers,
        body_text=parsed.body_text,
        body_html=parsed.body_html,
    )

    actions = list(recommended_actions(verdict)) + evaluate_rules(report, rules)
    report.recommended_actions = list(dict.fromkeys(actions))

    if ctx.evidence is not None and getattr(ctx.config, "evidence_enabled", True):
        try:
            ctx.evidence.store_artifacts(
                report.report_id,
                raw=raw,
                headers=parsed.raw_headers,
                body_text=parsed.body_text,
                body_html=parsed.body_html,
                report=report.to_dict(),
            )
        except Exception:
            pass

    return report


def _summary(results, verdict, score) -> str:
    titles = [f.title for r in results for f in r.findings]
    if not titles:
        return f"Verdict {verdict.value}: no significant signals (score {score})."
    head = "; ".join(titles[:4])
    more = "" if len(titles) <= 4 else f" (+{len(titles) - 4} more)"
    return f"Verdict {verdict.value} (score {score}): {head}{more}."
