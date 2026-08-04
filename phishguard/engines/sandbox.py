from __future__ import annotations

from phishguard.engines.base import AnalysisContext, make_finding, result
from phishguard.models import AnalyzerResult, ParsedEmail, Severity
from phishguard.sandbox import SandboxManager

NAME = "sandbox"
MAX_SCORE = 45


def analyze(email: ParsedEmail, ctx: AnalysisContext) -> AnalyzerResult:
    findings = []
    if not getattr(ctx.config, "clamav_enabled", False) and not getattr(ctx.config, "vt_enabled", False):
        return result(NAME, findings, MAX_SCORE, {"enabled": False})

    manager = SandboxManager(ctx.config, ctx.intel)
    for att in email.attachments:
        data = getattr(att, "payload", None)
        if data is None:
            continue
        try:
            verdict = manager.scan(att.filename, data)
        except Exception:
            continue
        if verdict.get("malicious"):
            findings.append(make_finding(
                NAME, "Malicious attachment (sandbox)",
                f"Attachment '{att.filename}' flagged by sandbox: {verdict.get('detail')}.",
                Severity.CRITICAL, 40, {"filename": att.filename, "detail": verdict.get("detail")}))

    return result(NAME, findings, MAX_SCORE, {"enabled": True})
