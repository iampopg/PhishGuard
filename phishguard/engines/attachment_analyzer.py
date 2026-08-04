from __future__ import annotations

from phishguard.engines.base import AnalysisContext, make_finding, result
from phishguard.models import AnalyzerResult, Attachment, ParsedEmail, Severity

NAME = "attachment_analyzer"
MAX_SCORE = 55

EXECUTABLE_EXT = {".exe", ".scr", ".js", ".vbs", ".bat", ".ps1", ".jar",
                  ".com", ".pif", ".cmd", ".msi", ".wsf", ".hta"}
MACRO_OFFICE_EXT = {".docm", ".xlsm", ".pptm"}
HTML_EXT = {".html", ".htm", ".svg", ".xml"}


def _ext(name: str) -> str:
    i = name.lower().rfind(".")
    return name.lower()[i:] if i != -1 else ""


def analyze(email: ParsedEmail, ctx: AnalysisContext) -> AnalyzerResult:
    findings = []
    for att in email.attachments:
        fn = att.filename or ""
        ext = _ext(fn)

        if ext in EXECUTABLE_EXT:
            findings.append(make_finding(
                NAME, "Executable attachment",
                f"Attachment '{fn}' is an executable file type.",
                Severity.CRITICAL, 35, {"filename": fn, "type": ext}))

        if fn.lower().endswith((".docm", ".xlsm", ".pptm")):
            findings.append(make_finding(
                NAME, "Macro-enabled Office document",
                f"Attachment '{fn}' can contain macros (malware risk).",
                Severity.HIGH, 22, {"filename": fn, "type": ext}))

        if ext in HTML_EXT:
            findings.append(make_finding(
                NAME, "HTML attachment",
                f"Attachment '{fn}' is HTML (possible credential-harvest page).",
                Severity.HIGH, 20, {"filename": fn, "type": ext}))

        base = fn.lower()
        if base.count(".") >= 2:
            last_two = base.split(".")[-2:]
            if last_two[0] in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"} and last_two[1] in EXECUTABLE_EXT:
                findings.append(make_finding(
                    NAME, "Double-extension attachment",
                    f"Attachment '{fn}' hides an executable behind a benign extension.",
                    Severity.CRITICAL, 35, {"filename": fn}))

        intel = getattr(ctx, "intel", None)
        if intel is not None and hasattr(intel, "check_hash"):
            try:
                verdict = intel.check_hash(att.sha256)
                if verdict and verdict.get("malicious"):
                    findings.append(make_finding(
                        NAME, "Malicious attachment (threat intel)",
                        f"Attachment '{fn}' hash flagged by threat intelligence: {verdict.get('source')}.",
                        Severity.CRITICAL, 40, {"sha256": att.sha256, "source": verdict.get("source")}))
            except Exception:
                pass

    return result(NAME, findings, MAX_SCORE, {"count": len(email.attachments)})
