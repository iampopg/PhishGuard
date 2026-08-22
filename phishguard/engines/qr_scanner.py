from __future__ import annotations

from typing import Any, Dict, List

from phishguard.engines.base import AnalysisContext, make_finding, result
from phishguard.models import AnalyzerResult, ParsedEmail, Severity
from phishguard.util.text import is_lookalike, registrable_domain

NAME = "qr_scanner"
MAX_SCORE = 40

_IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tiff", ".tif"}


def _decode_qr(data: bytes) -> List[str]:
    """Decode QR codes from image bytes. Returns empty list if pyzbar/PIL unavailable."""
    try:
        from PIL import Image
        import pyzbar.pyzbar as pyzbar  # type: ignore
    except Exception:
        return []
    try:
        img = Image.open(__import__("io").BytesIO(data))
        results = pyzbar.decode(img)
        return [r.data.decode("utf-8", "replace") for r in results]
    except Exception:
        return []


def analyze(email: ParsedEmail, ctx: AnalysisContext) -> AnalyzerResult:
    findings: List = []
    available = True
    try:
        import importlib
        importlib.import_module("pyzbar")
        importlib.import_module("PIL")
    except Exception:
        available = False

    if not available:
        return result(NAME, findings, MAX_SCORE, {"enabled": False, "reason": "pyzbar/PIL not installed"})

    payloads: List[str] = []
    for att in email.attachments:
        fn = (att.filename or "").lower()
        if not any(fn.endswith(ext) for ext in _IMAGE_EXT):
            continue
        if not att.payload:
            continue
        decoded = _decode_qr(att.payload)
        payloads.extend(decoded)

    seen = set()
    for payload in payloads:
        if payload in seen:
            continue
        seen.add(payload)
        if payload.startswith(("http://", "https://")):
            host = registrable_domain(payload)
            flagged = False
            for target in ctx.org_profile.protected_domains:
                if host and is_lookalike(host, target) and not ctx.org_profile.is_trusted(host):
                    findings.append(make_finding(
                        NAME, "QR code links to lookalike domain",
                        f"QR code in attachment points to '{payload}', lookalike of protected domain '{target}'.",
                        Severity.CRITICAL, 22, {"payload": payload, "domain": host, "protected": target}))
                    flagged = True
                    break
            if not flagged:
                findings.append(make_finding(
                    NAME, "QR code embeds URL",
                    f"QR code in attachment contains a URL: {payload}.",
                    Severity.MEDIUM, 8, {"payload": payload}))
        else:
            findings.append(make_finding(
                NAME, "QR code content extracted",
                f"QR code in attachment contains: {payload[:120]}.",
                Severity.LOW, 2, {"payload": payload}))

    return result(NAME, findings, MAX_SCORE,
                   {"enabled": True, "qrcodes": len(seen)})
