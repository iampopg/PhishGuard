from __future__ import annotations

import json
import socket
from typing import Optional

from phishguard.config import Config
from phishguard.models import Report, Severity

_SEVERITY_RANK = {
    Severity.INFO: 1, Severity.LOW: 3, Severity.MEDIUM: 5,
    Severity.HIGH: 8, Severity.CRITICAL: 10,
}

_VERDICT_TO_CEF = {"safe": 1, "suspicious": 5, "phishing": 8, "malicious": 10}


def _max_severity(report: Report) -> int:
    rank = 0
    for ar in report.analyzers:
        for f in ar.findings:
            rank = max(rank, _SEVERITY_RANK.get(f.severity, 0))
    return rank or _VERDICT_TO_CEF.get(report.verdict.value, 1)


def _cef_escape(s: str) -> str:
    out = []
    for ch in str(s):
        if ch in '\\=;|"':
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def build_cef(report: Report, vendor: str = "PhishGuard", version: str = "1.0") -> str:
    sig = report.verdict.value.upper()
    name = f"PhishGuard {report.verdict.value} (score {report.risk_score})"
    ext = {
        "msg": report.summary,
        "src": report.sender.get("from", ""),
        "dst": report.source.get("mailbox_id", ""),
        "request": ";".join(u.get("url", "") for u in report.urls[:5]),
        "externalId": report.report_id,
        "cs1Label": "recommendedActions",
        "cs1": ",".join(report.recommended_actions),
    }
    ext_str = " ".join(f"{k}={_cef_escape(v)}" for k, v in ext.items())
    return (
        f"CEF:0|{vendor}|PhishGuard|{version}|{sig}|{_cef_escape(name)}|"
        f"{_max_severity(report)}|{ext_str}"
    )


class ExportManager:
    def __init__(self, config: Config):
        self.config = config
        self.min_rank = _SEVERITY_RANK.get(
            Severity(_safe_sev(config.export_min_severity)), 0
        )

    def should_export(self, report: Report) -> bool:
        if not self.config.export_enabled:
            return False
        return _max_severity(report) >= self.min_rank

    def export(self, report: Report) -> None:
        if not self.should_export(report):
            return
        if self.config.export_syslog_addr:
            self._send_syslog(report)
        if self.config.export_webhook_url:
            self._send_webhook(report)

    def _send_syslog(self, report: Report) -> None:
        host, _, port = self.config.export_syslog_addr.partition(":")
        port = int(port) if port else 514
        msg = build_cef(report) if self.config.export_use_cef else json.dumps(report.to_dict(), default=str)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(msg.encode("utf-8"), (host, port))
            sock.close()
        except Exception:
            pass

    def _send_webhook(self, report: Report) -> None:
        try:
            import requests  # type: ignore
        except Exception:
            return
        try:
            requests.post(self.config.export_webhook_url, json=report.to_dict(), timeout=10)
        except Exception:
            pass


def _safe_sev(value: str) -> str:
    try:
        return Severity(value).value
    except Exception:
        return "medium"
