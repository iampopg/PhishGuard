from __future__ import annotations

import json
import zipfile
from io import BytesIO
from typing import Any, Dict


def build_takedown_package(report: Dict[str, Any], iocs: Dict[str, Any],
                           enrichment: Dict[str, Any] | None = None) -> bytes:
    """Build a takedown/intel package as a STIX-lite JSON + abuse-report txt in a zip."""
    bundle = {
        "type": "bundle",
        "spec_version": "2.1",
        "id": f"bundle--{report.get('report_id', 'unknown')}",
        "created": report.get("timestamp"),
        "objects": [
            {
                "type": "report",
                "id": f"report--{report.get('report_id', 'unknown')}",
                "name": (report.get("source", {}) or {}).get("subject") or "PhishGuard detection",
                "description": report.get("summary"),
                "labels": [report.get("verdict")],
                "object_refs": [
                    f"indicator--{report.get('report_id', 'unknown')}"
                ],
            },
            {
                "type": "indicator",
                "id": f"indicator--{report.get('report_id', 'unknown')}",
                "pattern": _stix_pattern(iocs),
                "valid_from": report.get("timestamp"),
                "labels": [report.get("verdict")],
            },
        ],
    }

    abuse_txt = _abuse_report(report, iocs)

    summary = {
        "report_id": report.get("report_id"),
        "verdict": report.get("verdict"),
        "risk_score": report.get("risk_score"),
        "sender": report.get("sender", {}),
        "iocs": iocs,
        "enrichment_summary": (enrichment or {}).get("summary"),
    }

    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("stix-bundle.json", json.dumps(bundle, indent=2, default=str))
        zf.writestr("abuse-report.txt", abuse_txt)
        zf.writestr("summary.json", json.dumps(summary, indent=2, default=str))
        zf.writestr("full-report.json", json.dumps(report, indent=2, default=str))
    return buf.getvalue()


def _stix_pattern(iocs: Dict[str, Any]) -> str:
    parts = []
    for u in (iocs.get("urls") or [])[:100]:
        parts.append(f"url:value = '{_esc(u)}'")
    for d in (iocs.get("domains") or [])[:100]:
        parts.append(f"domain-name:value = '{_esc(d)}'")
    for ip in (iocs.get("ips") or [])[:100]:
        parts.append(f"ipv4-addr:value = '{_esc(ip)}'")
    for h in (iocs.get("sha256") or [])[:100]:
        parts.append(f"file:hashesSHA-256 = '{_esc(h)}'")
    return " OR ".join(parts) if parts else "[email:subject EXISTS]"


def _esc(v: str) -> str:
    return str(v).replace("'", "\\'")


def _abuse_report(report: Dict[str, Any], iocs: Dict[str, Any]) -> str:
    sender = report.get("sender", {}) or {}
    lines = [
        "ABUSE / PHISHING TAKE-DOWN REQUEST",
        "=" * 40,
        f"Report ID: {report.get('report_id')}",
        f"Detected:  {report.get('timestamp')}",
        f"Verdict:   {report.get('verdict')} (score {report.get('risk_score')})",
        f"Sender:    {sender.get('from')}",
        f"From domain: {sender.get('from_domain')}",
        f"Subject:   {(report.get('source', {}) or {}).get('subject')}",
        "",
        "INDICATORS OF COMPROMISE:",
    ]
    for d in iocs.get("domains") or []:
        lines.append(f"  domain: {d}")
    for u in iocs.get("urls") or []:
        lines.append(f"  url: {u}")
    for ip in iocs.get("ips") or []:
        lines.append(f"  ip: {ip}")
    for h in iocs.get("sha256") or []:
        lines.append(f"  sha256: {h}")
    for w in iocs.get("wallets") or []:
        lines.append(f"  wallet ({w.get('currency')}): {w.get('address')}")
    lines += ["", "Please review and take action."]
    return "\n".join(lines)
