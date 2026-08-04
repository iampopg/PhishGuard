from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


class Verdict(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    PHISHING = "phishing"
    MALICIOUS = "malicious"


@dataclass
class Finding:
    analyzer: str
    title: str
    detail: str
    severity: Severity
    score: int
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class AnalyzerResult:
    name: str
    score: int
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "score": self.score,
            "findings": [f.to_dict() for f in self.findings],
            "metadata": self.metadata,
        }


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    md5: str
    payload: bytes = b""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("payload", None)
        return d


@dataclass
class AuthResult:
    spf: str = "unknown"
    dkim: str = "unknown"
    dmarc: str = "unknown"
    aligned: bool = False
    envelope_domain: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ParsedEmail:
    message_id: Optional[str]
    subject: str
    from_header: str
    to_header: str
    date_header: str
    sender_name: str
    sender_email: str
    sender_domain: str
    receiver_email: str
    receiver_domain: str
    envelope_from: Optional[str]
    reply_to: Optional[str]
    return_path: Optional[str]
    body_text: str
    body_html: str
    urls: List[str] = field(default_factory=list)
    attachments: List[Attachment] = field(default_factory=list)
    auth: AuthResult = field(default_factory=AuthResult)
    authentication_results: Dict[str, str] = field(default_factory=dict)
    raw_headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class Report:
    report_id: str
    timestamp: str
    source: Dict[str, Any]
    verdict: Verdict
    risk_score: int
    summary: str
    sender: Dict[str, Any]
    analyzers: List[AnalyzerResult]
    urls: List[Dict[str, Any]]
    attachments: List[Attachment]
    recommended_actions: List[str]
    labels: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "report_id": self.report_id,
            "timestamp": self.timestamp,
            "source": self.source,
            "verdict": self.verdict.value,
            "risk_score": self.risk_score,
            "summary": self.summary,
            "sender": self.sender,
            "analyzers": [a.to_dict() for a in self.analyzers],
            "urls": self.urls,
            "attachments": [a.to_dict() for a in self.attachments],
            "recommended_actions": self.recommended_actions,
            "labels": self.labels,
        }

    def to_json(self, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


def new_report_id() -> str:
    return uuid.uuid4().hex


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
