from __future__ import annotations

from phishguard.models import Severity
from phishguard.rules.engine import Rule

DEFAULT_RULES: List[Rule] = [
    Rule(
        id="quarantine_failed_auth",
        description="Quarantine when authentication (SPF/DKIM/DMARC) fails hard.",
        action="quarantine",
        analyzer="header_auth",
        severity_at_least=Severity.HIGH,
    ),
    Rule(
        id="quarantine_lookalike",
        description="Quarantine when a brand/your-domain lookalike is detected.",
        action="quarantine",
        title_contains="Lookalike",
        severity_at_least=Severity.HIGH,
    ),
    Rule(
        id="quarantine_executable",
        description="Quarantine messages carrying executable or macro attachments.",
        action="quarantine",
        title_contains="Executable",
        severity_at_least=Severity.HIGH,
    ),
    Rule(
        id="notify_soc_malicious_url",
        description="Notify SOC when a critical URL threat (phishing/C2) is found.",
        action="notify_soc",
        analyzer="url_scanner",
        severity_at_least=Severity.CRITICAL,
    ),
    Rule(
        id="review_suspicious",
        description="Route to analyst review queue for suspicious content.",
        action="review",
        severity_at_least=Severity.MEDIUM,
    ),
    Rule(
        id="train_user_phish",
        description="Flag for user phishing-awareness training at phishing verdict.",
        action="train_user",
        severity_at_least=Severity.HIGH,
    ),
]
