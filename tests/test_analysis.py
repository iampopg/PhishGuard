from __future__ import annotations

from pathlib import Path

from phishguard.config import Config
from phishguard.engines.base import AnalysisContext
from phishguard.intel import IntelligenceHub
from phishguard.mail.parser import parse_message
from phishguard.org_profile import OrgProfile
from phishguard.pipeline import analyze_email

FIXTURES = Path(__file__).parent / "fixtures"


def _ctx() -> AnalysisContext:
    org = OrgProfile(
        protected_domains=["company.com"],
        brand_domains=["paypal.com"],
        trusted_domains=["company.com"],
    )
    return AnalysisContext(
        config=Config(),
        org_profile=org,
        intel=IntelligenceHub(Config(), cache_dir=FIXTURES / ".cache"),
        behavioral=None,
        mailbox_id="test",
    )


def test_phish_sample_flags_malicious_or_phishing():
    raw = (FIXTURES / "sample_phish.eml").read_bytes()
    parsed = parse_message(raw)
    report = analyze_email(parsed, _ctx())

    assert report.risk_score > 0
    assert report.verdict.value in ("phishing", "malicious")

    titles = [f.title for ar in report.analyzers for f in ar.findings]
    assert any("Lookalike" in t for t in titles)
    assert any("Executable" in t for t in titles)


def test_scan_url_offline_runs():
    from phishguard.models import AuthResult, ParsedEmail

    email = ParsedEmail(
        message_id=None, subject=None, from_header="", to_header="",
        date_header="", sender_name="", sender_email="", sender_domain="",
        receiver_email="", receiver_domain="", envelope_from=None,
        reply_to=None, return_path=None, body_text="http://paypa1.com/login",
        body_html="", urls=["http://paypa1.com/login"], attachments=[],
        auth=AuthResult(), authentication_results={}, raw_headers={},
    )
    report = analyze_email(email, _ctx())
    assert report.verdict.value in ("suspicious", "phishing", "malicious")
    assert any("paypa1.com" in str(u) for u in report.urls)
