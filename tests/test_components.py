from __future__ import annotations

from pathlib import Path

from phishguard.config import Config
from phishguard.engines.base import AnalysisContext
from phishguard.intel import IntelligenceHub
from phishguard.models import (AnalyzerResult, Attachment, AuthResult, Finding,
                               ParsedEmail, Report, Severity, Verdict)
from phishguard.org_profile import OrgProfile
from phishguard.rules import DEFAULT_RULES, evaluate_rules
from phishguard.engines.scoring import aggregate, recommended_actions

FIX = Path(__file__).parent / "fixtures"


def _ctx(org=None, behavioral=None):
    return AnalysisContext(
        config=Config(),
        org_profile=org or OrgProfile(),
        intel=IntelligenceHub(Config(), cache_dir=FIX / ".cache"),
        behavioral=behavioral, mailbox_id="t",
    )


def _email(**kw) -> ParsedEmail:
    base = dict(
        message_id=None, subject="Subject", from_header="", to_header="",
        date_header="", sender_name="", sender_email="a@from.com",
        sender_domain="from.com", receiver_email="b@to.com", receiver_domain="to.com",
        envelope_from="a@from.com", reply_to=None, return_path="a@from.com",
        body_text="", body_html="", urls=[], attachments=[],
        auth=AuthResult(), authentication_results={}, raw_headers={},
    )
    base.update(kw)
    return ParsedEmail(**base)


# ---- Per-analyzer coverage ----

def test_header_auth_spf_fail():
    from phishguard.engines.header_auth import analyze
    e = _email(auth=AuthResult(spf="fail", dkim="pass", dmarc="pass"))
    res = analyze(e, _ctx())
    assert any("SPF" in f.title for f in res.findings)


def test_header_analysis_replyto_mismatch():
    from phishguard.engines.header_analysis import analyze
    e = _email(reply_to="evil@other.com")
    res = analyze(e, _ctx())
    assert any("Reply-To" in f.title for f in res.findings)


def test_domain_reputation_lookalike():
    from phishguard.engines.domain_reputation import analyze
    org = OrgProfile(brand_domains=["paypal.com"])
    e = _email(sender_domain="paypa1.com", sender_email="x@paypa1.com")
    res = analyze(e, _ctx(org=org))
    assert any("Lookalike" in f.title for f in res.findings)


def test_org_context_brand_in_display():
    from phishguard.engines.org_context import analyze
    org = OrgProfile(brand_keywords=["paypal"], protected_domains=["company.com"])
    e = _email(sender_name="PayPal Security", sender_domain="evil.com", sender_email="x@evil.com")
    res = analyze(e, _ctx(org=org))
    assert any("Brand" in f.title for f in res.findings)


def test_url_scanner_ip_and_shortener():
    from phishguard.engines.url_scanner import analyze
    e = _email(urls=["http://1.2.3.4/login", "https://bit.ly/abc"])
    res = analyze(e, _ctx())
    titles = [f.title for f in res.findings]
    assert any("IP address" in t for t in titles)
    assert any("shortener" in t for t in titles)


def test_content_analyzer_urgency():
    from phishguard.engines.content_analyzer import analyze
    e = _email(body_text="urgent verify now password OTP invoice wire transfer bank CEO final notice")
    res = analyze(e, _ctx())
    assert any("social-engineering" in f.title for f in res.findings)


def test_attachment_executable():
    from phishguard.engines.attachment_analyzer import analyze
    e = _email(attachments=[Attachment("invoice.exe", "application/octet-stream", 1, "s", "m")])
    res = analyze(e, _ctx())
    assert any("Executable" in f.title for f in res.findings)


def test_url_scanner_intel_flag():
    from phishguard.engines.url_scanner import analyze
    class StubIntel:
        def check_url(self, url):
            return {"malicious": True, "source": "urlhaus"}
    e = _email(urls=["http://bad.example/login"])
    ctx = _ctx()
    ctx.intel = StubIntel()
    res = analyze(e, ctx)
    assert any("threat intel" in f.title for f in res.findings)


# ---- Scoring & rules ----

def test_scoring_thresholds():
    assert aggregate([AnalyzerResult("x", 95, [])])[1] == Verdict.MALICIOUS
    assert aggregate([AnalyzerResult("x", 70, [])])[1] == Verdict.PHISHING
    assert aggregate([AnalyzerResult("x", 40, [])])[1] == Verdict.SUSPICIOUS
    assert aggregate([AnalyzerResult("x", 5, [])])[1] == Verdict.SAFE


def test_recommended_actions_for_verdict():
    assert "quarantine" in recommended_actions(Verdict.MALICIOUS)
    assert "monitor" in recommended_actions(Verdict.SAFE)


def test_rules_quarantine_on_hard_auth_fail():
    ar = AnalyzerResult("header_auth", 25, [Finding("header_auth", "SPF verification failed", "d", Severity.HIGH, 25)])
    report = Report(
        report_id="r", timestamp="t", source={}, verdict=Verdict.SUSPICIOUS,
        risk_score=25, summary="s", sender={}, analyzers=[ar],
        urls=[], attachments=[], recommended_actions=[], labels={},
    )
    actions = evaluate_rules(report, DEFAULT_RULES)
    assert "quarantine" in actions


# ---- Intel offline default ----

def test_intel_offline_returns_non_malicious():
    intel = IntelligenceHub(Config(), cache_dir=FIX / ".cache2")
    assert intel.check_url("http://example.com").get("malicious") is False
    assert intel.check_hash("0" * 64).get("malicious") is False
