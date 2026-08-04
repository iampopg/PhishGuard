from __future__ import annotations

from pathlib import Path

from phishguard.behavioral_store import BehavioralStore
from phishguard.config import Config
from phishguard.engines.base import AnalysisContext
from phishguard.engines.behavioral import analyze as behavioral_analyze
from phishguard.export import ExportManager, build_cef
from phishguard.feeds import FeedManager
from phishguard.models import AuthResult, ParsedEmail, Verdict
from phishguard.org_profile import OrgProfile
from phishguard.report_store import ReportStore


def _report(verdict=Verdict.MALICIOUS, score=90):
    from phishguard.models import (AnalyzerResult, Finding, Severity,
                                   new_report_id, now_iso, Report, Attachment)
    ar = AnalyzerResult(name="t", score=10, findings=[Finding("t", "x", "d", Severity.HIGH, 10)])
    return Report(
        report_id=new_report_id(), timestamp=now_iso(),
        source={"mailbox_id": "mb", "message_id": None},
        verdict=verdict, risk_score=score, summary="s",
        sender={"from": "a@b.com"}, analyzers=[ar],
        urls=[{"url": "http://x"}], attachments=[Attachment("a", "text/plain", 1, "s", "m")],
        recommended_actions=["quarantine"], labels={},
    )


def test_report_store_roundtrip(tmp_path):
    store = ReportStore(str(tmp_path / "r.db"))
    r = _report()
    store.save_report(r)
    assert store.get_report(r.report_id)["risk_score"] == 90
    assert len(store.list_reports(limit=10)) == 1
    store.add_feedback(r.report_id, "true_positive", "looks right")
    assert store.get_feedback(r.report_id)[0]["label"] == "true_positive"
    store.save_baseline("foo", {"a": 1})
    assert store.load_baseline("foo") == {"a": 1}


def test_export_cef_builds():
    cef = build_cef(_report())
    assert cef.startswith("CEF:0|PhishGuard|PhishGuard|")
    assert "malicious" in cef


def test_export_manager_disabled_by_default():
    em = ExportManager(Config())
    assert em.should_export(_report()) is False


def test_feeds_graceful_no_network():
    class StubIntel:
        def __init__(self):
            self.added = 0
        def add_url_verdict(self, url, v):
            self.added += 1
    intel = StubIntel()
    fm = FeedManager()
    res = fm.update_all(intel)
    assert set(res.keys()) == {"urlhaus", "openphish"}
    assert isinstance(res["urlhaus"], int) and isinstance(res["openphish"], int)


def _parsed(sender="evil@x.com", name="ceo", recip="victim@company.com"):
    return ParsedEmail(
        message_id=None, subject="hi", from_header="", to_header="",
        date_header="", sender_name=name, sender_email=sender, sender_domain="x.com",
        receiver_email=recip, receiver_domain="company.com", envelope_from=None,
        reply_to=None, return_path=None, body_text="", body_html="",
        urls=[], attachments=[], auth=AuthResult(), authentication_results={}, raw_headers={},
    )


def test_behavioral_first_contact_flags(tmp_path):
    bstore = BehavioralStore(str(tmp_path / "b.db"))
    bstore.record(_parsed(sender="friend@partner.com", name="bob", recip="victim@company.com"))
    org = OrgProfile(vip_names=["ceo"], protected_domains=["company.com"])
    ctx = AnalysisContext(config=Config(), org_profile=org, intel=None, behavioral=bstore, mailbox_id="t")
    report = behavioral_analyze(_parsed(sender="evil@x.com", name="ceo", recip="victim@company.com"), ctx)
    titles = [f.title for f in report.findings]
    assert any("First-time" in t for t in titles)
    assert any("Impersonated internal name" in t for t in titles)


def test_behavioral_disabled_when_store_none():
    ctx = AnalysisContext(config=Config(), org_profile=OrgProfile(), intel=None, behavioral=None, mailbox_id="t")
    report = behavioral_analyze(_parsed(), ctx)
    assert report.findings == []
