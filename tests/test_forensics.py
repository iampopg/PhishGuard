from __future__ import annotations

from phishguard.config import Config
from phishguard.engines.base import AnalysisContext
from phishguard.forensics.evidence import EvidenceStore
from phishguard.forensics.ioc import extract_iocs
from phishguard.forensics.takedown import build_takedown_package
from phishguard.models import AuthResult, ParsedEmail
from phishguard.org_profile import OrgProfile
from phishguard.ti import ThreatIntelligenceManager


def _report(**over):
    base = dict(
        report_id="r1", timestamp="t", verdict="phishing", risk_score=80,
        summary="s", sender={"from": "a@paypa1.com"}, source={"subject": "verify now"},
        urls=[{"url": "https://paypa1.com/login"}],
        attachments=[{"filename": "x", "content_type": "application/pdf", "size": 1,
                      "sha256": "abc123", "md5": "def456"}],
        body_text="log in http://t.co/xyz to 1.2.3.4", body_html="",
        recommended_actions=[], labels={},
    )
    base.update(over)
    return base


def test_extract_iocs_basic():
    iocs = extract_iocs(_report())
    assert "paypa1.com" in iocs.domains
    assert "https://paypa1.com/login" in iocs.urls
    assert "abc123" in iocs.sha256
    assert "1.2.3.4" in iocs.ips


def test_extract_iocs_empty():
    iocs = extract_iocs({})
    assert iocs.urls == []
    assert iocs.domains == []


def test_takedown_package_builds_zip():
    pkg = build_takedown_package(_report(), extract_iocs(_report()).to_dict())
    assert pkg[:2] == b"PK"


def test_takedown_package_with_enrichment():
    iocs = extract_iocs(_report())
    enrichment = ThreatIntelligenceManager(Config()).enrich(iocs)
    pkg = build_takedown_package(_report(), iocs.to_dict(), enrichment)
    assert pkg[:2] == b"PK"


def test_ti_manager_no_providers():
    m = ThreatIntelligenceManager(Config())
    assert m.enabled_names == []
    iocs = extract_iocs(_report())
    res = m.enrich(iocs)
    assert res["summary"]["checks"] == 0


def test_ti_manager_caches_results():
    cfg = Config()
    m = ThreatIntelligenceManager(cfg, providers=[_DummyProvider()])
    iocs = extract_iocs(_report())
    r1 = m.enrich(iocs)
    r2 = m.enrich(iocs)
    assert r1["summary"]["checks"] == r2["summary"]["checks"]
    assert m._cached(f"{_DummyProvider.name}:url:https://paypa1.com/login")


def test_evidence_store_roundtrip(tmp_path):
    es = EvidenceStore(str(tmp_path))
    written = es.store_artifacts("r1", raw=b"raw", headers={"From": "a@b.com"},
                                  body_text="hi", body_html="<p>hi</p>",
                                  report=_report())
    assert "raw.eml" in written
    assert "headers.json" in written
    assert es.list_artifacts("r1")
    p = es.get_artifact("r1", "raw.eml")
    assert p is not None
    assert p.read_bytes() == b"raw"


def test_evidence_store_traversal_guard(tmp_path):
    es = EvidenceStore(str(tmp_path))
    assert es.get_artifact("r1", "../etc/passwd") is None


def test_url_deep_scanner_disabled():
    from phishguard.engines.url_deep_scanner import analyze
    cfg = Config()
    cfg.url_deep_scan_enabled = False
    ctx = AnalysisContext(config=cfg, org_profile=OrgProfile(), mailbox_id="t")
    email = ParsedEmail(message_id=None, subject="s", from_header="", to_header="",
                        date_header="", sender_name="", sender_email="a@b.com",
                        sender_domain="b.com", receiver_email="c@d.com", receiver_domain="d.com",
                        envelope_from=None, reply_to=None, return_path=None, body_text="",
                        body_html="", urls=["https://x.com"], attachments=[], auth=AuthResult(),
                        authentication_results={}, raw_headers={})
    res = analyze(email, ctx)
    assert res.metadata.get("enabled") is False


def test_calendar_detector_no_calendar():
    from phishguard.engines.calendar import analyze
    ctx = AnalysisContext(config=Config(), org_profile=OrgProfile(), mailbox_id="t")
    email = ParsedEmail(message_id=None, subject="s", from_header="", to_header="",
                        date_header="", sender_name="", sender_email="a@b.com",
                        sender_domain="b.com", receiver_email="c@d.com", receiver_domain="d.com",
                        envelope_from=None, reply_to=None, return_path=None, body_text="hello",
                        body_html="", urls=[], attachments=[], auth=AuthResult(),
                        authentication_results={}, raw_headers={})
    res = analyze(email, ctx)
    assert res.findings == []


def test_calendar_detector_ics_attachment():
    from phishguard.engines.calendar import analyze
    ctx = AnalysisContext(config=Config(), org_profile=OrgProfile(), mailbox_id="t")
    att = _att("invite.ics", b"BEGIN:VCALENDAR\nSUMMARY:Urgent meeting\nEND:VCALENDAR")
    email = ParsedEmail(message_id=None, subject="s", from_header="", to_header="",
                        date_header="", sender_name="", sender_email="a@b.com",
                        sender_domain="b.com", receiver_email="c@d.com", receiver_domain="d.com",
                        envelope_from=None, reply_to=None, return_path=None, body_text="",
                        body_html="", urls=[], attachments=[att], auth=AuthResult(),
                        authentication_results={}, raw_headers={})
    res = analyze(email, ctx)
    assert any("Calendar invite" in f.title for f in res.findings)


def test_qr_scanner_no_lib():
    from phishguard.engines.qr_scanner import analyze
    ctx = AnalysisContext(config=Config(), org_profile=OrgProfile(), mailbox_id="t")
    email = ParsedEmail(message_id=None, subject="s", from_header="", to_header="",
                        date_header="", sender_name="", sender_email="a@b.com",
                        sender_domain="b.com", receiver_email="c@d.com", receiver_domain="d.com",
                        envelope_from=None, reply_to=None, return_path=None, body_text="",
                        body_html="", urls=[], attachments=[], auth=AuthResult(),
                        authentication_results={}, raw_headers={})
    res = analyze(email, ctx)
    assert res.metadata.get("enabled") is False


class _DummyProvider:
    name = "dummy"

    def check_url(self, url):
        return {"malicious": False, "source": "dummy"}

    def check_domain(self, domain):
        return {"malicious": False, "source": "dummy"}

    def check_ip(self, ip):
        return {"malicious": False, "source": "dummy"}

    def check_hash(self, sha256):
        return {"malicious": False, "source": "dummy"}


def _att(name: str, data: bytes):
    from phishguard.models import Attachment
    return Attachment(filename=name, content_type="application/ics", size=len(data),
                      sha256="x" * 64, md5="y" * 32, payload=data)
