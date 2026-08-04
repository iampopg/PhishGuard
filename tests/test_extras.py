from __future__ import annotations

from pathlib import Path

from phishguard.config import Config
from phishguard.intel import IntelligenceHub
from phishguard.models import Attachment
from phishguard.remediation import RemediationManager
from phishguard.sandbox import ClamAVSandbox, LocalHashSandbox, SandboxManager


def test_attachment_to_dict_excludes_payload():
    a = Attachment("x.exe", "application/octet-stream", 3, "sha", "md5", payload=b"MZ")
    d = a.to_dict()
    assert "payload" not in d
    assert d["sha256"] == "sha" and d["md5"] == "md5"


def test_sandbox_engine_offline_noop():
    from phishguard.engines.sandbox import analyze
    from phishguard.engines.base import AnalysisContext
    from phishguard.models import ParsedEmail
    e = ParsedEmail(message_id=None, subject="", from_header="", to_header="",
                    date_header="", sender_name="", sender_email="a@b.com", sender_domain="b.com",
                    receiver_email="c@d.com", receiver_domain="d.com", envelope_from=None,
                    reply_to=None, return_path=None, body_text="", body_html="",
                    urls=[], attachments=[Attachment("x.exe", "application/octet-stream", 1, "s", "m", payload=b"MZ")],
                    auth=None, authentication_results={}, raw_headers={})
    ctx = AnalysisContext(config=Config(), org_profile=None, intel=IntelligenceHub(Config()), behavioral=None, mailbox_id="t")
    res = analyze(e, ctx)
    assert res.metadata.get("enabled") is False
    assert res.findings == []


def test_local_hash_sandbox_flags_known_bad(tmp_path):
    import hashlib
    hub = IntelligenceHub(Config(), cache_dir=tmp_path / "c")
    real = hashlib.sha256(b"data").hexdigest()
    hub.add_hash_verdict(real, {"malicious": True, "source": "local"})
    sb = LocalHashSandbox(hub)
    out = sb.scan("f", b"data")
    assert out["malicious"] is True


def test_clamav_sandbox_graceful_when_unavailable():
    sb = ClamAVSandbox("127.0.0.1", 1, timeout=1)
    out = sb.scan("f", b"data")
    assert out["malicious"] is False
    assert "unavailable" in out["detail"]


def test_sandbox_manager_selects_clamav_when_enabled():
    cfg = Config()
    cfg.clamav_enabled = True
    mgr = SandboxManager(cfg, IntelligenceHub(cfg))
    assert isinstance(mgr.provider, ClamAVSandbox)


def test_remediation_disabled_is_noop():
    assert RemediationManager(Config()).apply(_fake_report()) == []


def test_remediation_enabled_without_provider_skips():
    cfg = Config()
    cfg.remediation_enabled = True
    cfg.remediation_provider = ""
    results = RemediationManager(cfg).apply(_fake_report())
    assert results and all(r["status"] == "skipped" for r in results)


def _fake_report():
    from phishguard.models import (AnalyzerResult, Report, Verdict)
    return Report(report_id="r", timestamp="t", source={"message_id": "m"},
                  verdict=Verdict.MALICIOUS, risk_score=90, summary="s", sender={},
                  analyzers=[AnalyzerResult("x", 1, [])], urls=[], attachments=[],
                  recommended_actions=["quarantine", "notify_soc"], labels={})
