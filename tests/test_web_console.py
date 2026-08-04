from __future__ import annotations

from pathlib import Path

from phishguard.config import Config
from phishguard.engines.base import AnalysisContext
from phishguard.intel import IntelligenceHub
from phishguard.org_profile import OrgProfile
from phishguard.web.app import create_app

FIX = Path(__file__).parent / "fixtures"


def _ctx(tmp_path):
    cfg = Config()
    cfg.web_username = "admin"
    cfg.web_password = "admin"
    cfg.web_secret_key = "test"
    cfg.report_dir = str(tmp_path / "reports")
    import os
    os.makedirs(cfg.report_dir, exist_ok=True)
    return AnalysisContext(config=cfg, org_profile=OrgProfile(), intel=IntelligenceHub(cfg), behavioral=None, mailbox_id="web")


def _login(c):
    c.post("/login", data={"username": "admin", "password": "admin"}, follow_redirects=True)


def test_web_console_pages_render(tmp_path):
    app = create_app(_ctx(tmp_path))
    c = app.test_client()
    _login(c)
    for page in ["/", "/reports", "/scan", "/mailbox", "/feeds", "/org", "/rules", "/remediation", "/export", "/settings"]:
        r = c.get(page)
        assert r.status_code == 200, page


def test_web_scan_upload_and_report_view(tmp_path):
    import io
    app = create_app(_ctx(tmp_path))
    c = app.test_client()
    _login(c)
    data = (FIX / "sample_phish.eml").read_bytes()
    r = c.post("/scan", data={"eml": (io.BytesIO(data), "sample_phish.eml")},
              content_type="multipart/form-data", follow_redirects=True)
    assert b"Verdict" in r.data
    rep = c.get("/reports")
    assert rep.status_code == 200
    rid = rep.get_data(as_text=True).split('href="/report/')[1].split('"')[0]
    rv = c.get(f"/report/{rid}")
    assert rv.status_code == 200
    assert b"Findings" in rv.data


def test_web_feedback_persists(tmp_path):
    import io
    app = create_app(_ctx(tmp_path))
    c = app.test_client()
    _login(c)
    data = (FIX / "sample_phish.eml").read_bytes()
    c.post("/scan", data={"eml": (io.BytesIO(data), "sample_phish.eml")},
          content_type="multipart/form-data", follow_redirects=True)
    rid = c.get("/reports").get_data(as_text=True).split('href="/report/')[1].split('"')[0]
    r = c.post(f"/report/{rid}", data={"label": "true_positive", "note": "test"}, follow_redirects=True)
    assert b"Feedback saved" in r.data
