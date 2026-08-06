from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import List, Optional

from email.header import decode_header, make_header
from fastapi import FastAPI, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware

from phishguard.behavioral_store import BehavioralStore
from phishguard.config import Config
from phishguard.config_store import (current_config, load_env_dict, reload_env,
                                     update_env)
from phishguard.export import ExportManager
from phishguard.feeds import FeedManager
from phishguard.intel import IntelligenceHub
from phishguard.mail.fetcher import MailFetcher
from phishguard.mail.parser import parse_message
from phishguard.models import AuthResult, ParsedEmail
from phishguard.org_profile import OrgProfile
from phishguard.pipeline import analyze_email
from phishguard.remediation import RemediationManager
from phishguard.report_store import ReportStore
from phishguard.rules import DEFAULT_RULES
from phishguard.util.text import extract_urls


def _runtime_ctx() -> "object":
    import phishguard.web.app as _wa  # reuse context builder to avoid duplication
    return _wa._runtime_ctx()


def _store(cfg: Config) -> ReportStore:
    return ReportStore(str(Path(cfg.report_dir) / "phishguard.db"))


def _persist(ctx, parsed: ParsedEmail, report) -> None:
    _store(ctx.config).save_report(report)
    if ctx.behavioral is not None:
        ctx.behavioral.record(parsed)
    ExportManager(ctx.config).export(report)
    RemediationManager(ctx.config).apply(report)


def _dec(s):
    if not isinstance(s, str):
        return s
    try:
        return str(make_header(decode_header(s)))
    except Exception:
        return s


def _clean_report(d: dict) -> dict:
    if isinstance(d, dict):
        if d.get("source", {}).get("subject"):
            d["source"]["subject"] = _dec(d["source"]["subject"])
        if d.get("sender", {}).get("display_name"):
            d["sender"]["display_name"] = _dec(d["sender"]["display_name"])
    return d


BOOL_KEYS = {
    "PG_IMAP_USE_SSL", "PG_IMAP_UNSEEN_ONLY", "PG_IMAP_MARK_READ", "PG_VT_ENABLED",
    "PG_GSB_ENABLED", "PG_CLAMAV_ENABLED", "PG_SANDBOX_ENABLED", "PG_MONITOR_ENABLED",
    "PG_BEHAVIORAL_ENABLED", "PG_REMEDIATION_ENABLED", "PG_EXPORT_ENABLED",
    "PG_EXPORT_CEF", "PG_DNS_CHECKS_ENABLED",
}
INT_KEYS = {
    "PG_IMAP_PORT", "PG_IMAP_TIMEOUT", "PG_CLAMAV_PORT", "PG_MONITOR_INTERVAL",
    "PG_BEHAVIORAL_BASELINE_DAYS", "PG_THRESHOLD_SUSPICIOUS", "PG_THRESHOLD_PHISHING",
    "PG_THRESHOLD_MALICIOUS", "PG_WEB_PORT",
}
STRING_KEYS = {
    "PG_IMAP_SERVER", "PG_IMAP_USERNAME", "PG_IMAP_PASSWORD", "PG_IMAP_MAILBOX",
    "PG_VT_API_KEY", "PG_GSB_API_KEY", "PG_CLAMAV_HOST", "PG_SANDBOX_PROVIDER",
    "PG_SANDBOX_API_KEY", "PG_SANDBOX_URL", "PG_ORG_PROFILE_PATH", "PG_WEB_HOST",
    "PG_WEB_USERNAME", "PG_WEB_PASSWORD", "PG_WEB_SECRET_KEY", "PG_REPORT_DIR",
    "PG_REMEDIATION_PROVIDER", "PG_M365_TENANT_ID", "PG_M365_CLIENT_ID",
    "PG_M365_CLIENT_SECRET", "PG_GMAIL_SA_JSON", "PG_EXPORT_SYSLOG_ADDR",
    "PG_EXPORT_WEBHOOK_URL", "PG_EXPORT_MIN_SEVERITY", "PG_TRUSTED_DOMAINS",
    "PG_LOG_LEVEL",
}


def create_api() -> FastAPI:
    app = FastAPI(title="PhishGuard API", version="1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
    )
    WEB_OUT = Path(__file__).resolve().parent.parent.parent / "web" / "out"
    app.state.feed_info = {}
    app.state.monitor = {"running": False, "interval": 60, "thread": None}

    def expected_token() -> str:
        try:
            return current_config().web_secret_key
        except Exception:
            return "change_me"

    @app.middleware("http")
    async def auth_mw(request: Request, call_next):
        p = request.url.path
        if p.startswith("/api") and p not in ("/api/login", "/api/health"):
            auth = request.headers.get("Authorization", "")
            tok = auth[7:] if auth.startswith("Bearer ") else auth
            if tok != expected_token():
                return JSONResponse({"error": "unauthorized"}, status_code=401)
        return await call_next(request)

    # ---------- auth ----------
    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    @app.post("/api/login")
    async def login(request: Request):
        cfg = current_config()
        ct = request.headers.get("content-type", "")
        if "application/json" in ct:
            body = await request.json()
            username, password = body.get("username"), body.get("password")
        else:
            form = await request.form()
            username, password = form.get("username"), form.get("password")
        if username == cfg.web_username and password == cfg.web_password:
            return {"access_token": cfg.web_secret_key, "token_type": "Bearer"}
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # ---------- dashboard / reports ----------
    @app.get("/api/status")
    def status():
        cfg = current_config()
        reports = _store(cfg).list_reports(limit=2000)
        counts = {"safe": 0, "suspicious": 0, "phishing": 0, "malicious": 0}
        for r in reports:
            counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        return {"monitor": app.state.monitor["running"], "total": len(reports), "counts": counts}

    @app.get("/api/dashboard")
    def dashboard():
        cfg = current_config()
        all_r = _store(cfg).list_reports(limit=5000)
        counts = {"safe": 0, "suspicious": 0, "phishing": 0, "malicious": 0}
        for r in all_r:
            counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        return {"counts": counts, "total": len(all_r),
                "recent": [_clean_report(r) for r in all_r[:15]],
                "monitor": app.state.monitor["running"]}

    @app.get("/api/reports")
    def reports(verdict: Optional[str] = None):
        cfg = current_config()
        all_r = _store(cfg).list_reports(limit=5000)
        counts = {"safe": 0, "suspicious": 0, "phishing": 0, "malicious": 0}
        for r in all_r:
            counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        shown = [r for r in all_r if r["verdict"] == verdict] if verdict else all_r
        return {"reports": [_clean_report(r) for r in shown], "counts": counts}

    @app.get("/api/report/{report_id}")
    def report_detail(report_id: str):
        r = _store(current_config()).get_report(report_id)
        if not r:
            raise HTTPException(status_code=404, detail="Not found")
        findings = [{"analyzer": a["name"], **f} for a in r["analyzers"] for f in a["findings"]]
        return {"report": _clean_report(r), "feedback": _store(current_config()).get_feedback(report_id)}

    @app.post("/api/report/{report_id}/feedback")
    def report_feedback(report_id: str, label: str = Form(""), note: str = Form("")):
        from phishguard.models import now_iso
        _store(current_config()).add_feedback(report_id, label, note, now_iso())
        return {"ok": True}

    # ---------- scan ----------
    @app.post("/api/scan")
    async def scan(eml: Optional[UploadFile] = None, text: str = Form(""), url: str = Form("")):
        ctx = _runtime_ctx()
        if eml is not None and eml.filename:
            data = await eml.read()
            parsed = parse_message(data)
        elif text:
            parsed = ParsedEmail(message_id=None, subject=None, from_header="", to_header="",
                                 date_header="", sender_name="", sender_email="", sender_domain="",
                                 receiver_email="", receiver_domain="", envelope_from=None,
                                 reply_to=None, return_path=None, body_text=text, body_html="",
                                 urls=extract_urls(text), attachments=[], auth=AuthResult(),
                                 authentication_results={}, raw_headers={})
        elif url:
            parsed = ParsedEmail(message_id=None, subject=None, from_header="", to_header="",
                                 date_header="", sender_name="", sender_email="", sender_domain="",
                                 receiver_email="", receiver_domain="", envelope_from=None,
                                 reply_to=None, return_path=None, body_text=url, body_html="",
                                 urls=[url], attachments=[], auth=AuthResult(),
                                 authentication_results={}, raw_headers={})
        else:
            raise HTTPException(status_code=400, detail="Provide eml, text or url")
        report = analyze_email(parsed, ctx)
        _persist(ctx, parsed, report)
        return report.to_dict()

    # ---------- mailbox ----------
    @app.post("/api/mailbox/config")
    def mailbox_config(
        PG_IMAP_SERVER: str = Form(""), PG_IMAP_USERNAME: str = Form(""),
        PG_IMAP_PASSWORD: str = Form(""), PG_IMAP_MAILBOX: str = Form("INBOX"),
        PG_IMAP_PORT: str = Form(""), PG_IMAP_USE_SSL: Optional[str] = Form(None),
        PG_IMAP_UNSEEN_ONLY: Optional[str] = Form(None), PG_IMAP_MARK_READ: Optional[str] = Form(None),
    ):
        # Merge: skip blank values so a partially-filled form never wipes
        # credentials that are already stored in .env (e.g. an empty password).
        updates = {}
        if PG_IMAP_SERVER:
            updates["PG_IMAP_SERVER"] = PG_IMAP_SERVER
        if PG_IMAP_USERNAME:
            updates["PG_IMAP_USERNAME"] = PG_IMAP_USERNAME
        if PG_IMAP_PASSWORD:
            updates["PG_IMAP_PASSWORD"] = PG_IMAP_PASSWORD
        if PG_IMAP_MAILBOX:
            updates["PG_IMAP_MAILBOX"] = PG_IMAP_MAILBOX
        if PG_IMAP_PORT:
            updates["PG_IMAP_PORT"] = PG_IMAP_PORT
        updates["PG_IMAP_USE_SSL"] = "true" if PG_IMAP_USE_SSL else "false"
        updates["PG_IMAP_UNSEEN_ONLY"] = "true" if PG_IMAP_UNSEEN_ONLY else "false"
        updates["PG_IMAP_MARK_READ"] = "true" if PG_IMAP_MARK_READ else "false"
        update_env(updates)
        reload_env()
        return {"ok": True}

    @app.post("/api/mailbox/scan")
    def mailbox_scan(limit: int = Form(10), all_msgs: bool = Form(False)):
        ctx = _runtime_ctx()
        fetcher = MailFetcher(ctx.config)
        fetcher.connect()
        items = fetcher.fetch_all(limit) if all_msgs else fetcher.fetch_unseen(limit)
        out = []
        for uid, raw in items:
            parsed = parse_message(raw)
            report = analyze_email(parsed, ctx)
            _persist(ctx, parsed, report)
            out.append(report.to_dict())
        fetcher.disconnect()
        return {"scanned": len(out), "results": out}

    def _monitor_loop(interval: int):
        ctx = _runtime_ctx()
        while app.state.monitor["running"]:
            try:
                fetcher = MailFetcher(ctx.config)
                fetcher.connect()
                for uid, raw in fetcher.fetch_unseen(50):
                    parsed = parse_message(raw)
                    report = analyze_email(parsed, ctx)
                    _persist(ctx, parsed, report)
                fetcher.disconnect()
            except Exception:
                pass
            time.sleep(interval)

    def set_monitor(on: bool, interval: int = None) -> None:
        if on:
            if app.state.monitor["running"]:
                return
            iv = interval or app.state.monitor.get("interval") or 60
            app.state.monitor["interval"] = iv
            app.state.monitor["running"] = True
            t = threading.Thread(target=_monitor_loop, args=(iv,), daemon=True)
            t.start()
            app.state.monitor["thread"] = t
        else:
            app.state.monitor["running"] = False
        # Persist so the toggle survives a server restart.
        try:
            update_env({"PG_MONITOR_ENABLED": "true" if on else "false"})
        except Exception:
            pass

    @app.post("/api/mailbox/monitor/start")
    def monitor_start(interval: int = Form(60)):
        set_monitor(True, interval)
        return {"running": True}

    @app.post("/api/mailbox/monitor/stop")
    def monitor_stop():
        set_monitor(False)
        return {"running": False}

    @app.get("/api/mailbox")
    def mailbox_get():
        return {"env": load_env_dict(), "monitor": app.state.monitor["running"]}

    # ---------- feeds ----------
    @app.get("/api/feeds")
    def feeds_get():
        return app.state.feed_info or {"counts": {}, "time": None}

    @app.post("/api/feeds/update")
    def feeds_update():
        ctx = _runtime_ctx()
        fm = FeedManager()
        res = fm.update_all(ctx.intel)
        app.state.feed_info = {"counts": res, "time": time.strftime("%Y-%m-%d %H:%M:%S")}
        return app.state.feed_info

    # ---------- org ----------
    @app.get("/api/org")
    def org_get():
        cfg = current_config()
        path = cfg.org_profile_path or "org_profile.json"
        org = OrgProfile.load(path) if Path(path).exists() else OrgProfile()
        return {"org": org.to_dict(), "path": path}

    @app.post("/api/org")
    def org_save(
        protected_domains: str = Form(""), vip_names: str = Form(""),
        brand_keywords: str = Form(""), brand_domains: str = Form(""),
        trusted_domains: str = Form(""),
    ):
        cfg = current_config()
        path = cfg.org_profile_path or "org_profile.json"
        org = OrgProfile(
            protected_domains=[d.strip() for d in protected_domains.split(",") if d.strip()],
            vip_names=[d.strip() for d in vip_names.split(",") if d.strip()],
            brand_keywords=[d.strip() for d in brand_keywords.split(",") if d.strip()],
            brand_domains=[d.strip() for d in brand_domains.split(",") if d.strip()],
            trusted_domains=[d.strip() for d in trusted_domains.split(",") if d.strip()],
        )
        org.save(path)
        reload_env()
        return {"ok": True, "path": path}

    # ---------- rules ----------
    @app.get("/api/rules")
    def rules_get():
        cfg = current_config()
        rules = [{
            "id": r.id, "analyzer": r.analyzer, "action": r.action,
            "description": r.description, "severity_at_least": r.severity_at_least.value,
            "title_contains": r.title_contains,
        } for r in DEFAULT_RULES]
        return {"rules": rules, "thresholds": {
            "suspicious": cfg.threshold_suspicious, "phishing": cfg.threshold_phishing,
            "malicious": cfg.threshold_malicious, "behavioral_baseline_days": cfg.behavioral_baseline_days,
        }}

    # ---------- remediation ----------
    @app.get("/api/remediation")
    def remediation_get():
        return {"env": {k: load_env_dict().get(k, "") for k in (
            "PG_REMEDIATION_ENABLED", "PG_REMEDIATION_PROVIDER", "PG_M365_TENANT_ID",
            "PG_M365_CLIENT_ID", "PG_GMAIL_SA_JSON")}}

    @app.post("/api/remediation")
    def remediation_save(
        PG_REMEDIATION_ENABLED: Optional[str] = Form(None),
        PG_REMEDIATION_PROVIDER: str = Form(""), PG_M365_TENANT_ID: str = Form(""),
        PG_M365_CLIENT_ID: str = Form(""), PG_M365_CLIENT_SECRET: str = Form(""),
        PG_GMAIL_SA_JSON: str = Form(""),
    ):
        update_env({
            "PG_REMEDIATION_ENABLED": "true" if PG_REMEDIATION_ENABLED else "false",
            "PG_REMEDIATION_PROVIDER": PG_REMEDIATION_PROVIDER,
            "PG_M365_TENANT_ID": PG_M365_TENANT_ID, "PG_M365_CLIENT_ID": PG_M365_CLIENT_ID,
            "PG_M365_CLIENT_SECRET": PG_M365_CLIENT_SECRET, "PG_GMAIL_SA_JSON": PG_GMAIL_SA_JSON,
        })
        reload_env()
        return {"ok": True}

    # ---------- export ----------
    @app.get("/api/export")
    def export_get():
        return {"env": {k: load_env_dict().get(k, "") for k in (
            "PG_EXPORT_ENABLED", "PG_EXPORT_CEF", "PG_EXPORT_SYSLOG_ADDR",
            "PG_EXPORT_WEBHOOK_URL", "PG_EXPORT_MIN_SEVERITY")}}

    @app.post("/api/export")
    def export_save(
        action: str = Form("save"), PG_EXPORT_ENABLED: Optional[str] = Form(None),
        PG_EXPORT_CEF: Optional[str] = Form(None), PG_EXPORT_SYSLOG_ADDR: str = Form(""),
        PG_EXPORT_WEBHOOK_URL: str = Form(""), PG_EXPORT_MIN_SEVERITY: str = Form("medium"),
    ):
        update_env({
            "PG_EXPORT_ENABLED": "true" if PG_EXPORT_ENABLED else "false",
            "PG_EXPORT_CEF": "true" if PG_EXPORT_CEF else "false",
            "PG_EXPORT_SYSLOG_ADDR": PG_EXPORT_SYSLOG_ADDR,
            "PG_EXPORT_WEBHOOK_URL": PG_EXPORT_WEBHOOK_URL,
            "PG_EXPORT_MIN_SEVERITY": PG_EXPORT_MIN_SEVERITY,
        })
        reload_env()
        if action == "test":
            ctx = _runtime_ctx()
            sample = _store(ctx.config).list_reports(limit=1)
            if sample:
                ExportManager(ctx.config).export(_dict_to_report(sample[0]))
                return {"ok": True, "tested": True}
            return {"ok": True, "tested": False, "note": "no reports"}
        return {"ok": True}

    # ---------- settings ----------
    @app.get("/api/settings")
    def settings_get():
        cfg = current_config()
        return {"config": _config_public(cfg), "env": load_env_dict()}

    @app.post("/api/settings")
    async def settings_save(request: Request):
        form = dict(await request.form())
        updates = {}
        for key in (BOOL_KEYS | INT_KEYS | STRING_KEYS):
            if key in form:
                val = form[key]
                if val in ("", None):
                    continue  # never wipe a stored value with a blank field
                if key in BOOL_KEYS:
                    updates[key] = "true" if val in ("true", "on", "1") else "false"
                elif key in INT_KEYS:
                    try:
                        updates[key] = str(int(val))
                    except ValueError:
                        pass
                else:
                    updates[key] = val
        update_env(updates)
        reload_env()
        if "PG_MONITOR_ENABLED" in updates:
            try:
                mi = int(form.get("PG_MONITOR_INTERVAL", current_config().monitor_interval))
            except Exception:
                mi = 60
            set_monitor(updates["PG_MONITOR_ENABLED"] == "true", mi)
        return {"ok": True, "updated": list(updates.keys())}

    @app.get("/api/behavioral")
    def behavioral_get():
        cfg = current_config()
        if not cfg.behavioral_enabled:
            return {"enabled": False}
        bs = BehavioralStore(Path(cfg.report_dir) / "behavioral.db")
        return {"enabled": True, "baselines": bs.list_baselines()}

    # ---------- SPA fallback ----------
    @app.get("/{full_path:path}")
    async def spa(full_path: str):
        if not WEB_OUT.exists():
            return JSONResponse({"error": "UI not built", "hint": "run: phishguard web build"},
                                status_code=503)
        if full_path:
            candidate = WEB_OUT / full_path
            if candidate.is_file():
                return FileResponse(candidate)
            html_file = WEB_OUT / (full_path + ".html")
            if html_file.is_file():
                return FileResponse(html_file)
            idx_dir = WEB_OUT / full_path / "index.html"
            if idx_dir.is_file():
                return FileResponse(idx_dir)
        return FileResponse(WEB_OUT / "index.html")

    # Auto-start continuous monitoring if it was enabled in the environment.
    try:
        if current_config().monitor_enabled:
            set_monitor(True)
    except Exception:
        pass

    return app


def _config_public(cfg: Config) -> dict:
    return {
        "threshold_suspicious": cfg.threshold_suspicious,
        "threshold_phishing": cfg.threshold_phishing,
        "threshold_malicious": cfg.threshold_malicious,
        "monitor_interval": cfg.monitor_interval,
        "behavioral_baseline_days": cfg.behavioral_baseline_days,
        "imap_port": cfg.imap_port,
        "clamav_port": cfg.clamav_port,
        "web_port": cfg.web_port,
        "org_profile_path": cfg.org_profile_path,
        "report_dir": cfg.report_dir,
        "behavioral_enabled": cfg.behavioral_enabled,
        "monitor_enabled": cfg.monitor_enabled,
        "vt_enabled": cfg.vt_enabled, "gsb_enabled": cfg.gsb_enabled,
        "clamav_enabled": cfg.clamav_enabled, "sandbox_enabled": cfg.sandbox_enabled,
        "dns_checks_enabled": cfg.dns_checks_enabled,
        "remediation_enabled": cfg.remediation_enabled, "export_enabled": cfg.export_enabled,
        "export_cef": cfg.export_use_cef, "export_min_severity": cfg.export_min_severity,
        "log_level": cfg.log_level,
    }


def _dict_to_report(d: dict):
    from phishguard.models import Report, Verdict
    return Report(
        report_id=d["report_id"], timestamp=d["timestamp"], source=d.get("source", {}),
        verdict=Verdict(d["verdict"]), risk_score=d["risk_score"], summary=d.get("summary", ""),
        sender=d.get("sender", {}), analyzers=[], urls=d.get("urls", []),
        attachments=[], recommended_actions=d.get("recommended_actions", []), labels=d.get("labels", {}),
    )


app = create_api()
