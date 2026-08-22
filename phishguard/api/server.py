from __future__ import annotations

import os
import json
import threading
import time
from datetime import datetime
import time
from pathlib import Path
from typing import List, Optional

import requests

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
from phishguard.forensics.ioc import extract_iocs
from phishguard.forensics.takedown import build_takedown_package
from phishguard.intel import IntelligenceHub
from phishguard.mail.fetcher import MailFetcher
from phishguard.mail.monitor_store import MonitorStore
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


def _persist(ctx, parsed: ParsedEmail, report, raw: bytes = None) -> None:
    _store(ctx.config).save_report(report, raw=raw)
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
    "PG_URLSCAN_ENABLED", "PG_SHODAN_ENABLED", "PG_OTX_ENABLED", "PG_MISP_ENABLED",
    "PG_ABUSEIPDB_ENABLED", "PG_URL_DEEP_SCREENSHOT_ENABLED",
}
INT_KEYS = {
    "PG_IMAP_PORT", "PG_IMAP_TIMEOUT", "PG_CLAMAV_PORT", "PG_MONITOR_INTERVAL",
    "PG_BEHAVIORAL_BASELINE_DAYS", "PG_THRESHOLD_SUSPICIOUS", "PG_THRESHOLD_PHISHING",
    "PG_THRESHOLD_MALICIOUS", "PG_WEB_PORT", "PG_URL_DEEP_MAX_REDIRECTS",
    "PG_URL_DEEP_TIMEOUT", "PG_TI_CACHE_TTL",
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
    "PG_URLSCAN_API_KEY", "PG_SHODAN_API_KEY", "PG_OTX_API_KEY",
    "PG_MISP_URL", "PG_MISP_API_KEY", "PG_ABUSEIPDB_API_KEY",
}


def create_api() -> FastAPI:
    app = FastAPI(title="PhishGuard API", version="1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
    )
    WEB_OUT = Path(__file__).resolve().parent.parent.parent / "web" / "out"
    app.state.monitor = {
        "running": False, "interval": 60, "thread": None,
        "last_scan": None, "last_new": 0, "last_error": None,
    }

    @app.on_event("startup")
    def _maybe_autostart_monitor() -> None:
        if current_config().monitor_enabled:
            try:
                set_monitor(True)
            except Exception:
                pass

    def _feed_meta_path() -> Path:
        return Path(current_config().report_dir) / ".feeds_meta.json"

    def _load_feed_info() -> dict:
        try:
            p = _feed_meta_path()
            if p.exists():
                return json.loads(p.read_text())
        except Exception:
            pass
        return {"counts": {}, "time": None}

    def _save_feed_info(info: dict) -> None:
        try:
            _feed_meta_path().write_text(json.dumps(info, default=str))
        except Exception:
            pass

    app.state.feed_info = _load_feed_info()

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
        mon = {k: v for k, v in app.state.monitor.items() if k != "thread"}
        return {"monitor": mon, "total": len(reports), "counts": counts}

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

    @app.get("/api/reports/export-pdf")
    def reports_export_pdf(verdict: Optional[str] = None,
                           date_from: Optional[str] = None, date_to: Optional[str] = None,
                           disposition: Optional[str] = None):
        from phishguard.report_pdf import generate_report_pdf
        cfg = current_config()
        reports = _store(cfg).list_reports(limit=10000)
        if verdict:
            reports = [r for r in reports if r["verdict"] == verdict]
        if date_from:
            reports = [r for r in reports if r["timestamp"] >= date_from]
        if date_to:
            reports = [r for r in reports if r["timestamp"] <= date_to + "T23:59:59"]
        pdf = generate_report_pdf(reports, output_path=None, verdict_filter=verdict,
                                  date_from=date_from, date_to=date_to)
        from fastapi.responses import Response
        fname = f"phishguard-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.pdf"
        # disposition=inline previews in the browser; attachment forces a download
        disp = "inline" if disposition == "inline" else "attachment"
        return Response(pdf, media_type="application/pdf",
                        headers={"Content-Disposition": f"{disp}; filename={fname}"})

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
            data = None
        elif url:
            parsed = ParsedEmail(message_id=None, subject=None, from_header="", to_header="",
                                 date_header="", sender_name="", sender_email="", sender_domain="",
                                 receiver_email="", receiver_domain="", envelope_from=None,
                                 reply_to=None, return_path=None, body_text=url, body_html="",
                                 urls=[url], attachments=[], auth=AuthResult(),
                                 authentication_results={}, raw_headers={})
            data = None
        else:
            raise HTTPException(status_code=400, detail="Provide eml, text or url")
        report = analyze_email(parsed, ctx, raw=data)
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
            report = analyze_email(parsed, ctx, raw=raw)
            _persist(ctx, parsed, report, raw=raw)
            out.append(report.to_dict())
        fetcher.disconnect()
        return {"scanned": len(out), "results": out}

    def _fetch_uid(fetcher: MailFetcher, uid: str):
        """Fetch a single message's RFC822 bytes by UID. Returns (uid, bytes) or None."""
        try:
            typ, msg_data = fetcher._conn.uid("FETCH", uid, "(RFC822)")
            if typ != "OK" or not msg_data or not msg_data[0]:
                return None
            raw = msg_data[0][1]
            if isinstance(raw, bytes):
                return (uid, raw)
        except Exception:
            return None
        return None


    def _alert(ctx, report, uid: str) -> None:
        """Send a monitor threat notification to a configured webhook (best-effort)."""
        url = getattr(ctx.config, "monitor_alert_webhook", "")
        if not url:
            return
        subject = (report.source.get("subject") if isinstance(report.source, dict) else None) or "(no subject)"
        payload = {
            "source": "phishguard-monitor",
            "verdict": report.verdict.value,
            "risk_score": report.risk_score,
            "subject": subject,
            "sender": report.sender,
            "report_id": report.report_id,
            "uid": uid,
        }
        try:
            requests.post(url, json=payload, timeout=10)
        except Exception:
            pass


    def _monitor_loop(interval: int):
        ctx = _runtime_ctx()
        store = MonitorStore(str(Path(ctx.config.report_dir) / "monitor.db"))
        backoff = interval
        consecutive_failures = 0
        while app.state.monitor["running"]:
            try:
                fetcher = MailFetcher(ctx.config)
                fetcher.connect()
                validity = fetcher.uidvalidity()
                if not validity:
                    raise RuntimeError("could not determine mailbox UIDVALIDITY")
                if store.update_uidvalidity(validity):
                    store.reset()
                batch = int(getattr(ctx.config, "monitor_batch", 50))
                uids = fetcher.fetch_unseen_uids(batch)
                fresh = store.unprocessed(uids, validity)
                scanned = 0
                for uid in fresh:
                    if not app.state.monitor["running"]:
                        break
                    pair = _fetch_uid(fetcher, uid)
                    if not pair:
                        continue
                    _, raw = pair
                    parsed = parse_message(raw)
                    report = analyze_email(parsed, ctx, raw=raw)
                    _persist(ctx, parsed, report, raw=raw)
                    store.mark_processed(validity, uid, report.report_id, report.timestamp)
                    scanned += 1
                    if report.verdict.value in ("phishing", "malicious"):
                        _alert(ctx, report, uid)
                fetcher.disconnect()
                consecutive_failures = 0
                backoff = interval
                if scanned:
                    app.state.monitor["last_scan"] = time.strftime("%Y-%m-%d %H:%M:%S")
                    app.state.monitor["last_new"] = scanned
            except Exception as e:
                consecutive_failures += 1
                app.state.monitor["last_error"] = f"{type(e).__name__}: {e}"
            sleep_for = backoff if consecutive_failures else interval
            time.sleep(sleep_for)
            if consecutive_failures:
                backoff = min(backoff * 2, int(getattr(ctx.config, "monitor_backoff_max", 600)))
        store.close()

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
        mon = {k: v for k, v in app.state.monitor.items() if k != "thread"}
        return {"env": load_env_dict(), "monitor": mon}

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
        _save_feed_info(app.state.feed_info)
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

    @app.post("/api/report/{report_id}/reanalyze")
    def report_reanalyze(report_id: str):
        cfg = current_config()
        store = _store(cfg)
        raw = store.get_raw(report_id)
        if not raw:
            raise HTTPException(status_code=404, detail="No raw email stored for this report")
        from phishguard.mail.parser import parse_message
        parsed = parse_message(raw)
        ctx = _runtime_ctx()
        report = analyze_email(parsed, ctx, raw=raw)
        store.update_report(report)
        ExportManager(cfg).export(report)
        RemediationManager(cfg).apply(report)
        return {"ok": True, "verdict": report.verdict.value, "risk_score": report.risk_score}

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
            if not sample:
                return {"ok": True, "tested": False, "note": "no reports to export"}
            import socket as _sock
            from phishguard.export import build_cef
            report = _dict_to_report(sample[0])
            cfg = ctx.config
            addr = cfg.export_syslog_addr
            wh = cfg.export_webhook_url
            use_cef = cfg.export_use_cef
            dests = []
            if addr:
                try:
                    host, _, port = addr.partition(":")
                    port = int(port) if port else 514
                    msg = build_cef(report) if use_cef else json.dumps(report.to_dict(), default=str)
                    s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
                    s.sendto(msg.encode("utf-8"), (host, port))
                    s.close()
                    dests.append({"type": "syslog", "target": addr, "ok": True})
                except Exception as e:
                    dests.append({"type": "syslog", "target": addr, "ok": False, "detail": str(e)})
            if wh:
                try:
                    requests.post(wh, json=report.to_dict(), timeout=10)
                    dests.append({"type": "webhook", "target": wh, "ok": True})
                except Exception as e:
                    dests.append({"type": "webhook", "target": wh, "ok": False, "detail": str(e)})
            if not dests:
                dests.append({"type": "none", "ok": False, "detail": "No syslog address or webhook URL configured"})
            return {"ok": True, "tested": True, "destinations": dests}
        return {"ok": True}

    # ---------- enrichment test ----------
    @app.post("/api/enrichment/test")
    async def enrichment_test(request: Request):
        d = dict(await request.form())
        provider = (d.get("provider") or "").lower()
        key = d.get("key", "") or ""
        host = d.get("host", "") or ""
        url = d.get("url", "") or ""
        if provider == "vt":
            if not key:
                return {"ok": False, "message": "No VirusTotal API key provided"}
            try:
                r = requests.get("https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1",
                                  headers={"x-apikey": key}, timeout=12)
                if r.status_code == 200:
                    return {"ok": True, "message": "VirusTotal connected successfully"}
                return {"ok": False, "message": f"VirusTotal returned HTTP {r.status_code}"}
            except Exception as e:
                return {"ok": False, "message": f"VirusTotal unreachable: {e}"}
        if provider == "gsb":
            if not key:
                return {"ok": False, "message": "No Google Safe Browsing API key provided"}
            return {"ok": True, "message": "Google Safe Browsing key saved (live test skipped to avoid API quota)"}
        if provider == "clamav":
            import socket as _sock
            target = host or "127.0.0.1:3310"
            try:
                h, _, p = target.partition(":")
                s = _sock.create_connection((h, int(p or 3310)), timeout=5)
                s.close()
                return {"ok": True, "message": f"ClamAV reachable at {target}"}
            except Exception as e:
                return {"ok": False, "message": f"ClamAV unreachable at {target}: {e}"}
        if provider == "sandbox":
            if key and url:
                return {"ok": True, "message": "Sandbox credentials saved"}
            return {"ok": False, "message": "Sandbox requires both API key and URL"}
        return {"ok": False, "message": "Unknown provider"}

    # ---------- settings ----------
    @app.get("/api/settings")
    def settings_get():
        cfg = current_config()
        return {"config": _config_public(cfg), "env": load_env_dict()}

    @app.post("/api/settings")
    async def settings_save(request: Request):
        fd = await request.form()
        form = {}
        for k, v in fd.multi_items():
            form[k] = v
        updates = {}
        for key in (BOOL_KEYS | INT_KEYS | STRING_KEYS):
            if key not in form:
                continue
            val = form[key]
            if key in BOOL_KEYS:
                # last-wins handles the hidden-input(false)+checkbox(true) trick:
                # checked -> true, unchecked -> false.
                updates[key] = "true" if (val or "") in ("true", "on", "1") else "false"
            elif key in INT_KEYS:
                try:
                    updates[key] = str(int(val))
                except ValueError:
                    pass
            else:
                if val not in (None, ""):
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

    # ---------- sender reputation ----------
    @app.get("/api/sender/reputation")
    def sender_reputation_get(sender: str = ""):
        ctx = _runtime_ctx()
        if not sender:
            return {"stats": ctx.reputation.stats(), "safe": ctx.reputation.all_safe()[:200]}
        return {"sender": sender, "reputation": ctx.reputation.reputation_of(sender)}

    @app.post("/api/sender/trust")
    def sender_trust(sender: str = Form(""), note: str = Form("")):
        ctx = _runtime_ctx()
        ctx.reputation.trust(sender, note)
        return {"ok": True, "sender": ctx.reputation._key(sender), "reputation": "safe"}

    @app.post("/api/sender/mark-bad")
    def sender_mark_bad(sender: str = Form(""), note: str = Form("")):
        ctx = _runtime_ctx()
        ctx.reputation.mark_bad(sender, note)
        return {"ok": True, "sender": ctx.reputation._key(sender), "reputation": "bad"}

    @app.delete("/api/sender/reputation")
    def sender_reputation_delete(sender: str = Form()):
        ctx = _runtime_ctx()
        ctx.reputation.remove(sender)
        return {"ok": True}

    # ---------- forensics ----------
    @app.get("/api/forensics/ioc/{report_id}")
    def forensics_ioc(report_id: str):
        r = _store(current_config()).get_report(report_id)
        if not r:
            raise HTTPException(status_code=404, detail="Not found")
        iocs = extract_iocs(r)
        return {"report_id": report_id, "iocs": iocs.to_dict()}

    @app.post("/api/forensics/enrich")
    async def forensics_enrich(request: Request):
        ctx = _runtime_ctx()
        if ctx.ti is None:
            return {"ok": False, "message": "No threat-intel providers enabled. Set a provider API key in Settings."}
        ct = request.headers.get("content-type", "")
        iocs = None
        if "application/json" in ct:
            body = await request.json()
            report_id = body.get("report_id")
            if report_id:
                r = _store(ctx.config).get_report(report_id)
                if not r:
                    raise HTTPException(status_code=404, detail="Report not found")
                iocs = extract_iocs(r)
            elif body.get("text"):
                from phishguard.util.text import extract_urls
                from phishguard.models import ParsedEmail, AuthResult
                text = body["text"]
                parsed = ParsedEmail(message_id=None, subject=None, from_header="", to_header="",
                                     date_header="", sender_name="", sender_email="", sender_domain="",
                                     receiver_email="", receiver_domain="", envelope_from=None,
                                     reply_to=None, return_path=None, body_text=text, body_html="",
                                     urls=extract_urls(text), attachments=[], auth=AuthResult(),
                                     authentication_results={}, raw_headers={})
                iocs = extract_iocs(parsed.to_dict() if hasattr(parsed, "to_dict") else {})
        else:
            data = await request.body()
            if data:
                try:
                    r = json.loads(data)
                    iocs = extract_iocs(r)
                except Exception:
                    iocs = None
        if iocs is None:
            return {"ok": False, "message": "Provide report_id, JSON report, or text."}
        enrichment = ctx.ti.enrich(iocs)
        return {"ok": True, "report_id": request.query_params.get("report_id"), **enrichment}

    @app.get("/api/forensics/evidence/{report_id}")
    def forensics_evidence_list(report_id: str):
        ctx = _runtime_ctx()
        if ctx.evidence is None:
            return {"enabled": False}
        return {"report_id": report_id, "artifacts": ctx.evidence.list_artifacts(report_id)}

    @app.get("/api/forensics/evidence/{report_id}/{name}")
    def forensics_evidence_get(report_id: str, name: str):
        ctx = _runtime_ctx()
        if ctx.evidence is None:
            raise HTTPException(status_code=404, detail="Evidence disabled")
        path = ctx.evidence.get_artifact(report_id, name)
        if path is None:
            raise HTTPException(status_code=404, detail="Artifact not found")
        return FileResponse(path)

    @app.get("/api/forensics/takedown/{report_id}")
    def forensics_takedown(report_id: str):
        r = _store(current_config()).get_report(report_id)
        if not r:
            raise HTTPException(status_code=404, detail="Not found")
        iocs = extract_iocs(r)
        enrichment = None
        ctx = _runtime_ctx()
        if ctx.ti is not None:
            enrichment = ctx.ti.enrich(iocs)
        pkg = build_takedown_package(r, iocs.to_dict(), enrichment)
        from fastapi.responses import Response
        return Response(pkg, media_type="application/zip",
                        headers={"Content-Disposition": f"attachment; filename={report_id}-takedown.zip"})

    @app.get("/api/ti/status")
    def ti_status():
        ctx = _runtime_ctx()
        names = ctx.ti.enabled_names if ctx.ti is not None else []
        return {"providers": names, "enabled": bool(names)}

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
        "urlscan_enabled": cfg.urlscan_enabled, "shodan_enabled": cfg.shodan_enabled,
        "otx_enabled": cfg.otx_enabled, "misp_enabled": cfg.misp_enabled,
        "abuseipdb_enabled": cfg.abuseipdb_enabled,
        "url_deep_scan_enabled": cfg.url_deep_scan_enabled,
        "url_deep_screenshot_enabled": cfg.url_deep_screenshot_enabled,
        "evidence_enabled": cfg.evidence_enabled,
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
