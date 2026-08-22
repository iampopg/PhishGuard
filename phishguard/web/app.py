from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import List, Optional

from phishguard.behavioral_store import BehavioralStore
from phishguard.config import Config
from phishguard.config_store import (current_config, load_env_dict, reload_env,
                                     update_env)
from phishguard.engines.base import AnalysisContext
from phishguard.export import ExportManager
from phishguard.feeds import FeedManager
from phishguard.forensics.ioc import extract_iocs
from phishguard.forensics.takedown import build_takedown_package
from phishguard.forensics.evidence import EvidenceStore
from phishguard.intel import IntelligenceHub
from phishguard.mail.fetcher import MailFetcher
from phishguard.mail.parser import parse_message
from phishguard.models import AuthResult, ParsedEmail
from phishguard.org_profile import OrgProfile
from phishguard.pipeline import analyze_email
from phishguard.remediation import RemediationManager
from phishguard.report_store import ReportStore
from phishguard.reputation import SenderReputationStore
from phishguard.rules import DEFAULT_RULES
from phishguard.ti import ThreatIntelligenceManager
from phishguard.util.text import extract_urls

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


def _runtime_ctx() -> AnalysisContext:
    cfg = current_config()
    org_path = cfg.org_profile_path or "org_profile.json"
    org = OrgProfile.load(org_path) if os.path.exists(org_path) else OrgProfile()
    intel = IntelligenceHub(cfg, cache_dir=Path(cfg.report_dir) / ".intel_cache")
    behavioral = BehavioralStore(Path(cfg.report_dir) / "behavioral.db") if cfg.behavioral_enabled else None
    evidence = EvidenceStore(Path(cfg.report_dir)) if cfg.evidence_enabled else None
    ti = ThreatIntelligenceManager(cfg) if cfg.urlscan_enabled or cfg.shodan_enabled or \
        cfg.otx_enabled or cfg.misp_enabled or cfg.abuseipdb_enabled else None
    reputation = SenderReputationStore(str(Path(cfg.report_dir) / "reputation.db"))
    return AnalysisContext(config=cfg, org_profile=org, intel=intel, behavioral=behavioral,
                           ti=ti, evidence=evidence, reputation=reputation, mailbox_id="web")


def _store(cfg: Config) -> ReportStore:
    return ReportStore(str(Path(cfg.report_dir) / "phishguard.db"))


def _persist(ctx: AnalysisContext, parsed: ParsedEmail, report) -> None:
    _store(ctx.config).save_report(report)
    if ctx.behavioral is not None:
        ctx.behavioral.record(parsed)
    ExportManager(ctx.config).export(report)
    RemediationManager(ctx.config).apply(report)


def create_app(ctx: Optional[AnalysisContext] = None):
    from flask import (Flask, request, render_template, redirect, url_for, flash)
    from flask_login import (LoginManager, UserMixin, login_user, login_required,
                             logout_user, current_user)

    app = Flask(__name__)
    app.secret_key = (ctx.config.web_secret_key if ctx else "change_me")
    app.config["ctx"] = ctx or _runtime_ctx()
    app.config["monitor"] = {"thread": None, "running": False, "interval": 60}

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = "login"

    class User(UserMixin):
        pass

    @login_manager.user_loader
    def load_user(uid):
        u = User()
        u.id = uid
        return u

    def _ctx() -> AnalysisContext:
        return app.config["ctx"]

    def _refresh_ctx():
        app.config["ctx"] = _runtime_ctx()

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            cfg = _ctx().config
            if (request.form.get("username") == cfg.web_username and
                    request.form.get("password") == cfg.web_password):
                u = User()
                u.id = cfg.web_username
                login_user(u)
                return redirect(url_for("dashboard"))
            flash("Invalid credentials")
        return render_template("login.html")

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("login"))

    @app.route("/")
    @login_required
    def dashboard():
        ctx = _ctx()
        reports = _store(ctx.config).list_reports(limit=200)
        counts = {"safe": 0, "suspicious": 0, "phishing": 0, "malicious": 0}
        for r in reports:
            counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        return render_template("dashboard.html", counts=counts, recent=reports[:15],
                               monitor=app.config["monitor"]["running"])

    @app.route("/reports")
    @login_required
    def reports():
        ctx = _ctx()
        verdict = request.args.get("verdict")
        all_reports = _store(ctx.config).list_reports(limit=500)
        counts = {"safe": 0, "suspicious": 0, "phishing": 0, "malicious": 0}
        for r in all_reports:
            counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        if verdict:
            all_reports = [r for r in all_reports if r["verdict"] == verdict]
        return render_template("reports.html", reports=all_reports, verdict=verdict, counts=counts)

    @app.route("/report/<report_id>", methods=["GET", "POST"])
    @login_required
    def report_view(report_id):
        ctx = _ctx()
        store = _store(ctx.config)
        r = store.get_report(report_id)
        if not r:
            return "Not found", 404
        if request.method == "POST":
            store.add_feedback(report_id, request.form.get("label", ""), request.form.get("note", ""))
            flash("Feedback saved")
            return redirect(url_for("report_view", report_id=report_id))
        findings = [(a["name"], f) for a in r["analyzers"] for f in a["findings"]]
        return render_template("report.html", r=r, findings=findings,
                               feedback=store.get_feedback(report_id))

    @app.route("/scan", methods=["GET", "POST"])
    @login_required
    def scan():
        ctx = _ctx()
        result_html = ""
        if request.method == "POST":
            f = request.files.get("eml")
            text = request.form.get("text", "")
            url = request.form.get("url", "")
            if f and f.filename:
                parsed = parse_message(f.read())
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
                parsed = None
            if parsed is not None:
                report = analyze_email(parsed, ctx)
                _persist(ctx, parsed, report)
                result_html = render_template("scan_result.html", report=report)
        return render_template("scan.html", result_html=result_html)

    @app.route("/mailbox", methods=["GET", "POST"])
    @login_required
    def mailbox():
        ctx = _ctx()
        cfg = ctx.config
        env = load_env_dict()
        if request.method == "POST":
            action = request.form.get("action")
            if action == "save":
                updates = {
                    "PG_IMAP_SERVER": request.form.get("PG_IMAP_SERVER", ""),
                    "PG_IMAP_USERNAME": request.form.get("PG_IMAP_USERNAME", ""),
                    "PG_IMAP_PASSWORD": request.form.get("PG_IMAP_PASSWORD", ""),
                    "PG_IMAP_MAILBOX": request.form.get("PG_IMAP_MAILBOX", "INBOX"),
                    "PG_IMAP_USE_SSL": "true" if "PG_IMAP_USE_SSL" in request.form else "false",
                    "PG_IMAP_UNSEEN_ONLY": "true" if "PG_IMAP_UNSEEN_ONLY" in request.form else "false",
                    "PG_IMAP_MARK_READ": "true" if "PG_IMAP_MARK_READ" in request.form else "false",
                }
                if request.form.get("PG_IMAP_PORT"):
                    updates["PG_IMAP_PORT"] = request.form["PG_IMAP_PORT"]
                update_env(updates)
                _refresh_ctx()
                flash("Mailbox configuration saved")
                return redirect(url_for("mailbox"))
            elif action == "scan":
                limit = int(request.form.get("limit", 10))
                out = run_mailbox_scan(_ctx(), limit)
                return render_template("mailbox.html", env=env, cfg=cfg, results=out,
                                       monitor=app.config["monitor"]["running"])
            elif action == "start_monitor":
                start_monitor(app, int(request.form.get("interval", cfg.monitor_interval)))
                flash("Monitor started")
                return redirect(url_for("mailbox"))
            elif action == "stop_monitor":
                stop_monitor(app)
                flash("Monitor stopped")
                return redirect(url_for("mailbox"))
        return render_template("mailbox.html", env=env, cfg=cfg, results=None,
                               monitor=app.config["monitor"]["running"])

    @app.route("/feeds", methods=["GET", "POST"])
    @login_required
    def feeds():
        ctx = _ctx()
        info = app.config.get("feed_info", {})
        if request.method == "POST":
            fm = FeedManager()
            res = fm.update_all(ctx.intel)
            app.config["feed_info"] = {"counts": res, "time": time.strftime("%Y-%m-%d %H:%M:%S")}
            flash(f"Feeds updated: {res}")
            return redirect(url_for("feeds"))
        return render_template("feeds.html", info=info)

    @app.route("/org", methods=["GET", "POST"])
    @login_required
    def org():
        ctx = _ctx()
        cfg = ctx.config
        path = cfg.org_profile_path or "org_profile.json"
        if request.method == "POST":
            org = OrgProfile(
                protected_domains=[d.strip() for d in request.form.get("protected_domains", "").split(",") if d.strip()],
                vip_names=[d.strip() for d in request.form.get("vip_names", "").split(",") if d.strip()],
                brand_keywords=[d.strip() for d in request.form.get("brand_keywords", "").split(",") if d.strip()],
                brand_domains=[d.strip() for d in request.form.get("brand_domains", "").split(",") if d.strip()],
                trusted_domains=[d.strip() for d in request.form.get("trusted_domains", "").split(",") if d.strip()],
            )
            org.save(path)
            _refresh_ctx()
            flash(f"Organization profile saved to {path}")
            return redirect(url_for("org"))
        org = ctx.org_profile
        return render_template("org.html", org=org, path=path)

    @app.route("/rules")
    @login_required
    def rules():
        return render_template("rules.html", rules=DEFAULT_RULES,
                               cfg=_ctx().config)

    @app.route("/remediation", methods=["GET", "POST"])
    @login_required
    def remediation():
        ctx = _ctx()
        if request.method == "POST":
            provider = request.form.get("PG_REMEDIATION_PROVIDER", "")
            updates = {
                "PG_REMEDIATION_ENABLED": "true" if "PG_REMEDIATION_ENABLED" in request.form else "false",
                "PG_REMEDIATION_PROVIDER": provider,
                "PG_M365_TENANT_ID": request.form.get("PG_M365_TENANT_ID", ""),
                "PG_M365_CLIENT_ID": request.form.get("PG_M365_CLIENT_ID", ""),
                "PG_M365_CLIENT_SECRET": request.form.get("PG_M365_CLIENT_SECRET", ""),
                "PG_GMAIL_SA_JSON": request.form.get("PG_GMAIL_SA_JSON", ""),
            }
            update_env(updates)
            _refresh_ctx()
            flash("Remediation configuration saved")
            return redirect(url_for("remediation"))
        return render_template("remediation.html", env=load_env_dict(), cfg=ctx.config)

    @app.route("/export", methods=["GET", "POST"])
    @login_required
    def export():
        ctx = _ctx()
        if request.method == "POST":
            action = request.form.get("action")
            updates = {
                "PG_EXPORT_ENABLED": "true" if "PG_EXPORT_ENABLED" in request.form else "false",
                "PG_EXPORT_CEF": "true" if "PG_EXPORT_CEF" in request.form else "false",
                "PG_EXPORT_SYSLOG_ADDR": request.form.get("PG_EXPORT_SYSLOG_ADDR", ""),
                "PG_EXPORT_WEBHOOK_URL": request.form.get("PG_EXPORT_WEBHOOK_URL", ""),
                "PG_EXPORT_MIN_SEVERITY": request.form.get("PG_EXPORT_MIN_SEVERITY", "medium"),
            }
            update_env(updates)
            _refresh_ctx()
            if action == "test":
                em = ExportManager(_ctx().config)
                sample = _store(ctx.config).list_reports(limit=1)
                if sample:
                    em.export(_dict_to_report(sample[0]))
                    flash("Test export sent for most recent report")
                else:
                    flash("No reports to test-export yet")
                return redirect(url_for("export"))
            flash("Export configuration saved")
            return redirect(url_for("export"))
        return render_template("export.html", env=load_env_dict(), cfg=ctx.config)

    @app.route("/settings", methods=["GET", "POST"])
    @login_required
    def settings():
        ctx = _ctx()
        if request.method == "POST":
            updates = {}
            for key in (BOOL_KEYS | INT_KEYS | STRING_KEYS):
                if key in request.form:
                    val = request.form[key]
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
            _refresh_ctx()
            flash("Settings saved")
            return redirect(url_for("settings"))
        return render_template("settings.html", cfg=ctx.config, bool_keys=BOOL_KEYS,
                               int_keys=INT_KEYS, str_keys=STRING_KEYS, env=load_env_dict())

    @app.route("/api/reports")
    @login_required
    def api_reports():
        from flask import jsonify
        return jsonify(_store(_ctx().config).list_reports(limit=int(request.args.get("limit", 100))))

    @app.route("/api/scan", methods=["POST"])
    @login_required
    def api_scan():
        from flask import jsonify
        raw = request.get_data()
        parsed = parse_message(raw)
        ctx = _ctx()
        report = analyze_email(parsed, ctx)
        _persist(ctx, parsed, report)
        return jsonify(report.to_dict())

    return app


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


def _dict_to_report(d: dict):
    from phishguard.models import Report
    return Report(
        report_id=d["report_id"], timestamp=d["timestamp"], source=d.get("source", {}),
        verdict=_verdict(d["verdict"]), risk_score=d["risk_score"], summary=d.get("summary", ""),
        sender=d.get("sender", {}), analyzers=[], urls=d.get("urls", []),
        attachments=[], recommended_actions=d.get("recommended_actions", []), labels=d.get("labels", {}),
    )


def _verdict(v):
    from phishguard.models import Verdict
    return Verdict(v)


def run_mailbox_scan(ctx: AnalysisContext, limit: int) -> List[dict]:
    fetcher = MailFetcher(ctx.config)
    fetcher.connect()
    items = fetcher.fetch_unseen(limit=limit)
    out = []
    for uid, raw in items:
        parsed = parse_message(raw)
        report = analyze_email(parsed, ctx)
        _persist(ctx, parsed, report)
        out.append(report.to_dict())
    fetcher.disconnect()
    return out


def _monitor_loop(app, interval: int):
    while app.config["monitor"]["running"]:
        try:
            run_mailbox_scan(app.config["ctx"], 50)
        except Exception:
            pass
        time.sleep(interval)


def start_monitor(app, interval: int) -> None:
    if app.config["monitor"]["running"]:
        return
    app.config["monitor"]["running"] = True
    app.config["monitor"]["interval"] = interval
    t = threading.Thread(target=_monitor_loop, args=(app, interval), daemon=True)
    t.start()
    app.config["monitor"]["thread"] = t


def stop_monitor(app) -> None:
    app.config["monitor"]["running"] = False
