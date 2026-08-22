from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from phishguard.config import Config
from phishguard.models import AuthResult, ParsedEmail
from phishguard.org_profile import OrgProfile
from phishguard.engines.base import AnalysisContext
from phishguard.mail.parser import parse_message
from phishguard.util.text import extract_urls
from phishguard.report_store import ReportStore
from phishguard.behavioral_store import BehavioralStore
from phishguard.export import ExportManager
from phishguard.remediation import RemediationManager
from phishguard.forensics.evidence import EvidenceStore
from phishguard.reputation import SenderReputationStore
from phishguard.ti import ThreatIntelligenceManager
from datetime import datetime


def _load_config() -> Config:
    try:
        from dotenv import load_dotenv  # type: ignore
        load_dotenv()
    except Exception:
        pass
    return Config.load()


def _load_ctx(args) -> AnalysisContext:
    config = _load_config()
    org = OrgProfile.load(args.org_profile) if Path(args.org_profile).exists() else OrgProfile()
    from phishguard.intel import IntelligenceHub
    intel = IntelligenceHub(config, cache_dir=Path(args.cache_dir))
    ctx = AnalysisContext(config=config, org_profile=org, intel=intel, behavioral=None, mailbox_id="cli")
    if config.behavioral_enabled:
        ctx.behavioral = BehavioralStore(str(Path(args.cache_dir) / "behavioral.db"))
    if config.evidence_enabled:
        ctx.evidence = EvidenceStore(str(Path(config.report_dir)))
    if getattr(config, "urlscan_enabled", False) or getattr(config, "shodan_enabled", False) or \
       getattr(config, "otx_enabled", False) or getattr(config, "misp_enabled", False) or \
       getattr(config, "abuseipdb_enabled", False):
        ctx.ti = ThreatIntelligenceManager(config)
    ctx.reputation = SenderReputationStore(str(Path(args.cache_dir) / "reputation.db"))
    from phishguard.ai import PhishGuardAI
    ctx.ai = PhishGuardAI(config)
    return ctx


def _persist(ctx: AnalysisContext, parsed: ParsedEmail, report, raw: bytes = None) -> None:
    store = ReportStore(str(Path(ctx.config.report_dir) / "phishguard.db"))
    store.save_report(report, raw=raw)
    if ctx.behavioral is not None:
        ctx.behavioral.record(parsed)
    ExportManager(ctx.config).export(report)
    RemediationManager(ctx.config).apply(report)


def _report_json(report) -> str:
    return json.dumps(report.to_dict(), indent=2, default=str)


def _empty_email(**kw) -> ParsedEmail:
    base = dict(
        message_id=None, subject=None, from_header="", to_header="",
        date_header="", sender_name="", sender_email="", sender_domain="",
        receiver_email="", receiver_domain="", envelope_from=None,
        reply_to=None, return_path=None, body_text="", body_html="",
        urls=[], attachments=[], auth=AuthResult(),
        authentication_results={}, raw_headers={},
    )
    base.update(kw)
    return ParsedEmail(**base)


def cmd_scan_eml(args, ctx: AnalysisContext) -> int:
    raw = Path(args.eml).read_bytes()
    parsed = parse_message(raw)
    from phishguard.pipeline import analyze_email
    report = analyze_email(parsed, ctx, raw=raw)
    print(_report_json(report))
    _persist(ctx, parsed, report, raw=raw)
    return 0


def cmd_scan_url(args, ctx: AnalysisContext) -> int:
    parsed = _empty_email(body_text=args.url, urls=[args.url])
    from phishguard.pipeline import analyze_email
    report = analyze_email(parsed, ctx)
    print(_report_json(report))
    _persist(ctx, parsed, report)
    return 0


def cmd_scan_text(args, ctx: AnalysisContext) -> int:
    text = args.text
    if Path(text).exists():
        text = Path(text).read_text()
    parsed = _empty_email(body_text=text, urls=extract_urls(text))
    from phishguard.pipeline import analyze_email
    report = analyze_email(parsed, ctx)
    print(_report_json(report))
    _persist(ctx, parsed, report)
    return 0


def cmd_scan_mailbox(args, ctx: AnalysisContext) -> int:
    from phishguard.mail.fetcher import MailFetcher
    from phishguard.pipeline import analyze_email
    fetcher = MailFetcher(ctx.config)
    fetcher.connect()
    if getattr(args, "all", False):
        items = fetcher.fetch_all(limit=args.limit)
    else:
        items = fetcher.fetch_unseen(limit=args.limit)
    out = []
    for n, (uid, raw) in enumerate(items, 1):
        print(f"[scan-mailbox] {n}/{len(items)} uid={uid}", file=sys.stderr, flush=True)
        parsed = parse_message(raw)
        report = analyze_email(parsed, ctx, raw=raw)
        _persist(ctx, parsed, report, raw=raw)
        out.append(report.to_dict())
    fetcher.disconnect()
    print(json.dumps(out, indent=2, default=str))
    return 0


def cmd_serve(args, ctx: AnalysisContext) -> int:
    import uvicorn

    web_out = Path(__file__).resolve().parent.parent / "web" / "out"
    if not web_out.exists():
        print("UI not built. Building Next.js app (first build may take a minute)...",
              file=sys.stderr, flush=True)
        if not _build_web():
            print("Could not build the UI. Run `phishguard web build` manually, then `phishguard serve`.",
                  file=sys.stderr)
            return 1
    print(f"PhishGuard serving on http://{args.host}:{args.port}", file=sys.stderr, flush=True)
    uvicorn.run("phishguard.api.server:app", host=args.host, port=args.port, log_level="info")
    return 0


def _run(cmd: list, cwd: Path) -> bool:
    print(f"[build] {' '.join(cmd)}", file=sys.stderr, flush=True)
    rc = subprocess.call(cmd, cwd=str(cwd))
    return rc == 0


def _build_web() -> bool:
    web_dir = Path(__file__).resolve().parent.parent / "web"
    if not (web_dir / "package.json").exists():
        print("web/ project not found", file=sys.stderr)
        return False
    if shutil.which("npm") is None:
        print("npm not found on PATH", file=sys.stderr)
        return False
    if not (web_dir / "node_modules").exists():
        if not _run(["npm", "install"], cwd=web_dir):
            return False
    return _run(["npm", "run", "build"], cwd=web_dir)


def cmd_web_build(args, ctx: AnalysisContext) -> int:
    return 0 if _build_web() else 1


def cmd_web_dev(args, ctx: AnalysisContext) -> int:
    web_dir = Path(__file__).resolve().parent.parent / "web"
    if not (web_dir / "node_modules").exists():
        _run(["npm", "install"], cwd=web_dir)
    os.chdir(web_dir)
    return subprocess.call(["npm", "run", "dev"])


def cmd_feeds(args, ctx: AnalysisContext) -> int:
    from phishguard.feeds import FeedManager
    fm = FeedManager()
    print(json.dumps(fm.update_all(ctx.intel)))
    return 0


def cmd_export_pdf(args, ctx: AnalysisContext) -> int:
    from phishguard.report_pdf import generate_report_pdf
    store = ReportStore(str(Path(ctx.config.report_dir) / "phishguard.db"))
    reports = store.list_reports(limit=10000)
    if args.verdict:
        reports = [r for r in reports if r["verdict"] == args.verdict]
    if args.from_date:
        reports = [r for r in reports if r["timestamp"] >= args.from_date]
    if args.to_date:
        reports = [r for r in reports if r["timestamp"] <= args.to_date + "T23:59:59"]
    out = Path(args.output) if args.output else Path(f"phishguard-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.pdf")
    generate_report_pdf(reports, str(out), verdict_filter=args.verdict or None,
                        date_from=args.from_date, date_to=args.to_date)
    print(f"Wrote PDF report ({len(reports)} analyses) to {out}")
    return 0


def cmd_forensics_extract(args, ctx: AnalysisContext) -> int:
    from phishguard.forensics.ioc import extract_iocs
    report = _load_report(ctx, args)
    if report is None:
        return 1
    print(json.dumps(extract_iocs(report).to_dict(), indent=2, default=str))
    return 0


def cmd_forensics_enrich(args, ctx: AnalysisContext) -> int:
    from phishguard.forensics.ioc import extract_iocs
    if ctx.ti is None:
        print("No threat-intel providers enabled. Set a provider API key.", file=sys.stderr)
        return 1
    report = _load_report(ctx, args)
    if report is None:
        return 1
    iocs = extract_iocs(report)
    print(json.dumps(ctx.ti.enrich(iocs), indent=2, default=str))
    return 0


def cmd_forensics_takedown(args, ctx: AnalysisContext) -> int:
    from phishguard.forensics.ioc import extract_iocs
    from phishguard.forensics.takedown import build_takedown_package
    report = _load_report(ctx, args)
    if report is None:
        return 1
    iocs = extract_iocs(report)
    enrichment = ctx.ti.enrich(iocs) if ctx.ti is not None else None
    out = Path(args.output) if args.output else Path(f"{args.report_id}-takedown.zip")
    out.write_bytes(build_takedown_package(report, iocs.to_dict(), enrichment))
    print(f"Wrote takedown package to {out}")
    return 0


def cmd_ti_status(args, ctx: AnalysisContext) -> int:
    names = ctx.ti.enabled_names if ctx.ti is not None else []
    print(json.dumps({"providers": names, "enabled": bool(names)}, indent=2))
    return 0


def _load_report(ctx: AnalysisContext, args) -> "object":
    if getattr(args, "eml", None):
        raw = Path(args.eml).read_bytes()
        parsed = parse_message(raw)
        from phishguard.pipeline import analyze_email
        return analyze_email(parsed, ctx, raw=raw).to_dict()
    store = ReportStore(str(Path(ctx.config.report_dir) / "phishguard.db"))
    r = store.get_report(args.report_id)
    if not r:
        print(f"Report not found: {args.report_id}", file=sys.stderr)
    return r


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="phishguard", description="PhishGuard phishing detection engine")
    p.add_argument("--org-profile", default="org_profile.json")
    p.add_argument("--cache-dir", default=".cache/intel")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan-eml", help="Scan an .eml file")
    s.add_argument("eml")
    s.set_defaults(func=cmd_scan_eml)

    s = sub.add_parser("scan-url", help="Scan a single URL")
    s.add_argument("url")
    s.set_defaults(func=cmd_scan_url)

    s = sub.add_parser("scan-text", help="Scan raw text or a .txt/.eml file")
    s.add_argument("text")
    s.set_defaults(func=cmd_scan_text)

    s = sub.add_parser("scan-mailbox", help="Scan mailbox messages via IMAP")
    s.add_argument("--limit", type=int, default=50)
    s.add_argument("--all", action="store_true", help="Scan all messages (not just unseen)")
    s.set_defaults(func=cmd_scan_mailbox)

    s = sub.add_parser("serve", help="Run API + built Next.js UI on one port")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.set_defaults(func=cmd_serve)

    w = sub.add_parser("web", help="Next.js UI tooling")
    ws = w.add_subparsers(dest="web_command", required=True)
    wb = ws.add_parser("build", help="Install deps and build the static UI")
    wb.set_defaults(func=cmd_web_build)
    wd = ws.add_parser("dev", help="Run the Next.js dev server (hot reload)")
    wd.set_defaults(func=cmd_web_dev)

    s = sub.add_parser("feeds", help="Pull free threat-intel feeds into the local cache")
    s.set_defaults(func=cmd_feeds)

    f = sub.add_parser("forensics", help="Forensic observables, enrichment and takedown")
    fs = f.add_subparsers(dest="forensics_command", required=True)
    fe = fs.add_parser("extract", help="Extract IOCs from a report or an .eml file")
    fe.add_argument("--report-id", dest="report_id", default="")
    fe.add_argument("--eml", default="")
    fe.set_defaults(func=cmd_forensics_extract)
    fn = fs.add_parser("enrich", help="Extract IOCs and enrich across threat-intel providers")
    fn.add_argument("--report-id", dest="report_id", default="")
    fn.add_argument("--eml", default="")
    fn.set_defaults(func=cmd_forensics_enrich)
    ft = fs.add_parser("takedown", help="Build a takedown/intel package for a report")
    ft.add_argument("report_id")
    ft.add_argument("--output", default="")
    ft.set_defaults(func=cmd_forensics_takedown)

    s = sub.add_parser("ti", help="Threat-intel provider status")
    s.set_defaults(func=cmd_ti_status)

    s = sub.add_parser("export-pdf", help="Export a filtered PDF report of all analyses")
    s.add_argument("--verdict", default="", help="Filter by verdict (safe/suspicious/phishing/malicious)")
    s.add_argument("--from", dest="from_date", default="", help="Start date (YYYY-MM-DD)")
    s.add_argument("--to", dest="to_date", default="", help="End date (YYYY-MM-DD)")
    s.add_argument("--output", default="", help="Output PDF path")
    s.set_defaults(func=cmd_export_pdf)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    ctx = _load_ctx(args)
    return args.func(args, ctx)


if __name__ == "__main__":
    raise SystemExit(main())
