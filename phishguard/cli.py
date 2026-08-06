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
    return ctx


def _persist(ctx: AnalysisContext, parsed: ParsedEmail, report) -> None:
    store = ReportStore(str(Path(ctx.config.report_dir) / "phishguard.db"))
    store.save_report(report)
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
    report = analyze_email(parsed, ctx)
    print(_report_json(report))
    _persist(ctx, parsed, report)
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
        report = analyze_email(parsed, ctx)
        _persist(ctx, parsed, report)
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
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    ctx = _load_ctx(args)
    return args.func(args, ctx)


if __name__ == "__main__":
    raise SystemExit(main())
