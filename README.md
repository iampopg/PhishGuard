# PhishGuard

An industrial-grade, **self-hosted, offline-first** email phishing detection & analysis
engine with a CLI and a full web control plane. PhishGuard is built to be **auditable
and transparent**: every verdict is explained by weighted, capped signals — no black
boxes.

> **Honest positioning:** PhishGuard aims to be the best *open / self-hosted / auditable*
> detection engine, not a claim to beat the top-1% commercial vendors (Abnormal, Defender,
> Proofpoint) at global scale. Its behavioral BEC signal is a strong second-line detector
> based on *your* mail, not a cross-tenant network effect.

## Features

- **Detection engine first.** 9 transparent analyzers:
  `header_auth` (SPF/DKIM/DMARC + alignment), `header_analysis` (reply-to/return-path/
  message-id mismatches, VIP display-name impersonation), `domain_reputation` (lookalike/
  disposable/newly-registered domains), `org_context` (brand-in-display + your-domain
  lookalike), `url_scanner` (IP hosts, suspicious TLDs, shorteners, display/text mismatch,
  brand lookalikes, threat-intel hits), `content_analyzer` (urgency/authority/credential/
  financial cues, external HTML forms, obfuscation), `attachment_analyzer` (executables,
  macro Office docs, double extensions, HTML, hash reputation), `behavioral` (first-contact
  BEC anomaly), `sandbox` (ClamAV INSTREAM / hash reputation).
- **Transparent scoring.** Weighted signals → `risk_score` 0–100 → `safe / suspicious /
  phishing / malicious` (thresholds configurable). Detections-as-code rule engine maps
  findings to recommended actions (quarantine, notify_soc, review, train_user, …).
- **Self-contained, optional APIs.** Works with **zero external APIs**. VirusTotal,
  Google Safe Browsing, ClamAV and free feeds (URLhaus/OpenPhish) are optional and degrade
  gracefully.
- **Web control plane.** Dashboard, Reports (+ analyst feedback), Scan (EML/text/URL),
  Mailbox (configure IMAP + Scan now + scheduled monitor), Feeds, Org Profile, Rules,
  Remediation, SIEM Export, and full Settings — all configurable from the browser; config
  is persisted to `.env` and shared with the CLI.
- **Persistence & export.** SQLite report store with feedback; SIEM export via syslog
  (CEF or JSON) and webhook.
- **Post-delivery remediation.** Optional M365 (Graph) / Gmail move-to-junk / soft-delete
  / notify. This is **post-delivery only**, not a pre-delivery gateway.

## Architecture

```
EML ─▶ parser ─▶ analyzers ─▶ aggregate(scoring) ─▶ rules ─▶ Report
                                   │
            IntelHub (VT/GSB/feeds) · BehavioralStore · SandboxManager
                                   │
                    ReportStore (SQLite) · ExportManager · RemediationManager
```

Each analyzer implements `analyze(email, ctx) -> AnalyzerResult(score, findings)`;
`pipeline.analyze_email` runs them, aggregates, builds a `Report`, and applies rules.

## Installation

```bash
pip install .[dev]        # includes pytest, ruff, mypy
cp .env.example .env      # then fill in values (see Configuration)
```

Python 3.10+.

## Configuration

All settings are environment variables (or a `.env` file). See `.env.example`. Key groups:
IMAP mailbox, VirusTotal / Google Safe Browsing, ClamAV / sandbox, monitor, behavioral,
org profile path, web dashboard, storage, remediation, SIEM export, and engine thresholds.
**Body text never leaves the box** when no external APIs are enabled.

## CLI usage

```bash
phishguard scan-eml sample.phish.eml
phishguard scan-url https://paypa1.com/login
phishguard scan-text "urgent verify password http://paypa1.com/login"
phishguard scan-mailbox --limit 50        # read-only IMAP scan
phishguard feeds                          # pull URLhaus + OpenPhish into cache
phishguard serve --host 127.0.0.1 --port 8080
```

The web dashboard is the recommended way to operate everything (configure mailbox, run
scans, start a monitor, manage org profile, rules, remediation, and export).

## Web dashboard

Run `phishguard serve`, open `http://127.0.0.1:8080`, log in with the configured
`PG_WEB_USERNAME` / `PG_WEB_PASSWORD`, and use the nav to control every capability.

## Docker

```bash
docker compose up --build     # serves the web UI on :8080
```

## Testing

```bash
python -m pytest -q
```

Covers every analyzer, scoring/rules, persistence, export, feeds, behavioral BEC, the IMAP
fetcher (mocked), the sandbox/remediation dry-paths, and the full web console (all pages
render; scan upload + feedback persist).

## Limitations / roadmap

- Single-admin auth (no RBAC yet); rules are view-only in the UI (edit `rules/defaults.py`).
- Behavioral BEC uses a local baseline (your org only), not a cross-tenant network effect.
- Remediation requires provider credentials and is post-delivery only.

## License

MIT.
