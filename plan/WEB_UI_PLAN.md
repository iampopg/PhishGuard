# Web Control Plane — Required UI Surfaces

A phishing-detection product is only useful if analysts/SOC can *operate* it from the
UI, not just read reports. The web dashboard was rebuilt as a full **control plane**.
Every engine capability is reachable from the browser; configuration is persisted to
`.env` (shared with the CLI) so changes apply everywhere.

## Pages (each maps to an engine capability)

| Page | Controls | Engine link |
|------|----------|------------|
| **Dashboard** | verdict stats, recent analyses, monitor status | Report store |
| **Reports** | list + filter by verdict, detail, **analyst feedback** (TP/FP) | Report store + feedback loop |
| **Scan** | upload `.eml`, paste text, or scan a single URL | `pipeline.analyze_email` |
| **Mailbox** | configure IMAP (server/user/pass/mailbox/SSL/port/mark-read), **Scan now**, **Start/Stop monitor** | `mail.fetcher` + monitor thread |
| **Feeds** | pull URLhaus/OpenPhish into cache, show counts | `feeds.FeedManager` |
| **Org Profile** | edit protected/brand/VIP/trusted domains | `OrgProfile` (lookalike/BEC) |
| **Rules** | view detection rules + scoring thresholds | `rules` engine |
| **Remediation** | enable + provider (M365/Gmail) + credentials | `remediation.RemediationManager` |
| **Export** | enable syslog(CEF/JSON)/webhook, min severity, **test export** | `export.ExportManager` |
| **Settings** | all engine config: IMAP, VT/GSB, ClamAV/sandbox, monitor, behavioral, thresholds, DNS checks, trusted domains, web creds, storage | `Config` |

## Design decisions
- Auth: Flask-Login single admin (from config).
- Config persistence: web writes `.env` in place (preserves comments); actions rebuild
  the runtime context from env so edits take effect immediately.
- Read-only by default: mailbox scan marks read only if explicitly enabled; remediation
  off unless configured.

## Out of scope (v1)
- Multi-user RBAC (single admin).
- Editing rule YAML in-browser (rules are view-only; change in `rules/defaults.py`).
- Live mailbox preview inside the web (scan is on demand / scheduled).
