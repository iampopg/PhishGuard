# PhishGuard — System Architecture

> Companion to `RESEARCH.md` (80% research) and `../docs/PLANNING.md` (decisions). This
> document specifies *how* PhishGuard is built: topologies, components, data flow, module
> contracts, data model, rule engine, storage, API, and export. It is the engineering
> blueprint for the implementation phase.

## 1. Design goals & principles
- **Offline-first, opt-in cloud.** Core detection works with zero external APIs. VirusTotal,
  Google Safe Browsing, ClamAV, sandboxes, and TI feeds are optional and degrade gracefully.
- **Transparent & auditable.** Every verdict explains *why* (Rspamd-style). No black box.
- **Privacy boundary.** Email bodies stay in-memory; only domains/URLs/IPs/hashes leave the
  box, and only when an integration is enabled (SARA stance).
- **Modular analyzers + weighted scoring.** Each signal is an independent analyzer; scoring is
  additive, capped, and explainable.
- **Detections-as-code.** Users extend detection with their own rules (Sublime MQL inspiration).
- **Enterprise-ready output.** CLI, web dashboard, REST, and SIEM/SOAR export (syslog/CEF/LEEF/OTLP).
- **Self-hostable / air-gap friendly.** Docker Compose, no mandatory SaaS.

## 2. Deployment topologies
```
(A) CLI-only (forensics / automation)
    phishguard scan-eml file.eml  ->  JSON/HTML report (stdout/file)

(B) Daemon + API (service)
    [IMAP/M365/Gmail] -> fetcher -> engine -> store -> [web dashboard]
                                                      \-> [SIEM/SOAR export]

(C) MSSP multi-tenant (builds local network effect via feedback.py)
    tenantA mailbox ┐
    tenantB mailbox ┼-> engine -> shared intel cache + per-tenant baselines -> dashboards
    tenantC mailbox ┘

(D) Air-gapped
    All TI feeds pre-loaded from an internal mirror; no egress.
```

## 3. Component diagram
```
                        ┌────────────────────────────────────────────┐
  Inputs                │                  PhishGuard                  │
  ───────               │                                              │
  .eml / IMAP  ───────► │  mail.parser ─► ParsedEmail                  │
  M365 / Gmail ───────► │        │                                     │
                        │        ▼                                     │
                        │  engines (run in parallel, each returns      │
                        │  AnalyzerResult + Findings):                 │
                        │   • header_auth     (SPF/DKIM/DMARC/align)   │
                        │   • header_analysis (From/Reply-To/MsgID)    │
                        │   • domain_reputation (age, lookalike)       │
                        │   • org_context (VIP/brand/your-domain)       │
                        │   • url_scanner (extract, expand, TI, TOC)   │
                        │   • content_analyzer (lexicon/NLP/structure)  │
                        │   • attachment_analyzer (hash, type, VT)      │
                        │   • behavioral      (relationship-graph base)│
                        │        │                                     │
                        │        ▼                                     │
                        │  scoring.aggregate ─► Report(risk 0-100,     │
                        │                          verdict, findings)   │
                        │        │                                     │
                        │        ├─► report.store (JSON + SQLite)      │
                        │        ├─► rules engine (post-score actions)  │
                        │        ├─► export (syslog/CEF/webhook/OTLP)   │
                        │        ├─► remediation (M365/Gmail, optional) │
                        │        └─► web API + dashboard                │
                        └────────────────────────────────────────────┘
                                │                │
                    intel feeds │                │ baselines/labels
                    (cached)    ▼                ▼
                 URLhaus/OpenPhish/PhishTank/    SQLite (behavioral baseline,
                 AbuseIPDB/VT/GSB + sandbox       analyst feedback labels)
```

## 4. Data-flow pipeline
1. **Ingest** — `mail.fetcher` (IMAP/MSG/EML) or `scan-eml` (file). Streaming-friendly.
2. **Parse** — `mail.parser` → `ParsedEmail` (headers, bodies, URLs, attachments, auth results).
3. **Enrich** — `intel` lookups (cached TI), `org_profile` load, DNS for auth.
4. **Analyze** — all `engines.*` run (parallel where independent); each emits `AnalyzerResult`.
5. **Score** — `scoring.aggregate` sums bounded weights → `risk_score` + `verdict`.
6. **Act** — store → rules (optional auto-actions) → export → remediation → UI.
7. **Learn** — `feedback` records analyst labels + updates behavioral baseline.

## 5. Module contracts (interfaces)
```python
# engines/base.py
@dataclass
class Finding:
    analyzer: str
    title: str
    detail: str
    severity: Severity          # INFO/LOW/MEDIUM/HIGH/CRITICAL
    score: int                  # positive = risky; bounded per analyzer
    evidence: dict

@dataclass
class AnalyzerResult:
    name: str
    score: int
    findings: list[Finding]
    metadata: dict

class Analyzer(Protocol):
    name: str
    max_score: int              # cap so no single analyzer dominates
    def analyze(self, email: ParsedEmail, ctx: AnalysisContext) -> AnalyzerResult: ...
```
- `AnalysisContext` carries `config`, `org_profile`, `intel_cache`, `behavioral_store`,
  `mailbox_id`. Analyzers are side-effect free except via injected stores.
- `scoring.aggregate(results, thresholds) -> Report` clamps to 0–100 and maps verdict:
  `safe ≤ suspicious(30) ≤ phishing(60) ≤ malicious(85)` (configurable).

## 6. Data model (canonical JSON report)
```json
{
  "schema_version": 1,
  "report_id": "uuid",
  "timestamp": "ISO-8601",
  "source": {"type": "imap|eml|m365|gmail", "mailbox": "...", "message_id": "..."},
  "verdict": "safe|suspicious|phishing|malicious",
  "risk_score": 0,
  "summary": "short human summary",
  "sender": {
    "from": "Display <a@b.com>", "from_domain": "b.com",
    "reply_to_domain": "x.com", "return_path_domain": "b.com",
    "envelope_from": "bounce@b.com", "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass", "aligned": true}
  },
  "analyzers": [
    {"name": "header_auth", "score": 0, "findings": [ {"title": "...", "severity": "high", "score": 25, "evidence": {...}} ]}
  ],
  "urls": [ {"raw": "...", "normalized": "...", "verdict": "malicious", "source": "urlhaus"} ],
  "attachments": [ {"filename": "x", "sha256": "...", "type": "pdf", "verdict": "clean"} ],
  "recommended_actions": ["quarantine", "train-user"],
  "labels": {"analyst": null, "fp": false, "confirmed_phish": false}
}
```
- `ParsedEmail`, `Finding`, `AnalyzerResult`, `Report`, `Verdict` are Python dataclasses
  with `to_dict()`; the JSON above is the wire/storage format.

## 7. Rule engine (detections-as-code)
- A **Rule** = `{id, description, severity, weight, match, action}`.
- `match` is a predicate over `ParsedEmail` + computed `Findings` (e.g.,
  `findings.any(analyzer=='header_auth' and severity=='critical')`).
- Shipped defaults in `rules/defaults/*.yaml` cover common patterns (CEO-fraud signals,
  credential-harvest URL + new domain, macro office doc + urgency, etc.).
- Users add YAML rules; engine evaluates post-scoring for auto-actions (quarantine, alert,
  tag). This is our Sublime-MQL-inspired differentiator, kept simple and auditable.
- Optional export to **Sigma** for SIEM portability.

## 8. Storage
- **Reports:** one JSON file per analysis under `PG_REPORT_DIR/` (human-readable, portable)
  **and** an append to a **SQLite** index (`reports` table) for fast queries/filtering.
- **Behavioral baseline:** SQLite tables
  - `relationships(sender_domain, recipient_user, count, first_seen, last_seen)`
  - `identity_profile(addr, usual_hours, request_types, style_features)`
  - `sender_history(addr, total, malicious_count)`
  Built from historical mail (batched, <10 ms queries per Cisco ETD guidance).
- **Analyst feedback:** `labels(report_id, fp, confirmed_phish, analyst, ts)` → improves
  thresholds and feeds the baseline (and, for MSSP, a local cross-tenant signal).

## 9. SIEM / SOAR export (`export/`)
- Emits a normalized **JSON event** for every analysis above `min_severity`.
- Transports: **syslog RFC 5424** (UDP/TCP/**TLS**), **CEF** (ArcSight), **LEEF** (QRadar),
  **OTLP** (OpenTelemetry), and **webhook** (JSON POST, e.g., Shuffle/Splunk).
- Severity mapped to syslog priority + CEF severity (0–10). Buffering + retry with backoff;
  graceful degradation if the collector is unreachable (events queued locally).
- Optional connectors: **TheHive/Cortex/MISP** (push case + observables), **Shuffle**
  (trigger playbook for auto-quarantine/ticketing).

## 10. Web API contract (`web/app.py`, Flask)
| Method | Path | Purpose |
|---|---|---|
| GET | `/login`, `/logout` | Auth (Flask-Login, env creds/secret) |
| GET | `/reports` | List/filter (verdict, date, domain) |
| GET | `/reports/<id>` | Full report + evidence |
| POST | `/reports/<id>/label` | Analyst FP / confirmed-phish label (feeds `feedback`) |
| GET | `/quarantine` | Messages flagged for quarantine + actions |
| POST | `/quarantine/<id>/release` \| `/purge` | Remediation actions |
| GET/POST | `/rules` | View default + manage custom rules |
| GET/POST | `/org-profile` | Protected domains, VIP names, brand list |
| GET | `/stats` | Detection-rate, verdict distribution, top senders |
| POST | `/api/v1/analyze` | Accept .eml/raw text → Report JSON (SARA/gsimransingh style) |
| POST | `/api/v1/recheck-url` | Time-of-click URL re-scan |

## 11. Configuration (`config.py` from env / `.env`)
- Mailbox (IMAP/M365/Gmail), optional API keys (VT, GSB, ClamAV, sandbox), web (host/port/
  auth/secret), `report_dir`, scoring thresholds, `trusted_domains`.
- Secrets never in code; `.env` is git-ignored. See `.env.example`.

## 12. Cross-cutting
- **Logging:** structured stderr logger (`logging_setup.py`), levels via `PG_LOG_LEVEL`.
- **Security:** no `eval` of rules (safe YAML predicate DSL), secrets via env, session
  signing, auth on web + API.
- **Performance:** analyzers parallelized; TI cache with TTL; DNS timeouts; behavioral
  queries <10 ms; batch baseline updates.
- **Testing:** `pytest` with EML fixtures; offline unit tests; `evaluation/` harness on
  public datasets with **cross-dataset** precision/recall/FPR reporting.

## 13. Technology stack
- Python 3.10+, stdlib `email`, `dnspython`, `requests`, `python-dotenv`.
- Optional: `dkimpy`, `checkdmarc`/`pyspf` (auth), `flask`+`flask-login` (web),
  `pyclamd` (AV), `jbxapi` (Joe Sandbox), `scikit-learn` (optional ML booster).
- Packaging: `pyproject.toml`, `phishguard` console script. Deploy: Dockerfile +
  docker-compose + nginx. CI: GitHub Actions (ruff/mypy/pytest).

## 14. Roadmap ↔ research mapping
- **Day 1:** scaffold + `config`/`models`/`logging` + `mail.parser`/`fetcher` + `header_auth`
  /`header_analysis`/`domain_reputation`/`url_scanner` (TOC recheck)/`content_analyzer`/
  `attachment_analyzer`/`scoring` + `org_profile`/`org_context` + offline tests.
  *(Research: Sublime, Rspamd, ThePhish, SARA, gsimransingh, dnstwist, SpamAssassin.)*
- **Day 2:** `behavioral.py` (baseline store) + `intel` feeds + `sandbox.py` + `report.store`
  + JSON/HTML renderer + `rules` engine + `feedback.py` + CLI (incl. `recheck-url`,
  `baseline build`). *(Research: Abnormal/Cisco ETD/Ironscales, URLhaus/OpenPhish/PhishTank,
  Any.Run/Joe/CAPE, Sigma/Shuffle.)*
- **Day 3:** `web.app` (auth, reports, quarantine, VIP/brand config, rules, stats, labels) +
  `remediation.py` (M365 Graph + Gmail) + `export/` (syslog/CEF/LEEF/OTLP/webhook) +
  Docker/compose/nginx + CI + README + `evaluation/` harness. *(Research: TheHive/Cortex/
  MISP, DNS Spy/CodeGraph SIEM formats, M365 Graph remediation, datasets §7.)*
```
