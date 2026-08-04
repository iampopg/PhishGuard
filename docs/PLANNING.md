# PhishGuard — Engineering Plan (3-Day Planning Phase)

Status: **Planning**. No production code yet. This document consolidates research on
reference email-security tools, the detection techniques they use, the recommended tech
stack, and the architecture we will build. It is the single source of truth for the
implementation phase that follows.

## 0. Honest competitiveness assessment (updated after Round-2 research)

**Does this plan beat 99% of email-security tools out there?** Honest answer:

- It will **decisively beat the long tail** — naive keyword scripts, basic SEGs with weak
  rules, and most small OSS tools — on signal coverage, transparency, and tunability.
- It will be **competitive with mid-tier commercial SEGs** once the Round-2 differentiators
  (behavioral BEC, org-context impersonation, time-of-click, sandbox hook, post-delivery
  remediation) are in.
- It will **not, by itself, out-detect Abnormal Security / Microsoft Defender / Proofpoint /
  Mimecast** at the very top, because those vendors have (a) a **global cross-tenant
  network effect** (billions of messages → trained models) and (b) **deployed-tenant
  behavioral foundation models** (e.g., Abnormal's Attune). That is a data/scale problem,
  not a code problem, and cannot be closed by a single self-hosted instance.

**Positioning that is both honest and compelling:** PhishGuard is the
**best-in-class open, self-hosted, auditable email detection engine** — ideal for
privacy-sensitive / air-gapped orgs, MSSPs who deploy it across many tenants (building
their *own* network effect), and teams that want transparent, tunable detection instead of
a black box. We close most of the technical signal gap with the leaders; the remaining gap
is deployment scale, which we address via community TI feeds + per-org behavioral baselines
+ an optional federated-feedback design (see §12).

See §12 for the Round-2 research that drove these conclusions and the added modules.

## 1. Product vision & scope (agreed)

- **Form factor:** CLI tool (for automation/forensics) **+** a web dashboard (for analysts,
  reports, quarantine, alerting).
- **External APIs:** Self-contained first. Works fully offline using open standards
  (SPF/DKIM/DMARC, heuristic scoring). VirusTotal and Google Safe Browsing are **optional**
  and degrade gracefully when no key is present.
- **Priority:** Detection engine quality first, then packaging/UI.

Outcome: an industrial, commercial-grade, audit-able email phishing detection and analysis
engine that an organization can run on its own infrastructure, tune, and integrate with
SIEM/SOAR.

---

## 2. Research findings (reference tools)

### 2.1 Sublime Platform (sublime-security/sublime-platform)
- Free, open platform for detecting BEC, malware, credential phishing.
- Core idea: **detections-as-code** via **MQL (Message Query Language)** — a DSL for
  describing email behavior; email-provider-agnostic; rules are shareable.
- Ships as Docker Compose; detection rules live in a separate repo
  (`sublime-security/sublime-rules`) with community feeds (DelivrTo, vector-sec, etc.).
- Supports automations, insights, YARA, DLP-discovery rules.
- **Lesson:** A user-extensible rule engine + a default ruleset + a community feed model is
  what makes a detection product usable and trustworthy. We will adopt the
  "detections-as-code" concept (our own simpler rule format).

### 2.2 Rspamd
- Multi-layer engine: reputation → sender authentication (SPF/DKIM/DMARC/ARC) → content
  filtering (regex/maps/selectors over headers, MIME, URLs, body) → malware (ClamAV) → ML.
- 100+ enterprise signals, fully auditable scoring, Lua scripting for custom rules.
- ClickHouse/Elasticsearch for telemetry; built-in web console.
- **Lesson:** Defense-in-depth layering and per-signal transparency (show *why* a message
  scored what it did) is the gold standard. We mirror this with a weighted, explainable
  scoring engine.

### 2.3 SARA Open Phishing Analyzer (sirp.io)
- Parses SPF/DKIM/DMARC + Received chain; extracts URLs/attachments; scores attachments via
  oletools; enriches URLs against ~8 TI sources; REST `POST /api/v1/phishing-analyze`.
- **Privacy stance:** body text is processed in-memory only and never sent to upstream APIs;
  only headers/URLs/sender IPs are queried.
- **Lesson:** Clear privacy boundary (body stays local; only domains/URLs/hashes leave). We
  adopt this boundary.

### 2.4 PhishingScanner / debjit604 phishing-detector (OSS examples)
- Flask + SQLite + risk score 0–100; ML via scikit-learn (optional TensorFlow); Selenium for
  visual brand-similarity; CLI + web + REST + batch.
- debjit604 reports a 7-model ensemble, 100+ engineered features, ~98.5% accuracy.
- **Lesson:** ML is valuable but should be an *optional layer* on top of transparent rules,
  not a black box. We keep a rules-first core and an optional, explainable ML booster.

### 2.5 Industry framing (Acronis, Ironscales, Clint McGuire)
- Phishing/BEC is the #1 initial-access vector (Verizon DBIR: ~90%+ of breaches start with
  phishing); FBI IC3 puts BEC losses in the billions.
- Effective controls: SPF/DKIM/DMARC enforcement, URL rewriting + time-of-click analysis,
  sandboxing, continuous threat intel (Forrester: -40% successful phishing with active TI).
- **Lesson:** Our engine must weight authentication failures and brand-impersonation URLs
  heavily, and we should integrate live TI feeds.

### 2.6 The provided Grok conversation
- **Could not be fetched** (the URL returned no readable content). Recommend the user paste
  the key points/design ideas here, or we proceed with the other references. Flagged as an
  open item in §9.

---

## 3. Detection signals & techniques (the engine)

Ordered by signal strength / phishing-predictiveness.

### 3.1 Sender authentication (highest value)
- **SPF** validate envelope sender IP against domain TXT `v=spf1` (use `pyspf`/`checkdmarc`
  when available; otherwise parse the `Authentication-Results` / `Received-SPF` header that
  Gmail/Outlook/M365 already attach).
- **DKIM** verify signature with `dkimpy` (optional dep); fall back to `DKIM-Signature` /
  `Authentication-Results` header parsing.
- **DMARC** fetch `_dmarc.<domain>` TXT, parse policy (`none`/`quarantine`/`reject`), compute
  **alignment** (relaxed = org-domain match; strict = exact). A fail on an aligned check is a
  strong phishing signal.
- **Envelope vs Header mismatch:** `Return-Path` domain vs `From` domain; `MAIL FROM` vs `From`.

### 3.2 Header analysis (anti-spoofing)
- `From` / `Reply-To` / `Return-Path` domain consistency.
- Display-name impersonation: e.g. display name "PayPal Security" but a mismatched address.
- `Message-ID` domain vs `From` domain mismatch (often indicates forged origin).
- Received-chain anomalies: `X-Originating-IP`, unexpected relays, timestamp gaps.
- Missing or malformed essential headers.

### 3.3 Domain reputation & typosquatting
- **Newly registered domain** (age < 30 days) — WHOIS/`whois`/Registrar APIs (best-effort,
  cached; degrade if unavailable).
- **Lookalike / homoglyph / typosquatting** vs a brand list (e.g., `paypa1.com`,
  `micros0ft-support.com`, punycode `xn--...`). Edit-distance + homoglyph map.
- **Free / disposable domains** in a business/finance context.
- **No DMARC / no SPF** published for a sender claiming to be a brand.

### 3.4 URL scanning
- Robust URL extraction (handle defanging, HTML, base64 blobs, markdown).
- **Expand shorteners** (bit.ly, t.co, tinyurl, …) via HEAD redirects.
- **Display-vs-href mismatch** (the visible text says one domain, the link another).
- **IP-literal URLs**, **punycode/homoglyph** hosts, suspicious TLDs (`.tk`, `.top`, `.xyz`
  in bulk context), long redirect chains.
- **Brand impersonation in host** (host contains a brand token but is not the brand domain).
- **Reputation** (optional, cached): URLhaus, OpenPhish, PhishTank, Google Safe Browsing,
  VirusTotal, phishunt.io. Refresh feeds on an interval; match by exact + normalized host.

### 3.5 Content analysis (heuristics + lightweight NLP)
- Urgency / scarcity / authority lexicon ("urgent", "immediately", "suspend", "CEO",
  "invoice", "verify", "gift card").
- Credential / OTP / MFA theft cues ("login", "password", "one-time code", "confirm account").
- Brand-impersonation keyword sets (banking, SaaS, shipping, gov).
- Suspicious structures: HTML forms posting to external domains, base64/obfuscated blobs,
  missing personalized greeting, generic "Dear customer".
- Basic spelling/grammar anomaly scoring (optional, lightweight; no heavy NLP dep required).

### 3.6 Attachment analysis
- Compute SHA-256/MD5; look up VirusTotal (optional) by hash.
- Type detection via magic/`python-magic` (not just extension); flag executable/macro office
  docs (`.docm`, `.xlsm`), HTML attachments (fake login pages), double extensions
  (`invoice.pdf.exe`), encrypted zips (entropy heuristic).
- ClamAV socket scan (optional).
- Office macro / OLE analysis (optional `oletools`).

### 3.7 Optional ML booster (explainable)
- Engineer ~100 features from the above signals; train a scikit-learn classifier
  (e.g., gradient boosting) as an *optional* ensemble member.
- Ship a training pipeline + (optionally) a small pretrained model; expose feature
  importances for auditability. Never a hard dependency.

---

## 4. Recommended tech stack & libraries

| Concern | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Stdlib `email` parser is robust; ecosystem is richest for security. |
| Email parsing | stdlib `email` | No dep; handles EML natively. |
| DKIM verify | `dkimpy` (optional) | Reference Python DKIM lib. |
| Auth/DMARC validation | `checkdmarc` / `pyspf` (optional) | Validates SPF/DMARC; degrades to header parsing. |
| DNS | `dnspython` | TXT lookups for SPF/DKIM/DMARC. |
| Threat intel | `requests` + local feed cache | URLhaus/OpenPhish/PhishTank/GSB/VT; async refresh. |
| Web | Flask + Flask-Login + Jinja2 + Bootstrap | Simpler than FastAPI for a dashboard; auth built-in. |
| Storage | JSON report files + SQLite index | Human-readable reports + fast queries. |
| Config | env / `.env` (`python-dotenv`) | No secrets in code (fixes current `cred.py` smell). |
| Quality | ruff, black, mypy, pytest | Commercial-grade hygiene. |
| Packaging | `pyproject.toml` + console_scripts | `phishguard` CLI entry point. |
| Deploy | Dockerfile + docker-compose + nginx | Matches Sublime's model; easy on-prem. |
| CI | GitHub Actions | Lint + type + test on every PR. |

**Non-goals / deferrals:** live sandbox detonation (out of scope for v1; we flag risky
attachments instead), full MTA integration (we ingest via IMAP / EML / API, not SMTP).

---

## 5. Architecture (modules)

```
phishguard/
  cli.py                # argparse: scan-mailbox, scan-eml, scan-url, scan-text, serve, rules
  config.py             # env/.env -> Config dataclass
  logging_setup.py
  models.py             # Finding, AnalyzerResult, ParsedEmail, Attachment, Report, Verdict
  exceptions.py
  engines/
    base.py             # Analyzer protocol + helper scoring
    header_auth.py      # SPF/DKIM/DMARC + alignment + envelope/header mismatch
    header_analysis.py  # From/Reply-To/Return-Path, Message-ID, display-name impersonation
    domain_reputation.py# age, typosquat/homoglyph, free-domain, no-DMARC
    url_scanner.py      # extract, expand, mismatch, reputation (cached feeds), time-of-click recheck
    content_analyzer.py # lexicon + lightweight NLP + structure
    attachment_analyzer.py # hashes, type, VT, ClamAV, macro/entropy
    behavioral.py       # BEC: per-identity + relationship-graph baseline (local, single-org)
    org_context.py      # VIP/employee + protected-domain lookalike + brand impersonation
    scoring.py          # aggregate findings -> risk 0-100 + verdict + recommended actions
  sandbox.py            # optional detonation hook (provider interface; ClamAV default + flag)
  remediation.py        # optional post-delivery actions: M365 Graph + Gmail API
  feedback.py           # analyst labels (FP / confirmed-phish) -> baseline + threshold tuning
  org_profile.py        # loads protected domains, VIP/employee names, brand list, trusted senders
  rules/
    engine.py           # detections-as-code runner (loads YAML/py rules)
    defaults/           # shipped default ruleset
  mail/
    parser.py           # raw bytes/.eml -> ParsedEmail
    fetcher.py          # IMAP fetch (SSL, unseen/all, robust)
  intel/
    feeds.py            # URLhaus/OpenPhish/PhishTank/phishunt client + cache
    virustotal.py       # optional
    safebrowsing.py     # optional
  report/
    store.py            # JSON + SQLite index
    renderer.py         # JSON + HTML report
  web/
    app.py              # Flask dashboard (reports, quarantine, rules, auth)
    templates/...
tests/
docs/
```

**Detections-as-code:** a `Rule` = id, description, severity, weight, and a predicate over
the `ParsedEmail` + already-computed findings. Shipped defaults cover the common phishing
patterns; users can add their own YAML rules. This is our Sublime-MQL-inspired differentiator
and keeps the engine transparent and tunable.

---

## 6. Data model & scoring

- `Finding`: analyzer, title, detail, severity (info/low/medium/high/critical), score
  (positive = risky), evidence dict.
- `AnalyzerResult`: name, score, findings, metadata.
- `Report`: email_id, timestamp, verdict, risk_score (0–100), summary, per-analyzer results,
  all findings, recommended actions, parsed-email metadata.
- `Verdict` thresholds (configurable): `safe` ≤ suspicious(30) ≤ phishing(60) ≤ malicious(85).
- Scoring is **additive & capped**, each analyzer contributes bounded points so no single
  weak signal dominates; the report always explains *why* (auditable, Rspamd-style).

---

## 7. CLI & web dashboard

CLI:
- `phishguard scan-eml <file.eml>` — forensic analysis of a single message.
- `phishguard scan-mailbox` — connect IMAP, scan new mail, write reports, optional quarantine.
- `phishguard scan-url <url>` / `scan-text "<text>"` — quick checks.
- `phishguard serve` — start the web dashboard.
- `phishguard rules list|test` — manage detections-as-code.

Web dashboard:
- Login (Flask-Login, env-configured creds/secret).
- List reports (filter by verdict/date), drill into a report with full evidence.
- Quarantine view + mark false-positive / confirmed-phish.
- Rules editor (view default rules; manage custom rules).
- Stats cards (detection rate, verdict distribution, top senders).
- Export report as JSON / Markdown.

---

## 8. Privacy & operational boundaries

- Email bodies are processed **in-memory only**; never sent to third parties.
- Only domains, URLs, sender IPs, and file hashes are sent to optional TI providers, and only
  when the user enables the relevant integration (opt-in).
- All network calls have timeouts, retries with backoff, and cached negative results.
- Secrets come from env/`.env`, never committed. `.env` is git-ignored.

---

## 9. Open questions / decisions needed

1. **Grok conversation** — the link was unreadable. Please paste its key design ideas so we
   can fold them in. (Round-2 research already closed the biggest gaps; not blocking.)
2. **Storage depth** — SQLite index + behavioral baseline + feedback labels now; do we want
   Elasticsearch/ClickHouse later for large-scale telemetry? (Defer; design store interface
   to allow swapping.)
3. **ML booster** — the Round-2 research shows **behavioral baselines + relationship graph**
   matter more than a classifier for BEC. Plan: ship heuristic + behavioral baseline first;
   optional scikit-learn ensemble as phase 2, trained on engineered features. (Decision:
   behavioral > classifier for v1.)
4. **Deployment target** — single on-prem host (Docker Compose) is the assumed v1 target;
   architecture supports MSSP multi-tenant (builds local network effect via `feedback.py`).
5. **Brand / VIP list source** — bundle a curated brand-impersonation list + ship an
   org-profile template (protected domains, VIP names, trusted senders); allow customer
   upload/editing via the web UI.
6. **Remediation scope (v1)** — post-delivery actions (M365 Graph / Gmail) are optional and
   config-gated; default off. Confirm we should ship the connectors in v1 (recommended: yes,
   behind config) or defer.
7. **Honest positioning** — confirm we market PhishGuard as the best open/self-hosted engine
   (transparent, auditable, air-gap friendly) rather than claiming to beat Abnormal/Defender
   on global accuracy. (Recommended: yes.)

---

## 10. Implementation roadmap (post-planning)

Detailed per-day plan (including the Round-2 behavioral / org-context / sandbox /
remediation modules) is in **Addendum D**. Summary:

- **Day 1 — Foundation & core engine + org context:** scaffold, config, models, mail
  parser/fetcher, header_auth, header_analysis, domain_reputation, url_scanner (incl.
  time-of-click recheck), content_analyzer, attachment_analyzer, scoring, and
  `org_profile` + `org_context` (VIP / protected-domain / brand impersonation). Offline
  unit tests with EML fixtures.
- **Day 2 — Behavioral + integrations + reporting + feedback:** `behavioral.py` baseline
  store (SQLite), intel feeds + optional VT/GSB/ClamAV, `sandbox.py` hook, report store,
  JSON/HTML renderer, detections-as-code engine + default rules, `feedback.py`, CLI (incl.
  `recheck-url`, `baseline build`).
- **Day 3 — Web dashboard, remediation & hardening:** Flask app (auth, reports, quarantine,
  VIP/brand config, rules, stats, feedback labels), optional `remediation.py` (M365 Graph +
  Gmail), Docker + compose + nginx, CI (ruff/mypy/pytest), README + operator docs, smoke test.

---

## 11. References

- Sublime Platform: https://github.com/sublime-security/sublime-platform
- Sublime Rules (detections-as-code): https://github.com/sublime-security/sublime-rules
- Rspamd: https://www.rspamd.com/
- SARA Open Phishing Analyzer: https://sara-open.sirp.io/free-tools/phishing-analyzer
- PhishingScanner: https://github.com/Lintshiwe/PhishingScanner
- debjit604 phishing-detector: https://github.com/debjit604/phishing-detector
- Email header analysis skill (SPF/DKIM/DMARC): https://github.com/jyahclaude/security-skills
- checkdmarc (PyPI): https://pypi.org/project/checkdmarc/
- dkimpy (PyPI): https://pypi.org/project/dkimpy/
- OpenPhish feed: https://openphish.com/ ; community feed:
  https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- PhishTank: https://phishtank.org/
- URLhaus (abuse.ch): https://urlhaus.abuse.ch/
- phishunt.io feed: https://phishunt.io/feed/
- Google Safe Browsing / Web Risk API
- VirusTotal API: https://docs.virustotal.com/
- Bolster comparison of phishing feeds:
  https://bolster.ai/blog/phishing-threat-intelligence
- CaptainDNS TI databases explainer:
  https://www.captaindns.com/en/blog/threat-intelligence-databases-explained
- Acronis email threat prevention guide (2026):
  https://www.acronis.com/en/blog/posts/what-is-email-threat-prevention-a-complete-guide-in-2026/

---

## Addendum — Research Round 2: matching the top 1% (Tier-1 differentiators)

The first draft covered the *detectable* signal classes (auth, content, URL, attachment,
rules). Round-2 research into the actual leaders — **Abnormal Security, Microsoft Defender
for Office 365, Proofpoint, Mimecast, Material, Sublime, Ironscales** — shows the
decisive differentiators are NOT more keyword lists; they are **behavioral, contextual, and
operational** capabilities. This addendum adds them.

### A. What the leaders actually do (research findings)

1. **Behavioral / relationship-graph BEC detection (the #1 differentiator).**
   - Abnormal builds a **behavioral baseline per identity** (sender, vendor, app) across
     ~45,000 signals and a **communication graph** (who talks to whom, about what, when).
     BEC/vendor-impersonation with *no payload* is caught by deviation from that baseline,
     not by content scanning. Training window: weeks–90 days. (Sources: abnormal.ai,
     CaptainDNS Abnormal guide, SecurityScientist Q&A, Gartner MQ note.)
   - Microsoft "Mailbox Intelligence" = ML on the org's email graph; flags anomalous
     sender behavior. Sublime surfaces message lineage + sender-profile shifts + language
     outliers. Material uses org structure (who is the CEO, who is finance).
   - **Implication:** we must add a `behavioral.py` analyzer that maintains a **local,
     single-org baseline** (persisted in the SQLite store) of per-sender relationships,
     request types, timing, and simple style features, and flags deviations. We are honest
     that this is single-org (no cross-tenant network effect) — see verdict below.

2. **Org-context impersonation (VIP / employee / domain lookalike).**
   - Proofpoint/Sophos/Material/Sublime detect (a) **user impersonation** — display name
     matches an internal VIP ("PayPal Security" / "Your CEO") even with a random freemail
     address; (b) **domain impersonation** — lookalike of *your* domain
     (`yourc0mpany.com`); (c) **brand impersonation** — external brands (Microsoft, Dropbox).
   - Requires an **org profile**: protected domains, VIP/employee display names, brand list,
     trusted senders. Display-name matching works *without* an email-address match.
   - **Implication:** add `org_context.py` + `org_profile.py`; feed `header_analysis.py`
     (display-name impersonation) and `domain_reputation.py` (your-domain lookalike).

3. **Time-of-click URL rewriting + sandbox detonation.**
   - Defender Safe Links **rewrites URLs and re-scans at click time**, catching links that
     were clean at delivery but weaponized later ("delayed weaponization"). Safe Attachments
     **detonates files in a sandbox** before delivery (macros, PDF exploits, archives).
   - **Implication:** `url_scanner.py` gains a **time-of-click recheck** mode (re-query
     reputation at analysis time; `phishguard recheck-url`) and awareness of delayed
     weaponization. `sandbox.py` is a **provider interface**: default = ClamAV + risk
     flagging; optional = plug a detonation service (e.g., a sandbox API). We do NOT build
     a full sandbox (out of scope/liability); we integrate one.

4. **Post-delivery remediation (close the loop).**
   - Defender/CanIPhish/Material act *after* delivery via **Microsoft Graph
     `analyzedEmails/remediate`** (move to junk/quarantine/soft-delete/hard-delete) and the
     **Gmail investigation tool**. This is how they stop phish that slipped through.
   - **Implication:** add `remediation.py` (optional, config-gated) with M365 Graph +
     Gmail connectors. Without it we only *analyze*; with it we *respond*.

5. **Network effect / federated intelligence.**
   - Abnormal's ThreatBase aggregates signals across 2,400+ tenants; Proofpoint correlates
     supplier behavior. This is the one gap we **cannot** close from one deployment.
   - **Implication:** (a) aggressively use **community feeds** (URLhaus, OpenPhish,
     PhishTank, phishunt.io, AbuseIPDB) as our shared signal; (b) design `feedback.py` so an
     MSSP deploying across many tenants can build a local cross-tenant signal; (c) be honest
     in positioning (§0).

### B. Honest verdict (restated)

With these additions PhishGuard becomes a **credible top-tier open/self-hosted engine** that
covers the *same signal classes* as the commercial leaders. It will:
- Beat the long tail (scripts, weak SEGs) decisively.
- Be competitive with mid-tier SEGs.
- **Not** out-detect Abnormal/Defender's *global-network behavioral models* from a single
  install — that is a scale/data problem. We monetize/position around transparency,
  self-hosting, air-gap suitability, and MSSP-multi-tenant deployment.

### C. Added/changed modules (architecture)

- `engines/behavioral.py` — local per-identity + relationship-graph baseline; deviation scoring.
- `engines/org_context.py` — VIP/employee/protected-domain/brand impersonation.
- `org_profile.py` — config-driven org profile (domains, VIP names, brand list, trusted senders).
- `sandbox.py` — optional detonation provider interface (ClamAV default; flag risky).
- `remediation.py` — optional M365 Graph + Gmail post-delivery actions.
- `feedback.py` — analyst labels (FP / confirmed-phish) improve baseline + thresholds.
- `url_scanner.py` — time-of-click recheck mode.
- SQLite store extended to hold behavioral baselines + analyst labels.

### D. Extended roadmap (folds Round-2 into the 3 days)

- **Day 1 — Foundation & core engine:** scaffold, config, models, mail parser/fetcher,
  header_auth, header_analysis, domain_reputation, url_scanner (incl. time-of-click
  recheck), content_analyzer, attachment_analyzer, scoring, `org_profile` + `org_context`
  (VIP/domain/brand impersonation). Unit tests with EML fixtures (offline).
- **Day 2 — Behavioral + integrations + reporting:** `behavioral.py` baseline store
  (SQLite), intel feeds + optional VT/GSB/ClamAV, `sandbox.py` hook, report store
  (JSON+SQLite), JSON/HTML renderer, detections-as-code engine + default rules, `feedback.py`,
  CLI wiring (incl. `recheck-url`, `baseline build`).
- **Day 3 — Web dashboard, remediation & hardening:** Flask app (auth, reports, quarantine,
  VIP/brand config, rules, stats, feedback labels), optional `remediation.py` (M365 Graph +
  Gmail), Docker + compose + nginx, CI (ruff/mypy/pytest), README + operator docs,
  end-to-end smoke test.

### E. Round-2 references

- Abnormal Security BEC / behavioral AI: https://abnormal.ai/solutions/prevent-bec
- Anomaly-based detection shift: https://abnormal.ai/learning/anomaly-based-detection
- CaptainDNS Abnormal guide: https://www.captaindns.com/en/blog/abnormal-secure-email-gateway
- Microsoft Safe Links (time-of-click): https://learn.microsoft.com/en-us/defender-office-365/safe-links-about
- Microsoft Safe Attachments (sandbox): https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-about
- M365 post-delivery remediation (Graph): https://learn.microsoft.com/en-us/defender-office-365/remediate-malicious-email-delivered-office-365
- Graph analyzedEmail remediate API: https://learn.microsoft.com/en-us/graph/api/security-analyzedemail-remediate
- Proofpoint Impersonation Protection: https://www.proofpoint.com/us/products/impersonation-protection
- Sublime impersonation protection: https://sublime.security/articles/email-impersonation-protection/
- Material VIP impersonation (org context): https://material.security/use-cases/prevent-vip-impersonation-attacks
- Sophos VIP impersonation: https://docs.sophos.com/central/customer/help/en-us/ManageYourProducts/EmailSecurity/EmailPolicies/EmailSecurityPolicy/EmailImpersProtection/
- Sendmarc CEO impersonation / lookalike defense: https://sendmarc.com/dmarc/ceo-impersonation/
- CanIPhish M365 quarantine via Graph: https://help.caniphish.com/hc/en-us/articles/13481309977103-Microsoft-365-Email-Quarantine

```
