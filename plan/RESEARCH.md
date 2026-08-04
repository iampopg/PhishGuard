# PhishGuard — Open-Source Research Catalog

> Status: **Planning phase (≈80% research / 20% plan).** This file documents every
> open-source project and reference we studied while designing PhishGuard, what techniques
> each uses, and what we adopt. Sources are cited inline. Keep appending as research
> continues. The consolidated plan lives in `../docs/PLANNING.md`; the system design in
> `ARCHITECTURE.md`; the planning self-assessment in `ASSESSMENT.md`.

---

## 1. Email phishing detection / analysis engines

### 1.1 Sublime Platform — `sublime-security/sublime-platform`
- URL: https://github.com/sublime-security/sublime-platform (MIT, ~267★)
- Rules: https://github.com/sublime-security/sublime-rules (~367★, YAML detection rules + community feeds)
- **What it is:** free, open platform for detecting BEC, malware, credential phishing.
- **Key idea — detections-as-code via MQL** (Message Query Language), a DSL for email
  behavior, provider-agnostic. Ships as Docker Compose. Rules live in a separate repo and
  are shareable (community feeds: DelivrTo, vector-sec, amitchell516).
- **What we adopt:** a user-extensible *rule engine* (our own simpler format) + a shipped
  default ruleset + an optional community-feed model. See `docs/PLANNING.md` §2.1 and §5.

### 1.2 Rspamd — https://www.rspamd.com/
- Open source (Apache-2.0), C engine, 100k+ installs.
- **Layered model:** reputation (RBL/URIBL) → sender auth (SPF/DKIM/DMARC/ARC) → content
  (regex/maps/selectors over headers, MIME, URLs, body) → malware (ClamAV) → ML. **100+
  signals**, fully auditable scoring, **Lua scripting** for custom rules, ClickHouse/
  Elasticsearch telemetry, built-in web console.
- **What we adopt:** defense-in-depth layering + per-signal transparency (show *why* a
  message scored what it did) + a weighted, explainable scoring engine. Lua → our
  detections-as-code. See `docs/PLANNING.md` §2.2.

### 1.3 ThePhish — `emalderson/ThePhish`
- URL: https://github.com/emalderson/ThePhish (AGPL-3.0, ~1.3k★)
- Academic paper: https://ceur-ws.org/Vol-3260/paper6.pdf
- **What it is:** automated phishing email analysis web app (Python/Flask) built on
  **TheHive + Cortex + MISP**. Extracts observables (IPs, emails, domains, URLs, attachments)
  from header+body, runs analyzers, computes a verdict, exports case to MISP, closes case.
- **Key lessons:** (a) observable extraction → analyzer fan-out → verdict is the canonical
  pipeline; (b) integrate with SOC stack (TheHive/Cortex/MISP) rather than reinvent it;
  (c) analyst can intervene when verdict is non-final. This validates our modular analyzer
  design + SIEM/SOAR export (§4.5).
- **What we adopt:** analyzer-fan-out architecture; optional Cortex/MISP/TheHive connectors;
  CEF/SIEM output (the paper's sibling tool outputs to MISP).

### 1.4 SARA Open Phishing Analyzer — https://sara-open.sirp.io/free-tools/phishing-analyzer
- **What it is:** parses SPF/DKIM/DMARC + Received chain, extracts URLs/attachments, scores
  attachments via oletools, enriches URLs vs ~8 TI sources; REST `POST /api/v1/phishing-analyze`.
- **Privacy stance (adopt):** email body processed in-memory only; never sent to upstream
  APIs — only headers/URLs/sender IPs are queried. We enshrine this boundary. See `docs/PLANNING.md` §8.

### 1.5 PhishingScanner — `Lintshiwe/PhishingScanner`
- URL: https://github.com/Lintshiwe/PhishingScanner (MIT)
- Flask + SQLite + risk score 0–100; ML (scikit-learn/TensorFlow optional) + Selenium visual
  brand-similarity; CLI + web + REST + batch.
- **Adopt:** risk-score 0–100 + CLI/web/REST surfaces; optional visual similarity is a nice
  future differentiator (defer).

### 1.6 debjit604/phishing-detector & similar ML demos
- `debjit604/phishing-detector`: 7-layer ensemble, 100+ features, claims ~98.5% accuracy.
- **Adopt (caveat):** ML is an *optional booster* on top of transparent rules; cross-dataset
  generalization is weak (see Datasets §7), so we never hard-depend on it.

### 1.7 gsimransingh/PhishGuard (independent project — validates our design)
- URL: https://github.com/gsimransingh/PhishGuard
- A Python CLI for Tier-1 SOC triage: parses .eml (headers, Reply-To, X-Originating-IP,
  Message-ID), validates SPF/DKIM/DMARC (headers + live DNS), extracts IOCs, checks AbuseIPDB
  + VirusTotal, **weighted risk scoring → LOW/MEDIUM/HIGH**, outputs **JSON / text / HTML /
  CEF** for SIEM, and runs **fully offline without API keys**.
- **Why it matters:** an independent OSS tool converged on almost exactly our planned design
  (offline-first, auth validation, weighted scoring, CEF output). Confirms the approach is
  sound and community-aligned.

### 1.8 bec-risk-detector / BEC engines (behavioral)
- `sa-hana285/bec-risk-detector`: NLP urgency/financial-intent + role-behavior mismatch +
  **Isolation Forest** anomaly detection + rule risk. FastAPI + web UI.
- `sjakkula0204-bit/bec-detection-engine`: BEC detection via **Splunk**, focuses on behavior
  sequences preceding wire fraud (not generic indicators).
- arXiv 2308.10776 "CAPE": modular system combining independent ML models across text, images,
  metadata, and **communication context**.
- **Adopt:** our `engines/behavioral.py` uses a local relationship-graph baseline + unsupervised
  anomaly detection (Isolation Forest-style) for novel BEC; supervised features for known types.

### 1.9 SpamAssassin — https://spamassassin.apache.org/
- Mature statistical spam filter: many tests over header + body, advanced statistical
  classification. Reference for **transparent, weighted, rule-based content scoring**.

---

## 2. Typosquatting / brand / domain-impersonation engines

### 2.1 dnstwist — `elceef/dnstwist`
- URL: https://github.com/elceef/dnstwist
- **Domain name permutation engine** for detecting homograph phishing, typosquatting, and
  brand impersonation (char swaps, omissions, bitsquatting, homoglyphs, double extensions).
- **Adopt:** core of our lookalike detection for both *your-domain* and *brand* lists
  (`engines/domain_reputation.py`, `org_context.py`).

### 2.2 opensquat — `securitybits/opensquat`
- Detects lookalike domains of your trademarks/brands; pairs with dnstwist.
- **Adopt:** periodic lookalike-domain monitoring for the org profile (future module).

### 2.3 phishing_catcher — `x0rz/phishing_catcher`
- URL: https://github.com/x0rz/phishing_catcher
- Scans **Certificate Transparency (CT) logs** for domains containing suspicious keywords.
  CT logs update almost instantly (vs daily NRD lists) and include subdomains.
- **Adopt:** complement to WHOIS age checks — flag newly-issued certs for lookalike/suspicious
  domains (real-time-ish, free). Integrates with our domain-reputation analyzer.

### 2.4 Proofpoint / Valimail / Sendmarc (commercial, for requirements)
- Proofpoint Impersonation Protection: stops domain spoofing, lookalike takedown, supplier
  account defense via behavioral AI + TI. Validates DMARC `p=reject`.
- Sendmarc: DMARC `p=reject` + lookalike-domain defense + breach detection for exec creds.
- **Adopt (requirements):** org profile needs protected domains + VIP/employee names + brand
  list; enforced DMARC guidance; lookalike monitoring.

---

## 3. Sandbox / detonation (attachment & URL)

- **Any.Run** (https://app.any.run/) — interactive malware sandbox, real-time behavior replay.
- **Hybrid Analysis** (VXunderground) — free community sandbox, automated analysis.
- **Joe Sandbox** (https://www.joesecurity.org/) — deep malware + phishing analysis; MIT
  Python API wrapper `joesecurity/jbxapi` (https://github.com/joesecurity/jbxapi).
- **CAPE** (https://github.com/kevoreilly/CAPE) — open-source malware sandbox (Cuckoo fork),
  config/payload extraction. **Self-hostable** → good default for on-prem detonation.
- **Dangerzone** (https://github.com/freedomofpress/dangerzone) — open-source, converts
  untrusted docs to safe PDF (disarms active content). Good for safe-rendering attachments.
- **urlscan.io** — passive URL page capture (DOM, screenshot, redirect chain, network calls)
  without direct browser contact; essential for credential-harvest page analysis.
- **Adopt:** `sandbox.py` is a **provider interface**. Default = ClamAV + risk flagging
  (no full sandbox). Optional providers: Joe Sandbox API (jbxapi), Any.Run/Hybrid via API,
  or self-hosted CAPE. URL analysis uses urlscan.io (optional) + redirect-chain tracing.
  We do **not** build a sandbox ourselves (liability/scope); we integrate one. See
  `docs/PLANNING.md` Addendum §A.4.

---

## 4. Threat-intel feeds (free / keyless where possible)

| Source | URL | Notes |
|---|---|---|
| URLhaus (abuse.ch) | https://urlhaus.abuse.ch/ | Malware URLs, free API, no key |
| OpenPhish | https://openphish.com/ | Community feed (12h), free txt; premium 5min |
| PhishTank (Cisco Talos) | https://phishtank.org/ | Free API key, community-voted |
| phishunt.io | https://phishunt.io/feed/ | Free TXT/JSON/CSV, enriched |
| AbuseIPDB | https://www.abuseipdb.com/ | IP reputation (key) |
| Google Safe Browsing / Web Risk | — | URL reputation (key; non-commercial limit) |
| VirusTotal | https://docs.virustotal.com/ | Multi-engine hash/URL (key, 4 req/min) |
| Spamhaus DBL/XBL | https://www.spamhaus.org/ | Domain/IP blocklists |
| ThreatFox / URLHaus-hosts | https://threatfox.abuse.ch/ | IOC feeds |
| TweetFeed / Phishing.Army | — | Community blocklists |

- **Adopt:** cache feeds locally (refresh interval), match by exact + normalized host;
  optional VT/GSB behind config. Body text never leaves the box (SARA stance). See
  `docs/PLANNING.md` §2.5, §3.4, Addendum §A.5.

---

## 5. SOC / SOAR / SIEM integration (required for enterprise buyers)

- **TheHive** (SIRP) + **Cortex** (analyzer/responder engine) + **MISP** (TI platform):
  the OSS SOC trinity ThePhish builds on. We add optional connectors.
- **Shuffle** (https://github.com/Shuffle/Shuffle) — general-purpose security automation
  (SOAR); orchestrates response playbooks. **Adopt:** emit webhook/JSON events PhishGuard
  can trigger Shuffle playbooks (auto-quarantine, ticket creation).
- **Sigma** (https://github.com/SigmaHQ/sigma) — generic SIEM signature format. Our
  detections-as-code can export to Sigma where useful for portability.
- **SIEM transport formats** (from DNS Spy, CodeGraph, pipelock research): **Syslog RFC 5424,
  CEF (ArcSight), LEEF (QRadar), OTLP (OpenTelemetry)**; transports UDP/TCP/TLS; severity
  mapping; buffering + retry. 
- **Adopt (`export/` module):** emit detection events as JSON + CEF (+ optional LEEF/OTLP)
  over syslog (TLS) and/or webhook. This is the enterprise integration surface. See
  `docs/PLANNING.md` Addendum + `ARCHITECTURE.md` §9.

---

## 6. Simulation / testing / gateway-validation (adjacent)

- **Gophish** (https://getgophish.com) — open phishing-simulation framework (awareness).
- **King Phisher**, **Evilginx2** (MFA-bypass), **SET** — red-team tooling.
- **CanIBeSpoofed**, **SPF-Bypass** (CanIPhish) — domain-spoofing / auth gap testing.
- **Phishious** (CanIPhish) — tests whether a Secure Email Gateway catches phishing.
- **Adopt:** we do not build simulation, but we (a) ship an **evaluation harness** on public
  datasets (§7) to measure detection quality, and (b) can be *tested* by Phishious-style
  corpora. Awareness/training is out of v1 scope but documented as future.

---

## 7. Datasets & benchmarks (for evaluation)

- **Phishing Email Dataset** (Kaggle, ~82.5k: Enron, Ling, CEAS, Nazario, Nigerian,
  SpamAssassin) — 42.9k spam / 39.6k ham.
- **Nazario Phishing Corpus** (~11k real phishing), **CEAS-08** (~39k), **SpamAssassin**.
- **IEEE DataPort multi-source** (Nazario, MeAJOR, Enron, etc.) with SPF/URL/structural features.
- **PhishFuzzer** (2026, ~23k, 3-class Phish/Spam/Valid, intent-annotated, open).
- **PhishNet** (UC Berkeley) — elder-targeted phishing, RAG + tiered verdicts, feedback loop.
- **Key research finding (MDPI Applsci 15 03396, 2025):** transformer models (BERT/RoBERTa)
  reach **~99% accuracy in-dataset**, but **cross-dataset generalization drops sharply**
  (external-set accuracy 50–85%). Therefore our evaluation MUST be **cross-dataset / held-out**
  and report precision/recall/FPR, not just in-sample accuracy.
- **Adopt:** ship an `evaluation/` harness that scores the engine on these datasets and reports
  precision/recall/FPR/AUC with cross-dataset splits. Thresholds tuned to keep false positives
  low (enterprise requirement).

---

## 8. Synthesis — what PhishGuard adopts (the 20% plan, grounded in the 80% research)

| Capability | Borrowed from | Module |
|---|---|---|
| Detections-as-code rule engine | Sublime (MQL), Rspamd (Lua) | `rules/` |
| Layered, transparent, weighted scoring | Rspamd, SpamAssassin | `scoring.py` |
| Observable extraction → analyzer fan-out → verdict | ThePhish, SARA | `mail/parser.py` + `engines/*` |
| Body-in-memory privacy boundary | SARA | `config`/`engines` |
| SPF/DKIM/DMARC + alignment | ThePhish, gsimransingh/PhishGuard, RFC 7208/6376/7489 | `engines/header_auth.py` |
| Typosquat / homoglyph / lookalike | dnstwist, opensquat, phishing_catcher (CT logs) | `domain_reputation.py`, `org_context.py` |
| Behavioral BEC (relationship graph) | Abnormal, Cisco ETD, Ironscales, bec-risk-detector | `engines/behavioral.py` |
| Sandbox hook (provider interface) | Any.Run, Joe Sandbox, CAPE, Dangerzone, urlscan | `sandbox.py` |
| TI feeds (cached) | URLhaus, OpenPhish, PhishTank, phishunt, AbuseIPDB, VT, GSB | `intel/` |
| SIEM/SOAR export | TheHive/Cortex/MISP, Shuffle, Sigma, syslog/CEF/LEEF/OTLP | `export/` |
| Risk score 0–100 + CLI/web/REST | PhishingScanner, gsimransingh/PhishGuard | `cli.py`, `web/` |
| Offline-first + optional APIs | gsimransingh/PhishGuard, SARA | `config` |
| Post-delivery remediation | M365 Graph, Gmail API | `remediation.py` |
| Evaluation harness (cross-dataset) | PhishFuzzer/PhishNet methodology, MDPI 2025 | `evaluation/` |

---

## 9. Open-source projects still worth a deeper look (backlog)
- `InQuest/awesome-yara`, `elastic/detection-rules`, `MITRE CAR` (detection rule formats)
- `matanolabs/matano` (OSS SIEM alternative), `airbnb/streamalert` (real-time detection)
- `MetaMask/eth-phishing-detect`, `phishing.army` (crypto/vertical blocklists)
- `hagezi/dns-blocklists` (high-quality DNS blocklists for reputation)
- Local ML: scikit-learn gradient boosting on the 58-feature BEC set (ResearchGate 2025)
