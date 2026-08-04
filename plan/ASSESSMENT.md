# PhishGuard — Planning Self-Assessment

This document answers the two direct questions about the plan, honestly and with evidence.
It is a living check during the 3-day planning phase.

---

## Q1 — Is this plan well planned and organized?

**Verdict: Yes — the plan is well-structured and decision-ready, with a few gaps to close
before code starts.** It is organized as a research-backed engineering blueprint, not a
wish-list.

### What is well done
- **Clear scope & decisions first.** `docs/PLANNING.md` §1 records the agreed form factor
  (CLI + web dashboard), the self-contained + optional-API stance, and the detection-engine
  priority — decided *before* design, so the work stays focused.
- **Evidence-based, not invented.** Every major decision cites a reference project
  (`plan/RESEARCH.md`): Sublime (detections-as-code), Rspamd (layered transparent scoring),
  ThePhish (analyzer fan-out + SOC integration), Abnormal/Cisco ETD (behavioral BEC),
  Defender (time-of-click + sandbox + remediation), dnstwist/opensquat (lookalike),
  gsimransingh/PhishGuard (independent convergence on the same design).
- **Honest gap analysis.** The plan explicitly states what it will *not* do as well as the
  top 1% (global network effect, deployed-tenant foundation models) instead of overclaiming.
- **Concrete architecture.** `plan/ARCHITECTURE.md` gives topologies, component diagram, data
  flow, module contracts, JSON data model, rule engine, storage schema, API contract, and a
  research→roadmap mapping.
- **Actionable roadmap.** Day 1/2/3 broken into mergeable units, each tied to research.

### Gaps to close before implementation (honest)
1. **Thresholds not yet tuned** — risk weights are directional; they need calibration against
   a labeled dataset (`evaluation/` harness) to hit enterprise FPR targets. *Plan: Day 2–3.*
2. **Rule DSL not formally specified** — only the concept exists. *Plan: write `rules/schema.md`
   in Day 2.*
3. **No data-flow sequence diagrams for remediation/export** — text only so far. *Minor.*
4. **Missing: adversarial-robustness section** — how we resist evasion (cloaking, prompt-injection
   via email content into any LLM assist). *Add before Day 1 if we include an LLM helper.*
5. **Grok conversation not ingested** — the provided link was unreadable; its points are not
   folded in. *Needs user paste.*
6. **Scalability only sketched** — queue/worker model for high volume is implied, not specified.
   *Expand in Day 3 if targeting large MSSP deployments.*

**Score:** 8/10 as a planning artifact. Strong enough to start Day 1; items 1–2 are the only
true blockers and are already scheduled.

---

## Q2 — Does this plan beat 99% of email-security tools out there?

**Verdict: As scoped and researched, PhishGuard will beat the long tail decisively and be
competitive with the mid-tier — but it will not out-detect the absolute top 1% (Abnormal,
Microsoft Defender, Proofpoint, Mimecast) from a single install.** This is an honest,
evidence-based answer, not a marketing claim.

### Tiers, and where PhishGuard lands
| Tier | Examples | PhishGuard vs this tier |
|---|---|---|
| Long tail (naive) | Keyword scripts, basic SEGs, many small OSS tools | **Wins clearly** — layered auth + URL + content + attachment + behavioral + explainable scoring |
| Mid-tier commercial SEG | Smaller SEGs, single-signal tools | **Competitive** — covers same signal classes, more transparent, self-hostable |
| Top 1% | Abnormal, Defender, Proofpoint, Mimecast, Sublime cloud | **Not a replacement** on raw accuracy at scale — see why below |

### Why it cannot beat the top 1% *as a single deployment*
1. **Network effect / data scale.** Abnormal aggregates signals across 2,400+ tenants;
   Proofpoint correlates supplier behavior; Cisco ETD uses a global relationship graph.
   A single self-hosted instance sees only your mail → no cross-tenant learning. *(Research:
   Abnormal ThreatBase, Proofpoint, Cisco ETD white paper.)*
2. **Deployed-tenant behavioral foundation models.** Abnormal's Attune, Defender Mailbox
   Intelligence, Material's org graph learn *your* relationships over weeks–90 days — but the
   top vendors compound that with billions of messages. Our `behavioral.py` is single-org
   only. *(Research: Abnormal anomaly detection, Ironscales, Cisco ETD.)*
3. **Sandbox detonation at scale.** Defender Safe Attachments / Safe Links rewrite + detonate
   billions of URLs/files. We integrate a sandbox (Joe/CAPE) optionally; we don't operate one.

### What it *does* close
- Covers the **same signal classes** the leaders use: SPF/DKIM/DMARC + alignment, BEC
  behavioral baseline, org-context impersonation (VIP/your-domain/brand), time-of-click URL
  recheck, attachment analysis, transparent scoring, SIEM/SOAR export, post-delivery
  remediation. Technically we are in the same league; the gap is deployment scale, not design.
- **Positioning that is both honest and strong:** best-in-class *open, self-hosted, auditable*
  engine — ideal for privacy-sensitive / air-gapped orgs, and for MSSPs who deploy it across
  many tenants (building their *own* network effect via `feedback.py`). This is a real,
  defensible commercial stance, not a consolation prize.

### Bottom line
- Beats ~99% of *tools that exist* (the long tail + weak SEGs) on capability and transparency.
- Does **not** beat the ~1% of vendors whose advantage is data/scale, not code.
- The honest pitch: *"The most transparent, self-hostable email detection engine — competitive
  with commercial SEGs, and the right choice when you can't or won't send mail to a vendor
  cloud."*

---

## Decisions still requested from the user
- Paste the **Grok conversation** content (link was unreadable) so we can fold in any unique
  ideas.
- Confirm **remediation-in-v1** ships behind config (recommended: yes).
- Confirm **positioning** language (recommended: open/self-hosted/auditable, not "beats
  Abnormal/Defender").
- Optional: whether to include an **LLM-assist** (explainability) module now, with an
  adversarial-robustness section added first.
