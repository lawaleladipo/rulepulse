# RulePulse — Autonomous, Read-Only Detection Quality & SIEM Drift Assurance Agent

[![CI](https://github.com/lawaleladipo/rulepulse/actions/workflows/ci.yml/badge.svg)](https://github.com/lawaleladipo/rulepulse/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB.svg)](setup.py)

**RulePulse** is a read-only, deterministic-first **Detection Quality & SIEM Drift Assurance Agent**. Instead of asking an LLM to guess whether a SIEM is healthy, RulePulse anchors every check in **12-week Median & Median Absolute Deviation (MAD)** baselines, closed-case precision telemetry, and static Detection-as-Code (`.yaral`) analysis—invoking an LLM *only* as a cost-bounded, cached second opinion on statistically ambiguous cases.

---

## Why RulePulse Exists

Most security teams celebrate when a detection rule passes CI and merges to `main`. Six months later, detection layers decay silently:
- **Silent log-source outages** drop alert counts on weekends or weekdays without throwing errors.
- **Ingestion latency drift** (`ingestion_timestamp - event_timestamp`) breaks 15-minute correlation windows while daily volume looks green.
- **Excessive whitelisting decay** mutes noisy rules with broad exclusions until true-positive precision sits at `0%`.
- **Static DaC drift** leaves deployed `.yaral` rules referencing dead log sources, missing MITRE ATT&CK metadata, or duplicating logic.

---

## Five Hard Runtime Boundaries

1. **Read-Only by Architecture:** Zero write permissions. RulePulse never disables a rule, edits an exclusion list, or closes a case—it emits statistical proof and exact verification queries for human engineers.
2. **LLM Off the Critical Path:** Clear breaches (`|Z| >= 3.5`) and healthy metrics (`|Z| < 2.2`) never invoke an LLM.
3. **Asymmetric Spike Correlation (The Concurrent-Spike Paradox):**
   - When **many rules** spike simultaneously (e.g., vulnerability scan / patch window), RulePulse correlates them into an org-wide `activity_burst` instead of paging 20 separate alerts.
   - When **many log sources** surge simultaneously, RulePulse **never** suppresses them—because simultaneous WAF + IAM + K8s + EDR surges may be an active intrusion.
4. **Weekday Volume vs. Pooled Latency Baselines:** Log volume compares Tuesday against historical Tuesdays (so quiet Sundays stay quiet), while ingestion lag pools per-source history (so naturally slow 30-minute cloud feeds stay green until their own transport degrades).
5. **Ambiguity Never Pages On-Call at 2 A.M.:** If the per-run LLM call budget is reached or no model key is configured, borderline findings degrade cleanly to `needs_review` in the weekly engineering digest—backed by an append-only JSONL token/USD cost ledger and 30-minute shift-handover routing.

---

## Architecture

```text
+-----------------------+     Read-Only Telemetry   +-------------------------------+
|   SIEM / Log Layer    | ------------------------> |  Independent Audit & Watch    |
|  & DaC Git Repository |                           |  Checks (Median / MAD / AST)  |
+-----------------------+                           +---------------+---------------+
                                                                    |
                                         +--------------------------+--------------------------+
                                         | Clear Statistical Breach (|Z| >= 3.5)               | Borderline Only (2.2 <= |Z| < 3.5)
                                         v                                                     v
                            +-------------------------+                           +-------------------------+
                            | Direct Evidence-Backed  |                           | Bounded LLM Escalation  |
                            | Finding (Zero LLM Call) |                           | (Budget + Cache Guard)  |
                            +------------+------------+                           +------------+------------+
                                         |                                                     |
                                         |                        API Error / Budget Hit       | Confirmed Signal
                                         |                    +--------------------------------+
                                         v                    v                                v
                            +------------------------------------+               +--------------------------+
                            | Weekly Digest Only (needs_review)  |               | Shift-Handover-Aware     |
                            | Never pages on-call at 2 a.m.      |               | Real-Time Watch Alert    |
                            +------------------------------------+               +--------------------------+
```

---

## Quick Start

```bash
git clone https://github.com/lawaleladipo/rulepulse.git
cd rulepulse
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run full audit against the bundled synthetic Acme FinTech SIEM dataset
rulepulse audit --sample

# Audit a directory of YARA-L 2.0 rules statically
rulepulse static-check sample_data/yaral_rules

# View local token/USD cost ledger (zero LLM calls)
rulepulse cost-report
```

### Run Tests & Lint

```bash
pytest -v
flake8 src tests --max-line-length=127
```

---

## Author & License

Built by **Olawale Oladipo** ([GitHub](https://github.com/lawaleladipo) · [Medium](https://medium.com/@lawaleladipo) · [LinkedIn](https://www.linkedin.com/in/olawale-oladipo-cybersecurity/)).  
Released under the [MIT License](LICENSE).
