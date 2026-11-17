from datetime import datetime, timezone
from pathlib import Path

from rulepulse.checks.disposition_and_whitelisting import (
    chunk_rule_ids,
    evaluate_dispositions_and_whitelisting,
)
from rulepulse.checks.log_health import compute_quota_runway, evaluate_log_sources
from rulepulse.checks.noisy_rules import evaluate_rule_noise
from rulepulse.checks.static_dac_audit import audit_yaral_directory
from rulepulse.cli import DEFAULT_SAMPLE_DIR, run_full_audit
from rulepulse.guardrails.cost_ledger import CostLedger
from rulepulse.guardrails.llm_reasoner import BoundedLLMReasoner
from rulepulse.guardrails.oncall_router import ShiftSlot, resolve_oncall_analyst
from rulepulse.stats.mad_baseline import (
    compute_mad_zscore,
    evaluate_ingestion_latency_pooled,
    evaluate_log_volume_by_weekday,
)


def test_mad_baseline_handles_outliers_and_sample_floors():
    sparse = compute_mad_zscore([1, 2, 1], 50, min_samples=4)
    assert sparse.status == "insufficient_data"

    # One historical incident outlier (400) does not poison Median/MAD baseline
    history = [10, 12, 11, 13, 12, 400, 11, 10, 12, 13]
    res = compute_mad_zscore(history, 95)
    assert res.status == "breach"
    assert res.direction == "up"
    assert res.modified_z >= 3.5


def test_weekday_volume_vs_pooled_latency_baselines():
    by_day = {
        "tuesday": [150000, 148000, 152000, 149000, 151000],
        "sunday": [15000, 16000, 14500, 15200, 14900],
    }
    # 15,100 events on Sunday is completely healthy, but on Tuesday is an outage
    sun = evaluate_log_volume_by_weekday(by_day, "sunday", 15100)
    tue = evaluate_log_volume_by_weekday(by_day, "tuesday", 15100)
    assert sun.status == "healthy"
    assert tue.status == "breach" and tue.direction == "down"

    # Steady 30-minute cloud feed stays healthy at 31 min, fires at 180 min
    lag_hist = [29.0, 30.5, 31.0, 28.5, 30.0, 29.5]
    assert evaluate_ingestion_latency_pooled(lag_hist, 31.0).status == "healthy"
    lag_spike = evaluate_ingestion_latency_pooled(lag_hist, 180.0)
    assert lag_spike.status == "breach" and lag_spike.direction == "up"


def test_concurrent_spike_paradox_rules_downgrade_but_logs_never_suppress():
    # 5 rules spiking simultaneously -> correlated 'activity_burst'
    spiking_rules = [
        {
            "rule_id": f"ru_{i}",
            "rule_name": f"rule_{i}",
            "weekly_counts": [10, 11, 12, 10, 11, 12],
            "current_count": 120,
        }
        for i in range(5)
    ]
    rule_res = evaluate_rule_noise(spiking_rules)
    assert all(r.verdict == "activity_burst" for r in rule_res)

    # Multiple log sources surging simultaneously -> NEVER downgraded
    surging_logs = [
        {
            "log_type": name,
            "volume_by_weekday": {"tuesday": [1000, 1050, 980, 1020, 1010]},
            "current_volume": 15000,
            "latency_minutes_history": [1.0, 1.1, 1.2, 1.0, 1.1, 1.2],
            "current_lag_minutes": 1.1,
        }
        for name in ("WAF", "CLOUD_IAM", "K8S_AUDIT", "EDR", "SASE")
    ]
    log_res = evaluate_log_sources(surging_logs, weekday="tuesday")
    assert all(item.volume_verdict == "log_source_surge" for item in log_res)


def test_disposition_batching_and_whitelisting_decay():
    ids = [f"ru_{i}" for i in range(60)]
    batches = chunk_rule_ids(ids)
    assert [len(b) for b in batches] == [25, 25, 10]

    report = evaluate_dispositions_and_whitelisting(
        [
            {
                "rule_id": "ru_decay",
                "rule_name": "muted_noisy_rule",
                "closed_cases": 50,
                "true_positives": 0,
                "escalated_cases": 0,
                "exclusion_clauses": 8,
                "prior_exclusion_clauses": 4,
            }
        ]
    )
    assert report["findings"][0].verdict == "whitelisting_decay"


def test_bounded_llm_cache_budget_and_cost_ledger(tmp_path: Path):
    ledger = CostLedger(tmp_path / "ledger.jsonl")
    calls = {"count": 0}

    def fake_provider(subject_id: str, payload: dict) -> dict:
        calls["count"] += 1
        return {
            "verdict": "escalate_oncall",
            "model": "gemini-flash",
            "prompt_tokens": 300,
            "output_tokens": 100,
            "rationale": "Correlated with elevated auth failures.",
        }

    reasoner = BoundedLLMReasoner(ledger=ledger, max_calls_per_run=1, provider_fn=fake_provider)
    borderline = compute_mad_zscore([18, 20, 17, 21, 19, 18, 22, 19], 23)
    assert borderline.status == "borderline"

    # First call invokes provider
    d1 = reasoner.adjudicate_borderline("ru_1", borderline)
    assert d1.llm_invoked is True and d1.disposition == "escalate_oncall"

    # Identical metrics hit cache without consuming budget or tokens
    d2 = reasoner.adjudicate_borderline("ru_1", borderline)
    assert d2.cache_hit is True and calls["count"] == 1

    # Second distinct borderline rule exceeds max_calls_per_run=1 -> degrades safely to needs_review
    d3 = reasoner.adjudicate_borderline("ru_2", borderline)
    assert d3.disposition == "needs_review" and d3.llm_invoked is False

    summary = ledger.summarize()
    assert summary["daily"]["calls"] == 1
    assert summary["daily"]["cached_hits"] == 1
    assert summary["daily"]["tokens"] == 400


def test_shift_handover_overlap_routes_to_incoming_analyst():
    t0 = datetime(2026, 5, 12, 8, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 5, 12, 16, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 5, 13, 0, 0, tzinfo=timezone.utc)
    schedule = [
        ShiftSlot("analyst_day", t0, t1),
        ShiftSlot("analyst_swing", t1, t2),
    ]
    # 15:15 UTC -> still analyst_day
    assert resolve_oncall_analyst(schedule, datetime(2026, 5, 12, 15, 15, tzinfo=timezone.utc)) == "analyst_day"
    # 15:40 UTC (within 30m handover before 16:00) -> routes to incoming analyst_swing
    assert resolve_oncall_analyst(schedule, datetime(2026, 5, 12, 15, 40, tzinfo=timezone.utc)) == "analyst_swing"


def test_full_sample_audit_cross_references_dead_logs_and_quota(tmp_path: Path):
    report = run_full_audit(DEFAULT_SAMPLE_DIR, tmp_path)
    classifications = {a["rule_name"]: a["classification"] for a in report["synthesized_actions"]}
    assert classifications["cloud_iam_service_account_key_created"] == "BLIND_RULE_DEAD_LOG"
    assert classifications["iam_admin_role_grant_unusual_runner"] == "RETIRE_OR_REWRITE"
    assert report["quota_runway"]["status"] in ("elevated_burn", "quota_breach_imminent")

    static = audit_yaral_directory(
        DEFAULT_SAMPLE_DIR / "yaral_rules",
        dead_log_sources=["CLOUD_AUDIT_IAM"],
    )
    by_name = {s.rule_name: s for s in static}
    assert any("$count" in i for i in by_name["iam_admin_role_grant_unusual_runner"].issues)
    assert compute_quota_runway([2.4, 2.45], 2.5).status == "quota_breach_imminent"
