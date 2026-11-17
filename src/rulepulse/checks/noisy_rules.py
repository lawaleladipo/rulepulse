"""Noisy-rule detection with concurrent org-wide activity-burst correlation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from rulepulse.stats.mad_baseline import MadEvaluation, compute_mad_zscore


@dataclass
class RuleNoiseFinding:
    rule_id: str
    rule_name: str
    verdict: str  # 'noisy_rule', 'activity_burst', 'borderline_noise', 'healthy', 'insufficient_data'
    evaluation: MadEvaluation
    verification_query: str


def evaluate_rule_noise(
    rules_telemetry: List[Dict[str, Any]],
    *,
    concurrent_burst_min_rules: int = 5,
    concurrent_burst_ratio: float = 0.35,
) -> List[RuleNoiseFinding]:
    """Evaluate 12-week weekly/daily alert counts per rule and correlate simultaneous spikes.

    Concurrent-Spike Paradox (Rule Side):
    When many detection rules spike in the exact same window (e.g. fleet vulnerability scan
    or patch Tuesday), paging on each rule individually creates alert fatigue. Concurrent
    upward breaches are correlated and downgraded to ``activity_burst``.
    """
    preliminary: List[RuleNoiseFinding] = []
    upward_breaches = 0
    eligible_rules = 0

    for item in rules_telemetry:
        rule_id = str(item["rule_id"])
        rule_name = str(item.get("rule_name", rule_id))
        history = item.get("weekly_counts", [])
        current = float(item.get("current_count", 0))
        eval_res = compute_mad_zscore(history, current, min_samples=4)

        if eval_res.status != "insufficient_data":
            eligible_rules += 1

        verdict = "healthy"
        if eval_res.status == "insufficient_data":
            verdict = "insufficient_data"
        elif eval_res.status == "breach" and eval_res.direction == "up":
            verdict = "noisy_rule"
            upward_breaches += 1
        elif eval_res.status == "borderline" and eval_res.direction == "up":
            verdict = "borderline_noise"

        query = (
            f'detection.detection.rule_id = "{rule_id}" '
            "| stats count() by principal.hostname, target.user.userid"
        )
        preliminary.append(
            RuleNoiseFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                verdict=verdict,
                evaluation=eval_res,
                verification_query=query,
            )
        )

    is_org_activity_burst = eligible_rules > 0 and (
        upward_breaches >= concurrent_burst_min_rules
        or (eligible_rules >= 4 and (upward_breaches / eligible_rules) >= concurrent_burst_ratio)
    )

    if is_org_activity_burst:
        for finding in preliminary:
            if finding.verdict == "noisy_rule":
                finding.verdict = "activity_burst"

    return preliminary
