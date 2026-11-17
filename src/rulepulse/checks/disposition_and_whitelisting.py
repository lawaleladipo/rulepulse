"""Closed-case disposition batching and excessive whitelisting decay detection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List

MAX_DISPOSITION_BATCH_SIZE = 25


@dataclass
class RuleDispositionFinding:
    rule_id: str
    rule_name: str
    closed_cases: int
    true_positives: int
    escalated_cases: int
    true_positive_rate: float
    escalation_rate: float
    exclusion_clauses: int
    prior_exclusion_clauses: int
    verdict: str  # 'whitelisting_decay', 'low_precision', 'healthy', 'insufficient_data'


def chunk_rule_ids(rule_ids: Iterable[str], batch_size: int = MAX_DISPOSITION_BATCH_SIZE) -> List[List[str]]:
    """Batch rule IDs into groups <= 25 to respect SIEM API rate limits."""
    if batch_size < 1 or batch_size > MAX_DISPOSITION_BATCH_SIZE:
        raise ValueError(f"batch_size must be between 1 and {MAX_DISPOSITION_BATCH_SIZE}")
    items = list(rule_ids)
    return [items[i:i + batch_size] for i in range(0, len(items), batch_size)]


def evaluate_dispositions_and_whitelisting(
    rule_case_records: List[Dict[str, Any]],
    *,
    min_closed_cases: int = 10,
) -> Dict[str, Any]:
    """Compute per-rule precision, whitelisting decay, and sample-weighted SOC trend."""
    findings: List[RuleDispositionFinding] = []
    total_closed = 0
    total_tp = 0

    batches = chunk_rule_ids([str(r["rule_id"]) for r in rule_case_records])
    by_id = {str(r["rule_id"]): r for r in rule_case_records}

    for batch in batches:
        for rule_id in batch:
            rec = by_id[rule_id]
            closed = int(rec.get("closed_cases", 0))
            tp = int(rec.get("true_positives", 0))
            esc = int(rec.get("escalated_cases", 0))
            exclusions = int(rec.get("exclusion_clauses", 0))
            prior_excl = int(rec.get("prior_exclusion_clauses", exclusions))

            total_closed += closed
            total_tp += tp

            if closed < min_closed_cases:
                verdict = "insufficient_data"
                tp_rate = 0.0 if closed == 0 else round(tp / closed, 3)
                esc_rate = 0.0 if closed == 0 else round(esc / closed, 3)
            else:
                tp_rate = round(tp / closed, 3)
                esc_rate = round(esc / closed, 3)
                exclusion_growth = exclusions - prior_excl
                if tp == 0 and exclusions >= 6 and exclusion_growth >= 2:
                    verdict = "whitelisting_decay"
                elif tp_rate < 0.05:
                    verdict = "low_precision"
                else:
                    verdict = "healthy"

            findings.append(
                RuleDispositionFinding(
                    rule_id=rule_id,
                    rule_name=str(rec.get("rule_name", rule_id)),
                    closed_cases=closed,
                    true_positives=tp,
                    escalated_cases=esc,
                    true_positive_rate=tp_rate,
                    escalation_rate=esc_rate,
                    exclusion_clauses=exclusions,
                    prior_exclusion_clauses=prior_excl,
                    verdict=verdict,
                )
            )

    weighted_soc_tp_rate = round(total_tp / total_closed, 3) if total_closed > 0 else 0.0
    return {
        "batches_executed": len(batches),
        "weighted_soc_true_positive_rate": weighted_soc_tp_rate,
        "findings": findings,
    }
