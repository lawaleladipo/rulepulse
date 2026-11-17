"""Cross-check synthesis joining rule noise, true-positive dispositions, whitelisting, and DaC drift."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from rulepulse.checks.disposition_and_whitelisting import RuleDispositionFinding
from rulepulse.checks.noisy_rules import RuleNoiseFinding
from rulepulse.checks.static_dac_audit import StaticRuleAuditFinding


@dataclass
class SynthesizedRecommendation:
    rule_name: str
    priority: str  # 'HIGH', 'MEDIUM'
    classification: str  # 'RETIRE_OR_REWRITE', 'BLIND_RULE_DEAD_LOG', 'TUNE_THRESHOLD'
    signals: List[str] = field(default_factory=list)
    recommended_action: str = ""


def synthesize_findings(
    noise_findings: List[RuleNoiseFinding],
    disposition_findings: List[RuleDispositionFinding],
    static_findings: List[StaticRuleAuditFinding],
) -> List[SynthesizedRecommendation]:
    """Join multi-check signals so chronically broken rules surface as a single engineering action."""
    noise_by_name = {f.rule_name: f for f in noise_findings}
    disp_by_name = {f.rule_name: f for f in disposition_findings}
    static_by_name = {f.rule_name: f for f in static_findings}

    all_names = sorted(set(noise_by_name) | set(disp_by_name) | set(static_by_name))
    synthesized: List[SynthesizedRecommendation] = []

    for name in all_names:
        nf = noise_by_name.get(name)
        df = disp_by_name.get(name)
        sf = static_by_name.get(name)

        if sf and sf.dead_log_types:
            synthesized.append(
                SynthesizedRecommendation(
                    rule_name=name,
                    priority="HIGH",
                    classification="BLIND_RULE_DEAD_LOG",
                    signals=[
                        f"Depends on silent log source(s): {', '.join(sf.dead_log_types)}",
                        *sf.issues,
                    ],
                    recommended_action=(
                        "Restore upstream log ingestion pipeline before relying on this rule for coverage."
                    ),
                )
            )

        is_noisy = nf is not None and nf.verdict in ("noisy_rule", "borderline_noise")
        is_zero_tp = df is not None and df.closed_cases >= 10 and df.true_positive_rate == 0.0
        is_whitelisted = df is not None and df.verdict == "whitelisting_decay"

        if is_whitelisted and (is_noisy or is_zero_tp):
            signals = []
            if nf:
                signals.append(
                    f"Volume Z={nf.evaluation.modified_z} ({nf.verdict}, current={nf.evaluation.current_value})"
                )
            if df:
                signals.append(
                    f"0% TP across {df.closed_cases} closed cases with {df.exclusion_clauses} exclusion clauses"
                )
            synthesized.append(
                SynthesizedRecommendation(
                    rule_name=name,
                    priority="HIGH",
                    classification="RETIRE_OR_REWRITE",
                    signals=signals,
                    recommended_action=(
                        "Stop appending exclusions; retire rule or rewrite around high-signal behavioral predicates."
                    ),
                )
            )
        elif is_noisy and df and df.verdict == "low_precision":
            synthesized.append(
                SynthesizedRecommendation(
                    rule_name=name,
                    priority="MEDIUM",
                    classification="TUNE_THRESHOLD",
                    signals=[
                        f"Noisy spike Z={nf.evaluation.modified_z}",
                        f"Low precision ({df.true_positive_rate * 100:.1f}% TP across {df.closed_cases} cases)",
                    ],
                    recommended_action=(
                        "Inspect top principal.hostname / target.user groupings and tighten match correlation window."
                    ),
                )
            )

    return synthesized
