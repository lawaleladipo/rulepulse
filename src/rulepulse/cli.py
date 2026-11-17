"""Command-line entrypoint for RulePulse."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

import click

from rulepulse.checks.disposition_and_whitelisting import evaluate_dispositions_and_whitelisting
from rulepulse.checks.log_health import compute_quota_runway, evaluate_log_sources
from rulepulse.checks.noisy_rules import evaluate_rule_noise
from rulepulse.checks.static_dac_audit import audit_yaral_directory
from rulepulse.guardrails.cost_ledger import CostLedger
from rulepulse.guardrails.llm_reasoner import BoundedLLMReasoner
from rulepulse.synthesis.cross_check import synthesize_findings

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SAMPLE_DIR = REPO_ROOT / "sample_data"


def run_full_audit(sample_dir: Path, state_dir: Path) -> Dict[str, Any]:
    telemetry = json.loads((sample_dir / "telemetry_snapshot.json").read_text(encoding="utf-8"))
    rules_dir = sample_dir / "yaral_rules"

    ledger = CostLedger(state_dir / "llm_cost_ledger.jsonl")
    max_calls = int(os.getenv("RULEPULSE_MAX_LLM_CALLS_PER_RUN", "5"))
    reasoner = BoundedLLMReasoner(ledger=ledger, max_calls_per_run=max_calls)

    noise_findings = evaluate_rule_noise(telemetry["rules_telemetry"])
    log_findings = evaluate_log_sources(
        telemetry["log_sources"],
        weekday=telemetry.get("weekday", "tuesday"),
    )
    dead_sources = [f.log_type for f in log_findings if f.volume_verdict == "log_source_down"]

    disp_report = evaluate_dispositions_and_whitelisting(telemetry["rule_dispositions"])
    static_findings = audit_yaral_directory(rules_dir, dead_log_sources=dead_sources)
    synthesized = synthesize_findings(
        noise_findings,
        disp_report["findings"],
        static_findings,
    )
    quota = compute_quota_runway(
        telemetry["quota"]["daily_tb_series"],
        float(telemetry["quota"]["daily_quota_tb"]),
        telemetry["quota"].get("source_daily_deltas_gb"),
    )

    borderline_decisions = []
    for nf in noise_findings:
        if nf.verdict == "borderline_noise":
            dec = reasoner.adjudicate_borderline(nf.rule_id, nf.evaluation, expected_direction="up")
            borderline_decisions.append(dec.__dict__)

    return {
        "mode": "read_only_deterministic_first",
        "weekday": telemetry.get("weekday", "tuesday"),
        "rule_noise": [
            {
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "verdict": f.verdict,
                "modified_z": f.evaluation.modified_z,
                "verification_query": f.verification_query,
            }
            for f in noise_findings
        ],
        "log_health": [
            {
                "log_type": f.log_type,
                "volume_verdict": f.volume_verdict,
                "latency_verdict": f.latency_verdict,
                "volume_z": f.volume_eval.modified_z,
                "latency_z": f.latency_eval.modified_z,
            }
            for f in log_findings
        ],
        "dispositions": {
            "batches_executed": disp_report["batches_executed"],
            "weighted_soc_true_positive_rate": disp_report["weighted_soc_true_positive_rate"],
            "whitelisting_decay_rules": [
                f.rule_name for f in disp_report["findings"] if f.verdict == "whitelisting_decay"
            ],
        },
        "static_dac_issues": [
            {"file": s.file_path, "rule_name": s.rule_name, "issues": s.issues}
            for s in static_findings
            if s.issues
        ],
        "synthesized_actions": [s.__dict__ for s in synthesized],
        "quota_runway": quota.__dict__,
        "borderline_llm_decisions": borderline_decisions,
        "cost_summary": ledger.summarize(),
    }


@click.group()
def cli() -> None:
    """RulePulse — Autonomous, Read-Only Detection Quality & SIEM Drift Assurance Agent."""


@cli.command("audit")
@click.option("--sample", is_flag=True, help="Run audit against synthetic Acme FinTech SIEM dataset.")
@click.option("--data-dir", type=click.Path(exists=True, path_type=Path), default=None)
@click.option("--json-out", is_flag=True, help="Emit raw JSON report.")
def audit_cmd(sample: bool, data_dir: Path | None, json_out: bool) -> None:
    """Run Median/MAD telemetry checks, static DaC audit, and cross-check synthesis."""
    target_dir = data_dir or (DEFAULT_SAMPLE_DIR if sample else DEFAULT_SAMPLE_DIR)
    state_dir = Path(os.getenv("RULEPULSE_STATE_DIR", ".state"))
    report = run_full_audit(target_dir, state_dir)

    if json_out:
        click.echo(json.dumps(report, indent=2))
        return

    click.echo("=" * 72)
    click.echo("RulePulse — Read-Only Detection Quality Assurance Report")
    click.echo("=" * 72)
    click.echo(f"Weekday Baseline : {report['weekday'].title()} (Median/MAD |Z| >= 3.5)")
    click.echo(
        f"SOC Weighted TP  : {report['dispositions']['weighted_soc_true_positive_rate'] * 100:.1f}% "
        f"({report['dispositions']['batches_executed']} API batch)"
    )
    qr = report["quota_runway"]
    click.echo(
        f"Quota Utilization: {qr['current_daily_tb']} / {qr['daily_quota_tb']} TB "
        f"({qr['utilization_pct']}%, status={qr['status']}, runway={qr['days_until_ceiling']}d)"
    )
    click.echo("\n[Log-Source Health]")
    for lh in report["log_health"]:
        click.echo(
            f"  - {lh['log_type']:<22} vol={lh['volume_verdict']} (Z={lh['volume_z']}) | "
            f"lag={lh['latency_verdict']} (Z={lh['latency_z']})"
        )
    click.echo("\n[Cross-Check Synthesized Engineering Actions]")
    for item in report["synthesized_actions"]:
        click.echo(f"  - [{item['priority']}] {item['rule_name']} -> {item['classification']}")
        for sig in item["signals"]:
            click.echo(f"      * {sig}")
        click.echo(f"      Action: {item['recommended_action']}")


@cli.command("static-check")
@click.argument("rules_dir", type=click.Path(exists=True, path_type=Path))
def static_check_cmd(rules_dir: Path) -> None:
    """Audit a directory of .yaral rules for duplicates, syntax traps, and missing ATT&CK tags."""
    results = audit_yaral_directory(rules_dir)
    for res in results:
        status = "PASS" if not res.issues else f"ISSUES ({len(res.issues)})"
        click.echo(f"{res.file_path}: {res.rule_name} -> {status}")
        for issue in res.issues:
            click.echo(f"  * {issue}")


@cli.command("cost-report")
def cost_report_cmd() -> None:
    """Print local daily/weekly/monthly LLM spend without making an LLM call."""
    state_dir = Path(os.getenv("RULEPULSE_STATE_DIR", ".state"))
    ledger = CostLedger(state_dir / "llm_cost_ledger.jsonl")
    click.echo(json.dumps(ledger.summarize(), indent=2))


if __name__ == "__main__":
    cli()
