"""Log-source downtime, multi-source surge, ingestion latency, and quota runway checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from rulepulse.stats.mad_baseline import (
    MadEvaluation,
    evaluate_ingestion_latency_pooled,
    evaluate_log_volume_by_weekday,
)


@dataclass
class LogHealthFinding:
    log_type: str
    volume_verdict: str  # 'log_source_down', 'log_source_surge', 'borderline_volume', 'healthy', 'insufficient_data'
    latency_verdict: str  # 'ingestion_lag_breach', 'borderline_lag', 'healthy', 'insufficient_data'
    volume_eval: MadEvaluation
    latency_eval: MadEvaluation
    verification_query: str


@dataclass
class QuotaRunwayReport:
    daily_quota_tb: float
    current_daily_tb: float
    rolling_7d_avg_tb: float
    utilization_pct: float
    days_until_ceiling: float | None
    status: str  # 'healthy', 'elevated_burn', 'quota_breach_imminent'
    top_accelerating_sources: List[str]


def evaluate_log_sources(
    sources_telemetry: List[Dict[str, Any]],
    *,
    weekday: str,
) -> List[LogHealthFinding]:
    """Evaluate per-source weekday volume and pooled ingestion lag.

    Concurrent-Spike Paradox (Log-Source Side):
    Unlike noisy rules, concurrent log-source surges are NEVER suppressed or downgraded
    because simultaneous surges across WAF, IAM, Kubernetes, and EDR may represent an
    active multi-plane intrusion.
    """
    findings: List[LogHealthFinding] = []
    for src in sources_telemetry:
        log_type = str(src["log_type"])
        current_vol = float(src.get("current_volume", 0))
        vol_eval = evaluate_log_volume_by_weekday(
            src.get("volume_by_weekday", {}),
            weekday,
            current_vol,
        )

        if vol_eval.status == "insufficient_data":
            vol_verdict = "insufficient_data"
        elif current_vol == 0.0 and vol_eval.baseline_median > 0:
            vol_verdict = "log_source_down"
        elif vol_eval.status == "breach" and vol_eval.direction == "down":
            vol_verdict = "log_source_down"
        elif vol_eval.status == "breach" and vol_eval.direction == "up":
            vol_verdict = "log_source_surge"
        elif vol_eval.status == "borderline":
            vol_verdict = "borderline_volume"
        else:
            vol_verdict = "healthy"

        lag_eval = evaluate_ingestion_latency_pooled(
            src.get("latency_minutes_history", []),
            float(src.get("current_lag_minutes", 0.0)),
        )
        if lag_eval.status == "insufficient_data":
            lag_verdict = "insufficient_data"
        elif lag_eval.status == "breach" and lag_eval.direction == "up":
            lag_verdict = "ingestion_lag_breach"
        elif lag_eval.status == "borderline" and lag_eval.direction == "up":
            lag_verdict = "borderline_lag"
        else:
            lag_verdict = "healthy"

        findings.append(
            LogHealthFinding(
                log_type=log_type,
                volume_verdict=vol_verdict,
                latency_verdict=lag_verdict,
                volume_eval=vol_eval,
                latency_eval=lag_eval,
                verification_query=(
                    f'metadata.log_type = "{log_type}" '
                    "| stats count(), avg(ingestion_delay_seconds) by hour"
                ),
            )
        )
    return findings


def compute_quota_runway(
    daily_tb_series: List[float],
    daily_quota_tb: float,
    source_daily_deltas_gb: Dict[str, float] | None = None,
) -> QuotaRunwayReport:
    """Estimate license ceiling utilization and linear daily burn-rate runway."""
    if not daily_tb_series:
        return QuotaRunwayReport(
            daily_quota_tb=daily_quota_tb,
            current_daily_tb=0.0,
            rolling_7d_avg_tb=0.0,
            utilization_pct=0.0,
            days_until_ceiling=None,
            status="healthy",
            top_accelerating_sources=[],
        )

    current_tb = float(daily_tb_series[-1])
    window = daily_tb_series[-7:]
    avg_tb = sum(window) / len(window)
    util_pct = round((current_tb / daily_quota_tb) * 100.0, 2) if daily_quota_tb > 0 else 0.0

    daily_slope = 0.0
    if len(window) >= 2:
        daily_slope = (window[-1] - window[0]) / (len(window) - 1)

    days_left: float | None = None
    if current_tb >= daily_quota_tb:
        days_left = 0.0
    elif daily_slope > 0.005:
        days_left = round((daily_quota_tb - current_tb) / daily_slope, 1)

    if util_pct >= 92.0 or (days_left is not None and days_left <= 5.0):
        status = "quota_breach_imminent"
    elif util_pct >= 80.0 or (days_left is not None and days_left <= 14.0):
        status = "elevated_burn"
    else:
        status = "healthy"

    accelerating = []
    if source_daily_deltas_gb:
        ranked = sorted(source_daily_deltas_gb.items(), key=lambda kv: kv[1], reverse=True)
        accelerating = [f"{k} (+{v:.1f} GB/d)" for k, v in ranked if v > 0][:3]

    return QuotaRunwayReport(
        daily_quota_tb=daily_quota_tb,
        current_daily_tb=round(current_tb, 3),
        rolling_7d_avg_tb=round(avg_tb, 3),
        utilization_pct=util_pct,
        days_until_ceiling=days_left,
        status=status,
        top_accelerating_sources=accelerating,
    )
