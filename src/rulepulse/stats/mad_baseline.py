"""Robust Median & Median Absolute Deviation (MAD) baselines for SIEM telemetry."""

from __future__ import annotations

from dataclasses import dataclass
from statistics import median
from typing import Dict, List, Sequence

MAD_CONSISTENCY_CONSTANT = 0.6745


@dataclass(frozen=True)
class MadEvaluation:
    status: str  # 'breach', 'borderline', 'healthy', 'insufficient_data'
    current_value: float
    baseline_median: float
    mad: float
    modified_z: float
    direction: str  # 'up', 'down', 'flat'
    sample_size: int


def compute_mad_zscore(
    history: Sequence[float],
    current_value: float,
    *,
    min_samples: int = 4,
    breach_z: float = 3.5,
    borderline_z: float = 2.2,
) -> MadEvaluation:
    """Evaluate a point against historical telemetry using Median/MAD (Iglewicz & Hoaglin).

    Returns 'insufficient_data' when history has fewer than ``min_samples`` points so
    sparse rules never fabricate high-confidence statistical verdicts.
    """
    samples = [float(x) for x in history]
    n = len(samples)
    if n < min_samples:
        return MadEvaluation(
            status="insufficient_data",
            current_value=float(current_value),
            baseline_median=0.0,
            mad=0.0,
            modified_z=0.0,
            direction="flat",
            sample_size=n,
        )

    med = float(median(samples))
    abs_devs = [abs(x - med) for x in samples]
    raw_mad = float(median(abs_devs))
    delta = float(current_value) - med

    if delta > 0:
        direction = "up"
    elif delta < 0:
        direction = "down"
    else:
        direction = "flat"

    if raw_mad == 0.0:
        if delta == 0.0:
            mod_z = 0.0
        else:
            # Flat baseline: scale relative to max(median, 1.0) so genuine step-changes register
            scale = max(abs(med) * 0.15, 1.0)
            mod_z = (MAD_CONSISTENCY_CONSTANT * delta) / scale
    else:
        mod_z = (MAD_CONSISTENCY_CONSTANT * delta) / raw_mad

    abs_z = abs(mod_z)
    if abs_z >= breach_z:
        status = "breach"
    elif abs_z >= borderline_z:
        status = "borderline"
    else:
        status = "healthy"

    return MadEvaluation(
        status=status,
        current_value=round(float(current_value), 3),
        baseline_median=round(med, 3),
        mad=round(raw_mad, 3),
        modified_z=round(mod_z, 3),
        direction=direction,
        sample_size=n,
    )


def evaluate_log_volume_by_weekday(
    history_by_weekday: Dict[str, List[float]],
    weekday: str,
    current_count: float,
    *,
    min_weeks: int = 4,
) -> MadEvaluation:
    """Compare a log source's volume against the same day-of-week (e.g. Tuesday vs Tuesdays).

    Prevents quiet Saturdays/Sundays on corporate SaaS/Identity feeds from paging as outages.
    """
    day_key = weekday.strip().lower()
    series = history_by_weekday.get(day_key, [])
    return compute_mad_zscore(series, current_count, min_samples=min_weeks)


def evaluate_ingestion_latency_pooled(
    latency_minutes_history: Sequence[float],
    current_lag_minutes: float,
    *,
    min_samples: int = 6,
) -> MadEvaluation:
    """Evaluate pipeline ingestion lag using a pooled per-source baseline (not weekday-split).

    Ingestion latency is a transport pipeline characteristic rather than a business-hours
    characteristic: feeds with steady 30-minute delivery stay green, while sudden 3-hour
    drift triggers immediately.
    """
    return compute_mad_zscore(
        latency_minutes_history,
        current_lag_minutes,
        min_samples=min_samples,
    )
