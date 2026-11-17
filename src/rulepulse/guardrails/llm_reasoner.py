"""Bounded LLM escalation engine — strictly off the primary detection path."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from rulepulse.guardrails.cost_ledger import CostLedger
from rulepulse.stats.mad_baseline import MadEvaluation


@dataclass
class EscalationDecision:
    subject_id: str
    disposition: str  # 'no_llm_needed', 'escalate_oncall', 'suppress_digest', 'needs_review'
    llm_invoked: bool
    cache_hit: bool
    rationale: str


class BoundedLLMReasoner:
    """Enforces 4 hard guardrails around model adjudication on borderline anomalies:

    1. Model cannot invent a flag unless statistical deviation already points in the breach direction.
    2. Metric-fingerprint cache prevents re-billing chronically borderline items every poll cycle.
    3. Hard ``max_calls_per_run`` budget degrades excess items safely to ``needs_review`` (weekly digest).
    4. Any API failure or missing API key degrades to ``needs_review`` — never pages on-call at 2 a.m.
    """

    def __init__(
        self,
        *,
        ledger: CostLedger,
        max_calls_per_run: int = 5,
        provider_fn: Optional[Callable[[str, Dict[str, Any]], Dict[str, Any]]] = None,
    ) -> None:
        self.ledger = ledger
        self.max_calls_per_run = max_calls_per_run
        self.provider_fn = provider_fn
        self.calls_this_run = 0
        self._cache: Dict[str, EscalationDecision] = {}

    def reset_run_budget(self) -> None:
        self.calls_this_run = 0

    @staticmethod
    def _fingerprint(subject_id: str, evaluation: MadEvaluation, context: Dict[str, Any]) -> str:
        payload = {
            "subject_id": subject_id,
            "status": evaluation.status,
            "direction": evaluation.direction,
            "z_bucket": round(evaluation.modified_z, 1),
            "median": round(evaluation.baseline_median, 1),
            "context": context,
        }
        raw = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]

    def adjudicate_borderline(
        self,
        subject_id: str,
        evaluation: MadEvaluation,
        *,
        expected_direction: str = "up",
        context: Optional[Dict[str, Any]] = None,
    ) -> EscalationDecision:
        ctx = context or {}

        # Guardrail 1: Never invoke LLM on healthy, clear breach, or wrong-direction metrics
        if evaluation.status != "borderline" or evaluation.direction != expected_direction:
            return EscalationDecision(
                subject_id=subject_id,
                disposition="no_llm_needed",
                llm_invoked=False,
                cache_hit=False,
                rationale=(
                    f"Deterministic path sufficient (status={evaluation.status}, "
                    f"direction={evaluation.direction})."
                ),
            )

        # Guardrail 2: Serve cached verdict if metric fingerprint has not materially changed
        fp = self._fingerprint(subject_id, evaluation, ctx)
        if fp in self._cache:
            cached_decision = self._cache[fp]
            self.ledger.record_call(
                subject_id=subject_id,
                model="cache",
                prompt_tokens=0,
                output_tokens=0,
                cached=True,
            )
            return EscalationDecision(
                subject_id=subject_id,
                disposition=cached_decision.disposition,
                llm_invoked=False,
                cache_hit=True,
                rationale=cached_decision.rationale,
            )

        # Guardrail 3: Hard per-run call cap -> degrade to weekly digest ('needs_review')
        if self.calls_this_run >= self.max_calls_per_run:
            return EscalationDecision(
                subject_id=subject_id,
                disposition="needs_review",
                llm_invoked=False,
                cache_hit=False,
                rationale=(
                    f"Per-run LLM call budget ({self.max_calls_per_run}) exhausted; "
                    "routed to weekly digest without paging on-call."
                ),
            )

        # Guardrail 4: Offline / no provider / API error -> safe degradation to 'needs_review'
        if self.provider_fn is None:
            return EscalationDecision(
                subject_id=subject_id,
                disposition="needs_review",
                llm_invoked=False,
                cache_hit=False,
                rationale="No live LLM provider configured; routed to weekly digest (needs_review).",
            )

        try:
            self.calls_this_run += 1
            resp = self.provider_fn(subject_id, {"evaluation": evaluation.__dict__, **ctx})
            verdict = str(resp.get("verdict", "needs_review"))
            if verdict not in ("escalate_oncall", "suppress_digest", "needs_review"):
                verdict = "needs_review"
            self.ledger.record_call(
                subject_id=subject_id,
                model=str(resp.get("model", "gemini-flash")),
                prompt_tokens=int(resp.get("prompt_tokens", 280)),
                output_tokens=int(resp.get("output_tokens", 90)),
                cached=False,
            )
            decision = EscalationDecision(
                subject_id=subject_id,
                disposition=verdict,
                llm_invoked=True,
                cache_hit=False,
                rationale=str(resp.get("rationale", "Bounded second-opinion completed.")),
            )
            self._cache[fp] = decision
            return decision
        except Exception as exc:  # noqa: BLE001
            return EscalationDecision(
                subject_id=subject_id,
                disposition="needs_review",
                llm_invoked=True,
                cache_hit=False,
                rationale=f"LLM provider error ({exc}); degraded safely to weekly digest.",
            )
