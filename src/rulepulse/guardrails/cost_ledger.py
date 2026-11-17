"""Append-only JSONL token and USD cost ledger with zero-LLM local budget reporting."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict


class CostLedger:
    """Tracks every LLM call's token count and exact USD cost in an inspectable JSONL file."""

    # Default pricing per 1M tokens (configurable per model)
    INPUT_USD_PER_1M = 0.15
    OUTPUT_USD_PER_1M = 0.60

    def __init__(self, ledger_path: Path) -> None:
        self.ledger_path = ledger_path
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)

    def record_call(
        self,
        *,
        subject_id: str,
        model: str,
        prompt_tokens: int,
        output_tokens: int,
        cached: bool = False,
    ) -> Dict[str, Any]:
        cost_usd = 0.0
        if not cached:
            cost_usd = (
                (prompt_tokens / 1_000_000.0) * self.INPUT_USD_PER_1M
                + (output_tokens / 1_000_000.0) * self.OUTPUT_USD_PER_1M
            )
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "subject_id": subject_id,
            "model": model,
            "prompt_tokens": int(prompt_tokens),
            "output_tokens": int(output_tokens),
            "cached": bool(cached),
            "cost_usd": round(cost_usd, 6),
        }
        with self.ledger_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        return entry

    def summarize(self, now: datetime | None = None) -> Dict[str, Any]:
        """Compute daily, 7-day, and 30-day token & USD spend strictly from local JSONL."""
        ref = now or datetime.now(timezone.utc)
        buckets = {
            "daily": {"calls": 0, "cached_hits": 0, "tokens": 0, "cost_usd": 0.0},
            "weekly": {"calls": 0, "cached_hits": 0, "tokens": 0, "cost_usd": 0.0},
            "monthly": {"calls": 0, "cached_hits": 0, "tokens": 0, "cost_usd": 0.0},
        }
        if not self.ledger_path.exists():
            return buckets

        for line in self.ledger_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            ts = datetime.fromisoformat(row["timestamp"])
            age = ref - ts
            targets = []
            if age <= timedelta(days=1):
                targets.append("daily")
            if age <= timedelta(days=7):
                targets.append("weekly")
            if age <= timedelta(days=30):
                targets.append("monthly")
            for key in targets:
                if row.get("cached"):
                    buckets[key]["cached_hits"] += 1
                else:
                    buckets[key]["calls"] += 1
                    buckets[key]["tokens"] += int(row["prompt_tokens"]) + int(row["output_tokens"])
                    buckets[key]["cost_usd"] = round(
                        buckets[key]["cost_usd"] + float(row["cost_usd"]), 6
                    )
        return buckets
