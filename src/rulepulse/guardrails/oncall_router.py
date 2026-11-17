"""Shift-aware on-call alert router with 30-minute handover overlap protection."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List


@dataclass(frozen=True)
class ShiftSlot:
    analyst: str
    start: datetime
    end: datetime


def resolve_oncall_analyst(
    schedule: List[ShiftSlot],
    event_time: datetime,
    *,
    handover_minutes: int = 30,
) -> str:
    """Resolve who receives a real-time watch alert during shift transitions.

    During the final ``handover_minutes`` of an outgoing shift, incoming alerts route to
    the incoming shift analyst so the outgoing analyst writing handover notes is not paged
    minutes before signing off.
    """
    ordered = sorted(schedule, key=lambda s: s.start)
    handover_delta = timedelta(minutes=handover_minutes)

    for idx, slot in enumerate(ordered):
        if slot.start <= event_time < slot.end:
            if (slot.end - event_time) <= handover_delta and (idx + 1) < len(ordered):
                next_slot = ordered[idx + 1]
                if next_slot.start <= slot.end:
                    return next_slot.analyst
            return slot.analyst

    return "unassigned-secops-queue"
