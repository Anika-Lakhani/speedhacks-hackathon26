"""The one validation entry point for events (sites, ingestion, read API, fixtures).

from contracts import validate_event, validate_batch

event = validate_event(raw)                 # raises EventValidationError
result = validate_batch(raw_list, customer_id="customer-a")
result.accepted, result.rejected            # §4a.6 POST /events response shape
"""

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from contracts.events import Event

RawEvent = Event | Mapping[str, Any] | str | bytes


class EventValidationError(ValueError):
    """An event broke the contract. `reason` is a one-line, human-readable summary."""

    def __init__(self, reason: str, event_id: str | None = None):
        super().__init__(reason)
        self.reason = reason
        self.event_id = event_id


@dataclass(frozen=True)
class Rejection:
    index: int
    event_id: str | None
    reason: str


@dataclass(frozen=True)
class BatchResult:
    accepted: list[Event] = field(default_factory=list)
    rejected: list[Rejection] = field(default_factory=list)

    def response(self) -> dict[str, list]:
        """Body for POST /events: {"accepted": [event_id...], "rejected": [{event_id, reason}]}."""
        return {
            "accepted": [e.event_id for e in self.accepted],
            "rejected": [{"event_id": r.event_id, "reason": r.reason} for r in self.rejected],
        }


def _format(err: ValidationError) -> str:
    parts = []
    for e in err.errors():
        loc = ".".join(str(p) for p in e["loc"])
        msg = e["msg"].removeprefix("Value error, ")
        parts.append(f"{loc}: {msg}" if loc else msg)
    return "; ".join(parts)


def _raw_event_id(raw: Any) -> str | None:
    if isinstance(raw, Mapping):
        eid = raw.get("event_id")
        return eid if isinstance(eid, str) else None
    return None


def validate_event(raw: RawEvent) -> Event:
    """Validate one event (model, dict, or JSON text) against the v1.1 contract."""
    if isinstance(raw, Event):
        return raw
    if isinstance(raw, (str, bytes)):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as e:
            raise EventValidationError(f"invalid JSON: {e}") from e
    if not isinstance(raw, Mapping):
        raise EventValidationError(f"event must be a JSON object, got {type(raw).__name__}")
    try:
        return Event.model_validate(raw)
    except ValidationError as e:
        raise EventValidationError(_format(e), _raw_event_id(raw)) from e


def validate_batch(raw_events: Iterable[RawEvent], customer_id: str | None = None) -> BatchResult:
    """Validate each event independently; one bad event never rejects the rest.

    With `customer_id`, events for any other tenant are rejected (tenant isolation on ingest).
    """
    result = BatchResult()
    for i, raw in enumerate(raw_events):
        try:
            event = validate_event(raw)
        except EventValidationError as e:
            result.rejected.append(Rejection(i, e.event_id, e.reason))
            continue
        if customer_id is not None and event.customer_id != customer_id:
            reason = f"customer_id mismatch: expected {customer_id!r}, got {event.customer_id!r}"
            result.rejected.append(Rejection(i, event.event_id, reason))
            continue
        result.accepted.append(event)
    return result
