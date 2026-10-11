"""Ingestion: validate, route by customer_id, store, and log every rejection.

Transport-independent so the HTTP API, scripts and tests share one path.
"""

from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from contracts import EventValidationError, validate_event
from keewano.rejects import RejectsLog
from keewano.storage import (
    Artifact,
    ArtifactExists,
    DuplicateEvent,
    EventStore,
    UnknownTenant,
    tenant_of,
)


@dataclass
class IngestResult:
    accepted: list[str] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)

    def response(self) -> dict[str, list]:
        """dev-B §4a.6 body: {"accepted": [event_id...], "rejected": [{event_id, reason}]}."""
        return {"accepted": self.accepted, "rejected": self.rejected}


class Ingestor:
    def __init__(self, store: EventStore, rejects: RejectsLog, tenants: tuple[str, ...]):
        self.store = store
        self.rejects = rejects
        self.tenants = frozenset(tenants)

    def _reject(self, result, index, raw, event_id, reason, customer_id=None):
        self.rejects.record(
            kind="event",
            reason=reason,
            raw=raw,
            event_id=event_id,
            customer_id=customer_id,
            index=index,
        )
        result.rejected.append({"event_id": event_id, "reason": reason})

    def ingest(self, raw_events: list[Any]) -> IngestResult:
        """Each event is accepted or rejected on its own; input order is kept."""
        result = IngestResult()
        for i, raw in enumerate(raw_events):
            if not isinstance(raw, dict):
                self._reject(result, i, raw, None, "event must be a JSON object")
                continue
            claimed = raw.get("customer_id")
            claimed = claimed if isinstance(claimed, str) else None
            try:
                event = validate_event(raw)
            except EventValidationError as e:
                self._reject(result, i, raw, e.event_id, e.reason, claimed)
                continue
            cid = event.customer_id
            if cid not in self.tenants:
                self._reject(result, i, raw, event.event_id, f"unknown customer_id {cid!r}", cid)
                continue
            try:
                self.store.write_event(event)
            except UnknownTenant:
                reason = f"unknown customer_id {cid!r} (store not set up for it)"
                self._reject(result, i, raw, event.event_id, reason, cid)
                continue
            except DuplicateEvent as e:
                self._reject(result, i, raw, event.event_id, str(e), cid)
                continue
            result.accepted.append(event.event_id)
        return result

    def put_artifact(self, raw: Any) -> str:
        """Store one artifact; returns its evidence_ref. Raises ArtifactRejected."""
        if not isinstance(raw, dict):
            return self._artifact_reject(raw, "artifact must be a JSON object")
        ref = raw.get("evidence_ref")
        if not isinstance(ref, str):
            return self._artifact_reject(raw, "evidence_ref: required string")
        try:
            cid = tenant_of(ref)
        except ValueError as e:
            return self._artifact_reject(raw, str(e))
        if cid not in self.tenants:
            return self._artifact_reject(raw, f"unknown customer_id {cid!r}", cid)
        try:
            artifact = Artifact.model_validate(
                {k: v for k, v in raw.items() if k != "evidence_ref"}
            )
        except ValidationError as e:
            reason = "; ".join(f"{'.'.join(map(str, x['loc']))}: {x['msg']}" for x in e.errors())
            return self._artifact_reject(raw, reason, cid)
        try:
            self.store.put_artifact(ref, artifact)
        except (UnknownTenant, ArtifactExists) as e:
            return self._artifact_reject(raw, str(e), cid, conflict=isinstance(e, ArtifactExists))
        return ref

    def _artifact_reject(self, raw, reason, customer_id=None, conflict=False):
        self.rejects.record(kind="artifact", reason=reason, raw=raw, customer_id=customer_id)
        raise ArtifactRejected(reason, conflict=conflict)


class ArtifactRejected(ValueError):
    def __init__(self, reason: str, conflict: bool = False):
        super().__init__(reason)
        self.reason = reason
        self.conflict = conflict
