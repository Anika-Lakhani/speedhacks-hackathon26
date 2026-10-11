"""Builds the `swarm.*` events the harness emits (spec §6)."""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from contracts import Event, EventType, make_evidence_ref, new_event_id


class EventFactory:
    def __init__(
        self,
        customer_id: str,
        run_id: str,
        code_revision: str,
        knowledge_version: str,
        catalog_version: str,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ):
        self.customer_id = customer_id
        self.run_id = run_id
        self.code_revision = code_revision
        self.knowledge_version = knowledge_version
        self.catalog_version = catalog_version
        self._clock = clock

    def make(
        self,
        event_type: EventType,
        *,
        target: str,
        action: str,
        policy_outcome: str = "allow",
        scenario_id: str | None = None,
        verdict: str | None = None,
        evidence_ref: str | None = None,
        attrs: dict[str, Any] | None = None,
    ) -> Event:
        event_id = new_event_id()
        return Event(
            event_id=event_id,
            customer_id=self.customer_id,
            ts=self._clock(),
            run_id=self.run_id,
            actor="swarm_agent",
            tool="attack-harness",
            event_type=event_type.value,
            target=target,
            action=action,
            policy_outcome=policy_outcome,
            code_revision=self.code_revision,
            knowledge_version=self.knowledge_version,
            simulated=True,
            evidence_ref=evidence_ref or make_evidence_ref(self.customer_id, self.run_id, event_id),
            scenario_id=scenario_id,
            verdict=verdict,
            attrs={"catalog_version": self.catalog_version, **(attrs or {})},
        )
