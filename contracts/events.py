"""Keewano event schema v1.1 (overview §5.1, dev-B §4a.4).

Every event, organic or simulated, is one `Event`. B owns this contract; changes
need sign-off from A, B and C. Regenerate `event.schema.json` after any change:

    uv run python -m contracts
"""

import json
import re
import uuid
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from contracts.labels import Verdict

SCHEMA_VERSION = "1.1"
SCHEMA_PATH = Path(__file__).with_name("event.schema.json")

ORGANIC_RUN_SEGMENT = "organic"
_EVIDENCE_REF = re.compile(r"^ev://(?P<customer_id>[^/]+)/(?P<run_id>[^/]+)/(?P<event_id>[^/]+)$")


class Actor(StrEnum):
    USER = "user"
    SYSTEM = "system"
    SWARM_AGENT = "swarm_agent"


class PolicyOutcome(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    FLAG = "flag"


class EventType(StrEnum):
    """Event types with contract rules attached. Organic types are free-form strings."""

    PROBE_RESULT = "probe.result"
    SWARM_RUN_START = "swarm.run_start"
    SWARM_PLAN = "swarm.plan"
    SWARM_PROBE = "swarm.probe"
    SWARM_VERDICT = "swarm.verdict"
    SWARM_RUN_END = "swarm.run_end"


SWARM_PREFIX = "swarm."
# Events about one specific scenario; these must carry scenario_id.
SCENARIO_SCOPED = {EventType.PROBE_RESULT, EventType.SWARM_PROBE, EventType.SWARM_VERDICT}


def new_event_id() -> str:
    return str(uuid.uuid4())


def make_evidence_ref(customer_id: str, run_id: str | None, event_id: str) -> str:
    return f"ev://{customer_id}/{run_id or ORGANIC_RUN_SEGMENT}/{event_id}"


def parse_evidence_ref(ref: str) -> tuple[str, str | None, str]:
    """Return (customer_id, run_id, event_id); run_id is None for organic events."""
    m = _EVIDENCE_REF.match(ref)
    if not m:
        raise ValueError(f"malformed evidence_ref: {ref!r}")
    run_id = m["run_id"]
    return m["customer_id"], None if run_id == ORGANIC_RUN_SEGMENT else run_id, m["event_id"]


class Event(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=True)

    # --- v1 ---
    event_id: str = Field(default_factory=new_event_id, description="Primary key (uuid)")
    customer_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$", description="Tenant scope")
    ts: AwareDatetime = Field(description="Event time, timezone-aware ISO-8601")
    run_id: str | None = Field(
        default=None, description="Groups events from one run; null for organic events"
    )
    actor: Actor
    tool: str | None = Field(default=None, description="Tool/agent identity, if any")
    event_type: str = Field(min_length=1, description="e.g. auth.login, probe.result")
    target: str = Field(description="Endpoint/resource")
    action: str = Field(description="What was attempted")
    policy_outcome: PolicyOutcome
    state_transition: str | None = Field(default=None, description="Before->after, if relevant")
    code_revision: str = Field(min_length=1, description="Version of the site under test")
    knowledge_version: str | None = Field(
        default=None, description="Version of shared-intelligence.md in play"
    )
    simulated: bool = Field(description="True for anything the attack engine produces")
    evidence_ref: str | None = Field(
        default=None, description="ev://<customer_id>/<run_id|organic>/<event_id>"
    )

    # --- v1.1 ---
    scenario_id: str | None = Field(default=None, description="Scenario catalog ID")
    verdict: Verdict | None = Field(default=None, description="Only on swarm.verdict")
    attrs: dict[str, Any] | None = Field(
        default=None, description="Free-form extras; never required for parsing"
    )

    @model_validator(mode="after")
    def _check_contract(self) -> "Event":
        et = self.event_type
        is_swarm = et.startswith(SWARM_PREFIX)
        is_probe_result = et == EventType.PROBE_RESULT

        if is_swarm and et not in {e.value for e in EventType}:
            raise ValueError(f"unknown swarm event_type {et!r}")
        if is_swarm and self.actor != Actor.SWARM_AGENT:
            raise ValueError("swarm.* events must have actor=swarm_agent")
        if is_probe_result and self.actor != Actor.SYSTEM:
            raise ValueError("probe.result events must have actor=system")

        if is_swarm or is_probe_result:
            if not self.simulated:
                raise ValueError(f"{et} events must have simulated=true")
            if not self.run_id:
                raise ValueError(f"{et} events must have a run_id")
            if not self.evidence_ref:
                raise ValueError(f"{et} events must have an evidence_ref")

        if et in SCENARIO_SCOPED and not self.scenario_id:
            raise ValueError(f"{et} events must have a scenario_id")

        if et == EventType.SWARM_VERDICT:
            if self.verdict is None:
                raise ValueError("swarm.verdict events must have a verdict")
        elif self.verdict is not None:
            raise ValueError("verdict is only allowed on swarm.verdict events")

        if self.evidence_ref is not None:
            ref_customer, ref_run, _ = parse_evidence_ref(self.evidence_ref)
            if ref_customer != self.customer_id:
                raise ValueError("evidence_ref customer_id does not match event customer_id")
            if ref_run != self.run_id:
                raise ValueError("evidence_ref run_id does not match event run_id")

        return self


def json_schema() -> dict[str, Any]:
    schema = Event.model_json_schema()
    schema["$id"] = f"swarmshield/event/v{SCHEMA_VERSION}"
    return schema


def write_json_schema(path: Path = SCHEMA_PATH) -> None:
    path.write_text(json.dumps(json_schema(), indent=2) + "\n")
