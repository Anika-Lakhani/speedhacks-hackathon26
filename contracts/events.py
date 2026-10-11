"""Keewano event schema v1.1 (overview §5.1, dev-B §4a.4).

Every event, organic or simulated, is one `Event`. B owns this contract; changes
need sign-off from A, B and C. Regenerate `event.schema.json` after any change:

    uv run python -m contracts
"""

import json
import re
import uuid
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

from pydantic import (
    AwareDatetime,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StrictBool,
    model_validator,
)

from contracts.labels import Verdict

SCHEMA_VERSION = "1.1"
SCHEMA_PATH = Path(__file__).with_name("event.schema.json")

ORGANIC_RUN_SEGMENT = "organic"  # reserved: stands in for run_id in organic evidence refs
_EVIDENCE_REF = re.compile(r"^ev://(?P<customer_id>[^/]+)/(?P<run_id>[^/]+)/(?P<event_id>[^/]+)$")
# ids are path segments of evidence_ref, so they can't be empty or contain "/"
ID_SEGMENT_PATTERN = r"^[^/]+$"
EVIDENCE_REF_PATTERN = r"^ev://[^/]+/[^/]+/[^/]+$"
# RFC 3339 date-time with a mandatory offset; mirrored in the JSON Schema
TS_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
_TS = re.compile(TS_PATTERN)


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


def _check_ts(value: Any) -> Any:
    """Accept datetimes and RFC 3339 strings only; no epoch numbers or loose formats."""
    if isinstance(value, str):
        if not _TS.match(value):
            raise ValueError("ts must be RFC 3339 with a timezone, e.g. 2026-10-11T12:00:00Z")
    elif not isinstance(value, datetime):
        raise ValueError("ts must be a datetime or an RFC 3339 string")
    return value


Timestamp = Annotated[AwareDatetime, BeforeValidator(_check_ts)]


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
    event_id: str = Field(
        default_factory=new_event_id,
        pattern=ID_SEGMENT_PATTERN,
        description="Primary key; non-empty, no '/'. Defaults to a uuid4",
    )
    customer_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$", description="Tenant scope")
    ts: Timestamp = Field(description="Event time, RFC 3339 with timezone")
    run_id: str | None = Field(
        default=None,
        pattern=ID_SEGMENT_PATTERN,
        description="Groups events from one run; null for organic events. No '/', not 'organic'",
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
    simulated: StrictBool = Field(description="True for anything the attack engine produces")
    evidence_ref: str | None = Field(
        default=None,
        pattern=EVIDENCE_REF_PATTERN,
        description="ev://<customer_id>/<run_id|organic>/<event_id>",
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

        if self.run_id == ORGANIC_RUN_SEGMENT:
            raise ValueError(f"run_id {ORGANIC_RUN_SEGMENT!r} is reserved")
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


def _when(
    event_type_schema: dict[str, Any], then: dict[str, Any], otherwise: dict[str, Any] | None = None
) -> dict[str, Any]:
    rule = {
        "if": {"properties": {"event_type": event_type_schema}, "required": ["event_type"]},
        "then": then,
    }
    if otherwise is not None:
        rule["else"] = otherwise
    return rule


def _run_scoped(actor: Actor, **extra_props: Any) -> dict[str, Any]:
    """probe.result and swarm.*: simulated, with a run_id and an evidence_ref."""
    return {
        "properties": {
            **extra_props,
            "actor": {"const": actor.value},
            "simulated": {"const": True},
            "run_id": {"type": "string"},
            "evidence_ref": {"type": "string"},
        },
        "required": ["run_id", "evidence_ref"],
    }


def _scenario_required() -> dict[str, Any]:
    return {
        "properties": {"scenario_id": {"type": "string", "minLength": 1}},
        "required": ["scenario_id"],
    }


def json_schema() -> dict[str, Any]:
    """JSON Schema for Event, including the cross-field rules of `Event._check_contract`.

    One rule can't be expressed in JSON Schema and is enforced only by `Event`: evidence_ref
    must name the event's own customer_id and run_id.
    """
    schema = Event.model_json_schema()
    schema["$id"] = f"swarmshield/event/v{SCHEMA_VERSION}"
    props = schema["properties"]
    props["ts"]["pattern"] = TS_PATTERN
    props["run_id"]["not"] = {"const": ORGANIC_RUN_SEGMENT}

    swarm_types = sorted(e.value for e in EventType if e.value.startswith(SWARM_PREFIX))
    schema["allOf"] = [
        _when({"const": EventType.PROBE_RESULT.value}, _run_scoped(Actor.SYSTEM)),
        _when(
            {"pattern": rf"^{re.escape(SWARM_PREFIX)}"},
            _run_scoped(Actor.SWARM_AGENT, event_type={"enum": swarm_types}),
        ),
        _when({"enum": sorted(e.value for e in SCENARIO_SCOPED)}, _scenario_required()),
        _when(
            {"const": EventType.SWARM_VERDICT.value},
            {"properties": {"verdict": {"$ref": "#/$defs/Verdict"}}, "required": ["verdict"]},
            otherwise={"properties": {"verdict": {"type": "null"}}},
        ),
    ]
    return schema


def write_json_schema(path: Path = SCHEMA_PATH) -> None:
    path.write_text(json.dumps(json_schema(), indent=2) + "\n")
