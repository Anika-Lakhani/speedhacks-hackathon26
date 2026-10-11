import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from contracts import Event, make_evidence_ref, parse_evidence_ref
from contracts.events import SCHEMA_PATH, json_schema

TS = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)
RUN = "run-1"


def organic(**kw):
    base = dict(
        customer_id="customer-a",
        ts=TS,
        actor="user",
        event_type="auth.login",
        target="/login",
        action="login",
        policy_outcome="allow",
        code_revision="abc123",
        simulated=False,
    )
    return Event(**(base | kw))


def swarm(event_type, **kw):
    eid = kw.pop("event_id", "e1")
    base = dict(
        event_id=eid,
        customer_id="customer-a",
        ts=TS,
        run_id=RUN,
        actor="swarm_agent",
        tool="attack-harness",
        event_type=event_type,
        target="/orders/{id}",
        action="probe",
        policy_outcome="flag",
        code_revision="abc123",
        knowledge_version="0.1.0",
        simulated=True,
        evidence_ref=make_evidence_ref("customer-a", RUN, eid),
        scenario_id="SCN-IDOR-001",
    )
    return Event(**(base | kw))


def test_organic_event_minimal():
    e = organic()
    assert e.run_id is None and e.evidence_ref is None
    assert len(e.event_id) == 36


def test_roundtrip_json():
    e = swarm("swarm.verdict", verdict="confirmed", attrs={"confidence": 0.9})
    assert Event.model_validate_json(e.model_dump_json()) == e


def test_naive_timestamp_rejected():
    with pytest.raises(ValidationError):
        organic(ts=datetime(2026, 10, 11))


def test_unknown_field_rejected():
    with pytest.raises(ValidationError):
        organic(severity="high")


@pytest.mark.parametrize(
    "kw",
    [
        {"simulated": False},
        {"run_id": None, "evidence_ref": make_evidence_ref("customer-a", None, "e1")},
        {"actor": "system"},
        {"scenario_id": None},
    ],
)
def test_swarm_probe_contract(kw):
    with pytest.raises(ValidationError):
        swarm("swarm.probe", **kw)


def test_verdict_required_on_swarm_verdict_only():
    with pytest.raises(ValidationError):
        swarm("swarm.verdict")
    with pytest.raises(ValidationError):
        swarm("swarm.probe", verdict="confirmed")


def test_run_start_needs_no_scenario():
    swarm("swarm.run_start", scenario_id=None)


def test_unknown_swarm_type_rejected():
    with pytest.raises(ValidationError):
        swarm("swarm.exploit")


def test_probe_result_is_system_actor():
    swarm("probe.result", actor="system")
    with pytest.raises(ValidationError):
        swarm("probe.result")


def test_evidence_ref_must_match_tenant_and_run():
    with pytest.raises(ValidationError):
        swarm("swarm.probe", evidence_ref=make_evidence_ref("customer-b", RUN, "e1"))
    with pytest.raises(ValidationError):
        swarm("swarm.probe", evidence_ref=make_evidence_ref("customer-a", "run-2", "e1"))


def test_evidence_ref_roundtrip():
    assert parse_evidence_ref(make_evidence_ref("customer-a", None, "x")) == (
        "customer-a",
        None,
        "x",
    )
    with pytest.raises(ValueError):
        parse_evidence_ref("http://nope")


def test_committed_json_schema_is_current():
    assert json.loads(SCHEMA_PATH.read_text()) == json_schema(), "run: uv run python -m contracts"
