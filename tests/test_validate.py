"""Contract v1.1 validation: contracts.validate and the generated JSON Schema must agree."""

import json

import pytest
from jsonschema import Draft202012Validator

from contracts import (
    Event,
    EventValidationError,
    make_evidence_ref,
    validate_batch,
    validate_event,
)
from contracts.events import SCHEMA_PATH

RUN = "run-7"
PROBE_ID = "3f1c2b9e-5d4a-4c1e-9a7b-2e6f8d0c1a55"

ORGANIC = {
    "event_id": "8b0e6c2a-1f3d-4e5b-9c7a-6d2f1e0b3c44",
    "customer_id": "customer-a",
    "ts": "2026-10-11T12:00:00Z",
    "run_id": None,
    "actor": "user",
    "tool": None,
    "event_type": "auth.login",
    "target": "/login",
    "action": "login",
    "policy_outcome": "allow",
    "state_transition": "anonymous->authenticated",
    "code_revision": "a1b2c3d",
    "knowledge_version": None,
    "simulated": False,
    "evidence_ref": None,
}

PROBE_RESULT = {
    "event_id": PROBE_ID,
    "customer_id": "customer-a",
    "ts": "2026-10-11T12:05:00.123+00:00",
    "run_id": RUN,
    "actor": "system",
    "tool": "customer-a-site",
    "event_type": "probe.result",
    "target": "/orders/{id}",
    "action": "GET /orders/1002",
    "policy_outcome": "allow",
    "code_revision": "a1b2c3d",
    "knowledge_version": None,
    "simulated": True,
    "evidence_ref": make_evidence_ref("customer-a", RUN, PROBE_ID),
    "scenario_id": "SCN-IDOR-001",
    "attrs": {"flag": "idor_orders", "flag_on": True},
}

SCHEMA = Draft202012Validator(json.loads(SCHEMA_PATH.read_text()))


def drop(base, *keys):
    return {k: v for k, v in base.items() if k not in keys}


def with_(base, **kw):
    return base | kw


VALID = {
    "organic": ORGANIC,
    "organic_minimal": drop(
        ORGANIC,
        "event_id",
        "run_id",
        "tool",
        "state_transition",
        "knowledge_version",
        "evidence_ref",
    ),
    "organic_with_evidence": with_(
        ORGANIC, evidence_ref=make_evidence_ref("customer-a", None, ORGANIC["event_id"])
    ),
    "organic_offset_ts": with_(ORGANIC, ts="2026-10-11T05:00:00-07:00"),
    "probe_result": PROBE_RESULT,
    "probe_result_deny": with_(
        PROBE_RESULT, policy_outcome="deny", attrs={"flag": "idor_orders", "flag_on": False}
    ),
    "probe_result_no_attrs": drop(PROBE_RESULT, "attrs"),
    "non_uuid_event_id": with_(ORGANIC, event_id="e1"),
}

INVALID = {
    # missing fields
    "missing_customer_id": drop(ORGANIC, "customer_id"),
    "missing_ts": drop(ORGANIC, "ts"),
    "missing_actor": drop(ORGANIC, "actor"),
    "missing_event_type": drop(ORGANIC, "event_type"),
    "missing_target": drop(ORGANIC, "target"),
    "missing_action": drop(ORGANIC, "action"),
    "missing_policy_outcome": drop(ORGANIC, "policy_outcome"),
    "missing_code_revision": drop(ORGANIC, "code_revision"),
    "missing_simulated": drop(ORGANIC, "simulated"),
    # wrong types
    "customer_id_int": with_(ORGANIC, customer_id=7),
    "customer_id_bad_format": with_(ORGANIC, customer_id="Customer_A"),
    "customer_id_null": with_(ORGANIC, customer_id=None),
    "ts_epoch_number": with_(ORGANIC, ts=1760184000),
    "ts_naive": with_(ORGANIC, ts="2026-10-11T12:00:00"),
    "ts_garbage": with_(ORGANIC, ts="yesterday"),
    "target_int": with_(ORGANIC, target=42),
    "attrs_list": with_(ORGANIC, attrs=["x"]),
    "code_revision_empty": with_(ORGANIC, code_revision=""),
    "event_type_empty": with_(ORGANIC, event_type=""),
    # simulated must be a real boolean
    "simulated_str_true": with_(ORGANIC, simulated="true"),
    "simulated_int_1": with_(ORGANIC, simulated=1),
    "simulated_str_yes": with_(ORGANIC, simulated="yes"),
    "simulated_null": with_(ORGANIC, simulated=None),
    # bad enums
    "actor_bad": with_(ORGANIC, actor="admin"),
    "policy_outcome_bad": with_(ORGANIC, policy_outcome="block"),
    "policy_outcome_case": with_(ORGANIC, policy_outcome="ALLOW"),
    "verdict_bad": with_(ORGANIC, event_type="swarm.verdict", verdict="pwned"),
    # ids
    "event_id_empty": with_(ORGANIC, event_id=""),
    "event_id_slash": with_(ORGANIC, event_id="a/b"),
    "run_id_organic": with_(
        PROBE_RESULT,
        run_id="organic",
        evidence_ref=make_evidence_ref("customer-a", "organic", PROBE_ID),
    ),
    "run_id_slash": with_(ORGANIC, run_id="run/1"),
    "run_id_empty": with_(ORGANIC, run_id=""),
    "evidence_ref_malformed": with_(ORGANIC, evidence_ref="http://example/x"),
    # unknown fields
    "unknown_field": with_(ORGANIC, severity="high"),
    # probe.result contract
    "probe_missing_scenario_id": drop(PROBE_RESULT, "scenario_id"),
    "probe_empty_scenario_id": with_(PROBE_RESULT, scenario_id=""),
    "probe_missing_evidence_ref": drop(PROBE_RESULT, "evidence_ref"),
    "probe_null_evidence_ref": with_(PROBE_RESULT, evidence_ref=None),
    "probe_missing_run_id": drop(PROBE_RESULT, "run_id"),
    "probe_not_simulated": with_(PROBE_RESULT, simulated=False),
    "probe_wrong_actor": with_(PROBE_RESULT, actor="swarm_agent"),
    "probe_with_verdict": with_(PROBE_RESULT, verdict="confirmed"),
    # swarm.* contract
    "swarm_unknown_type": with_(PROBE_RESULT, event_type="swarm.exploit", actor="swarm_agent"),
    "swarm_verdict_missing_verdict": with_(
        PROBE_RESULT, event_type="swarm.verdict", actor="swarm_agent"
    ),
}

# Enforced by contracts.Event only; JSON Schema can't compare two fields.
PYDANTIC_ONLY = {
    "probe_evidence_other_tenant": with_(
        PROBE_RESULT, evidence_ref=make_evidence_ref("customer-b", RUN, PROBE_ID)
    ),
    "probe_evidence_other_run": with_(
        PROBE_RESULT, evidence_ref=make_evidence_ref("customer-a", "run-8", PROBE_ID)
    ),
}


def schema_errors(raw):
    return list(SCHEMA.iter_errors(raw))


@pytest.mark.parametrize("raw", VALID.values(), ids=VALID.keys())
def test_valid_events_accepted(raw):
    event = validate_event(raw)
    assert isinstance(event, Event)
    assert schema_errors(raw) == []


@pytest.mark.parametrize("raw", INVALID.values(), ids=INVALID.keys())
def test_invalid_events_rejected_by_both(raw):
    with pytest.raises(EventValidationError):
        validate_event(raw)
    assert schema_errors(raw), "JSON Schema accepted an event pydantic rejects"


@pytest.mark.parametrize("raw", PYDANTIC_ONLY.values(), ids=PYDANTIC_ONLY.keys())
def test_cross_field_evidence_rules_pydantic_only(raw):
    with pytest.raises(EventValidationError):
        validate_event(raw)
    assert schema_errors(raw) == []  # documented gap in json_schema()


def test_serialized_events_validate_against_schema():
    for raw in VALID.values():
        event = validate_event(raw)
        dumped = json.loads(event.model_dump_json())
        assert schema_errors(dumped) == []
        assert validate_event(dumped) == event


def test_default_event_id_is_uuid4():
    event = validate_event(VALID["organic_minimal"])
    assert len(event.event_id) == 36 and event.event_id[14] == "4"


def test_validate_event_accepts_json_text_and_models():
    text = json.dumps(PROBE_RESULT)
    event = validate_event(text)
    assert validate_event(event) is event
    assert validate_event(text.encode()) == event


@pytest.mark.parametrize("raw", ["{not json", "[1, 2]", "42"])
def test_validate_event_rejects_non_objects(raw):
    with pytest.raises(EventValidationError):
        validate_event(raw)


def test_rejection_reason_names_the_field():
    with pytest.raises(EventValidationError) as exc:
        validate_event(drop(ORGANIC, "customer_id"))
    assert "customer_id" in exc.value.reason
    assert exc.value.event_id == ORGANIC["event_id"]


def test_batch_partial_accept():
    result = validate_batch([ORGANIC, INVALID["simulated_str_true"], PROBE_RESULT])
    assert [e.event_id for e in result.accepted] == [ORGANIC["event_id"], PROBE_ID]
    assert [r.index for r in result.rejected] == [1]
    assert "simulated" in result.rejected[0].reason


def test_batch_rejects_other_tenant():
    other = with_(ORGANIC, customer_id="customer-b", event_id="other-1")
    result = validate_batch([ORGANIC, other], customer_id="customer-a")
    assert len(result.accepted) == 1
    assert result.rejected[0].event_id == "other-1"
    assert "customer_id mismatch" in result.rejected[0].reason


def test_batch_response_shape():
    body = validate_batch([ORGANIC, drop(ORGANIC, "ts")]).response()
    assert body["accepted"] == [ORGANIC["event_id"]]
    assert body["rejected"][0]["event_id"] == ORGANIC["event_id"]
    assert set(body["rejected"][0]) == {"event_id", "reason"}


def test_doc_examples_match_and_validate():
    import re
    from pathlib import Path

    doc = (Path(__file__).parents[1] / "docs" / "event-schema.md").read_text(encoding="utf-8")
    blocks = [json.loads(b) for b in re.findall(r"```json\n(.*?)```", doc, re.S)]
    assert blocks == [ORGANIC, PROBE_RESULT]
    for raw in blocks:
        validate_event(raw)
        assert schema_errors(raw) == []
