"""Ingestion API (POST /events, POST /evidence), rejects log, and fixtures."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from contracts import make_evidence_ref, validate_event
from keewano import fixtures
from keewano.api import create_app
from keewano.config import Settings
from keewano.storage import StoreNotConfigured

FIXTURES = Path(__file__).parents[1] / "fixtures" / "events"


def organic(cid="customer-a", **kw):
    base = {
        "customer_id": cid,
        "ts": "2026-10-11T12:00:00Z",
        "actor": "user",
        "event_type": "auth.login",
        "target": "/login",
        "action": "login",
        "policy_outcome": "allow",
        "code_revision": "r1",
        "simulated": False,
    }
    return base | kw


def probe_result(cid="customer-a", eid="3f1c2b9e-0000-4000-8000-000000000001", run="run-7"):
    return {
        "event_id": eid,
        "customer_id": cid,
        "ts": "2026-10-11T12:05:00Z",
        "run_id": run,
        "actor": "system",
        "tool": f"{cid}-site",
        "event_type": "probe.result",
        "target": "/orders/{id}",
        "action": "GET /orders/1002",
        "policy_outcome": "allow",
        "code_revision": "r1",
        "simulated": True,
        "evidence_ref": make_evidence_ref(cid, run, eid),
        "scenario_id": "SCN-IDOR-001",
        "attrs": {"flag": "idor_orders", "flag_on": True},
    }


@pytest.fixture
def app(tmp_path):
    settings = Settings(
        sqlite_path=tmp_path / "store.sqlite3",
        rejects_path=tmp_path / "rejects.jsonl",
        tenants=("customer-a", "customer-b", "customer-c"),
    )
    return create_app(settings)


@pytest.fixture
def client(app):
    return TestClient(app)


def stored(app, cid):
    return app.state.store.query_events(cid)


def rejects(app):
    return app.state.rejects.read()


def test_single_valid_event_lands_in_right_tenant(app, client):
    r = client.post("/events", json=organic("customer-b", event_id="e-b1"))
    assert r.status_code == 200
    assert r.json() == {"accepted": ["e-b1"], "rejected": []}
    assert [e.event_id for e in stored(app, "customer-b")] == ["e-b1"]
    assert stored(app, "customer-a") == [] and stored(app, "customer-c") == []
    assert rejects(app) == []


def test_malformed_event_rejected_and_logged(app, client):
    bad = organic(event_id="e-bad", simulated="true")
    r = client.post("/events", json=[bad])
    body = r.json()
    assert body["accepted"] == []
    assert body["rejected"][0]["event_id"] == "e-bad"
    assert "simulated" in body["rejected"][0]["reason"]
    [entry] = rejects(app)
    assert entry["kind"] == "event" and entry["event_id"] == "e-bad"
    assert entry["customer_id"] == "customer-a"
    assert entry["raw"] == bad
    assert stored(app, "customer-a") == []


def test_missing_customer_id_rejected_and_logged(app, client):
    r = client.post("/events", json=[{k: v for k, v in organic().items() if k != "customer_id"}])
    assert "customer_id" in r.json()["rejected"][0]["reason"]
    assert rejects(app)[0]["customer_id"] is None


def test_unknown_tenant_rejected(app, client):
    r = client.post("/events", json=[organic("customer-z", event_id="e-z")])
    assert r.json() == {
        "accepted": [],
        "rejected": [{"event_id": "e-z", "reason": "unknown customer_id 'customer-z'"}],
    }
    assert rejects(app)[0]["customer_id"] == "customer-z"


def test_mixed_batch_handled_per_event(app, client):
    batch = [
        organic(event_id="ok-1"),
        organic(event_id="bad-enum", policy_outcome="block"),
        organic("customer-c", event_id="ok-2"),
        organic("customer-q", event_id="bad-tenant"),
        "not an object",
        organic(event_id="ok-1"),  # duplicate of the first
        probe_result(),
    ]
    body = client.post("/events", json=batch).json()
    assert body["accepted"] == ["ok-1", "ok-2", probe_result()["event_id"]]
    reasons = {r["event_id"]: r["reason"] for r in body["rejected"]}
    assert len(body["rejected"]) == 4
    assert "policy_outcome" in reasons["bad-enum"]
    assert "unknown customer_id" in reasons["bad-tenant"]
    assert "duplicate event_id" in reasons["ok-1"]
    assert "JSON object" in reasons[None]
    assert [e["index"] for e in rejects(app)] == [1, 3, 4, 5]
    assert len(stored(app, "customer-a")) == 2 and len(stored(app, "customer-c")) == 1


def test_probe_result_accepted_alongside_organic(app, client):
    body = client.post("/events", json=[organic(event_id="o1"), probe_result()]).json()
    assert body["rejected"] == []
    events = stored(app, "customer-a")
    assert [e.event_type for e in events] == ["auth.login", "probe.result"]
    assert events[1].simulated is True and events[1].scenario_id == "SCN-IDOR-001"


def test_swarm_event_from_dev_a_accepted(app, client):
    eid = "v1"
    verdict = probe_result(eid=eid) | {
        "actor": "swarm_agent",
        "tool": "attack-harness",
        "event_type": "swarm.verdict",
        "verdict": "confirmed",
        "policy_outcome": "flag",
        "attrs": {"confidence": 0.9},
    }
    assert client.post("/events", json=verdict).json()["accepted"] == [eid]


@pytest.mark.parametrize("payload", [b"{not json", b'"just a string"', b"42"])
def test_bad_request_body_rejected_and_logged(app, client, payload):
    r = client.post("/events", content=payload, headers={"content-type": "application/json"})
    assert r.status_code == 400
    assert r.json()["accepted"] == []
    assert rejects(app)[0]["kind"] == "request"


def test_artifact_upload_tenant_scoped(app, client):
    ref = probe_result()["evidence_ref"]
    artifact = {
        "evidence_ref": ref,
        "request": {"method": "GET", "path": "/orders/1002"},
        "response": {"status": 200, "body": {"order_id": "1002", "owner_user_id": "u-2"}},
        "flags_snapshot": {"idor_orders": True},
        "code_revision": "r1",
    }
    r = client.post("/evidence", json=artifact)
    assert r.status_code == 201 and r.json() == {"evidence_ref": ref}
    store = app.state.store
    assert store.get_artifact("customer-a", ref).response["status"] == 200
    assert store.get_artifact("customer-b", ref) is None
    assert client.post("/evidence", json=artifact).status_code == 409  # immutable


@pytest.mark.parametrize(
    "artifact, status",
    [
        ({"request": {}, "response": {}, "code_revision": "r"}, 422),  # no evidence_ref
        ({"evidence_ref": "http://x", "request": {}, "response": {}, "code_revision": "r"}, 422),
        (
            {
                "evidence_ref": make_evidence_ref("customer-z", "r", "e"),
                "request": {},
                "response": {},
                "code_revision": "r",
            },
            422,
        ),
        ({"evidence_ref": make_evidence_ref("customer-a", "r", "e"), "request": {}}, 422),
        ([1, 2], 422),
    ],
)
def test_bad_artifacts_rejected_and_logged(app, client, artifact, status):
    assert client.post("/evidence", json=artifact).status_code == status
    assert rejects(app)[-1]["kind"] == "artifact"


def test_keewano_store_fails_at_startup(tmp_path):
    with pytest.raises(StoreNotConfigured, match="not configured"):
        create_app(Settings(store="keewano", rejects_path=tmp_path / "r.jsonl"))


def test_health(client):
    assert client.get("/health").json()["store"] == "sqlite"


# --- fixtures (dev-B §4a.7) ---


@pytest.mark.parametrize("cid", ["customer-a", "customer-b", "customer-c"])
def test_fixture_files_are_current_and_valid(cid):
    lines = (FIXTURES / f"{cid}.jsonl").read_text(encoding="utf-8").splitlines()
    expected = [e.model_dump_json(exclude_none=True) for e in fixtures.build(cid)]
    assert lines == expected, "run: uv run python -m keewano.fixtures"
    events = [validate_event(line) for line in lines]
    assert {e.customer_id for e in events} == {cid}
    organic_events = [e for e in events if not e.simulated]
    probes = [e for e in events if e.event_type == "probe.result"]
    assert len(organic_events) == 50 and len(probes) == 4


def test_fixtures_ingest_cleanly(app, client):
    for cid in ("customer-a", "customer-b", "customer-c"):
        raws = [json.loads(line) for line in (FIXTURES / f"{cid}.jsonl").read_text().splitlines()]
        body = client.post("/events", json=raws).json()
        assert body["rejected"] == [] and len(body["accepted"]) == 54
        assert len(stored(app, cid)) == 54
