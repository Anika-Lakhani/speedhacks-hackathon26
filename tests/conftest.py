from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from contracts import make_evidence_ref
from keewano.api import create_app
from keewano.config import Settings

TENANTS = ("customer-a", "customer-b", "customer-c")
T0 = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)


def iso(minutes: float) -> str:
    return (T0 + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def make_organic(cid, n, minutes, revision="r1", event_type="auth.login"):
    return {
        "event_id": f"{cid}-o{n}",
        "customer_id": cid,
        "ts": iso(minutes),
        "actor": "user",
        "event_type": event_type,
        "target": "/login",
        "action": "login",
        "policy_outcome": "allow",
        "code_revision": revision,
        "simulated": False,
    }


def make_probe(cid, n, minutes, run_id, revision="r1"):
    eid = f"{cid}-p{n}"
    return {
        "event_id": eid,
        "customer_id": cid,
        "ts": iso(minutes),
        "run_id": run_id,
        "actor": "system",
        "tool": f"{cid}-site",
        "event_type": "probe.result",
        "target": "/orders/{id}",
        "action": "GET /orders/1002",
        "policy_outcome": "allow",
        "code_revision": revision,
        "simulated": True,
        "evidence_ref": make_evidence_ref(cid, run_id, eid),
        "scenario_id": "SCN-IDOR-001",
        "attrs": {"flag": "idor_orders", "flag_on": True},
    }


def make_artifact(ref, revision="r1"):
    return {
        "evidence_ref": ref,
        "request": {
            "method": "GET",
            "path": "/orders/1002",
            "headers": {"X-SwarmShield-Probe": "SCN-IDOR-001"},
        },
        "response": {"status": 200, "body": {"order_id": "1002", "owner_user_id": "u-2"}},
        "flags_snapshot": {"idor_orders": True},
        "code_revision": revision,
    }


@pytest.fixture
def read_app(tmp_path):
    settings = Settings(
        sqlite_path=tmp_path / "store.sqlite3",
        rejects_path=tmp_path / "rejects.jsonl",
        tenants=TENANTS,
        cursor_secret=b"test-secret",
    )
    return create_app(settings)


@pytest.fixture
def seeded(read_app):
    """Tenants a and b with overlapping timestamps, run IDs and event types (c is empty).

    customer-a: 30 organic (r1 for the first 20, r2 after), 4 probes in run "run-1"
    customer-b: 30 organic (same shape and times), 4 probes in run "run-1" (same run_id!)
    """
    client = TestClient(read_app)
    for cid in ("customer-a", "customer-b"):
        batch = [
            make_organic(
                cid,
                n,
                n,
                revision="r1" if n < 20 else "r2",
                event_type=("order.view" if n % 3 == 0 else "auth.login"),
            )
            for n in range(30)
        ]
        batch += [make_probe(cid, n, 5.5 + n, "run-1") for n in range(4)]
        body = client.post("/events", json=batch).json()
        assert body["rejected"] == []
        for p in batch[-4:]:
            assert (
                client.post("/evidence", json=make_artifact(p["evidence_ref"])).status_code == 201
            )
    return client
