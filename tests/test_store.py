"""Storage adapter: SQLite implementation, Keewano stub, and config-only switching."""

from datetime import UTC, datetime, timedelta

import pytest

from contracts import Event, make_evidence_ref
from keewano.config import load_settings
from keewano.keewano_store import KeewanoStore
from keewano.sqlite_store import SQLiteStore
from keewano.storage import (
    Artifact,
    ArtifactExists,
    DuplicateEvent,
    StoreNotConfigured,
    UnknownTenant,
    make_store,
)

TENANTS = ("customer-a", "customer-b")
T0 = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)


def ev(cid="customer-a", minutes=0, **kw):
    base = dict(
        customer_id=cid,
        ts=T0 + timedelta(minutes=minutes),
        actor="user",
        event_type="auth.login",
        target="/login",
        action="login",
        policy_outcome="allow",
        code_revision="r1",
        simulated=False,
    )
    return Event(**(base | kw))


ART = Artifact(
    request={"method": "GET", "path": "/orders/1002"},
    response={"status": 200, "body": {"order_id": "1002"}},
    flags_snapshot={"idor_orders": True},
    code_revision="r1",
)


@pytest.fixture
def store(tmp_path):
    s = SQLiteStore(tmp_path / "store.sqlite3")
    s.setup(TENANTS)
    return s


def test_setup_is_idempotent(store):
    store.write_event(ev())
    store.setup(TENANTS)
    store.setup(TENANTS + ("customer-c",))
    assert store.tenants() == {"customer-a", "customer-b", "customer-c"}
    assert len(store.query_events("customer-a")) == 1


def test_one_table_per_tenant(store):
    import sqlite3

    tables = {
        r[0]
        for r in sqlite3.connect(store.path).execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    assert {"events_customer_a", "events_customer_b"} <= tables
    assert {"artifacts_customer_a", "artifacts_customer_b"} <= tables


def test_events_land_in_their_own_tenant(store):
    a, b = ev("customer-a"), ev("customer-b")
    store.write_event(a)
    store.write_event(b)
    assert store.query_events("customer-a") == [a]
    assert store.query_events("customer-b") == [b]


def test_unknown_tenant_rejected(store):
    with pytest.raises(UnknownTenant):
        store.write_event(ev("customer-z"))
    with pytest.raises(UnknownTenant):
        store.query_events("customer-z")


def test_duplicate_event_id_rejected(store):
    e = ev()
    store.write_event(e)
    with pytest.raises(DuplicateEvent):
        store.write_event(e)


def test_query_filters_and_order(store):
    later = ev(minutes=5, event_type="order.view")
    earlier = ev(minutes=1)
    probe_eid = "p1"
    probe = ev(
        minutes=3,
        event_id=probe_eid,
        run_id="run-1",
        actor="system",
        event_type="probe.result",
        simulated=True,
        evidence_ref=make_evidence_ref("customer-a", "run-1", probe_eid),
        scenario_id="SCN-IDOR-001",
    )
    for e in (later, earlier, probe):
        store.write_event(e)
    assert store.query_events("customer-a") == [earlier, probe, later]
    assert store.query_events("customer-a", event_type="order.view") == [later]
    assert store.query_events("customer-a", run_id="run-1") == [probe]
    window = store.query_events(
        "customer-a", since=T0 + timedelta(minutes=1), until=T0 + timedelta(minutes=5)
    )
    assert window == [earlier, probe]  # since inclusive, until exclusive
    assert store.query_events("customer-a", limit=1) == [earlier]


def test_timezones_normalized_for_ordering(store):
    utc = ev(minutes=0)
    pacific = ev(ts=datetime(2026, 10, 11, 5, 30, tzinfo=UTC).astimezone())  # 05:30Z < 12:00Z
    store.write_event(utc)
    store.write_event(pacific)
    assert [e.event_id for e in store.query_events("customer-a")] == [
        pacific.event_id,
        utc.event_id,
    ]


def test_artifacts_are_tenant_scoped_and_immutable(store):
    ref = make_evidence_ref("customer-a", "run-1", "p1")
    store.put_artifact(ref, ART)
    assert store.get_artifact("customer-a", ref) == ART
    assert store.get_artifact("customer-b", ref) is None  # other tenant can't read it
    assert store.get_artifact("customer-a", "not-a-ref") is None
    assert store.get_artifact("customer-a", make_evidence_ref("customer-a", "run-1", "x")) is None
    with pytest.raises(ArtifactExists):
        store.put_artifact(ref, ART)
    with pytest.raises(UnknownTenant):
        store.put_artifact(make_evidence_ref("customer-z", "run-1", "p1"), ART)


@pytest.mark.parametrize(
    "call",
    [
        lambda s: s.setup(TENANTS),
        lambda s: s.tenants(),
        lambda s: s.write_event(ev()),
        lambda s: s.query_events("customer-a"),
        lambda s: s.put_artifact(make_evidence_ref("customer-a", "r", "e"), ART),
        lambda s: s.get_artifact("customer-a", make_evidence_ref("customer-a", "r", "e")),
    ],
)
def test_keewano_stub_raises_not_configured(call):
    with pytest.raises(StoreNotConfigured, match="not configured"):
        call(KeewanoStore())


def test_store_selected_by_env_only(tmp_path):
    sqlite = make_store(load_settings({"SWARMSHIELD_SQLITE_PATH": str(tmp_path / "x.db")}))
    assert isinstance(sqlite, SQLiteStore)
    keewano = make_store(
        load_settings({"SWARMSHIELD_STORE": "keewano", "KEEWANO_PROJECT_IDS": "customer-a=p1"})
    )
    assert isinstance(keewano, KeewanoStore)
    assert keewano.project_ids == {"customer-a": "p1"}
    with pytest.raises(StoreNotConfigured):
        make_store(load_settings({"SWARMSHIELD_STORE": "postgres"}))


def test_settings_tenants_from_env():
    s = load_settings({"SWARMSHIELD_TENANTS": " customer-a, customer-x ,"})
    assert s.tenants == ("customer-a", "customer-x")
    assert load_settings({}).tenants == ("customer-a", "customer-b", "customer-c")
