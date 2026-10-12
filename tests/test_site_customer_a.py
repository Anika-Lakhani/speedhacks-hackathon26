"""customer-a demo site: flows emit contract-valid events that land only in customer-a."""

import time

import pytest
from fastapi.testclient import TestClient

from contracts import validate_event
from sites.common.emitter import EventEmitter
from sites.customer_a import config
from sites.customer_a.app import FAILED_LOGIN_FLAG_THRESHOLD, create_app

ALICE = {"email": "alice@example.test", "password": "alice-demo-pass"}
BOB = {"email": "bob@example.test", "password": "bob-demo-pass"}


@pytest.fixture
def store_client(read_app):  # the event store from tests/conftest.py, empty
    return TestClient(read_app)


@pytest.fixture
def emitter(store_client, tmp_path):
    def send(batch):
        r = store_client.post("/events", json=batch)
        r.raise_for_status()
        return r.json()

    e = EventEmitter(send, tmp_path / "emit-fallback.jsonl")
    yield e
    e.shutdown()


@pytest.fixture
def site(emitter):
    with TestClient(create_app(emitter=emitter)) as client:
        yield client


def login(site, creds=ALICE):
    r = site.post("/login", json=creds)
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def landed(store_client, emitter, cid="customer-a", **params):
    assert emitter.flush()
    r = store_client.get("/events", params={"customer_id": cid, **params})
    assert r.status_code == 200
    return r.json()


def outcomes(events, event_type):
    return [e["policy_outcome"] for e in events if e["event_type"] == event_type]


# --- revision -------------------------------------------------------------------------------


def test_revision_endpoint_header_and_meta(site):
    r = site.get("/revision")
    assert r.json() == {"customer_id": "customer-a", "code_revision": config.CODE_REVISION}
    assert r.headers["X-Code-Revision"] == config.CODE_REVISION
    assert site.get("/products").headers["X-Code-Revision"] == config.CODE_REVISION
    assert (
        site.post("/login", json={"email": "x", "password": "y"}).headers["X-Code-Revision"]
        == config.CODE_REVISION
    )
    meta = site.get("/__meta").json()
    assert set(meta) == {"customer_id", "code_revision", "flags"}


def test_bumped_revision_flows_into_events(emitter, store_client):
    with TestClient(create_app(emitter=emitter, code_revision="customer-a-9.9.9")) as site:
        assert site.get("/revision").json()["code_revision"] == "customer-a-9.9.9"
        login(site)
    [event] = landed(store_client, emitter)
    assert event["code_revision"] == "customer-a-9.9.9"


# --- flows ----------------------------------------------------------------------------------


def test_login_success_and_failures(site, emitter, store_client):
    login(site)
    assert site.post("/login", json={**ALICE, "password": "wrong"}).status_code == 401
    assert (
        site.post("/login", json={"email": "nobody@example.test", "password": "x"}).status_code
        == 401
    )
    events = landed(store_client, emitter, event_type="auth.login")
    assert outcomes(events, "auth.login") == ["allow", "deny", "deny"]
    ok, bad, unknown = events
    assert ok["state_transition"] == "anonymous->authenticated"
    assert ok["attrs"] == {"user_id": "u-1"}
    assert bad["attrs"]["reason"] == "bad_password"
    assert unknown["attrs"] == {"reason": "unknown_account"}


def test_repeated_failures_get_flagged(site, emitter, store_client):
    for _ in range(FAILED_LOGIN_FLAG_THRESHOLD + 1):
        site.post("/login", json={**BOB, "password": "nope"})
    got = outcomes(landed(store_client, emitter), "auth.login")
    assert got == ["deny"] * (FAILED_LOGIN_FLAG_THRESHOLD - 1) + ["flag", "flag"]


def test_password_reset_flow(site, emitter, store_client):
    assert site.post("/password-reset", json={"email": ALICE["email"]}).status_code == 202
    unknown = site.post("/password-reset", json={"email": "ghost@example.test"})
    assert (
        unknown.status_code == 202
        and unknown.json()
        == site.post("/password-reset", json={"email": "ghost2@example.test"}).json()
    )  # no account enumeration
    [token] = site.app.state.reset_outbox
    bad = site.post("/password-reset/confirm", json={"token": "forged", "new_password": "x" * 10})
    assert bad.status_code == 400
    ok = site.post("/password-reset/confirm", json={"token": token, "new_password": "new-pass-123"})
    assert ok.status_code == 200
    again = site.post("/password-reset/confirm", json={"token": token, "new_password": "y" * 10})
    assert again.status_code == 400  # single use
    login(site, {"email": ALICE["email"], "password": "new-pass-123"})
    events = landed(store_client, emitter)
    assert outcomes(events, "auth.password_reset_request") == ["allow", "flag", "flag"]
    assert outcomes(events, "auth.password_reset_confirm") == ["deny", "allow", "deny"]


def test_cart_and_orders(site, emitter, store_client):
    h = login(site)
    assert site.post("/cart", json={"product_id": "p-101", "qty": 2}, headers=h).status_code == 200
    assert site.post("/cart", json={"product_id": "p-999", "qty": 1}, headers=h).status_code == 404
    order = site.post("/orders", headers=h).json()
    assert order["owner_user_id"] == "u-1" and order["total_cents"] == 2400
    assert site.post("/orders", headers=h).status_code == 400  # cart now empty
    assert {o["order_id"] for o in site.get("/orders", headers=h).json()} == {
        "1001",
        "1002",
        order["order_id"],
    }
    assert site.get("/orders/1001", headers=h).status_code == 200
    events = landed(store_client, emitter)
    assert outcomes(events, "cart.add") == ["allow", "deny"]
    assert outcomes(events, "order.create") == ["allow", "deny"]
    assert outcomes(events, "order.list") == ["allow"]
    assert outcomes(events, "order.access") == ["allow"]


def test_other_users_order_denied_and_logged(site, emitter, store_client):
    h = login(site)  # alice
    r = site.get("/orders/1003", headers=h)  # bob's
    missing = site.get("/orders/9999", headers=h)
    assert r.status_code == missing.status_code == 404
    assert r.json() == missing.json()  # can't tell "not yours" from "doesn't exist"
    events = [e for e in landed(store_client, emitter) if e["event_type"] == "order.access"]
    assert [(e["policy_outcome"], e["attrs"]["reason"]) for e in events] == [
        ("deny", "not_owner"),
        ("deny", "not_found"),
    ]


def test_unauthenticated_access_denied_and_logged(site, emitter, store_client):
    assert site.get("/orders/1001").status_code == 401
    assert site.post("/cart", json={"product_id": "p-100", "qty": 1}).status_code == 401
    assert site.get("/orders/1001", headers={"Authorization": "Bearer forged"}).status_code == 401
    events = landed(store_client, emitter)
    assert [(e["event_type"], e["policy_outcome"]) for e in events] == [
        ("order.access", "deny"),
        ("cart.add", "deny"),
        ("order.access", "deny"),
    ]
    assert all(e["attrs"] == {"reason": "unauthenticated"} for e in events)


def test_logout_ends_session(site, emitter, store_client):
    h = login(site)
    assert site.post("/logout", headers=h).status_code == 200
    assert site.get("/me", headers=h).status_code == 401
    assert outcomes(landed(store_client, emitter), "auth.logout") == ["allow"]


# --- events are contract-valid, customer-a only, and carry no secrets -----------------------


def run_all_flows(site):
    h = login(site)
    site.post("/login", json={**BOB, "password": "nope"})
    site.post("/password-reset", json={"email": BOB["email"]})
    site.post("/cart", json={"product_id": "p-100", "qty": 1}, headers=h)
    site.post("/orders", headers=h)
    site.get("/orders/1003", headers=h)
    site.get("/orders/1001")
    site.post("/logout", headers=h)


def test_all_events_valid_and_only_in_customer_a(site, emitter, store_client):
    run_all_flows(site)
    events = landed(store_client, emitter)
    assert len(events) == 8
    for e in events:
        validated = validate_event(e)
        assert validated.customer_id == "customer-a"
        assert validated.simulated is False and validated.run_id is None
        assert validated.actor == "user" and validated.tool == "customer-a-site"
        assert validated.code_revision == config.CODE_REVISION
        assert validated.policy_outcome in {"allow", "deny", "flag"}
    for other in ("customer-b", "customer-c"):
        assert landed(store_client, emitter, cid=other) == []
    assert emitter.read_fallback() == []


def test_events_never_contain_credentials(site, emitter, store_client):
    run_all_flows(site)
    raw = str(landed(store_client, emitter))
    for secret in ("alice-demo-pass", "bob-demo-pass", "nope", "Bearer", "@example.test"):
        assert secret not in raw
    for token in site.app.state.reset_outbox:
        assert token not in raw


# --- fail-safe emission ---------------------------------------------------------------------


def test_store_down_never_breaks_requests(tmp_path):
    def down(batch):
        raise ConnectionError("store unreachable")

    emitter = EventEmitter(down, tmp_path / "fallback.jsonl")
    with TestClient(create_app(emitter=emitter)) as site:
        start = time.perf_counter()
        h = login(site)
        assert site.get("/orders/1001", headers=h).status_code == 200
        assert time.perf_counter() - start < 2
        assert emitter.flush()
    logged = emitter.read_fallback()
    assert [x["kind"] for x in logged] == ["store_unreachable", "store_unreachable"]
    assert [x["event"]["event_type"] for x in logged] == ["auth.login", "order.access"]


def test_slow_store_does_not_block_requests(tmp_path):
    def slow(batch):
        time.sleep(1.0)
        return {"accepted": [e["event_id"] for e in batch], "rejected": []}

    emitter = EventEmitter(slow, tmp_path / "fallback.jsonl")
    with TestClient(create_app(emitter=emitter)) as site:
        start = time.perf_counter()
        for _ in range(10):  # unknown account: emits an event but skips password hashing
            site.post("/login", json={"email": "nobody@example.test", "password": "x"})
        assert time.perf_counter() - start < 1.0  # one slow send alone takes 1.0 s


def test_full_queue_drops_and_logs(tmp_path):
    import threading

    gate = threading.Event()

    def blocked(batch):
        gate.wait(5)
        return {"accepted": [e["event_id"] for e in batch], "rejected": []}

    emitter = EventEmitter(blocked, tmp_path / "fallback.jsonl", max_queue=2, max_batch=1)
    with TestClient(create_app(emitter=emitter)) as site:
        for _ in range(6):
            assert site.post("/login", json=ALICE).status_code == 200
        gate.set()
    kinds = [x["kind"] for x in emitter.read_fallback()]
    assert kinds and set(kinds) == {"queue_full"}


def test_store_rejection_is_logged_locally(tmp_path):
    def rejecting(batch):
        return {
            "accepted": [],
            "rejected": [{"event_id": e["event_id"], "reason": "nope"} for e in batch],
        }

    emitter = EventEmitter(rejecting, tmp_path / "fallback.jsonl")
    with TestClient(create_app(emitter=emitter)) as site:
        login(site)
        assert emitter.flush()
    [entry] = emitter.read_fallback()
    assert entry["kind"] == "store_rejected" and entry["reason"] == "nope"
