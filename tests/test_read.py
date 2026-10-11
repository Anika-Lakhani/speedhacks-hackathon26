"""Read API (M3): slices, paging, since-timestamp, since-revision, artifacts, OpenAPI."""

import json
from urllib.parse import quote

from contracts import Event, make_evidence_ref, validate_event
from keewano.openapi import OPENAPI_PATH, openapi_spec
from keewano.read import MAX_LIMIT
from tests.conftest import iso


def ids(r):
    return [e["event_id"] for e in r.json()]


def all_pages(client, path, params, limit):
    out, cursor, pages = [], None, 0
    while True:
        q = params | {"limit": limit} | ({"cursor": cursor} if cursor else {})
        r = client.get(path, params=q)
        assert r.status_code == 200, r.text
        out += ids(r)
        pages += 1
        cursor = r.headers.get("X-Next-Cursor")
        if r.headers["X-Has-More"] == "false":
            return out, pages


def test_slice_is_a_plain_array_of_contract_events(seeded):
    r = seeded.get("/events", params={"customer_id": "customer-a"})
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, list) and len(body) == 34
    for e in body:
        assert validate_event(e).customer_id == "customer-a"
    ts = [Event.model_validate(e).ts for e in body]
    assert ts == sorted(ts)  # oldest first


def test_time_window_since_inclusive_until_exclusive(seeded):
    r = seeded.get(
        "/events", params={"customer_id": "customer-a", "since": iso(10), "until": iso(13)}
    )
    assert ids(r) == ["customer-a-o10", "customer-a-o11", "customer-a-o12"]


def test_events_since_timestamp(seeded):
    r = seeded.get("/events", params={"customer_id": "customer-a", "since": iso(27)})
    assert ids(r) == ["customer-a-o27", "customer-a-o28", "customer-a-o29"]


def test_since_accepts_offsets(seeded):
    pacific = "2026-10-11T05:27:00-07:00"  # == iso(27)
    r = seeded.get("/events", params={"customer_id": "customer-a", "since": pacific})
    assert ids(r)[0] == "customer-a-o27"


def test_filters(seeded):
    r = seeded.get(
        "/events",
        params={"customer_id": "customer-a", "event_type": "probe.result", "run_id": "run-1"},
    )
    assert ids(r) == [f"customer-a-p{n}" for n in range(4)]
    r = seeded.get("/events", params={"customer_id": "customer-a", "event_type": "order.view"})
    assert all(e["event_type"] == "order.view" for e in r.json()) and len(r.json()) == 10


def test_default_and_max_page_size(seeded):
    r = seeded.get("/events", params={"customer_id": "customer-a", "limit": 5})
    assert len(r.json()) == 5 and r.headers["X-Has-More"] == "true"
    assert seeded.get(
        "/events", params={"customer_id": "customer-a", "limit": MAX_LIMIT}
    ).is_success
    over = seeded.get("/events", params={"customer_id": "customer-a", "limit": MAX_LIMIT + 1})
    assert over.status_code == 422
    assert (
        seeded.get("/events", params={"customer_id": "customer-a", "limit": 0}).status_code == 422
    )


def test_cursor_pagination_walks_everything_once(seeded):
    full = ids(seeded.get("/events", params={"customer_id": "customer-a"}))
    paged, pages = all_pages(seeded, "/events", {"customer_id": "customer-a"}, limit=7)
    assert paged == full and pages == 5


def test_cursor_pagination_with_filters(seeded):
    params = {"customer_id": "customer-a", "event_type": "auth.login", "since": iso(3)}
    full = ids(seeded.get("/events", params=params))
    paged, _ = all_pages(seeded, "/events", params, limit=4)
    assert paged == full


def test_cursor_is_stable_when_new_events_arrive(seeded):
    r1 = seeded.get("/events", params={"customer_id": "customer-a", "limit": 10})
    cursor = r1.headers["X-Next-Cursor"]
    seeded.post("/events", json=[{**json.loads(json.dumps(r1.json()[0])), "event_id": "late"}])
    r2 = seeded.get("/events", params={"customer_id": "customer-a", "limit": 10, "cursor": cursor})
    seen = set(ids(r1))
    assert not seen & set(ids(r2))  # no repeats
    assert "late" in ids(seeded.get("/events", params={"customer_id": "customer-a"}))


def test_tailing_keeps_cursor_on_empty_page(seeded):
    r = seeded.get("/events", params={"customer_id": "customer-c"})
    assert r.json() == [] and "X-Next-Cursor" not in r.headers
    last = seeded.get("/events", params={"customer_id": "customer-a", "limit": MAX_LIMIT})
    cursor = last.headers["X-Next-Cursor"]
    empty = seeded.get("/events", params={"customer_id": "customer-a", "cursor": cursor})
    assert empty.json() == [] and empty.headers["X-Next-Cursor"] == cursor
    seeded.post("/events", json=[{**last.json()[-1], "event_id": "new-1", "ts": iso(99)}])
    nxt = seeded.get("/events", params={"customer_id": "customer-a", "cursor": cursor})
    assert ids(nxt) == ["new-1"]


def test_since_revision(seeded):
    r = seeded.get("/events/since-revision", params={"customer_id": "customer-a", "revision": "r2"})
    assert ids(r) == [f"customer-a-o{n}" for n in range(20, 30)]
    r = seeded.get("/events/since-revision", params={"customer_id": "customer-a", "revision": "r1"})
    assert len(r.json()) == 34
    r = seeded.get(
        "/events/since-revision",
        params={"customer_id": "customer-a", "revision": "r1", "event_type": "probe.result"},
    )
    assert ids(r) == [f"customer-a-p{n}" for n in range(4)]


def test_since_revision_paging(seeded):
    params = {"customer_id": "customer-a", "revision": "r1"}
    full = ids(seeded.get("/events/since-revision", params=params))
    paged, _ = all_pages(seeded, "/events/since-revision", params, limit=6)
    assert paged == full


def test_since_unknown_revision_404(seeded):
    r = seeded.get("/events/since-revision", params={"customer_id": "customer-a", "revision": "zz"})
    assert r.status_code == 404


def test_get_evidence(seeded):
    ref = make_evidence_ref("customer-a", "run-1", "customer-a-p0")
    r = seeded.get(f"/evidence/{ref}", params={"customer_id": "customer-a"})
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"request", "response", "flags_snapshot", "code_revision"}
    assert body["flags_snapshot"] == {"idor_orders": True}
    encoded = seeded.get(f"/evidence/{quote(ref, safe='')}", params={"customer_id": "customer-a"})
    assert encoded.json() == body


def test_get_evidence_missing_and_malformed(seeded):
    missing = make_evidence_ref("customer-a", "run-1", "nope")
    assert (
        seeded.get(f"/evidence/{missing}", params={"customer_id": "customer-a"}).status_code == 404
    )
    bad = seeded.get("/evidence/not-a-ref", params={"customer_id": "customer-a"})
    assert bad.status_code == 422


def test_dev_a_client_call_shapes(seeded):
    """Mirrors attack/clients/keewano.py (feat/ato-response): get_slice and get_evidence."""
    params = {"customer_id": "customer-a", "since": iso(5), "run_id": "run-1", "limit": 500}
    body = seeded.get("/events", params=params).json()
    assert isinstance(body, list) and {e["run_id"] for e in body} == {"run-1"}
    ref = body[0]["evidence_ref"]
    record = seeded.get(f"/evidence/{ref}", params={"customer_id": "customer-a"}).json()
    for key in ("request", "response", "flags_snapshot", "code_revision"):
        assert key in record  # what attack/harness/replay.py reads


def test_openapi_file_is_current():
    committed = json.loads(OPENAPI_PATH.read_text(encoding="utf-8"))
    assert committed == openapi_spec(), "run: uv run python -m keewano.openapi"
    paths = committed["paths"]
    assert {"/events", "/events/since-revision", "/evidence/{evidence_ref}"} <= set(paths)
    params = {p["name"]: p for p in paths["/events"]["get"]["parameters"]}
    assert params["customer_id"]["required"] is True
