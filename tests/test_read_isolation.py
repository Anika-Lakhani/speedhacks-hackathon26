"""Adversarial tenant-isolation suite for the read API.

customer-a and customer-b share timestamps, event types, revisions and even a run_id
("run-1"), so any leak would show up. Every read path is attacked; none may return a row
or an artifact belonging to a tenant other than the one asked for.
"""

import base64
import json

import pytest

from contracts import make_evidence_ref

A, B, C = "customer-a", "customer-b", "customer-c"
READ_PATHS = [
    ("/events", {}),
    ("/events/since-revision", {"revision": "r1"}),
    ("/evidence/" + make_evidence_ref(A, "run-1", "customer-a-p0"), {}),
]


def tenants_in(r):
    return {e["customer_id"] for e in r.json()}


def assert_only(r, cid):
    assert r.status_code == 200, r.text
    assert tenants_in(r) <= {cid}


# --- mismatched customer_id -------------------------------------------------------------


def test_run_id_shared_across_tenants_stays_scoped(seeded):
    for cid in (A, B):
        r = seeded.get("/events", params={"customer_id": cid, "run_id": "run-1"})
        assert_only(r, cid)
        assert len(r.json()) == 4


@pytest.mark.parametrize("cid", [A, B, C])
def test_every_slice_returns_only_the_requested_tenant(seeded, cid):
    for path, extra in READ_PATHS[:2]:
        r = seeded.get(path, params={"customer_id": cid, **extra})
        if r.status_code == 404:  # customer-c has no r1 events
            assert cid == C and path.endswith("since-revision")
            continue
        assert_only(r, cid)


def test_other_tenants_event_id_as_filter_returns_nothing(seeded):
    r = seeded.get("/events", params={"customer_id": B, "event_type": "auth.login"})
    assert "customer-a-o1" not in {e["event_id"] for e in r.json()}
    assert_only(r, B)


def test_customer_id_given_twice_rejected(seeded):
    for path, extra in READ_PATHS:
        query = "&".join(f"{k}={v}" for k, v in extra.items())
        r = seeded.get(f"{path}?customer_id={B}&customer_id={A}" + (f"&{query}" if query else ""))
        assert r.status_code == 400, path


@pytest.mark.parametrize(
    "injected",
    [
        "customer-a' OR '1'='1",
        "customer-a; DROP TABLE events_customer_b",
        "customer-a,customer-b",
        "customer_a",
        "CUSTOMER-A",
        "*",
        "%",
    ],
)
def test_injection_shaped_customer_id_rejected(seeded, injected):
    for path, extra in READ_PATHS:
        r = seeded.get(path, params={"customer_id": injected, **extra})
        assert r.status_code in (404, 422), (path, r.status_code)


@pytest.mark.parametrize(
    "param, value",
    [
        ("event_type", "x' OR '1'='1"),
        ("run_id", "run-1' OR customer_id != 'customer-b"),
        ("event_type", "%"),
    ],
)
def test_injection_shaped_filters_are_just_values(seeded, param, value):
    r = seeded.get("/events", params={"customer_id": B, param: value})
    assert r.status_code == 200 and r.json() == []


# --- pagination cursor from tenant A used against tenant B --------------------------------


def a_cursor(seeded, path="/events", **extra):
    r = seeded.get(path, params={"customer_id": A, "limit": 3, **extra})
    return r.headers["X-Next-Cursor"]


@pytest.mark.parametrize("path, extra", READ_PATHS[:2])
def test_cursor_from_tenant_a_rejected_for_tenant_b(seeded, path, extra):
    cursor = a_cursor(seeded, path, **extra)
    r = seeded.get(path, params={"customer_id": B, "cursor": cursor, **extra})
    assert r.status_code == 400
    assert "different customer_id" in r.json()["detail"]


def test_cursor_rejected_for_different_query(seeded):
    cursor = a_cursor(seeded)
    r = seeded.get("/events", params={"customer_id": A, "cursor": cursor, "event_type": "x"})
    assert r.status_code == 400
    r = seeded.get(
        "/events/since-revision", params={"customer_id": A, "revision": "r1", "cursor": cursor}
    )
    assert r.status_code == 400


def test_forged_cursor_rejected(seeded):
    cursor = a_cursor(seeded)
    body_b64, sig = cursor.split(".")
    body = json.loads(base64.urlsafe_b64decode(body_b64 + "=" * (-len(body_b64) % 4)))
    body["c"] = B
    forged_body = (
        base64.urlsafe_b64encode(json.dumps(body, sort_keys=True, separators=(",", ":")).encode())
        .rstrip(b"=")
        .decode()
    )
    r = seeded.get("/events", params={"customer_id": B, "cursor": f"{forged_body}.{sig}"})
    assert r.status_code == 400 and "signature" in r.json()["detail"]


@pytest.mark.parametrize("cursor", ["", "garbage", "a.b.c", "....", "eyJ9.eyJ9"])
def test_malformed_cursor_rejected(seeded, cursor):
    r = seeded.get("/events", params={"customer_id": A, "cursor": cursor})
    assert r.status_code == 400


# --- evidence_ref belonging to another tenant ---------------------------------------------


def test_other_tenants_evidence_not_returned(seeded):
    a_ref = make_evidence_ref(A, "run-1", "customer-a-p0")
    assert seeded.get(f"/evidence/{a_ref}", params={"customer_id": A}).status_code == 200
    r = seeded.get(f"/evidence/{a_ref}", params={"customer_id": B})
    assert r.status_code == 404


def test_other_tenant_and_missing_evidence_look_identical(seeded):
    a_ref = make_evidence_ref(A, "run-1", "customer-a-p0")
    missing = make_evidence_ref(B, "run-1", "does-not-exist")
    leaked = seeded.get(f"/evidence/{a_ref}", params={"customer_id": B})
    absent = seeded.get(f"/evidence/{missing}", params={"customer_id": B})
    assert (leaked.status_code, leaked.json()) == (absent.status_code, absent.json())


def test_evidence_ref_path_tricks_rejected(seeded):
    for ref in (
        f"ev://{B}/../{A}/run-1/customer-a-p0",
        f"ev://{B}/run-1/customer-a-p0/../../{A}",
        "ev://customer-b/run-1/customer-a-p0",  # A's event id under B's ref: not B's artifact
    ):
        r = seeded.get(f"/evidence/{ref}", params={"customer_id": B})
        assert r.status_code in (404, 422), ref


def test_evidence_requires_customer_id(seeded):
    a_ref = make_evidence_ref(A, "run-1", "customer-a-p0")
    assert seeded.get(f"/evidence/{a_ref}").status_code == 422


# --- missing, empty and unknown customer_id ------------------------------------------------


@pytest.mark.parametrize("path, extra", READ_PATHS)
def test_missing_customer_id_rejected(seeded, path, extra):
    r = seeded.get(path, params=extra)
    assert r.status_code == 422


@pytest.mark.parametrize("path, extra", READ_PATHS)
@pytest.mark.parametrize("value", ["", " "])
def test_empty_customer_id_rejected(seeded, path, extra, value):
    r = seeded.get(path, params={"customer_id": value, **extra})
    assert r.status_code == 422


@pytest.mark.parametrize("path, extra", READ_PATHS)
def test_unknown_customer_id_rejected(seeded, path, extra):
    r = seeded.get(path, params={"customer_id": "customer-z", **extra})
    assert r.status_code == 404
    assert "unknown customer_id" in r.json()["detail"]


def test_no_read_response_ever_contains_two_tenants(seeded):
    """Sweep: every combination of filters on every tenant returns one tenant at most."""
    for cid in (A, B, C):
        for params in (
            {},
            {"run_id": "run-1"},
            {"event_type": "probe.result"},
            {"since": "2026-10-11T00:00:00Z"},
            {"until": "2030-01-01T00:00:00Z"},
            {"limit": 1000},
        ):
            r = seeded.get("/events", params={"customer_id": cid, **params})
            assert_only(r, cid)
            assert not any(
                "customer-" + x in json.dumps(r.json()) for x in "abc" if f"customer-{x}" != cid
            )
