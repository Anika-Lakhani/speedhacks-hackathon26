from attack.clients import FakeSite
from attack.engine import run_probe
from attack.engine.probe import build_request


def test_probe_is_marked_and_synthetic(catalog):
    req = build_request(catalog["SCN-IDOR-001"], "run-1")
    assert req["headers"]["X-SwarmShield-Probe"] == "SCN-IDOR-001"
    assert req["headers"]["X-SwarmShield-Run"] == "run-1"
    assert req["path"] == "/orders/ORD-90002"


def test_post_blocked_by_default_verb_allowlist(catalog):
    site = FakeSite("customer-a", catalog, {})
    res = run_probe(catalog["SCN-RATE-001"], site, "run-1")
    assert res.error.startswith("blocked:")
    assert site.calls == []  # nothing was sent


def test_unknown_fixture_blocks(catalog):
    s = catalog["SCN-IDOR-001"]
    s = s.model_copy(
        update={
            "probe": s.probe.model_copy(update={"params": {"other_user_order_id": "fixture:nope"}})
        }
    )
    res = run_probe(s, FakeSite("customer-a", catalog, {}), "run-1")
    assert res.error.startswith("blocked:")


def test_connection_error_is_captured_without_retry(catalog):
    class Down(FakeSite):
        def probe(self, *a, **k):
            self.calls.append(("x", "x"))
            raise TimeoutError("boom")

    site = Down("customer-a", catalog, {})
    res = run_probe(catalog["SCN-IDOR-001"], site, "run-1")
    assert res.error.startswith("error:") and res.response == {}
    assert len(site.calls) == 1


def test_result_records_flags_and_revision(catalog):
    site = FakeSite("customer-a", catalog, {"idor_orders": True}, code_revision="abc")
    res = run_probe(catalog["SCN-IDOR-001"], site, "run-1")
    assert res.flags_snapshot["idor_orders"] is True and res.code_revision == "abc"
    assert res.evidence_ref.startswith("ev://customer-a/run-1/")
