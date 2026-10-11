"""All six cells of the §4 decision table, plus the signal assertions."""

from attack.clients import FakeSite
from attack.engine import ProbeResult, run_probe
from attack.verify import judge, signal_matched
from contracts import Verdict

SCN = "SCN-IDOR-001"


def probe(catalog, flag_on, override=None, **site_kw):
    site = FakeSite("customer-a", catalog, {"idor_orders": flag_on}, **site_kw)
    if override is not None:
        site.signal_override[SCN] = override
    return run_probe(catalog[SCN], site, "run-t")


def test_confirmed(catalog):
    r = judge(catalog[SCN], probe(catalog, True))
    assert r.verdict == Verdict.CONFIRMED and r.signal_matched and r.flag_was_on


def test_not_reproduced(catalog):
    assert judge(catalog[SCN], probe(catalog, False)).verdict == Verdict.NOT_REPRODUCED


def test_signal_without_flag_is_inconclusive_mismatch(catalog):
    r = judge(catalog[SCN], probe(catalog, False, override=True))
    assert r.verdict == Verdict.INCONCLUSIVE and "MISMATCH" in r.notes


def test_flag_on_but_no_signal_is_inconclusive(catalog):
    r = judge(catalog[SCN], probe(catalog, True, override=False))
    assert r.verdict == Verdict.INCONCLUSIVE and not r.signal_matched


def test_error_is_inconclusive(catalog):
    res = ProbeResult(
        scenario_id=SCN,
        request={},
        response={},
        flags_snapshot={},
        code_revision="x",
        error="error: ConnectError",
    )
    assert judge(catalog[SCN], res).verdict == Verdict.INCONCLUSIVE


def test_missing_flag_in_meta_is_inconclusive(catalog):
    res = probe(catalog, True).model_copy(update={"flags_snapshot": {}})
    assert judge(catalog[SCN], res).verdict == Verdict.INCONCLUSIVE


def test_blocked(catalog):
    res = ProbeResult(
        scenario_id=SCN,
        request={},
        response={},
        flags_snapshot={},
        code_revision="x",
        error="blocked: target not on allowlist",
    )
    assert judge(catalog[SCN], res).verdict == Verdict.BLOCKED


def test_verifier_never_returns_verified_label(catalog):
    assert "verified" not in {v.value for v in Verdict}


def test_owner_is_other_requires_different_owner(catalog):
    sig = catalog[SCN].expected_signal
    req = {"headers": {"X-SwarmShield-Synthetic-User": "user-1001"}}
    mine = {"status": 200, "headers": {}, "body": {"order_id": 1, "owner_user_id": "user-1001"}}
    other = {**mine, "body": {"order_id": 1, "owner_user_id": "user-2002"}}
    assert not signal_matched(sig, mine, req)
    assert signal_matched(sig, other, req)


def test_header_absent_assertion(catalog):
    sig = catalog["SCN-RATE-001"].expected_signal
    body = {"error": "invalid_credentials"}
    vuln = {"status": 401, "headers": {}, "body": body}
    secure = {"status": 401, "headers": {"x-ratelimit-limit": "5"}, "body": body}
    assert signal_matched(sig, vuln, {})
    assert not signal_matched(sig, secure, {})


def test_every_scenario_correct_against_ground_truth(catalog):
    """confirmed <=> flag on, for every scenario in the catalog."""
    for s in catalog.values():
        for on in (True, False):
            site = FakeSite(s.customer_id, catalog, {s.flag: on})
            v = judge(s, run_probe(s, site, "run-t", frozenset({"GET", "POST"}))).verdict
            assert v == (Verdict.CONFIRMED if on else Verdict.NOT_REPRODUCED), s.id
