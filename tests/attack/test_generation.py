"""Scenario generation: the code-side gate, the store/promotion flow, and the generators."""

import json
from types import SimpleNamespace

import pytest
import yaml

from attack.agent import DummyGenerator, GeminiGenerator, GenerationOutcome, GenerationRequest
from attack.catalog import load_catalog, load_flags, validate_catalog
from attack.catalog.generation import (
    DraftParam,
    DraftProbe,
    DraftSignal,
    GeneratedStore,
    PromotionError,
    ScenarioDraft,
    load_full_catalog,
    validate_drafts,
)


def draft(**kw):
    base = {
        "title": "Search marker with quote",
        "weakness_class": "injection",
        "invariant": "User input is never interpreted as query syntax",
        "flag": "unsafe_input_handling",
        "probe": DraftProbe(
            method="GET", path="/search", params=[DraftParam(name="q", value="SWARMSHIELD_QUOTE'")]
        ),
        "expected_signal": DraftSignal(status=500, body_contains=["query_error"]),
        "severity": "high",
        "rationale": "r42 interpolates q into the query",
    }
    base.update(kw)
    return ScenarioDraft(**base)


def probe(method="GET", path="/search", **params):
    return DraftProbe(
        method=method, path=path, params=[DraftParam(name=k, value=v) for k, v in params.items()]
    )


def validate(drafts, catalog, max_new=5, customer="customer-c"):
    existing = [s for s in catalog.values() if s.customer_id == customer]
    return validate_drafts(drafts, customer, load_flags(), existing, max_new=max_new, model="m")


def test_good_draft_becomes_generated_scenario(catalog):
    res = validate([draft()], catalog)
    assert not res.rejected
    s = res.accepted[0]
    assert s.id == "SCN-GEN-001" and s.origin == "generated" and s.customer_id == "customer-c"
    assert s.probe.kind == "benign_request" and s.probe.params == {"q": "SWARMSHIELD_QUOTE'"}
    assert s.provenance["model"] == "m" and "r42" in s.provenance["rationale"]
    validate_catalog({s.id: s}, load_flags())  # same fail-fast checks as curated


@pytest.mark.parametrize(
    "kw,reason",
    [
        ({"flag": "nope"}, "not in the registry"),
        ({"flag": "idor_orders"}, "not in the registry"),  # another customer's flag
        ({"probe": probe(path="/admin")}, "not an endpoint"),
        ({"probe": probe(path="/search/../etc")}, "disallowed characters"),
        ({"probe": probe(method="DELETE")}, "not allowed"),
        ({"probe": probe(method="PUT")}, "not allowed"),
        ({"probe": probe(q="x" * 201)}, "longer than"),
        ({"probe": probe(q="line1\nline2")}, "control characters"),
        ({"probe": probe(q="tab\there")}, "control characters"),
        ({"probe": probe(q="fixture:nope")}, "unknown fixture"),
        (
            {
                "probe": DraftProbe(
                    method="GET",
                    path="/search",
                    params=[DraftParam(name="q", value="SWARMSHIELD_A")] * 2,
                )
            },
            "duplicate param",
        ),
        (
            {"probe": probe(**{"Bad-Name": "SWARMSHIELD_A"})},
            "bad param name",
        ),
        ({"expected_signal": DraftSignal(status=200, body_contains=["x" * 65])}, "body_contains"),
        ({"expected_signal": DraftSignal(status=200, header_absent=["bad header"])}, "header"),
        ({"weakness_class": "Not Snake"}, "snake_case"),
        ({"title": ""}, "length"),
    ],
)
def test_bad_drafts_rejected_with_reason(catalog, kw, reason):
    res = validate([draft(**kw)], catalog)
    assert not res.accepted
    assert reason in res.rejected[0].reason


def test_realistic_test_inputs_are_accepted(catalog):
    """The value gate is about shape and size, not about refusing realistic inputs."""
    inputs = ["' OR 1=1 --", "<img src=x onerror=alert(1)>", "../../etc/passwd", "a" * 200]
    drafts = [draft(probe=probe(q=v)) for v in inputs]
    res = validate(drafts, catalog, max_new=10)
    assert len(res.accepted) == len(inputs) and not res.rejected


def test_path_placeholder_must_be_a_fixture_or_plain_id(catalog):
    d = draft(flag="idor_orders", probe=probe(path="/orders/{id}", id="../../admin"))
    res = validate_drafts([d], "customer-a", load_flags(), [], max_new=3)
    assert "fixture or a plain ID" in res.rejected[0].reason
    plain = draft(flag="idor_orders", probe=probe(path="/orders/{id}", id="ORD-12345"))
    assert validate_drafts([plain], "customer-a", load_flags(), [], max_new=3).accepted
    fix = draft(flag="idor_orders", probe=probe(path="/orders/{id}", id="fixture:other_order"))
    assert validate_drafts([fix], "customer-a", load_flags(), [], max_new=3).accepted


def test_duplicates_rejected_against_existing_and_within_batch(catalog):
    existing = [s for s in catalog.values() if s.customer_id == "customer-c"]
    curated = catalog["SCN-INJ-001"]
    dup = draft(
        probe=DraftProbe(
            method="GET",
            path="/search",
            params=[DraftParam(name="q", value=curated.probe.params["q"])],
        )
    )
    res = validate_drafts([dup, draft(), draft()], "customer-c", load_flags(), existing, max_new=5)
    assert [r.reason[:9] for r in res.rejected] == ["duplicate", "duplicate"]
    assert len(res.accepted) == 1


def test_max_new_and_id_assignment_continue_from_existing(catalog):
    first = validate([draft()], catalog).accepted
    second = validate_drafts(
        [draft(probe=probe(q="SWARMSHIELD_B")), draft(probe=probe(q="SWARMSHIELD_C"))],
        "customer-c",
        load_flags(),
        first,
        max_new=1,
    )
    assert [s.id for s in second.accepted] == ["SCN-GEN-002"]
    assert second.rejected[0].reason == "over max_new"


def test_long_rationale_is_truncated_not_rejected(catalog):
    res = validate([draft(rationale="x" * 3000)], catalog)
    assert len(res.accepted[0].provenance["rationale"]) == 600


def test_model_cannot_set_id_or_customer(catalog):
    with pytest.raises(ValueError):
        ScenarioDraft(**{**draft().model_dump(), "id": "SCN-EVIL-001"})
    with pytest.raises(ValueError):
        ScenarioDraft(**{**draft().model_dump(), "customer_id": "customer-a"})


# --- store and promotion ---------------------------------------------------------------


def test_store_roundtrip_and_verdict_tracking(tmp_path, catalog):
    path = tmp_path / "g.json"
    s = validate([draft()], catalog).accepted
    store = GeneratedStore(path)
    store.add(s)
    store.record_verdict(s[0].id, "confirmed")
    again = GeneratedStore(path)
    rec = again.records[s[0].id]
    assert rec.status == "pending" and rec.runs == 1 and rec.last_verdict == "confirmed"
    assert list(again.pending_scenarios("customer-c")) == [s[0].id]
    assert not again.pending_scenarios("customer-a")


def test_promotion_requires_a_run_then_lands_in_catalog(tmp_path, catalog):
    scen_dir = tmp_path / "scenarios"
    scen_dir.mkdir()
    (scen_dir / "customer-c.yaml").write_text(yaml.safe_dump([]))
    s = validate([draft()], catalog).accepted
    store = GeneratedStore(tmp_path / "g.json")
    store.add(s)
    with pytest.raises(PromotionError, match="never been run"):
        store.promote(s[0].id, load_flags(), scen_dir)
    store.record_verdict(s[0].id, "confirmed")
    target = store.promote(s[0].id, load_flags(), scen_dir)
    assert target.name == "customer-c.generated.yaml"
    loaded = load_catalog(scen_dir)
    assert loaded["SCN-GEN-001"].origin == "generated"
    assert store.records["SCN-GEN-001"].status == "promoted"
    assert not store.pending_scenarios()  # promoted ones live in the catalog now
    with pytest.raises(PromotionError, match="not pending"):
        store.promote(s[0].id, load_flags(), scen_dir)


def test_force_promote_and_reject(tmp_path, catalog):
    scen_dir = tmp_path / "scenarios"
    scen_dir.mkdir()
    s = validate([draft(), draft(probe=probe(q="SWARMSHIELD_B"))], catalog).accepted
    store = GeneratedStore(tmp_path / "g.json")
    store.add(s)
    store.promote(s[0].id, load_flags(), scen_dir, force=True)
    store.reject(s[1].id)
    assert store.records[s[1].id].status == "rejected"
    with pytest.raises(PromotionError):
        store.promote(s[1].id, load_flags(), scen_dir, force=True)
    with pytest.raises(KeyError):
        store.reject("SCN-GEN-999")


def test_promoted_file_does_not_collide_with_catalog_version(tmp_path, catalog):
    from attack.catalog import catalog_version

    scen_dir = tmp_path / "scenarios"
    scen_dir.mkdir()
    (scen_dir / "customer-c.yaml").write_text(yaml.safe_dump([]))
    before = catalog_version(scen_dir)
    s = validate([draft()], catalog).accepted
    store = GeneratedStore(None)
    store.add(s)
    store.promote(s[0].id, load_flags(), scen_dir, force=True)
    assert catalog_version(scen_dir) != before  # promotion is a catalog change


def test_full_catalog_includes_stored_scenarios(tmp_path, catalog):
    s = validate([draft()], catalog).accepted
    store = GeneratedStore(None)
    store.add(s)
    full = load_full_catalog(store)
    assert "SCN-GEN-001" in full and "SCN-INJ-001" in full


# --- generators ------------------------------------------------------------------------


def gen_request(max_new=3):
    return GenerationRequest(
        customer_id="customer-c",
        objective="t",
        max_new=max_new,
        code_context={"app.py": "def search(): ..."},
        flags=[{"flag": "unsafe_input_handling", "endpoints": ["/search"]}],
        existing=[],
        fixtures=["injection_marker"],
        value_rules="rules",
    )


class FakeGemini:
    def __init__(self, payloads):
        self.payloads, self.calls, self.models = list(payloads), [], self

    def generate_content(self, **kw):
        self.calls.append(kw)
        p = self.payloads.pop(0)
        if isinstance(p, Exception):
            raise p
        usage = SimpleNamespace(prompt_token_count=2000, candidates_token_count=300)
        return SimpleNamespace(
            text=p if isinstance(p, str) else json.dumps(p), usage_metadata=usage
        )


GOOD = {"drafts": [draft().model_dump(mode="json")]}


def test_gemini_generator_parses_drafts_and_sends_safe_schema():
    client = FakeGemini([GOOD])
    out = GeminiGenerator(client=client, model="gemini-test").generate(gen_request())
    assert len(out.drafts) == 1 and out.generator == "gemini" and out.model == "gemini-test"
    assert out.cost_usd > 0 and not out.degraded
    cfg = client.calls[0]["config"]
    assert "additionalProperties" not in json.dumps(cfg["response_json_schema"])
    assert "def search" in client.calls[0]["contents"]  # the code reaches the model
    assert "flag" in cfg["system_instruction"]


def test_params_are_a_list_of_pairs_in_the_schema():
    """A free-form map loses its value type under Gemini's schema, so it would emit {}."""
    client = FakeGemini([GOOD])
    GeminiGenerator(client=client).generate(gen_request())
    schema = json.dumps(client.calls[0]["config"]["response_json_schema"])
    assert '"name"' in schema and '"value"' in schema


def test_gemini_generator_failure_degrades_to_no_drafts():
    out = GeminiGenerator(client=FakeGemini(["junk", ConnectionError("down")])).generate(
        gen_request()
    )
    assert out.degraded and out.drafts == [] and "ConnectionError" in out.error


def test_gemini_generator_rejects_unknown_fields():
    bad = {"drafts": [{**GOOD["drafts"][0], "shell": "rm -rf /"}]}
    out = GeminiGenerator(client=FakeGemini([bad, bad])).generate(gen_request())
    assert out.degraded and out.drafts == []


def test_dummy_generator_is_deterministic_and_valid(catalog):
    gen = DummyGenerator(catalog)
    a, b = gen.generate(gen_request()), gen.generate(gen_request())
    assert a == b and a.drafts
    res = validate(a.drafts, catalog)
    assert res.accepted and not res.rejected


def test_dummy_generator_skips_path_only_scenarios(catalog):
    req = gen_request().model_copy(update={"customer_id": "customer-a"})
    out = DummyGenerator(catalog).generate(req)
    assert all("/orders" not in d.probe.path for d in out.drafts)


def test_outcome_model_defaults():
    assert GenerationOutcome().drafts == []
