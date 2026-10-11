"""Generated scenarios flowing through the whole harness."""

from attack.agent import DummyGenerator, DummyPlanner, GenerationOutcome
from attack.catalog.generation import (
    DraftParam,
    DraftProbe,
    DraftSignal,
    GeneratedStore,
    ScenarioDraft,
    load_full_catalog,
)
from attack.clients import FakeSite
from attack.engine import run_probe
from attack.harness import RunBudget, replay, run
from attack.verify import judge
from contracts import EventType
from tests.attack.conftest import make_config


def run_with(catalog, keewano, site, generator, store=None, planner=None, **cfg):
    store = store if store is not None else GeneratedStore(None)
    config = make_config(site, generate_max=3, **cfg)
    report = run(
        config,
        planner or DummyPlanner(),
        site,
        keewano,
        catalog,
        generator=generator,
        generated_store=store,
    )
    return report, store


class Static:
    """A generator returning fixed drafts, standing in for the model."""

    def __init__(self, drafts, cost=0.0):
        self.drafts, self.cost, self.requests = drafts, cost, []

    def generate(self, request):
        self.requests.append(request)
        return GenerationOutcome(
            drafts=self.drafts,
            generator="static",
            model="m",
            prompt_version="p",
            cost_usd=self.cost,
        )


def search_draft(status=500, body=("query_error",), q="' OR 1=1 --"):
    return ScenarioDraft(
        title="Search marker",
        weakness_class="injection",
        invariant="Input is never query syntax",
        flag="unsafe_input_handling",
        probe=DraftProbe(method="GET", path="/search", params=[DraftParam(name="q", value=q)]),
        expected_signal=DraftSignal(status=status, body_contains=list(body)),
        severity="high",
        rationale="r42 interpolates q",
    )


def test_generated_scenarios_run_and_are_judged_by_ground_truth(catalog, keewano, site_factory):
    site = site_factory("customer-c", unsafe_input_handling=True)
    report, store = run_with(catalog, keewano, site, DummyGenerator(catalog))
    gen_ids = [a["id"] for a in report.generation["accepted"]]
    assert gen_ids and not report.generation["rejected"]
    verdicts = {o.scenario_id: o.verdict.value for o in report.outcomes}
    assert verdicts["SCN-GEN-001"] == "confirmed"  # variant of the /search scenario, flag on
    assert all(store.records[i].runs == 1 for i in gen_ids if i in verdicts)


def test_wrong_guess_is_scored_inconclusive_not_echoed_back(catalog, keewano, site_factory):
    """The site answers by route, so a draft whose guessed signal is wrong cannot pass."""
    site = site_factory("customer-c", unsafe_input_handling=True)
    gen = Static([search_draft(status=200, body=("totally_made_up",))])
    report, _ = run_with(catalog, keewano, site, gen)
    gen_outcome = next(o for o in report.outcomes if o.scenario_id == "SCN-GEN-001")
    assert gen_outcome.verdict.value == "inconclusive"
    assert "did not trigger" in gen_outcome.notes


def test_correct_guess_with_flag_off_is_not_reproduced(catalog, keewano, site_factory):
    site = site_factory("customer-c", unsafe_input_handling=False)
    report, _ = run_with(catalog, keewano, site, Static([search_draft()]))
    o = next(o for o in report.outcomes if o.scenario_id == "SCN-GEN-001")
    assert o.verdict.value == "not_reproduced"


def test_invalid_drafts_never_reach_the_site(catalog, keewano, site_factory):
    """Structural gate: unknown endpoints and other customers' flags never run."""
    site = site_factory("customer-c", unsafe_input_handling=True)
    off_path = search_draft()
    off_path.probe.path = "/admin/export"
    wrong_flag = search_draft()
    wrong_flag.flag = "idor_orders"
    report, store = run_with(catalog, keewano, site, Static([off_path, wrong_flag]))
    assert report.generation["accepted"] == [] and len(report.generation["rejected"]) == 2
    assert not store.records
    assert all(path in {"/search", "/comments/preview", "/uploads"} for _, path in site.calls)


def test_payload_shaped_inputs_run_against_the_simulated_site(catalog, keewano, site_factory):
    site = site_factory("customer-c", unsafe_input_handling=True)
    report, _ = run_with(catalog, keewano, site, Static([search_draft(q="' OR 1=1 --")]))
    o = next(o for o in report.outcomes if o.scenario_id == "SCN-GEN-001")
    assert o.verdict.value == "confirmed"


def test_generation_info_and_origin_are_logged_in_events(catalog, keewano, site_factory):
    site = site_factory("customer-c", unsafe_input_handling=True)
    report, _ = run_with(catalog, keewano, site, Static([search_draft()]))
    plan = next(e for e in keewano.events if e.event_type == EventType.SWARM_PLAN.value)
    gen = plan.attrs["generation"]
    assert gen["model"] == "m" and gen["accepted"][0]["id"] == "SCN-GEN-001"
    assert gen["accepted"][0]["rationale"] == "r42 interpolates q"
    verdicts = [e for e in keewano.events if e.event_type == "swarm.verdict"]
    origins = {e.scenario_id: e.attrs["origin"] for e in verdicts}
    assert origins["SCN-GEN-001"] == "generated" and origins["SCN-INJ-001"] == "curated"
    end = keewano.events[-1]
    assert end.attrs["generated_ids"] == ["SCN-GEN-001"]


def test_planner_sees_generated_scenarios_marked_as_such(catalog, keewano, site_factory):
    seen = []

    class Spy(DummyPlanner):
        def plan(self, request):
            seen.extend(request.scenarios)
            return super().plan(request)

    site = site_factory("customer-c")
    run_with(catalog, keewano, site, Static([search_draft()]), planner=Spy())
    assert {s.id: s.origin for s in seen}["SCN-GEN-001"] == "generated"


def test_generator_receives_code_events_flags_and_existing(catalog, keewano, site_factory):
    site = site_factory("customer-c")
    gen = Static([])
    run_with(
        catalog,
        keewano,
        site,
        gen,
        code_context={"app.py": "def search(): ..."},
        diff_summary="r42 search change",
        changed_surfaces=["/search"],
    )
    req = gen.requests[0]
    assert req.code_context == {"app.py": "def search(): ..."}
    assert req.diff_summary == "r42 search change" and req.changed_surfaces == ["/search"]
    assert {f["flag"] for f in req.flags} == {
        "unsafe_input_handling",
        "missing_output_encoding",
        "insecure_upload_path",
    }  # only this customer's flags
    assert {e["id"] for e in req.existing} == {"SCN-INJ-001", "SCN-XSS-001", "SCN-UPLOAD-001"}
    assert "injection_marker" in req.fixtures


def test_recent_events_reach_generator_and_planner(catalog, keewano, site_factory):
    from tests.attack.test_events_context import organic_event

    keewano.events.append(organic_event())
    site = site_factory("customer-c")
    gen = Static([])
    run_with(catalog, keewano, site, gen)
    assert gen.requests[0].recent_events[0]["event_type"] == "search.query"


def test_events_not_read_when_tool_not_allowed(catalog, keewano, site_factory):
    from tests.attack.test_events_context import organic_event

    keewano.events.append(organic_event())
    gen = Static([])
    site = site_factory("customer-c")
    run_with(
        catalog,
        keewano,
        site,
        gen,
        allowed_tools=["site.meta", "site.probe", "keewano.post_events"],
    )
    assert gen.requests[0].recent_events == []


def test_generator_spend_counts_against_budget(catalog, keewano, site_factory):
    site = site_factory("customer-c")
    config = make_config(site, generate_max=3, budget=RunBudget(max_spend_usd=0.5))
    report = run(
        config,
        DummyPlanner(),
        site,
        keewano,
        catalog,
        generator=Static([search_draft()], cost=2.0),
        generated_store=GeneratedStore(None),
    )
    assert report.stop_reason == "budget:max_spend_usd" and report.outcomes == []
    assert keewano.events[-1].event_type == "swarm.run_end"


def test_crashing_generator_does_not_stop_curated_tests(catalog, keewano, site_factory):
    class Boom:
        def generate(self, request):
            raise RuntimeError("model exploded")

    site = site_factory("customer-c", unsafe_input_handling=True)
    report, _ = run_with(catalog, keewano, site, Boom())
    assert report.generation["degraded"] and "RuntimeError" in report.generation["error"]
    assert {o.scenario_id for o in report.outcomes} == {
        "SCN-INJ-001",
        "SCN-XSS-001",
        "SCN-UPLOAD-001",
    }


def test_generation_disabled_by_default(catalog, keewano, site_factory):
    site = site_factory("customer-c")
    gen = Static([search_draft()])
    config = make_config(site)  # generate_max defaults to 0
    report = run(config, DummyPlanner(), site, keewano, catalog, generator=gen)
    assert report.generation is None and gen.requests == []


def test_second_run_dedupes_against_the_store(catalog, keewano, site_factory):
    store = GeneratedStore(None)
    gen = DummyGenerator(catalog)
    site = site_factory("customer-c")
    first, _ = run_with(catalog, keewano, site, gen, store=store)
    second, _ = run_with(catalog, keewano, site, gen, store=store)
    assert first.generation["accepted"] and not second.generation["accepted"]
    assert all("duplicate" in r["reason"] for r in second.generation["rejected"])


def test_generated_finding_replays_from_stored_evidence(catalog, keewano, site_factory):
    store = GeneratedStore(None)
    site = site_factory("customer-c", unsafe_input_handling=True)
    report, _ = run_with(catalog, keewano, site, Static([search_draft()]), store=store)
    ref = next(o.evidence_ref for o in report.outcomes if o.scenario_id == "SCN-GEN-001")
    other = site_factory("customer-c", unsafe_input_handling=False)
    result = replay(ref, load_full_catalog(store), other, keewano)
    assert result.reproduced and result.replay_verdict.value == "confirmed"


# --- the fake site answers by route -----------------------------------------------------


def test_fake_site_routes_by_endpoint_and_method(catalog):
    site = FakeSite("customer-c", catalog, {"unsafe_input_handling": True})
    hdr = {"X-SwarmShield-Probe": "SCN-GEN-007"}  # unknown id: route still decides
    assert site.probe("GET", "/search", hdr, query={"q": "x"}).status == 500
    assert site.probe("POST", "/search", hdr).status == 405
    assert site.probe("GET", "/nope", hdr).status == 404
    assert site.probe("GET", "/search", {}).status == 404  # unmarked requests are not simulated


def test_fake_site_ignores_generated_scenarios_when_building_routes(catalog):
    gen = search_draft(status=418, body=("teapot",))
    from attack.catalog import load_flags
    from attack.catalog.generation import validate_drafts

    s = validate_drafts([gen], "customer-c", load_flags(), [], max_new=1).accepted[0]
    site = FakeSite("customer-c", {**catalog, s.id: s}, {"unsafe_input_handling": True})
    res = run_probe(s, site, "run-1")
    assert res.response["status"] == 500  # the curated route, not the draft's guess
    assert judge(s, res).verdict.value == "inconclusive"
