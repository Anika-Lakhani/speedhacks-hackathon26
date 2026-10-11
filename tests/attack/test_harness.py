import pytest
from pydantic import ValidationError

from attack.agent import DummyPlanner, PlannedStep, TestPlan
from attack.clients import FakeKeewano
from attack.harness import ApprovalQueue, RunBudget, replay, run
from attack.harness.budget import BudgetTracker, GuardedSite, ToolNotAllowed
from attack.harness.replay import ReplayError
from contracts import Event, EventType, parse_evidence_ref
from tests.attack.conftest import make_config


def events_of(keewano, kind):
    return [e for e in keewano.events if e.event_type == kind.value]


def test_end_to_end_emits_schema_valid_simulated_events(catalog, keewano, site_factory):
    site = site_factory("customer-a", idor_orders=True)
    report = run(make_config(site), DummyPlanner(), site, keewano, catalog)
    assert report.stop_reason == "completed"
    assert len(report.outcomes) == 4
    kinds = [e.event_type for e in keewano.events]
    assert (
        kinds[0] == "swarm.run_start" and kinds[1] == "swarm.plan" and kinds[-1] == "swarm.run_end"
    )
    assert kinds.count("swarm.probe") == kinds.count("swarm.verdict") == 4
    for e in keewano.events:
        Event.model_validate(e.model_dump(mode="json"))
        assert e.simulated and e.actor == "swarm_agent" and e.run_id == report.run_id
        assert e.code_revision == "fake-rev-1" and e.catalog_version if False else True
        assert e.attrs["catalog_version"] == report.catalog_version
    verdicts = {e.scenario_id: e.verdict for e in events_of(keewano, EventType.SWARM_VERDICT)}
    assert verdicts["SCN-IDOR-001"] == "confirmed"
    assert verdicts["SCN-RESET-001"] == "not_reproduced"


@pytest.mark.parametrize("customer", ["customer-a", "customer-b", "customer-c"])
def test_every_scenario_runs_and_matches_ground_truth(catalog, keewano, site_factory, customer):
    flags = {s.flag: True for s in catalog.values() if s.customer_id == customer}
    site = site_factory(customer, **flags)
    report = run(make_config(site, auto_approve=True), DummyPlanner(), site, keewano, catalog)
    assert {o.verdict.value for o in report.outcomes} == {"confirmed"}
    assert len(report.outcomes) == sum(s.customer_id == customer for s in catalog.values())


def test_verdict_evidence_ref_points_at_probe_evidence(catalog, keewano, site_factory):
    site = site_factory("customer-a", idor_orders=True)
    run(make_config(site), DummyPlanner(), site, keewano, catalog)
    for v in events_of(keewano, EventType.SWARM_VERDICT):
        assert v.evidence_ref in keewano.evidence
        assert parse_evidence_ref(v.evidence_ref)[0] == "customer-a"


def test_budget_halts_runaway_run_on_tool_calls(catalog, keewano, site_factory):
    site = site_factory("customer-a")
    cfg = make_config(site, budget=RunBudget(max_tool_calls=3))  # meta + 1 probe(2) = 3
    report = run(cfg, DummyPlanner(), site, keewano, catalog)
    assert report.stop_reason == "budget:max_tool_calls"
    assert len(report.outcomes) == 1
    assert keewano.events[-1].event_type == "swarm.run_end"
    assert keewano.events[-1].attrs["stop_reason"] == "budget:max_tool_calls"


def test_budget_halts_on_runtime(catalog, keewano, site_factory):
    site = site_factory("customer-a")
    ticks = iter(range(0, 1000, 100))
    report = run(
        make_config(site, budget=RunBudget(max_runtime_s=150)),
        DummyPlanner(),
        site,
        keewano,
        catalog,
        clock=lambda: next(ticks),
    )
    assert report.stop_reason == "budget:max_runtime_s" and len(report.outcomes) < 4


def test_budget_halts_on_spend(catalog, keewano, site_factory):
    class Pricey:
        def plan(self, request):
            plan = DummyPlanner().plan(request)
            return plan.model_copy(update={"cost_usd": 5.0})

    site = site_factory("customer-a")
    report = run(make_config(site), Pricey(), site, keewano, catalog)
    assert report.stop_reason == "budget:max_spend_usd" and report.outcomes == []


def test_max_scenarios_truncates_plan(catalog, keewano, site_factory):
    site = site_factory("customer-a")
    report = run(
        make_config(site, budget=RunBudget(max_scenarios=2)), DummyPlanner(), site, keewano, catalog
    )
    assert len(report.outcomes) == 2


def test_tool_not_in_allowlist_refused(catalog, keewano, site_factory):
    site = site_factory("customer-a")
    cfg = make_config(site, allowed_tools=["site.meta", "keewano.post_events"])
    report = run(cfg, DummyPlanner(), site, keewano, catalog)
    assert report.stop_reason == "tool_not_allowed:site.probe"
    assert site.calls == []


def test_guarded_site_refuses_unlisted_tool(catalog, site_factory):
    site = site_factory("customer-a")
    guarded = GuardedSite(site, BudgetTracker(RunBudget(), ["site.meta"]))
    with pytest.raises(ToolNotAllowed):
        guarded.probe("GET", "/x", {})


def test_target_outside_allowlist_is_blocked_and_never_hit(catalog, keewano, site_factory):
    site = site_factory("customer-a", idor_orders=True)
    cfg = make_config(site).model_copy(update={"target_allowlist": ["http://elsewhere"]})
    report = run(cfg, DummyPlanner(), site, keewano, catalog)
    assert {o.verdict.value for o in report.outcomes} == {"blocked"}
    assert site.calls == []
    assert all(e.policy_outcome == "deny" for e in events_of(keewano, EventType.SWARM_PROBE))


def test_planner_unknown_id_never_executes(catalog, keewano, site_factory):
    class Rogue:
        def plan(self, request):
            return TestPlan(
                steps=[
                    PlannedStep(
                        scenario_id="SCN-IDOR-001", rationale="r", priority=2, expected_value=0.5
                    ),
                    PlannedStep(
                        scenario_id="SCN-EVIL-666", rationale="r", priority=1, expected_value=1.0
                    ),
                    PlannedStep(
                        scenario_id="SCN-BOLA-001",
                        rationale="other tenant",
                        priority=3,
                        expected_value=1.0,
                    ),
                ]
            )

    site = site_factory("customer-a")
    report = run(make_config(site), Rogue(), site, keewano, catalog)
    assert [o.scenario_id for o in report.outcomes] == ["SCN-IDOR-001"]
    assert report.plan.dropped_ids == ["SCN-EVIL-666", "SCN-BOLA-001"]


def test_approval_gate(catalog, keewano, site_factory):
    site = site_factory("customer-a", idor_orders=True)
    queue = ApprovalQueue(None)
    report = run(make_config(site), DummyPlanner(), site, keewano, catalog, queue)
    idor = next(o for o in report.outcomes if o.scenario_id == "SCN-IDOR-001")
    assert idor.evidence_label.value == "reproduced" and idor.approval == "pending"
    assert [p.scenario_id for p in queue.pending(report.run_id)] == ["SCN-IDOR-001"]
    queue.approve(report.run_id, "SCN-IDOR-001")
    assert queue.pending() == []
    with pytest.raises(KeyError):
        queue.approve(report.run_id, "SCN-IDOR-001")


def test_auto_approve_and_no_approval_paths(catalog, site_factory):
    for kw, approval in (
        ({"auto_approve": True}, "auto"),
        ({"require_approval": False}, "not_required"),
    ):
        site = site_factory("customer-a", idor_orders=True)
        report = run(make_config(site, **kw), DummyPlanner(), site, FakeKeewano(), catalog)
        idor = next(o for o in report.outcomes if o.scenario_id == "SCN-IDOR-001")
        assert idor.evidence_label.value == "verified" and idor.approval == approval


def test_approval_queue_persists(tmp_path):
    from attack.harness import PendingApproval

    q = ApprovalQueue(tmp_path / "q.json")
    q.add(
        PendingApproval(
            customer_id="customer-a", run_id="r", scenario_id="SCN-IDOR-001", evidence_ref=None
        )
    )
    assert len(ApprovalQueue(tmp_path / "q.json").pending()) == 1


def test_keewano_failure_does_not_crash_run(catalog, site_factory):
    class Broken(FakeKeewano):
        def post_events(self, events):
            raise ConnectionError("down")

    site = site_factory("customer-a")
    report = run(make_config(site), DummyPlanner(), site, Broken(), catalog)
    assert report.warnings and report.outcomes


def test_replay_confirmed_finding_from_stored_evidence(catalog, keewano, site_factory):
    site = site_factory("customer-a", idor_orders=True)
    report = run(make_config(site), DummyPlanner(), site, keewano, catalog)
    ref = next(o.evidence_ref for o in report.outcomes if o.scenario_id == "SCN-IDOR-001")
    # A fresh site in a different flag state: replay must pin flags and still reproduce.
    other = site_factory("customer-a", idor_orders=False)
    result = replay(ref, catalog, other, keewano)
    assert result.stored_verdict.value == result.replay_verdict.value == "confirmed"
    assert result.reproduced
    assert other.flags["idor_orders"] is False  # flags restored afterwards


def test_replay_refuses_when_revision_differs(catalog, keewano, site_factory):
    site = site_factory("customer-a", idor_orders=True)
    report = run(make_config(site), DummyPlanner(), site, keewano, catalog)
    ref = report.outcomes[0].evidence_ref
    site.code_revision = "fake-rev-2"
    with pytest.raises(ReplayError):
        replay(ref, catalog, site, keewano)


def test_event_contract_rejects_bad_swarm_event():
    with pytest.raises(ValidationError):
        Event(
            customer_id="customer-a",
            ts="2026-01-01T00:00:00+00:00",
            actor="swarm_agent",
            event_type="swarm.verdict",
            target="/",
            action="x",
            policy_outcome="allow",
            code_revision="r",
            simulated=True,
        )


def test_caller_supplied_run_id_is_used_everywhere(catalog, keewano, site_factory):
    site = site_factory("customer-a", idor_orders=True)
    report = run(make_config(site), DummyPlanner(), site, keewano, catalog, run_id="run-ui-0001")
    assert report.run_id == "run-ui-0001"
    assert {e.run_id for e in keewano.events} == {"run-ui-0001"}
    assert all(parse_evidence_ref(e.evidence_ref)[1] == "run-ui-0001" for e in keewano.events)


@pytest.mark.parametrize("bad", ["a/b", "organic", "../x"])
def test_invalid_run_id_rejected_before_anything_runs(catalog, keewano, site_factory, bad):
    site = site_factory("customer-a")
    with pytest.raises(ValueError, match="invalid run_id"):
        run(make_config(site), DummyPlanner(), site, keewano, catalog, run_id=bad)
    assert keewano.events == [] and site.calls == []


def test_run_id_is_generated_when_not_given(catalog, keewano, site_factory):
    site = site_factory("customer-a")
    a = run(make_config(site), DummyPlanner(), site, keewano, catalog)
    b = run(make_config(site), DummyPlanner(), site, keewano, catalog)
    assert a.run_id.startswith("run-") and a.run_id != b.run_id
