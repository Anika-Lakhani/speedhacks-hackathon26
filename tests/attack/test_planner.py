import json
from types import SimpleNamespace

from attack.agent import DummyPlanner, GeminiPlanner, PlanRequest, ScenarioBrief, TestPlan
from attack.agent.models import PlannedStep
from attack.agent.planner import sanitize_plan
from attack.agent.prompts import build_user_message


def request(catalog, customer="customer-a", max_scenarios=12, **kw):
    briefs = [
        ScenarioBrief(
            id=s.id,
            title=s.title,
            weakness_class=s.weakness_class,
            severity=s.severity,
            invariant=s.invariant,
            path=s.probe.path,
        )
        for s in catalog.values()
        if s.customer_id == customer
    ]
    return PlanRequest(
        customer_id=customer, objective="t", max_scenarios=max_scenarios, scenarios=briefs, **kw
    )


def step(sid, p):
    return PlannedStep(scenario_id=sid, rationale="r", priority=p, expected_value=0.5)


def test_unknown_ids_dropped_and_logged():
    plan = sanitize_plan(
        TestPlan(steps=[step("SCN-FAKE-999", 1), step("SCN-IDOR-001", 2)]), {"SCN-IDOR-001"}, 5
    )
    assert [s.scenario_id for s in plan.steps] == ["SCN-IDOR-001"]
    assert plan.dropped_ids == ["SCN-FAKE-999"]


def test_plan_truncated_to_budget_and_deduped():
    plan = sanitize_plan(
        TestPlan(
            steps=[
                step("SCN-A-001", 1),
                step("SCN-A-001", 2),
                step("SCN-B-001", 3),
                step("SCN-C-001", 4),
            ]
        ),
        {"SCN-A-001", "SCN-B-001", "SCN-C-001"},
        2,
    )
    assert [s.scenario_id for s in plan.steps] == ["SCN-A-001", "SCN-B-001"]
    assert [s.scenario_id for s in plan.skipped] == ["SCN-C-001"]


def test_dummy_favors_changed_surfaces(catalog):
    plan = DummyPlanner().plan(request(catalog, changed_surfaces=["/orders"]))
    assert plan.steps[0].scenario_id == "SCN-IDOR-001"  # high, but changed beats critical
    plan2 = DummyPlanner().plan(request(catalog))
    assert plan2.steps[0].scenario_id == "SCN-RESET-001"  # no change info: severity wins


def test_dummy_is_deterministic_and_respects_budget(catalog):
    a = DummyPlanner().plan(request(catalog, max_scenarios=2))
    b = DummyPlanner().plan(request(catalog, max_scenarios=2))
    assert a == b and len(a.steps) == 2


def test_prompt_contains_catalog_ids_and_diff(catalog):
    msg = build_user_message(request(catalog, diff_summary="touched login handler"))
    assert "SCN-IDOR-001" in msg and "touched login handler" in msg


class FakeGemini:
    """Stands in for genai.Client: returns canned response texts, or raises."""

    def __init__(self, payloads):
        self.payloads = list(payloads)
        self.calls = []
        self.models = self

    def generate_content(self, **kw):
        self.calls.append(kw)
        p = self.payloads.pop(0)
        if isinstance(p, Exception):
            raise p
        usage = SimpleNamespace(prompt_token_count=1000, candidates_token_count=200)
        return SimpleNamespace(
            text=p if isinstance(p, str) else json.dumps(p), usage_metadata=usage
        )


GOOD = {
    "steps": [
        {
            "scenario_id": "SCN-RATE-001",
            "rationale": "login changed",
            "priority": 1,
            "expected_value": 0.9,
        },
        {
            "scenario_id": "SCN-HALLUCINATED-001",
            "rationale": "x",
            "priority": 2,
            "expected_value": 0.1,
        },
    ]
}


def test_gemini_planner_uses_env_model_and_json_schema(catalog, monkeypatch):
    monkeypatch.setenv("GEMINI_MODEL", "gemini-test-model")
    client = FakeGemini([GOOD])
    plan = GeminiPlanner(client=client).plan(request(catalog))
    call = client.calls[0]
    assert call["model"] == "gemini-test-model"
    assert call["config"]["response_mime_type"] == "application/json"
    assert "SCN-RATE-001" in call["contents"]
    assert [s.scenario_id for s in plan.steps] == ["SCN-RATE-001"]
    assert plan.dropped_ids == ["SCN-HALLUCINATED-001"]
    assert plan.planner == "gemini" and plan.cost_usd > 0 and not plan.degraded


def test_gemini_planner_retries_once_then_succeeds(catalog):
    client = FakeGemini(["not json at all", GOOD])
    plan = GeminiPlanner(client=client).plan(request(catalog))
    assert len(client.calls) == 2 and plan.planner == "gemini"


def test_gemini_planner_falls_back_degraded(catalog):
    client = FakeGemini([{"bad": 1}, ConnectionError("no network")])
    plan = GeminiPlanner(client=client).plan(request(catalog))
    assert plan.degraded and plan.planner == "dummy-fallback" and plan.steps
    assert "ConnectionError" in plan.error


def test_safety_filtered_reply_falls_back(catalog):
    class Blocked(FakeGemini):
        def generate_content(self, **kw):
            self.calls.append(kw)
            return SimpleNamespace(text=None, usage_metadata=None)

    plan = GeminiPlanner(client=Blocked([])).plan(request(catalog))
    assert plan.degraded and plan.steps


def test_extra_fields_in_model_output_rejected(catalog):
    bad = {"steps": [{**GOOD["steps"][0], "run_command": "rm -rf /"}]}
    plan = GeminiPlanner(client=FakeGemini([bad, bad])).plan(request(catalog))
    assert plan.degraded  # off-schema output is rejected, never executed


def test_schema_sent_to_model_is_plan_output_only_and_gemini_safe(catalog):
    client = FakeGemini([GOOD])
    GeminiPlanner(client=client).plan(request(catalog))
    schema = client.calls[0]["config"]["response_json_schema"]
    assert set(schema["properties"]) == {"steps", "skipped"}
    assert "additionalProperties" not in json.dumps(schema)
