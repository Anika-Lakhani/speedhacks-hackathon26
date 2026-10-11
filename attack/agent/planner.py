from typing import Protocol

from attack.agent.models import PlannedStep, PlanRequest, SkippedScenario, TestPlan

SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}


class Planner(Protocol):
    def plan(self, request: PlanRequest) -> TestPlan: ...


def sanitize_plan(plan: TestPlan, allowed_ids: set[str], max_scenarios: int) -> TestPlan:
    """Enforced in code, not the prompt: unknown/duplicate IDs dropped, plan truncated."""
    dropped: list[str] = []
    seen: set[str] = set()
    kept: list[PlannedStep] = []
    for step in sorted(plan.steps, key=lambda s: s.priority):
        if step.scenario_id not in allowed_ids:
            dropped.append(step.scenario_id)
        elif step.scenario_id not in seen:
            seen.add(step.scenario_id)
            kept.append(step)
    skipped = list(plan.skipped)
    for step in kept[max_scenarios:]:
        skipped.append(SkippedScenario(scenario_id=step.scenario_id, reason="over budget"))
    return plan.model_copy(
        update={
            "steps": kept[:max_scenarios],
            "skipped": skipped,
            "dropped_ids": plan.dropped_ids + dropped,
        }
    )


class DummyPlanner:
    """Deterministic plan: changed surfaces first, then severity. Test/fallback only."""

    def plan(self, request: PlanRequest) -> TestPlan:
        def changed(path: str) -> bool:
            base = path.split("{")[0].rstrip("/")
            return any(
                base.startswith(c.rstrip("/")) or c.startswith(base)
                for c in request.changed_surfaces
                if base
            )

        ranked = sorted(
            request.scenarios,
            key=lambda s: (not changed(s.path), -SEVERITY_WEIGHT.get(s.severity, 0), s.id),
        )
        steps = [
            PlannedStep(
                scenario_id=s.id,
                rationale=("touches a recently changed surface; " if changed(s.path) else "")
                + f"{s.severity} severity {s.weakness_class}",
                priority=i,
                expected_value=round(
                    min(
                        1.0,
                        SEVERITY_WEIGHT.get(s.severity, 0.25) * (1.0 if changed(s.path) else 0.7),
                    ),
                    2,
                ),
            )
            for i, s in enumerate(ranked, start=1)
        ]
        return sanitize_plan(
            TestPlan(steps=steps, planner="dummy"),
            {s.id for s in request.scenarios},
            request.max_scenarios,
        )
