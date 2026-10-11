"""GeminiPlanner: picks and orders scenarios. Model id and key come from the environment."""

from attack.agent.gemini import GeminiBase, load_dotenv
from attack.agent.models import PlanOutput, PlanRequest, TestPlan
from attack.agent.planner import DummyPlanner, sanitize_plan
from attack.agent.prompts import PROMPT_VERSION, SYSTEM_PROMPT, build_user_message

__all__ = ["GeminiPlanner", "load_dotenv"]


class GeminiPlanner(GeminiBase):
    def plan(self, request: PlanRequest) -> TestPlan:
        output, cost, error = self.generate_json(
            SYSTEM_PROMPT, build_user_message(request), PlanOutput
        )
        if output is None:
            fallback = DummyPlanner().plan(request)
            return fallback.model_copy(
                update={
                    "degraded": True,
                    "planner": "dummy-fallback",
                    "model": self.model,
                    "prompt_version": PROMPT_VERSION,
                    "cost_usd": cost,
                    "error": error,
                }
            )
        plan = TestPlan(
            **output.model_dump(),
            planner="gemini",
            model=self.model,
            prompt_version=PROMPT_VERSION,
            cost_usd=cost,
        )
        return sanitize_plan(plan, {s.id for s in request.scenarios}, request.max_scenarios)
