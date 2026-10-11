"""ClaudePlanner: the real planner. Model id and key come from the environment."""

import os
from pathlib import Path
from typing import Any

from attack.agent.models import PlanOutput, PlanRequest, TestPlan
from attack.agent.planner import DummyPlanner, sanitize_plan
from attack.agent.prompts import PROMPT_VERSION, SYSTEM_PROMPT, build_user_message

DEFAULT_MODEL = "claude-opus-5-5"
TOOL_NAME = "submit_plan"
# Rough $/Mtok used only for the budget tracker's spend estimate; override via env.
DEFAULT_PRICE_IN = 15.0
DEFAULT_PRICE_OUT = 75.0


def load_dotenv(path: Path = Path(".env")) -> None:
    """Minimal .env reader; real environment variables win."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip("'\""))


class ClaudePlanner:
    def __init__(self, client: Any = None, model: str | None = None, max_tokens: int = 2000):
        load_dotenv()
        self.model = model or os.environ.get("ANTHROPIC_MODEL", DEFAULT_MODEL)
        self.max_tokens = max_tokens
        if client is None:
            import anthropic

            key = os.environ.get("ANTHROPIC_KEY") or os.environ.get("ANTHROPIC_API_KEY")
            client = anthropic.Anthropic(api_key=key)
        self.client = client

    def _cost(self, usage: Any) -> float:
        price_in = float(os.environ.get("ANTHROPIC_PRICE_IN", DEFAULT_PRICE_IN))
        price_out = float(os.environ.get("ANTHROPIC_PRICE_OUT", DEFAULT_PRICE_OUT))
        tokens_in = getattr(usage, "input_tokens", 0) or 0
        tokens_out = getattr(usage, "output_tokens", 0) or 0
        return (tokens_in * price_in + tokens_out * price_out) / 1_000_000

    def _call(self, request: PlanRequest) -> tuple[PlanOutput, float]:
        resp = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": build_user_message(request)}],
            tools=[
                {
                    "name": TOOL_NAME,
                    "description": "Submit the ordered test plan.",
                    "input_schema": PlanOutput.model_json_schema(),
                }
            ],
            tool_choice={"type": "tool", "name": TOOL_NAME},
        )
        block = next(b for b in resp.content if b.type == "tool_use" and b.name == TOOL_NAME)
        return PlanOutput.model_validate(block.input), self._cost(resp.usage)

    def plan(self, request: PlanRequest) -> TestPlan:
        cost = 0.0
        for _ in range(2):  # one retry on a decode failure
            try:
                output, spent = self._call(request)
            except Exception:  # decode, network or auth failure: retry once, then degrade
                continue
            cost += spent
            plan = TestPlan(
                **output.model_dump(),
                planner="claude",
                model=self.model,
                prompt_version=PROMPT_VERSION,
                cost_usd=cost,
            )
            return sanitize_plan(plan, {s.id for s in request.scenarios}, request.max_scenarios)
        fallback = DummyPlanner().plan(request)
        return fallback.model_copy(
            update={
                "degraded": True,
                "planner": "dummy-fallback",
                "model": self.model,
                "prompt_version": PROMPT_VERSION,
                "cost_usd": cost,
            }
        )
