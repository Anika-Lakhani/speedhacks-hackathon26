"""GeminiPlanner: the real planner. Model id and key come from the environment."""

import os
from pathlib import Path
from typing import Any

from attack.agent.models import PlanOutput, PlanRequest, TestPlan
from attack.agent.planner import DummyPlanner, sanitize_plan
from attack.agent.prompts import PROMPT_VERSION, SYSTEM_PROMPT, build_user_message

DEFAULT_MODEL = "gemini-2.5-pro"
# Rough $/Mtok used only for the budget tracker's spend estimate; override via env.
DEFAULT_PRICE_IN = 1.25
DEFAULT_PRICE_OUT = 10.0


def load_dotenv(path: Path = Path(".env")) -> None:
    """Minimal .env reader; real environment variables win."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def _strip_additional_properties(node: Any) -> Any:
    """Gemini's structured output rejects `additionalProperties`; strictness is enforced
    on our side by PlanOutput (extra='forbid') when the response is validated."""
    if isinstance(node, dict):
        return {
            k: _strip_additional_properties(v)
            for k, v in node.items()
            if k != "additionalProperties"
        }
    if isinstance(node, list):
        return [_strip_additional_properties(v) for v in node]
    return node


RESPONSE_SCHEMA = _strip_additional_properties(PlanOutput.model_json_schema())


class GeminiPlanner:
    def __init__(self, client: Any = None, model: str | None = None):
        load_dotenv()
        self.model = model or os.environ.get("GEMINI_MODEL", DEFAULT_MODEL)
        if client is None:
            from google import genai

            client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))
        self.client = client

    def _cost(self, usage: Any) -> float:
        price_in = float(os.environ.get("GEMINI_PRICE_IN", DEFAULT_PRICE_IN))
        price_out = float(os.environ.get("GEMINI_PRICE_OUT", DEFAULT_PRICE_OUT))
        tokens_in = getattr(usage, "prompt_token_count", 0) or 0
        tokens_out = getattr(usage, "candidates_token_count", 0) or 0
        return (tokens_in * price_in + tokens_out * price_out) / 1_000_000

    def _call(self, request: PlanRequest) -> tuple[PlanOutput, float]:
        resp = self.client.models.generate_content(
            model=self.model,
            contents=build_user_message(request),
            config={
                "system_instruction": SYSTEM_PROMPT,
                "response_mime_type": "application/json",
                "response_json_schema": RESPONSE_SCHEMA,
            },
        )
        # resp.text is None when a safety filter blocks the reply; that fails validation.
        output = PlanOutput.model_validate_json(resp.text)
        return output, self._cost(getattr(resp, "usage_metadata", None))

    def plan(self, request: PlanRequest) -> TestPlan:
        cost = 0.0
        for _ in range(2):  # one retry on a decode failure
            try:
                output, spent = self._call(request)
            except Exception:  # decode, filter, network or auth failure: retry once, then degrade
                continue
            cost += spent
            plan = TestPlan(
                **output.model_dump(),
                planner="gemini",
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
