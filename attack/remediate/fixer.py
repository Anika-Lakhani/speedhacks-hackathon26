"""Remediation agent (MVP). The vulnerability *is* the flag, so the fix is flipping it off.

Gemini chooses which flag to disable for a confirmed scenario; the choice is a *data*
selection, validated in code against the flags that actually govern that scenario (mirrors
the planner's "model selects IDs, code decides" contract). An off-scope pick or an
unavailable model falls back to the mapped flag, so the fix always lands.
"""

from typing import Protocol

from pydantic import BaseModel, ConfigDict

from attack.agent.gemini import GeminiBase

PROMPT_VERSION = "fix-1"

SYSTEM_PROMPT = (
    "You are a defensive security remediation assistant working on OUR OWN demo systems. "
    "A test scenario has been CONFIRMED as a reproducible weakness. Each weakness is "
    "controlled by exactly one vulnerability flag; turning that flag OFF removes the "
    "weakness. Pick the single flag to disable from the allowed list. Never pick a flag "
    'outside that list. Reply with JSON only: {"flag": <name>, "rationale": <why>}.'
)


class FixDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    flag: str
    rationale: str


class FixRequest(BaseModel):
    customer_id: str
    scenario_id: str
    invariant: str | None = None
    allowed_flags: list[str]  # the flags that govern this scenario; always non-empty


class Fixer(Protocol):
    def decide(self, request: FixRequest) -> FixDecision: ...


def build_user_message(r: FixRequest) -> str:
    lines = [
        f"customer_id: {r.customer_id}",
        f"confirmed scenario: {r.scenario_id}",
        f"security invariant to restore: {r.invariant or '(unspecified)'}",
        f"allowed flags (choose exactly one to disable): {', '.join(r.allowed_flags)}",
    ]
    return "\n".join(lines)


class GeminiFlagFixer(GeminiBase):
    def decide(self, request: FixRequest) -> FixDecision:
        output, _cost, error = self.generate_json(
            SYSTEM_PROMPT, build_user_message(request), FixDecision
        )
        if output is None or output.flag not in request.allowed_flags:
            reason = error or f"model chose out-of-scope flag {getattr(output, 'flag', None)!r}"
            return FixDecision(
                flag=request.allowed_flags[0],
                rationale=f"deterministic fallback: disable the governing flag ({reason})",
            )
        return output


class DummyFlagFixer:
    """Deterministic fixer: disable the scenario's governing flag. Test/fallback only."""

    def decide(self, request: FixRequest) -> FixDecision:
        return FixDecision(
            flag=request.allowed_flags[0],
            rationale="deterministic: disable the flag that governs this weakness",
        )
