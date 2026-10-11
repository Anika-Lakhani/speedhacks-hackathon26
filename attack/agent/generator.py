"""Scenario generation: the LLM drafts new scenarios as data; code validates them."""

from typing import Protocol

from pydantic import BaseModel

from attack.agent.gemini import GeminiBase
from attack.agent.models import SharedLesson
from attack.agent.prompts import (
    GENERATOR_PROMPT_VERSION,
    GENERATOR_SYSTEM_PROMPT,
    build_generator_message,
)
from attack.catalog import Catalog
from attack.catalog.generation import (
    DraftParam,
    DraftProbe,
    DraftSignal,
    GenerationOutput,
    ScenarioDraft,
)


class GenerationRequest(BaseModel):
    customer_id: str
    objective: str
    max_new: int
    customer_sections: dict[str, str] = {}
    diff_summary: str = ""
    changed_surfaces: list[str] = []
    code_context: dict[str, str] = {}  # path -> (redacted, truncated) source
    recent_events: list[dict] = []
    shared_lessons: list[SharedLesson] = []
    flags: list[dict]  # [{flag, endpoints, weakness_classes}]
    existing: list[dict]  # [{id, flag, method, path, params, title, origin}]
    fixtures: list[str]
    marker_rules: str


class GenerationOutcome(BaseModel):
    drafts: list[ScenarioDraft] = []
    generator: str = "unknown"
    model: str | None = None
    prompt_version: str | None = None
    cost_usd: float = 0.0
    degraded: bool = False
    error: str | None = None


class ScenarioGenerator(Protocol):
    def generate(self, request: GenerationRequest) -> GenerationOutcome: ...


class GeminiGenerator(GeminiBase):
    def generate(self, request: GenerationRequest) -> GenerationOutcome:
        output, cost, error = self.generate_json(
            GENERATOR_SYSTEM_PROMPT, build_generator_message(request), GenerationOutput
        )
        return GenerationOutcome(
            drafts=output.drafts if output else [],
            generator="gemini",
            model=self.model,
            prompt_version=GENERATOR_PROMPT_VERSION,
            cost_usd=cost,
            degraded=output is None,  # on failure: no new scenarios, curated ones still run
            error=error,
        )


class DummyGenerator:
    """Deterministic: a marker-valued variant of each curated scenario's non-path param.
    Test and offline-demo use only."""

    def __init__(self, catalog: Catalog):
        self._catalog = catalog

    def generate(self, request: GenerationRequest) -> GenerationOutcome:
        drafts: list[ScenarioDraft] = []
        for s in sorted(self._catalog.values(), key=lambda x: x.id):
            if s.customer_id != request.customer_id or s.origin != "curated":
                continue
            names = [k for k in s.probe.params if f"{{{k}}}" not in s.probe.path]
            if not names:
                continue
            params = {**s.probe.params, names[0]: "SWARMSHIELD_VARIANT"}
            sig = s.expected_signal
            drafts.append(
                ScenarioDraft(
                    title=f"{s.title} (variant: marker in {names[0]})",
                    weakness_class=s.weakness_class,
                    invariant=s.invariant,
                    flag=s.flag,
                    preconditions=s.preconditions,
                    probe=DraftProbe(
                        method=s.probe.method,
                        path=s.probe.path,
                        params=[DraftParam(name=k, value=v) for k, v in params.items()],
                    ),
                    expected_signal=DraftSignal(
                        status=sig.status or 200,
                        body_contains=sig.body_contains,
                        header_absent=sig.header_absent,
                        owner_is_other=sig.owner_is_other,
                    ),
                    severity=s.severity,
                    rationale=f"Deterministic variant of {s.id} using a marker value.",
                )
            )
        return GenerationOutcome(
            drafts=drafts[: request.max_new], generator="dummy", prompt_version="dummy"
        )
