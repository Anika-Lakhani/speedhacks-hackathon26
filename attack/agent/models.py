from pydantic import BaseModel, ConfigDict, Field


class ScenarioBrief(BaseModel):
    id: str
    title: str
    weakness_class: str
    severity: str
    invariant: str
    path: str


class SharedLesson(BaseModel):
    id: str
    text: str


class PlanRequest(BaseModel):
    customer_id: str
    objective: str
    max_scenarios: int
    customer_sections: dict[str, str] = {}  # customer-X.md §2/§3/§4/§7/§9, by heading
    diff_summary: str = ""
    changed_surfaces: list[str] = []
    shared_lessons: list[SharedLesson] = []
    scenarios: list[ScenarioBrief]


class PlannedStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    rationale: str
    priority: int = Field(ge=1, description="1 = highest")
    expected_value: float = Field(ge=0, le=1)


class SkippedScenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    reason: str


class PlanOutput(BaseModel):
    """The only shape the model is allowed to return."""

    model_config = ConfigDict(extra="forbid")

    steps: list[PlannedStep]
    skipped: list[SkippedScenario] = []


class TestPlan(PlanOutput):
    __test__ = False  # not a pytest class

    planner: str = "unknown"
    model: str | None = None
    prompt_version: str | None = None
    degraded: bool = False
    cost_usd: float = 0.0
    dropped_ids: list[str] = []
