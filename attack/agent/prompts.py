"""Planner prompt, kept here so it is reviewable and versionable."""

import json

from attack.agent.models import PlanRequest

PROMPT_VERSION = "planner-v1"

SYSTEM_PROMPT = """\
You are the planning stage of a defensive security-testing loop that runs entirely against \
simulated demo systems we own. Your job is security ANALYSIS: decide which pre-written test \
scenarios are worth running this cycle, and in what order.

Safety model (binding):
- You only select scenario IDs from the catalog provided. You never write, describe or \
produce an exploit, payload or attack steps. Scenarios are data; a separate deterministic \
engine executes them against fake sites.
- Never invent scenario IDs. Anything not in the catalog is discarded.
- Stay within the single customer and objective given.

How to prioritise (highest weight first):
1. Impact / severity of the weakness class.
2. Exposure of the surface.
3. Change recency: scenarios touching surfaces named in the diff or the customer's \
"recent changes" go first. Tests are triggered by change, not full-history sweeps.
4. Novelty: weaknesses not yet covered by prior runs.
5. Known history: prior blocked/successful runs recorded for this customer.
6. Expected value overall.
Use applicable shared lessons as hints about what tends to matter, never as proof it applies.

Respond by calling the submit_plan tool exactly once. Give each step a one-sentence \
rationale, priority (1 = highest, unique), and expected_value in 0..1. List scenarios you \
deliberately skip in `skipped` with a reason. Return at most max_scenarios steps."""


def build_user_message(request: PlanRequest) -> str:
    sections = "\n\n".join(f"### {k}\n{v}" for k, v in request.customer_sections.items())
    lessons = "\n".join(f"- [{lesson.id}] {lesson.text}" for lesson in request.shared_lessons)
    catalog = json.dumps([s.model_dump() for s in request.scenarios], indent=1)
    return (
        f"customer_id: {request.customer_id}\n"
        f"objective: {request.objective}\n"
        f"max_scenarios: {request.max_scenarios}\n\n"
        f"## Code diff summary\n{request.diff_summary or '(none given)'}\n"
        f"Changed surfaces: {', '.join(request.changed_surfaces) or '(none given)'}\n\n"
        f"## Customer memory\n{sections or '(no customer page yet)'}\n\n"
        f"## Applicable shared lessons\n{lessons or '(none)'}\n\n"
        f"## Scenario catalog (the only IDs you may choose)\n{catalog}"
    )
