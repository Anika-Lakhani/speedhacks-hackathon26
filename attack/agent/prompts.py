"""Planner prompt, kept here so it is reviewable and versionable."""

import json

from attack.agent.models import PlanRequest

PROMPT_VERSION = "planner-v3"
GENERATOR_PROMPT_VERSION = "generator-v2"

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
Scenarios marked origin=generated were drafted this cycle and have no run history; weigh \
them on their invariant and the surface they touch. Recent events show what the system has \
actually been doing; use them to judge exposure.
Use applicable shared lessons as hints about what tends to matter, never as proof it applies.

Respond with a single JSON object matching the provided schema. Give each step a one-sentence \
rationale, priority (1 = highest, unique), and expected_value in 0..1. List scenarios you \
deliberately skip in `skipped` with a reason. Return at most max_scenarios steps."""


def build_user_message(request: PlanRequest) -> str:
    events = json.dumps(request.recent_events[-40:]) if request.recent_events else "(none)"
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
        f"## Recent events (newest last)\n{events}\n\n"
        f"## Applicable shared lessons\n{lessons or '(none)'}\n\n"
        f"## Scenario catalog (the only IDs you may choose)\n{catalog}"
    )


GENERATOR_SYSTEM_PROMPT = """\
You are the test-design stage of a defensive security-testing loop. Everything it touches \
is a set of simulated demo systems that we own; no real user, system or data is involved. \
Your job is security ANALYSIS: read the code, events and notes provided and design NEW \
scenarios (test definitions) that would reveal whether the system violates a security \
invariant.

A scenario is DATA, not an attack. It names one inert, header-tagged request, the invariant \
it checks, and what a vulnerable response would look like. A separate deterministic engine \
sends the request to a simulated site; a verifier compares the reply with ground truth. You \
never execute anything.

Hard rules (enforced by code; violations are discarded):
- Only use flags from the provided list, and only paths that are endpoints of that flag.
- Methods: GET or POST only.
- Parameter values: `fixture:<name>` from the provided list, or a marker string. Path \
placeholder values must be fixtures.
- A marker is ONE token: it must start with SWARMSHIELD, contain NO spaces, and use only \
letters, digits and _-.:/'<>=%. Good: SWARMSHIELD_QUOTE'   SWARMSHIELD_TAG<b>   \
SWARMSHIELD_DOTDOT../   SWARMSHIELD_PCT%25   SWARMSHIELD_LONG_AAAAAAAAAAAAAAAA. \
Bad (rejected): anything with a space, SQL or script text, event handlers, javascript: URLs, \
absolute file paths, shell syntax, credentials, and words like select/union/sleep/passwd/\
onerror/alert.
- You are NOT writing a payload that works. The simulated site decides vulnerable-or-not from \
its flags; a marker only has to be shaped like the kind of input that would stress the code \
you can see (a stray quote, a tag character, a path separator, an oversized token). Never try \
to make a value "work"; a plain marker is the correct answer.
- Do not duplicate an existing scenario (same flag, method, path and params).
- Propose at most max_new scenarios. Fewer, well-justified ones beat many.

How to choose what to design:
1. Look at what changed (diff, code, recent events) and which invariants that could break.
2. Prefer surfaces and parameters that existing scenarios do not already cover: a different \
parameter, a different endpoint of the same flag, a different object, a different state.
3. Set expected_signal from evidence in the code or events: the status and body fields a \
VULNERABLE response would show. If you cannot infer it, choose the most conservative signal \
and say so in the rationale.
4. The rationale must cite what in the code, events or notes motivated the scenario.

Respond with a single JSON object matching the provided schema."""


def build_generator_message(request) -> str:
    sections = "\n\n".join(f"### {k}\n{v}" for k, v in request.customer_sections.items())
    code = "\n\n".join(
        f"### {path}\n```\n{text}\n```" for path, text in request.code_context.items()
    )
    lessons = "\n".join(f"- [{lesson.id}] {lesson.text}" for lesson in request.shared_lessons)
    events = json.dumps(request.recent_events[-40:]) if request.recent_events else "(none)"
    flags = json.dumps(request.flags, indent=1)
    existing = json.dumps(request.existing, indent=1)
    return (
        f"customer_id: {request.customer_id}\n"
        f"objective: {request.objective}\n"
        f"max_new: {request.max_new}\n\n"
        f"## Code diff summary\n{request.diff_summary or '(none given)'}\n"
        f"Changed surfaces: {', '.join(request.changed_surfaces) or '(none given)'}\n\n"
        f"## Code\n{code or '(none given)'}\n\n"
        f"## Customer memory\n{sections or '(no customer page yet)'}\n\n"
        f"## Recent events (newest last)\n{events}\n\n"
        f"## Applicable shared lessons\n{lessons or '(none)'}\n\n"
        f"## Flags you may target (flag -> endpoints)\n{flags}\n\n"
        f"## Existing scenarios (do not duplicate)\n{existing}\n\n"
        f"## Fixture names\n{', '.join(request.fixtures)}\n\n"
        f"## Value rules\n{request.marker_rules}"
    )
