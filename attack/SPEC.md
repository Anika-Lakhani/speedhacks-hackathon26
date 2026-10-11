# Dev A — `attack/` technical spec

**Scope:** the offense side of the loop. **Safety model:** simulation only. No real
exploitation ever (overview §5.6): scenarios are *data* describing benign, header-tagged
probes; the demo site returns a *simulated* outcome derived from its vulnerability flags;
Claude only plans, prioritizes and interprets. Nothing here sends an exploit.

**Reads:** `customer-X.md` and `shared-intelligence.md` (Dev C), Keewano event slices and
`contracts/flags.yaml` (Dev B). **Writes:** `swarm.*` events to Keewano. **Imports:**
`contracts.Event`, `contracts.Verdict`.

```
attack/
  catalog/     scenario catalog (YAML) + loader + models
  agent/       the planner (Claude): picks scenarios, interprets results
  engine/      fires marked probes at the demo site, returns raw ProbeResult
  verify/      ProbeResult + invariant + flag ground truth -> Verdict
  harness/     orchestrates a run; enforces budgets/allowlists; logs to Keewano
  clients/     thin httpx wrappers for sites and the Keewano API
```

Control flow of one run:
`harness` → `agent.plan` → for each scenario: `engine.run_probe` → `verify.judge` →
`harness` logs `swarm.*` events → `harness` emits run summary.

---

## 1. Scenario catalog (`attack/catalog/`)

A scenario is **data the model reads, never code the model executes.** One YAML file per
customer under `attack/catalog/scenarios/` (e.g. `customer-a.yaml`), each a list of:

```yaml
- id: SCN-IDOR-001                    # unique, SCN-<CLASS>-<NNN>
  title: Horizontal IDOR on order detail
  customer_id: customer-a
  weakness_class: idor                # taxonomy key, aligns with shared-intelligence
  invariant: "A user can only read their own orders"
  flag: idor_orders                   # must exist in contracts/flags.yaml for this customer
  preconditions: ["authenticated session", "flag:idor_orders == on"]
  probe:
    kind: benign_request              # only kind for MVP; harness-executed, marked
    method: GET
    path: "/orders/{other_user_order_id}"
    params: { other_user_order_id: "fixture:other_order" }
    marker_header: X-SwarmShield-Probe # value is the scenario id, set by the engine
  expected_signal:                    # what a VULNERABLE (flag on) response looks like
    status: 200
    body_contains: ["order_id", "owner_user_id"]
    owner_is_other: true              # verifier assertion key (see §4)
  severity: high                      # low|medium|high|critical
```

**Models** (`catalog/models.py`, pydantic): `Scenario`, `Probe`, `ExpectedSignal`.
**Loader** (`catalog/loader.py`): `load_catalog(dir) -> dict[scenario_id, Scenario]`.

**Validation on load** (fail fast, also a pytest):
- IDs unique across all files; `SCN-...` format.
- Every `flag` exists in `contracts/flags.yaml` under the same `customer_id`, and the
  flag's `endpoints` cover the probe `path` template.
- Catalog is pinned by a `catalog_version` (a hash of the files) stamped onto every event
  for deterministic replay.

Target coverage: 8–12 scenarios spanning idor/bola, missing authz, missing rate limit,
weak reset flow, injection-shaped input, ssrf-shaped callback — mapped to Dev B's nine
flags. Keep them synthetic; coordinate the flag names with B.

---

## 2. Planner agent (`attack/agent/`)

Claude doing ordinary security *analysis*: given context, choose and order scenarios.
It never sees a tool that sends traffic — it only emits scenario IDs.

**Input** (`PlanRequest`): bounded objective; relevant `customer-X.md` sections (§2 assets/
invariants, §3 recent changes, §4 observed events, §9 next tests); a code diff summary;
applicable shared lessons (filtered by `applicability` against this customer); the list of
available scenario IDs with titles/classes; `budget` (max scenarios this run).

**Output** (`TestPlan`, structured, schema-constrained):
```python
class PlannedStep(BaseModel):
    scenario_id: str
    rationale: str
    priority: int            # 1 = highest
    expected_value: float    # 0..1, model's own estimate
class TestPlan(BaseModel):
    steps: list[PlannedStep]
    skipped: list[SkippedScenario]   # id + reason
```

**Prioritization signals** (stated in the prompt, ranked): impact/severity · exposure ·
change-recency (scenarios touching changed surfaces first) · novelty · known history from
`customer-X.md` §7 · expected value. Change-triggered, not full-history sweeps.

**Hard constraints enforced in code, not the prompt:**
- Output passes through a structured-output decoder; anything off-schema is rejected.
- Every returned `scenario_id` must be in the allowed set for this customer; unknown IDs
  are dropped and logged, never executed.
- The plan is truncated to `budget.max_scenarios`.
- Model output is **data**: it selects IDs; the harness, not the model, decides execution.

`agent/client.py` wraps the Anthropic SDK (model id `claude-opus-5-5` for planning; a
cheaper id is fine for interpretation). A `DummyPlanner` returning a deterministic plan
lets the rest of the pipeline run offline and in tests.

---

## 3. Probe engine (`attack/engine/`)

Deterministic, no model. Turns one `Scenario` into one `ProbeResult`.

```python
class ProbeResult(BaseModel):
    scenario_id: str
    request: dict        # method, url, headers, params (as sent)
    response: dict       # status, headers, body (as received)
    flags_snapshot: dict # site flags at probe time (from GET /__meta)
    code_revision: str
    error: str | None
```

`run_probe(scenario, site_client, run_id) -> ProbeResult`:
1. Resolve the probe template: fill path/params from the scenario's `fixture:` references
   (synthetic values only — never real user data).
2. Send via `site_client` with headers `X-SwarmShield-Probe: <scenario_id>` and
   `X-SwarmShield-Run: <run_id>`. Only `benign_request` kind is supported; the method is
   read-only-by-default and the engine refuses any scenario whose probe is not on the
   allowed-verb list.
3. Capture the full request/response and the `X-SwarmShield-Evidence` header.
4. Snapshot flags via `GET /__meta` so the verifier has ground truth.
5. Timeouts/connection errors → `error` set, response empty (verifier maps this to
   `inconclusive` or `blocked`).

No retries that change state; a single attempt per probe. The engine never interprets —
it only reports what happened.

---

## 4. Verifier (`attack/verify/`)

Turns a `ProbeResult` into a `Verdict` (`contracts.Verdict`) by checking the response
against the scenario's `expected_signal` **and** its `invariant`, cross-checked against the
flag ground truth. A claimed success is never a pass on its own.

```python
class VerifiedResult(BaseModel):
    scenario_id: str
    verdict: Verdict
    invariant: str
    signal_matched: bool
    flag_was_on: bool
    confidence: float
    evidence_ref: str
    notes: str
```

`judge(scenario, probe_result) -> VerifiedResult` decision table:

| Signal matched (vuln response) | Flag on | Verdict |
|---|---|---|
| yes | yes | `confirmed` |
| no (secure response) | no | `not_reproduced` |
| yes | no | `inconclusive` → flag as a verifier/catalog mismatch to investigate |
| no | yes | `inconclusive` → probe didn't trigger a known-present weakness |
| probe errored / ambiguous | any | `inconclusive` |
| precondition unmet / target out of scope | any | `blocked` |

- `signal_matched` evaluates the `expected_signal` assertions (status, `body_contains`,
  `owner_is_other`, etc.) — pure, deterministic functions over the response.
- The invariant string is recorded on the verdict so Dev C and humans see what was being
  protected. On the demo sites the flag is ground truth, so correctness is checkable
  (confirmed ⟺ flag on).
- **`verified` is not produced here.** Promoting a `confirmed` finding to the `verified`
  evidence label is a separate, human-gated step (§5), consistent with §5.3.

---

## 5. Harness (`attack/harness/`)

Orchestrates a run and is the *only* place that enforces limits. Limits live in code so a
prompt can't talk its way past them.

```python
class RunBudget(BaseModel):
    max_scenarios: int = 12
    max_tool_calls: int = 50
    max_runtime_s: int = 120
    max_retries: int = 0
    max_spend_usd: float = 1.0
    max_swarm_size: int = 1
class RunConfig(BaseModel):
    customer_id: str
    objective: str
    budget: RunBudget = RunBudget()
    allowed_tools: list[str]      # allowlist; anything else is refused
    target_allowlist: list[str]   # base URLs the engine may hit
    require_approval: bool = True # human gate before promoting to `verified`
```

`run(config) -> RunReport`:
1. Generate `run_id`; read site `/__meta` for `code_revision`; read current
   `knowledge_version` from `shared-intelligence.md`.
2. Emit `swarm.run_start`.
3. Build `PlanRequest` (pull C's page sections + applicable shared lessons + Keewano
   slices via `clients/`), call `agent.plan`; emit `swarm.plan`.
4. For each planned step, in priority order, until a budget trips:
   - Check target is on `target_allowlist` (else `blocked`).
   - `engine.run_probe`; emit `swarm.probe`.
   - `verify.judge`; emit `swarm.verdict` (carries `contracts.Verdict`).
5. Emit `swarm.run_end` with counts per verdict.
6. Return `RunReport` (plan, per-scenario verdicts, budget usage, stop reason).

**Budget enforcement:** a `BudgetTracker` wraps every tool call and ticks runtime/calls/
spend; the first breach halts the run with `stop_reason` and emits `swarm.run_end`. This is
the "provably halts a runaway run" criterion — covered by a test that sets tiny budgets and
asserts the run stops.

**Approval gate:** when `require_approval`, a `confirmed` verdict proposed for promotion to
`verified` pauses in a `PendingApproval` queue; for the MVP a CLI `approve <run_id> <scn>`
(or an auto-approve flag for the demo) releases it. Nothing reaches the `verified` label
without passing the gate.

**Determinism / replay:** `run_id`, `catalog_version`, `code_revision`, `knowledge_version`
are stamped on every event and the evidence record. `replay(evidence_ref)` re-runs the
stored request against a site pinned to the stored revision+flags and asserts the same
verdict — the "reproducible from stored evidence alone" criterion.

---

## 6. Event logging (`attack/harness/events.py`)

Every step emits a `contracts.Event` to Keewano via `clients/keewano.py`
(`POST /events`). Mapping:

| Step | `event_type` | key fields |
|---|---|---|
| run opens | `swarm.run_start` | objective, budget in `attrs` |
| plan ready | `swarm.plan` | plan (ids + rationale) in `attrs` |
| probe sent | `swarm.probe` | `scenario_id`, `target`, request summary, `policy_outcome` |
| verdict | `swarm.verdict` | `scenario_id`, `verdict`, `confidence`/`invariant` in `attrs` |
| run closes | `swarm.run_end` | verdict counts, `stop_reason` in `attrs` |

All carry `actor=swarm_agent`, `simulated=true`, the `run_id`, and an `evidence_ref`
(`make_evidence_ref`). Shaped so Dev C distills without extra parsing (events already carry
`scenario_id`, `verdict`, invariant).

---

## 7. Clients (`attack/clients/`)

- `site.py`: `SiteClient(base_url)` with `meta()`, `set_flags(...)` (test-only),
  `probe(method, path, headers, params)`. httpx, short timeouts.
- `keewano.py`: `post_events([Event])`, `get_slice(customer_id, since, event_type,...)`,
  `get_evidence(evidence_ref)`. Validates outgoing events through `contracts.Event` first.

Both have fixture-backed fakes so A develops before B is live: `FakeSite` honors a
flag dict and returns the scenario's vulnerable/secure signal; `FakeKeewano` stores events
in memory and serves slices.

---

## 8. Build order (fixtures first)

1. `catalog/` models + loader + 3–4 scenarios + `FakeSite` honoring their flags.
2. `engine/` against `FakeSite`; `ProbeResult` captured end to end.
3. `verify/` with the §4 table; unit tests for each cell.
4. `harness/` wiring + `DummyPlanner`; budgets + `swarm.*` events into `FakeKeewano`.
5. `agent/` real planner with structured output; keep `DummyPlanner` for tests.
6. Swap fakes for real `SiteClient`/`KeewanoClient` at integration.

## 9. Acceptance criteria (from `docs/dev-A-...md` §5)

- Plan favors recently-changed surfaces over untouched ones.
- Every catalog scenario runs against a demo site and logs `simulated:true` events.
- Verdicts correct against flag ground truth (confirmed ⟺ flag on).
- A confirmed finding replays from stored evidence alone.
- Budgets/stop-conditions provably halt a runaway run.
- Result events distill into `customer-X.md` with no extra parsing.

## 10. Tests

`tests/attack/`: catalog validation; verifier decision table (all six cells);
budget-halt; evidence replay determinism; planner output schema + unknown-ID rejection;
end-to-end on `FakeSite`+`FakeKeewano` producing schema-valid events.

---

## 11. Project context for implementers

Everything an implementer needs that isn't in this file lives in `docs/`. Read
`docs/swarmshield-mvp-overview.md` (§5 contracts, §5.6 safety model) and
`docs/dev-A-simulation-core-and-attack-engine.md` first. This section is the quick orientation.

### What SwarmShield is
A self-improving security-testing loop over 3 **simulated** demo customers (fake sites we
own). B produces events into a per-tenant store (Keewano); C distills events into per-customer
memory (`customer-X.md`) and a generalized `shared-intelligence.md`; A (this component) reads
that memory, runs simulated tests against the sites, and logs results back for C to re-distill.
The branch is `feat/ato-response`; it is also the repo's default branch.

### Repo layout (you own `attack/`)
```
contracts/   SHARED. Event schema + verdict/label enums. Import from here; do not fork it.
fixtures/    Sample events (events/<customer_id>.jsonl) for building without B live.
sites/       Dev B — 3 demo sites, customer_a/_b/_c (ports 3001/3002/3003), local only.
keewano/     Dev B — event store + read API (port 4000).
attack/      Dev A — THIS component (catalog/ agent/ engine/ verify/ harness/ clients/).
distill/     Dev C — customer analysis, shared updater, privacy.
memory/      Dev C — customers/customer-X.md and shared-intelligence.md.
docs/        All specs.
tests/       Pytest. Put A's tests under tests/attack/.
```

### Tooling
- Python **3.12+**, managed with **uv**. `uv sync` installs; `uv run pytest -q` tests;
  `uv run ruff check .` and `uv run ruff format .` lint/format. Add deps with `uv add <pkg>`.
- Installed already: `anthropic`, `fastapi`, `uvicorn`, `httpx`, `pydantic` (v2), `pyyaml`.
- Ruff config: line length 100, rules E/F/I/B/UP. Keep the tree green before committing.

### The `contracts` API (already built — use it, don't redefine events)
```python
from contracts import (
    Event,            # pydantic model for every Keewano event (§5.1 v1.1)
    Actor,            # USER | SYSTEM | SWARM_AGENT
    EventType,        # PROBE_RESULT, SWARM_RUN_START/PLAN/PROBE/VERDICT/RUN_END
    PolicyOutcome,    # ALLOW | DENY | FLAG
    Verdict,          # CONFIRMED | NOT_REPRODUCED | INCONCLUSIVE | BLOCKED
    EvidenceLabel,    # OBSERVED | HYPOTHESIZED | REPRODUCED | VERIFIED
    make_evidence_ref, parse_evidence_ref, new_event_id,
)
```
`Event` is frozen, forbids unknown fields, and enforces the cross-field rules this spec
relies on, so building an event wrong raises `ValidationError` immediately:
- `swarm.*` ⇒ `actor=swarm_agent`; `probe.result` ⇒ `actor=system`.
- `swarm.*` and `probe.result` ⇒ `simulated=True` + a `run_id` + an `evidence_ref`.
- `scenario_id` required on `probe.result`, `swarm.probe`, `swarm.verdict`.
- `verdict` required on `swarm.verdict`, forbidden elsewhere.
- `evidence_ref` must name the event's own `customer_id` and `run_id`.
- `ts` must be timezone-aware.
Evidence-ref format: `ev://<customer_id>/<run_id>/<event_id>`; organic (non-run) events use
the literal `organic` in place of `run_id`. A non-Python mirror is `contracts/event.schema.json`
(field types only); regenerate it with `uv run python -m contracts` after changing `events.py`.

Minimal example of a verdict event A emits:
```python
from datetime import datetime, UTC
from contracts import Event, make_evidence_ref, new_event_id
eid = new_event_id()
ev = Event(
    event_id=eid, customer_id="customer-a", ts=datetime.now(UTC), run_id="run-1",
    actor="swarm_agent", tool="attack-harness", event_type="swarm.verdict",
    target="/orders/{id}", action="probe", policy_outcome="flag",
    code_revision="abc123", knowledge_version="0.1.0", simulated=True,
    evidence_ref=make_evidence_ref("customer-a", "run-1", eid),
    scenario_id="SCN-IDOR-001", verdict="confirmed", attrs={"confidence": 0.9},
)
```

### Cross-team interface facts (from dev-B §4a — proposed by A, pending B sign-off)
- Site base URLs: customer-a `:3001`, customer-b `:3002`, customer-c `:3003`.
- Each site: `GET /__meta` → `{customer_id, code_revision, flags}`; `PUT /__flags` (test-only).
- Probe headers A sends: `X-SwarmShield-Probe: <scenario_id>`, `X-SwarmShield-Run: <run_id>`.
  Response echoes `X-SwarmShield-Evidence: <evidence_ref>`.
- Keewano API (`:4000`): `POST /events` (array), `GET /events?customer_id=&since=&until=&event_type=&run_id=&limit=`,
  `GET /events/since-revision?customer_id=&revision=`, `GET /evidence/{evidence_ref}`.
- Flag registry at `contracts/flags.yaml` (B owns; B ships at M1). Initial flag names:
  customer-a `idor_orders`, `login_rate_limit_off`, `weak_password_reset`;
  customer-b `broken_object_authz`, `role_escalation`, `ssrf_callback`;
  customer-c `unsafe_input_handling`, `missing_output_encoding`, `insecure_upload_path`.
- `customer_id` values keep hyphens (`customer-a`); only the site *directory* names use
  underscores (`customer_a`) so they import as Python packages.

### Build against fakes first
B and C may not be live when you build. Everything in §7 (`FakeSite`, `FakeKeewano`) and the
`DummyPlanner` (§2) exist so A's full pipeline runs offline and in CI. Swap in real clients at
integration. Build order is §8; don't wait on anyone to start on `catalog/ → engine/ → verify/`.

### Decisions already made (so a new session doesn't relitigate them)
- Event schema extended to **v1.1**: added `scenario_id`, `verdict`, `attrs`; all nullable.
- `scenario_id` is required only on scenario-scoped events, not every `swarm.*` (run_start/
  plan/run_end are not about one scenario).
- Organic events' `evidence_ref` uses `organic` in place of `run_id`.
These are reflected in `contracts/events.py`, overview §5.1, and dev-B §4a, and are marked
"pending B + C sign-off" — confirm at the schema-freeze (M1) before relying on them hard.

### Still open / needs the team
- B must sign off dev-B §4a and ship `contracts/flags.yaml` + fixtures.
- A fills the `scenario_ids` column of the flag registry as the catalog grows.
- Product framing: README says "self-healing security / ATO response"; specs say
  attack-simulation. Confirm which story the demo tells (affects which scenarios to prioritize
  — ATO response leans on customer-a's rate-limit + password-reset flags).
