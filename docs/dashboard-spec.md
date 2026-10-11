# Dashboard spec (demo UI)

**Status:** Proposed · **Role:** the demo surface for the whole loop · **Cross-team:** reads
from B (Keewano, site flags) and C (Markdown memory) and triggers A (a run).
**Read first:** `swarmshield-mvp-overview.md` (§3 dependency flow, §6 definition of done).

The system is Markdown files and event rows, which don't demo well. This dashboard makes the
self-improving loop *visible*: toggle a weakness, trigger a run, watch Claude choose what to
test, watch verdicts land, watch the customer's memory update, and — the payoff — watch a
lesson generalize to another customer. It contains **no business logic**; it is a thin view
over data the three components already produce, plus one button that calls A's run API.

---

## 1. The demo narrative it must support

The dashboard exists to tell this story on stage, in order:

1. **Here is a customer.** Open the `customer-a` tab: its site revision, its current flags,
   its memory page (`customer-a.md`) with known findings and "next tests".
2. **Something changed / is vulnerable.** Toggle `idor_orders` **on** (a stand-in for a bad
   deploy introducing a weakness).
3. **Claude decides what to test.** Hit **Run**. The plan panel shows the scenarios Claude
   chose *and its rationale* — visibly prioritizing the changed/risky surface.
4. **The system tests itself safely.** Verdicts stream in: `SCN-IDOR-001 → confirmed`,
   others `not_reproduced`. Every row is a `simulated` probe, never a real attack.
5. **The memory improves.** `customer-a.md` updates with the new confirmed finding and a new
   regression test — the loop closed.
6. **The network learns (finale).** The lesson appears, generalized and tenant-sanitized, in
   `shared-intelligence.md`, and shows up as a *suggested test* on the `customer-b` tab.

Build the UI backwards from these six beats. Anything that doesn't serve one is out of scope
for the MVP.

---

## 2. Scope & ownership

- **One page, three customer tabs** — not three dashboards. Tabs switch `customer_id`; the
  layout is identical per customer.
- Lives at repo root in `dashboard/` (its own FastAPI app), because it crosses all three
  components. Suggested owner: **Dev A** (the run-trigger half is A's), with B and C each
  contributing their read endpoints. Agree ownership before building.
- **Read-only over existing data**, with exactly one write path: the "Run" button → A's run
  API. Flag toggles call B's existing `PUT /__flags` (test-only, localhost). The dashboard
  stores nothing of its own.

Out of scope: auth, multi-user, persistence, mobile, anything not in the six beats.

---

## 3. Architecture

```
browser (one HTML page, vanilla JS or htmx; poll every 1s)
   │  GET /api/...                      POST /api/run
   ▼                                        │
dashboard/  (FastAPI, port 8000) ───────────┤  thin aggregator; no logic
   ├─ GET  /api/customers                    │  list + status
   ├─ GET  /api/customer/{id}/meta  ──────────▶ B: site GET /__meta
   ├─ PUT  /api/customer/{id}/flags ──────────▶ B: site PUT /__flags
   ├─ GET  /api/customer/{id}/events ─────────▶ B: Keewano GET /events (slice)
   ├─ GET  /api/customer/{id}/memory ─────────▶ C: read memory/customers/{id}.md
   ├─ GET  /api/shared ───────────────────────▶ C: read memory/shared-intelligence.md
   └─ POST /api/run {customer_id} ────────────▶ A: harness.run(RunConfig) (background task)
```

- **FastAPI + uvicorn** (already deps). One `index.html` served statically; keep JS minimal
  — polling, not websockets. A 1s poll of `/api/customer/{id}/events?since=...` is enough to
  make verdicts "stream".
- `/api/run` kicks `attack.harness.run` as a background task and returns a `run_id`
  immediately; the UI then polls events filtered by that `run_id`.
- Markdown is rendered client-side (e.g. `marked`) or server-side; either is fine.

---

## 4. Panels (per customer tab)

| Panel | Source | Shows |
|---|---|---|
| **Header** | `/meta` | `customer_id`, app type, `code_revision`, site up/down |
| **Flags** | `/meta` + `PUT /flags` | each flag as a toggle; flipping calls B's `/__flags` |
| **Memory** | `/memory` | rendered `customer-X.md`; highlight §5 confirmed, §9 next tests |
| **Run control** | `POST /run` | objective (preset), budget, **Run** button, `--dummy-planner` toggle |
| **Plan** | events `swarm.plan` | Claude's chosen scenarios + rationale + priority |
| **Live verdicts** | events `swarm.probe`/`swarm.verdict` | table: scenario · verdict · flag state · confidence; color by verdict |
| **Shared intel** | `/shared` | `shared-intelligence.md` summary + `knowledge_version`; new/updated items flagged |

Verdict colors (align with `contracts.Verdict`): `confirmed` red/filled, `not_reproduced`
green, `inconclusive` amber, `blocked` grey. Every verdict row links to its `evidence_ref`
so you can show "reproducible from stored evidence" on demand.

---

## 5. Data contracts it depends on (all already defined)

- **B — site:** `GET /__meta`, `PUT /__flags` (dev-B §4a.1).
- **B — Keewano:** `GET /events?customer_id=&since=&event_type=&run_id=` (dev-B §4a.6). The
  dashboard only ever reads one `customer_id` at a time, matching tenant isolation.
- **C — memory:** files at `memory/customers/{customer_id}.md` and
  `memory/shared-intelligence.md` (overview §5.4/§5.5). Read-only.
- **A — run API:** a small wrapper over `attack.harness.run`. Define as:
  `POST /api/run {customer_id, objective?, budget?, dummy_planner?} -> {run_id}`. A owns
  this; it's the harness (SPEC §5) exposed over HTTP.
- **Events** follow `contracts.Event`; the UI relies on `event_type`, `scenario_id`,
  `verdict`, `attrs`, `evidence_ref`.

If a component isn't live, the dashboard points at the fakes (`FakeSite`, `FakeKeewano`) and
fixture Markdown, so it can be built and demoed standalone.

---

## 6. Build order

1. Static page + tabs + `/api/customers` + `/meta` against `FakeSite`. (shell works)
2. Flag toggles → `PUT /__flags`; header reflects the change.
3. Memory + shared panels rendering fixture Markdown.
4. **Run** button → `/api/run` (A's harness on fakes); verdicts panel polling events.
5. Wire to real B/C/A; run the full six-beat narrative end to end.
6. Polish: colors, the cross-customer finale, a "reset demo" button that restores seed flags.

## 7. Demo-day checklist

- One command brings up sites + Keewano + dashboard (`make demo` or `docker compose up`).
- Seed state: `customer-a` has one pre-existing finding so memory isn't empty at open.
- `.env` has `ANTHROPIC_KEY`; `--dummy-planner` toggle verified as a fallback.
- Rehearse the six beats; have the cross-customer finale working or cut it cleanly.
- Keep a recorded screen capture as a backup if live services fail.
