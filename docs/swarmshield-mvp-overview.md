# SwarmShield MVP — Team Split & Integration Contracts

**Status:** Proposed · **Owner:** SpeedHacks · **Date:** October 2026
**Companion to:** the SwarmShield vision/system-design spec.

This document exists so three developers can build SwarmShield in parallel. It defines (1) how the MVP is divided, (2) the interface contracts every workstream depends on, and (3) the timeline and integration plan. Read this first; then read your individual spec (`dev-A`, `dev-B`, `dev-C`).

---

## 1. Scope of the MVP

Build the full self-improving loop end-to-end for **3 simulated customers**, where:

- Each "customer" is a **fake website** we own that emits security-relevant events.
- Each customer has its own Keewano table and its own `customer-X.md` memory page.
- A **simulated** attack/test runner selects and "runs" tests, logs results, and feeds local memory.
- A shared updater generalizes eligible lessons into `shared-intelligence.md`.
- Shared lessons feed back into the next cycle.

Non-goals for the MVP: real customers, real exploitation, production targets, a UI beyond the Markdown files and basic run logs, and any dependency on external products for the product architecture (Claude may power agents internally; the data model, loop, and interfaces are ours).

---

## 2. The three workstreams

The system divides along two clean seams: **producing data** (sites → Keewano), **understanding data** (Keewano → customer md → shared md), and **testing** (the simulated offense that creates new data).

| Dev | Workstream | Boundary | Effort |
|-----|-----------|----------|--------|
| **A** | Attack Simulation & Orchestration (offense) | Agent harness, attack/test agent, the fake-hacking engine, and result verification. Writes results back to Keewano. | **40%** |
| **B** | Demo Sites & Keewano Event Store (produce + land data) | Everything **up to and including getting data into Keewano**: the 3 sites, event emission, vulnerability flags, and the Keewano store (schema, ingestion, isolation, read API). | **30%** |
| **C** | Distillation & Shared Intelligence (understand → big md) | Everything from **reading/distilling Keewano onward**: the customer-analysis agent, `customer-X.md`, generalization, privacy, and updating `shared-intelligence.md`. | **30%** |

**Why these sizes.** A owns the parts most likely to fail in novel ways — nondeterministic exploitation-planning, the simulation engine, and verifying a "successful" attack against an invariant — so it stays the 40%. B is high volume (three instrumented sites + a datastore) at lower unit difficulty. C is reasoning-heavy (two layers of understanding + privacy correctness) but a smaller code surface. *C's scope grew with this redistribution; see the final note if you'd rather rebalance to match.*

---

## 3. Dependency flow

```
  Dev B                         Dev C                      Dev A
  ─────                         ─────                      ─────
  demo sites ─▶ events ─────▶ Keewano store
                                 │  (read)
                                 ▼
                         customer-analysis agent ─▶ customer-X.md
                                 │                      │
                                 │                      ├─────────────▶ attack runner (simulated)
                                 │                      │                 reads: customer-X.md,
                                 │                      │                 Keewano slices, shared md
                                 │                      │                      │
                                 │                      │   results (simulated)▼
                                 │◀─────────────────────┼──────────────── Keewano store
                                 ▼                      │
                          shared updater ─▶ shared-intelligence.md ─▶ (consumed next cycle by A)
```

- **B is upstream of everyone.** Nothing can be distilled or tested until events land in Keewano.
- **C sits between B and A on both sides of the loop:** it distills B's events into the `customer-X.md` that A tests against, and it re-distills A's result events and generalizes them into the shared corpus.
- The B→C→A→(Keewano)→C cycle is inherent to the self-improving loop. To keep everyone unblocked, **all shared contracts in §5 are frozen at M1 (end of Week 1)** and each dev builds against fixtures, not against each other's live code.

---

## 4. Timeline (6-week MVP)

| Week | Dev A (40%) | Dev B (30%) | Dev C (30%) |
|------|-------------|-------------|-------------|
| 1 | Harness skeleton + attack-agent I/O; stub simulator | **Freeze event schema (§5.1)**; scaffold site #1 + Keewano ingestion/store/read API | **Freeze page schemas (§5.4/§5.5)**; customer-analysis agent skeleton on fixture events; `shared-intelligence.md` skeleton |
| 2 | Attack-agent prioritization on fixtures | Sites #2–#3; instrumentation + vulnerability flags | Customer-analysis agent → `customer-X.md` patches |
| 3 | Simulation engine + scenario catalog | Harden read/query (slices, since-revision); flag registry | Shared updater: generalize + dedup/merge |
| 4 | Verification + verdicts + budgets/approval gates | Seed realistic organic traffic | Privacy scanners (secrets/PII/re-id) + provenance/quarantine/versioning |
| 5 | **Integration:** full loop on 1 customer → then 3 | Support integration; fill event gaps | Live distill across 3 customers; promote first shared lessons |
| 6 | Hardening, stop-conditions, demo | Hardening, demo data | Privacy audit + rollback test, demo |

Milestones: **M1 (end W1)** contracts frozen · **M2 (end W2)** a site's events land in Keewano and C distills them into a page · **M3 (end W4)** simulated attacks run and log results on one customer · **M4 (end W5)** end-to-end loop across all 3 customers · **M5 (end W6)** shippable demo.

---

## 5. Shared contracts (frozen at M1)

The only hard interfaces between workstreams. Ownership of each canonical contract: **B owns the event schema, C owns the two Markdown page schemas, A owns the fake-hacking + verdict model.** Changes after M1 require all three to sign off.

### 5.1 Keewano event schema (v1.1, frozen by B at M1; Dev C sign-off pending) — owned by B

Every event — real or simulated — is one row. Unknown fields are rejected (extras go in `attrs`). Field-by-field reference with examples: `docs/event-schema.md`.

| Field | Type | Required? | Notes |
|-------|------|-----------|-------|
| `event_id` | string | no (defaults to a uuid4) | Primary key; non-empty, no `/` |
| `customer_id` | string | **yes** | Tenant scope; never crosses tenants. Lowercase letters, digits, hyphens (`customer-a`) |
| `ts` | RFC 3339 string | **yes** | Event time; timezone required |
| `run_id` | string, nullable | on `probe.result` and `swarm.*` | Groups events from one agent/test run; null for organic site events. No `/`; `organic` is reserved |
| `actor` | enum | **yes** | `user` \| `system` \| `swarm_agent` |
| `tool` | string, nullable | no | Tool/agent identity, if any |
| `event_type` | string | **yes** | e.g. `auth.login`, `order.access`, `probe.result` |
| `target` | string | **yes** | Endpoint/resource |
| `action` | string | **yes** | What was attempted |
| `policy_outcome` | enum | **yes** | `allow` \| `deny` \| `flag` (meaning on `probe.result`: see below) |
| `state_transition` | string, nullable | no | Before→after, if relevant |
| `code_revision` | string | **yes** | Version of the site under test |
| `knowledge_version` | string, nullable | no | Version of `shared-intelligence.md` in play |
| `simulated` | bool (strict) | **yes** | **`true` for anything the attack engine produces**; must be a JSON boolean |
| `evidence_ref` | string, nullable | on `probe.result` and `swarm.*` | Pointer to stored request/response/log artifact; format `ev://<customer_id>/<run_id>/<event_id>` (`organic` in place of `run_id` for organic events) |
| `scenario_id` | string, nullable | on `probe.result`, `swarm.probe`, `swarm.verdict` | *(v1.1)* Scenario catalog ID |
| `verdict` | enum, nullable | on `swarm.verdict` (forbidden elsewhere) | *(v1.1)* `confirmed` \| `not_reproduced` \| `inconclusive` \| `blocked` (§5.3) |
| `attrs` | JSON object, nullable | no | *(v1.1)* Free-form extras (confidence, severity, invariant); never required for parsing |

`policy_outcome` on `probe.result` records what the site did with the marked request: `allow` = flag on, the synthetic vulnerable response was returned; `deny` = flag off, the secure response was returned; `flag` = the site detected and flagged the probe.

`event_type` ownership (v1.1): sites emit organic types and `probe.result` (`actor: system`); Dev A's harness emits `swarm.run_start`, `swarm.plan`, `swarm.probe`, `swarm.verdict`, `swarm.run_end` (`actor: swarm_agent`). Full integration details: `dev-B` §4a. Code: `contracts/events.py` (pydantic) and `contracts/event.schema.json`.

### 5.2 Evidence labels (used in both memory files)
Every conclusion is one of: `observed` · `hypothesized` · `reproduced` · `verified`. Missing evidence is never a pass.

### 5.3 Test verdicts
`confirmed` · `not_reproduced` · `inconclusive` · `blocked`. A "successful attack" must be checked against resulting state and the stated security invariant before it can be `confirmed`.

### 5.4 Customer page schema (`customer-X.md`) — owned by C
Fixed section order (the customer-analysis agent writes targeted patches, never full rewrites):
1. Environment profile & tested revision
2. Assets, sensitive actions, trust boundaries, security invariants
3. Recent code/config changes
4. Observed events & notable sequences (→ Keewano `event_id`s)
5. Confirmed findings & evidence
6. Hypotheses & unverified leads
7. Prior swarm runs (blocked and successful)
8. Defenses & regression tests
9. Open risks & prioritized next tests
10. Candidate lessons for shared intelligence (each with sharing status)

### 5.5 Shared page schema (`shared-intelligence.md`) — owned by C
Sections: taxonomy & version · generalized attack patterns & preconditions · reusable synthetic scenarios · invariants & defensive patterns · verified mitigation/regression guidance · deprecated/superseded knowledge · change log · pending contributions.
Per-item metadata (required): `id` · `version` · `status` · `source_class` · `evidence_level` · `applicability` · `last_validation` · `expiry`. Provenance must not expose another tenant's identity.

### 5.6 Fake-hacking model (binding on everyone) — owned by A
- **No real exploitation, ever.** The attack engine never performs destructive or exfiltrating actions against real data.
- Demo sites expose **vulnerability flags**: toggleable conditions that make a known weakness present or absent.
- A **scenario catalog** describes techniques as *data* (preconditions, probe, expected signal).
- The harness fires **benign, clearly-marked probes**; the site returns a **simulated outcome** derived from its flags.
- **Claude plans, prioritizes, and interprets. Claude does not exploit.** This keeps the agent in an allowed analysis role and avoids refusals.
- Every resulting event carries `simulated: true` and runs only against demo sites in an isolated environment.

---

## 6. Definition of done (MVP)

- A new event reliably lands in the right customer table and updates the right page.
- A code change on a demo site triggers *relevant* tests, not full-history reanalysis.
- A prior simulated attack is reproducible from stored evidence.
- A new finding changes that customer's future regression coverage.
- A lesson generalized from one customer produces a useful test for another.
- Confirmed findings are distinguishable from hypotheses and false positives.
- Shared intelligence improves with no raw tenant data leaking (privacy audit passes).

---

> **Note on the B/C seam and effort split.** B owns the Keewano store *including its read/query API* (infrastructure stays with infrastructure); C consumes that API to distill. If you'd rather the query layer live in C, that's a one-line move. Also, this redistribution shifted the customer-analysis agent to C, so C's conceptual load rose — the 40/30/30 holds if C's scope stays tight, but 40/35/25 (A/C/B) would track the new scope more literally. Say the word and I'll rebalance.
