# Dev B — Demo Sites & Keewano Event Store

**Effort:** 30% of MVP · **Role:** foundation (critical path)
**Read first:** `swarmshield-mvp-overview.md` (you own the §5.1 event-schema contract)
**Downstream consumers:** Dev C (reads Keewano to distill), Dev A (event slices + vulnerability flags)

Your responsibility covers everything **up to and including getting data into Keewano**: three realistic demo websites that emit security events, the vulnerability flags the simulation keys off of, and the Keewano event store (schema, ingestion, isolation, read API). Lower unit difficulty than Dev A, but the most surface area — and you're on the critical path, so **freezing the §5.1 event schema in Week 1 is your first and most important deliverable.**

Your work ends once events are **reliably produced, stored per-tenant, and queryable**. Interpreting those events is Dev C's job.

---

## 1. What you own

1. **Three demo websites** — three distinct "customers," each a small but realistic app with a security-relevant surface.
2. **Event instrumentation** — each site emits structured events to its own Keewano table per the §5.1 schema (organic events and `probe.result` events).
3. **Vulnerability flags** — toggleable conditions that make known weaknesses present/absent, driving the simulation outcomes Dev A reads. Plus a **flag registry** mapping `flag → endpoints/scenarios`.
4. **Keewano store** — per-tenant tables, ingestion, isolation, and a **read/query API** for sliced event windows.

---

## 2. The three demo sites

Make them *different* so cross-customer learning has something to generalize. Suggested profiles (adjust to taste, keep them small):

| Customer | App type | Flavor of weaknesses to flag |
|----------|----------|------------------------------|
| **customer-A** | E-commerce (orders, cart, accounts) | IDOR/BOLA on orders, missing rate limit on login, weak password reset |
| **customer-B** | SaaS dashboard (multi-user workspace) | Broken object/function authz, role escalation, SSRF-shaped integration callback |
| **customer-C** | Content/CMS (posts, comments, uploads) | Injection-shaped input handling, missing output encoding, insecure upload path |

Each site must:
- Expose a **code/config revision identifier** so findings bind to the version tested.
- Emit events for security-relevant actions **and outcomes** (`policy_outcome`: allow/deny/flag).
- Honor **vulnerability flags** that the attack simulation keys off of — flag on = weakness present and probe returns the vulnerable signal; flag off = safe response.

Keep the sites deliberately boring in stack terms (whatever the team is fastest in). Realism lives in the *events and flags*, not in the UI.

---

## 3. Vulnerability flags (the hook for fake hacking)

Dev A's simulation engine fires benign, header-tagged probes (`X-SwarmShield-Probe: SCN-...`). Your sites recognize these markers and respond based on flags, returning a **simulated** outcome — never performing a real unsafe operation on real data.

Contract per probe:
- If the referenced weakness's flag is **on**, return the "vulnerable signal" described in the scenario (e.g. a synthetic other-user order object populated with fake data).
- If **off**, return the correct secure response (deny/flag).
- Always emit a Keewano `probe.result` event with `simulated: true` and an `evidence_ref`.

Maintain the **flag registry** (`flag_name → affected endpoints/scenarios`) and share it with Dev A so the catalog and the sites stay in sync.

---

## 4. Keewano store

- **Per-tenant isolation:** one table/namespace per customer; queries cannot cross `customer_id`.
- **Ingestion:** accept events conforming to §5.1 (from the sites *and* from Dev A's attack harness); reject/flag malformed ones.
- **Read/query API (for Dev C and Dev A):** fetch by `customer_id` + time window + optional `event_type`/`run_id`, returning **slices**, not full history (context-bloat control). Support "events since revision/timestamp X" for change-triggered analysis.
- **Retention of detail:** Keewano is the source of truth for raw events; the Markdown layers only link back by `event_id`. Keep full request/response artifacts addressable by `evidence_ref`.

---

## 4a. Integration contract with Dev A (proposed by A — working contract, needs Dev B sign-off; §4a.4 frozen by B at M1, Dev C sign-off pending)

Dev A builds against exactly these assumptions using fixtures until your live versions exist. If you change any of them, tell A; everything here should be a one-file change on A's side.

### 4a.1 Site addressing & metadata
| Customer | Base URL (local only, never publicly deployed) |
|----------|------|
| `customer-a` | `http://localhost:3001` |
| `customer-b` | `http://localhost:3002` |
| `customer-c` | `http://localhost:3003` |

Every site exposes:
- `GET /__meta` → `{"customer_id": "customer-a", "code_revision": "<git sha or semver>", "flags": {"<flag_name>": true|false, ...}}`
- `PUT /__flags` with body `{"<flag_name>": true|false}` → sets flags, returns the new `/__meta` body. Bound to localhost only. A uses this to set ground truth before a test run and to check verdicts against it.

### 4a.2 Probe markers
- Request headers A sends on every probe: `X-SwarmShield-Probe: <scenario_id>` and `X-SwarmShield-Run: <run_id>`.
- Only requests carrying `X-SwarmShield-Probe` get the flag-driven simulated outcome; unmarked requests behave normally.
- Every probe response includes the header `X-SwarmShield-Evidence: <evidence_ref>`, so A can link its verdict to your stored artifact without a lookup.

### 4a.3 Flag registry (`contracts/flags.yaml`, B owns, A reads)
```yaml
- flag: idor_orders            # snake_case, unique per customer
  customer_id: customer-a
  default: false
  endpoints: ["/orders/{id}"]
  scenario_ids: ["SCN-IDOR-001"]   # A fills these in; B keeps endpoints accurate
```
Initial flag names (from the §2 table): `customer-a`: `idor_orders`, `login_rate_limit_off`, `weak_password_reset` · `customer-b`: `broken_object_authz`, `role_escalation`, `ssrf_callback` · `customer-c`: `unsafe_input_handling`, `missing_output_encoding`, `insecure_upload_path`.

### 4a.4 Event schema additions (§5.1 v1.1; nullable, required by `event_type` as listed)
| Field | Type | Notes |
|-------|------|-------|
| `scenario_id` | string | Required on `probe.result`, `swarm.probe`, `swarm.verdict` |
| `verdict` | enum | `confirmed` \| `not_reproduced` \| `inconclusive` \| `blocked` (§5.3); required on `swarm.verdict`, forbidden elsewhere |
| `attrs` | JSON object | Free-form extras (confidence, severity, invariant); never required for parsing |

`event_type` vocabulary, split so there are no duplicate events:
- **Site emits** (`actor: system`): organic types (`auth.login`, `order.access`, ...) and `probe.result`, which records what the site actually did with a marked request.
- **A's harness emits** (`actor: swarm_agent`): `swarm.run_start`, `swarm.plan`, `swarm.probe`, `swarm.verdict`, `swarm.run_end`.
- All probe and swarm events have `simulated: true` and share the run's `run_id`.
- `probe.result` `policy_outcome`: `allow` = flag on, synthetic vulnerable response returned; `deny` = flag off, secure response returned; `flag` = the site detected and flagged the probe.
- Full field reference, required fields and examples: `docs/event-schema.md`. Validate with `contracts.validate_event` / `validate_batch`.

### 4a.5 Evidence
- `evidence_ref` format: `ev://<customer_id>/<run_id>/<event_id>`; organic events use `organic` in place of `run_id`.
- `GET /evidence/{evidence_ref}` (on the Keewano API) returns `{"request": {...}, "response": {...}, "flags_snapshot": {...}, "code_revision": "..."}`. This is what makes a finding replayable from stored evidence alone.

### 4a.6 Keewano API surface (base `http://localhost:4000`)
- `POST /events` with a JSON array of events → `{"accepted": [event_id...], "rejected": [{"event_id", "reason"}]}`. Rejects events missing required §5.1 fields or with a `customer_id` mismatch.
- `GET /events?customer_id=&since=&until=&event_type=&run_id=&limit=` → a time-ordered slice. `customer_id` is required, and the default limit is 500.
- `GET /events/since-revision?customer_id=&revision=` → events emitted after that revision was first seen.
- No endpoint returns rows from more than one `customer_id`.

### 4a.7 Fixtures (deliver with the M1 schema freeze)
- `fixtures/events/<customer_id>.jsonl`: about 50 organic events and a few `probe.result` events per customer, valid against §5.1 v1.1.
- `contracts/flags.yaml`: populated for all three customers.

---

## 5. Acceptance criteria

- §5.1 event schema frozen and documented by **end of Week 1 (M1)**.
- All three sites run, expose a revision ID, and emit well-formed §5.1 events for normal usage.
- Flipping a vulnerability flag changes the probe response and the emitted event, with no change to real data handling.
- Keewano stores events per tenant with zero cross-tenant leakage; the query API returns correct sliced windows and "since-revision" results.
- Dev A's result events ingest cleanly alongside organic events.
- Seeded "organic" traffic produces a realistic baseline of events for the demo.
- Every item in §4a (ports, `/__meta`, `/__flags`, probe headers, flag registry, v1.1 fields, evidence format, API surface, fixtures) is implemented as written or renegotiated with Dev A.

---

## 6. Out of scope for you
- The customer-analysis agent or `customer-X.md` — Dev C reads your store and does the distilling.
- The agents, attack simulation, or verdict logic (Dev A).

---

## 7. Suggested sequencing
W1 **freeze §5.1 schema (v1.1 per §4a.4)**, sign off §4a with Dev A, ship §4a.7 fixtures, scaffold site A + Keewano ingestion/store/read API · W2 sites B & C + instrumentation + flags · W3 harden read/query (slices, since-revision) + flag registry + full flag coverage for the catalog · W4 seed realistic organic traffic · W5 support integration, fill event gaps · W6 demo data, harden.
