# Dev B plan

Spec: `docs/dev-B-demo-sites-and-event-pipeline.md` (with the §4a contract proposed by Dev A).
Rules and commands: `CLAUDE.md` (Dev B section). Work on `dev-b/foundation`.

Order follows the critical path: nothing downstream (Dev A, Dev C) works until events are
valid, stored per tenant, and queryable.

**Already in the repo** (from the shared skeleton): `contracts/events.py` + `event.schema.json`
+ `tests/test_events.py` (partly covers M1); empty packages `keewano/`, `sites/customer_a|b|c/`
and `fixtures/events/` (nothing yet for M2–M8).

---

- [x] **M1: Review and freeze the event contract (v1.1)** *(done 2026-10-11; Dev C sign-off pending)*
  - **Build:** resolve §4a vs §5.1 differences (D1–D14); strict `simulated`, `event_id`/`run_id`
    rules; `contracts/validate.py` (`validate_event`, `validate_batch`); JSON Schema with the
    cross-field rules; `docs/event-schema.md`; `docs/CONTRACT-CHANGES-v1.1.md`.
  - **Verify:** valid/invalid event tests; JSON Schema and pydantic agree on the same cases;
    schema staleness test; all existing tests still pass.
  - **Depends on:** nothing. Dev C sign-off still pending (see Open decisions).

- [x] **M2: Store and ingestion** *(done 2026-10-11; API doc: `docs/ingestion-api.md`)*
  - **Build:** a storage adapter interface in `keewano/` with (1) a local SQLite implementation,
    one table per `customer_id`, used for dev and tests, and (2) a Keewano implementation stubbed
    behind the same interface. The implementation is chosen by config (env var), not code
    changes. `POST /events` on port 4000 returning `{accepted, rejected}` per §4a.6, validating
    through `contracts.validate_batch`. Store evidence artifacts keyed by `evidence_ref`.
    Ship M1 fixtures: `fixtures/events/<customer_id>.jsonl` (~50 organic + a few `probe.result`
    per customer, §4a.7).
  - **Verify:** adapter contract tests run against both implementations (the stub raises a clear
    "not configured" error); malformed and wrong-tenant events rejected with reasons; config switch
    test; fixtures validate.
  - **Depends on:** M1. `keewano/` was an empty package; built inside it.
  - **Added beyond §4a:** `POST /evidence` (artifact upload, write-once) and an operator-only
    rejects log (`.data/rejects.jsonl`, not exposed over HTTP). Needs Dev A's acknowledgement.

- [ ] **M3: Read API**
  - **Build:** `GET /events` (required `customer_id`; `since`/`until`/`event_type`/`run_id`;
    default limit 500) with cursor pagination; `GET /events/since-revision`; since-timestamp;
    `GET /evidence/{evidence_ref}` returning `{request, response, flags_snapshot, code_revision}`.
  - **Verify:** slice correctness, time ordering, pagination stability; adversarial
    tenant-isolation tests (missing `customer_id`, another tenant's `evidence_ref`, injection-shaped
    params, cursor reuse across tenants) all return nothing from other tenants.
  - **Depends on:** M2.

- [ ] **M3b: Keewano real sink** *(blocked)*
  - **Build:** replace the Keewano stub with the real ingestion path.
  - **Verify:** events written through the sink are visible via the Keewano MCP (read-only);
    same adapter contract tests pass.
  - **Depends on:** M2; Keewano ingestion method (SDK or REST) and credentials; project-per-tenant
    decision.

- [ ] **M4: Site A (customer-a, e-commerce, port 3001)**
  - **Build:** minimal FastAPI app: login, orders, password reset; `GET /__meta`; emits organic
    events through `contracts.validate_event` to the store; exposes `code_revision`.
  - **Verify:** normal usage produces valid events in the store; `/__meta` shape matches §4a.1.
  - **Depends on:** M2 (M3 for end-to-end checks).

- [ ] **M5: Flags, registry and probe handling**
  - **Build:** `contracts/flags.yaml` for all three customers (nine flags, §4a.3); `PUT /__flags`
    (localhost only); probe handling on `X-SwarmShield-Probe` / `X-SwarmShield-Run`, returning
    `X-SwarmShield-Evidence`; flag on = synthetic vulnerable signal from fake data, flag off = secure
    response; `probe.result` events with `policy_outcome` per D10 and evidence artifacts.
  - **Verify:** flipping each flag changes the probe response and the emitted event; unmarked
    requests unaffected; no real data touched; response bodies carry the fields Dev A's
    `expected_signal` checks (e.g. `order_id`, `owner_user_id`).
  - **Depends on:** M4; Dev A's scenario IDs for the registry's `scenario_ids` column.

- [ ] **M6a: Site B (customer-b, SaaS dashboard, port 3002)**
  - **Build:** workspace/roles app with its three flags (object authz, role escalation, SSRF-shaped
    callback, simulated only).
  - **Verify:** same as M4 + M5 for customer-b.
  - **Depends on:** M5 patterns.

- [ ] **M6b: Site C (customer-c, CMS, port 3003)**
  - **Build:** posts/comments/uploads app with its three flags.
  - **Verify:** same as M4 + M5 for customer-c.
  - **Depends on:** M5 patterns.

- [ ] **M7: Seeded organic traffic**
  - **Build:** a seeding script producing a realistic baseline of organic events per customer.
  - **Verify:** volumes and type mix per customer; all events valid; deterministic with a seed.
  - **Depends on:** M4, M6a, M6b.

- [ ] **M8: Hardening and integration**
  - **Build:** fill event gaps found by Dev A and Dev C; run the full loop with A's harness and C's
    distiller; demo data.
  - **Verify:** Dev A's result events ingest alongside organic events; every §4a item implemented or
    renegotiated; dev-B §5 acceptance criteria.
  - **Depends on:** everything above; Dev A and Dev C integration.

---

## Open decisions
- **Dev C sign-off on contract v1.1.** Dev B froze it at M1; see `docs/CONTRACT-CHANGES-v1.1.md`.
- **Keewano ingestion method:** SDK or REST ingest API. The Keewano MCP is read-only and can't write.
- **One Keewano project per tenant** (customer-a/b/c), versus one project with per-tenant tables.
  Currently only one Keewano project exists ("Aaoli").
- **Which branch PRs target:** `main` or `feat/ato-response` (the remote's default branch, where the
  shared skeleton lives).
