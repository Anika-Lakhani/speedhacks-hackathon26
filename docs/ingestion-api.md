# Event store: ingestion API, storage and artifacts (Dev B, M2)

**Status:** M2 (ingestion and artifact upload). Reads (`GET /events`, `GET /evidence/{ref}`,
since-revision) arrive in M3. **Code:** `keewano/`. **Contract:** `docs/event-schema.md`.

```sh
uv run python -m keewano.setup                                   # create per-tenant tables (idempotent)
uv run uvicorn keewano.api:create_app --factory --port 4000      # serve (also runs setup)
uv run python -m keewano.rejects                                 # inspect the rejects log
uv run python -m keewano.fixtures                                # regenerate fixtures/events/*.jsonl
```

## Configuration (environment only)

| Variable | Default | Meaning |
|---|---|---|
| `SWARMSHIELD_STORE` | `sqlite` | `sqlite` (dev/tests) or `keewano` (stub; fails at startup until M3b) |
| `SWARMSHIELD_SQLITE_PATH` | `.data/keewano.sqlite3` | SQLite file |
| `SWARMSHIELD_REJECTS_PATH` | `.data/rejects.jsonl` | Rejects log |
| `SWARMSHIELD_TENANTS` | `customer-a,customer-b,customer-c` | Known tenants; any other `customer_id` is rejected |
| `KEEWANO_PROJECT_IDS` | empty | `customer-a=<id>,...` (one Keewano project per tenant; read by the stub, unused until M3b) |

Copy `.env.example` to `.env` and run with `uv run --env-file .env ...` to use a file.
Switching implementations is only a change to `SWARMSHIELD_STORE`.

## `POST /events`

Body: one event object, or an array of events. Every event is validated with
`contracts.validate_event` (the M1 validator) and accepted or rejected **on its own**; one bad
event never rejects the rest. Accepted events are routed to their tenant's table by
`customer_id`. Sites send organic events and `probe.result`; Dev A sends `swarm.*`. All go
through the same endpoint.

Response `200`, shape from dev-B §4a.6:

```json
{
  "accepted": ["8b0e6c2a-1f3d-4e5b-9c7a-6d2f1e0b3c44"],
  "rejected": [{"event_id": "e-bad", "reason": "simulated: Input should be a valid boolean"}]
}
```

`accepted` keeps input order. `event_id` in a rejection is `null` when the event didn't carry a
usable one.

An event is rejected when:

| Reason (prefix) | Cause |
|---|---|
| `<field>: ...` | Fails the v1.1 contract (missing field, wrong type, bad enum, cross-field rule) |
| `event must be a JSON object` | An array element isn't an object |
| `unknown customer_id '<id>'` | Valid event for a tenant not in `SWARMSHIELD_TENANTS` |
| `duplicate event_id '<id>'` | That tenant already has this `event_id`; the original is kept |

Response `400`, same shape, with nothing stored: the body isn't valid JSON, or it's neither an
object nor an array.

## `POST /evidence`

Stores the full request/response artifact behind an `evidence_ref` (dev-B §4a.5). Sites call
it when they answer a probe; anyone holding evidence for an event may call it.

```json
{
  "evidence_ref": "ev://customer-a/run-7/3f1c2b9e-5d4a-4c1e-9a7b-2e6f8d0c1a55",
  "request": {"method": "GET", "path": "/orders/1002", "headers": {"X-SwarmShield-Probe": "SCN-IDOR-001"}},
  "response": {"status": 200, "body": {"order_id": "1002", "owner_user_id": "u-2"}},
  "flags_snapshot": {"idor_orders": true},
  "code_revision": "a1b2c3d"
}
```

| Status | Meaning |
|---|---|
| `201 {"evidence_ref": ...}` | Stored |
| `409 {"error": ...}` | An artifact already exists for that ref. Evidence is immutable, so replays stay reproducible |
| `422 {"error": ...}` | Malformed ref, unknown tenant, missing `request`/`response`/`code_revision`, or unknown keys |
| `400 {"error": ...}` | Body isn't JSON |

`request`, `response` and `code_revision` are required; `flags_snapshot` defaults to `{}`.

## Artifact store: how it works

- **Keyed by `evidence_ref`**, which encodes its tenant: `ev://<customer_id>/<run_id|organic>/<event_id>`.
  The tenant is taken from the ref, so an artifact can only be stored under the tenant it names.
- **One artifacts table per tenant** (`artifacts_customer_a`, ...), next to that tenant's events table.
- **Tenant-scoped reads:** `get_artifact(customer_id, evidence_ref)` returns nothing if the ref
  names another tenant, so a caller scoped to customer-b can't read customer-a's evidence even
  with the exact ref. (HTTP `GET /evidence/{ref}` lands in M3 on top of this.)
- **Write-once:** a second write for the same ref is refused (`409`).
- **Not linked by foreign key to events:** an artifact may arrive before or after its event.
- Contents are synthetic by the safety rule (demo sites only ever return fake data).

## Storage adapter

`keewano/storage.py` defines `EventStore` with `setup`, `tenants`, `write_event`,
`query_events`, `put_artifact`, `get_artifact`. Every method is scoped to one `customer_id`.

| Implementation | Use |
|---|---|
| `SQLiteStore` (`keewano/sqlite_store.py`) | Dev and tests. Per tenant: `events_<tenant>` (ingest sequence, `event_id` unique, indexed `ts`/`event_type`/`run_id`/`code_revision`, full event JSON) and `artifacts_<tenant>`. `ts` is stored as fixed-width UTC so ordering is correct across timezones. |
| `KeewanoStore` (`keewano/keewano_store.py`) | Stub. Every method raises `StoreNotConfigured` until the ingestion method and credentials are decided (M3b). Never writes through the Keewano MCP, which is read-only. |

`query_events` ordering is `(ts, ingest order)`; `since` is inclusive and `until` exclusive.

## Rejects log

Every rejected event, artifact and unparseable request is appended to `SWARMSHIELD_REJECTS_PATH`
as one JSON line:

```json
{"logged_at": "...", "kind": "event", "reason": "...", "event_id": "e-bad",
 "customer_id": "customer-a", "index": 1, "raw": {"...": "the payload as received"}}
```

`kind` is `event`, `artifact` or `request`; `index` is the position in the batch. `raw` is
truncated past 8 KB. The log is a local operator file, deliberately not exposed over HTTP: it
can hold payloads for unknown or missing tenants, so an endpoint for it would cross `customer_id`.
