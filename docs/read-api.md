# Event store: read/query API (Dev B, M3)

Base URL `http://localhost:4000`. Machine-readable spec: [`docs/openapi.json`](openapi.json)
(regenerate with `uv run python -m keewano.openapi`; a test fails if it's stale). Live docs at
`/docs` when the server runs. Writes are in `docs/ingestion-api.md`.

```sh
uv run uvicorn keewano.api:create_app --factory --port 4000
```

## Rules for every read
- **`customer_id` is required, exactly once**, on every read, evidence included. Missing or empty
  → `422`; given twice → `400`; not a configured tenant → `404`.
- A read only ever touches that tenant's tables. Nothing returns another tenant's rows, and there
  is no "all tenants" query.
- Responses are **slices**, oldest first by `(ts, ingest order)`: default page **500**, maximum
  **1000** (`limit` above that → `422`).
- Times are RFC 3339 with a timezone (`2026-10-11T12:00:00Z`, `...-07:00`). `since` is inclusive,
  `until` exclusive.

## `GET /events`: a time window

| Param | | |
|---|---|---|
| `customer_id` | required | Tenant |
| `since` | optional | "Events since timestamp X" (inclusive) |
| `until` | optional | Exclusive upper bound |
| `event_type` | optional | Exact match, e.g. `probe.result` |
| `run_id` | optional | Exact match |
| `limit` | optional | 1–1000, default 500 |
| `cursor` | optional | `X-Next-Cursor` from the previous page |

**Body:** a plain JSON array of events (`contracts.Event`, every field present, `null` where
unset). That's what Dev A's `KeewanoClient.get_slice` returns as-is.

**Headers:**
- `X-Has-More: true|false`: more events matched beyond this page.
- `X-Next-Cursor`: opaque, positioned after the last event returned. Pass it back with the
  **same other params** to get the next page. On an empty page the cursor you sent is echoed back,
  so a poller can keep tailing with it.

```sh
# Slice of customer-a's probe results for one run
curl -s "localhost:4000/events?customer_id=customer-a&event_type=probe.result&run_id=run-7"

# Everything since 12:00 UTC, 200 at a time, with headers
curl -si "localhost:4000/events?customer_id=customer-a&since=2026-10-11T12:00:00Z&limit=200"
# HTTP/1.1 200 OK
# x-has-more: true
# x-next-cursor: eyJjIjoiY3VzdG9tZXItYSIs...Lw
# [{"event_id": "...", "customer_id": "customer-a", "ts": "2026-10-11T12:00:03Z", ...}, ...]

# Next page: same params plus the cursor
curl -s "localhost:4000/events?customer_id=customer-a&since=2026-10-11T12:00:00Z&limit=200&cursor=eyJj...Lw"
```

```python
import httpx

def all_events(customer_id, **filters):
    params, cursor = {"customer_id": customer_id, **filters}, None
    while True:
        r = httpx.get("http://localhost:4000/events",
                      params=params | ({"cursor": cursor} if cursor else {}))
        r.raise_for_status()
        yield from r.json()
        if r.headers["X-Has-More"] == "false":
            return
        cursor = r.headers["X-Next-Cursor"]
```

### Cursors
- Signed (HMAC-SHA256) and bound to the `customer_id`, the endpoint and the filters it was issued
  for. A cursor used with another tenant, another endpoint or other filters, or edited in any way,
  is rejected with `400`.
- Keyset-based, so new events arriving between pages don't cause repeats or skips.
- Signed with `SWARMSHIELD_CURSOR_SECRET`. If that isn't set, a random secret is generated at
  startup and cursors stop working after a restart; start again without a cursor.

## `GET /events/since-revision`: change-triggered reads

"Events since code_revision X": every event of the tenant from the **first event seen at that
revision** onward, in time order (so it includes events from later revisions too).

| Param | | |
|---|---|---|
| `customer_id` | required | Tenant |
| `revision` | required | A `code_revision` value |
| `event_type` | optional | Exact match |
| `limit`, `cursor` | optional | As above |

`404` if the tenant has no event at that revision. Same body and headers as `GET /events`.

```sh
curl -s "localhost:4000/events/since-revision?customer_id=customer-a&revision=a1b2c3d"
curl -s "localhost:4000/events/since-revision?customer_id=customer-a&revision=a1b2c3d&event_type=probe.result"
```

## `GET /evidence/{evidence_ref}`: one raw artifact

The full request/response record stored with `POST /evidence` (dev-B §4a.5):

```json
{
  "request": {"method": "GET", "path": "/orders/1002", "headers": {"X-SwarmShield-Probe": "SCN-IDOR-001"}},
  "response": {"status": 200, "body": {"order_id": "1002", "owner_user_id": "u-2"}},
  "flags_snapshot": {"idor_orders": true},
  "code_revision": "a1b2c3d"
}
```

The ref goes in the path as-is or URL-encoded; both work. `customer_id` is **required** and must
match the tenant in the ref. A ref for another tenant gets exactly the same `404` as a missing
one, so the response doesn't reveal whether it exists. Malformed ref → `422`.

```sh
curl -s "localhost:4000/evidence/ev://customer-a/run-7/3f1c2b9e-5d4a-4c1e-9a7b-2e6f8d0c1a55?customer_id=customer-a"
curl -s "localhost:4000/evidence/ev%3A%2F%2Fcustomer-a%2Frun-7%2F3f1c...?customer_id=customer-a"
```

## Errors

| Status | When |
|---|---|
| `400` | Bad, tampered or foreign cursor; `customer_id` given more than once |
| `404` | Unknown `customer_id`; revision not seen; evidence not found for this tenant |
| `422` | Missing/empty/malformed `customer_id`, bad timestamp, `limit` out of range, malformed ref |

Bodies are FastAPI's `{"detail": ...}`.

## For Dev A and Dev C
- **Dev A** (`attack/clients/keewano.py` on `feat/ato-response`): `get_slice` works unchanged
  (plain array, `limit=500` is the default). `get_evidence` must add `customer_id`:
  `self._http.get(f"/evidence/{evidence_ref}", params={"customer_id": customer_id})`, using the
  customer being tested. The record has the four keys `attack/harness/replay.py` reads. To page
  past 500, follow `X-Next-Cursor`.
- **Dev C:** use `GET /events?customer_id=&since=` for new windows, and `/events/since-revision`
  when a site's `code_revision` changes. For incremental distilling, keep the last `X-Next-Cursor`
  and poll with it; it never repeats an event.
- **Dashboard** (`docs/dashboard-spec.md`): poll `/events` with the cursor rather than a moving
  `since`, which avoids re-reading the last event.

## Not access control
Isolation is enforced per request on the `customer_id` the caller declares. There is no
authentication in the MVP, so a caller can still ask for any tenant by name. What the API
guarantees is that a request scoped to one tenant can never receive another tenant's data.
