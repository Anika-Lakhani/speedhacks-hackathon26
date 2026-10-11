# Event schema v1.1

**Status:** frozen by Dev B at M1 (2026-10-11). Dev C sign-off pending. Owner: Dev B.
**Code (source of truth):** `contracts/events.py` (pydantic `Event`), validated through
`contracts/validate.py`. **Machine-readable:** `contracts/event.schema.json` (JSON Schema
2020-12, generated from the code with `uv run python -m contracts`).
**Spec context:** overview §5.1, dev-B §4a.4. **Changes from the draft:** `docs/CONTRACT-CHANGES-v1.1.md`.

Every event, organic or simulated, is one JSON object. Fields not listed here are rejected;
put extras in `attrs`.

```python
from contracts import validate_event, validate_batch

event = validate_event(raw)          # dict, JSON text or Event; raises EventValidationError
result = validate_batch(raws, customer_id="customer-a")   # per-event accept/reject
result.response()                    # {"accepted": [event_id...], "rejected": [{event_id, reason}]}
```

## Fields

| Field | Type | Required? | Rules and meaning |
|---|---|---|---|
| `event_id` | string | no; defaults to a uuid4 | Primary key. Non-empty, must not contain `/` (it's a segment of `evidence_ref`). uuid format is not enforced. |
| `customer_id` | string | **yes** | Tenant scope. Pattern `^[a-z0-9][a-z0-9-]*$`, e.g. `customer-a`. Never crosses tenants. |
| `ts` | string | **yes** | Event time, RFC 3339 with a timezone: `2026-10-11T12:00:00Z` or `...+00:00`, optional fractional seconds. Epoch numbers and timestamps without a timezone are rejected. |
| `run_id` | string or null | on `probe.result` and `swarm.*` | Groups events from one test run; null for organic events. Non-empty, no `/`, and `organic` is reserved. |
| `actor` | enum | **yes** | `user` \| `system` \| `swarm_agent`. `probe.result` must be `system`; `swarm.*` must be `swarm_agent`. |
| `tool` | string or null | no | Tool or agent identity, e.g. `customer-a-site`, `attack-harness`. |
| `event_type` | string | **yes** | Non-empty. Organic types are free-form (`auth.login`, `order.access`, ...). Reserved: `probe.result` (sites) and `swarm.run_start`, `swarm.plan`, `swarm.probe`, `swarm.verdict`, `swarm.run_end` (Dev A). Any other `swarm.*` is rejected. |
| `target` | string | **yes** | Endpoint or resource, e.g. `/orders/{id}`. |
| `action` | string | **yes** | What was attempted, e.g. `login`, `GET /orders/1002`. |
| `policy_outcome` | enum | **yes** | `allow` \| `deny` \| `flag` (lowercase). On `probe.result`, see below. |
| `state_transition` | string or null | no | Before→after, e.g. `anonymous->authenticated`. |
| `code_revision` | string | **yes** | Non-empty. Version of the site that produced or was tested by the event (git sha or semver; the site's `/__meta` value). |
| `knowledge_version` | string or null | no | Version of `shared-intelligence.md` in play. Usually null for site events. |
| `simulated` | boolean | **yes** | Strict JSON boolean: `"true"`, `1`, `"yes"` are rejected. `true` for anything the attack engine produces; `probe.result` and `swarm.*` must be `true`. |
| `evidence_ref` | string or null | on `probe.result` and `swarm.*` | `ev://<customer_id>/<run_id>/<event_id>`; organic events use `organic` for the run segment and may leave it null. Must name the event's own `customer_id` and `run_id`. |
| `scenario_id` | string or null | on `probe.result`, `swarm.probe`, `swarm.verdict` | Scenario catalog ID (Dev A), e.g. `SCN-IDOR-001`. Non-empty when required. |
| `verdict` | enum or null | on `swarm.verdict`; forbidden elsewhere | `confirmed` \| `not_reproduced` \| `inconclusive` \| `blocked` (overview §5.3). |
| `attrs` | object or null | no | Free-form extras. Never required for parsing. |

### `policy_outcome` on `probe.result`
Records what the site actually did with the marked request:

| Value | Meaning |
|---|---|
| `allow` | Flag on: the site returned the synthetic vulnerable response (fake data only). |
| `deny` | Flag off: the site returned the correct secure response. |
| `flag` | The site detected and flagged the probe. |

### `attrs` convention on `probe.result`
Recommended, not required: `{"flag": "<flag_name>", "flag_on": true|false}`, naming the
vulnerability flag from `contracts/flags.yaml` that decided the outcome. Consumers must not
depend on it for parsing; Dev A's ground truth stays `GET /__meta`.

### Rules only the Python validator enforces
`contracts/event.schema.json` carries every rule above except one, which JSON Schema can't
express: `evidence_ref` must name the event's own `customer_id` and `run_id`. Use
`contracts.validate_event` wherever possible; non-Python consumers get everything else.

## Examples

Valid organic event (a user logging in to customer-a):

```json
{
  "event_id": "8b0e6c2a-1f3d-4e5b-9c7a-6d2f1e0b3c44",
  "customer_id": "customer-a",
  "ts": "2026-10-11T12:00:00Z",
  "run_id": null,
  "actor": "user",
  "tool": null,
  "event_type": "auth.login",
  "target": "/login",
  "action": "login",
  "policy_outcome": "allow",
  "state_transition": "anonymous->authenticated",
  "code_revision": "a1b2c3d",
  "knowledge_version": null,
  "simulated": false,
  "evidence_ref": null
}
```

Valid `probe.result` (customer-a answered Dev A's IDOR probe with the flag on):

```json
{
  "event_id": "3f1c2b9e-5d4a-4c1e-9a7b-2e6f8d0c1a55",
  "customer_id": "customer-a",
  "ts": "2026-10-11T12:05:00.123+00:00",
  "run_id": "run-7",
  "actor": "system",
  "tool": "customer-a-site",
  "event_type": "probe.result",
  "target": "/orders/{id}",
  "action": "GET /orders/1002",
  "policy_outcome": "allow",
  "code_revision": "a1b2c3d",
  "knowledge_version": null,
  "simulated": true,
  "evidence_ref": "ev://customer-a/run-7/3f1c2b9e-5d4a-4c1e-9a7b-2e6f8d0c1a55",
  "scenario_id": "SCN-IDOR-001",
  "attrs": {"flag": "idor_orders", "flag_on": true}
}
```

Both examples are checked by `tests/test_validate.py`, so they can't drift from the code.
