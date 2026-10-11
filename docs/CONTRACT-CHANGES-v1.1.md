# Event contract v1.1: changes at the M1 freeze

**Date:** 2026-10-11 · **Author:** Dev B (contract owner) · **Branch:** `dev-b/foundation`
**Baseline:** `contracts/events.py` as of `1f194d3` ("Define event schema v1.1 in contracts"),
overview §5.1 and dev-B §4a.4 on `feat/ato-response`.
**Reference:** `docs/event-schema.md`.

**Dev B sign-off:** done (frozen at M1).
**Dev A sign-off:** pending (§4a was proposed by A; review the "What this means for Dev A" section).
**Dev C sign-off: pending**

Schema version stays `1.1`: nothing was frozen before this, so these changes finalize v1.1
rather than starting v1.2. All existing tests pass unchanged.

## Changes

| # | Change | Kind |
|---|---|---|
| D1 | §4a.4 heading said "all optional / nullable"; now says "nullable, required by `event_type` as listed". The code's rules are kept: `scenario_id` required on `probe.result`, `swarm.probe`, `swarm.verdict`; `verdict` required on `swarm.verdict` and forbidden elsewhere. | docs only |
| D2 | `run_id`, `tool`, `state_transition`, `knowledge_version`, `evidence_ref` documented as nullable (the code already allowed null). | docs only |
| D3 | Required fields documented with a "Required?" column in §5.1: `customer_id`, `ts`, `actor`, `event_type`, `target`, `action`, `policy_outcome`, `code_revision`, `simulated`. | docs only |
| D4 | Field stays named `ts`. Must be RFC 3339 with a timezone. Now also rejects epoch numbers and loose formats (e.g. a space instead of `T`), so pydantic and the JSON Schema agree. | **stricter** |
| D5 | Unknown fields are rejected (already true in code); documented, with "extras go in `attrs`". | docs only |
| D6 | `customer_id` pattern `^[a-z0-9][a-z0-9-]*$` (already in code); documented. | docs only |
| D7 | `event_id` must be non-empty and contain no `/`. uuid format not enforced; the default is still uuid4. | **stricter** |
| D8 | `run_id` must be non-empty, contain no `/`, and can't be `organic` (reserved for organic evidence refs). | **stricter** |
| D9 | `simulated` is a strict boolean: `"true"`, `1`, `"yes"` were silently coerced to `true` before; now rejected. | **stricter** |
| D10 | `policy_outcome` on `probe.result` defined: `allow` = flag on, synthetic vulnerable response returned; `deny` = flag off, secure response; `flag` = the site detected and flagged the probe. | docs only (meaning) |
| D11 | `contracts/event.schema.json` now carries the cross-field rules as `if`/`then`. The one rule JSON Schema can't express (`evidence_ref` names the event's own tenant and run) stays Python-only. Also added: `evidence_ref` pattern, `ts` pattern. | schema file |
| D12 | Status: "v1.1, frozen by B at M1; Dev C sign-off pending" in §5.1 and §4a. | docs only |
| D13 | `attrs` convention on `probe.result`: `{"flag": "<flag_name>", "flag_on": bool}`. Recommended, never required. | docs only |
| D14 | `SCHEMA_VERSION` stays `"1.1"`. | none |

**New code:** `contracts/validate.py` with `validate_event` and `validate_batch` (plus
`EventValidationError`, `BatchResult`, `Rejection`), exported from `contracts`. `validate_batch`
accepts or rejects each event independently and can enforce one `customer_id` per batch;
`BatchResult.response()` is the §4a.6 `POST /events` body. **New dev dependency:** `jsonschema`
(tests only).

## What this means for Dev A
- **Nothing to rename.** `Event`, `EventType`, `PolicyOutcome`, `Verdict`, `EvidenceLabel`,
  `make_evidence_ref`, `parse_evidence_ref`, `new_event_id` and the field names are unchanged.
- **Could break you:**
  - D9: if any code or fixture builds events with `simulated="true"` or `1`, pass a real boolean.
  - D7/D8: run IDs and event IDs can't contain `/`; don't name a run `organic`.
  - D4: if you build `ts` from an epoch number, pass a timezone-aware `datetime` instead.
- **New and optional:**
  - Your `clients/keewano.py` can call `contracts.validate_event` before `POST /events`; it's
    what the store runs on ingest.
  - `probe.result` events from the sites will carry `attrs.flag` / `attrs.flag_on` (D13). Your
    ground truth stays `GET /__meta`.
- **Still open from §4a (not part of this freeze):** response-body field names your
  `expected_signal` checks rely on (e.g. `order_id`, `owner_user_id`), and how flag
  `endpoints` "cover" a scenario's probe path (`/orders/{id}` vs `/orders/{other_user_order_id}`).
  These land with the flag registry (Dev B M5).

## What this means for Dev C
- **What you can rely on for distilling:**
  - Every event has `event_id`, `customer_id`, `ts`, `event_type`, `policy_outcome`,
    `code_revision` and a real boolean `simulated`.
  - Every `probe.result` and `swarm.*` event has `run_id` and `evidence_ref`.
  - Scenario-scoped events have `scenario_id`, and `swarm.verdict` has `verdict`.
- **New semantics to use:** D10 defines `policy_outcome` on `probe.result`; D13's
  `attrs.flag` names the weakness behind the outcome.
- **Nullable fields:** `knowledge_version` is usually null on site events. Use the one on
  `swarm.*` events for the run's knowledge version.
- **No changes to anything you own** (page schemas, evidence labels).
- **Please review** `docs/event-schema.md` and reply with sign-off or requested changes.
