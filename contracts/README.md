# contracts/

Shared interfaces between workstreams. The overview (§5) is the source of truth; changes need sign-off from A, B and C.

| File (planned) | Owner | Spec |
|---|---|---|
| `events.py`, `event.schema.json` (v1.1) | Dev B | `docs/swarmshield-mvp-overview.md` §5.1 |
| `flags.yaml` (flag registry) | Dev B | `docs/dev-B-demo-sites-and-event-pipeline.md` §4a.3 |
| `labels.py` (verdicts, evidence labels) | Dev A | overview §5.2, §5.3 |
| Page schemas (`customer-X.md`, `shared-intelligence.md`) | Dev C | overview §5.4, §5.5 |

## Using the event schema

```python
from contracts import Event, make_evidence_ref

event = Event.model_validate_json(raw)  # raises ValidationError if it breaks the contract
```

Non-Python consumers can validate against `event.schema.json`. That file only covers field types; the cross-field rules below are enforced in `events.py`:

- `swarm.*` events: `actor=swarm_agent`; `probe.result`: `actor=system`
- `probe.result` and `swarm.*`: `simulated=true`, plus a `run_id` and an `evidence_ref`
- `probe.result`, `swarm.probe`, `swarm.verdict`: `scenario_id` required
- `verdict`: required on `swarm.verdict`, forbidden elsewhere
- `evidence_ref` must name the event's own `customer_id` and `run_id`
- timestamps must be timezone-aware; unknown fields are rejected

After changing `events.py`, regenerate the JSON schema with `uv run python -m contracts` (a test fails if it is stale).
