# attack/ — Dev A

Attack simulation and orchestration.

| Dir | Purpose |
|---|---|
| `harness/` | Runs agents with budgets, allowlists, run IDs and approval gates |
| `agent/` | Planner: picks scenarios and interprets results (no exploitation) |
| `engine/` | Fires the marked probes and collects the results |
| `catalog/` | Versioned scenario catalog (data) |
| `verify/` | Turns results into verdicts against each scenario's invariant |

Spec: `docs/dev-A-simulation-core-and-attack-engine.md`.
