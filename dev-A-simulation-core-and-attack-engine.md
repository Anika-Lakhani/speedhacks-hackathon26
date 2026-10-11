# Dev A — Attack Simulation & Orchestration

**Effort:** 40% of MVP · **Role:** the offense
**Read first:** `swarmshield-mvp-overview.md` (esp. §5 contracts, §5.6 fake-hacking model)
**Depends on:** Dev B (Keewano read API, event schema, demo-site vulnerability flags) and Dev C (`customer-X.md`, `shared-intelligence.md`)

You own the testing side of the loop: the agent harness, the attack/test agent, the engine that *simulates* attacks safely, and the verification that turns probe outcomes into verdicts. This is the highest-risk, highest-novelty workstream — the agents are nondeterministic and the "hacking" has to look real while being completely safe.

You **no longer** own the customer-analysis agent or the customer page — those moved to Dev C. You *consume* `customer-X.md` as input and you *write result events to Keewano*; Dev C re-distills those results back into the page.

---

## 1. What you own

1. **Agent orchestration harness** — runs agents with bounded scope, budgets, allowed tools, and structured-output contracts. The harness (not the prompt) enforces limits.
2. **Attack/test agent** — selects what to test and produces a test plan; interprets simulated results.
3. **Simulation engine (fake hacking)** — the deterministic component that actually "runs" tests safely.
4. **Result verification** — turns raw probe outcomes into `confirmed | not_reproduced | inconclusive | blocked`, tied to a stated invariant.
5. **Result logging** — writes `simulated: true` result events to Keewano (Dev B's store) for Dev C to distill.

---

## 2. The fake-hacking model (your most important constraint)

Our Claude agents will refuse to perform real attacks, and we don't want real exploitation for security reasons. So the architecture splits cleanly:

- **Claude's job:** *reason* about the system — prioritize targets, propose a test plan referencing scenarios from the catalog, and interpret results. This is ordinary security *analysis*, which Claude will do.
- **The harness's job:** *execute* the plan by running scripted, benign probes from the scenario catalog against the demo site and reading back a simulated outcome.

Claude never sends an exploit and never needs to. If a prompt would ever ask the model to actually exploit, that's a design bug — the model only selects scenario IDs and reads structured results.

### Scenario catalog (you build this)

A versioned library where each scenario is **data, not code for the model to execute**:

```yaml
- id: SCN-IDOR-001
  title: Horizontal IDOR on order detail
  invariant: "A user can only read their own orders"
  preconditions: [ "authenticated session", "flag:idor_orders == on" ]
  probe:
    kind: benign_request          # harness-executed, clearly marked
    request: "GET /orders/{other_user_order_id}"
    marker: "X-SwarmShield-Probe: SCN-IDOR-001"
  expected_signal: "200 with another user's (synthetic) order payload"
  severity: high
```

The **harness** runs `probe` against the demo site; the site (Dev B) returns a simulated result based on its `flag:idor_orders`. No real user data, no destructive actions, every probe header-tagged and logged with `simulated: true`.

Start with ~8–12 scenarios spanning the basics (IDOR/BOLA, missing authz, missing rate limit, weak reset flow, injection-shaped input handling, SSRF-shaped callbacks). Keep them synthetic and tied to Dev B's flags; coordinate on the flag registry so catalog and sites stay in sync.

---

## 3. Attack/test agent I/O contract

- **Input:** a bounded objective, relevant `customer-X.md` sections (from C), relevant Keewano event slices + prior swarm events (from B), code diff, applicable shared intelligence (from C), allowed tools, budget, sandbox details.
- **Output:** a structured test plan (ordered scenario IDs + rationale), expected vs. observed outcomes, evidence references, state changes, confidence.
- **Constraints:** cannot expand scope, touch other tenants, self-grant permissions, or change production state. Prioritizes by impact, exposure, novelty, change-recency, known history, expected value — tests triggered by *change*, not full-history sweeps.

### Verification
- Compare claimed success against resulting state **and** the scenario's `invariant`.
- Emit a verdict from §5.3. A missing or ambiguous signal is `inconclusive`, never a pass.
- Promoting a finding to `verified` is a high-impact action → human-approval gate.

---

## 4. Harness requirements

- Per-run caps: tool calls, runtime, retries, spend, swarm size.
- Allowed-tools allowlist and target-scope allowlist enforced in code.
- Every run records `run_id`, `code_revision`, `knowledge_version`.
- All actions logged to Keewano with `simulated: true` and an `evidence_ref`.
- High-impact actions require a human-approval gate (a simple hold/approve step is fine for MVP).
- Deterministic replay: given stored evidence + scenario version, a prior attack reproduces.

---

## 5. Acceptance criteria

- Attack agent produces a prioritized plan that favors recently-changed surfaces over untouched ones.
- Simulation engine runs every catalog scenario against a demo site and logs `simulated: true` events with evidence refs.
- Verdicts are correct against the flagged ground truth on the demo sites (confirmed when the flag is on, not_reproduced when off).
- A confirmed finding is reproducible from stored evidence alone.
- Budgets and stop-conditions provably halt a runaway run.
- Result events are shaped so Dev C can distill them into `customer-X.md` without extra parsing.

---

## 6. Out of scope for you
- Writing demo sites or Keewano (Dev B).
- The customer-analysis agent, `customer-X.md`, generalization, or privacy (Dev C). You consume the page; you don't write it.

---

## 7. Suggested sequencing
W1 harness skeleton + attack-agent I/O, stub simulator against fixtures · W2 attack-agent prioritization to green on fixtures · W3 simulation engine + scenario catalog · W4 verification + verdicts + budgets/approval gates · W5 integrate full loop on 1→3 customers · W6 harden, demo.
