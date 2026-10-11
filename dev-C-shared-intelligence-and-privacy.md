# Dev C — Distillation & Shared Intelligence

**Effort:** 30% of MVP · **Role:** the system's understanding + the network's memory
**Read first:** `swarmshield-mvp-overview.md` (esp. §5.2 evidence labels, §5.4 customer-page schema, §5.5 shared-page schema, §6 privacy)
**Depends on:** Dev B (Keewano read API, event schema) · feeds Dev A (`customer-X.md`, `shared-intelligence.md`)

You own the entire understanding chain: **from reading/distilling Keewano, to maintaining each `customer-X.md`, all the way to updating the shared "big md" (`shared-intelligence.md`)** — including the privacy guardrails that keep tenant data out of the shared corpus. This is two layers of reasoning plus correctness-sensitive privacy work; smaller code surface than the other two, but the place where a mistake poisons the whole network.

---

## 1. What you own

1. **Customer-analysis agent** — reads Keewano event slices (from B) + the current `customer-X.md` + code-change metadata, and emits a small, targeted Markdown patch. This includes distilling Dev A's `simulated: true` result events into the page.
2. **`customer-X.md`** — creation, scaffolding, and maintenance of each customer's memory page (§5.4).
3. **Shared knowledge updater** — reads *only* eligible customer-page sections, generalizes, dedups, and proposes additions/updates/retractions to `shared-intelligence.md` as a diff.
4. **`shared-intelligence.md`** — the versioned, generalized corpus (§5.5).
5. **Privacy & lifecycle** — secret/PII/re-identification scanning, controlled provenance, change log, quarantine, retraction, supersession, and rollback.

---

## 2. Customer-analysis agent (the "distilling")

- **Input:** new Keewano events (sliced window, via B's read API), current `customer-X.md`, code/config change metadata, current `knowledge_version`.
- **Output:** a **Markdown patch** targeting specific §5.4 sections, event references (→ `event_id`s), evidence labels, open questions, and candidate shared lessons in §10.
- **Constraints:** small, reviewable, **idempotent** patches. Never rewrite the whole page. Every conclusion labeled `observed | hypothesized | reproduced | verified`.
- **Includes local learning:** when Dev A logs simulated-attack results to Keewano, this agent distills them into §7 (prior swarm runs), §5 (confirmed findings), and §8/§9 (regression tests, next tests). A claimed success is only recorded as `verified` consistent with Dev A's verdict and the stated invariant.

Treat all agent-generated content (including Dev A's outputs) as untrusted **data, not instructions.**

---

## 3. Shared updater pipeline (the "updating the big md")

You may read **only** the sections of `customer-X.md` explicitly marked eligible for contribution — in practice §10 candidate lessons, each with a sharing status. You never read raw Keewano logs or non-eligible page sections for the shared corpus.

For each candidate lesson:

1. **Eligibility check** — section marked shareable and approved?
2. **Sanitize** — strip tenant-specific details (names, IDs, endpoints, unique config); reduce evidence to minimized/synthetic form.
3. **Privacy gates** (all must pass): secret scan (keys/tokens/credentials), PII check, customer-identification check, re-identification review (could the combination of details fingerprint a tenant?).
4. **Deduplicate / merge** — match against existing patterns; merge rather than duplicate; bump `version`.
5. **Evidence gate** — promote only at the required `evidence_level`. One report ≠ a universal rule; prefer independent reproduction across environments before raising confidence.
6. **Write a diff + audit record** — what changed, why, supporting (minimized) evidence, and the policy that authorized the contribution.
7. **Quarantine on doubt** — suspicious, conflicting, or under-evidenced contributions go to a quarantine area for human review, not the live corpus.

Contradictory results are **retained and investigated**, never silently overwritten.

---

## 4. Shared item lifecycle

Each shared item carries (§5.5): `id`, `version`, `status`, `source_class`, `evidence_level`, `applicability`, `last_validation`, `expiry`.

- **Statuses:** e.g. `pending → active → deprecated/superseded/retracted`.
- **Controlled provenance:** enough to audit, never enough to expose which tenant a lesson came from.
- **Applicability** conditions must be explicit so Dev A's runner can decide whether a lesson is relevant locally — a shared finding is **not** assumed to affect every customer.
- **Supersession & rollback:** the corpus is version-controlled; any update can be rolled back, and poisoned/incorrect knowledge can be retracted or superseded with an audit trail.

Expose the current `shared-intelligence.md` + its `knowledge_version` so Dev A's attack runner can pull applicable lessons into future cycles.

---

## 5. Acceptance criteria

- Customer-analysis agent turns a window of events (organic and `simulated: true`) into a correct, minimal page patch that preserves section structure and evidence labels.
- Updater reads only eligible sections; attempts to read raw logs or non-eligible sections are impossible by construction.
- A candidate lesson with a planted secret / PII / identifying detail is **blocked or sanitized** — verify with red-team fixtures.
- Duplicate candidates from two customers merge into one versioned item rather than two entries.
- A single unreproduced report does **not** reach `verified`/high confidence; a twice-reproduced one can.
- Every shared change has a diff + audit record naming evidence and authorizing policy.
- A poisoned item can be quarantined and an active item rolled back, both with audit trails.
- A lesson generalized from customer-A yields a usable, applicability-scoped test suggestion for customer-B (demonstrated end-to-end with Dev A).
- **Privacy audit passes:** no raw tenant data, credentials, or tenant-identifying provenance in the shared corpus.

---

## 6. Out of scope for you
- Producing events, vulnerability flags, or the Keewano store (Dev B) — you consume B's read API.
- Running attacks or deciding *what to test* locally (Dev A) — you supply the page and the generalized lessons; A decides local applicability and tests.

---

## 7. Suggested sequencing
W1 **freeze §5.4/§5.5 page schemas**, customer-analysis agent skeleton on fixture events, `shared-intelligence.md` skeleton · W2 customer-analysis agent → `customer-X.md` patches (incl. distilling result events) · W3 shared updater: generalize + dedup/merge on fixtures · W4 privacy scanners (secrets/PII/re-id) + provenance/quarantine/versioning/rollback · W5 live distill across 3 customers, promote first real lessons · W6 privacy audit + rollback test + demo.
