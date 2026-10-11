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

## 5. Acceptance criteria

- §5.1 event schema frozen and documented by **end of Week 1 (M1)**.
- All three sites run, expose a revision ID, and emit well-formed §5.1 events for normal usage.
- Flipping a vulnerability flag changes the probe response and the emitted event, with no change to real data handling.
- Keewano stores events per tenant with zero cross-tenant leakage; the query API returns correct sliced windows and "since-revision" results.
- Dev A's result events ingest cleanly alongside organic events.
- Seeded "organic" traffic produces a realistic baseline of events for the demo.

---

## 6. Out of scope for you
- The customer-analysis agent or `customer-X.md` — Dev C reads your store and does the distilling.
- The agents, attack simulation, or verdict logic (Dev A).

---

## 7. Suggested sequencing
W1 **freeze §5.1 schema**, scaffold site A + Keewano ingestion/store/read API · W2 sites B & C + instrumentation + flags · W3 harden read/query (slices, since-revision) + flag registry + full flag coverage for the catalog · W4 seed realistic organic traffic · W5 support integration, fill event gaps · W6 demo data, harden.
