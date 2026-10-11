# Dev C plan

Spec: `docs/dev-C-shared-intelligence-and-privacy.md`. Formats and CLIs:
`docs/memory-page-schema.md`. Branch: `dev-c/foundation`.

- [x] **M1: Page schemas.** `customer-X.md` and `shared-intelligence.md` formats, scaffolds,
  contract tests against Dev A's reader (`attack/harness/context.py`).
- [x] **M2: Customer-analysis agent.** Event window + page -> keyed section patch; idempotent;
  distills Dev A's swarm verdicts; event content treated as untrusted.
- [x] **M3: Shared updater + privacy.** §10-only reads, template-based items, secret/PII/tenant/
  re-identification gates, merge across tenants, evidence gate, provenance tokens, audit,
  snapshots, retract, rollback.
- [x] **M4: Live reads + lifecycle.** Paged reads from Dev B's read API (incremental from
  `last_distilled`); quarantine review (release/reject), supersede, expiry.
- [x] **Acceptance criterion 8 end to end** (`tests/distill/test_end_to_end.py`): customer-a's
  IDOR lesson reaches customer-b's planner input in a real harness run (not customer-c's), and
  customer-b's BOLA finding merges back into the same item at high confidence.
- [ ] **M5: Demo support.** One-command loop (harness run -> distill -> approve -> update),
  seeded customer-a finding, dashboard memory/shared panels with Dev A.
- [ ] **M6: Live run on the 3 demo sites** (needs Dev B M4-M6) and the final privacy audit.

## Later (nice to have)
- **Human-approval toggle for sharing.** Today a human approves each §10 candidate
  (`shared_updater approve`). Add a config switch: on = current behavior; off = candidates are
  approved automatically. Privacy gates, quarantine and the evidence gate still apply either way.
- Bump an item's version when its lesson template text changes.
- Optional LLM summary in the analysis agent (deterministic rules stay the source of truth).

## Out of scope: sent for human review
- **Cross-tenant contradictions** (dev-C §3, "contradictory results are retained and
  investigated"). Within one customer this is handled: a same-revision contradiction marks the
  finding `contradicted` and holds its lesson back. Across customers it is not: if one tenant
  disproves an active shared item, the corpus isn't told, because only confirmed findings flow
  up. Until this is built, a reviewer handles it by hand: `shared_updater retract` or
  `supersede` the item, with the reason recorded in the audit log.

## Open
- Dev C sign-off on event contract v1.1 (`docs/CONTRACT-CHANGES-v1.1.md`).
- Dev A: reader fixes in `patches/dev-a-context-reader-fix.patch`; an event when a finding is
  approved (today the analyzer reads `.swarmshield/approvals.json`).
