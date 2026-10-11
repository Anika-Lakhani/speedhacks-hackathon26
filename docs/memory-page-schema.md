# Memory page schema (v1.0)

**Owner:** Dev C · **Code:** `distill/pages.py` · **Tests:** `tests/distill/test_pages.py`
**Spec:** overview §5.4 (customer page) and §5.5 (shared page).
**Readers:** Dev A's planner (`attack/harness/context.py`) and the dashboard (read-only).

Create missing pages with `uv run python -m distill.scaffold` (never overwrites; `--force` to reset).

## `memory/customers/<customer_id>.md`

- Title line, then a header line `page_schema: 1.0 · customer_id: <id>`.
- Exactly ten sections, in order, as `## <n>. <title>` (titles in `CUSTOMER_SECTIONS`).
  No other heading in the page may start with a digit (A's reader treats it as a section).
- §1 and §2 are seeded from a static profile per customer; §3–§10 start empty and are filled
  by the customer-analysis agent through section patches, never full rewrites.
- A's planner reads §2, §3, §4, §7, §9. Empty sections are skipped.

### Entries (written by `distill/customer_analysis`)

One bullet line per entry: `` - `KEY` [label] text (field: value, field: value) ``.
`label` is an evidence label (overview §5.2). The trailing fields are the state the analyzer
merges on its next pass; list values are space-separated. §1 uses plain `- name: value` lines.
Entries are upserted or removed by key; other lines (e.g. the §2 profile) are never touched.

| § | Key | Meaning |
|---|---|---|
| 1 | `tested_revision`, `last_distilled`, `knowledge_version_seen` | latest revision, event time, knowledge version |
| 3 | `REV-<revision>` | a code revision, first seen time, change summary and surfaces if supplied |
| 4 | `OBS-<event_type>-<deny\|flag>` | organic deny/flag events, with event refs (first 8 chars of `event_id`) |
| 5 | `F-<scenario_id>` | a confirmed finding: `status` open / fixed / contradicted, confirming runs, `evidence_ref` |
| 6 | `HYP-<weakness_class>` | weakness suggested by organic signals; `status` open / confirmed / not_reproduced |
| 6 | `PRB-<scenario_id>` | vulnerable probe response with no verdict yet (a lead, not a finding) |
| 7 | `RUN-<run_id>` | one swarm run: revision, planner, per-scenario verdicts or probe outcomes |
| 8 | `REG-<scenario_id>`, `DEF-<scenario_id>` | regression test for a finding (failing/passing); invariant seen holding |
| 9 | `NEXT-<scenario_id>`, `GAP-<weakness_class>` | next test to run (removed once tested); class with no catalog scenario |
| 10 | `CL-<weakness_class>` | candidate lesson; `sharing` proposed / approved (human) / hold (contradicted) |

A finding is `reproduced` when Dev A confirms it and `verified` only after a human approves it
(`attack.harness approve`, read from `.swarmshield/approvals.json`).

Run it: `uv run python -m distill.customer_analysis --customer customer-a --events
fixtures/events/customer-a.jsonl --dry-run` (or `--keewano http://localhost:4000` once Dev B's
read API is live). It prints the patch as a diff and applies it unless `--dry-run`.

## `memory/shared-intelligence.md`

- `knowledge_version: <x.y.z>` near the top, before any item. A stamps it on every run.
- Sections (`## <title>`): taxonomy & version · generalized attack patterns & preconditions ·
  reusable synthetic scenarios · invariants & defensive patterns · verified mitigation &
  regression guidance · deprecated & superseded knowledge · change log · pending contributions.
- **Item headings:** active items are `### <id>`. A reads every `### ` heading as a live
  lesson, so pending, quarantined, deprecated, superseded and retracted items use `#### <id>`.
- Every item has an `applicability:` line listing weakness classes from the taxonomy
  (e.g. `applicability: idor, bola`). A matches it as a substring against the customer's
  catalog classes, and treats `any` or `all` anywhere in the line as "every customer", so
  applicability lines name classes only.

### Shared updater (`distill/shared_updater`)

`shared-intelligence.md` is generated from `memory/shared/corpus.json`; never edit it by hand.
Every version is snapshotted in `memory/shared/history/`, every change is appended to
`memory/shared/audit.jsonl` (minimized evidence + authorizing policy `shared-policy/1`).

```sh
uv run python -m distill.shared_updater approve --customer customer-a --class idor  # human gate
uv run python -m distill.shared_updater update [--dry-run]   # promote approved §10 candidates
uv run python -m distill.shared_updater retract <item-id> --reason "..."
uv run python -m distill.shared_updater rollback <knowledge_version>
uv run python -m distill.shared_updater audit                 # privacy audit of the shared page
```

- Reads only §10 `CL-*` lines with `sharing: approved` and label `reproduced`/`verified`.
- Item text comes from per-weakness templates (`lessons.py`), never from customer pages. `idor`
  and `bola` share one lesson, so findings from two tenants merge into one item.
- Candidates carrying secrets or PII, unknown classes, and contributions to retracted items are
  quarantined (`#### Q-…` under Pending contributions; the content stays on the customer page).
- Evidence gate: one tenant, one confirmation → `confidence: low`; two confirmations → `medium`;
  two tenants → `high`. `evidence_level: verified` needs a human-verified source and ≥2
  confirmations.
- Provenance is an HMAC token per tenant keyed by `SWARMSHIELD_PROVENANCE_SALT` (or a generated
  `.data/provenance.salt`); tenant names never appear in the corpus, history or audit log.

### Taxonomy

Weakness classes match `weakness_class` in Dev A's scenario catalog, grouped into families so a
lesson can be scoped to sibling classes on other tenants:

| Family | Weakness classes |
|---|---|
| `object_access` | `idor`, `bola` |
| `authorization` | `missing_authz` |
| `auth_abuse` | `missing_rate_limit`, `weak_reset_flow` |
| `server_side_request` | `ssrf` |
| `input_handling` | `injection`, `output_encoding`, `path_traversal` |

## Open with Dev A
- A's lesson splitter runs from one `### ` heading to the next, so the last active item's text
  includes the following `##` sections. Proposed fix in `context.py`: end a chunk at the next
  `## ` heading too.
- The `any`/`all` substring check also matches words like "callback" or "allowlist".
  Proposed fix: match whole words, or only an explicit `applicability: any`.
