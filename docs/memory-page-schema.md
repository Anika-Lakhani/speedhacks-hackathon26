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
