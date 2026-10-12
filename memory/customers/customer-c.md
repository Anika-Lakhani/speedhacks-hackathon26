# customer-c: security memory

page_schema: 1.0 · customer_id: customer-c

<!-- Maintained by distill/customer_analysis via targeted section patches. -->

## 1. Environment profile & tested revision

- app: CMS (posts, comments, uploads)
- base_url: http://localhost:3003 (local only)
- tested_revision: customer-c-1.7.1
- last_distilled: 2026-10-12T00:22:04.957356Z
- knowledge_version: 0.4.0
- knowledge_version_seen: 0.4.0

## 2. Assets, sensitive actions, trust boundaries, security invariants

**Assets**
- posts and comments
- uploaded files
- search index

**Sensitive actions**
- search (`/search`)
- comment preview rendering (`/comments/preview`)
- file uploads (`/uploads`)

**Trust boundaries**
- user input -> query engine
- user markup -> other readers' browsers
- uploaded filename -> server filesystem

**Security invariants**
- User input is never interpreted as query syntax
- User-supplied markup is always encoded on output
- Uploaded files are stored under server-chosen names inside the upload root

## 3. Recent code/config changes

- `REV-customer-c-1.7.0` [observed] code revision customer-c-1.7.0 (first: 2026-10-12T00:22:04.927170Z)
- `REV-customer-c-1.7.1` [observed] code revision customer-c-1.7.1 (first: 2026-10-12T00:22:04.945982Z)

## 4. Observed events & notable sequences


## 5. Confirmed findings & evidence

- `F-SCN-INJ-001` [verified] SCN-INJ-001 Search input reaches the query layer unsanitised (injection, high): invariant 'User input is never interpreted as query syntax' violated; open at rev customer-c-1.7.1 (status: open, confirmed_rev: customer-c-1.7.1, rev: customer-c-1.7.1, run: run-850bbedf, at: 2026-10-12T00:22:04.953746Z, confirmations: run-850bbedf run-cfda5c13, evidence: ev://customer-c/run-850bbedf/2eae77ea-2501-4b5c-9986-0112ae1ddcc7)
- `F-SCN-XSS-001` [verified] SCN-XSS-001 Comment preview reflects markup unencoded (output_encoding, medium): invariant 'User-supplied markup is always encoded on output' violated; held at rev customer-c-1.7.1, fixed (status: fixed, confirmed_rev: customer-c-1.7.0, rev: customer-c-1.7.1, run: run-850bbedf, at: 2026-10-12T00:22:04.956640Z, confirmations: run-cfda5c13, evidence: ev://customer-c/run-cfda5c13/0c3e503e-254e-47d7-8d6a-0dadd201bcb3)

## 6. Hypotheses & unverified leads


## 7. Prior swarm runs

- `RUN-run-cfda5c13` [observed] run on rev customer-c-1.7.0: 2 confirmed, 1 not_reproduced (planner: dummy, stop: completed, at: 2026-10-12T00:22:04.927170Z, rev: customer-c-1.7.0, verdicts: SCN-INJ-001=confirmed SCN-UPLOAD-001=not_reproduced SCN-XSS-001=confirmed, knowledge: 0.3.0)
- `RUN-run-850bbedf` [observed] run on rev customer-c-1.7.1: 1 confirmed, 2 not_reproduced (planner: dummy, stop: completed, at: 2026-10-12T00:22:04.945982Z, rev: customer-c-1.7.1, verdicts: SCN-INJ-001=confirmed SCN-UPLOAD-001=not_reproduced SCN-XSS-001=not_reproduced, knowledge: 0.4.0)

## 8. Defenses & regression tests

- `REG-SCN-INJ-001` [observed] regression test: rerun SCN-INJ-001 on any change to /search; failing (status: failing, guards: F-SCN-INJ-001)
- `REG-SCN-XSS-001` [observed] regression test: rerun SCN-XSS-001 on any change to /comments/preview; passing since rev customer-c-1.7.1 (status: passing, guards: F-SCN-XSS-001)
- `DEF-SCN-UPLOAD-001` [observed] invariant 'Uploaded files are stored under server-chosen names inside the upload root' held against SCN-UPLOAD-001 at rev customer-c-1.7.1 (run: run-850bbedf, at: 2026-10-12T00:22:04.955194Z)

## 9. Open risks & prioritized next tests


## 10. Candidate lessons for shared intelligence

- `CL-injection` [verified] injection in family input_handling: invariant 'User input is never interpreted as query syntax' was violated; suggested test: Search input reaches the query layer unsanitised (sharing: approved, class: injection, scenarios: SCN-INJ-001, confirmations: 2)
- `CL-output_encoding` [verified] output_encoding in family input_handling: invariant 'User-supplied markup is always encoded on output' was violated; suggested test: Comment preview reflects markup unencoded (sharing: approved, class: output_encoding, scenarios: SCN-XSS-001, confirmations: 1)
