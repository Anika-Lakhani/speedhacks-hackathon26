# customer-c: security memory

page_schema: 1.0 · customer_id: customer-c

<!-- Maintained by distill/customer_analysis via targeted section patches. -->

## 1. Environment profile & tested revision

- app: CMS (posts, comments, uploads)
- base_url: http://localhost:3003 (local only)
- tested_revision: unknown
- last_distilled: never

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


## 4. Observed events & notable sequences


## 5. Confirmed findings & evidence


## 6. Hypotheses & unverified leads


## 7. Prior swarm runs


## 8. Defenses & regression tests


## 9. Open risks & prioritized next tests


## 10. Candidate lessons for shared intelligence
