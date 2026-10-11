# customer-b: security memory

page_schema: 1.0 · customer_id: customer-b

<!-- Maintained by distill/customer_analysis via targeted section patches. -->

## 1. Environment profile & tested revision

- app: SaaS dashboard (workspaces and roles)
- base_url: http://localhost:3002 (local only)
- tested_revision: unknown
- last_distilled: never

## 2. Assets, sensitive actions, trust boundaries, security invariants

**Assets**
- workspace accounts
- member roles
- integration callback settings

**Sensitive actions**
- account reads (`/api/accounts/{id}`)
- user administration (`/admin/users`)
- webhook test callbacks (`/api/webhooks/test`)

**Trust boundaries**
- member -> admin role
- one workspace's accounts -> another's
- server -> internal network via callbacks

**Security invariants**
- A user can only read accounts they own
- Only admin roles can list users
- Server-side callbacks never target internal or non-allowlisted hosts

## 3. Recent code/config changes


## 4. Observed events & notable sequences


## 5. Confirmed findings & evidence


## 6. Hypotheses & unverified leads


## 7. Prior swarm runs


## 8. Defenses & regression tests


## 9. Open risks & prioritized next tests


## 10. Candidate lessons for shared intelligence
