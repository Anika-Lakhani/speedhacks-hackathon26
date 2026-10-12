# customer-b: security memory

page_schema: 1.0 · customer_id: customer-b

<!-- Maintained by distill/customer_analysis via targeted section patches. -->

## 1. Environment profile & tested revision

- app: SaaS dashboard (workspaces and roles)
- base_url: http://localhost:3002 (local only)
- tested_revision: customer-b-2.4.0
- last_distilled: 2026-10-12T00:22:04.920661Z
- knowledge_version: 0.3.0
- knowledge_version_seen: 0.3.0

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

- `REV-customer-b-2.3.0` [observed] code revision customer-b-2.3.0 (first: 2026-10-12T00:22:04.859599Z)
- `REV-customer-b-2.3.1` [observed] code revision customer-b-2.3.1 (first: 2026-10-12T00:22:04.886803Z)
- `REV-customer-b-2.4.0` [observed] code revision customer-b-2.4.0 (first: 2026-10-12T00:22:04.906960Z)

## 4. Observed events & notable sequences


## 5. Confirmed findings & evidence

- `F-SCN-BOLA-001` [verified] SCN-BOLA-001 Account object readable by another tenant user (bola, high): invariant 'A user can only read accounts they own' violated; held at rev customer-b-2.4.0, fixed (status: fixed, confirmed_rev: customer-b-2.3.0, rev: customer-b-2.4.0, run: run-5e7c0c15, at: 2026-10-12T00:22:04.918140Z, confirmations: run-df36d7ee, evidence: ev://customer-b/run-df36d7ee/4a167a85-1abc-4e27-b341-142470736f13)
- `F-SCN-SSRF-001` [verified] SCN-SSRF-001 Webhook test endpoint fetches an internal-shaped URL (ssrf, high): invariant 'Server-side callbacks never target internal or non-allowlisted hosts' violated; held at rev customer-b-2.4.0, fixed (status: fixed, confirmed_rev: customer-b-2.3.1, rev: customer-b-2.4.0, run: run-5e7c0c15, at: 2026-10-12T00:22:04.919804Z, confirmations: run-a9f8ac2b run-df36d7ee, evidence: ev://customer-b/run-a9f8ac2b/c1dcb26c-b159-4a0a-a6fe-6c4bfdabc156)

## 6. Hypotheses & unverified leads


## 7. Prior swarm runs

- `RUN-run-df36d7ee` [observed] run on rev customer-b-2.3.0: 2 confirmed, 1 not_reproduced (planner: dummy, stop: completed, at: 2026-10-12T00:22:04.859599Z, rev: customer-b-2.3.0, verdicts: SCN-AUTHZ-001=not_reproduced SCN-BOLA-001=confirmed SCN-SSRF-001=confirmed, knowledge: 0.1.0)
- `RUN-run-a9f8ac2b` [observed] run on rev customer-b-2.3.1: 1 confirmed, 2 not_reproduced (planner: dummy, stop: completed, at: 2026-10-12T00:22:04.886803Z, rev: customer-b-2.3.1, verdicts: SCN-AUTHZ-001=not_reproduced SCN-BOLA-001=not_reproduced SCN-SSRF-001=confirmed, knowledge: 0.2.0)
- `RUN-run-5e7c0c15` [observed] run on rev customer-b-2.4.0: 3 not_reproduced (planner: dummy, stop: completed, at: 2026-10-12T00:22:04.906960Z, rev: customer-b-2.4.0, verdicts: SCN-AUTHZ-001=not_reproduced SCN-BOLA-001=not_reproduced SCN-SSRF-001=not_reproduced, knowledge: 0.3.0)

## 8. Defenses & regression tests

- `REG-SCN-BOLA-001` [observed] regression test: rerun SCN-BOLA-001 on any change to /api/accounts/{other_account_id}; passing since rev customer-b-2.4.0 (status: passing, guards: F-SCN-BOLA-001)
- `REG-SCN-SSRF-001` [observed] regression test: rerun SCN-SSRF-001 on any change to /api/webhooks/test; passing since rev customer-b-2.4.0 (status: passing, guards: F-SCN-SSRF-001)
- `DEF-SCN-AUTHZ-001` [observed] invariant 'Only admin roles can list users' held against SCN-AUTHZ-001 at rev customer-b-2.4.0 (run: run-5e7c0c15, at: 2026-10-12T00:22:04.916637Z)

## 9. Open risks & prioritized next tests


## 10. Candidate lessons for shared intelligence

- `CL-bola` [verified] bola in family object_access: invariant 'A user can only read accounts they own' was violated; suggested test: Account object readable by another tenant user (sharing: approved, class: bola, scenarios: SCN-BOLA-001, confirmations: 1)
- `CL-ssrf` [verified] ssrf in family server_side_request: invariant 'Server-side callbacks never target internal or non-allowlisted hosts' was violated; suggested test: Webhook test endpoint fetches an internal-shaped URL (sharing: approved, class: ssrf, scenarios: SCN-SSRF-001, confirmations: 2)
