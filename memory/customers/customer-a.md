# customer-a: security memory

page_schema: 1.0 · customer_id: customer-a

<!-- Maintained by distill/customer_analysis via targeted section patches. -->

## 1. Environment profile & tested revision

- app: e-commerce storefront
- base_url: http://localhost:3001 (local only)
- tested_revision: customer-a-1.0.40
- last_distilled: 2026-10-12T00:22:06.631463Z
- knowledge_version: 0.5.0
- knowledge_version_seen: 0.5.0

## 2. Assets, sensitive actions, trust boundaries, security invariants

**Assets**
- customer accounts and sessions
- orders (per-user)
- password reset tokens

**Sensitive actions**
- login and one-time-code verification (`/login`, `/login/verify-otp`)
- password reset confirmation (`/password-reset/confirm`)
- order detail reads (`/orders/{id}`)

**Trust boundaries**
- anonymous -> authenticated session
- one user -> another user's orders

**Security invariants**
- A user can only read their own orders
- Repeated failed logins for one account are throttled
- One-time-code guesses are rate limited per account
- A password reset requires an unguessable, single-use token

## 3. Recent code/config changes

- `REV-customer-a-1.0.40` [observed] code revision customer-a-1.0.40 (first: 2026-10-12T00:22:06.597242Z)

## 4. Observed events & notable sequences


## 5. Confirmed findings & evidence

- `F-SCN-RESET-001` [verified] SCN-RESET-001 Password reset accepts a guessable token (weak_reset_flow, critical): invariant 'A password reset requires an unguessable, single-use token' violated; open at rev customer-a-1.0.40 (status: open, confirmed_rev: customer-a-1.0.40, rev: customer-a-1.0.40, run: run-67e3509e, at: 2026-10-12T00:22:06.620961Z, confirmations: run-67e3509e, evidence: ev://customer-a/run-67e3509e/3b896198-6cc5-420f-8331-6593ca3e28a9)
- `F-SCN-IDOR-001` [verified] SCN-IDOR-001 Horizontal IDOR on order detail (idor, high): invariant 'A user can only read their own orders' violated; open at rev customer-a-1.0.40 (status: open, confirmed_rev: customer-a-1.0.40, rev: customer-a-1.0.40, run: run-67e3509e, at: 2026-10-12T00:22:06.624519Z, confirmations: run-67e3509e, evidence: ev://customer-a/run-67e3509e/b4c79274-ffde-4996-b782-1702b3af63d6)
- `F-SCN-RATE-001` [verified] SCN-RATE-001 Login endpoint has no attempt throttling (missing_rate_limit, high): invariant 'Repeated failed logins for one account are throttled' violated; open at rev customer-a-1.0.40 (status: open, confirmed_rev: customer-a-1.0.40, rev: customer-a-1.0.40, run: run-67e3509e, at: 2026-10-12T00:22:06.627722Z, confirmations: run-67e3509e, evidence: ev://customer-a/run-67e3509e/062c075a-4d29-4305-99fb-8cb3c3ae5146)
- `F-SCN-RATE-002` [verified] SCN-RATE-002 One-time-code verification has no attempt throttling (missing_rate_limit, high): invariant 'One-time-code guesses are rate limited per account' violated; open at rev customer-a-1.0.40 (status: open, confirmed_rev: customer-a-1.0.40, rev: customer-a-1.0.40, run: run-67e3509e, at: 2026-10-12T00:22:06.630730Z, confirmations: run-67e3509e, evidence: ev://customer-a/run-67e3509e/469e1f83-ffa3-44ef-906e-0882d83ed725)

## 6. Hypotheses & unverified leads


## 7. Prior swarm runs

- `RUN-run-67e3509e` [observed] run on rev customer-a-1.0.40: 4 confirmed (planner: dummy, stop: completed, at: 2026-10-12T00:22:06.597242Z, rev: customer-a-1.0.40, verdicts: SCN-IDOR-001=confirmed SCN-RATE-001=confirmed SCN-RATE-002=confirmed SCN-RESET-001=confirmed, knowledge: 0.5.0)

## 8. Defenses & regression tests

- `REG-SCN-RESET-001` [observed] regression test: rerun SCN-RESET-001 on any change to /password-reset/confirm; failing (status: failing, guards: F-SCN-RESET-001)
- `REG-SCN-IDOR-001` [observed] regression test: rerun SCN-IDOR-001 on any change to /orders/{other_user_order_id}; failing (status: failing, guards: F-SCN-IDOR-001)
- `REG-SCN-RATE-001` [observed] regression test: rerun SCN-RATE-001 on any change to /login; failing (status: failing, guards: F-SCN-RATE-001)
- `REG-SCN-RATE-002` [observed] regression test: rerun SCN-RATE-002 on any change to /login/verify-otp; failing (status: failing, guards: F-SCN-RATE-002)

## 9. Open risks & prioritized next tests


## 10. Candidate lessons for shared intelligence

- `CL-weak_reset_flow` [verified] weak_reset_flow in family auth_abuse: invariant 'A password reset requires an unguessable, single-use token' was violated; suggested test: Password reset accepts a guessable token (sharing: approved, class: weak_reset_flow, scenarios: SCN-RESET-001, confirmations: 1)
- `CL-idor` [verified] idor in family object_access: invariant 'A user can only read their own orders' was violated; suggested test: Horizontal IDOR on order detail (sharing: approved, class: idor, scenarios: SCN-IDOR-001, confirmations: 1)
- `CL-missing_rate_limit` [verified] missing_rate_limit in family auth_abuse: invariant 'Repeated failed logins for one account are throttled' was violated; suggested test: Login endpoint has no attempt throttling (sharing: approved, class: missing_rate_limit, scenarios: SCN-RATE-001 SCN-RATE-002, confirmations: 1)
