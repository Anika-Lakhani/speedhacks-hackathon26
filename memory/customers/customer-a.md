# customer-a: security memory

page_schema: 1.0 · customer_id: customer-a

<!-- Maintained by distill/customer_analysis via targeted section patches. -->

## 1. Environment profile & tested revision

- app: e-commerce storefront
- base_url: http://localhost:3001 (local only)
- tested_revision: unknown
- last_distilled: never

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


## 4. Observed events & notable sequences


## 5. Confirmed findings & evidence


## 6. Hypotheses & unverified leads


## 7. Prior swarm runs


## 8. Defenses & regression tests


## 9. Open risks & prioritized next tests


## 10. Candidate lessons for shared intelligence
