# CLAUDE.md

Shared repo for the SwarmShield MVP (three developers). Start with `README.md` and
`docs/swarmshield-mvp-overview.md`. Each developer keeps their standing rules in a marked
section below; edit only your own section.

---

## Dev B: demo sites and event store

### Role
- I'm Dev B: everything up to and including getting events into Keewano.
- I build three demo customer sites that emit security events and honor vulnerability flags.
- I own the per-tenant event store: ingestion, isolation, and the read/query API.
- I own the event schema contract (overview §5.1, dev-B §4a) and the flag registry.
- I don't interpret events (Dev C) or run attacks (Dev A); I make their inputs reliable.

**Folders I own:** `sites/`, `keewano/`, `contracts/` (event schema and `flags.yaml`; `labels.py`
is Dev A's), `fixtures/events/`, `tests/` files for those folders, and these docs:
`docs/dev-B-demo-sites-and-event-pipeline.md`, `docs/PLAN-dev-b.md`, `docs/event-schema.md`,
`docs/CONTRACT-CHANGES-*.md`. Plan and milestone status: `docs/PLAN-dev-b.md`.

### Commands
Python 3.12 and [uv](https://docs.astral.sh/uv/). Run everything from the repo root.

```sh
uv sync                          # create .venv, install deps (incl. dev group)
uv run pytest                    # all tests
uv run pytest tests/test_events.py tests/test_validate.py   # contract tests only
uv run ruff check                # lint
uv run python -m contracts       # regenerate contracts/event.schema.json after editing events.py
```

Services (ports fixed by dev-B §4a.1/§4a.6). These modules don't exist yet; they arrive in
M2–M6 and these are the intended entry points:

```sh
uv run uvicorn keewano.api:app --port 4000               # event store + read API
uv run uvicorn sites.customer_a.app:app --port 3001      # customer-a (e-commerce)
uv run uvicorn sites.customer_b.app:app --port 3002      # customer-b (SaaS dashboard)
uv run uvicorn sites.customer_c.app:app --port 3003      # customer-c (CMS)
```

Add dependencies with `uv add <pkg>` (or `uv add --dev <pkg>`) and commit `pyproject.toml`
and `uv.lock` together. Don't introduce another package manager or test runner.

### Rules
- **Schema source of truth is `contracts/`.** Sites, ingestion and the read API all validate
  through `contracts/validate.py` (`validate_event`, `validate_batch`). Never define a second
  event model. After changing `events.py`, regenerate `event.schema.json`.
- **SAFETY RULE.** Demo sites never perform real unsafe operations. With a flag on, a probe
  (request carrying `X-SwarmShield-Probe`) gets a synthetic "vulnerable signal" built from
  fake data only. Never implement genuinely exploitable behavior against real data. Sites
  run on localhost only and are never deployed publicly.
- **Tenant isolation.** No query path may cross `customer_id`. Every read requires a
  `customer_id`, and no endpoint returns rows from more than one tenant.
- **Minimal UIs.** Realism lives in events and flags, not in the front end.
- **Keewano MCP is read-only.** Use it only to verify what landed; never attempt writes
  through it. Writes go through the store's sink (SQLite locally, Keewano stub/real later).
- **Workflow.** Write tests alongside code and run them before declaring anything done. One
  commit per milestone. Never commit secrets (`.env` is gitignored; use `.env.example`).
  Touch only the folders I own unless told otherwise. No PRs unless asked.
- **Shared contract changes** (event schema, flag registry, §4a) need A and C sign-off; log
  each one in `docs/CONTRACT-CHANGES-*.md`.
