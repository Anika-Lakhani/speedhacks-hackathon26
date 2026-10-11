# SpeedHacks 2026: self-healing security

A security agent that detects an incident, asks a human to confirm risky fixes, applies the fix, and checks that the fix worked.

Built at SpeedHacks (SF Tech Week, Oct 11 2026) with Alike, Keewano, Sparta, Dial and Darwin.

## Repo layout

| Path | Owner | What |
|---|---|---|
| `docs/` | all | MVP overview and per-dev specs. Start with `docs/swarmshield-mvp-overview.md` |
| `contracts/` | all | Shared schemas and the flag registry |
| `fixtures/` | all | Sample events for building against |
| `sites/` | Dev B | The 3 demo customer sites (local only) |
| `keewano/` | Dev B | Event store and read API |
| `attack/` | Dev A | Harness, planner, probe engine, catalog, verification |
| `distill/` | Dev C | Customer analysis, shared updater, privacy |
| `memory/` | Dev C | `customer-X.md` pages and `shared-intelligence.md` |

## Setup

Python 3.12+, managed with [uv](https://docs.astral.sh/uv/):

```sh
uv sync            # create .venv and install deps
uv run pytest      # run tests
uv run ruff check  # lint
```

Add a dependency with `uv add <pkg>` and commit `pyproject.toml` and `uv.lock` together.
