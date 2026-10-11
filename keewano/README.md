# keewano/ — Dev B

The per-tenant event store: ingestion, isolation, and the read/query API on port 4000.

| Module | What |
|---|---|
| `storage.py` | `EventStore` interface, `Artifact`, errors, `make_store(settings)` |
| `sqlite_store.py` | Local implementation: one events and one artifacts table per tenant |
| `keewano_store.py` | Keewano implementation, stubbed (raises "not configured") until M3b |
| `config.py` | Settings from env (`SWARMSHIELD_STORE`, paths, tenants) |
| `ingest.py` | Validate, route by `customer_id`, store, log rejections |
| `rejects.py` | Rejects log (JSONL); `python -m keewano.rejects` to inspect |
| `api.py` | FastAPI app: `POST /events`, `POST /evidence`, `GET /health` |
| `setup.py` | `python -m keewano.setup`: create per-tenant tables, idempotent |
| `fixtures.py` | `python -m keewano.fixtures`: regenerate `fixtures/events/*.jsonl` |

Docs: `docs/ingestion-api.md`. Spec: `docs/dev-B-demo-sites-and-event-pipeline.md` §4 and §4a.6.
