"""Event store HTTP API (port 4000). M2: ingestion and artifact upload; reads arrive in M3.

uv run uvicorn keewano.api:create_app --factory --port 4000
"""

import json

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from keewano.config import Settings, load_settings
from keewano.ingest import ArtifactRejected, Ingestor
from keewano.rejects import RejectsLog
from keewano.storage import EventStore, make_store


def create_app(settings: Settings | None = None, store: EventStore | None = None) -> FastAPI:
    settings = settings or load_settings()
    store = store or make_store(settings)
    store.setup(settings.tenants)  # idempotent; raises StoreNotConfigured for the Keewano stub
    rejects = RejectsLog(settings.rejects_path)
    ingestor = Ingestor(store, rejects, settings.tenants)

    app = FastAPI(title="SwarmShield event store", version="0.2.0")
    app.state.settings = settings
    app.state.store = store
    app.state.rejects = rejects
    app.state.ingestor = ingestor

    async def _json_body(request: Request, kind: str):
        raw = await request.body()
        try:
            return json.loads(raw), None
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            reason = f"request body is not valid JSON: {e}"
            rejects.record(kind=kind, reason=reason, raw=raw.decode("utf-8", "replace"))
            return None, reason

    @app.post("/events")
    async def post_events(request: Request):
        """One event object or an array of events. Each is accepted or rejected on its own."""
        body, error = await _json_body(request, "request")
        if error:
            return JSONResponse(
                {"accepted": [], "rejected": [{"event_id": None, "reason": error}]},
                status_code=400,
            )
        if isinstance(body, dict):
            body = [body]
        if not isinstance(body, list):
            reason = "body must be an event object or an array of events"
            rejects.record(kind="request", reason=reason, raw=body)
            return JSONResponse(
                {"accepted": [], "rejected": [{"event_id": None, "reason": reason}]},
                status_code=400,
            )
        return ingestor.ingest(body).response()

    @app.post("/evidence", status_code=201)
    async def post_evidence(request: Request):
        """Store one artifact: {evidence_ref, request, response, flags_snapshot, code_revision}."""
        body, error = await _json_body(request, "artifact")
        if error:
            return JSONResponse({"error": error}, status_code=400)
        try:
            ref = ingestor.put_artifact(body)
        except ArtifactRejected as e:
            return JSONResponse({"error": e.reason}, status_code=409 if e.conflict else 422)
        return {"evidence_ref": ref}

    @app.get("/health")
    def health():
        return {"status": "ok", "store": settings.store, "tenants": list(settings.tenants)}

    return app
