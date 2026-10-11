"""Read/query API (M3): event slices, since-revision, and artifacts by evidence_ref.

Every route requires exactly one customer_id and reads only that tenant's tables. Event
bodies are plain JSON arrays of contracts.Event (what Dev A's KeewanoClient.get_slice
returns); paging state travels in the X-Next-Cursor / X-Has-More response headers.
"""

from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from contracts import Event
from contracts.events import Timestamp
from keewano.cursor import CursorCodec, InvalidCursor
from keewano.sqlite_store import ts_key
from keewano.storage import Artifact, EventStore, Position, tenant_of

DEFAULT_LIMIT = 500
MAX_LIMIT = 1000
CUSTOMER_ID_PATTERN = r"^[a-z0-9][a-z0-9-]*$"

CustomerId = Annotated[
    str,
    Query(
        min_length=1,
        pattern=CUSTOMER_ID_PATTERN,
        description="Tenant to read. Required; exactly one.",
        examples=["customer-a"],
    ),
]
Limit = Annotated[int, Query(ge=1, le=MAX_LIMIT, description=f"Page size (max {MAX_LIMIT}).")]
Cursor = Annotated[
    str | None,
    Query(description="X-Next-Cursor from the previous page. Send the same other params."),
]

PAGE_HEADERS = {
    "X-Next-Cursor": {
        "description": "Opaque cursor positioned after the last event returned. Absent only "
        "when the page is empty and no cursor was sent. Bound to this customer_id and query.",
        "schema": {"type": "string"},
    },
    "X-Has-More": {
        "description": "`true` if more events matched beyond this page right now.",
        "schema": {"type": "string", "enum": ["true", "false"]},
    },
}
ERRORS = {
    400: {
        "description": "Cursor invalid, tampered, or issued for another tenant or query; "
        "or customer_id given more than once"
    },
    404: {"description": "Unknown customer_id (or revision / evidence not found for it)"},
    422: {"description": "Missing, empty or malformed parameter"},
}


def _error(status: int, detail: str) -> HTTPException:
    return HTTPException(status_code=status, detail=detail)


def build_read_router(store: EventStore, tenants: tuple[str, ...], codec: CursorCodec) -> APIRouter:
    router = APIRouter(tags=["read"])
    known = frozenset(tenants)

    def tenant(request: Request, customer_id: str) -> str:
        if len(request.query_params.getlist("customer_id")) != 1:
            raise _error(400, "customer_id must be given exactly once")
        if customer_id not in known:
            raise _error(404, f"unknown customer_id {customer_id!r}")
        return customer_id

    def page(
        customer_id: str,
        kind: str,
        filters: dict[str, Any],
        cursor: str | None,
        limit: int,
        **query: Any,
    ) -> JSONResponse:
        after = None
        if cursor is not None:
            try:
                after = codec.decode(cursor, customer_id, kind, filters)
            except InvalidCursor as e:
                raise _error(400, str(e)) from e
        rows = store.query_page(customer_id, after=after, limit=limit + 1, **query)
        has_more = len(rows) > limit
        rows = rows[:limit]
        headers = {"X-Has-More": "true" if has_more else "false"}
        last: Position | None = rows[-1][0] if rows else after
        if last is not None:
            headers["X-Next-Cursor"] = codec.encode(customer_id, kind, filters, last)
        body = [e.model_dump(mode="json") for _, e in rows]
        return JSONResponse(body, headers=headers)

    @router.get(
        "/events",
        response_model=list[Event],
        responses={200: {"headers": PAGE_HEADERS}, **ERRORS},
        summary="One tenant's events in a time window (a slice, oldest first)",
    )
    def get_events(
        request: Request,
        customer_id: CustomerId,
        since: Annotated[
            Timestamp | None, Query(description="RFC 3339, inclusive. 'Events since timestamp X'.")
        ] = None,
        until: Annotated[Timestamp | None, Query(description="RFC 3339, exclusive.")] = None,
        event_type: Annotated[str | None, Query(min_length=1)] = None,
        run_id: Annotated[str | None, Query(min_length=1)] = None,
        limit: Limit = DEFAULT_LIMIT,
        cursor: Cursor = None,
    ):
        cid = tenant(request, customer_id)
        filters = {
            "since": ts_key(since) if since else None,
            "until": ts_key(until) if until else None,
            "event_type": event_type,
            "run_id": run_id,
        }
        return page(
            cid,
            "events",
            filters,
            cursor,
            limit,
            since=since,
            until=until,
            event_type=event_type,
            run_id=run_id,
        )

    @router.get(
        "/events/since-revision",
        response_model=list[Event],
        responses={200: {"headers": PAGE_HEADERS}, **ERRORS},
        summary="One tenant's events from the first event at code_revision X onward",
    )
    def get_events_since_revision(
        request: Request,
        customer_id: CustomerId,
        revision: Annotated[str, Query(min_length=1, description="A code_revision value.")],
        event_type: Annotated[str | None, Query(min_length=1)] = None,
        limit: Limit = DEFAULT_LIMIT,
        cursor: Cursor = None,
    ):
        cid = tenant(request, customer_id)
        start = store.first_seen(cid, revision)
        if start is None:
            raise _error(404, f"code_revision {revision!r} not seen for {cid!r}")
        filters = {"revision": revision, "event_type": event_type}
        return page(
            cid, "since-revision", filters, cursor, limit, start=start, event_type=event_type
        )

    @router.get(
        "/evidence/{evidence_ref:path}",
        response_model=Artifact,
        responses=ERRORS,
        summary="The raw request/response artifact behind an evidence_ref",
    )
    def get_evidence(request: Request, evidence_ref: str, customer_id: CustomerId):
        cid = tenant(request, customer_id)
        try:
            tenant_of(evidence_ref)
        except ValueError as e:
            raise _error(422, str(e)) from e
        artifact = store.get_artifact(cid, evidence_ref)
        if artifact is None:  # missing, or the ref names another tenant: same answer
            raise _error(404, "evidence not found for this customer_id")
        return artifact

    return router
