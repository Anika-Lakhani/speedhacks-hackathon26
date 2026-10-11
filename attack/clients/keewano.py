from typing import Any, Protocol

import httpx

from contracts import Event


class Keewano(Protocol):
    def post_events(self, events: list[Event]) -> dict[str, Any]: ...

    def get_slice(
        self,
        customer_id: str,
        since: str | None = None,
        event_type: str | None = None,
        run_id: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]: ...

    def get_evidence(self, evidence_ref: str) -> dict[str, Any]: ...


class KeewanoClient:
    """Thin httpx wrapper over the Keewano API (dev-B §4a.6)."""

    def __init__(self, base_url: str = "http://localhost:4000", timeout: float = 5.0):
        self._http = httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout)

    def post_events(self, events: list[Event]) -> dict[str, Any]:
        # Event(**dump) re-validates, so a malformed event never leaves this process.
        payload = [
            Event.model_validate(e.model_dump(mode="json")).model_dump(mode="json") for e in events
        ]
        r = self._http.post("/events", json=payload)
        r.raise_for_status()
        return r.json()

    def get_slice(
        self,
        customer_id: str,
        since: str | None = None,
        event_type: str | None = None,
        run_id: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        params = {
            "customer_id": customer_id,
            "since": since,
            "event_type": event_type,
            "run_id": run_id,
            "limit": limit,
        }
        r = self._http.get("/events", params={k: v for k, v in params.items() if v is not None})
        r.raise_for_status()
        return r.json()

    def get_evidence(self, evidence_ref: str) -> dict[str, Any]:
        r = self._http.get(f"/evidence/{evidence_ref}")
        r.raise_for_status()
        return r.json()
