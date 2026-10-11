"""Reads event windows from Dev B's event store (`docs/read-api.md`), following cursors.

Incremental distilling resumes from the page's own `last_distilled` time rather than a saved
cursor: `since` is inclusive, so the boundary event comes back again, and the analyzer's merge
makes that a no-op. This keeps no state outside the page and survives a store restart (cursors
expire when the store's secret changes).
"""

import httpx

PAGE_SIZE = 1000  # the store's maximum


class WindowTooLarge(RuntimeError):
    pass


class EventSource:
    def __init__(
        self,
        base_url: str = "http://localhost:4000",
        client: httpx.Client | None = None,
        timeout: float = 5.0,
    ):
        self._http = client or httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout)

    def window(
        self,
        customer_id: str,
        *,
        since: str | None = None,
        revision: str | None = None,
        max_events: int = 20_000,
    ) -> list[dict]:
        """All of one tenant's events since a time, or since a code revision first appeared."""
        if revision:
            path = "/events/since-revision"
            params = {"customer_id": customer_id, "revision": revision}
        else:
            path = "/events"
            params = {"customer_id": customer_id, **({"since": since} if since else {})}
        params["limit"] = PAGE_SIZE
        events: list[dict] = []
        cursor = None
        while True:
            r = self._http.get(path, params=params | ({"cursor": cursor} if cursor else {}))
            r.raise_for_status()
            page = r.json()
            events.extend(page)
            if not page or r.headers.get("X-Has-More", "false") != "true":
                return events
            if len(events) >= max_events:
                raise WindowTooLarge(f"more than {max_events} events; narrow it with --since")
            cursor = r.headers["X-Next-Cursor"]
