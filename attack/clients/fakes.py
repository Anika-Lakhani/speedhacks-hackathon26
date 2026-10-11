"""Fixture-backed stand-ins so A builds and tests before B is live (spec §7)."""

import json
import re
from collections.abc import Callable
from typing import Any

from attack.catalog import Catalog
from attack.catalog.fixtures import OTHER_USER
from attack.clients.site import SiteResponse
from contracts import Event, make_evidence_ref, new_event_id

PROBE_HEADER = "X-SwarmShield-Probe"
RUN_HEADER = "X-SwarmShield-Run"
EVIDENCE_HEADER = "X-SwarmShield-Evidence"


class FakeSite:
    """Honors a flag dict. Routes and their vulnerable/secure responses come from the
    *curated* scenarios only, keyed by endpoint, so a generated scenario that hits a real
    route is judged against the route's actual response, not an echo of its own guess."""

    def __init__(
        self,
        customer_id: str,
        catalog: Catalog,
        flags: dict[str, bool] | None = None,
        code_revision: str = "fake-rev-1",
        base_url: str | None = None,
        evidence_sink: Callable[[str, dict[str, Any]], None] | None = None,
    ):
        self.customer_id = customer_id
        self.base_url = base_url or f"http://fake-site/{customer_id}"
        self.code_revision = code_revision
        self.flags = dict(flags or {})
        self.signal_override: dict[str, bool] = {}  # scenario_id -> force vulnerable signal
        self.evidence_sink = evidence_sink
        self._routes = [
            (re.compile("^" + re.sub(r"\\\{\w+\\\}", "[^/]+", re.escape(s.probe.path)) + "$"), s)
            for s in sorted(catalog.values(), key=lambda x: x.id)
            if s.customer_id == customer_id and s.origin == "curated"
        ]
        self.calls: list[tuple[str, str]] = []

    def meta(self) -> dict[str, Any]:
        return {
            "customer_id": self.customer_id,
            "code_revision": self.code_revision,
            "flags": dict(self.flags),
        }

    def set_flags(self, flags: dict[str, bool]) -> dict[str, Any]:
        self.flags.update(flags)
        return self.meta()

    def probe(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        query: dict[str, str] | None = None,
        json: dict[str, str] | None = None,
    ) -> SiteResponse:
        self.calls.append((method, path))
        marker = headers.get(PROBE_HEADER)
        route = next((s for rx, s in self._routes if rx.match(path)), None)
        if not marker or route is None:
            return SiteResponse(status=404, body={"error": "not_found"})
        if route.probe.method != method:
            return SiteResponse(status=405, body={"error": "method_not_allowed"})
        scenario, sig = route, route.expected_signal
        vulnerable = self.signal_override.get(marker, self.flags.get(scenario.flag, False))
        if vulnerable:
            status = sig.status or 200
            body: dict[str, Any] = {"simulated": True, "echo": list(sig.body_contains)}
            if sig.owner_is_other:
                body["owner_user_id"] = OTHER_USER
            resp_headers: dict[str, str] = {}
        else:
            status = 429 if "login" in scenario.probe.path else 403
            body = {"error": "denied"}
            resp_headers = {name: "1" for name in sig.header_absent}
        evidence_ref = make_evidence_ref(self.customer_id, headers.get(RUN_HEADER), new_event_id())
        resp_headers[EVIDENCE_HEADER] = evidence_ref
        response = SiteResponse(status=status, headers=resp_headers, body=body)
        if self.evidence_sink:
            self.evidence_sink(
                evidence_ref,
                {
                    "request": {
                        "method": method,
                        "path": path,
                        "headers": headers,
                        "query": query,
                        "json": json,
                    },
                    "response": response.model_dump(),
                    "flags_snapshot": dict(self.flags),
                    "code_revision": self.code_revision,
                },
            )
        return response


class FakeKeewano:
    """In-memory event store with the slice and evidence reads."""

    def __init__(self) -> None:
        self.events: list[Event] = []
        self.evidence: dict[str, dict[str, Any]] = {}

    def post_events(self, events: list[Event]) -> dict[str, Any]:
        # Round-trip through JSON so anything unserialisable fails like the real API would.
        for e in events:
            json.dumps(e.model_dump(mode="json"))
        self.events.extend(events)
        return {"accepted": [e.event_id for e in events], "rejected": []}

    def get_slice(
        self,
        customer_id: str,
        since: str | None = None,
        event_type: str | None = None,
        run_id: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        out = [e for e in self.events if e.customer_id == customer_id]
        if since:
            out = [e for e in out if e.ts.isoformat() >= since]
        if event_type:
            out = [e for e in out if e.event_type == event_type]
        if run_id:
            out = [e for e in out if e.run_id == run_id]
        return [e.model_dump(mode="json") for e in out[:limit]]

    def store_evidence(self, ref: str, record: dict[str, Any]) -> None:
        self.evidence[ref] = record

    def get_evidence(self, evidence_ref: str) -> dict[str, Any]:
        return self.evidence[evidence_ref]
