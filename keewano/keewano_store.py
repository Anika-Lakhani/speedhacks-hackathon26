"""Keewano implementation of the store: a stub until M3b.

How events get into Keewano (SDK or REST ingest API) and with which credentials is still
undecided (docs/PLAN-dev-b.md, Open decisions). The Keewano MCP available to us is read-only,
so it is never used for writes; it's only for checking what landed once M3b exists.
Every method raises StoreNotConfigured, so selecting this store fails loudly at startup.
"""

from datetime import datetime

from contracts import Event
from keewano.storage import Artifact, EventStore, StoreNotConfigured

NOT_CONFIGURED = (
    "Keewano store is not configured: the ingestion method (SDK or REST) and credentials "
    "are not decided yet (docs/PLAN-dev-b.md, M3b). Use SWARMSHIELD_STORE=sqlite."
)


class KeewanoStore(EventStore):
    def __init__(self, project_ids: dict[str, str] | None = None):
        # Planned mapping: one Keewano project per tenant (open decision).
        self.project_ids = dict(project_ids or {})

    def _fail(self):
        raise StoreNotConfigured(NOT_CONFIGURED)

    def setup(self, tenants: tuple[str, ...]) -> None:
        self._fail()

    def tenants(self) -> set[str]:
        self._fail()

    def write_event(self, event: Event) -> None:
        self._fail()

    def query_events(
        self,
        customer_id: str,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        event_type: str | None = None,
        run_id: str | None = None,
        limit: int = 500,
    ) -> list[Event]:
        self._fail()

    def put_artifact(self, evidence_ref: str, artifact: Artifact) -> None:
        self._fail()

    def get_artifact(self, customer_id: str, evidence_ref: str) -> Artifact | None:
        self._fail()
