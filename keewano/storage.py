"""Storage adapter interface. Every implementation is tenant-scoped by construction:
each call names exactly one customer_id, and nothing returns rows for more than one.

Implementations: `SQLiteStore` (dev and tests), `KeewanoStore` (stub until M3b).
Pick one with `make_store(settings)`; callers never import an implementation directly.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from contracts import Event, parse_evidence_ref
from keewano.config import Settings


class StoreError(Exception):
    """Base class for store errors."""


class StoreNotConfigured(StoreError):
    """The selected implementation can't be used yet (e.g. Keewano before M3b)."""


class UnknownTenant(StoreError):
    def __init__(self, customer_id: str):
        super().__init__(f"unknown customer_id {customer_id!r}")
        self.customer_id = customer_id


class DuplicateEvent(StoreError):
    def __init__(self, event_id: str):
        super().__init__(f"duplicate event_id {event_id!r}")
        self.event_id = event_id


class ArtifactExists(StoreError):
    def __init__(self, evidence_ref: str):
        super().__init__(f"artifact already stored for {evidence_ref!r}; evidence is immutable")
        self.evidence_ref = evidence_ref


class Artifact(BaseModel):
    """Full request/response record behind an evidence_ref (dev-B §4a.5)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request: dict[str, Any]
    response: dict[str, Any]
    flags_snapshot: dict[str, bool] = {}
    code_revision: str


def tenant_of(evidence_ref: str) -> str:
    """customer_id named by an evidence_ref (raises ValueError if malformed)."""
    return parse_evidence_ref(evidence_ref)[0]


class EventStore(ABC):
    """Per-tenant event and artifact storage."""

    @abstractmethod
    def setup(self, tenants: tuple[str, ...]) -> None:
        """Create per-tenant storage for each tenant. Idempotent."""

    @abstractmethod
    def tenants(self) -> set[str]:
        """customer_ids this store has been set up for."""

    @abstractmethod
    def write_event(self, event: Event) -> None:
        """Store one validated event in its tenant. Raises UnknownTenant, DuplicateEvent."""

    @abstractmethod
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
        """One tenant's events, ordered by (ts, ingest order). since inclusive, until exclusive."""

    @abstractmethod
    def put_artifact(self, evidence_ref: str, artifact: Artifact) -> None:
        """Store an artifact under its evidence_ref's tenant.

        Raises UnknownTenant, or ArtifactExists (evidence is immutable)."""

    @abstractmethod
    def get_artifact(self, customer_id: str, evidence_ref: str) -> Artifact | None:
        """The artifact, or None if missing or if the ref names another tenant."""


def make_store(settings: Settings) -> EventStore:
    if settings.store == "sqlite":
        from keewano.sqlite_store import SQLiteStore

        return SQLiteStore(settings.sqlite_path)
    if settings.store == "keewano":
        from keewano.keewano_store import KeewanoStore

        return KeewanoStore(settings.keewano_project_ids)
    raise StoreNotConfigured(
        f"unknown SWARMSHIELD_STORE {settings.store!r}; expected 'sqlite' or 'keewano'"
    )
