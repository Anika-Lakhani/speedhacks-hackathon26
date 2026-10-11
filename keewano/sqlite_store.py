"""Local SQLite store: one events table and one artifacts table per customer_id.

Table names are derived from customer_id (`customer-a` -> `events_customer_a`). customer_id
is restricted to [a-z0-9-] by the contract and '_' is not allowed in it, so the mapping is
injective and safe to splice into SQL; it's still checked and quoted here.
"""

import re
import sqlite3
import threading
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from contracts import Event
from keewano.storage import (
    Artifact,
    ArtifactExists,
    DuplicateEvent,
    EventStore,
    Position,
    UnknownTenant,
    tenant_of,
)

_CUSTOMER_ID = re.compile(r"^[a-z0-9][a-z0-9-]*$")


def _suffix(customer_id: str) -> str:
    if not _CUSTOMER_ID.match(customer_id):
        raise UnknownTenant(customer_id)
    return customer_id.replace("-", "_")


def _events_table(customer_id: str) -> str:
    return f'"events_{_suffix(customer_id)}"'


def _artifacts_table(customer_id: str) -> str:
    return f'"artifacts_{_suffix(customer_id)}"'


def ts_key(ts: datetime) -> str:
    """Fixed-width UTC string, so lexical order is time order."""
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _now() -> str:
    return ts_key(datetime.now(UTC))


class SQLiteStore(EventStore):
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # One connection per store, serialized by a lock (FastAPI runs sync routes in threads).
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        # WAL + NORMAL: no fsync per commit (durable across app crashes, not power loss).
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._lock = threading.RLock()
        self._tenants: set[str] | None = None

    @contextmanager
    def _db(self):
        with self._lock, self._conn:  # commit on success, roll back on error
            yield self._conn

    def close(self) -> None:
        self._conn.close()

    def setup(self, tenants: tuple[str, ...]) -> None:
        with self._db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS tenants (customer_id TEXT PRIMARY KEY)")
            for cid in tenants:
                ev, art = _events_table(cid), _artifacts_table(cid)
                db.execute(
                    f"""CREATE TABLE IF NOT EXISTS {ev} (
                        seq INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT NOT NULL UNIQUE,
                        ts TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        run_id TEXT,
                        code_revision TEXT NOT NULL,
                        simulated INTEGER NOT NULL,
                        ingested_at TEXT NOT NULL,
                        body TEXT NOT NULL
                    )"""
                )
                for col in ("ts", "event_type", "run_id", "code_revision"):
                    idx = f'"idx_{_suffix(cid)}_{col}"'
                    db.execute(f"CREATE INDEX IF NOT EXISTS {idx} ON {ev} ({col})")
                db.execute(
                    f"""CREATE TABLE IF NOT EXISTS {art} (
                        evidence_ref TEXT PRIMARY KEY,
                        stored_at TEXT NOT NULL,
                        body TEXT NOT NULL
                    )"""
                )
                db.execute("INSERT OR IGNORE INTO tenants VALUES (?)", (cid,))
        self._tenants = None

    def tenants(self) -> set[str]:
        if self._tenants is None:
            with self._db() as db:
                try:
                    self._tenants = {r[0] for r in db.execute("SELECT customer_id FROM tenants")}
                except sqlite3.OperationalError:  # setup() never ran
                    return set()
        return set(self._tenants)

    def _require(self, customer_id: str) -> None:
        if customer_id not in self.tenants():
            raise UnknownTenant(customer_id)

    def write_event(self, event: Event) -> None:
        self._require(event.customer_id)
        try:
            with self._db() as db:
                db.execute(
                    f"""INSERT INTO {_events_table(event.customer_id)}
                        (event_id, ts, event_type, run_id, code_revision, simulated,
                         ingested_at, body)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        event.event_id,
                        ts_key(event.ts),
                        event.event_type,
                        event.run_id,
                        event.code_revision,
                        int(event.simulated),
                        _now(),
                        event.model_dump_json(),
                    ),
                )
        except sqlite3.IntegrityError as e:
            raise DuplicateEvent(event.event_id) from e

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
        rows = self.query_page(
            customer_id,
            since=since,
            until=until,
            event_type=event_type,
            run_id=run_id,
            limit=limit,
        )
        return [e for _, e in rows]

    def query_page(
        self,
        customer_id: str,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        event_type: str | None = None,
        run_id: str | None = None,
        after: Position | None = None,
        start: Position | None = None,
        limit: int = 500,
    ) -> list[tuple[Position, Event]]:
        self._require(customer_id)
        where, params = [], []
        if since is not None:
            where.append("ts >= ?")
            params.append(ts_key(since))
        if until is not None:
            where.append("ts < ?")
            params.append(ts_key(until))
        if event_type is not None:
            where.append("event_type = ?")
            params.append(event_type)
        if run_id is not None:
            where.append("run_id = ?")
            params.append(run_id)
        if after is not None:
            where.append("(ts > ? OR (ts = ? AND seq > ?))")
            params += [after.ts, after.ts, after.seq]
        if start is not None:
            where.append("(ts > ? OR (ts = ? AND seq >= ?))")
            params += [start.ts, start.ts, start.seq]
        sql = f"SELECT ts, seq, body FROM {_events_table(customer_id)}"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY ts, seq LIMIT ?"
        params.append(max(0, limit))
        with self._db() as db:
            return [
                (Position(ts, seq), Event.model_validate_json(body))
                for ts, seq, body in db.execute(sql, params)
            ]

    def first_seen(self, customer_id: str, code_revision: str) -> Position | None:
        self._require(customer_id)
        with self._db() as db:
            row = db.execute(
                f"""SELECT ts, seq FROM {_events_table(customer_id)}
                    WHERE code_revision = ? ORDER BY ts, seq LIMIT 1""",
                (code_revision,),
            ).fetchone()
        return Position(*row) if row else None

    def put_artifact(self, evidence_ref: str, artifact: Artifact) -> None:
        customer_id = tenant_of(evidence_ref)
        self._require(customer_id)
        try:
            with self._db() as db:
                db.execute(
                    f"INSERT INTO {_artifacts_table(customer_id)} VALUES (?, ?, ?)",
                    (evidence_ref, _now(), artifact.model_dump_json()),
                )
        except sqlite3.IntegrityError as e:
            raise ArtifactExists(evidence_ref) from e

    def get_artifact(self, customer_id: str, evidence_ref: str) -> Artifact | None:
        self._require(customer_id)
        try:
            if tenant_of(evidence_ref) != customer_id:
                return None
        except ValueError:
            return None
        with self._db() as db:
            row = db.execute(
                f"SELECT body FROM {_artifacts_table(customer_id)} WHERE evidence_ref = ?",
                (evidence_ref,),
            ).fetchone()
        return Artifact.model_validate_json(row[0]) if row else None


def dump_counts(store: SQLiteStore) -> dict[str, int]:
    """Events per tenant (for the setup script and debugging)."""
    out = {}
    with store._db() as db:
        for cid in sorted(store.tenants()):
            out[cid] = db.execute(f"SELECT COUNT(*) FROM {_events_table(cid)}").fetchone()[0]
    return out
