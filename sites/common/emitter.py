"""Fail-safe event emitter shared by the demo sites.

`emit()` validates the event against the contract and puts it on a bounded queue; it never
blocks and never raises into the request. A background thread posts batches to the store's
POST /events. If the store is down, rejects an event, or the queue is full, the event is
written to a local JSONL fallback log instead and the site carries on.
"""

import json
import logging
import queue
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from contracts import Event, EventValidationError, validate_event

_log = logging.getLogger("swarmshield.sites.emitter")

# Takes a list of JSON-ready events, returns the store's {"accepted", "rejected"} body.
Sender = Callable[[list[dict[str, Any]]], dict[str, Any]]


def http_sender(store_url: str, timeout: float = 2.0) -> Sender:
    import httpx

    client = httpx.Client(base_url=store_url.rstrip("/"), timeout=timeout)

    def send(batch: list[dict[str, Any]]) -> dict[str, Any]:
        r = client.post("/events", json=batch)
        r.raise_for_status()
        return r.json()

    return send


class EventEmitter:
    def __init__(
        self,
        sender: Sender,
        fallback_path: Path | str,
        *,
        max_queue: int = 1000,
        max_batch: int = 100,
    ):
        self._send = sender
        self.fallback_path = Path(fallback_path)
        self.fallback_path.parent.mkdir(parents=True, exist_ok=True)
        self._queue: queue.Queue[Event | None] = queue.Queue(maxsize=max_queue)
        self._max_batch = max_batch
        self._file_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._start_lock = threading.Lock()

    # --- request side: never blocks, never raises -----------------------------------------

    def emit(self, **fields: Any) -> Event | None:
        try:
            event = validate_event(fields)
        except EventValidationError as e:
            self._fallback("invalid", e.reason, fields)
            return None
        try:
            self._ensure_started()
            self._queue.put_nowait(event)
        except queue.Full:
            self._fallback("queue_full", "emit queue full; event dropped", event)
        except Exception as e:  # pragma: no cover - defensive: never break the request
            self._fallback("emit_error", repr(e), event)
        return event

    # --- background side -------------------------------------------------------------------

    def _ensure_started(self) -> None:
        if self._thread is None:
            with self._start_lock:
                if self._thread is None:
                    self._thread = threading.Thread(
                        target=self._run, name="event-emitter", daemon=True
                    )
                    self._thread.start()

    def _run(self) -> None:
        while True:
            first = self._queue.get()
            if first is None:
                self._queue.task_done()
                return
            batch = [first]
            while len(batch) < self._max_batch:
                try:
                    nxt = self._queue.get_nowait()
                except queue.Empty:
                    break
                if nxt is None:  # shutdown marker: send what we have, then stop
                    self._deliver(batch)
                    self._queue.task_done()
                    for _ in batch:
                        self._queue.task_done()
                    return
                batch.append(nxt)
            self._deliver(batch)
            for _ in batch:
                self._queue.task_done()

    def _deliver(self, batch: list[Event]) -> None:
        payload = [e.model_dump(mode="json") for e in batch]
        try:
            result = self._send(payload)
        except Exception as e:
            _log.warning("store unreachable (%s); %d event(s) logged locally", e, len(batch))
            for event in batch:
                self._fallback("store_unreachable", repr(e), event)
            return
        rejected = {r.get("event_id"): r.get("reason") for r in result.get("rejected", [])}
        for event in batch:
            if event.event_id in rejected:
                self._fallback("store_rejected", rejected[event.event_id], event)

    def _fallback(self, kind: str, reason: str, event: Event | dict[str, Any]) -> None:
        body = event.model_dump(mode="json") if isinstance(event, Event) else event
        line = json.dumps(
            {
                "logged_at": datetime.now(UTC).isoformat(),
                "kind": kind,
                "reason": reason,
                "event": body,
            },
            default=str,
        )
        try:
            with self._file_lock, self.fallback_path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:  # pragma: no cover - last resort
            _log.error("could not write emit fallback log: %s", line)

    def read_fallback(self) -> list[dict[str, Any]]:
        if not self.fallback_path.exists():
            return []
        with self.fallback_path.open(encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    # --- lifecycle -------------------------------------------------------------------------

    def flush(self, timeout: float = 5.0) -> bool:
        """Wait until everything queued so far has been delivered or logged. True if drained."""
        if self._thread is None:
            return True
        done = threading.Event()

        def wait():
            self._queue.join()
            done.set()

        threading.Thread(target=wait, daemon=True).start()
        return done.wait(timeout)

    def shutdown(self, timeout: float = 5.0) -> None:
        """Deliver what's queued, then stop the thread."""
        if self._thread is None:
            return
        try:
            self._queue.put(None, timeout=timeout)
        except queue.Full:
            _log.warning("emitter shutdown: queue full, some events stay undelivered")
            return
        self._thread.join(timeout)
