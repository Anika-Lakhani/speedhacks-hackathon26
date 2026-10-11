"""Rejects log: every event or artifact the store refused, one JSON object per line.

This is an operator file, not an API: it can hold payloads for unknown or missing tenants,
so exposing it over HTTP would cross customer_id. Inspect it with:

    uv run python -m keewano.rejects            # last 20 entries
    uv run python -m keewano.rejects --all
"""

import json
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MAX_RAW_CHARS = 8192  # keep the log bounded; enough to debug a malformed event


def _clip(raw: Any) -> Any:
    try:
        text = raw if isinstance(raw, str) else json.dumps(raw, default=str)
    except (TypeError, ValueError):
        text = repr(raw)
    if len(text) <= MAX_RAW_CHARS:
        return raw if not isinstance(raw, bytes) else text
    return text[:MAX_RAW_CHARS] + "...[truncated]"


class RejectsLog:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def record(
        self,
        *,
        kind: str,
        reason: str,
        raw: Any,
        event_id: str | None = None,
        customer_id: str | None = None,
        index: int | None = None,
    ) -> dict[str, Any]:
        entry = {
            "logged_at": datetime.now(UTC).isoformat(),
            "kind": kind,  # "event" | "artifact" | "request"
            "reason": reason,
            "event_id": event_id,
            "customer_id": customer_id,
            "index": index,
            "raw": _clip(raw),
        }
        line = json.dumps(entry, default=str)
        with self._lock, self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
        return entry

    def read(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]


def main(argv: list[str]) -> None:
    from keewano.config import load_settings

    entries = RejectsLog(load_settings().rejects_path).read()
    for e in entries if "--all" in argv else entries[-20:]:
        print(json.dumps(e))
    print(f"{len(entries)} rejected item(s) in total", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1:])
