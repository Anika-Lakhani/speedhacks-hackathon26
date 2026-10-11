"""Read-only data layer for the dashboard.

Every panel goes through `DashboardData`, which talks to the same clients the attack harness
uses (`SiteClient`, `KeewanoClient`) and reads Dev C's Markdown from `memory/`. When a
backend isn't up yet (Dev B's store and sites, Dev C's pages) the panel degrades to a
placeholder with `source: "placeholder"` instead of failing; once it is up, the same call
returns `source: "live"`. Nothing here needs changing when B and C ship.
"""

import os
from collections import defaultdict
from pathlib import Path
from typing import Any, Protocol

from attack.catalog.flags import DEFAULT_FLAGS_PATH, FlagDef, load_flags
from attack.clients.keewano import KeewanoClient
from attack.clients.site import SiteClient

ROOT = Path(__file__).resolve().parents[1]
MEMORY_DIR = ROOT / "memory"

SITE_PORTS = {"customer-a": 3001, "customer-b": 3002, "customer-c": 3003}
APP_TYPES = {
    "customer-a": "E-commerce",
    "customer-b": "SaaS dashboard",
    "customer-c": "Content / CMS",
}


class EventSource(Protocol):
    def get_slice(
        self,
        customer_id: str,
        since: str | None = None,
        event_type: str | None = None,
        run_id: str | None = None,
        limit: int = 500,
    ) -> Any: ...


class SiteLike(Protocol):
    def meta(self) -> dict[str, Any]: ...


def _site_url(customer_id: str) -> str:
    env = os.environ.get(f"DASHBOARD_SITE_URL_{customer_id.upper().replace('-', '_')}")
    return env or f"http://localhost:{SITE_PORTS.get(customer_id, 3000)}"


class DashboardData:
    def __init__(
        self,
        events: EventSource | None = None,
        site_factory=None,
        memory_dir: Path = MEMORY_DIR,
        flags_path: Path = DEFAULT_FLAGS_PATH,
    ):
        self._events = events or KeewanoClient(
            os.environ.get("DASHBOARD_KEEWANO_URL", "http://localhost:4000"), timeout=1.5
        )
        self._site_factory = site_factory or (lambda cid: SiteClient(_site_url(cid), timeout=1.5))
        self._memory_dir = memory_dir
        self._registry: list[FlagDef] = load_flags(flags_path)

    # -- customers ---------------------------------------------------------------------

    def customer_ids(self) -> list[str]:
        return sorted({f.customer_id for f in self._registry} | set(SITE_PORTS))

    def known(self, customer_id: str) -> bool:
        return customer_id in self.customer_ids()

    def customers(self) -> list[dict[str, Any]]:
        out = []
        for cid in self.customer_ids():
            meta = self.meta(cid)
            out.append({"customer_id": cid, "app_type": APP_TYPES.get(cid), **meta})
        return out

    def meta(self, customer_id: str) -> dict[str, Any]:
        """Site header: revision and flag state, or a placeholder while the site is down."""
        try:
            m = self._site_factory(customer_id).meta()
            return {
                "source": "live",
                "site_up": True,
                "code_revision": m.get("code_revision"),
                "flags": m.get("flags", {}),
            }
        except Exception:
            return {"source": "placeholder", "site_up": False, "code_revision": None, "flags": {}}

    # -- flags -------------------------------------------------------------------------

    def flags(self, customer_id: str) -> dict[str, Any]:
        meta = self.meta(customer_id)
        live = meta["flags"]
        rows = [
            {
                "flag": f.flag,
                "on": live.get(f.flag, f.default),
                "default": f.default,
                "endpoints": f.endpoints,
                "scenario_ids": f.scenario_ids,
            }
            for f in self._registry
            if f.customer_id == customer_id
        ]
        return {"source": meta["source"], "code_revision": meta["code_revision"], "flags": rows}

    # -- events: runs and vulnerabilities ----------------------------------------------

    def _swarm_events(self, customer_id: str) -> tuple[str, list[dict[str, Any]], str | None]:
        try:
            raw = self._events.get_slice(customer_id, limit=500)
        except Exception as e:  # store not up yet (Dev B M3)
            return "placeholder", [], f"event store unavailable ({type(e).__name__})"
        rows = raw.get("events", []) if isinstance(raw, dict) else raw
        swarm = [e for e in rows if str(e.get("event_type", "")).startswith("swarm.")]
        # Defence in depth on top of the store's own isolation: never show another tenant.
        swarm = [e for e in swarm if e.get("customer_id") == customer_id]
        return "live", sorted(swarm, key=lambda e: e["ts"]), None

    def runs(self, customer_id: str) -> dict[str, Any]:
        source, events, note = self._swarm_events(customer_id)
        by_run: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for e in events:
            if e.get("run_id"):
                by_run[e["run_id"]].append(e)
        runs = []
        for run_id, evs in by_run.items():
            counts: dict[str, int] = defaultdict(int)
            verdicts = []
            for e in evs:
                if e["event_type"] == "swarm.verdict":
                    counts[e["verdict"]] += 1
                    verdicts.append(
                        {
                            "scenario_id": e["scenario_id"],
                            "verdict": e["verdict"],
                            "evidence_ref": e.get("evidence_ref"),
                            "confidence": (e.get("attrs") or {}).get("confidence"),
                        }
                    )
            ended = any(e["event_type"] == "swarm.run_end" for e in evs)
            runs.append(
                {
                    "run_id": run_id,
                    "started": evs[0]["ts"],
                    "status": "complete" if ended else "running",
                    "code_revision": evs[0].get("code_revision"),
                    "knowledge_version": evs[0].get("knowledge_version"),
                    "verdict_counts": dict(counts),
                    "verdicts": verdicts,
                }
            )
        runs.sort(key=lambda r: r["started"], reverse=True)
        return {"source": source, "note": note, "runs": runs}

    def vulnerabilities(self, customer_id: str) -> dict[str, Any]:
        """Latest confirmed verdict per scenario that hasn't been superseded by a later one."""
        source, events, note = self._swarm_events(customer_id)
        flag_for = {s: f.flag for f in self._registry for s in f.scenario_ids}
        latest: dict[str, dict[str, Any]] = {}
        for e in events:
            if e["event_type"] == "swarm.verdict":
                latest[e["scenario_id"]] = e
        vulns = [
            {
                "scenario_id": sid,
                "flag": flag_for.get(sid),
                "run_id": e["run_id"],
                "ts": e["ts"],
                "invariant": (e.get("attrs") or {}).get("invariant"),
                "severity": (e.get("attrs") or {}).get("severity"),
                "evidence_ref": e.get("evidence_ref"),
            }
            for sid, e in latest.items()
            if e["verdict"] == "confirmed"
        ]
        return {"source": source, "note": note, "vulnerabilities": vulns}

    # -- memory (Dev C) ----------------------------------------------------------------

    def _read_md(self, path: Path, title: str) -> dict[str, Any]:
        if path.is_file():
            return {
                "source": "live",
                "path": path.name,
                "markdown": path.read_text(),
            }
        return {
            "source": "placeholder",
            "path": None,
            "markdown": f"# {title}\n\n_Not written yet. Dev C's pipeline will create it._\n",
        }

    def memory(self, customer_id: str) -> dict[str, Any]:
        return self._read_md(self._memory_dir / "customers" / f"{customer_id}.md", customer_id)

    def shared(self) -> dict[str, Any]:
        return self._read_md(self._memory_dir / "shared-intelligence.md", "Shared intelligence")
