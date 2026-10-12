"""In-process demo backend so the dashboard runs the whole loop with nothing else up.

One `FakeKeewano` plus a `FakeSite` per customer (the dashboard spec's "point at the fakes"
fallback, §5). A customer is seeded with a weakness flag ON so the first **Run** has
something to confirm.

Runs are asynchronous: `start_run` launches the harness on a background thread and returns a
`run_id` immediately; the page polls `run_status(run_id)`, which derives a coarse stage from
the events the harness is emitting and hands back the full `RunReport` once it finishes. One
run per customer at a time. **Fix** is the MVP remediation: Gemini turns the confirmed
scenario's vulnerability flag off (`attack/remediate`), we bump the site revision and re-run
to prove the verdict flips `confirmed -> not_reproduced`. Reads go through the same
`DashboardData` as the live path, pointed at these in-memory fakes.
"""

import re
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from attack.agent import (
    DummyGenerator,
    DummyPlanner,
    GeminiGenerator,
    GeminiPlanner,
    Planner,
    ScenarioGenerator,
)
from attack.catalog import Catalog, FlagDef, load_catalog, load_flags
from attack.catalog.generation import DEFAULT_CATALOG_DIR, GeneratedStore
from attack.clients.fakes import FakeKeewano, FakeSite
from attack.harness.approval import ApprovalQueue
from attack.harness.config import RunBudget, RunConfig
from attack.harness.run import RunReport, run
from attack.remediate import DummyFlagFixer, Fixer, FixRequest, GeminiFlagFixer
from dashboard.data import MEMORY_DIR, DashboardData
from distill.loop import after_run

# Weakness flags seeded ON at startup, standing in for a "bad deploy" (dashboard spec beat 2).
SEED_VULNERABLE: dict[str, dict[str, bool]] = {"customer-a": {"idor_orders": True}}

DEFAULT_OBJECTIVE = "Test recently changed surfaces for regressions"

# Mask obvious credentials before any pasted code reaches Gemini (defence, not a guarantee).
_SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|passwd|token|authorization|bearer)\b(\s*[:=]\s*|\s+)\S+"
)
_MAX_CODE_CHARS = 4000
_MAX_CODE_FILES = 6


class RunOptions(BaseModel):
    objective: str = DEFAULT_OBJECTIVE
    changed_surfaces: list[str] = []
    diff_summary: str = ""
    code_context: dict[str, str] = {}  # path -> source; redacted + capped here
    generate_max: int = Field(default=0, ge=0, le=5)
    offline: bool = False  # force the deterministic planner/generator
    auto_approve: bool = True  # release the human gate so confirmed -> verified immediately
    max_scenarios: int = Field(default=12, ge=1, le=50)
    max_runtime_s: int = Field(default=120, ge=1, le=600)
    max_spend_usd: float = Field(default=1.0, ge=0.0, le=20.0)


class RunBusy(Exception):
    def __init__(self, run_id: str):
        super().__init__(f"a run is already in progress ({run_id})")
        self.run_id = run_id


class RunJob:
    def __init__(self, run_id: str, customer_id: str):
        self.run_id = run_id
        self.customer_id = customer_id
        self.status = "running"  # running | done | error
        self.report: RunReport | None = None
        self.error: str | None = None
        self.started = datetime.now(UTC).isoformat()
        self.distill: dict[str, Any] | None = None  # Dev C: page updates + sharing summary


def _maybe(factory):
    """Construct the real (Gemini) component, or None if it can't (no key / offline)."""
    try:
        return factory()
    except Exception:
        return None


def _redact(code_context: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for path, text in list(code_context.items())[:_MAX_CODE_FILES]:
        masked = _SECRET_RE.sub(r"\1=***REDACTED***", text)[:_MAX_CODE_CHARS]
        out[str(path)[:120]] = masked
    return out


class DemoWorld:
    def __init__(
        self,
        planner: Planner | None = None,
        fixer: Fixer | None = None,
        generator: ScenarioGenerator | None = None,
        memory_dir: Path = MEMORY_DIR,
        catalog_dir: Path = DEFAULT_CATALOG_DIR,
        keewano=None,
        site_factory=None,
    ):
        self._catalog_dir = catalog_dir
        self._memory_dir = memory_dir
        self.catalog: Catalog = load_catalog(catalog_dir)
        self.flags: list[FlagDef] = load_flags()
        # Live mode injects the real Keewano store (HTTP) and real demo sites (HTTP); the
        # default is the in-process fakes so the dashboard still runs with nothing else up.
        self.keewano = keewano or FakeKeewano()
        self._live = keewano is not None
        self.queue = ApprovalQueue(None)  # in-memory; nothing written to disk
        self.generated = GeneratedStore(None)  # in-memory; promotion still writes the catalog
        self._rev: dict[str, int] = {}
        self.sites: dict[str, Any] = {}
        for cid in sorted({f.customer_id for f in self.flags}):
            if site_factory is not None:
                self.sites[cid] = site_factory(cid)
            else:
                self.sites[cid] = FakeSite(
                    cid, self.catalog, self._seed_flags(cid),
                    evidence_sink=self.keewano.store_evidence,
                )
        if self._live:
            # Stand in for a "bad deploy": seed the weakness flag ON on the real site so the
            # first Run has a genuine vulnerability to confirm (best-effort; site may be down).
            for cid, seed in SEED_VULNERABLE.items():
                if cid in self.sites:
                    try:
                        self.sites[cid].set_flags(seed)
                    except Exception:
                        pass

        self._planner_override = planner
        self._generator_override = generator
        self._fixer = fixer or (_maybe(GeminiFlagFixer) or DummyFlagFixer())
        self._gemini_planner = None if planner else _maybe(GeminiPlanner)
        self._gemini_generator = None if generator else _maybe(GeminiGenerator)

        # Async run bookkeeping.
        self._runs: dict[str, RunJob] = {}
        self._active: dict[str, str | None] = {}
        self._registry_lock = threading.Lock()

        self.data = DashboardData(
            events=self.keewano,
            site_factory=lambda cid: self.sites[cid],
            memory_dir=memory_dir,
        )

    def known(self, customer_id: str) -> bool:
        return customer_id in self.sites

    # -- runs (async) --------------------------------------------------------------------

    def start_run(self, customer_id: str, options: RunOptions) -> str:
        with self._registry_lock:
            active = self._active.get(customer_id)
            if active and self._runs[active].status == "running":
                raise RunBusy(active)
            run_id = self._new_run_id()
            job = RunJob(run_id, customer_id)
            self._runs[run_id] = job
            self._active[customer_id] = run_id
        config, planner, generator = self._prepare(customer_id, options)
        threading.Thread(
            target=self._execute, args=(job, config, planner, generator), daemon=True
        ).start()
        return run_id

    def run_sync(self, customer_id: str, options: RunOptions | None = None) -> RunJob:
        """Same run, inline. For fix verification and tests (no thread to await)."""
        options = options or RunOptions()
        run_id = self._new_run_id()
        job = RunJob(run_id, customer_id)
        with self._registry_lock:
            self._runs[run_id] = job
        config, planner, generator = self._prepare(customer_id, options)
        self._execute(job, config, planner, generator)
        return job

    def run_status(self, run_id: str) -> dict[str, Any]:
        job = self._runs.get(run_id)
        if job is None:
            raise KeyError(run_id)
        events = self.keewano.get_slice(job.customer_id, run_id=run_id)
        types = [e["event_type"] for e in events]
        planned = next(
            (
                len((e.get("attrs") or {}).get("steps", []))
                for e in events
                if e["event_type"] == "swarm.plan"
            ),
            None,
        )
        if job.status == "error":
            stage = "error"
        elif job.status == "done":
            stage = "done"
        elif "swarm.plan" in types:
            stage = "probing"
        else:
            stage = "planning"
        out: dict[str, Any] = {
            "run_id": run_id,
            "customer_id": job.customer_id,
            "status": job.status,
            "stage": stage,
            "planned": planned,
            "probed": types.count("swarm.verdict"),
            "started": job.started,
        }
        if job.status in ("done", "error"):
            out["error"] = job.error
            out["report"] = job.report.model_dump(mode="json") if job.report else None
            out["distill"] = job.distill
        return out

    # -- fix -----------------------------------------------------------------------------

    def fix(self, customer_id: str, scenario_id: str) -> dict[str, Any]:
        allowed = self._flags_for_scenario(customer_id, scenario_id)
        if not allowed:
            raise KeyError(f"no vulnerability flag governs {scenario_id} for {customer_id}")
        scenario = self.catalog.get(scenario_id)
        decision = self._fixer.decide(
            FixRequest(
                customer_id=customer_id,
                scenario_id=scenario_id,
                invariant=scenario.invariant if scenario else None,
                allowed_flags=allowed,
            )
        )
        self.sites[customer_id].set_flags({decision.flag: False})
        self._bump_revision(customer_id)
        # Verify deterministically (offline) so the re-run is instant and quota-proof.
        job = self.run_sync(customer_id, RunOptions(offline=True, auto_approve=True))
        report = job.report
        verdict = (
            next((o.verdict.value for o in report.outcomes if o.scenario_id == scenario_id), None)
            if report
            else None
        )
        return {
            "flag": decision.flag,
            "rationale": decision.rationale,
            "run_id": job.run_id,
            "verdict": verdict,
            "fixed": verdict == "not_reproduced",
            "code_revision": self._revision(customer_id),
        }

    def _revision(self, customer_id: str) -> str | None:
        site = self.sites[customer_id]
        rev = getattr(site, "code_revision", None)
        if rev is not None:
            return rev
        try:
            return site.meta().get("code_revision")
        except Exception:
            return None

    # -- flags ---------------------------------------------------------------------------

    def set_flags(self, customer_id: str, flags: dict[str, bool]) -> dict[str, Any]:
        known = {f.flag for f in self.flags if f.customer_id == customer_id}
        updates = {k: bool(v) for k, v in flags.items() if k in known}
        if not updates:
            raise KeyError(f"no known flag for {customer_id} in {sorted(flags)}")
        self.sites[customer_id].set_flags(updates)
        self._bump_revision(customer_id)
        return self.data.flags(customer_id)

    def reset_demo(self, customer_id: str) -> dict[str, Any]:
        # Go through set_flags so it works for both FakeSite and the live HTTP SiteClient.
        self.sites[customer_id].set_flags(self._seed_flags(customer_id))
        self._bump_revision(customer_id)
        return self.data.flags(customer_id)

    # -- generated-scenario review gate --------------------------------------------------

    def generated_scenarios(self, customer_id: str) -> dict[str, Any]:
        rows = [self._gen_row(r) for r in self.generated.records_for(customer_id)]
        return {"generated": rows}

    def promote(self, scenario_id: str) -> dict[str, Any]:
        path = self.generated.promote(scenario_id, self.flags, scenarios_dir=self._catalog_dir)
        self.catalog = load_catalog(self._catalog_dir)  # pick up the newly permanent scenario
        return {"promoted": scenario_id, "path": path.name}

    def reject(self, scenario_id: str) -> dict[str, Any]:
        self.generated.reject(scenario_id)
        return {"rejected": scenario_id}

    # -- approval gate -------------------------------------------------------------------

    def approvals(self, customer_id: str) -> dict[str, Any]:
        pending = [a.model_dump() for a in self.queue.pending() if a.customer_id == customer_id]
        return {"approvals": pending}

    def approve(self, run_id: str, scenario_id: str) -> dict[str, Any]:
        item = self.queue.approve(run_id, scenario_id)
        self._distill(item.customer_id, [])  # promote the finding to verified on the page
        return item.model_dump()

    # -- internals -----------------------------------------------------------------------

    def _prepare(self, customer_id: str, options: RunOptions):
        site = self.sites[customer_id]
        config = RunConfig(
            customer_id=customer_id,
            objective=options.objective or DEFAULT_OBJECTIVE,
            target_allowlist=[site.base_url],
            changed_surfaces=options.changed_surfaces,
            diff_summary=options.diff_summary,
            code_context=_redact(options.code_context),
            generate_max=options.generate_max,
            require_approval=True,
            auto_approve=options.auto_approve,
            budget=RunBudget(
                max_scenarios=options.max_scenarios,
                max_runtime_s=options.max_runtime_s,
                max_spend_usd=options.max_spend_usd,
            ),
        )
        planner = self._pick_planner(options.offline)
        generator = self._pick_generator(options.offline) if options.generate_max > 0 else None
        return config, planner, generator

    def _execute(self, job: RunJob, config: RunConfig, planner, generator) -> None:
        try:
            job.report = run(
                config,
                planner,
                self.sites[job.customer_id],
                self.keewano,
                self.catalog,
                self.queue,
                generator=generator,
                generated_store=self.generated,
                run_id=job.run_id,
                memory_dir=self._memory_dir,
            )
            events = self.keewano.get_slice(job.customer_id, run_id=job.run_id, limit=1000)
            job.distill = self._distill(job.customer_id, events)
            job.status = "done"
        except Exception as e:  # keep a runaway/unexpected failure out of the HTTP thread
            job.error = f"{type(e).__name__}: {e}"[:300]
            job.status = "error"
        finally:
            with self._registry_lock:
                if self._active.get(job.customer_id) == job.run_id:
                    self._active[job.customer_id] = None

    def _distill(self, customer_id: str, events: list[dict[str, Any]]) -> dict[str, Any]:
        """Dev C closes the loop: update customer-X.md, then share per SWARMSHIELD_SHARE_MODE
        (review = wait for a human approve; auto = promote now). Never fails the run."""
        approved = {(a.run_id, a.scenario_id) for a in self.queue.items if a.status == "approved"}
        try:
            return after_run(customer_id, events, approvals=approved, memory_dir=self._memory_dir)
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}"[:300]}

    def _pick_planner(self, offline: bool) -> Planner:
        if self._planner_override is not None:
            return self._planner_override
        if offline:
            return DummyPlanner()
        return self._gemini_planner or DummyPlanner()

    def _pick_generator(self, offline: bool) -> ScenarioGenerator:
        if self._generator_override is not None:
            return self._generator_override
        if offline:
            return DummyGenerator(self.catalog)
        return self._gemini_generator or DummyGenerator(self.catalog)

    def _gen_row(self, record) -> dict[str, Any]:
        s = record.scenario
        return {
            "id": s.id,
            "title": s.title,
            "flag": s.flag,
            "method": s.probe.method,
            "path": s.probe.path,
            "params": s.probe.params,
            "runs": record.runs,
            "last_verdict": record.last_verdict,
            "status": record.status,
            "rationale": (s.provenance or {}).get("rationale"),
        }

    def _seed_flags(self, customer_id: str) -> dict[str, bool]:
        defaults = {f.flag: f.default for f in self.flags if f.customer_id == customer_id}
        return {**defaults, **SEED_VULNERABLE.get(customer_id, {})}

    def _flags_for_scenario(self, customer_id: str, scenario_id: str) -> list[str]:
        return [
            f.flag
            for f in self.flags
            if f.customer_id == customer_id and scenario_id in f.scenario_ids
        ]

    def _bump_revision(self, customer_id: str) -> None:
        # Live HTTP sites bump their own revision on PUT /__flags; only the fakes need this.
        if self._live:
            return
        self._rev[customer_id] = self._rev.get(customer_id, 1) + 1
        self.sites[customer_id].code_revision = f"fake-rev-{self._rev[customer_id]}"

    def _new_run_id(self) -> str:
        return f"run-{uuid.uuid4().hex[:8]}"


__all__ = ["DemoWorld", "RunBusy", "RunJob", "RunOptions"]
