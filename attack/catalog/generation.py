"""Code-side gate for LLM-drafted scenarios.

Gemini returns `ScenarioDraft`s (data). Nothing it says is trusted: every field is checked
here, the ID is assigned here, and anything that fails is rejected with a reason. A draft
that passes becomes an ordinary `Scenario` with `origin="generated"`, run by the same
deterministic engine and verifier as the hand-written ones.
"""

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from attack.catalog import fixtures
from attack.catalog.flags import FlagDef
from attack.catalog.loader import (
    DEFAULT_CATALOG_DIR,
    Catalog,
    load_catalog,
    normalise_path,
    validate_catalog,
)
from attack.catalog.models import PATH_PARAM, ExpectedSignal, Probe, Scenario, Severity

GENERATED_PREFIX = "SCN-GEN-"
DEFAULT_STORE_PATH = Path(".data") / "swarmshield" / "generated.json"

ALLOWED_METHODS = {"GET", "POST"}
MAX_VALUE_LEN = 200
PATH_ID_RE = re.compile(r"^[A-Za-z0-9_\-]{1,40}$")
VALUE_RULES = (
    "Parameter values are strings of at most 200 printable characters (no newlines). Use "
    "`fixture:<name>` (names are listed) for synthetic objects such as other users' order or "
    "account IDs. Path placeholder values must be a fixture or a plain ID of letters, digits, "
    "_ and -. Realistic test inputs are fine: the target is a simulated site."
)
PATH_RE = re.compile(r"^/[A-Za-z0-9_\-./{}]{0,99}$")
PARAM_KEY_RE = re.compile(r"^[a-z_][a-z0-9_]{0,30}$")
HEADER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,40}$")
CLASS_RE = re.compile(r"^[a-z0-9_]{2,40}$")


class DraftParam(BaseModel):
    """A list of pairs, not a dict: Gemini's schema drops free-form map value types and
    would emit `{}`."""

    model_config = ConfigDict(extra="forbid")

    name: str
    value: str


class DraftProbe(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: str
    path: str
    params: list[DraftParam] = []


class DraftSignal(BaseModel):
    """What a VULNERABLE response looks like, as inferred from code, events and memory."""

    model_config = ConfigDict(extra="forbid")

    status: int = Field(ge=100, le=599)
    body_contains: list[str] = []
    header_absent: list[str] = []
    owner_is_other: bool = False


class ScenarioDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str
    weakness_class: str
    invariant: str
    flag: str
    preconditions: list[str] = []
    probe: DraftProbe
    expected_signal: DraftSignal
    severity: Severity
    rationale: str


class GenerationOutput(BaseModel):
    """The only shape the model is allowed to return."""

    model_config = ConfigDict(extra="forbid")

    drafts: list[ScenarioDraft]


class Rejection(BaseModel):
    title: str
    reason: str


class ValidationResult(BaseModel):
    accepted: list[Scenario] = []
    rejected: list[Rejection] = []


def _dedupe_key(flag: str, method: str, path: str, params: dict[str, str]):
    return (flag, method.upper(), normalise_path(path), tuple(sorted(params.items())))


def next_gen_number(existing_ids: set[str]) -> int:
    nums = [int(i[len(GENERATED_PREFIX) :]) for i in existing_ids if i.startswith(GENERATED_PREFIX)]
    return max(nums, default=0) + 1


def _check_value(value: str) -> str | None:
    if value.startswith(fixtures.PREFIX):
        try:
            fixtures.resolve(value)
        except fixtures.FixtureError:
            return f"unknown fixture {value!r}"
        return None
    if len(value) > MAX_VALUE_LEN:
        return f"param value longer than {MAX_VALUE_LEN} characters"
    if not value.isprintable():
        return "param value has control characters or newlines"
    return None


def _params(draft: ScenarioDraft) -> dict[str, str] | None:
    names = [p.name for p in draft.probe.params]
    if len(set(names)) != len(names):
        return None
    return {p.name: p.value for p in draft.probe.params}


def _check_draft(draft: ScenarioDraft, flag_def: FlagDef | None, seen: set) -> str | None:
    params = _params(draft)
    if params is None:
        return "duplicate param name"
    if flag_def is None:
        return f"flag {draft.flag!r} is not in the registry for this customer"
    p = draft.probe
    if p.method.upper() not in ALLOWED_METHODS:
        return f"method {p.method!r} not allowed (GET/POST only)"
    if not PATH_RE.match(p.path) or ".." in p.path:
        return "path has disallowed characters"
    covered = {normalise_path(e) for e in flag_def.endpoints}
    if normalise_path(p.path) not in covered:
        return f"path {p.path!r} is not an endpoint of flag {draft.flag!r}"
    placeholders = set(PATH_PARAM.findall(p.path))
    if placeholders - set(params):
        return "path placeholder without a value in params"
    if len(params) > 6:
        return "too many params"
    for key, value in params.items():
        if not PARAM_KEY_RE.match(key):
            return f"bad param name {key!r}"
        if (
            key in placeholders
            and not value.startswith(fixtures.PREFIX)
            and not PATH_ID_RE.match(value)
        ):
            return f"path param {key!r} must be a fixture or a plain ID"
        if (reason := _check_value(value)) is not None:
            return reason
    sig = draft.expected_signal
    if len(sig.body_contains) > 5 or any(not 1 <= len(s) <= 64 for s in sig.body_contains):
        return "body_contains must be at most 5 strings of 1-64 characters"
    if len(sig.header_absent) > 3 or any(not HEADER_RE.match(h) for h in sig.header_absent):
        return "bad header_absent"
    if not CLASS_RE.match(draft.weakness_class):
        return "weakness_class must be snake_case"
    if not (1 <= len(draft.title) <= 120 and 1 <= len(draft.invariant) <= 200):
        return "title/invariant length out of range"
    key = _dedupe_key(draft.flag, p.method, p.path, params)
    if key in seen:
        return "duplicate of an existing or already-accepted scenario"
    return None


def validate_drafts(
    drafts: list[ScenarioDraft],
    customer_id: str,
    flags: list[FlagDef],
    existing: list[Scenario],
    *,
    max_new: int,
    model: str | None = None,
    prompt_version: str | None = None,
    run_id: str | None = None,
) -> ValidationResult:
    by_flag = {f.flag: f for f in flags if f.customer_id == customer_id}
    seen = {_dedupe_key(s.flag, s.probe.method, s.probe.path, s.probe.params) for s in existing}
    number = next_gen_number({s.id for s in existing})
    out = ValidationResult()
    for draft in drafts:
        if len(out.accepted) >= max_new:
            out.rejected.append(Rejection(title=draft.title, reason="over max_new"))
            continue
        reason = _check_draft(draft, by_flag.get(draft.flag), seen)
        if reason is None and number > 999:
            reason = "generated id space exhausted"
        if reason is not None:
            out.rejected.append(Rejection(title=draft.title, reason=reason))
            continue
        scenario = Scenario(
            id=f"{GENERATED_PREFIX}{number:03d}",
            title=draft.title,
            customer_id=customer_id,
            weakness_class=draft.weakness_class,
            invariant=draft.invariant,
            flag=draft.flag,
            preconditions=[c[:80] for c in draft.preconditions[:5]],
            probe=Probe(
                kind="benign_request",
                method=draft.probe.method.upper(),
                path=draft.probe.path,
                params=_params(draft),
            ),
            expected_signal=ExpectedSignal(**draft.expected_signal.model_dump()),
            severity=draft.severity,
            origin="generated",
            provenance={
                "model": model,
                "prompt_version": prompt_version,
                "run_id": run_id,
                "rationale": draft.rationale[:600],  # models are verbose; keep the gist
                "generated_at": datetime.now(UTC).isoformat(),
            },
        )
        number += 1
        seen.add(
            _dedupe_key(
                scenario.flag, scenario.probe.method, scenario.probe.path, scenario.probe.params
            )
        )
        out.accepted.append(scenario)
    return out


# --- persistence and the promotion gate -------------------------------------------------


class GeneratedRecord(BaseModel):
    scenario: Scenario
    status: Literal["pending", "promoted", "rejected"] = "pending"
    runs: int = 0
    last_verdict: str | None = None


class PromotionError(Exception):
    pass


class GeneratedStore:
    """Where generated scenarios live until a human promotes or rejects them."""

    def __init__(self, path: Path | None = DEFAULT_STORE_PATH):
        self.path = path
        self.records: dict[str, GeneratedRecord] = {}
        if path and path.exists():
            for row in json.loads(path.read_text()):
                rec = GeneratedRecord(**row)
                self.records[rec.scenario.id] = rec

    def _save(self) -> None:
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            rows = [r.model_dump(mode="json") for r in self.records.values()]
            self.path.write_text(json.dumps(rows, indent=2))

    def ids(self) -> set[str]:
        return set(self.records)

    def add(self, scenarios: list[Scenario]) -> None:
        for s in scenarios:
            self.records[s.id] = GeneratedRecord(scenario=s)
        self._save()

    def records_for(self, customer_id: str | None = None, status: str | None = None):
        return [
            r
            for r in self.records.values()
            if (customer_id is None or r.scenario.customer_id == customer_id)
            and (status is None or r.status == status)
        ]

    def pending_scenarios(self, customer_id: str | None = None) -> Catalog:
        return {r.scenario.id: r.scenario for r in self.records_for(customer_id, "pending")}

    def record_verdict(self, scenario_id: str, verdict: str) -> None:
        rec = self.records.get(scenario_id)
        if rec:
            rec.runs += 1
            rec.last_verdict = verdict
            self._save()

    def reject(self, scenario_id: str) -> GeneratedRecord:
        rec = self._get(scenario_id)
        rec.status = "rejected"
        self._save()
        return rec

    def promote(
        self,
        scenario_id: str,
        flags: list[FlagDef],
        scenarios_dir: Path = DEFAULT_CATALOG_DIR,
        force: bool = False,
    ) -> Path:
        """Append the scenario to the permanent catalog. Human-gated: it must have run."""
        rec = self._get(scenario_id)
        if rec.status != "pending":
            raise PromotionError(f"{scenario_id} is {rec.status}, not pending")
        if rec.runs == 0 and not force:
            raise PromotionError(f"{scenario_id} has never been run; run it or pass force")
        s = rec.scenario
        validate_catalog({s.id: s}, flags)  # same fail-fast checks as the curated catalog
        if s.id in load_catalog(scenarios_dir):
            raise PromotionError(f"{s.id} already in catalog")
        target = scenarios_dir / f"{s.customer_id}.generated.yaml"
        rows = yaml.safe_load(target.read_text()) if target.exists() else []
        rows.append(s.model_dump(mode="json"))
        target.write_text(yaml.safe_dump(rows, sort_keys=False))
        rec.status = "promoted"
        self._save()
        return target

    def _get(self, scenario_id: str) -> GeneratedRecord:
        try:
            return self.records[scenario_id]
        except KeyError:
            raise KeyError(f"no generated scenario {scenario_id}") from None


def load_full_catalog(
    store: GeneratedStore | None = None, directory: Path = DEFAULT_CATALOG_DIR
) -> Catalog:
    """Curated + promoted (from disk) + every stored generated scenario, for run and replay."""
    catalog = load_catalog(directory)
    if store:
        for rec in store.records.values():
            catalog.setdefault(rec.scenario.id, rec.scenario)
    return catalog


__all__ = [
    "ALLOWED_METHODS",
    "DraftParam",
    "DraftProbe",
    "DraftSignal",
    "GenerationOutput",
    "GeneratedRecord",
    "GeneratedStore",
    "VALUE_RULES",
    "PromotionError",
    "Rejection",
    "ScenarioDraft",
    "ValidationResult",
    "load_full_catalog",
    "validate_drafts",
]
