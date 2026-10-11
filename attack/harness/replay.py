"""Re-run a stored evidence record against a site pinned to its revision and flags."""

from typing import Any

from pydantic import BaseModel

from attack.catalog import Catalog
from attack.engine import ProbeResult, send
from attack.engine.probe import READ_ONLY_VERBS
from attack.verify import judge
from contracts import Verdict


class ReplayError(Exception):
    pass


class ReplayResult(BaseModel):
    evidence_ref: str
    scenario_id: str
    stored_verdict: Verdict
    replay_verdict: Verdict
    reproduced: bool


def _as_request(stored: dict[str, Any]) -> dict[str, Any]:
    """Accept both shapes: {params} (engine) or {query, json} (site-recorded)."""
    params = stored.get("params")
    if params is None:
        params = stored.get("query") or stored.get("json") or {}
    return {
        "method": stored["method"],
        "path": stored["path"],
        "headers": stored["headers"],
        "params": params,
    }


def replay(evidence_ref: str, catalog: Catalog, site, keewano) -> ReplayResult:
    ev = keewano.get_evidence(evidence_ref)
    request = _as_request(ev["request"])
    scenario_id = next(
        v for k, v in request["headers"].items() if k.lower() == "x-swarmshield-probe"
    )
    scenario = catalog[scenario_id]

    stored = ProbeResult(
        scenario_id=scenario_id,
        request=request,
        response=ev["response"],
        flags_snapshot=ev["flags_snapshot"],
        code_revision=ev["code_revision"],
        evidence_ref=evidence_ref,
    )
    stored_verdict = judge(scenario, stored).verdict

    meta = site.meta()
    if meta.get("code_revision") != ev["code_revision"]:
        raise ReplayError(
            f"site is at {meta.get('code_revision')!r}, evidence was recorded at "
            f"{ev['code_revision']!r}; cannot pin"
        )
    if request["method"] not in READ_ONLY_VERBS | {"POST"}:
        raise ReplayError(f"refusing to replay verb {request['method']}")

    original_flags = dict(meta.get("flags", {}))
    site.set_flags(ev["flags_snapshot"])
    try:
        resp = send(site, request)
        now = site.meta()
    finally:
        site.set_flags(original_flags)
    replayed = ProbeResult(
        scenario_id=scenario_id,
        request=request,
        response=resp.model_dump(),
        flags_snapshot=now.get("flags", {}),
        code_revision=now.get("code_revision", ""),
    )
    replay_verdict = judge(scenario, replayed).verdict
    return ReplayResult(
        evidence_ref=evidence_ref,
        scenario_id=scenario_id,
        stored_verdict=stored_verdict,
        replay_verdict=replay_verdict,
        reproduced=stored_verdict == replay_verdict,
    )
