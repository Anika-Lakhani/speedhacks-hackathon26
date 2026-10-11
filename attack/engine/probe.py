"""Deterministic probe engine: one Scenario -> one ProbeResult. No model, no retries."""

from typing import Any

from pydantic import BaseModel

from attack.catalog import Scenario
from attack.catalog.fixtures import SESSION_USER, FixtureError, resolve
from attack.catalog.models import PATH_PARAM
from attack.clients.site import Site

READ_ONLY_VERBS = frozenset({"GET", "HEAD", "OPTIONS"})
RUN_HEADER = "X-SwarmShield-Run"
ACTOR_HEADER = "X-SwarmShield-Synthetic-User"
EVIDENCE_HEADER = "X-SwarmShield-Evidence"
BLOCKED = "blocked: "


class ProbeResult(BaseModel):
    scenario_id: str
    request: dict[str, Any]
    response: dict[str, Any]
    flags_snapshot: dict[str, bool]
    code_revision: str
    error: str | None = None
    evidence_ref: str | None = None
    catalog_version: str | None = None


def build_request(scenario: Scenario, run_id: str) -> dict[str, Any]:
    """Resolve fixtures into the exact request that will be sent."""
    probe = scenario.probe
    values = {k: resolve(v) for k, v in probe.params.items()}
    path_vars = set(PATH_PARAM.findall(probe.path))
    path = PATH_PARAM.sub(lambda m: values[m.group(1)], probe.path)
    return {
        "method": probe.method,
        "path": path,
        "headers": {
            probe.marker_header: scenario.id,
            RUN_HEADER: run_id,
            ACTOR_HEADER: SESSION_USER,
        },
        "params": {k: v for k, v in values.items() if k not in path_vars},
    }


def send(site: Site, request: dict[str, Any]):
    """Params ride in the query for read-only verbs, as a JSON body otherwise."""
    read_only = request["method"] in READ_ONLY_VERBS
    params = request["params"] or None
    return site.probe(
        request["method"],
        request["path"],
        request["headers"],
        query=params if read_only else None,
        json=params if not read_only else None,
    )


def run_probe(
    scenario: Scenario,
    site: Site,
    run_id: str,
    allowed_verbs: frozenset[str] = READ_ONLY_VERBS,
    catalog_version: str | None = None,
) -> ProbeResult:
    def result(request, response=None, flags=None, revision="", error=None, ref=None):
        return ProbeResult(
            scenario_id=scenario.id,
            request=request,
            response=response or {},
            flags_snapshot=flags or {},
            code_revision=revision,
            error=error,
            evidence_ref=ref,
            catalog_version=catalog_version,
        )

    try:
        request = build_request(scenario, run_id)
    except FixtureError as e:
        return result({}, error=f"{BLOCKED}{e}")
    request["url"] = site.base_url + request["path"]

    if request["method"] not in allowed_verbs:
        return result(request, error=f"{BLOCKED}verb {request['method']} not allowed")

    try:
        resp = send(site, request)
    except Exception as e:  # timeouts, connection errors: single attempt, no retry
        return result(request, error=f"error: {type(e).__name__}: {e}")

    try:
        meta = site.meta()
    except Exception as e:
        return result(
            request, resp.model_dump(), error=f"error: meta unavailable: {type(e).__name__}"
        )
    return result(
        request,
        resp.model_dump(),
        meta.get("flags", {}),
        meta.get("code_revision", ""),
        ref=resp.headers.get(EVIDENCE_HEADER),
    )
