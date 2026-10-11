"""Orchestrates one run. The only place limits are enforced (spec §5)."""

import uuid
from collections import Counter
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from attack.agent import PlanRequest, ScenarioBrief, TestPlan
from attack.agent.planner import Planner, sanitize_plan
from attack.catalog import Catalog, Scenario, catalog_version, load_catalog
from attack.engine import ProbeResult, run_probe
from attack.engine.probe import BLOCKED
from attack.harness import context
from attack.harness.approval import ApprovalQueue, PendingApproval
from attack.harness.budget import BudgetTracker, GuardedSite, HaltRun
from attack.harness.config import RunConfig
from attack.harness.events import EventFactory
from attack.verify import judge
from contracts import Event, EventType, EvidenceLabel, Verdict, parse_evidence_ref


class ScenarioOutcome(BaseModel):
    scenario_id: str
    verdict: Verdict
    evidence_label: EvidenceLabel
    approval: str | None  # pending | auto | not_required | None
    confidence: float
    evidence_ref: str | None
    notes: str


class RunReport(BaseModel):
    run_id: str
    customer_id: str
    code_revision: str
    knowledge_version: str
    catalog_version: str
    plan: TestPlan
    outcomes: list[ScenarioOutcome]
    counts: dict[str, int]
    budget_usage: dict[str, Any]
    stop_reason: str
    warnings: list[str] = []


def _brief(s: Scenario) -> ScenarioBrief:
    return ScenarioBrief(
        id=s.id,
        title=s.title,
        weakness_class=s.weakness_class,
        severity=s.severity,
        invariant=s.invariant,
        path=s.probe.path,
    )


def _own_ref(ref: str | None, customer_id: str, run_id: str) -> str | None:
    """Use the site's evidence ref only if it belongs to this customer and run."""
    if not ref:
        return None
    try:
        c, r, _ = parse_evidence_ref(ref)
    except ValueError:
        return None
    return ref if (c, r) == (customer_id, run_id) else None


def run(
    config: RunConfig,
    planner: Planner,
    site,
    keewano,
    catalog: Catalog | None = None,
    queue: ApprovalQueue | None = None,
    memory_dir: Path = context.MEMORY_DIR,
    clock=None,
) -> RunReport:
    catalog = catalog if catalog is not None else load_catalog()
    cat_version = catalog_version()
    scenarios = {s.id: s for s in catalog.values() if s.customer_id == config.customer_id}
    queue = queue if queue is not None else ApprovalQueue(None)
    tracker = BudgetTracker(
        config.budget, config.allowed_tools, **({"clock": clock} if clock else {})
    )
    guarded = GuardedSite(site, tracker)
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    warnings: list[str] = []

    try:
        code_revision = guarded.meta().get("code_revision") or "unknown"
    except HaltRun:
        code_revision = "unknown"
    except Exception:
        code_revision = "unknown"
        warnings.append("site /__meta unavailable at run start")
    knowledge_version = context.read_knowledge_version(memory_dir)

    factory = EventFactory(
        config.customer_id, run_id, code_revision, knowledge_version, cat_version
    )

    def emit(event_type: EventType, **kw) -> Event:
        event = factory.make(event_type, **kw)
        if "keewano.post_events" not in config.allowed_tools:
            warnings.append(f"keewano.post_events not allowed; {event_type.value} not logged")
            return event
        try:
            keewano.post_events([event])
        except Exception as e:
            warnings.append(f"failed to log {event_type.value}: {type(e).__name__}")
        return event

    emit(
        EventType.SWARM_RUN_START,
        target=site.base_url,
        action="run_start",
        attrs={
            "objective": config.objective,
            "budget": config.budget.model_dump(),
            "allowed_tools": config.allowed_tools,
        },
    )

    stop_reason = "completed"
    outcomes: list[ScenarioOutcome] = []
    plan = TestPlan(steps=[], planner="none")

    try:
        request = PlanRequest(
            customer_id=config.customer_id,
            objective=config.objective,
            max_scenarios=config.budget.max_scenarios,
            customer_sections=context.read_customer_sections(config.customer_id, memory_dir),
            diff_summary=config.diff_summary,
            changed_surfaces=config.changed_surfaces,
            shared_lessons=context.read_shared_lessons(config.customer_id, catalog, memory_dir),
            scenarios=[_brief(s) for s in scenarios.values()],
        )
        plan = sanitize_plan(planner.plan(request), set(scenarios), config.budget.max_scenarios)
        emit(
            EventType.SWARM_PLAN,
            target=config.customer_id,
            action="plan",
            attrs={
                "steps": [
                    {"scenario_id": s.scenario_id, "priority": s.priority, "rationale": s.rationale}
                    for s in plan.steps
                ],
                "skipped": [s.model_dump() for s in plan.skipped],
                "dropped_ids": plan.dropped_ids,
                "planner": plan.planner,
                "model": plan.model,
                "prompt_version": plan.prompt_version,
                "degraded": plan.degraded,
            },
        )
        tracker.add_spend(plan.cost_usd)

        in_scope = site.base_url in config.target_allowlist
        for step in plan.steps:
            scenario = scenarios[step.scenario_id]
            tracker.require_calls(2)  # probe + meta
            if in_scope:
                result = run_probe(
                    scenario, guarded, run_id, frozenset(config.allowed_verbs), cat_version
                )
            else:
                result = ProbeResult(
                    scenario_id=scenario.id,
                    request={},
                    response={},
                    flags_snapshot={},
                    code_revision=code_revision,
                    catalog_version=cat_version,
                    error=f"{BLOCKED}target {site.base_url} not on allowlist",
                )
            verified = judge(scenario, result)
            outcomes.append(
                _log_scenario(
                    emit, factory, queue, config, scenario, step.priority, result, verified
                )
            )
    except HaltRun as halt:
        reason = getattr(halt, "reason", None)
        stop_reason = f"budget:{reason}" if reason else f"tool_not_allowed:{halt}"

    counts = Counter(o.verdict.value for o in outcomes)
    emit(
        EventType.SWARM_RUN_END,
        target=config.customer_id,
        action="run_end",
        attrs={
            "verdict_counts": dict(counts),
            "stop_reason": stop_reason,
            "budget_usage": tracker.usage(),
            "scenarios_run": len(outcomes),
            "pending_approvals": len(queue.pending(run_id)),
        },
    )

    return RunReport(
        run_id=run_id,
        customer_id=config.customer_id,
        code_revision=code_revision,
        knowledge_version=knowledge_version,
        catalog_version=cat_version,
        plan=plan,
        outcomes=outcomes,
        counts=dict(counts),
        budget_usage=tracker.usage(),
        stop_reason=stop_reason,
        warnings=warnings,
    )


def _log_scenario(emit, factory, queue, config, scenario, priority, result, verified):
    blocked = verified.verdict == Verdict.BLOCKED
    status = result.response.get("status")
    probe_event = emit(
        EventType.SWARM_PROBE,
        target=scenario.probe.path,
        action=f"{scenario.probe.method} probe",
        policy_outcome="deny" if blocked else "allow",
        scenario_id=scenario.id,
        evidence_ref=_own_ref(result.evidence_ref, factory.customer_id, factory.run_id),
        attrs={
            "priority": priority,
            "http_status": status,
            "error": result.error,
            "request": {k: result.request.get(k) for k in ("method", "path", "params")},
        },
    )
    label, approval = EvidenceLabel.OBSERVED, None
    if verified.verdict == Verdict.CONFIRMED:
        label = EvidenceLabel.REPRODUCED
        if not config.require_approval:
            label, approval = EvidenceLabel.VERIFIED, "not_required"
        elif config.auto_approve:
            label, approval = EvidenceLabel.VERIFIED, "auto"
        else:
            approval = "pending"
            queue.add(
                PendingApproval(
                    customer_id=config.customer_id,
                    run_id=factory.run_id,
                    scenario_id=scenario.id,
                    evidence_ref=probe_event.evidence_ref,
                )
            )
    emit(
        EventType.SWARM_VERDICT,
        target=scenario.probe.path,
        action="verdict",
        policy_outcome="deny"
        if blocked
        else ("flag" if verified.verdict == Verdict.CONFIRMED else "allow"),
        scenario_id=scenario.id,
        verdict=verified.verdict.value,
        evidence_ref=probe_event.evidence_ref,
        attrs={
            "confidence": verified.confidence,
            "invariant": verified.invariant,
            "severity": scenario.severity,
            "weakness_class": scenario.weakness_class,
            "signal_matched": verified.signal_matched,
            "flag_was_on": verified.flag_was_on,
            "evidence_label": label.value,
            "approval": approval,
            "notes": verified.notes,
        },
    )
    return ScenarioOutcome(
        scenario_id=scenario.id,
        verdict=verified.verdict,
        evidence_label=label,
        approval=approval,
        confidence=verified.confidence,
        evidence_ref=probe_event.evidence_ref,
        notes=verified.notes,
    )
