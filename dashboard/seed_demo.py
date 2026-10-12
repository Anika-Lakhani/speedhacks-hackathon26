"""Seed a rich, authentic demo state across the fleet.

Runs the real attack harness for customer-b and customer-c (in-process sites, events posted
to the REAL Keewano store), then runs Dev C's distiller so their `customer-X.md` pages and the
shared `shared-intelligence.md` corpus are populated the same way the live loop populates them
— no hand-written markdown. customer-a is left clean (IDOR armed) so the live demo shows a
fresh find -> fix -> share on top of an already-established intelligence layer.

    uv run uvicorn keewano.api:create_app --factory --port 4000   # store must be up
    uv run --env-file .env python -m dashboard.seed_demo

Each tenant gets a short history: a weakness is confirmed, then remediated in a later
"deploy" (verdict flips to not_reproduced), except one left open per tenant to show an active
risk the swarm is still tracking.
"""

import os

from attack.agent import DummyPlanner
from attack.catalog import load_catalog, load_flags
from attack.clients.fakes import FakeSite
from attack.clients.keewano import KeewanoClient
from attack.harness.approval import ApprovalQueue
from attack.harness.config import RunBudget, RunConfig
from attack.harness.run import run
from distill.loop import after_run
from distill.scaffold import MEMORY_DIR, scaffold

STORE_URL = os.environ.get("DASHBOARD_KEEWANO_URL", "http://localhost:4000")

# Per tenant: an ordered list of (code_revision, {flag: on}) "deploys". Flags not named stay at
# their registry default (off). The last state of each flag is the end state.
TIMELINE: dict[str, list[tuple[str, dict[str, bool]]]] = {
    "customer-b": [
        ("customer-b-2.3.0", {"broken_object_authz": True, "ssrf_callback": True}),
        ("customer-b-2.3.1", {"broken_object_authz": False, "ssrf_callback": True}),
        ("customer-b-2.4.0", {"broken_object_authz": False, "ssrf_callback": False}),
    ],
    "customer-c": [
        ("customer-c-1.7.0", {"missing_output_encoding": True, "unsafe_input_handling": True}),
        ("customer-c-1.7.1", {"missing_output_encoding": False, "unsafe_input_handling": True}),
    ],
}
OBJECTIVE = "Scheduled sweep of known weaknesses on changed surfaces"


def _run_once(keewano, catalog, flags_registry, cid, revision, overrides, memory_dir):
    seed = {f.flag: f.default for f in flags_registry if f.customer_id == cid}
    seed.update(overrides)
    site = FakeSite(cid, catalog, flags=seed, code_revision=revision)
    config = RunConfig(
        customer_id=cid,
        objective=OBJECTIVE,
        target_allowlist=[site.base_url],
        require_approval=True,
        auto_approve=True,  # release the gate so confirmed findings become verified
        budget=RunBudget(max_scenarios=12),
    )
    report = run(config, DummyPlanner(), site, keewano, catalog, ApprovalQueue(None))
    events = keewano.get_slice(cid, run_id=report.run_id, limit=1000)
    after_run(cid, events, share="auto", memory_dir=memory_dir, catalog=catalog)
    counts = {}
    for o in report.outcomes:
        counts[o.verdict.value] = counts.get(o.verdict.value, 0) + 1
    return revision, counts


def main(memory_dir=MEMORY_DIR) -> None:
    keewano = KeewanoClient(STORE_URL, timeout=10.0)
    catalog = load_catalog()
    flags_registry = load_flags()
    scaffold(memory_dir)
    for cid, timeline in TIMELINE.items():
        print(f"\n== {cid} ==")
        for revision, overrides in timeline:
            rev, counts = _run_once(
                keewano, catalog, flags_registry, cid, revision, overrides, memory_dir
            )
            print(f"  {rev}: {counts}")
    print("\nSeeded. shared-intelligence.md + customer-b/c pages are populated.")
    print("customer-a is intentionally left clean for the live demo.")


if __name__ == "__main__":
    main()
