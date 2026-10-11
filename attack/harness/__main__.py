"""CLI: run / approve / replay / generated.

    uv run python -m attack.harness run --customer customer-a --fake --auto-approve \\
        --generate 3 --code sites/customer_a/app.py --changed /login
    uv run python -m attack.harness generated list
    uv run python -m attack.harness generated promote SCN-GEN-001
"""

import argparse
import json
import sys
from pathlib import Path

from attack.agent import DummyGenerator, DummyPlanner, GeminiGenerator, GeminiPlanner
from attack.catalog import load_catalog, load_flags
from attack.catalog.generation import GeneratedStore, PromotionError, load_full_catalog
from attack.clients import FakeKeewano, FakeSite, KeewanoClient, SiteClient
from attack.harness import context
from attack.harness.approval import DEFAULT_QUEUE_PATH, ApprovalQueue
from attack.harness.config import RunConfig
from attack.harness.replay import replay
from attack.harness.run import run
from contracts import Event

SITE_URLS = {
    "customer-a": "http://localhost:3001",
    "customer-b": "http://localhost:3002",
    "customer-c": "http://localhost:3003",
}
FIXTURE_EVENTS = Path(__file__).resolve().parents[2] / "fixtures" / "events"


def _flag_arg(text: str) -> tuple[str, bool]:
    name, _, value = text.partition("=")
    return name, value.lower() in ("1", "true", "on", "yes")


def _seed_fake_keewano(keewano: FakeKeewano, customer_id: str) -> None:
    """Load Dev B's fixture events so the planner/generator see realistic traffic."""
    path = FIXTURE_EVENTS / f"{customer_id}.jsonl"
    if path.exists():
        rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        keewano.events.extend(Event.model_validate(r) for r in rows)


def cmd_run(args) -> int:
    catalog = load_catalog()
    store = GeneratedStore()
    if args.fake:
        keewano = FakeKeewano()
        _seed_fake_keewano(keewano, args.customer)
        defaults = {f.flag: f.default for f in load_flags() if f.customer_id == args.customer}
        site = FakeSite(
            args.customer,
            catalog,
            {**defaults, **dict(args.flag)},
            evidence_sink=keewano.store_evidence,
        )
    else:
        site = SiteClient(args.site_url or SITE_URLS[args.customer])
        keewano = KeewanoClient(args.keewano_url)
    config = RunConfig(
        customer_id=args.customer,
        objective=args.objective,
        target_allowlist=[site.base_url],
        require_approval=not args.no_approval,
        auto_approve=args.auto_approve,
        diff_summary=args.diff,
        changed_surfaces=args.changed,
        generate_max=args.generate,
        code_context=context.read_code_context(args.code),
    )
    planner = DummyPlanner() if args.dummy_planner else GeminiPlanner()
    generator = None
    if args.generate > 0:
        generator = DummyGenerator(catalog) if args.dummy_generator else GeminiGenerator()
    report = run(
        config,
        planner,
        site,
        keewano,
        catalog,
        ApprovalQueue(DEFAULT_QUEUE_PATH),
        generator=generator,
        generated_store=store,
    )
    if report.plan.degraded:
        print(f"WARNING: planner degraded to fallback: {report.plan.error}", file=sys.stderr)
    if report.generation and report.generation["degraded"]:
        print(f"WARNING: generator failed: {report.generation['error']}", file=sys.stderr)
    print(report.model_dump_json(indent=2))
    return 0


def cmd_approve(args) -> int:
    item = ApprovalQueue(DEFAULT_QUEUE_PATH).approve(args.run_id, args.scenario_id)
    print(f"approved {item.scenario_id} in {item.run_id}: promoted to verified")
    return 0


def cmd_replay(args) -> int:
    site = SiteClient(args.site_url)
    catalog = load_full_catalog(GeneratedStore())
    result = replay(args.evidence_ref, catalog, site, KeewanoClient(args.keewano_url))
    print(result.model_dump_json(indent=2))
    return 0 if result.reproduced else 1


def cmd_generated(args) -> int:
    store = GeneratedStore()
    if args.action == "list":
        for r in store.records_for(args.customer):
            s = r.scenario
            print(
                f"{s.id}  {r.status:<9} runs={r.runs} last={r.last_verdict or '-':<14} "
                f"{s.customer_id} {s.flag} {s.probe.method} {s.probe.path}  {s.title}"
            )
        return 0
    try:
        if args.action == "promote":
            path = store.promote(args.scenario_id, load_flags(), force=args.force)
            print(f"promoted {args.scenario_id} into {path}")
        else:
            store.reject(args.scenario_id)
            print(f"rejected {args.scenario_id}")
    except (PromotionError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="attack.harness")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run")
    r.add_argument("--customer", required=True, choices=sorted(SITE_URLS))
    r.add_argument("--objective", default="Test recently changed surfaces for regressions")
    r.add_argument("--diff", default="")
    r.add_argument("--changed", nargs="*", default=[], help="changed surfaces, e.g. /login")
    r.add_argument("--code", nargs="*", default=[], help="source files for the generator to read")
    r.add_argument("--generate", type=int, default=0, metavar="N", help="draft up to N scenarios")
    r.add_argument("--dummy-generator", action="store_true")
    r.add_argument("--dummy-planner", action="store_true")
    r.add_argument("--auto-approve", action="store_true")
    r.add_argument("--no-approval", action="store_true")
    r.add_argument("--fake", action="store_true", help="in-memory FakeSite/FakeKeewano")
    r.add_argument("--flag", action="append", default=[], type=_flag_arg, metavar="NAME=BOOL")
    r.add_argument("--site-url")
    r.add_argument("--keewano-url", default="http://localhost:4000")
    r.set_defaults(fn=cmd_run)

    a = sub.add_parser("approve")
    a.add_argument("run_id")
    a.add_argument("scenario_id")
    a.set_defaults(fn=cmd_approve)

    rp = sub.add_parser("replay")
    rp.add_argument("evidence_ref")
    rp.add_argument("--site-url", required=True)
    rp.add_argument("--keewano-url", default="http://localhost:4000")
    rp.set_defaults(fn=cmd_replay)

    g = sub.add_parser("generated", help="review LLM-drafted scenarios")
    g.add_argument("action", choices=["list", "promote", "reject"])
    g.add_argument("scenario_id", nargs="?")
    g.add_argument("--customer")
    g.add_argument("--force", action="store_true", help="promote without a prior run")
    g.set_defaults(fn=cmd_generated)

    args = p.parse_args(argv)
    if args.cmd == "generated" and args.action != "list" and not args.scenario_id:
        p.error(f"{args.action} needs a scenario_id")
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
