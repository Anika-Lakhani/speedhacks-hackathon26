"""CLI: run / approve / replay.

    uv run python -m attack.harness run --customer customer-a --fake --dummy-planner \\
        --flag idor_orders=true --auto-approve
"""

import argparse
import sys

from attack.agent import DummyPlanner, GeminiPlanner
from attack.catalog import load_catalog, load_flags
from attack.clients import FakeKeewano, FakeSite, KeewanoClient, SiteClient
from attack.harness.approval import DEFAULT_QUEUE_PATH, ApprovalQueue
from attack.harness.config import RunConfig
from attack.harness.replay import replay
from attack.harness.run import run

SITE_URLS = {
    "customer-a": "http://localhost:3001",
    "customer-b": "http://localhost:3002",
    "customer-c": "http://localhost:3003",
}


def _flag_arg(text: str) -> tuple[str, bool]:
    name, _, value = text.partition("=")
    return name, value.lower() in ("1", "true", "on", "yes")


def cmd_run(args) -> int:
    catalog = load_catalog()
    if args.fake:
        keewano = FakeKeewano()
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
    )
    planner = DummyPlanner() if args.dummy_planner else GeminiPlanner()
    report = run(config, planner, site, keewano, catalog, ApprovalQueue(DEFAULT_QUEUE_PATH))
    if report.plan.degraded:
        print(f"WARNING: planner degraded to fallback: {report.plan.error}", file=sys.stderr)
    print(report.model_dump_json(indent=2))
    return 0


def cmd_approve(args) -> int:
    item = ApprovalQueue(DEFAULT_QUEUE_PATH).approve(args.run_id, args.scenario_id)
    print(f"approved {item.scenario_id} in {item.run_id}: promoted to verified")
    return 0


def cmd_replay(args) -> int:
    site = SiteClient(args.site_url)
    result = replay(args.evidence_ref, load_catalog(), site, KeewanoClient(args.keewano_url))
    print(result.model_dump_json(indent=2))
    return 0 if result.reproduced else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="attack.harness")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run")
    r.add_argument("--customer", required=True, choices=sorted(SITE_URLS))
    r.add_argument("--objective", default="Test recently changed surfaces for regressions")
    r.add_argument("--diff", default="")
    r.add_argument("--changed", nargs="*", default=[], help="changed surfaces, e.g. /login")
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

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
