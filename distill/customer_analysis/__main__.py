"""CLI: distill a window of events into a customer page.

    uv run python -m distill.customer_analysis --customer customer-a \\
        --events fixtures/events/customer-a.jsonl [--dry-run]
    uv run python -m distill.customer_analysis --customer customer-a \\
        --keewano http://localhost:4000 [--since 2026-10-11T00:00:00Z]

Prints the patch as a unified diff and applies it unless --dry-run.
"""

import argparse
import json
import sys
from pathlib import Path

from attack.catalog import load_catalog
from distill.customer_analysis.analyze import Change, analyze
from distill.customer_analysis.patch import apply_patch, render_diff
from distill.scaffold import MEMORY_DIR

APPROVALS_PATH = Path(".swarmshield") / "approvals.json"


def load_events(args) -> list:
    if args.events:
        return [json.loads(line) for line in Path(args.events).read_text().splitlines() if line]
    from attack.clients import KeewanoClient  # only needed for the live path

    return KeewanoClient(args.keewano).get_slice(args.customer, since=args.since, limit=args.limit)


def load_approvals(path: Path) -> set[tuple[str, str]]:
    if not path.exists():
        return set()
    return {
        (row["run_id"], row["scenario_id"])
        for row in json.loads(path.read_text())
        if row.get("status") == "approved"
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="distill.customer_analysis")
    p.add_argument("--customer", required=True)
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--events", help="JSONL file of events")
    src.add_argument("--keewano", help="event store base URL, e.g. http://localhost:4000")
    p.add_argument("--since", help="RFC 3339 lower bound for --keewano")
    p.add_argument("--limit", type=int, default=500)
    p.add_argument("--change-revision", help="revision the change metadata below describes")
    p.add_argument("--change-summary", default="")
    p.add_argument("--changed-surface", action="append", default=[], help="e.g. /orders")
    p.add_argument("--memory-dir", type=Path, default=MEMORY_DIR)
    p.add_argument("--approvals", type=Path, default=APPROVALS_PATH)
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args(argv)

    page = args.memory_dir / "customers" / f"{args.customer}.md"
    if not page.exists():
        print(f"{page} does not exist; run `python -m distill.scaffold` first", file=sys.stderr)
        return 1
    changes = []
    if args.change_revision:
        changes.append(Change(args.change_revision, args.change_summary, args.changed_surface))
    before = page.read_text()
    result = analyze(
        args.customer,
        load_events(args),
        before,
        load_catalog(),
        changes=changes,
        approvals=load_approvals(args.approvals),
    )
    for reason in result.skipped:
        print(f"skipped: {reason}", file=sys.stderr)
    if not result.patch:
        print("no changes")
        return 0
    after = apply_patch(before, result.patch)
    print(render_diff(before, after, f"memory/customers/{args.customer}.md"), end="")
    if not args.dry_run:
        page.write_text(after)
    return 0


if __name__ == "__main__":
    sys.exit(main())
