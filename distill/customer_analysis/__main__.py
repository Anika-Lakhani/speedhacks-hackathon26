"""CLI: distill a window of events into a customer page.

    uv run python -m distill.customer_analysis --customer customer-a \\
        --events fixtures/events/customer-a.jsonl [--dry-run]
    uv run python -m distill.customer_analysis --customer customer-a \\
        --keewano http://localhost:4000 [--since T | --since-revision REV | --full]

With --keewano it reads every page of the window from Dev B's read API. By default the window
starts at the page's `last_distilled` time, so repeated runs only distill what is new.
Prints the patch as a unified diff and applies it unless --dry-run.
"""

import argparse
import json
import sys
from pathlib import Path

import httpx

from attack.catalog import load_catalog
from attack.harness.context import read_knowledge_version
from distill.customer_analysis.analyze import Change, analyze
from distill.customer_analysis.patch import apply_patch, read_entries, render_diff
from distill.customer_analysis.source import EventSource
from distill.scaffold import MEMORY_DIR

APPROVALS_PATH = Path(".swarmshield") / "approvals.json"


def last_distilled(page_text: str) -> str | None:
    line = read_entries(page_text).get(1, {}).get("last_distilled", "")
    value = line.partition(":")[2].strip()
    return None if value in ("", "never") else value


def load_events(args, page_text: str, source: EventSource | None = None) -> list:
    if args.events:
        return [json.loads(line) for line in Path(args.events).read_text().splitlines() if line]
    source = source or EventSource(args.keewano)
    if args.since_revision:
        return source.window(args.customer, revision=args.since_revision)
    since = args.since or (None if args.full else last_distilled(page_text))
    return source.window(args.customer, since=since)


def load_approvals(path: Path) -> set[tuple[str, str]]:
    if not path.exists():
        return set()
    return {
        (row["run_id"], row["scenario_id"])
        for row in json.loads(path.read_text())
        if row.get("status") == "approved"
    }


def main(argv=None, source: EventSource | None = None) -> int:
    p = argparse.ArgumentParser(prog="distill.customer_analysis")
    p.add_argument("--customer", required=True)
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--events", help="JSONL file of events")
    src.add_argument("--keewano", help="event store base URL, e.g. http://localhost:4000")
    window = p.add_mutually_exclusive_group()
    window.add_argument("--since", help="RFC 3339 lower bound for --keewano (inclusive)")
    window.add_argument("--since-revision", help="events from this code_revision onward")
    window.add_argument("--full", action="store_true", help="ignore last_distilled; read all")
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
    try:
        events = load_events(args, before, source)
    except httpx.HTTPStatusError as e:
        detail = e.response.text[:200]
        print(f"event store returned {e.response.status_code}: {detail}", file=sys.stderr)
        return 1
    except httpx.TransportError as e:
        print(f"event store unreachable at {args.keewano}: {e}", file=sys.stderr)
        return 1
    result = analyze(
        args.customer,
        events,
        before,
        load_catalog(),
        changes=changes,
        approvals=load_approvals(args.approvals),
        knowledge_version=read_knowledge_version(args.memory_dir),
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
