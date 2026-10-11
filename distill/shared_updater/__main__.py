"""CLI for the shared corpus.

uv run python -m distill.shared_updater approve --customer customer-a --class idor
uv run python -m distill.shared_updater update [--dry-run]
uv run python -m distill.shared_updater retract SI-object_access_authz --reason "..."
uv run python -m distill.shared_updater rollback 0.2.0
uv run python -m distill.shared_updater audit
"""

import argparse
import sys
from datetime import date
from pathlib import Path

from distill.customer_analysis.patch import Op, Patch, apply_patch, parse_entry, render_diff
from distill.privacy.provenance import load_salt, source_token
from distill.privacy.scanners import scan
from distill.shared_updater.corpus import MEMORY_DIR, Store, render_shared
from distill.shared_updater.update import (
    Contribution,
    Outcome,
    contribute,
    read_candidates,
    retract,
    rollback,
)


def _finish(store: Store, before_text: str, outcome: Outcome, dry_run: bool) -> int:
    if not outcome.changed:
        print("no changes")
        return 0
    after = render_shared(outcome.corpus)
    print(render_diff(before_text, after, "memory/shared-intelligence.md"), end="")
    for record in outcome.audit:
        print(f"audit: {record['action']} {record['item']} {record.get('reasons', '')}".rstrip())
    if not dry_run:
        store.save(outcome.corpus, outcome.audit)
    return 0


def cmd_approve(args) -> int:
    """Human step: mark one §10 candidate lesson as approved for sharing."""
    page = args.memory_dir / "customers" / f"{args.customer}.md"
    text = page.read_text()
    key = f"CL-{args.weakness_class}"
    line = next((ln for ln in text.splitlines() if ln.startswith(f"- `{key}`")), None)
    entry = parse_entry(line) if line else None
    if entry is None:
        print(f"no candidate {key} on {page.name}", file=sys.stderr)
        return 1
    if entry.tail.get("sharing") == "hold":
        print(f"{key} is on hold (contradictory evidence); not approving", file=sys.stderr)
        return 1
    entry.tail["sharing"] = "approved"
    page.write_text(apply_patch(text, Patch(args.customer, [Op(10, key, entry.render())])))
    print(f"approved {key} on {page.name}")
    return 0


def cmd_update(args) -> int:
    store = Store(args.memory_dir)
    salt = load_salt()
    contributions = [
        Contribution(source_token(page.stem, salt), candidate)
        for page in sorted((args.memory_dir / "customers").glob("*.md"))
        for candidate in read_candidates(page.read_text())
    ]
    corpus = store.load()
    outcome = contribute(corpus, contributions, date.today())
    return _finish(store, render_shared(corpus), outcome, args.dry_run)


def cmd_retract(args) -> int:
    store = Store(args.memory_dir)
    corpus = store.load()
    return _finish(
        store, render_shared(corpus), retract(corpus, args.item, args.reason, date.today()), False
    )


def cmd_rollback(args) -> int:
    store = Store(args.memory_dir)
    corpus = store.load()
    outcome = rollback(corpus, store.snapshot(args.version), date.today())
    return _finish(store, render_shared(corpus), outcome, False)


def cmd_audit(args) -> int:
    """Privacy audit: the shared page must pass every gate."""
    store = Store(args.memory_dir)
    text = store.page.read_text() if store.page.exists() else ""
    hits = sorted({f"{h.kind}:{h.rule}" for h in scan(text)})
    for hit in hits:
        print(f"FAIL {hit}")
    print("privacy audit passed" if not hits else f"privacy audit failed ({len(hits)} rules)")
    return 1 if hits else 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="distill.shared_updater")
    p.add_argument("--memory-dir", type=Path, default=MEMORY_DIR)
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("approve", help="approve a customer's candidate lesson for sharing")
    a.add_argument("--customer", required=True)
    a.add_argument("--class", dest="weakness_class", required=True)
    a.set_defaults(fn=cmd_approve)

    u = sub.add_parser("update", help="promote approved candidates into the shared corpus")
    u.add_argument("--dry-run", action="store_true")
    u.set_defaults(fn=cmd_update)

    r = sub.add_parser("retract", help="retract an active item")
    r.add_argument("item")
    r.add_argument("--reason", required=True)
    r.set_defaults(fn=cmd_retract)

    rb = sub.add_parser("rollback", help="restore the items of an earlier knowledge_version")
    rb.add_argument("version")
    rb.set_defaults(fn=cmd_rollback)

    au = sub.add_parser("audit", help="privacy audit of shared-intelligence.md")
    au.set_defaults(fn=cmd_audit)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
