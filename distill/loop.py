"""One call that closes the loop after a swarm run: distill it, then (optionally) share.

    from distill.loop import after_run
    after_run(customer_id, run_events, approvals=approved_pairs)

Dev A's dashboard calls this when a run finishes. `share` is the human-in-the-loop toggle for
the shared corpus (default from SWARMSHIELD_SHARE_MODE, else "review"):

- "review": candidate lessons wait on the customer page for `shared_updater approve`
- "auto":   this customer's proposed candidates are approved and promoted immediately

Either way every privacy gate, quarantine rule and the evidence gate still apply; "auto" only
skips the human approval click. Writes are serialized, so concurrent runs for different
customers can't interleave updates to the shared corpus.
"""

import os
import threading
from collections.abc import Iterable
from datetime import date
from pathlib import Path
from typing import Any, Literal

from attack.catalog import Catalog, load_catalog
from attack.harness.context import read_knowledge_version
from distill.customer_analysis.analyze import analyze
from distill.customer_analysis.patch import Op, Patch, apply_patch, parse_entry, read_entries
from distill.privacy.provenance import load_salt, source_token
from distill.scaffold import MEMORY_DIR, scaffold
from distill.shared_updater.corpus import Store
from distill.shared_updater.update import Contribution, contribute, read_candidates

ShareMode = Literal["review", "auto"]
_LOCK = threading.Lock()


def share_mode() -> ShareMode:
    return "auto" if os.environ.get("SWARMSHIELD_SHARE_MODE", "").lower() == "auto" else "review"


def _approve_proposed(page: Path, customer_id: str) -> list[str]:
    text = page.read_text()
    ops = []
    for key, line in read_entries(text).get(10, {}).items():
        entry = parse_entry(line)
        if entry and key.startswith("CL-") and entry.tail.get("sharing") == "proposed":
            entry.tail["sharing"] = "approved"
            ops.append(Op(10, key, entry.render()))
    if ops:
        page.write_text(apply_patch(text, Patch(customer_id, ops)))
    return [op.key for op in ops]


def after_run(
    customer_id: str,
    events: Iterable[Any],
    *,
    approvals: Iterable[tuple[str, str]] = (),
    share: ShareMode | None = None,
    memory_dir: Path = MEMORY_DIR,
    catalog: Catalog | None = None,
    today: date | None = None,
) -> dict[str, Any]:
    """Distill one run's events into the customer page; share per the toggle. Returns a short
    summary the dashboard can show."""
    share = share or share_mode()
    catalog = catalog or load_catalog()
    with _LOCK:
        scaffold(memory_dir)  # creates only missing pages
        page = memory_dir / "customers" / f"{customer_id}.md"
        result = analyze(
            customer_id,
            events,
            page.read_text(),
            catalog,
            approvals=approvals,
            knowledge_version=read_knowledge_version(memory_dir),
        )
        if result.patch:
            page.write_text(apply_patch(page.read_text(), result.patch))
        summary: dict[str, Any] = {
            "customer_id": customer_id,
            "page_updates": [op.key for op in result.patch.ops],
            "skipped_events": len(result.skipped),
            "share_mode": share,
            "approved": [],
            "shared": [],
        }
        if share != "auto":
            return summary
        summary["approved"] = _approve_proposed(page, customer_id)
        store = Store(memory_dir)
        salt = load_salt()
        contributions = [
            Contribution(source_token(p.stem, salt), c)
            for p in sorted((memory_dir / "customers").glob("*.md"))
            for c in read_candidates(p.read_text())
        ]
        outcome = contribute(store.load(), contributions, today or date.today())
        if outcome.changed:
            store.save(outcome.corpus, outcome.audit)
        summary["shared"] = [f"{r['action']} {r['item']}" for r in outcome.audit]
        summary["knowledge_version"] = outcome.corpus.knowledge_version
        return summary
