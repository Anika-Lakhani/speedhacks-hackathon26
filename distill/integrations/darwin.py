"""Optional: find remediation agents for active shared lessons via Darwin Search.

    uv run python -m distill.integrations.darwin [--dry-run] [--max 3]

Self-contained and on demand: nothing else imports this module, so deleting it (and
`memory/shared/darwin-agents.json`) removes the integration. Only the tenant-neutral lesson title
and invariant are sent, and the query must pass every privacy gate first. Darwin's results are
untrusted third-party text: reduced to a safe character set, capped, and never acted on.
Docs: https://darwin.so/docs/speedhacks. DARWIN_API_KEY is optional (anonymous limit otherwise).
"""

import argparse
import json
import os
import sys
from datetime import date
from pathlib import Path
from typing import Any

import httpx

from distill.customer_analysis.analyze import clean, clean_text
from distill.privacy.scanners import scan
from distill.shared_updater.corpus import MEMORY_DIR, Store
from distill.shared_updater.lessons import LESSONS

SEARCH_URL = "https://api.darwin.so/api/v3/search"
OUTPUT = "darwin-agents.json"


def query_for(item_id: str) -> str:
    lesson = LESSONS[item_id]
    return f"Remediation guidance for: {lesson.title}. Goal: {lesson.invariant}"


def _agent(raw: dict[str, Any]) -> dict[str, Any]:
    agent_id, cap_id = clean(raw.get("agentId", ""), 40), clean(raw.get("capabilityId", ""), 40)
    return {
        "name": clean_text(raw.get("name", ""), 80),
        "why": clean_text((raw.get("reasons") or [""])[0], 200),
        "readiness": clean(raw.get("readiness", "unknown"), 20),
        "can_start": bool(raw.get("canStartThread")),
        "page": f"https://index.darwin.so/agent/{agent_id}?capability={cap_id}",
    }


def search(query: str, max_results: int, client: httpx.Client) -> dict[str, Any]:
    """One Darwin Search. Never raises: failures come back as status `error`."""
    if hits := scan(query):
        return {
            "status": "blocked",
            "note": f"query failed privacy gates: {[h.rule for h in hits]}",
        }
    headers = {"Content-Type": "application/json"}
    if key := os.environ.get("DARWIN_API_KEY"):
        headers["Authorization"] = f"Bearer {key}"
    try:
        r = client.post(
            SEARCH_URL, json={"query": query, "maxResults": max_results}, headers=headers
        )
        r.raise_for_status()
        body = r.json()
    except (httpx.HTTPError, ValueError) as e:
        return {"status": "error", "note": f"{type(e).__name__}: {str(e)[:120]}"}
    response = body.get("response") or {}
    note = response.get("noMatchReason") or response.get("question") or ""
    return {
        "status": clean(body.get("status", "unknown"), 20),
        "note": clean_text(note, 200),
        "agents": [_agent(a) for a in (response.get("agents") or [])[:max_results]],
    }


def run(
    memory_dir: Path = MEMORY_DIR,
    max_results: int = 3,
    dry_run: bool = False,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    corpus = Store(memory_dir).load()
    active = [i.id for i in corpus.items.values() if i.status == "active" and i.id in LESSONS]
    out: dict[str, Any] = {
        "knowledge_version": corpus.knowledge_version,
        "searched": str(date.today()),
        "lessons": {},
    }
    client = client or httpx.Client(timeout=30.0)
    for item_id in active:
        query = query_for(item_id)
        result = {"status": "dry_run"} if dry_run else search(query, max_results, client)
        out["lessons"][item_id] = {"query": query, **result}
    if not dry_run:
        path = memory_dir / "shared" / OUTPUT
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(out, indent=2) + "\n")
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="distill.integrations.darwin")
    p.add_argument("--memory-dir", type=Path, default=MEMORY_DIR)
    p.add_argument("--max", type=int, default=3, help="agents per lesson (1-20)")
    p.add_argument("--dry-run", action="store_true", help="print queries; send nothing")
    args = p.parse_args(argv)
    out = run(args.memory_dir, max(1, min(args.max, 20)), args.dry_run)
    if not out["lessons"]:
        print("no active shared lessons; run the shared updater first")
    for item_id, res in out["lessons"].items():
        print(f"{item_id}  [{res['status']}]  query: {res['query']}")
        if res.get("note"):
            print(f"    {res['note']}")
        for a in res.get("agents", []):
            print(f"    - {a['name']} (readiness: {a['readiness']}): {a['why']}")
            print(f"      {a['page']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
