"""The shared corpus: state in `memory/shared/corpus.json`, rendered to `shared-intelligence.md`.

Every saved version is snapshotted to `memory/shared/history/<knowledge_version>.json` so any
update can be rolled back, and every change is appended to `memory/shared/audit.jsonl`.
Nothing here names a tenant: sources are keyed tokens (`distill/privacy/provenance.py`).
"""

import json
from datetime import date as Date
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from distill.pages import INITIAL_KNOWLEDGE_VERSION, PAGE_SCHEMA_VERSION, SHARED_SECTIONS, TAXONOMY
from distill.shared_updater.lessons import LESSONS

MEMORY_DIR = Path(__file__).resolve().parents[2] / "memory"


class Source(BaseModel):
    label: str  # reproduced | verified
    confirmations: int


class Item(BaseModel):
    id: str
    version: int
    status: str  # active | expired | retracted | superseded (non-active: Deprecated section)
    source_class: str = "swarm-simulation"
    evidence_level: str  # reproduced | verified
    confidence: str  # low | medium | high
    applicability: list[str]
    last_validation: Date
    expiry: Date
    sources: dict[str, Source] = {}
    note: str = ""  # retraction / supersession reason


class Quarantined(BaseModel):
    id: str
    weakness_class: str
    source: str
    candidate_key: str
    reasons: list[str]
    date: Date
    status: str = "pending_review"  # pending_review | released | rejected


class ChangeLogEntry(BaseModel):
    version: str
    date: Date | None = None
    summary: str


class Corpus(BaseModel):
    knowledge_version: str = INITIAL_KNOWLEDGE_VERSION
    items: dict[str, Item] = {}
    quarantine: list[Quarantined] = []
    changelog: list[ChangeLogEntry] = [
        ChangeLogEntry(version=INITIAL_KNOWLEDGE_VERSION, summary="corpus created (empty)")
    ]


def bump(version: str) -> str:
    major, minor, _ = (int(x) for x in version.split("."))
    return f"{major}.{minor + 1}.0"


# ---- rendering ---------------------------------------------------------------------------


def render_item(item: Item) -> str:
    """One active item as a `### <id>` chunk: the text Dev A's planner reads."""
    lesson = LESSONS[item.id]
    meta = " · ".join(
        [
            f"id: {item.id}",
            f"version: {item.version}",
            f"status: {item.status}",
            f"source_class: {item.source_class}",
            f"evidence_level: {item.evidence_level}",
            f"confidence: {item.confidence}",
            f"sources: {len(item.sources)}",
            f"last_validation: {item.last_validation}",
            f"expiry: {item.expiry}",
        ]
    )
    return "\n".join(
        [
            f"### {item.id}",
            "",
            f"**{lesson.title}.** {lesson.pattern}",
            f"Suggested test: {lesson.test}",
            "",
            f"applicability: {', '.join(item.applicability)}",
            f"- preconditions: {lesson.preconditions}",
            f"- invariant: {lesson.invariant}",
            f"- {meta}",
        ]
    )


def render_shared(corpus: Corpus) -> str:
    active = [i for i in corpus.items.values() if i.status == "active"]
    retired = [i for i in corpus.items.values() if i.status != "active"]
    pending = [q for q in corpus.quarantine if q.status == "pending_review"]
    taxonomy = "\n".join(
        f"| `{family}` | {', '.join(f'`{c}`' for c in classes)} |"
        for family, classes in TAXONOMY.items()
    )
    body: dict[str, list[str]] = {
        "Taxonomy & version": [
            "| Family | Weakness classes |\n|---|---|\n" + taxonomy,
            "Active items are `### <id>` headings. Pending, quarantined and retired items are\n"
            "`#### <id>` so the attack planner never reads them as live lessons.",
        ],
        "Generalized attack patterns & preconditions": [render_item(i) for i in active],
        "Reusable synthetic scenarios": [
            "\n".join(f"- `{i.id}`: {LESSONS[i.id].test}" for i in active)
        ],
        "Invariants & defensive patterns": [
            "\n".join(
                f"- `{i.id}`: {LESSONS[i.id].invariant} Defense: {LESSONS[i.id].mitigation}"
                for i in active
            )
        ],
        "Verified mitigation & regression guidance": [
            "\n".join(
                f"- `{i.id}`: {LESSONS[i.id].mitigation} Regression: {LESSONS[i.id].regression}"
                for i in active
                if i.evidence_level == "verified"
            )
        ],
        "Deprecated & superseded knowledge": [
            f"#### {i.id}\n\n- status: {i.status} · version: {i.version}"
            + (f" · reason: {i.note}" if i.note else "")
            for i in retired
        ],
        "Change log": [
            "\n".join(
                f"- {c.version}" + (f" ({c.date})" if c.date else "") + f": {c.summary}"
                for c in reversed(corpus.changelog)
            )
        ],
        "Pending contributions": [
            f"#### {q.id}\n\n- quarantined {q.date}: weakness class {q.weakness_class}; "
            f"rules: {', '.join(q.reasons)}; awaiting human review"
            for q in pending
        ],
    }
    parts = [
        "# Shared intelligence",
        "",
        f"knowledge_version: {corpus.knowledge_version}",
        f"page_schema: {PAGE_SCHEMA_VERSION}",
        "",
        "<!-- Generated by distill/shared_updater from memory/shared/corpus.json; do not edit.",
        "     Contains no tenant-identifying data. -->",
    ]
    for title in SHARED_SECTIONS:
        parts += ["", f"## {title}"]
        for block in body.get(title, []):
            if block:
                parts += ["", block]
    return "\n".join(parts).rstrip() + "\n"


# ---- storage -----------------------------------------------------------------------------


class Store:
    def __init__(self, memory_dir: Path = MEMORY_DIR):
        self.dir = memory_dir / "shared"
        self.page = memory_dir / "shared-intelligence.md"

    @property
    def corpus_path(self) -> Path:
        return self.dir / "corpus.json"

    def load(self) -> Corpus:
        if not self.corpus_path.exists():
            return Corpus()
        return Corpus.model_validate_json(self.corpus_path.read_text())

    def snapshot(self, version: str) -> Corpus:
        path = self.dir / "history" / f"{version}.json"
        if not path.exists():
            raise KeyError(f"no snapshot for knowledge_version {version}")
        return Corpus.model_validate_json(path.read_text())

    def save(self, corpus: Corpus, audit: list[dict[str, Any]]) -> None:
        text = corpus.model_dump_json(indent=2)
        (self.dir / "history").mkdir(parents=True, exist_ok=True)
        self.corpus_path.write_text(text + "\n")
        (self.dir / "history" / f"{corpus.knowledge_version}.json").write_text(text + "\n")
        self.page.write_text(render_shared(corpus))
        with (self.dir / "audit.jsonl").open("a") as f:
            for record in audit:
                f.write(json.dumps(record, default=str, sort_keys=True) + "\n")
