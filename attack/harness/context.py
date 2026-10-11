"""Reads Dev C's memory files (customer page and shared intelligence) for the planner."""

import re
from pathlib import Path

from attack.agent.models import SharedLesson
from attack.catalog import Catalog

MEMORY_DIR = Path(__file__).resolve().parents[2] / "memory"
# customer-X.md sections the planner sees (overview §5.4): invariants, changes, events,
# prior runs, next tests.
WANTED_SECTIONS = {2, 3, 4, 7, 9}
_HEADING = re.compile(r"^#{1,3}\s*(?:§\s*)?(\d+)[.:)]?\s*(.*)$")
_VERSION = re.compile(r"knowledge_version[\s:=`\"']*([\w.\-]+)", re.IGNORECASE)
_PLACEHOLDER = re.compile(r"^_[^_\n]*_\.?$")
_SECRET = re.compile(
    r"(?i)((?:api[_-]?key|secret|token|passw(?:or)?d|authorization|bearer)\w*[\"']?\s*[:=]\s*)"
    r"[\"']?[^\s\"',;]{6,}[\"']?"
)
MAX_FILE_CHARS = 6000
MAX_CODE_CHARS = 20000


def read_customer_sections(customer_id: str, memory_dir: Path = MEMORY_DIR) -> dict[str, str]:
    path = memory_dir / "customers" / f"{customer_id}.md"
    if not path.exists():
        return {}
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in path.read_text().splitlines():
        m = _HEADING.match(line)
        if m:
            current = f"{m[1]}. {m[2]}".strip() if int(m[1]) in WANTED_SECTIONS else None
            if current:
                sections[current] = []
        elif current:
            sections[current].append(line)
    out = {k: "\n".join(v).strip() for k, v in sections.items()}
    # Dev C's skeleton pages hold only italic placeholders like `_Not yet distilled._`.
    return {k: v for k, v in out.items() if v and not _PLACEHOLDER.match(v)}


def _shared_text(memory_dir: Path) -> str:
    path = memory_dir / "shared-intelligence.md"
    return path.read_text() if path.exists() else ""


def read_knowledge_version(memory_dir: Path = MEMORY_DIR) -> str:
    m = _VERSION.search(_shared_text(memory_dir))
    return m[1] if m else "0.0.0"


def read_shared_lessons(
    customer_id: str, catalog: Catalog, memory_dir: Path = MEMORY_DIR
) -> list[SharedLesson]:
    """Lessons are `### <id>` chunks; keep those whose `applicability:` line is empty/'any'
    or names a weakness class or surface this customer actually has."""
    classes = {s.weakness_class for s in catalog.values() if s.customer_id == customer_id}
    lessons: list[SharedLesson] = []
    for chunk in re.split(r"^### ", _shared_text(memory_dir), flags=re.MULTILINE)[1:]:
        title, _, body = chunk.partition("\n")
        app = re.search(r"applicability\s*:\s*(.*)", body, re.IGNORECASE)
        cond = app[1].lower() if app else ""
        if not cond or "any" in cond or "all" in cond or any(c in cond for c in classes):
            lessons.append(SharedLesson(id=title.strip(), text=" ".join(body.split())[:600]))
    return lessons


def redact(text: str) -> str:
    """Mask obvious credentials before any text is sent to an external model."""
    return _SECRET.sub(r"\1[REDACTED]", text)


def read_code_context(paths: list[str]) -> dict[str, str]:
    """Read source files for the generator: redacted, per-file and total size capped."""
    out: dict[str, str] = {}
    budget = MAX_CODE_CHARS
    for raw in paths:
        path = Path(raw)
        if not path.is_file() or budget <= 0:
            continue
        text = redact(path.read_text(errors="replace"))[: min(MAX_FILE_CHARS, budget)]
        out[raw] = text
        budget -= len(text)
    return out


_EVENT_KEYS = (
    "ts",
    "actor",
    "event_type",
    "target",
    "action",
    "policy_outcome",
    "state_transition",
    "scenario_id",
    "verdict",
)


def summarize_events(events: list[dict], limit: int = 40) -> list[dict]:
    """Keep only the fields useful for reasoning; drop attrs, ids and evidence refs."""
    return [{k: e[k] for k in _EVENT_KEYS if e.get(k) is not None} for e in events[-limit:]]
