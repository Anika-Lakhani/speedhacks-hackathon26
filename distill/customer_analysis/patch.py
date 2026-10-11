"""Keyed section patches for `customer-X.md`.

An entry is one bullet line with a stable key: `` - `KEY` [label] text (field: value, ...) ``,
or a plain `- name: value` field line (§1). A patch upserts or removes entries by key inside one
section and leaves every other line on the page alone, so applying the same patch twice is a
no-op. The trailing `(field: value, ...)` tail holds the state the analyzer merges on its next
pass (event refs, run, revision, time); list values are space-separated.
"""

import difflib
import re
from dataclasses import dataclass, field

_HEADING = re.compile(r"^##\s+(\d+)\.\s")
_KEYED = re.compile(r"^- `([^`]+)`")
_FIELD = re.compile(r"^- ([a-z_]+):")
_ENTRY = re.compile(
    r"^- `(?P<key>[^`]+)` \[(?P<label>[a-z_]+)\] (?P<text>.*?)"
    r"(?: \((?P<tail>[a-z_]+: [^()]*)\))?$"
)


@dataclass(frozen=True)
class Op:
    section: int
    key: str
    line: str | None  # None removes the entry


@dataclass
class Patch:
    customer_id: str
    ops: list[Op] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.ops)

    def sections(self) -> list[int]:
        return sorted({o.section for o in self.ops})


@dataclass
class Entry:
    key: str
    label: str
    text: str
    tail: dict[str, str] = field(default_factory=dict)

    def render(self) -> str:
        tail = ", ".join(f"{k}: {v}" for k, v in self.tail.items() if v)
        return f"- `{self.key}` [{self.label}] {self.text}" + (f" ({tail})" if tail else "")


def line_key(line: str) -> str | None:
    m = _KEYED.match(line) or _FIELD.match(line)
    return m[1] if m else None


def parse_entry(line: str) -> Entry | None:
    m = _ENTRY.match(line)
    if not m:
        return None
    tail = {}
    for part in (m["tail"] or "").split(", "):
        k, _, v = part.partition(": ")
        if k:
            tail[k] = v
    return Entry(m["key"], m["label"], m["text"], tail)


def _spans(lines: list[str]) -> dict[int, tuple[int, int]]:
    """Section number -> [start, end) line range of its body."""
    heads = [(i, int(m[1])) for i, line in enumerate(lines) if (m := _HEADING.match(line))]
    return {
        n: (i + 1, heads[j + 1][0] if j + 1 < len(heads) else len(lines))
        for j, (i, n) in enumerate(heads)
    }


def read_entries(text: str) -> dict[int, dict[str, str]]:
    """Section number -> {key: line} for every keyed line on the page."""
    lines = text.splitlines()
    return {
        n: {k: line for line in lines[a:b] if (k := line_key(line))}
        for n, (a, b) in _spans(lines).items()
    }


def minimize(patch: Patch, text: str) -> Patch:
    """Drop ops that would not change the page."""
    entries = read_entries(text)
    ops = [
        op
        for op in patch.ops
        if entries.get(op.section, {}).get(op.key) != op.line
        and not (op.line is None and op.key not in entries.get(op.section, {}))
    ]
    return Patch(patch.customer_id, ops)


def apply_patch(text: str, patch: Patch) -> str:
    lines = text.splitlines()
    for section in patch.sections():
        spans = _spans(lines)
        if section not in spans:
            raise KeyError(f"page has no section {section}")
        a, b = spans[section]
        body = lines[a:b]
        for op in (o for o in patch.ops if o.section == section):
            idx = next((i for i, line in enumerate(body) if line_key(line) == op.key), None)
            if op.line is None:
                if idx is not None:
                    del body[idx]
            elif idx is not None:
                body[idx] = op.line
            else:
                last = max((i for i, line in enumerate(body) if line.strip()), default=-1)
                body.insert(last + 1, op.line)
        while body and not body[0].strip():
            body.pop(0)
        while body and not body[-1].strip():
            body.pop()
        lines[a:b] = ["", *body, ""] if body else ["", ""]
    return "\n".join(lines).rstrip() + "\n"


def render_diff(before: str, after: str, name: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{name}",
            tofile=f"b/{name}",
        )
    )
