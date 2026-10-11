"""Shared updater: approved candidate lessons -> versioned, sanitized shared corpus.

The updater reads only §10 of each customer page (`read_candidates`), and `contribute` accepts
only `Contribution`s, so raw events and other page sections can't reach the corpus. Per
candidate (dev-C §3):

1. eligibility: `sharing: approved` and evidence `reproduced` or `verified`
2. sanitize: item text comes from a tenant-neutral template (`lessons.py`); the candidate
   supplies only its weakness class, evidence label and confirmation count
3. privacy gates: a candidate carrying secrets or PII is quarantined; the rendered item must
   pass every gate (secret, PII, tenant identifier, re-identification) or it is blocked
4. dedup/merge: one item per lesson; repeat contributions from a tenant replace, not add
5. evidence gate: one tenant's single confirmation stays `low` confidence; `verified` needs a
   human-verified source and at least two confirmations
6. audit: every change is recorded with minimized evidence and the authorizing policy
7. quarantine: suspicious or unknown contributions, and contributions to retired items, wait
   for human review instead of reaching the live corpus
"""

import hashlib
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Any

from distill.customer_analysis.analyze import clean, clean_text
from distill.customer_analysis.patch import parse_entry
from distill.pages import parse_customer_sections
from distill.privacy.scanners import scan
from distill.shared_updater.corpus import (
    ChangeLogEntry,
    Corpus,
    Item,
    Quarantined,
    Source,
    bump,
    render_item,
)
from distill.shared_updater.lessons import LESSON_FOR_CLASS

POLICY_ID = "shared-policy/1"
ELIGIBLE_LABELS = ("reproduced", "verified")
EXPIRY = timedelta(days=90)


@dataclass(frozen=True)
class Candidate:
    key: str
    weakness_class: str
    label: str
    confirmations: int
    sharing: str
    line: str  # the raw §10 line, scanned but never copied into the corpus


@dataclass(frozen=True)
class Contribution:
    source: str  # provenance token, never a tenant name
    candidate: Candidate


@dataclass
class Outcome:
    corpus: Corpus
    audit: list[dict[str, Any]] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.audit)


def read_candidates(page_text: str) -> list[Candidate]:
    """Candidate lessons from §10 only. Nothing else on the page is read."""
    out = []
    for line in parse_customer_sections(page_text).get(10, "").splitlines():
        entry = parse_entry(line)
        if not entry or not entry.key.startswith("CL-"):
            continue
        try:
            confirmations = int(entry.tail.get("confirmations", "0"))
        except ValueError:
            confirmations = 0
        out.append(
            Candidate(
                key=entry.key,
                weakness_class=entry.tail.get("class") or entry.key.removeprefix("CL-"),
                label=entry.label,
                confirmations=confirmations,
                sharing=entry.tail.get("sharing", ""),
                line=line,
            )
        )
    return out


def _record(action: str, today: date, **fields: Any) -> dict[str, Any]:
    return {"action": action, "date": today, "policy": POLICY_ID, **fields}


def _evidence(sources: dict[str, Source]) -> tuple[str, str]:
    """(evidence_level, confidence) from all sources of an item."""
    total = sum(s.confirmations for s in sources.values())
    verified = any(s.label == "verified" for s in sources.values())
    level = "verified" if verified and total >= 2 else "reproduced"
    if len(sources) >= 2:
        confidence = "high"  # independently reproduced in two environments
    elif total >= 2:
        confidence = "medium"
    else:
        confidence = "low"
    return level, confidence


def _finish(corpus: Corpus, audit: list[dict[str, Any]], today: date, summary: str) -> Outcome:
    if not audit:
        return Outcome(corpus)
    corpus.knowledge_version = bump(corpus.knowledge_version)
    corpus.changelog.append(
        ChangeLogEntry(version=corpus.knowledge_version, date=today, summary=summary)
    )
    for record in audit:
        record["knowledge_version"] = corpus.knowledge_version
    return Outcome(corpus, audit)


def _merge(corpus: Corpus, contrib: Contribution, today: date) -> dict[str, Any] | None:
    """Merge one eligible, scanned contribution into its item. Returns the audit record, or
    None when it adds nothing. An expired item comes back only on changed evidence."""
    c = contrib.candidate
    lesson = LESSON_FOR_CLASS[c.weakness_class]
    item = corpus.items.get(lesson.id)
    source = Source(label=c.label, confirmations=c.confirmations)
    if item and item.sources.get(contrib.source) == source:
        return None  # nothing new from this tenant (an unchanged page can't revive an item)
    sources = {**(item.sources if item else {}), contrib.source: source}
    level, confidence = _evidence(sources)
    merged = Item(
        id=lesson.id,
        version=item.version + 1 if item else 1,
        status="active",
        evidence_level=level,
        confidence=confidence,
        applicability=list(lesson.classes),
        last_validation=today,
        expiry=today + EXPIRY,
        sources=sources,
    )
    hits = sorted({f"{h.kind}:{h.rule}" for h in scan(render_item(merged))})
    if hits:
        return _record("blocked", today, item=lesson.id, reasons=hits)
    action = "add" if item is None else "revalidate" if item.status == "expired" else "merge"
    corpus.items[lesson.id] = merged
    return _record(
        action,
        today,
        item=lesson.id,
        item_version=merged.version,
        evidence={
            "weakness_class": c.weakness_class,
            "label": c.label,
            "confirmations": c.confirmations,
            "source": contrib.source,
        },
        result={"evidence_level": level, "confidence": confidence},
    )


def _expire(corpus: Corpus, today: date) -> list[dict[str, Any]]:
    """Active items past their expiry stop reaching the planner until revalidated."""
    audit = []
    for item in corpus.items.values():
        if item.status == "active" and item.expiry < today:
            item.status, item.version = "expired", item.version + 1
            item.note = f"expired {item.expiry}; awaiting fresh evidence"
            audit.append(_record("expire", today, item=item.id, item_version=item.version))
    return audit


def _summary(audit: list[dict[str, Any]], fallback: str) -> str:
    return "; ".join(f"{r['action']} {r['item']}" for r in audit if r["action"] != "blocked") or (
        fallback
    )


def contribute(corpus: Corpus, contributions: list[Contribution], today: date) -> Outcome:
    corpus = corpus.model_copy(deep=True)
    audit = _expire(corpus, today)
    queued = {q.id for q in corpus.quarantine}

    def quarantine(contrib: Contribution, reasons: list[str]) -> None:
        c = contrib.candidate
        digest = hashlib.sha256(f"{contrib.source}|{c.line}".encode()).hexdigest()[:10]
        qid = f"Q-{digest}"
        if qid in queued:
            return  # already queued, released or rejected: a human has it
        queued.add(qid)
        corpus.quarantine.append(
            Quarantined(
                id=qid,
                weakness_class=clean(c.weakness_class, 40),
                source=contrib.source,
                candidate_key=clean(c.key, 60),
                reasons=reasons,
                date=today,
            )
        )
        audit.append(_record("quarantine", today, item=qid, reasons=reasons, source=contrib.source))

    for contrib in contributions:
        c = contrib.candidate
        if c.sharing != "approved" or c.label not in ELIGIBLE_LABELS or c.confirmations < 1:
            continue
        lesson = LESSON_FOR_CLASS.get(c.weakness_class)
        reasons = sorted({h.rule for h in scan(c.line, kinds=("secret", "pii"))})
        if lesson is None:
            reasons.append("unknown_weakness_class")
        if reasons:
            quarantine(contrib, reasons)
            continue
        item = corpus.items.get(lesson.id)
        if item and item.status in ("retracted", "superseded"):
            quarantine(contrib, [f"contributes_to_{item.status}_item"])
            continue
        if record := _merge(corpus, contrib, today):
            audit.append(record)

    return _finish(corpus, audit, today, _summary(audit, "blocked contributions only"))


def pending_review(corpus: Corpus) -> list[Quarantined]:
    return [q for q in corpus.quarantine if q.status == "pending_review"]


def release(corpus: Corpus, qid: str, contrib: Contribution, note: str, today: date) -> Outcome:
    """A human judged a quarantined contribution safe (e.g. a scanner false positive). It is
    merged through the normal path, so the rendered item still has to pass every gate."""
    corpus = corpus.model_copy(deep=True)
    q = _pending(corpus, qid)
    c = contrib.candidate
    if (contrib.source, clean(c.key, 60)) != (q.source, q.candidate_key):
        raise ValueError(f"{qid} came from a different contribution")
    if "unknown_weakness_class" in q.reasons or c.weakness_class not in LESSON_FOR_CLASS:
        raise ValueError(f"{qid} has no lesson template for its weakness class; reject it")
    if any(r.startswith("contributes_to_") for r in q.reasons):
        raise ValueError(f"{qid} targets a retired item; it can't be released into it")
    item = corpus.items.get(LESSON_FOR_CLASS[c.weakness_class].id)
    if item and item.status in ("retracted", "superseded"):
        raise ValueError(f"{qid} targets a {item.status} item; it can't be released into it")
    note = _safe_note(note)
    record = _merge(corpus, contrib, today)
    if record and record["action"] == "blocked":
        raise ValueError(f"{qid} would render an item that fails the privacy gates")
    q.status = "released"
    audit = [_record("release", today, item=qid, note=note)]
    if record:
        audit.append(record)
    return _finish(corpus, audit, today, _summary(audit, f"release {qid}"))


def reject(corpus: Corpus, qid: str, note: str, today: date) -> Outcome:
    corpus = corpus.model_copy(deep=True)
    q = _pending(corpus, qid)
    q.status = "rejected"
    audit = [_record("reject", today, item=qid, note=_safe_note(note))]
    return _finish(corpus, audit, today, f"reject {qid}")


def _pending(corpus: Corpus, qid: str) -> Quarantined:
    for q in corpus.quarantine:
        if q.id == qid and q.status == "pending_review":
            return q
    raise KeyError(f"nothing pending review with id {qid}")


def _safe_note(note: str) -> str:
    note = clean_text(note, 160)
    if hits := scan(note):
        raise ValueError(f"note fails privacy gates: {sorted({h.rule for h in hits})}")
    return note


def supersede(corpus: Corpus, old_id: str, new_id: str, reason: str, today: date) -> Outcome:
    """Replace an active item with another active one, keeping the old one for the record."""
    corpus = corpus.model_copy(deep=True)
    old, new = corpus.items.get(old_id), corpus.items.get(new_id)
    if old is None or old.status != "active":
        raise KeyError(f"no active item {old_id}")
    if new is None or new.status != "active" or new_id == old_id:
        raise KeyError(f"{new_id} must be a different active item")
    reason = _safe_note(reason)
    old.status, old.version = "superseded", old.version + 1
    old.note = f"superseded by {new_id}: {reason}"
    audit = [
        _record("supersede", today, item=old_id, item_version=old.version, by=new_id, reason=reason)
    ]
    return _finish(corpus, audit, today, f"supersede {old_id} by {new_id}")


def retract(corpus: Corpus, item_id: str, reason: str, today: date) -> Outcome:
    """Pull a poisoned or wrong item out of the live corpus. Later contributions to it are
    quarantined rather than reviving it."""
    corpus = corpus.model_copy(deep=True)
    item = corpus.items.get(item_id)
    if item is None or item.status not in ("active", "expired"):
        raise KeyError(f"no active or expired item {item_id}")
    reason = _safe_note(reason)
    item.status, item.note, item.version = "retracted", reason, item.version + 1
    audit = [_record("retract", today, item=item_id, item_version=item.version, reason=reason)]
    return _finish(corpus, audit, today, f"retract {item_id}")


def rollback(current: Corpus, snapshot: Corpus, today: date) -> Outcome:
    """Restore the items of an earlier version as a new version. History is never rewritten;
    quarantine is kept as is."""
    corpus = snapshot.model_copy(deep=True)
    corpus.knowledge_version = current.knowledge_version
    corpus.changelog = list(current.changelog)
    corpus.quarantine = list(current.quarantine)
    audit = [_record("rollback", today, item="*", restored=snapshot.knowledge_version)]
    return _finish(corpus, audit, today, f"rollback to {snapshot.knowledge_version}")
