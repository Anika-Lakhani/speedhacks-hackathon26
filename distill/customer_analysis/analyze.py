"""Customer-analysis agent: a window of Keewano events + the current page -> a section patch.

Deterministic rules, no model. Overlapping or repeated windows are safe: every entry merges
with what the page already records (see `patch.py`), so the same events never count twice.

Events are untrusted data, including Dev A's `swarm.*` output. Only contract-validated,
enum-valued or pattern-checked fields reach the page, and every string is reduced to a safe
character set, so event content can't add headings, links or instructions to the page.
Scenario titles and invariants come from Dev A's catalog, not from event attrs.
"""

import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from attack.catalog import Catalog
from contracts import Event, EventValidationError, validate_event
from distill.customer_analysis.patch import Entry, Op, Patch, minimize, parse_entry, read_entries
from distill.pages import TAXONOMY

# Organic (event_type, policy_outcome) pairs that hint at a weakness class.
SIGNALS: dict[tuple[str, str], str] = {
    ("auth.login", "deny"): "missing_rate_limit",
    ("auth.password_reset", "flag"): "weak_reset_flow",
    ("order.view", "deny"): "idor",
    ("doc.view", "deny"): "bola",
    ("workspace.view", "deny"): "bola",
    ("role.change", "deny"): "missing_authz",
    ("integration.callback_register", "flag"): "ssrf",
    ("comment.create", "flag"): "output_encoding",
    ("post.create", "flag"): "output_encoding",
    ("upload.create", "deny"): "path_traversal",
}
HYPOTHESIS_MIN_EVENTS = 2
FAMILY = {c: family for family, classes in TAXONOMY.items() for c in classes}
LABEL_RANK = {"observed": 0, "hypothesized": 0, "reproduced": 1, "verified": 2}

_TOKEN = re.compile(r"[^A-Za-z0-9._:/{}@+=-]")
_TEXT = re.compile(r"[^A-Za-z0-9 ._:/{}@+=,'-]")


def clean(value: Any, limit: int = 80) -> str:
    """One token, safe for a page line and a tail value."""
    return _TOKEN.sub("", str(value))[:limit] or "-"


def clean_text(value: Any, limit: int = 200) -> str:
    """Free text (operator-supplied change summaries) without markdown or tail syntax."""
    return " ".join(_TEXT.sub("", str(value)).split())[:limit]


def ts(dt: datetime) -> str:
    """UTC with fixed-width microseconds, so string order is time order."""
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def ref(event_id: str) -> str:
    return clean(event_id)[:8]


def _words(value: str | None) -> list[str]:
    return value.split() if value else []


def _pairs(value: str | None) -> dict[str, str]:
    return dict(p.split("=", 1) for p in _words(value) if "=" in p)


def _join_pairs(d: dict[str, str]) -> str:
    return " ".join(f"{k}={v}" for k, v in sorted(d.items()))


@dataclass
class Change:
    """Code/config change metadata for one revision (from CI or the operator)."""

    revision: str
    summary: str = ""
    surfaces: list[str] = field(default_factory=list)


@dataclass
class Analysis:
    patch: Patch
    skipped: list[str]


def analyze(
    customer_id: str,
    raw_events: Iterable[Any],
    page_text: str,
    catalog: Catalog,
    *,
    changes: Iterable[Change] = (),
    approvals: Iterable[tuple[str, str]] = (),
) -> Analysis:
    """`approvals` holds approved (run_id, scenario_id) pairs from Dev A's approval queue."""
    events: list[Event] = []
    skipped: list[str] = []
    for raw in raw_events:
        try:
            event = validate_event(raw)
        except EventValidationError as e:
            skipped.append(f"invalid event: {str(e)[:120]}")
            continue
        if event.customer_id != customer_id:
            skipped.append(f"{ref(event.event_id)}: belongs to another tenant")
            continue
        events.append(event)
    events.sort(key=lambda e: (e.ts, e.event_id))
    run = _Run(customer_id, page_text, catalog, set(approvals))
    run.distill(events, list(changes))
    return Analysis(minimize(Patch(customer_id, run.ops), page_text), skipped)


class _Run:
    def __init__(self, customer_id, page_text, catalog, approvals):
        self.customer_id = customer_id
        self.view = read_entries(page_text)  # current state, updated as ops are added
        self.scenarios = {s.id: s for s in catalog.values() if s.customer_id == customer_id}
        self.approvals = approvals
        self.ops: list[Op] = []

    # ---- page state -------------------------------------------------------------------

    def get(self, section: int, key: str) -> Entry | None:
        line = self.view.get(section, {}).get(key)
        return parse_entry(line) if line else None

    def keys(self, section: int, prefix: str) -> list[str]:
        return [k for k in self.view.get(section, {}) if k.startswith(prefix)]

    def put(self, section: int, entry: Entry) -> None:
        line = entry.render()
        self.view.setdefault(section, {})[entry.key] = line
        self.ops.append(Op(section, entry.key, line))

    def field(self, name: str) -> str:
        line = self.view.get(1, {}).get(name, "")
        return line.partition(":")[2].strip()

    def put_field(self, name: str, value: str) -> None:
        line = f"- {name}: {value}"
        self.view.setdefault(1, {})[name] = line
        self.ops.append(Op(1, name, line))

    def remove(self, section: int, key: str) -> None:
        self.view.get(section, {}).pop(key, None)
        self.ops.append(Op(section, key, None))

    def last_checked(self, sid: str) -> str:
        """Time of the newest verdict the page records for a scenario."""
        entries = (self.get(5, f"F-{sid}"), self.get(8, f"DEF-{sid}"))
        return max((e.tail.get("at", "") for e in entries if e), default="")

    def scenario_text(self, sid: str) -> tuple[str, str, str, str]:
        """(title, weakness_class, invariant, probe path) from the catalog."""
        s = self.scenarios.get(sid)
        if s is None:
            return sid, "unknown", "unknown invariant", "-"
        return s.title, s.weakness_class, s.invariant, s.probe.path

    # ---- distillation -----------------------------------------------------------------

    def distill(self, events: list[Event], changes: list[Change]) -> None:
        verdicts = [e for e in events if e.event_type == "swarm.verdict" and e.scenario_id]
        self.environment(events)
        self.changes(events, changes)
        self.observations(events)
        self.findings(verdicts)
        self.approve_existing()
        self.runs(events)
        self.unverdicted_probes(events, verdicts)
        self.hypotheses(verdicts)
        self.defenses(verdicts)
        self.next_tests(changes)
        self.candidate_lessons()

    def environment(self, events: list[Event]) -> None:
        """§1: tested revision, last distilled event time, knowledge version in play."""
        if not events:
            return
        latest = events[-1]
        seen = self.field("last_distilled")
        if seen not in ("", "never") and seen >= ts(latest.ts):
            return  # an older window: don't move §1 backwards
        self.put_field("tested_revision", clean(latest.code_revision))
        self.put_field("last_distilled", ts(latest.ts))
        kv = [e.knowledge_version for e in events if e.knowledge_version]
        if kv:
            self.put_field("knowledge_version_seen", clean(kv[-1]))

    def changes(self, events: list[Event], changes: list[Change]) -> None:
        """§3: each code revision once, with change metadata when supplied."""
        meta = {clean(c.revision): c for c in changes}
        first: dict[str, str] = {}
        for e in events:
            first.setdefault(clean(e.code_revision), ts(e.ts))
        for rev in meta:
            first.setdefault(rev, "")
        for rev, at in first.items():
            key = f"REV-{rev}"
            entry = self.get(3, key) or Entry(key, "observed", f"code revision {rev}", {})
            if at and (not entry.tail.get("first") or at < entry.tail["first"]):
                entry.tail["first"] = at
            if rev in meta:
                change = meta[rev]
                summary = clean_text(change.summary)
                entry.text = f"code revision {rev}" + (f": {summary}" if summary else "")
                surfaces = " ".join(clean(s) for s in change.surfaces)
                if surfaces:
                    entry.tail["surfaces"] = surfaces
            self.put(3, entry)

    def observations(self, events: list[Event]) -> None:
        """§4: organic deny/flag events, grouped by type and outcome, with event refs."""
        groups: dict[tuple[str, str], list[Event]] = defaultdict(list)
        for e in events:
            if not e.simulated and e.policy_outcome in ("deny", "flag"):
                groups[(clean(e.event_type), str(e.policy_outcome))].append(e)
        for (etype, outcome), group in groups.items():
            key = f"OBS-{etype}-{outcome}"
            old = self.get(4, key)
            tail = old.tail if old else {}
            refs = sorted(set(_words(tail.get("events"))) | {ref(e.event_id) for e in group})
            targets = sorted(set(_words(tail.get("targets"))) | {clean(e.target) for e in group})
            times = [t for t in (tail.get("first"), tail.get("last")) if t]
            times += [ts(e.ts) for e in group]
            text = f"{len(refs)} {etype} events with outcome {outcome} on {', '.join(targets)}"
            self.put(
                4,
                Entry(
                    key,
                    "observed",
                    text,
                    {
                        "first": min(times),
                        "last": max(times),
                        "targets": " ".join(targets),
                        "events": " ".join(refs),
                    },
                ),
            )

    def findings(self, verdicts: list[Event]) -> None:
        """§5: one entry per scenario, following its latest verdict. Contradictions stay."""
        for e in verdicts:
            sid = clean(e.scenario_id)
            key, at, rev, run_id = f"F-{sid}", ts(e.ts), clean(e.code_revision), clean(e.run_id)
            old = self.get(5, key)
            if old and old.tail.get("at", "") >= at:
                continue  # already distilled this or a newer verdict
            attrs = e.attrs or {}
            if e.verdict == "confirmed":
                label = attrs.get("evidence_label")
                label = label if label in ("reproduced", "verified") else "reproduced"
                runs = sorted(set(_words(old.tail.get("confirmations") if old else "")) | {run_id})
                if old and LABEL_RANK.get(old.label, 0) > LABEL_RANK[label]:
                    label = old.label
                tail = {
                    "status": "open",
                    "confirmed_rev": rev,
                    "rev": rev,
                    "run": run_id,
                    "at": at,
                    "confirmations": " ".join(runs),
                    "evidence": clean(e.evidence_ref, 160),
                }
                self.put(5, self._finding(sid, label, tail))
            elif e.verdict == "not_reproduced" and old:
                tail = dict(old.tail, rev=rev, run=run_id, at=at)
                tail["status"] = "contradicted" if old.tail.get("confirmed_rev") == rev else "fixed"
                self.put(5, self._finding(sid, old.label, tail))
            # inconclusive / blocked never change a finding; a missing signal is not a pass

    def _finding(self, sid: str, label: str, tail: dict[str, str]) -> Entry:
        title, cls, invariant, _ = self.scenario_text(sid)
        severity = self.scenarios[sid].severity if sid in self.scenarios else "unknown"
        status = {
            "open": f"open at rev {tail['rev']}",
            "fixed": f"held at rev {tail['rev']}, fixed",
            "contradicted": f"not reproduced at the same rev {tail['rev']}: contradictory, "
            "investigate",
        }[tail["status"]]
        text = f"{sid} {title} ({cls}, {severity}): invariant '{invariant}' violated; {status}"
        return Entry(f"F-{sid}", label, text, tail)

    def approve_existing(self) -> None:
        """Promote reproduced findings to verified once a human approved one of their runs."""
        for key in self.keys(5, "F-"):
            entry = self.get(5, key)
            sid = key.removeprefix("F-")
            runs = _words(entry.tail.get("confirmations"))
            if entry.label == "reproduced" and any((r, sid) in self.approvals for r in runs):
                self.put(5, self._finding(sid, "verified", entry.tail))

    def runs(self, events: list[Event]) -> None:
        """§7: one entry per swarm run, blocked and successful alike."""
        by_run: dict[str, list[Event]] = defaultdict(list)
        for e in events:
            if e.simulated and e.run_id:
                by_run[clean(e.run_id)].append(e)
        for run_id, group in by_run.items():
            key = f"RUN-{run_id}"
            old = self.get(7, key)
            tail = dict(old.tail) if old else {}
            verdicts = _pairs(tail.get("verdicts"))
            probes = _pairs(tail.get("probes"))
            times = [t for t in [tail.get("at")] if t] + [ts(e.ts) for e in group]
            for e in group:
                attrs = e.attrs or {}
                if e.event_type == "swarm.verdict" and e.scenario_id:
                    verdicts[clean(e.scenario_id)] = str(e.verdict)
                elif e.event_type == "probe.result" and e.scenario_id:
                    probes[clean(e.scenario_id)] = str(e.policy_outcome)
                elif e.event_type == "swarm.plan":
                    tail["planner"] = clean(attrs.get("planner", "-"))
                elif e.event_type == "swarm.run_end":
                    tail["stop"] = clean(attrs.get("stop_reason", "-"))
            tail.update(
                at=min(times),
                rev=clean(group[-1].code_revision),
                verdicts=_join_pairs(verdicts),
                probes=_join_pairs(probes),
            )
            kv = [e.knowledge_version for e in group if e.knowledge_version]
            if kv:
                tail["knowledge"] = clean(kv[-1])
            if verdicts:
                counts: dict[str, int] = defaultdict(int)
                for v in verdicts.values():
                    counts[v] += 1
                summary = ", ".join(f"{n} {v}" for v, n in sorted(counts.items()))
            else:
                vulnerable = sum(1 for o in probes.values() if o == "allow")
                summary = f"{len(probes)} probes, {vulnerable} vulnerable responses, no verdicts"
            self.put(7, Entry(key, "observed", f"run on rev {tail['rev']}: {summary}", tail))

    def unverdicted_probes(self, events: list[Event], verdicts: list[Event]) -> None:
        """§6: a vulnerable probe response with no verdict is a lead, not a finding."""
        judged = {(e.run_id, e.scenario_id) for e in verdicts}
        for e in events:
            if (
                e.event_type != "probe.result"
                or e.policy_outcome != "allow"
                or (e.run_id, e.scenario_id) in judged
            ):
                continue
            sid, at = clean(e.scenario_id), ts(e.ts)
            if self.last_checked(sid) >= at:
                continue
            key = f"PRB-{sid}"
            old = self.get(6, key)
            if old and old.tail.get("at", "") >= at:
                continue
            text = f"probe {sid} got the vulnerable response; no verdict recorded yet"
            tail = {"run": clean(e.run_id), "at": at, "evidence": clean(e.evidence_ref, 160)}
            self.put(6, Entry(key, "observed", text, tail))
        for key in self.keys(6, "PRB-"):
            if self.last_checked(key.removeprefix("PRB-")) >= self.get(6, key).tail.get("at", ""):
                self.remove(6, key)

    def hypotheses(self, verdicts: list[Event]) -> None:
        """§6: weakness classes suggested by organic signals, and what testing showed."""
        by_class: dict[str, list[Entry]] = defaultdict(list)
        for key in self.keys(4, "OBS-"):
            entry = self.get(4, key)
            etype, _, outcome = key.removeprefix("OBS-").rpartition("-")
            cls = SIGNALS.get((etype, outcome))
            if cls:
                by_class[cls].append(entry)
        latest: dict[str, Event] = {}
        for e in verdicts:
            if e.verdict in ("confirmed", "not_reproduced"):
                _, cls, _, _ = self.scenario_text(clean(e.scenario_id))
                latest[cls] = e
        for cls, entries in by_class.items():
            count = sum(len(_words(x.tail.get("events"))) for x in entries)
            if count < HYPOTHESIS_MIN_EVENTS:
                continue
            key = f"HYP-{cls}"
            old = self.get(6, key)
            tail = dict(old.tail) if old else {"status": "open"}
            tail["signals"] = " ".join(sorted(x.key for x in entries))
            tail["since"] = max(x.tail.get("last", "") for x in entries)
            e = latest.get(cls)
            if e and ts(e.ts) > tail.get("at", ""):
                tail.update(status=str(e.verdict), scenario=clean(e.scenario_id), at=ts(e.ts))
            status = {
                "open": "untested",
                "confirmed": f"confirmed by {tail.get('scenario')}, see section 5",
                "not_reproduced": f"not reproduced by {tail.get('scenario')}; keep watching",
            }[tail["status"]]
            label = "reproduced" if tail["status"] == "confirmed" else "hypothesized"
            text = f"possible {cls}: {count} unusual events; {status}"
            self.put(6, Entry(key, label, text, tail))

    def defenses(self, verdicts: list[Event]) -> None:
        """§8: regression tests for findings; invariants observed holding."""
        for key in self.keys(5, "F-"):
            finding = self.get(5, key)
            sid = key.removeprefix("F-")
            _, _, invariant, path = self.scenario_text(sid)
            passing = finding.tail.get("status") == "fixed"
            state = f"passing since rev {finding.tail.get('rev')}" if passing else "failing"
            text = f"regression test: rerun {sid} on any change to {path}; {state}"
            tail = {"status": "passing" if passing else "failing", "guards": key}
            self.put(8, Entry(f"REG-{sid}", "observed", text, tail))
        for e in verdicts:
            sid, at = clean(e.scenario_id), ts(e.ts)
            if e.verdict != "not_reproduced" or self.get(5, f"F-{sid}"):
                continue
            key = f"DEF-{sid}"
            old = self.get(8, key)
            if old and old.tail.get("at", "") >= at:
                continue
            _, _, invariant, _ = self.scenario_text(sid)
            rev = clean(e.code_revision)
            text = f"invariant '{invariant}' held against {sid} at rev {rev}"
            self.put(8, Entry(key, "observed", text, {"run": clean(e.run_id), "at": at}))

    def next_tests(self, changes: list[Change]) -> None:
        """§9: scenarios worth running next, and coverage gaps. Resolved once tested."""
        wanted: dict[str, tuple[str, str]] = {}  # sid -> (reason, since)
        gaps: dict[str, tuple[str, str]] = {}
        for key in self.keys(6, "HYP-"):
            hyp = self.get(6, key)
            if hyp.tail.get("status") != "open":
                continue
            cls = key.removeprefix("HYP-")
            sids = [s.id for s in self.scenarios.values() if s.weakness_class == cls]
            for sid in sids:
                wanted[sid] = (f"organic signals suggest {cls}", hyp.tail.get("since", ""))
            if not sids:
                gaps[cls] = (hyp.text, hyp.tail.get("since", ""))
        for change in changes:
            rev = clean(change.revision)
            entry = self.get(3, f"REV-{rev}")
            since = entry.tail.get("first", "") if entry else ""
            for sid, s in self.scenarios.items():
                base = s.probe.path.split("{")[0].rstrip("/")
                if base and any(clean(x).rstrip("/").startswith(base) for x in change.surfaces):
                    wanted[sid] = (f"rev {rev} changed {base}", since)
        for sid, (reason, since) in wanted.items():
            if self.last_checked(sid) < since or not since:
                title = self.scenario_text(sid)[0]
                text = f"run {sid} {title}: {reason}"
                self.put(9, Entry(f"NEXT-{sid}", "hypothesized", text, {"since": since}))
        for cls, (why, since) in gaps.items():
            text = f"no catalog scenario covers {cls}; ask Dev A for one. Seen: {why}"
            self.put(9, Entry(f"GAP-{cls}", "hypothesized", text, {"since": since}))
        for key in self.keys(9, "NEXT-"):
            since = self.get(9, key).tail.get("since", "")
            if since and self.last_checked(key.removeprefix("NEXT-")) >= since:
                self.remove(9, key)

    def candidate_lessons(self) -> None:
        """§10: one candidate per weakness class with a confirmed finding. A human sets
        `sharing: approved`; the shared updater reads only approved candidates."""
        by_class: dict[str, list[Entry]] = defaultdict(list)
        for key in self.keys(5, "F-"):
            entry = self.get(5, key)
            by_class[self.scenario_text(key.removeprefix("F-"))[1]].append(entry)
        for cls, findings in by_class.items():
            key = f"CL-{cls}"
            old = self.get(10, key)
            sharing = old.tail.get("sharing", "proposed") if old else "proposed"
            if any(f.tail.get("status") == "contradicted" for f in findings):
                sharing = "hold"  # contradictory evidence never leaves the tenant
            elif sharing == "hold":
                sharing = "proposed"
            sids = sorted(f.key.removeprefix("F-") for f in findings)
            runs = {r for f in findings for r in _words(f.tail.get("confirmations"))}
            label = max((f.label for f in findings), key=lambda x: LABEL_RANK.get(x, 0))
            title, _, invariant, _ = self.scenario_text(sids[0])
            text = (
                f"{cls} in family {FAMILY.get(cls, 'unclassified')}: invariant '{invariant}' "
                f"was violated; suggested test: {title}"
            )
            tail = {
                "sharing": sharing,
                "class": cls,
                "scenarios": " ".join(sids),
                "confirmations": str(len(runs)),
            }
            self.put(10, Entry(key, label, text, tail))
