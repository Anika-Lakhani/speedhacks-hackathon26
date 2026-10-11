"""Shared updater: eligibility, privacy, merge, evidence gate, audit, quarantine, rollback."""

import json
from datetime import date

import pytest

from attack.harness import context as a_context
from distill.customer_analysis.analyze import analyze
from distill.customer_analysis.patch import apply_patch
from distill.privacy.provenance import source_token
from distill.privacy.scanners import scan
from distill.scaffold import scaffold
from distill.shared_updater import lessons
from distill.shared_updater.__main__ import main as cli
from distill.shared_updater.corpus import Corpus, Store, render_shared
from distill.shared_updater.update import (
    Candidate,
    Contribution,
    contribute,
    read_candidates,
    retract,
    rollback,
)
from tests.distill.test_customer_analysis import swarm_run

TODAY = date(2026, 10, 11)
SALT = b"test-salt"
A, B = source_token("customer-a", SALT), source_token("customer-b", SALT)
OBJ = "SI-object_access_authz"


def cand(cls="idor", label="reproduced", confirmations=1, sharing="approved", extra=""):
    line = (
        f"- `CL-{cls}` [{label}] {cls} lesson{extra} "
        f"(sharing: {sharing}, class: {cls}, confirmations: {confirmations})"
    )
    return Candidate(f"CL-{cls}", cls, label, confirmations, sharing, line)


def run(*contribs, corpus=None):
    return contribute(corpus or Corpus(), list(contribs), TODAY)


# ---- eligibility -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "candidate",
    [
        cand(sharing="proposed"),
        cand(sharing="hold"),
        cand(label="hypothesized"),
        cand(confirmations=0),
    ],
)
def test_ineligible_candidates_change_nothing(candidate):
    out = run(Contribution(A, candidate))
    assert not out.changed and out.corpus == Corpus()


def test_reads_only_section_10():
    page = scaffold_page()
    secret = "password=hunter2! jane.doe@example.com"
    page = page.replace(
        "## 5. Confirmed findings & evidence\n",
        f"## 5. Confirmed findings & evidence\n\n- {secret}\n",
    )
    page = page.replace(
        "## 4. Observed events & notable sequences\n",
        f"## 4. Observed events & notable sequences\n\n- {secret}\n",
    )
    page = page.rstrip() + "\n\n" + cand().line + "\n"
    candidates = read_candidates(page)
    assert [c.key for c in candidates] == ["CL-idor"]
    out = run(*(Contribution(A, c) for c in candidates))
    assert [r["action"] for r in out.audit] == ["add"] and not out.corpus.quarantine


# ---- privacy -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "planted", [" AKIAIOSFODNN7EXAMPLE", " token=abc123secret", " mail jane.doe@example.com"]
)
def test_candidate_with_planted_secret_or_pii_is_quarantined(planted):
    out = run(Contribution(A, cand(extra=planted)))
    assert out.corpus.items == {}
    assert len(out.corpus.quarantine) == 1 and out.audit[0]["action"] == "quarantine"
    page = render_shared(out.corpus)
    assert planted.strip() not in page and planted.strip() not in json.dumps(out.audit, default=str)
    assert "#### Q-" in page  # waits for review, invisible to the planner


def test_unknown_class_is_quarantined():
    out = run(Contribution(A, cand(cls="quantum_tunnel")))
    assert out.corpus.quarantine[0].reasons == ["unknown_weakness_class"]


def test_rendered_item_failing_a_gate_is_blocked(monkeypatch):
    leaky = lessons.LESSONS[OBJ].__class__(
        **{**lessons.LESSONS[OBJ].__dict__, "test": "GET /orders/1002 as another user"}
    )
    monkeypatch.setitem(lessons.LESSONS, OBJ, leaky)
    out = run(Contribution(A, cand()))
    assert out.corpus.items == {} and out.audit[0]["action"] == "blocked"


def test_corpus_and_audit_never_name_a_tenant(tmp_path, catalog):
    memory = end_to_end(tmp_path, catalog)
    for path in [memory / "shared-intelligence.md", *(memory / "shared").rglob("*.json*")]:
        text = path.read_text()
        assert "customer-" not in text, path
    assert cli(["--memory-dir", str(memory), "audit"]) == 0


# ---- merge and evidence gate -------------------------------------------------------------


def test_same_weakness_from_two_tenants_merges_into_one_item():
    out = run(Contribution(A, cand("idor")), Contribution(B, cand("bola")))
    assert list(out.corpus.items) == [OBJ]
    item = out.corpus.items[OBJ]
    assert item.version == 2 and len(item.sources) == 2 and item.confidence == "high"
    assert out.corpus.knowledge_version == "0.2.0"


def test_repeat_contribution_is_a_no_op():
    first = run(Contribution(A, cand()))
    again = run(Contribution(A, cand()), corpus=first.corpus)
    assert not again.changed and again.corpus.knowledge_version == "0.2.0"


def test_single_report_stays_low_and_cannot_reach_verified():
    item = run(Contribution(A, cand(label="verified"))).corpus.items[OBJ]
    assert (item.evidence_level, item.confidence) == ("reproduced", "low")


def test_twice_reproduced_verified_report_can_reach_verified():
    item = run(Contribution(A, cand(label="verified", confirmations=2))).corpus.items[OBJ]
    assert (item.evidence_level, item.confidence) == ("verified", "medium")
    assert "Verified mitigation" in render_shared(
        run(Contribution(A, cand(label="verified", confirmations=2))).corpus
    )


def test_every_change_has_an_audit_record_with_evidence_and_policy():
    out = run(Contribution(A, cand()))
    (record,) = out.audit
    assert record["policy"] == "shared-policy/1"
    assert record["evidence"] == {
        "weakness_class": "idor",
        "label": "reproduced",
        "confirmations": 1,
        "source": A,
    }
    assert record["knowledge_version"] == "0.2.0"


# ---- lifecycle ---------------------------------------------------------------------------


def test_retracted_item_leaves_the_planner_and_is_not_revived(tmp_path, catalog):
    added = run(Contribution(A, cand()))
    out = retract(added.corpus, OBJ, "poisoned: contradicted on review", TODAY)
    store_page(tmp_path, out.corpus)
    assert a_context.read_shared_lessons("customer-b", catalog, tmp_path) == []
    assert "#### SI-object_access_authz" in render_shared(out.corpus)
    revived = run(Contribution(B, cand("bola")), corpus=out.corpus)
    assert revived.corpus.items[OBJ].status == "retracted"
    assert revived.corpus.quarantine[0].reasons == ["contributes_to_retracted_item"]


def test_retraction_reason_must_pass_privacy_gates():
    added = run(Contribution(A, cand()))
    with pytest.raises(ValueError):
        retract(added.corpus, OBJ, "customer-a reported it", TODAY)


def test_rollback_restores_an_earlier_version_as_a_new_one(tmp_path):
    store = Store(tmp_path)
    v2 = run(Contribution(A, cand()))
    store.save(v2.corpus, v2.audit)
    v3 = run(Contribution(B, cand("ssrf")), corpus=v2.corpus)
    store.save(v3.corpus, v3.audit)
    out = rollback(store.load(), store.snapshot("0.2.0"), TODAY)
    assert list(out.corpus.items) == [OBJ]
    assert out.corpus.knowledge_version == "0.4.0"
    assert out.corpus.changelog[-1].summary == "rollback to 0.2.0"
    store.save(out.corpus, out.audit)
    actions = [
        json.loads(x)["action"]
        for x in (tmp_path / "shared" / "audit.jsonl").read_text().splitlines()
    ]
    assert actions == ["add", "add", "rollback"]


# ---- end to end: a lesson from customer-a becomes a test for customer-b ----------------


def scaffold_page():
    from distill.pages import render_customer_scaffold

    return render_customer_scaffold("customer-a")


def store_page(memory, corpus):
    (memory / "shared-intelligence.md").write_text(render_shared(corpus))


def end_to_end(memory, catalog):
    scaffold(memory)
    page_path = memory / "customers" / "customer-a.md"
    events, _ = swarm_run(memory, catalog, idor_orders=True)
    result = analyze("customer-a", events, page_path.read_text(), catalog)
    page_path.write_text(apply_patch(page_path.read_text(), result.patch))
    assert (
        cli(["--memory-dir", str(memory), "approve", "--customer", "customer-a", "--class", "idor"])
        == 0
    )
    assert cli(["--memory-dir", str(memory), "update"]) == 0
    return memory


def test_lesson_from_customer_a_reaches_customer_b_planner(tmp_path, catalog):
    memory = end_to_end(tmp_path, catalog)
    assert a_context.read_knowledge_version(memory) == "0.2.0"
    for_b = a_context.read_shared_lessons("customer-b", catalog, memory)
    assert [x.id for x in for_b] == [OBJ]
    assert "Suggested test" in for_b[0].text and scan(for_b[0].text) == []
    assert a_context.read_shared_lessons("customer-c", catalog, memory) == []


def test_contradicted_candidate_cannot_be_approved(tmp_path, catalog):
    scaffold(tmp_path)
    page_path = tmp_path / "customers" / "customer-a.md"
    for flag in (True, False):
        events, _ = swarm_run(tmp_path, catalog, rev="rev-1", idor_orders=flag)
        result = analyze("customer-a", events, page_path.read_text(), catalog)
        page_path.write_text(apply_patch(page_path.read_text(), result.patch))
    assert (
        cli(
            [
                "--memory-dir",
                str(tmp_path),
                "approve",
                "--customer",
                "customer-a",
                "--class",
                "idor",
            ]
        )
        == 1
    )
