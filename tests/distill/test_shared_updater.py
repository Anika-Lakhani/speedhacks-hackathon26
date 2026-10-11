"""Shared updater: eligibility, privacy, merge, evidence gate, audit, quarantine, rollback."""

import json
from datetime import date, timedelta

import pytest

from attack.harness import context as a_context
from distill.customer_analysis.analyze import analyze
from distill.customer_analysis.patch import Op, Patch, apply_patch
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
    reject,
    release,
    retract,
    rollback,
    supersede,
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


# ---- expiry, quarantine review, supersession ---------------------------------------------


LATER = TODAY + timedelta(days=91)
PHONE = " +1 415-555-0134"  # trips the PII gate


def test_expired_item_leaves_the_planner_until_new_evidence(tmp_path, catalog):
    added = run(Contribution(A, cand()))
    expired = contribute(added.corpus, [Contribution(A, cand())], LATER)
    item = expired.corpus.items[OBJ]
    assert item.status == "expired" and [r["action"] for r in expired.audit] == ["expire"]
    store_page(tmp_path, expired.corpus)
    assert a_context.read_shared_lessons("customer-b", catalog, tmp_path) == []
    assert "#### SI-object_access_authz" in render_shared(expired.corpus)
    fresh = contribute(expired.corpus, [Contribution(A, cand(confirmations=2))], LATER)
    item = fresh.corpus.items[OBJ]
    assert item.status == "active" and item.expiry == LATER + timedelta(days=90)
    assert [r["action"] for r in fresh.audit] == ["revalidate"]


def test_release_merges_a_false_positive_and_it_stays_resolved():
    contrib = Contribution(A, cand(extra=PHONE))
    held = run(contrib)
    (q,) = held.corpus.quarantine
    out = release(held.corpus, q.id, contrib, "sample number, not PII", TODAY)
    assert out.corpus.items[OBJ].status == "active"
    assert out.corpus.quarantine[0].status == "released"
    assert [r["action"] for r in out.audit] == ["release", "add"]
    assert PHONE.strip() not in render_shared(out.corpus)
    assert not contribute(out.corpus, [contrib], TODAY).changed  # not re-queued


@pytest.mark.parametrize(
    "setup,match",
    [
        ("other_source", "different contribution"),
        ("unknown_class", "no lesson template"),
        ("retracted", "retracted item"),
    ],
)
def test_release_refuses_unsafe_cases(setup, match):
    cls = "quantum_tunnel" if setup == "unknown_class" else "idor"
    contrib = Contribution(A, cand(cls=cls, extra=PHONE))
    corpus = run(contrib).corpus
    qid = corpus.quarantine[0].id
    if setup == "other_source":
        contrib = Contribution(B, contrib.candidate)
    if setup == "retracted":
        corpus = run(Contribution(B, cand("bola")), corpus=corpus).corpus
        corpus = retract(corpus, OBJ, "wrong", TODAY).corpus
    with pytest.raises(ValueError, match=match):
        release(corpus, qid, contrib, "ok", TODAY)


def test_rejected_contribution_is_hidden_and_not_requeued():
    contrib = Contribution(A, cand(extra=PHONE))
    held = run(contrib)
    out = reject(held.corpus, held.corpus.quarantine[0].id, "real number", TODAY)
    assert out.corpus.quarantine[0].status == "rejected"
    assert "#### Q-" not in render_shared(out.corpus)
    assert not contribute(out.corpus, [contrib], TODAY).changed


def test_supersede_retires_the_old_item(tmp_path, catalog):
    corpus = run(Contribution(A, cand()), Contribution(A, cand("ssrf"))).corpus
    out = supersede(corpus, "SI-server_side_fetch", OBJ, "folded into a broader lesson", TODAY)
    old = out.corpus.items["SI-server_side_fetch"]
    assert old.status == "superseded" and old.note.startswith(f"superseded by {OBJ}")
    store_page(tmp_path, out.corpus)
    assert a_context.read_shared_lessons("customer-b", catalog, tmp_path)[0].id == OBJ
    later = run(Contribution(B, cand("ssrf", confirmations=2)), corpus=out.corpus)
    assert later.corpus.quarantine[0].reasons == ["contributes_to_superseded_item"]
    with pytest.raises(KeyError):
        supersede(out.corpus, OBJ, OBJ, "x", TODAY)


def test_review_cli_flow(tmp_path, capsys):
    scaffold(tmp_path)
    page = tmp_path / "customers" / "customer-a.md"
    line = cand(extra=PHONE).line
    page.write_text(apply_patch(page.read_text(), Patch("customer-a", [Op(10, "CL-idor", line)])))
    base = ["--memory-dir", str(tmp_path)]
    assert cli([*base, "update"]) == 0
    capsys.readouterr()
    assert cli([*base, "review"]) == 0
    qid = capsys.readouterr().out.split()[0]
    assert qid.startswith("Q-")
    assert cli([*base, "release", "Q-nope", "--note", "x"]) == 1
    assert "nothing pending" in capsys.readouterr().err
    assert cli([*base, "release", qid, "--note", "sample number"]) == 0
    assert "### SI-object_access_authz" in (tmp_path / "shared-intelligence.md").read_text()
    assert cli([*base, "audit"]) == 0


def _page_with(tmp_path, *candidates):
    scaffold(tmp_path)
    page = tmp_path / "customers" / "customer-a.md"
    ops = [Op(10, c.key, c.line) for c in candidates]
    page.write_text(apply_patch(page.read_text(), Patch("customer-a", ops)))
    return ["--memory-dir", str(tmp_path)]


def test_lifecycle_cli_commands(tmp_path, capsys):
    base = _page_with(tmp_path, cand(), cand("ssrf"))
    assert cli([*base, "update"]) == 0  # 0.2.0: two items
    shared = tmp_path / "shared-intelligence.md"

    assert cli([*base, "supersede", "SI-server_side_fetch", "--by", OBJ, "--reason", "merged"]) == 0
    assert "#### SI-server_side_fetch" in shared.read_text()  # 0.3.0

    assert cli([*base, "retract", OBJ, "--reason", "poisoned on review"]) == 0
    assert "#### SI-object_access_authz" in shared.read_text()  # 0.4.0
    assert "### SI-" not in shared.read_text().replace("#### SI-", "")

    assert cli([*base, "rollback", "0.2.0"]) == 0  # 0.5.0 restores both items
    text = shared.read_text()
    assert "knowledge_version: 0.5.0" in text
    assert "### SI-object_access_authz" in text and "### SI-server_side_fetch" in text

    capsys.readouterr()
    assert cli([*base, "retract", "SI-nope", "--reason", "x"]) == 1
    assert cli([*base, "rollback", "9.9.9"]) == 1
    assert cli([*base, "retract", OBJ, "--reason", "seen on customer-a"]) == 1  # privacy gate
    assert capsys.readouterr().err.count("error:") == 3
    actions = [
        json.loads(x)["action"]
        for x in (tmp_path / "shared" / "audit.jsonl").read_text().splitlines()
    ]
    assert actions == ["add", "add", "supersede", "retract", "rollback"]


def test_reject_cli(tmp_path, capsys):
    base = _page_with(tmp_path, cand(extra=PHONE))
    assert cli([*base, "update"]) == 0
    capsys.readouterr()
    assert cli([*base, "review"]) == 0
    qid = capsys.readouterr().out.split()[0]
    assert cli([*base, "reject", qid, "--note", "real number; removed from page"]) == 0
    assert "#### Q-" not in (tmp_path / "shared-intelligence.md").read_text()
    capsys.readouterr()
    assert cli([*base, "review"]) == 0
    assert "0 pending review" in capsys.readouterr().out
