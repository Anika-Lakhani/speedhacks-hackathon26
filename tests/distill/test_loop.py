"""after_run: the dashboard's hook into Dev C, with the review/auto sharing toggle."""

from attack.harness import context as a_context
from distill.loop import after_run
from distill.shared_updater.corpus import Store
from tests.distill.test_customer_analysis import swarm_run

OBJ = "SI-object_access_authz"


def test_review_mode_updates_memory_but_shares_nothing(tmp_path, catalog):
    events, _ = swarm_run(tmp_path, catalog, idor_orders=True)
    out = after_run("customer-a", events, share="review", memory_dir=tmp_path, catalog=catalog)
    assert "F-SCN-IDOR-001" in out["page_updates"] and out["shared"] == []
    page = (tmp_path / "customers" / "customer-a.md").read_text()
    assert "sharing: proposed" in page
    assert not Store(tmp_path).corpus_path.exists()


def test_auto_mode_shares_and_reaches_customer_b(tmp_path, catalog, monkeypatch):
    monkeypatch.setenv("SWARMSHIELD_SHARE_MODE", "auto")
    events, _ = swarm_run(tmp_path, catalog, idor_orders=True)
    out = after_run(
        "customer-a",
        [e.model_dump(mode="json") for e in events],
        memory_dir=tmp_path,
        catalog=catalog,
    )
    assert out["share_mode"] == "auto" and out["approved"] == ["CL-idor"]
    assert out["shared"] == [f"add {OBJ}"] and out["knowledge_version"] == "0.2.0"
    assert [x.id for x in a_context.read_shared_lessons("customer-b", catalog, tmp_path)] == [OBJ]
    again = after_run("customer-a", events, memory_dir=tmp_path, catalog=catalog)
    assert again["page_updates"] == ["knowledge_version"]  # §1 now records 0.2.0
    assert again["shared"] == []
    third = after_run("customer-a", events, memory_dir=tmp_path, catalog=catalog)
    assert third["page_updates"] == [] and third["shared"] == []  # idempotent


def test_auto_mode_never_shares_a_contradicted_lesson(tmp_path, catalog):
    for flag in (True, False):
        events, _ = swarm_run(tmp_path, catalog, rev="rev-1", idor_orders=flag)
        after_run("customer-a", events, share="review", memory_dir=tmp_path, catalog=catalog)
    out = after_run("customer-a", [], share="auto", memory_dir=tmp_path, catalog=catalog)
    assert out["approved"] == [] and out["shared"] == []
