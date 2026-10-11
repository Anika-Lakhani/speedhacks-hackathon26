"""Dashboard runs close the loop through Dev C (`distill.loop.after_run`)."""

from attack.agent import DummyPlanner
from dashboard.demo import DemoWorld, RunOptions
from distill.scaffold import scaffold


def test_run_updates_memory_and_auto_shares(tmp_path, monkeypatch):
    monkeypatch.setenv("SWARMSHIELD_SHARE_MODE", "auto")
    monkeypatch.setenv("SWARMSHIELD_PROVENANCE_SALT", "test")
    scaffold(tmp_path)
    world = DemoWorld(planner=DummyPlanner(), memory_dir=tmp_path)
    job = world.run_sync("customer-a", RunOptions(offline=True))  # idor_orders seeded on
    status = world.run_status(job.run_id)
    assert "F-SCN-IDOR-001" in status["distill"]["page_updates"]
    assert status["distill"]["shared"] == ["add SI-object_access_authz"]
    assert "### SI-object_access_authz" in world.data.shared()["markdown"]

    world.set_flags("customer-b", {"broken_object_authz": True})
    jb = world.run_sync("customer-b", RunOptions(offline=True))
    start = world.keewano.get_slice("customer-b", run_id=jb.run_id, event_type="swarm.run_start")
    assert start[0]["knowledge_version"] == "0.2.0"  # customer-b planned with the lesson
    assert world.run_status(jb.run_id)["distill"]["shared"] == ["merge SI-object_access_authz"]


def test_review_mode_shares_nothing(tmp_path, monkeypatch):
    monkeypatch.delenv("SWARMSHIELD_SHARE_MODE", raising=False)
    scaffold(tmp_path)
    world = DemoWorld(planner=DummyPlanner(), memory_dir=tmp_path)
    job = world.run_sync("customer-a", RunOptions(offline=True))
    assert world.run_status(job.run_id)["distill"]["shared"] == []
    assert "sharing: proposed" in (tmp_path / "customers" / "customer-a.md").read_text()
