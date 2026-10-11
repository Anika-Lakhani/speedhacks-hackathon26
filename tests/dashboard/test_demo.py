"""The run surface: async runs, the one-run-per-customer lock, degraded surfacing, the
generated/approval review gates, flags, and the Fix loop over the in-process demo world."""

import shutil
import threading
import time

import pytest
from fastapi.testclient import TestClient

from attack.agent import DummyPlanner
from attack.catalog import load_catalog
from attack.catalog.generation import DEFAULT_CATALOG_DIR
from attack.remediate import DummyFlagFixer, FixRequest, GeminiFlagFixer
from dashboard.app import create_app
from dashboard.demo import DemoWorld, RunBusy, RunOptions


def world(tmp_path, **kw):
    kw.setdefault("planner", DummyPlanner())
    kw.setdefault("fixer", DummyFlagFixer())
    return DemoWorld(memory_dir=tmp_path, **kw)


def wait(w, run_id, tries=200):
    for _ in range(tries):
        st = w.run_status(run_id)
        if st["status"] in ("done", "error"):
            return st
        time.sleep(0.02)
    raise AssertionError("run did not finish")


# -- async run + progress ------------------------------------------------------------------


def test_async_run_confirms_seeded_weakness(tmp_path):
    w = world(tmp_path)
    run_id = w.start_run("customer-a", RunOptions())
    st = wait(w, run_id)
    assert st["status"] == "done"
    assert st["report"]["counts"].get("confirmed", 0) >= 1
    assert st["planned"] is not None and st["probed"] >= 1
    vulns = w.data.vulnerabilities("customer-a")["vulnerabilities"]
    assert "SCN-IDOR-001" in [v["scenario_id"] for v in vulns]


class BlockingPlanner:
    def __init__(self):
        self.entered = threading.Event()
        self.release = threading.Event()

    def plan(self, request):
        self.entered.set()
        self.release.wait(5)
        return DummyPlanner().plan(request)


def test_one_run_per_customer(tmp_path):
    bp = BlockingPlanner()
    w = world(tmp_path, planner=bp)
    run_id = w.start_run("customer-a", RunOptions())
    assert bp.entered.wait(5)
    with pytest.raises(RunBusy):
        w.start_run("customer-a", RunOptions())
    bp.release.set()
    assert wait(w, run_id)["status"] == "done"
    # lock releases: a second run is allowed once the first finished
    assert w.start_run("customer-a", RunOptions())


class DegradedPlanner:
    def plan(self, request):
        plan = DummyPlanner().plan(request)
        return plan.model_copy(
            update={
                "degraded": True,
                "error": "RESOURCE_EXHAUSTED: quota",
                "planner": "dummy-fallback",
            }
        )


def test_degraded_planner_is_surfaced(tmp_path):
    w = world(tmp_path, planner=DegradedPlanner())
    job = w.run_sync("customer-a", RunOptions())
    assert job.report.plan.degraded and "quota" in job.report.plan.error
    assert w.run_status(job.run_id)["report"]["plan"]["degraded"] is True


def test_unknown_run_raises(tmp_path):
    with pytest.raises(KeyError):
        world(tmp_path).run_status("run-nope")


# -- flags ---------------------------------------------------------------------------------


def test_flags_toggle_and_reset(tmp_path):
    w = world(tmp_path)
    assert w.sites["customer-a"].flags["idor_orders"] is True
    w.set_flags("customer-a", {"idor_orders": False})
    assert w.sites["customer-a"].flags["idor_orders"] is False
    w.set_flags("customer-a", {"login_rate_limit_off": True})
    w.reset_demo("customer-a")
    assert w.sites["customer-a"].flags == {
        "idor_orders": True,
        "login_rate_limit_off": False,
        "weak_password_reset": False,
    }


def test_unknown_flag_rejected(tmp_path):
    with pytest.raises(KeyError):
        world(tmp_path).set_flags("customer-a", {"not_a_flag": True})


# -- fix -----------------------------------------------------------------------------------


def test_fix_flips_flag_and_clears_vulnerability(tmp_path):
    w = world(tmp_path)
    wait(w, w.start_run("customer-a", RunOptions()))
    rev_before = w.sites["customer-a"].code_revision
    result = w.fix("customer-a", "SCN-IDOR-001")
    assert result["flag"] == "idor_orders"
    assert result["fixed"] is True and result["verdict"] == "not_reproduced"
    assert w.sites["customer-a"].flags["idor_orders"] is False
    assert w.sites["customer-a"].code_revision != rev_before
    vulns = w.data.vulnerabilities("customer-a")["vulnerabilities"]
    assert "SCN-IDOR-001" not in [v["scenario_id"] for v in vulns]


def test_fix_unknown_scenario_rejected(tmp_path):
    with pytest.raises(KeyError):
        world(tmp_path).fix("customer-a", "SCN-DOES-NOT-EXIST")


# -- generated review gate -----------------------------------------------------------------


def test_generate_then_promote_and_reject(tmp_path):
    cat_dir = tmp_path / "scenarios"
    shutil.copytree(DEFAULT_CATALOG_DIR, cat_dir)
    w = world(tmp_path, catalog_dir=cat_dir)
    w.run_sync("customer-c", RunOptions(offline=True, generate_max=2))
    gen = w.generated_scenarios("customer-c")["generated"]
    assert gen and all(g["id"].startswith("SCN-GEN-") for g in gen)
    assert all(g["runs"] >= 1 for g in gen)  # ran during the cycle, so promotable

    out = w.promote(gen[0]["id"])
    assert out["path"].endswith(".generated.yaml")
    assert gen[0]["id"] in load_catalog(cat_dir)  # now in the permanent catalog

    w.reject(gen[1]["id"])
    after = {g["id"]: g["status"] for g in w.generated_scenarios("customer-c")["generated"]}
    assert after[gen[0]["id"]] == "promoted" and after[gen[1]["id"]] == "rejected"


# -- approval gate -------------------------------------------------------------------------


def test_approvals_when_gate_on(tmp_path):
    w = world(tmp_path)
    job = w.run_sync("customer-a", RunOptions(auto_approve=False))
    pending = w.approvals("customer-a")["approvals"]
    assert any(a["scenario_id"] == "SCN-IDOR-001" for a in pending)
    item = pending[0]
    w.approve(item["run_id"], item["scenario_id"])
    still = w.approvals("customer-a")["approvals"]
    assert not any(
        a["run_id"] == item["run_id"] and a["scenario_id"] == item["scenario_id"] for a in still
    )
    assert job.report is not None


# -- HTTP surface --------------------------------------------------------------------------


def test_http_run_and_gates(tmp_path):
    c = TestClient(create_app(world=world(tmp_path)))
    assert c.get("/api/features").json() == {"write": True}
    run_id = c.post("/api/customer/customer-a/run", json={}).json()["run_id"]
    for _ in range(200):
        st = c.get(f"/api/run/{run_id}").json()
        if st["status"] in ("done", "error"):
            break
        time.sleep(0.02)
    assert st["status"] == "done" and st["report"]["counts"].get("confirmed", 0) >= 1
    assert c.get("/api/run/run-nope").status_code == 404

    flags = c.put("/api/customer/customer-a/flags", json={"flags": {"idor_orders": False}}).json()
    assert {x["flag"]: x["on"] for x in flags["flags"]}["idor_orders"] is False
    assert c.post("/api/customer/customer-a/reset").status_code == 200

    fixed = c.post("/api/customer/customer-a/fix", json={"scenario_id": "SCN-IDOR-001"}).json()
    assert fixed["fixed"] is True
    bad = c.post("/api/customer/customer-a/fix", json={"scenario_id": "SCN-NOPE"})
    assert bad.status_code == 400
    assert c.get("/api/customer/customer-a/generated").json() == {"generated": []}


def test_read_only_app_has_no_write_features(tmp_path):
    from attack.clients.fakes import FakeKeewano
    from dashboard.data import DashboardData

    data = DashboardData(events=FakeKeewano(), site_factory=lambda cid: None, memory_dir=tmp_path)
    c = TestClient(create_app(data))
    assert c.get("/api/features").json() == {"write": False}
    assert c.post("/api/customer/customer-a/run", json={}).status_code == 404


# -- the fixer's code-side guardrail -------------------------------------------------------


class _Resp:
    def __init__(self, text):
        self.text = text
        self.usage_metadata = None


class _FakeClient:
    def __init__(self, text):
        self.models = type("M", (), {"generate_content": lambda _s, **k: _Resp(text)})()


def _req():
    return FixRequest(
        customer_id="customer-a",
        scenario_id="SCN-IDOR-001",
        invariant="own orders only",
        allowed_flags=["idor_orders"],
    )


def test_gemini_fixer_accepts_in_scope_choice():
    fixer = GeminiFlagFixer(client=_FakeClient('{"flag": "idor_orders", "rationale": "ok"}'))
    assert fixer.decide(_req()).flag == "idor_orders"


def test_gemini_fixer_rejects_out_of_scope_choice():
    fixer = GeminiFlagFixer(client=_FakeClient('{"flag": "ssrf_callback", "rationale": "nope"}'))
    decision = fixer.decide(_req())
    assert decision.flag == "idor_orders" and "fallback" in decision.rationale
