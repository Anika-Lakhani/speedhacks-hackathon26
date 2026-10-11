from datetime import UTC, datetime

import httpx
import pytest
from fastapi.testclient import TestClient

from attack.clients.fakes import FakeKeewano
from attack.harness.events import EventFactory
from contracts import EventType
from dashboard.app import create_app
from dashboard.data import DashboardData


class DownSite:
    def meta(self):
        raise httpx.ConnectError("down")


class UpSite:
    def meta(self):
        return {
            "customer_id": "customer-a",
            "code_revision": "abc123",
            "flags": {"idor_orders": True},
        }


class DownKeewano:
    def get_slice(self, *a, **k):
        raise httpx.ConnectError("down")


def seed(store: FakeKeewano, customer_id="customer-a", verdict="confirmed"):
    f = EventFactory(customer_id, "run-1", "abc123", "0.0.0", "cat1")
    store.post_events(
        [
            f.make(EventType.SWARM_RUN_START, target="-", action="start"),
            f.make(
                EventType.SWARM_VERDICT,
                target="/orders/{id}",
                action="verdict",
                scenario_id="SCN-IDOR-001",
                verdict=verdict,
                attrs={"confidence": 0.9, "invariant": "own orders only"},
            ),
            f.make(EventType.SWARM_RUN_END, target="-", action="end"),
        ]
    )


def client(events, site=DownSite, tmp_path=None):
    data = DashboardData(events=events, site_factory=lambda cid: site(), memory_dir=tmp_path)
    return TestClient(create_app(data))


def test_placeholders_when_backends_down(tmp_path):
    c = client(DownKeewano(), tmp_path=tmp_path)
    assert c.get("/api/customers").status_code == 200
    runs = c.get("/api/customer/customer-a/runs").json()
    assert runs["source"] == "placeholder" and runs["runs"] == []
    flags = c.get("/api/customer/customer-a/flags").json()
    assert flags["source"] == "placeholder" and len(flags["flags"]) == 3
    assert all(f["on"] is False for f in flags["flags"])
    mem = c.get("/api/customer/customer-a/memory").json()
    assert mem["source"] == "placeholder" and "customer-a" in mem["markdown"]


def test_live_runs_vulns_flags(tmp_path):
    store = FakeKeewano()
    seed(store)
    c = client(store, UpSite, tmp_path)
    runs = c.get("/api/customer/customer-a/runs").json()
    assert runs["source"] == "live"
    assert runs["runs"][0]["status"] == "complete"
    assert runs["runs"][0]["verdict_counts"] == {"confirmed": 1}
    vulns = c.get("/api/customer/customer-a/vulnerabilities").json()["vulnerabilities"]
    assert [v["scenario_id"] for v in vulns] == ["SCN-IDOR-001"] and vulns[0][
        "flag"
    ] == "idor_orders"
    flags = {f["flag"]: f["on"] for f in c.get("/api/customer/customer-a/flags").json()["flags"]}
    assert flags["idor_orders"] is True and flags["weak_password_reset"] is False


def test_later_not_reproduced_clears_vulnerability(tmp_path):
    store = FakeKeewano()
    seed(store)
    f = EventFactory(
        "customer-a", "run-2", "abc124", "0.0.0", "cat1", clock=lambda: datetime.now(UTC)
    )
    store.post_events(
        [
            f.make(
                EventType.SWARM_VERDICT,
                target="/o",
                action="v",
                scenario_id="SCN-IDOR-001",
                verdict="not_reproduced",
            )
        ]
    )
    c = client(store, tmp_path=tmp_path)
    assert c.get("/api/customer/customer-a/vulnerabilities").json()["vulnerabilities"] == []


def test_tenant_isolation_even_if_store_leaks(tmp_path):
    class Leaky:
        def get_slice(self, customer_id, **k):
            return store.get_slice("customer-b")

    store = FakeKeewano()
    seed(store, "customer-b")
    c = client(Leaky(), tmp_path=tmp_path)
    assert c.get("/api/customer/customer-a/runs").json()["runs"] == []


def test_memory_file_served_when_present(tmp_path):
    (tmp_path / "customers").mkdir()
    (tmp_path / "customers" / "customer-a.md").write_text("# real page")
    c = client(DownKeewano(), tmp_path=tmp_path)
    m = c.get("/api/customer/customer-a/memory").json()
    assert m["source"] == "live" and m["markdown"] == "# real page"


@pytest.mark.parametrize("path", ["/api/customer/nope/flags", "/customer/nope"])
def test_unknown_customer_404(path, tmp_path):
    assert client(DownKeewano(), tmp_path=tmp_path).get(path).status_code == 404


def test_pages_served(tmp_path):
    c = client(DownKeewano(), tmp_path=tmp_path)
    for p in ["/", "/customer/customer-a", "/static/common.js", "/api/shared"]:
        assert c.get(p).status_code == 200


def test_repo_memory_stubs_exist():
    from dashboard.data import MEMORY_DIR

    for c in "abc":
        assert (MEMORY_DIR / "customers" / f"customer-{c}.md").is_file()
    assert (MEMORY_DIR / "shared-intelligence.md").is_file()
