"""The analysis agent against Dev B's real read API (in-process), not fixtures."""

import pytest
from fastapi.testclient import TestClient

from distill.customer_analysis import source as source_mod
from distill.customer_analysis.__main__ import main as cli
from distill.customer_analysis.patch import parse_entry, read_entries
from distill.customer_analysis.source import EventSource
from distill.scaffold import scaffold
from tests.conftest import make_organic
from tests.distill.test_customer_analysis import fixture_events, swarm_run


@pytest.fixture
def store(read_app):
    return TestClient(read_app)


def post(client, events):
    body = client.post("/events", json=events).json()
    assert body["rejected"] == [], body["rejected"]


def as_json(events):
    return [e.model_dump(mode="json") for e in events]


def test_window_follows_cursors_in_order_within_one_tenant(store, monkeypatch):
    monkeypatch.setattr(source_mod, "PAGE_SIZE", 7)
    post(store, [make_organic("customer-a", n, n) for n in range(30)])
    post(store, [make_organic("customer-b", n, n) for n in range(30)])
    got = EventSource(client=store).window("customer-a")
    assert [e["event_id"] for e in got] == [f"customer-a-o{n}" for n in range(30)]


def test_window_since_revision(store):
    post(
        store,
        [make_organic("customer-a", n, n, revision="r1" if n < 5 else "r2") for n in range(8)],
    )
    got = EventSource(client=store).window("customer-a", revision="r2")
    assert [e["code_revision"] for e in got] == ["r2"] * 3


def page_entry(memory, section, key):
    text = (memory / "customers" / "customer-a.md").read_text()
    line = read_entries(text)[section].get(key)
    return parse_entry(line) if line else None


def run_cli(memory, store, *extra):
    args = [
        "--customer",
        "customer-a",
        "--keewano",
        "http://testserver",
        "--memory-dir",
        str(memory),
    ]
    return cli(
        [*args, "--approvals", str(memory / "none.json"), *extra], source=EventSource(client=store)
    )


def test_live_loop_is_incremental(tmp_path, store, catalog, capsys):
    scaffold(tmp_path)
    post(store, fixture_events("customer-a"))
    assert run_cli(tmp_path, store) == 0
    assert page_entry(tmp_path, 9, "NEXT-SCN-RESET-001")

    capsys.readouterr()
    assert run_cli(tmp_path, store) == 0  # resumes from last_distilled: nothing new
    assert capsys.readouterr().out.strip() == "no changes"

    events, report = swarm_run(tmp_path, catalog, idor_orders=True)
    post(store, as_json(events))
    assert run_cli(tmp_path, store) == 0
    assert page_entry(tmp_path, 5, "F-SCN-IDOR-001").tail["status"] == "open"
    assert page_entry(tmp_path, 7, f"RUN-{report.run_id}")
    assert not page_entry(tmp_path, 9, "NEXT-SCN-RESET-001")  # tested by the run


def test_unknown_revision_is_a_clean_error(tmp_path, store, capsys):
    scaffold(tmp_path)
    assert run_cli(tmp_path, store, "--since-revision", "nope") == 1
    assert "404" in capsys.readouterr().err
