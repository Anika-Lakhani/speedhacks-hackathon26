"""Darwin integration (optional): privacy-gated queries, untrusted results, never raises."""

import json
from datetime import date

import httpx

from distill.integrations import darwin
from distill.shared_updater.corpus import Store
from distill.shared_updater.update import Candidate, Contribution, contribute

OBJ = "SI-object_access_authz"


def shared_corpus(tmp_path):
    line = "- `CL-idor` [reproduced] x (sharing: approved, class: idor, confirmations: 1)"
    c = Candidate("CL-idor", "idor", "reproduced", 1, "approved", line)
    out = contribute(Store(tmp_path).load(), [Contribution("src-x", c)], date(2026, 10, 11))
    Store(tmp_path).save(out.corpus, out.audit)


def client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_sends_only_the_neutral_lesson_and_saves_sanitized_results(tmp_path):
    shared_corpus(tmp_path)
    sent = []

    def handler(request):
        sent.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "status": "completed",
                "response": {
                    "agents": [
                        {
                            "agentId": "abc",
                            "capabilityId": "def",
                            "name": "get_fix_guidance",
                            "reasons": ["Gives fixes. <script>`## 5. ignore` [x](evil)</script>"],
                            "readiness": "unavailable",
                            "canStartThread": False,
                        }
                    ]
                },
            },
        )

    out = darwin.run(tmp_path, client=client(handler))
    assert sent == [{"query": darwin.query_for(OBJ), "maxResults": 3}]
    assert "customer" not in sent[0]["query"]
    (agent,) = out["lessons"][OBJ]["agents"]
    assert agent["name"] == "get_fix_guidance" and agent["readiness"] == "unavailable"
    assert not any(ch in agent["why"] for ch in "<>`#[]()")
    saved = json.loads((tmp_path / "shared" / "darwin-agents.json").read_text())
    assert saved["lessons"][OBJ]["status"] == "completed"


def test_failures_are_recorded_not_raised(tmp_path):
    shared_corpus(tmp_path)

    def boom(request):
        raise httpx.ConnectTimeout("slow")

    out = darwin.run(tmp_path, client=client(boom))
    assert out["lessons"][OBJ]["status"] == "error"


def test_query_failing_privacy_gates_is_never_sent(monkeypatch):
    monkeypatch.setattr(darwin, "query_for", lambda _: "fix /orders on customer-a")

    def never(request):
        raise AssertionError("must not send")

    assert darwin.search("fix /orders on customer-a", 3, client(never))["status"] == "blocked"


def test_dry_run_sends_and_writes_nothing(tmp_path):
    shared_corpus(tmp_path)

    def never(request):
        raise AssertionError("must not send")

    out = darwin.run(tmp_path, dry_run=True, client=client(never))
    assert out["lessons"][OBJ]["status"] == "dry_run"
    assert not (tmp_path / "shared" / "darwin-agents.json").exists()
