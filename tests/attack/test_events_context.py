from datetime import UTC, datetime

from attack.harness import context
from contracts import Event


def organic_event():
    return Event(
        customer_id="customer-c",
        ts=datetime(2026, 10, 11, tzinfo=UTC),
        actor="user",
        event_type="search.query",
        target="/search",
        action="GET /search",
        policy_outcome="allow",
        code_revision="r1",
        simulated=False,
    )


def test_summarize_events_keeps_reasoning_fields_only():
    ev = organic_event().model_dump(mode="json")
    out = context.summarize_events([ev] * 3, limit=2)
    assert len(out) == 2
    assert set(out[0]) == {"ts", "actor", "event_type", "target", "action", "policy_outcome"}


def test_redact_masks_credentials_including_prefixed_names():
    text = 'SECRET_KEY = "hunter2hunter2"\nAPI_TOKEN: abcdef123456\nplain = 1'
    out = context.redact(text)
    assert "hunter2" not in out and "abcdef123456" not in out and "plain = 1" in out


def test_read_code_context_redacts_caps_and_skips_missing(tmp_path):
    big = tmp_path / "big.py"
    big.write_text('password = "supersecret123"\n' + "x = 1\n" * 5000)
    out = context.read_code_context([str(big), str(tmp_path / "missing.py")])
    assert list(out) == [str(big)]
    assert len(out[str(big)]) <= context.MAX_FILE_CHARS and "supersecret" not in out[str(big)]


def test_total_code_budget_is_enforced(tmp_path):
    files = []
    for i in range(6):
        f = tmp_path / f"f{i}.py"
        f.write_text("y = 2\n" * 3000)
        files.append(str(f))
    out = context.read_code_context(files)
    assert sum(len(v) for v in out.values()) <= context.MAX_CODE_CHARS


def test_placeholder_sections_are_not_sent_to_the_model(tmp_path):
    (tmp_path / "customers").mkdir()
    (tmp_path / "customers" / "customer-a.md").write_text(
        "## 2. Assets\n_Not yet distilled._\n## 3. Recent code/config changes\nLogin rewritten.\n"
    )
    assert context.read_customer_sections("customer-a", tmp_path) == {
        "3. Recent code/config changes": "Login rewritten."
    }


def test_knowledge_version_parses_the_skeleton_format(tmp_path):
    (tmp_path / "shared-intelligence.md").write_text("- **Taxonomy:** knowledge_version `0.3.1`\n")
    assert context.read_knowledge_version(tmp_path) == "0.3.1"
