from attack.harness import context

PAGE = """# customer-a
## 1. Environment
secret env stuff
## 2. Assets and invariants
Orders belong to one user.
## 3. Recent code changes
Login handler rewritten.
## 5. Confirmed findings
hidden
"""
SHARED = """knowledge_version: 0.4.2
### L-1
applicability: any web app with sequential ids
Check horizontal access.
### L-2
applicability: ssrf only
Check callbacks.
"""


def test_reads_only_wanted_sections(tmp_path):
    (tmp_path / "customers").mkdir()
    (tmp_path / "customers" / "customer-a.md").write_text(PAGE)
    s = context.read_customer_sections("customer-a", tmp_path)
    assert list(s) == ["2. Assets and invariants", "3. Recent code changes"]


def test_missing_memory_is_tolerated(tmp_path):
    assert context.read_customer_sections("customer-a", tmp_path) == {}
    assert context.read_knowledge_version(tmp_path) == "0.0.0"


def test_knowledge_version_and_lesson_filtering(tmp_path, catalog):
    (tmp_path / "shared-intelligence.md").write_text(SHARED)
    assert context.read_knowledge_version(tmp_path) == "0.4.2"
    lessons = context.read_shared_lessons("customer-a", catalog, tmp_path)
    assert [x.id for x in lessons] == ["L-1"]  # customer-a has no ssrf scenario
