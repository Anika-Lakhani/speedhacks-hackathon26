"""Acceptance criterion 8 (dev-C §5): a lesson generalized from customer-a yields a usable,
applicability-scoped test suggestion for customer-b, end to end through Dev A's harness."""

from attack.agent import DummyPlanner
from attack.harness import context as a_context
from distill.customer_analysis.analyze import analyze
from distill.customer_analysis.patch import apply_patch, parse_entry, read_entries
from distill.privacy.scanners import scan
from distill.scaffold import scaffold
from distill.shared_updater.__main__ import main as shared_cli
from distill.shared_updater.corpus import Store
from tests.distill.test_customer_analysis import swarm_run

OBJ = "SI-object_access_authz"


class RecordingPlanner(DummyPlanner):
    """Dev A's deterministic planner, keeping the request it was given."""

    def plan(self, request):
        self.request = request
        return super().plan(request)


def distill_run(memory, customer_id, catalog, **flags):
    page = memory / "customers" / f"{customer_id}.md"
    planner = RecordingPlanner()
    events, report = swarm_run(memory, catalog, customer_id, planner=planner, **flags)
    kv = a_context.read_knowledge_version(memory)
    result = analyze(customer_id, events, page.read_text(), catalog, knowledge_version=kv)
    page.write_text(apply_patch(page.read_text(), result.patch))
    return planner.request, events, page


def share(memory, customer_id, cls):
    base = ["--memory-dir", str(memory)]
    assert shared_cli([*base, "approve", "--customer", customer_id, "--class", cls]) == 0
    assert shared_cli([*base, "update"]) == 0


def test_lesson_from_customer_a_drives_customer_b_and_merges_back(tmp_path, catalog):
    scaffold(tmp_path)

    # customer-a: IDOR confirmed -> candidate lesson -> approved -> shared
    request_a, _, _ = distill_run(tmp_path, "customer-a", catalog, idor_orders=True)
    assert request_a.shared_lessons == []  # nothing shared yet
    share(tmp_path, "customer-a", "idor")

    # customer-b's next real harness run receives it in the planner's input
    request_b, events_b, page_b = distill_run(
        tmp_path, "customer-b", catalog, broken_object_authz=True
    )
    (lesson,) = request_b.shared_lessons
    assert lesson.id == OBJ and "Suggested test" in lesson.text and scan(lesson.text) == []
    assert {e.knowledge_version for e in events_b} == {"0.2.0"}  # run stamped with the corpus
    # ...and the lesson is scoped: it matches a scenario customer-b actually has
    assert any(s.weakness_class == "bola" for s in request_b.scenarios)

    # customer-b confirms its own BOLA finding; its page records the knowledge version in play
    finding = parse_entry(read_entries(page_b.read_text())[5]["F-SCN-BOLA-001"])
    assert finding.tail["status"] == "open"
    assert "- knowledge_version: 0.2.0" in page_b.read_text()

    # sharing it merges into the same item: two independent tenants -> high confidence
    share(tmp_path, "customer-b", "bola")
    item = Store(tmp_path).load().items[OBJ]
    assert (len(item.sources), item.confidence, item.version) == (2, "high", 2)

    # customer-c has no object-access surface, so it never receives the lesson
    request_c, _, _ = distill_run(tmp_path, "customer-c", catalog)
    assert request_c.shared_lessons == []
