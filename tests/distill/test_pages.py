"""Page schemas, and the contract that Dev A's reader parses our pages as intended."""

from pathlib import Path

import pytest

from attack.catalog import load_catalog
from attack.harness import context
from distill.pages import (
    CUSTOMER_SECTIONS,
    INITIAL_KNOWLEDGE_VERSION,
    PROFILES,
    TAXONOMY,
    parse_customer_sections,
    render_customer_scaffold,
    render_shared_scaffold,
)
from distill.scaffold import scaffold

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def catalog():
    return load_catalog()


@pytest.mark.parametrize("customer_id", list(PROFILES))
def test_customer_scaffold_has_all_sections_in_order(customer_id):
    sections = parse_customer_sections(render_customer_scaffold(customer_id))
    assert list(sections) == list(CUSTOMER_SECTIONS)
    assert sections[2]  # seeded
    assert all(not sections[n] for n in range(3, 11))


def test_a_reads_only_seeded_planner_sections(tmp_path):
    scaffold(tmp_path)
    got = context.read_customer_sections("customer-a", tmp_path)
    assert list(got) == [f"2. {CUSTOMER_SECTIONS[2]}"]  # §1 never reaches the planner
    assert "A user can only read their own orders" in next(iter(got.values()))


def test_a_reads_knowledge_version_and_no_lessons_from_empty_corpus(tmp_path, catalog):
    scaffold(tmp_path)
    assert context.read_knowledge_version(tmp_path) == INITIAL_KNOWLEDGE_VERSION
    for customer_id in PROFILES:
        assert context.read_shared_lessons(customer_id, catalog, tmp_path) == []


def test_only_active_items_reach_the_planner(tmp_path, catalog):
    text = render_shared_scaffold().replace(
        "## Generalized attack patterns & preconditions\n",
        "## Generalized attack patterns & preconditions\n\n### SI-0001\n"
        "applicability: idor, bola\nCheck object ownership on per-user resources.\n",
    ).replace(
        "## Pending contributions\n",
        "## Pending contributions\n\n#### SI-0002\napplicability: idor\nUnder review.\n",
    )
    (tmp_path / "shared-intelligence.md").write_text(text)
    # the idor lesson from customer-a's family reaches customer-b (bola), not customer-c
    assert [x.id for x in context.read_shared_lessons("customer-b", catalog, tmp_path)] == [
        "SI-0001"
    ]
    assert context.read_shared_lessons("customer-c", catalog, tmp_path) == []


def test_taxonomy_covers_catalog_and_avoids_wildcard_substrings(catalog):
    classes = {c for cs in TAXONOMY.values() for c in cs}
    assert {s.weakness_class for s in catalog.values()} <= classes
    assert not any("any" in c or "all" in c for c in classes)


def test_scaffold_never_overwrites(tmp_path):
    assert len(scaffold(tmp_path)) == 4
    page = tmp_path / "customers" / "customer-a.md"
    page.write_text("edited")
    assert scaffold(tmp_path) == []
    assert page.read_text() == "edited"


def test_committed_pages_parse():
    for customer_id in PROFILES:
        text = (REPO / "memory" / "customers" / f"{customer_id}.md").read_text()
        assert list(parse_customer_sections(text)) == list(CUSTOMER_SECTIONS)
    assert context.read_knowledge_version(REPO / "memory") != "0.0.0"
