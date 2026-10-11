"""Privacy gates: red-team fixtures must be caught; generated shared content must pass."""

from datetime import date

import pytest

from distill.privacy.provenance import source_token
from distill.privacy.scanners import scan
from distill.shared_updater.corpus import Corpus, Item, render_item, render_shared
from distill.shared_updater.lessons import LESSONS

# (planted text, gate that must fire). Synthetic values only.
RED_TEAM = [
    ("aws key AKIAIOSFODNN7EXAMPLE leaked", "secret"),
    ("-----BEGIN RSA PRIVATE KEY-----", "secret"),
    ("token ghp_" + "a1B2c3D4e5" * 4, "secret"),
    ("auth eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig", "secret"),
    ("password=hunter2!", "secret"),
    ("api_key: sk_live_" + "x" * 24, "secret"),
    ("contact jane.doe@example.com", "pii"),
    ("call +1 415-555-0134", "pii"),
    ("ssn 123-45-6789", "pii"),
    ("card 4111 1111 1111 1111", "pii"),
    ("host 10.0.0.5", "pii"),
    ("seen on customer-a", "tenant_identifier"),
    ("site http://localhost:3001", "tenant_identifier"),
    ("flag idor_orders was on", "tenant_identifier"),
    ("GET /orders/1002", "tenant_identifier"),
    ("at 2026-10-11T09:15:40Z", "reidentification"),
    ("evidence ev://x/y/z", "reidentification"),
    ("scenario SCN-IDOR-001", "reidentification"),
    ("event 6aa9ed9d-3da2-4373-8872-425a636b93fb", "reidentification"),
    ("path /internal/billing/export", "reidentification"),
]


@pytest.mark.parametrize("text,kind", RED_TEAM)
def test_red_team_fixture_is_caught(text, kind):
    assert kind in {h.kind for h in scan(text)}


def test_hits_name_the_rule_not_the_secret():
    hits = scan("password=hunter2!")
    assert all("hunter2" not in f"{h.kind}{h.rule}" for h in hits)


@pytest.mark.parametrize("text", ["2026-10-11", "knowledge_version: 0.2.0", "version: 12"])
def test_dates_and_versions_are_not_flagged(text):
    assert scan(text) == []


def test_every_generated_item_passes_all_gates():
    corpus = Corpus()
    for lesson in LESSONS.values():
        corpus.items[lesson.id] = Item(
            id=lesson.id,
            version=3,
            status="active",
            evidence_level="verified",
            confidence="high",
            applicability=list(lesson.classes),
            last_validation=date(2026, 10, 11),
            expiry=date(2027, 1, 9),
        )
        assert scan(render_item(corpus.items[lesson.id])) == [], lesson.id
    assert scan(render_shared(corpus)) == []


def test_provenance_token_is_stable_keyed_and_anonymous():
    a1 = source_token("customer-a", b"k1")
    assert a1 == source_token("customer-a", b"k1")
    assert a1 != source_token("customer-a", b"k2")
    assert a1 != source_token("customer-b", b"k1")
    assert "customer" not in a1 and scan(a1) == []
