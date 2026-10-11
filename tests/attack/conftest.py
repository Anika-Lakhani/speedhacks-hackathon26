import pytest

from attack.catalog import load_catalog, load_flags
from attack.clients import FakeKeewano, FakeSite
from attack.harness import RunBudget, RunConfig


@pytest.fixture(scope="session")
def catalog():
    return load_catalog()


@pytest.fixture
def keewano():
    return FakeKeewano()


def make_site(customer_id, catalog, keewano, **flags):
    defaults = {f.flag: f.default for f in load_flags() if f.customer_id == customer_id}
    return FakeSite(
        customer_id, catalog, {**defaults, **flags}, evidence_sink=keewano.store_evidence
    )


@pytest.fixture
def site_factory(catalog, keewano):
    return lambda customer_id, **flags: make_site(customer_id, catalog, keewano, **flags)


def make_config(site, **kw):
    kw.setdefault("budget", RunBudget())
    return RunConfig(
        customer_id=site.customer_id, objective="test", target_allowlist=[site.base_url], **kw
    )
