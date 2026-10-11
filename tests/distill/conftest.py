import pytest

from attack.catalog import load_catalog


@pytest.fixture(scope="session")
def catalog():
    return load_catalog()


@pytest.fixture(autouse=True)
def provenance_salt(monkeypatch):
    """Never create the real local salt file from tests."""
    monkeypatch.setenv("SWARMSHIELD_PROVENANCE_SALT", "test-salt")
