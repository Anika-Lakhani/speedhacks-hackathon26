import importlib

import pytest

PACKAGES = ["contracts", "keewano", "sites", "attack", "distill"]


@pytest.mark.parametrize("name", PACKAGES)
def test_package_imports(name):
    importlib.import_module(name)
