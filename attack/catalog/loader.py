import hashlib
import re
from pathlib import Path

import yaml

from attack.catalog.flags import FlagDef
from attack.catalog.models import Scenario

DEFAULT_CATALOG_DIR = Path(__file__).with_name("scenarios")
Catalog = dict[str, Scenario]


class CatalogError(ValueError):
    pass


def _files(directory: Path) -> list[Path]:
    return sorted(directory.glob("*.yaml"))


def load_catalog(directory: Path = DEFAULT_CATALOG_DIR) -> Catalog:
    catalog: Catalog = {}
    for path in _files(directory):
        for row in yaml.safe_load(path.read_text()) or []:
            scenario = Scenario(**row)
            if scenario.id in catalog:
                raise CatalogError(f"duplicate scenario id {scenario.id}")
            catalog[scenario.id] = scenario
    return catalog


def catalog_version(directory: Path = DEFAULT_CATALOG_DIR) -> str:
    """Hash of the catalog files, stamped on every event for deterministic replay."""
    digest = hashlib.sha256()
    for path in _files(directory):
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()[:12]


def normalise_path(path: str) -> str:
    return re.sub(r"\{\w+\}", "{}", path)


def validate_catalog(catalog: Catalog, flags: list[FlagDef]) -> None:
    """Every scenario's flag must exist for its customer and cover its probe path."""
    by_key = {(f.customer_id, f.flag): f for f in flags}
    for s in catalog.values():
        flag = by_key.get((s.customer_id, s.flag))
        if flag is None:
            raise CatalogError(f"{s.id}: flag {s.flag!r} not in registry for {s.customer_id}")
        covered = {normalise_path(e) for e in flag.endpoints}
        if normalise_path(s.probe.path) not in covered:
            raise CatalogError(f"{s.id}: path {s.probe.path!r} not covered by flag endpoints")
