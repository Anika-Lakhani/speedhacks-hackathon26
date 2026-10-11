import pytest

from attack.catalog import (
    CatalogError,
    Scenario,
    catalog_version,
    load_catalog,
    load_flags,
    validate_catalog,
)


def test_catalog_validates_against_flag_registry(catalog):
    validate_catalog(catalog, load_flags())
    assert 8 <= len(catalog) <= 12


def test_every_flag_has_a_scenario(catalog):
    covered = {(s.customer_id, s.flag) for s in catalog.values()}
    assert covered == {(f.customer_id, f.flag) for f in load_flags()}


def test_flag_registry_scenario_ids_match_catalog(catalog):
    for f in load_flags():
        mapped = {
            s.id for s in catalog.values() if (s.customer_id, s.flag) == (f.customer_id, f.flag)
        }
        assert set(f.scenario_ids) == mapped


def test_duplicate_ids_rejected(tmp_path, catalog):
    row = next(iter(catalog.values())).model_dump(mode="json")
    import yaml

    for name in ("a.yaml", "b.yaml"):
        (tmp_path / name).write_text(yaml.safe_dump([row]))
    with pytest.raises(CatalogError, match="duplicate"):
        load_catalog(tmp_path)


def test_bad_id_format_rejected(catalog):
    row = next(iter(catalog.values())).model_dump()
    with pytest.raises(ValueError):
        Scenario(**{**row, "id": "idor-1"})


def test_unknown_flag_rejected(catalog):
    s = next(iter(catalog.values())).model_copy(update={"flag": "nope"})
    with pytest.raises(CatalogError, match="not in registry"):
        validate_catalog({s.id: s}, load_flags())


def test_uncovered_path_rejected(catalog):
    s = catalog["SCN-IDOR-001"]
    s = s.model_copy(update={"probe": s.probe.model_copy(update={"path": "/other"})})
    with pytest.raises(CatalogError, match="not covered"):
        validate_catalog({s.id: s}, load_flags())


def test_catalog_version_is_stable_and_content_sensitive(tmp_path):
    assert catalog_version() == catalog_version()
    (tmp_path / "x.yaml").write_text("[]")
    v1 = catalog_version(tmp_path)
    (tmp_path / "x.yaml").write_text("[] ")
    assert catalog_version(tmp_path) != v1
