from pathlib import Path

from rab.api import CatalogueAPI
from rab.acquisition import Acquisition
from rab.catalogue import Catalogue
from rab.sources import SourceDefinition
from rab.store import Archive


def _source():
    return SourceDefinition.from_dict({
        "id": "aminet", "name": "Aminet", "class": "MIRROR", "backend": "manual",
        "bulk_acquisition": "allowed", "rights_default": "REDISTRIBUTABLE",
        "enabled": True, "mirror_authorized": True, "platforms": ["Amiga"],
    })


def _archive(tmp_path):
    archive = Archive(tmp_path / "archive")
    source = tmp_path / "source"; (source / "comm").mkdir(parents=True)
    (source / "comm" / "foo.lha").write_bytes(b"LHA payload")
    (source / "comm" / "foo.readme").write_text("Name: Foo\nShort: serial terminal\nVersion: 1.0\n", encoding="ascii")
    Acquisition(archive).sync_aminet(_source(), source)
    return archive


def test_catalogue_rebuild_survives_database_deletion(tmp_path):
    archive = _archive(tmp_path); catalogue = Catalogue(archive)
    first = catalogue.rebuild(); semantic = catalogue.semantic()
    assert first["objects"] == 2 and catalogue.verify()["outcome"] == "PASS"
    archive.db_path.unlink()
    second = Catalogue(archive); assert second.rebuild() == first
    assert second.semantic() == semantic
    assert second.verify()["outcome"] == "PASS"


def test_catalogue_search_filters_and_api(tmp_path):
    archive = _archive(tmp_path); catalogue = Catalogue(archive); catalogue.rebuild()
    result = catalogue.search("serial terminal", platform="amiga", source="aminet", limit=1)
    assert result["returned"] == 1 and result["results"][0]["package_id"] == "aminet:comm/foo"
    api = CatalogueAPI(catalogue)
    assert api.dispatch("GET", "/api/v1/status")[0] == 200
    assert api.dispatch("GET", "/api/v1/packages/aminet/comm/foo")[0] == 200
    assert api.dispatch("GET", "/api/v1/packages/../../etc/passwd")[0] in {400, 404}
    assert api.dispatch("POST", "/api/v1/status")[0] == 405


def test_catalogue_identifies_lha_and_indexes_readme(tmp_path):
    archive = _archive(tmp_path); catalogue = Catalogue(archive); catalogue.rebuild()
    package = catalogue.show_package("aminet:comm/foo")
    assert package["preservation_complete"] is True
    payload = catalogue.show_object(package["payload_object"])
    assert payload["format"] == "lha"
    assert catalogue.search("serial")["returned"] >= 1
