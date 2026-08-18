from pathlib import Path
import json
import threading
import pytest
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from rab.api import CatalogueAPI
from rab.api import build_server
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
    assert api.dispatch("GET", "/api/v1/search?limit=999999")[1]["limit"] == 100
    assert api.dispatch("GET", "/api/v1/search?offset=-2")[1]["offset"] == 0
    assert api.dispatch("GET", "/api/v1/search?x=" + "a" * 9000)[0] == 414


def test_catalogue_identifies_lha_and_indexes_readme(tmp_path):
    archive = _archive(tmp_path); catalogue = Catalogue(archive); catalogue.rebuild()
    package = catalogue.show_package("aminet:comm/foo")
    assert package["preservation_complete"] is True
    payload = catalogue.show_object(package["payload_object"])
    assert payload["format"] == "lha"
    assert catalogue.search("serial")["returned"] >= 1


def test_catalogue_v1_migration_and_future_schema_rejection(tmp_path):
    archive = _archive(tmp_path); catalogue = Catalogue(archive); catalogue.rebuild()
    with archive.db() as db:
        db.execute("UPDATE cat_schema SET version=1")
        db.execute("ALTER TABLE cat_objects RENAME TO cat_objects_v2")
        db.execute("CREATE TABLE cat_objects AS SELECT sha256,blake3,sha1,md5,crc32,size,media_type,title,format,detection_method,confidence,preservation_state,derived_from,created_at FROM cat_objects_v2")
        db.execute("DROP TABLE cat_objects_v2")
    Catalogue(archive).initialize()
    with archive.db() as db:
        assert db.execute("SELECT version FROM cat_schema").fetchone()[0] == 2
        assert db.execute("SELECT count(*) FROM cat_objects").fetchone()[0] == 2
        assert "format_evidence" in {x[1] for x in db.execute("PRAGMA table_info(cat_objects)")}
        db.execute("UPDATE cat_schema SET version=99")
    try:
        Catalogue(archive).initialize()
    except Exception as exc:
        assert "future" in str(exc)
    else:
        raise AssertionError("future schema was accepted")


def test_corrupt_catalogue_is_rebuilt_without_touching_objects(tmp_path):
    archive = _archive(tmp_path); catalogue = Catalogue(archive); catalogue.rebuild()
    manifests = sorted(archive.objects.glob("**/manifest.json"))
    before = {path: path.read_bytes() for path in manifests}
    archive.db_path.write_bytes(b"not sqlite")
    rebuilt = Catalogue(archive).rebuild()
    assert rebuilt["objects"] == 2 and Catalogue(archive).verify()["outcome"] == "PASS"
    assert before == {path: path.read_bytes() for path in manifests}


def test_actual_http_runtime_and_streaming_download(tmp_path):
    archive = _archive(tmp_path); catalogue = Catalogue(archive); catalogue.rebuild()
    try:
        server = build_server(archive, None, "127.0.0.1", 0)
    except PermissionError:
        pytest.skip("sandbox disallows localhost sockets")
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        status = json.loads(urlopen(base + "/api/v1/status").read())
        assert status["objects"] == 2
        package = json.loads(urlopen(base + "/api/v1/packages/aminet/comm/foo").read())
        object_id = package["payload_object"]
        response = urlopen(base + "/api/v1/objects/" + object_id + "/download")
        assert response.read() == b"LHA payload"
        ranged = urlopen(Request(base + "/api/v1/objects/" + object_id + "/download", headers={"Range": "bytes=0-2"}))
        assert ranged.status == 206 and ranged.read() == b"LHA"
        public_download = CatalogueAPI(catalogue).dispatch("GET", "/api/v1/objects/" + object_id + "/download")[1]
        assert "path" not in public_download["download"]
        with pytest.raises(HTTPError):
            urlopen(base + "/api/v1/objects/not-a-hash/download")
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)


def test_read_only_download_fixity_does_not_append_event(tmp_path):
    archive = _archive(tmp_path); catalogue = Catalogue(archive); catalogue.rebuild()
    package = catalogue.show_package("aminet:comm/foo")
    before = sorted((archive.object_dir(package["payload_object"].split(":", 1)[1]) / "events").glob("*.json"))
    CatalogueAPI(catalogue).download_object(package["payload_object"])
    after = sorted((archive.object_dir(package["payload_object"].split(":", 1)[1]) / "events").glob("*.json"))
    assert after == before
