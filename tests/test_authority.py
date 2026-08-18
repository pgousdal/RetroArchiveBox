import json

import pytest

from rab.api import CatalogueAPI
from rab.authority import Authority, parse_tosec
from rab.catalogue import Catalogue
from rab.errors import RabError
from rab.model import IngestRequest, Rights
from rab.store import Archive


DAT = b'''<?xml version="1.0"?>
<datafile><header><name>TOSEC Test</name><version>2026-01</version><date>2026-01-02</date></header>
<game name="Demo (1990)(Publisher)(EN)" system="Amiga"><rom name="DEMO" size="4" crc="81dc9bdb" md5="098f6bcd4621d373cade4e832627b4f6" sha1="a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" status="verified" /></game>
</datafile>'''


def test_tosec_parse_preserves_name_and_hashes():
    header, records = parse_tosec(DAT)
    assert header["name"] == "TOSEC Test"
    assert records[0].name == "Demo (1990)(Publisher)(EN)"
    assert records[0].size == 4 and records[0].crc32 == "81dc9bdb"
    assert records[0].md5 and records[0].sha1


def test_tosec_real_logiqx_doctype_and_multiple_roms():
    data = b'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE datafile PUBLIC "-//Logiqx//DTD ROM Management Datafile//EN" "http://www.logiqx.com/Dats/datafile.dtd">
<datafile><header><name>Commodore Amiga - Multipart</name><version>2025-03-13</version></header>
<game name="Unicode Cafe"><description>Unicode Cafe</description>
<rom name="one.bin" size="1" crc="c4ca4238" md5="c4ca4238c4ca4238c4ca4238c4ca4238" sha1="1111111111111111111111111111111111111111" />
<rom name="two.bin" size="2" crc="c81e728d" md5="c81e728d9d4c2f636f067f89cc14862c" sha1="2222222222222222222222222222222222222222" />
</game></datafile>'''.decode().encode()
    header, records = parse_tosec(data, "real-shape.dat")
    assert header["version"] == "2025-03-13"
    assert len(records) == 2 and records[0].system == "Commodore Amiga"
    assert records[0].name == "Unicode Cafe" and records[1].rom_name == "two.bin"


def test_authority_import_match_rebuild_and_rights_independence(tmp_path):
    dat = tmp_path / "test.dat"; dat.write_bytes(DAT)
    content = tmp_path / "content.bin"; content.write_bytes(b"test")
    archive = Archive(tmp_path / "archive")
    obj = archive.ingest(IngestRequest(content, "manual", "content.bin", Rights.RESTRICTED, "application/octet-stream"))["object_id"]
    authority = Authority(archive)
    imported = authority.import_tosec(dat, release="tosec-2026")
    assertions = authority.assertions(obj)
    assert assertions[0]["result"] == "EXACT_MATCH"
    assert assertions[0]["canonical_name"] == "Demo (1990)(Publisher)(EN)"
    assert archive.show(obj)["occurrences"][0]["rights"] == "RESTRICTED"
    before = {p: p.read_bytes() for p in archive.objects.rglob("*") if p.is_file()}
    semantic = assertions
    archive.db_path  # catalogue DB is independent from authority DB
    (archive.root / "authority.sqlite3").unlink()
    assert Authority(archive).rebuild()["assertions"] == 2
    assert Authority(archive).assertions(obj)[0]["result"] == semantic[0]["result"]
    assert before == {p: p.read_bytes() for p in archive.objects.rglob("*") if p.is_file()}
    assert Authority(archive).verify()["outcome"] == "PASS"
    assert imported["dataset_id"]


def test_authority_history_and_ambiguity(tmp_path):
    one = tmp_path / "one.dat"; one.write_bytes(DAT)
    two = tmp_path / "two.dat"; two.write_bytes(DAT.replace(b"Demo (1990)(Publisher)(EN)", b"Demo Renamed (1990)(Publisher)(EN)"))
    content = tmp_path / "content"; content.write_bytes(b"test")
    archive = Archive(tmp_path / "archive")
    obj = archive.ingest(IngestRequest(content, "manual", "content", Rights.UNKNOWN, "application/octet-stream"))["object_id"]
    authority = Authority(archive)
    authority.import_tosec(one, release="old")
    authority.import_tosec(two, release="new")
    names = {x["canonical_name"] for x in authority.assertions(obj) if x["canonical_name"]}
    assert names == {"Demo (1990)(Publisher)(EN)", "Demo Renamed (1990)(Publisher)(EN)"}


def test_malformed_tosec_preserves_source(tmp_path):
    dat = tmp_path / "bad.dat"; dat.write_bytes(b"<!DOCTYPE datafile [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><datafile/>")
    archive = Archive(tmp_path / "archive")
    with pytest.raises(RabError):
        Authority(archive).import_tosec(dat)
    assert len(list(archive.objects.rglob("master"))) == 1
    assert Authority(archive).list()[0]["status"] == "FAILED"


def test_authority_api_and_catalogue_object_view(tmp_path):
    dat = tmp_path / "test.dat"; dat.write_bytes(DAT)
    content = tmp_path / "content"; content.write_bytes(b"test")
    archive = Archive(tmp_path / "archive")
    obj = archive.ingest(IngestRequest(content, "manual", "content", Rights.UNKNOWN, "application/octet-stream"))["object_id"]
    Authority(archive).import_tosec(dat)
    catalogue = Catalogue(archive); catalogue.rebuild()
    api = CatalogueAPI(catalogue)
    assert api.dispatch("GET", "/api/v1/authorities")[0] == 200
    assert api.dispatch("GET", f"/api/v1/objects/{obj}/assertions")[1][0]["result"] == "EXACT_MATCH"
    assert Catalogue(archive).show_object(obj)["authority_assertions"]
