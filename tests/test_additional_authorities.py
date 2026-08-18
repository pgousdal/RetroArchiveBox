import hashlib
import sqlite3
from pathlib import Path

import pytest

from rab.additional_authorities import AdditionalAuthority
from rab.api import CatalogueAPI
from rab.authority import Authority
from rab.catalogue import Catalogue
from rab.errors import RabError
from rab.model import IngestRequest, Rights
from rab.media import MediaRepresentation, RepresentationKind, RepresentationRelation
from rab.store import Archive


def _mame_xml(sha1: str, crc: str) -> bytes:
    return f'''<?xml version="1.0"?>
<!DOCTYPE softwarelist SYSTEM "softwarelist.dtd">
<softwarelist name="amiga_fixture" description="Amiga fixture">
<software name="demo" supported="yes"><description>Demo</description><year>1990</year><publisher>Publisher</publisher>
<part name="flop1" interface="floppy_3_5"><feature name="part_id" value="Disk 1"/><dataarea name="flop" size="4"><rom name="demo.adf" size="4" crc="{crc}" sha1="{sha1}"/></dataarea></part>
<part name="cd1" interface="cdrom"><diskarea name="cdrom"><disk name="demo.chd" sha1="{'f' * 40}"/></diskarea></part>
</software></softwarelist>'''.encode()


def _nointro_xml(sha1: str, crc: str) -> bytes:
    return f'''<?xml version="1.0"?><datafile><header><name>Commodore - Amiga</name></header>
<game name="Demo (1990)(Publisher)"><rom name="demo.adf" size="4" crc="{crc}" sha1="{sha1}"/></game></datafile>'''.encode()


def test_mame_and_nointro_component_purposes_and_cross_assertions(tmp_path):
    payload = b"demo"; sha1 = hashlib.sha1(payload).hexdigest(); crc = f"{__import__('zlib').crc32(payload) & 0xffffffff:08x}"
    mame = tmp_path / "amiga.xml"; mame.write_bytes(_mame_xml(sha1, crc))
    nointro = tmp_path / "amiga.dat"; nointro.write_bytes(_nointro_xml(sha1, crc))
    archive = Archive(tmp_path / "archive"); additional = AdditionalAuthority(archive)
    mame_result = additional.import_file(mame, authority_id="MAME", release="mame-fixture-1", source="mame")
    nointro_result = additional.import_file(nointro, authority_id="NO_INTRO", release="nointro-fixture-1", source="nointro")
    obj_path = tmp_path / "object.bin"; obj_path.write_bytes(payload)
    object_id = archive.ingest(IngestRequest(obj_path, "manual", "object.bin", Rights.PRIVATE_LICENSED, "application/octet-stream"))["object_id"]
    mame_assertion = additional.match(object_id, authority_id="MAME")
    nointro_assertion = additional.match(object_id, authority_id="NO_INTRO")
    assert mame_assertion[0]["result"] == "EXACT_MATCH"
    assert nointro_assertion[0]["result"] == "EXACT_MATCH"
    assert {x["authority_purpose"] for x in Authority(archive).assertions(object_id)} == {"EMULATION_REFERENCE", "IDENTIFICATION"}
    assert archive.show(object_id)["occurrences"][0]["rights"] == "PRIVATE_LICENSED"
    with sqlite3.connect(additional.authority.db_path) as db:
        assert db.execute("SELECT count(*) FROM component_records WHERE authority_id='MAME' AND component_type='ROM'").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM component_records WHERE authority_id='MAME' AND component_type='DISK'").fetchone()[0] == 1
    assert mame_result["components"] == 2 and nointro_result["components"] == 1
    Authority(archive).rebuild()
    assert {x["authority_purpose"] for x in Authority(archive).assertions(object_id)} == {"EMULATION_REFERENCE", "IDENTIFICATION"}
    api = CatalogueAPI(Catalogue(archive)); Catalogue(archive).rebuild()
    assert api.dispatch("GET", f"/api/v1/authorities/{mame_result['dataset_id']}/records")[0] == 200


def test_additional_authorities_rebuild_and_parser_safety(tmp_path):
    payload = b"safe"; sha1 = hashlib.sha1(payload).hexdigest(); crc = f"{__import__('zlib').crc32(payload) & 0xffffffff:08x}"
    source = tmp_path / "mame.xml"; source.write_bytes(_mame_xml(sha1, crc))
    archive = Archive(tmp_path / "archive"); additional = AdditionalAuthority(archive)
    additional.import_file(source, authority_id="MAME", release="fixture", source="mame")
    with sqlite3.connect(additional.authority.db_path) as db:
        before = [list(row) for row in db.execute("SELECT * FROM component_records ORDER BY record_id")]
    rebuilt = additional.authority.rebuild()
    with sqlite3.connect(additional.authority.db_path) as db:
        after = [list(row) for row in db.execute("SELECT * FROM component_records ORDER BY record_id")]
    assert rebuilt["components"] == 2 and before == after and additional.authority.verify()["outcome"] == "PASS"
    bad = tmp_path / "bad.xml"; bad.write_bytes(b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x/>')
    with pytest.raises(RabError):
        additional.import_file(bad, authority_id="NO_INTRO", release="bad", source="bad")
    assert len(list(archive.objects.rglob("master"))) == 2


def test_sps_representation_kinds_do_not_claim_equivalence():
    ipf = MediaRepresentation("sha256:ipf", RepresentationKind.PRESERVATION_FORMAT, "floppy")
    adf = MediaRepresentation("sha256:adf", RepresentationKind.SECTOR_IMAGE, "floppy",
                              source_object=ipf.object_id, relation=RepresentationRelation.DATA_TRACK_EXTRACTION)
    assert ipf.object_id != adf.object_id and adf.relation != RepresentationRelation.LOSSLESS_DERIVATIVE
