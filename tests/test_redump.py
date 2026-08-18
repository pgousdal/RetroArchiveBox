import hashlib
import json
import sqlite3
import zlib
from dataclasses import replace
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from rab.api import CatalogueAPI
from rab.catalogue import Catalogue
from rab.errors import RabError
from rab.model import IngestRequest, Rights
from rab.optical import OpticalDisc, OpticalSession, parse_cue
from rab.redump import RedumpAuthority, _safe_xml
from rab.store import Archive


def _hashes(data: bytes) -> dict[str, str | int]:
    return {"size": len(data), "crc32": f"{zlib.crc32(data) & 0xffffffff:08x}",
            "md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest()}


def _fixture(tmp_path: Path):
    payloads = {
        "single.bin": b"S" * 2352,
        "mixed-data.bin": b"D" * 2352,
        "mixed-audio.bin": b"A" * 2352 * 2,
    }
    records = []
    for title, files, category in (
        ("Single Data (Europe)", ["single.bin"], "Games"),
        ("Mixed Mode (Europe)", ["mixed-data.bin", "mixed-audio.bin"], "Games"),
    ):
        roms = []
        for filename in files:
            h = _hashes(payloads[filename])
            roms.append(f'<rom name="{filename}" size="{h["size"]}" crc="{h["crc32"]}" md5="{h["md5"]}" sha1="{h["sha1"]}"/>')
        records.append(f'<game name="{title}"><category>{category}</category><description>{title}</description>{"".join(roms)}</game>')
    dat = (b'<?xml version="1.0"?>\n<!DOCTYPE datafile PUBLIC "-//Logiqx//DTD ROM Management Datafile//EN" "http://www.logiqx.com/Dats/datafile.dtd">\n'
           + f'<datafile><header><name>Commodore - Amiga CD</name><description>fixture</description><version>fixture-1</version><date>2026-01-01</date></header>{"".join(records)}</datafile>'.encode())
    cues = {
        "Single Data (Europe).cue": 'FILE "single.bin" BINARY\n  TRACK 01 MODE1/2352\n    INDEX 01 00:00:00\n',
        "Mixed Mode (Europe).cue": 'REM SESSION 01\nFILE "mixed-data.bin" BINARY\n  TRACK 01 MODE1/2352\n    INDEX 01 00:00:00\nFILE "mixed-audio.bin" BINARY\n  TRACK 02 AUDIO\n    INDEX 00 00:00:00\n    INDEX 01 00:02:00\n',
    }
    dat_path = tmp_path / "redump.dat"; dat_path.write_bytes(dat)
    cues_path = tmp_path / "redump-cues.zip"
    with ZipFile(cues_path, "w", ZIP_DEFLATED) as archive:
        for name, content in cues.items(): archive.writestr(name, content)
    return dat_path, cues_path, payloads


def test_redump_imports_disc_sessions_tracks_and_hashes(tmp_path):
    dat, cues, payloads = _fixture(tmp_path)
    authority = RedumpAuthority(Archive(tmp_path / "archive"))
    result = authority.import_dataset(dat, cues, release="fixture-1", dat_source="https://redump.org/datfile/acd/", cues_source="https://redump.org/cues/acd/")
    assert result["discs"] == 2 and result["tracks"] == 3
    discs = authority.list_discs(result["dataset_id"])
    mixed = next(x for x in discs if x["canonical_title"].startswith("Mixed"))
    shown = authority.show_disc(mixed["disc_id"])
    assert len(shown["tracks"]) == 2
    assert shown["tracks"][0]["track_type"] == "DATA"
    assert shown["tracks"][1]["track_type"] == "AUDIO"
    assert shown["tracks"][1]["start_lba"] == 150
    assert shown["tracks"][0]["sha1"] == _hashes(payloads["mixed-data.bin"])["sha1"]
    assert authority.list_discs(result["dataset_id"])[0]["system"] == "Commodore Amiga CD"
    with sqlite3.connect(authority.authority.db_path) as db:
        assert db.execute("SELECT platform_id FROM platform_mappings WHERE dataset_id=?", (result["dataset_id"],)).fetchone()[0] == "amiga"
    assert authority.verify()["outcome"] == "PASS"


def test_redump_structural_match_partial_and_conflict(tmp_path):
    dat, cues, payloads = _fixture(tmp_path)
    archive = Archive(tmp_path / "archive"); authority = RedumpAuthority(archive)
    dataset = authority.import_dataset(dat, cues, release="fixture-1", dat_source="dat", cues_source="cues")["dataset_id"]
    cue = 'FILE "mixed-data.bin" BINARY\n  TRACK 01 MODE1/2352\n    INDEX 01 00:00:00\n'.encode()
    observed = parse_cue(cue, file_hashes={"mixed-data.bin": _hashes(payloads["mixed-data.bin"])})
    assert authority.compare(observed, dataset)["result"] != "EXACT_MATCH"
    mixed = next(x for x in authority.list_discs(dataset) if x["canonical_title"].startswith("Mixed"))
    full = parse_cue(cues.read_bytes() if False else b'REM SESSION 01\nFILE "mixed-data.bin" BINARY\n  TRACK 01 MODE1/2352\n    INDEX 01 00:00:00\nFILE "mixed-audio.bin" BINARY\n  TRACK 02 AUDIO\n    INDEX 00 00:00:00\n    INDEX 01 00:02:00\n', file_hashes={k: _hashes(v) for k, v in payloads.items()})
    assert authority.compare(full, dataset)["result"] == "EXACT_MATCH"
    assert len(authority.compare(full, dataset)["evidence"]["tracks"]) == 2
    bad = replace(full, sessions=(OpticalSession(1, (replace(full.tracks[0], hashes={"sha1": "0" * 40, "size": 2352}), full.tracks[1])),))
    assert authority.compare(bad, dataset)["result"] == "CONFLICT"
    assert mixed["disc_id"]


def test_redump_assertion_rights_rebuild_and_api(tmp_path):
    dat, cues, payloads = _fixture(tmp_path)
    archive = Archive(tmp_path / "archive"); authority = RedumpAuthority(archive)
    dataset = authority.import_dataset(dat, cues, release="fixture-1", dat_source="dat", cues_source="cues")["dataset_id"]
    observed = parse_cue(b'FILE "single.bin" BINARY\n  TRACK 01 MODE1/2352\n    INDEX 01 00:00:00\n', file_hashes={"single.bin": _hashes(payloads["single.bin"])})
    object_path = tmp_path / "disc-representation.bin"; object_path.write_bytes(b"representation")
    object_id = archive.ingest(IngestRequest(object_path, "physical", "disc.bin", Rights.PRIVATE_LICENSED, "application/octet-stream"))["object_id"]
    assertion = authority.match_observation(object_id, observed, dataset)
    assert assertion["result"] == "EXACT_MATCH"
    assert archive.show(object_id)["occurrences"][0]["rights"] == "PRIVATE_LICENSED"
    before = {p: p.read_bytes() for p in archive.objects.rglob("*") if p.is_file()}
    with sqlite3.connect(authority.authority.db_path) as db:
        semantic = [list(row) for row in db.execute("SELECT * FROM redump_tracks ORDER BY disc_id,track_number")]
    authority.authority.db_path.unlink()
    rebuilt = authority.authority.rebuild()
    assert rebuilt["datasets"] == 1
    assert [list(row) for row in sqlite3.connect(authority.authority.db_path).execute("SELECT * FROM redump_tracks ORDER BY disc_id,track_number")] == semantic
    assert authority.authority.assertions(object_id)[0]["result"] == "EXACT_MATCH"
    assert authority.authority.verify()["outcome"] == "PASS"
    assert before == {p: p.read_bytes() for p in archive.objects.rglob("*") if p.is_file()}
    catalogue = Catalogue(archive); catalogue.rebuild()
    api = CatalogueAPI(catalogue)
    disc_id = assertion["record_id"]
    assert api.dispatch("GET", f"/api/v1/redump/discs/{disc_id}")[0] == 200
    assert api.dispatch("GET", f"/api/v1/redump/discs/{disc_id}/tracks")[0] == 200
    assert api.dispatch("GET", "/api/v1/redump/discs/not-a-disc")[0] == 404


def test_redump_parser_rejects_entities():
    with pytest.raises(RabError):
        _safe_xml(b'<!DOCTYPE datafile [<!ENTITY x SYSTEM "file:///etc/passwd">]><datafile/>', "bad.dat")
