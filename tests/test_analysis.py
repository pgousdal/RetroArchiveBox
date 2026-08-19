import io
import json
import zipfile

import pytest

from rab.analysis import AnalysisLimits, AnalysisManager, ZipAnalyzer
from rab.identity import IdentityCatalogue
from rab.model import IngestRequest, Rights
from rab.store import Archive
from rab.api import CatalogueAPI
from rab.catalogue import Catalogue
from rab.products import ProductBuilder
from rab.web import WebApplication
from rab.analysis import FATAnalyzer, ISO9660Analyzer


def zip_bytes(entries):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, data in entries.items(): archive.writestr(name, data)
    return output.getvalue()


def ingest_zip(archive, data):
    source = archive.root / "input.zip"; source.parent.mkdir(parents=True, exist_ok=True); source.write_bytes(data)
    return archive.ingest(IngestRequest(source, "fixture", "input.zip", Rights.UNKNOWN, "application/zip", "input.zip"))


def test_metadata_only_discovery_does_not_create_children_or_mutate_master(tmp_path):
    archive = Archive(tmp_path / "archive"); root = ingest_zip(archive, zip_bytes({"docs/readme.txt": b"hello", "../escape": b"no"}))
    before = (archive.object_dir(archive.resolve(root["object_id"])) / "master").read_bytes()
    job = AnalysisManager(archive).analyze(root["object_id"], policy="metadata-only")
    assert job["state"] == "COMPLETED_WITH_WARNINGS" and job["materialized_count"] == 0
    assert (archive.object_dir(archive.resolve(root["object_id"])) / "master").read_bytes() == before
    assert IdentityCatalogue(archive).relationships(root["object_id"]) == []


def test_preserve_nested_zip_hashes_children_and_relationships(tmp_path):
    archive = Archive(tmp_path / "archive"); nested = zip_bytes({"game.adf": b"synthetic adf"}); root = ingest_zip(archive, zip_bytes({"nested.zip": nested, "docs/readme.txt": b"hello"}))
    job = AnalysisManager(archive).analyze(root["object_id"], policy="preserve", limits=AnalysisLimits(max_depth=3, max_files=10, max_bytes=1024 * 1024, max_single_bytes=1024 * 1024))
    assert job["materialized_count"] >= 2 and job["relationships"]
    relationships = IdentityCatalogue(archive).relationships(root["object_id"])
    assert any(x["relationship"] == "CONTAINS" for x in relationships)
    assert len(list(archive.objects.rglob("master"))) >= 3
    assert AnalysisManager(archive).status()["completed"] == 1
    assert AnalysisManager(archive).jobs()[0]["malware"][0]["state"] == "NOT_SCANNED"
    assert ProductBuilder(archive).build("containment")["record_count"] >= 1
    assert CatalogueAPI(Catalogue(archive)).dispatch("GET", "/api/v1/analysis/jobs")[0] == 200
    assert WebApplication(archive).dispatch("GET", "/retro/analysis")[0] == 200


def test_limits_and_malformed_archive_stop_safely(tmp_path):
    archive = Archive(tmp_path / "archive"); root = ingest_zip(archive, zip_bytes({f"{x}.txt": b"x" for x in range(4)}))
    limited = AnalysisManager(archive).analyze(root["object_id"], policy="preserve", limits=AnalysisLimits(max_files=2, max_bytes=10, max_single_bytes=10))
    assert limited["limits_reached"]
    bad = archive.root / "bad.zip"; bad.write_bytes(b"not zip"); bad_obj = archive.ingest(IngestRequest(bad, "fixture", "bad.zip", Rights.UNKNOWN, "application/octet-stream", "bad.zip"))
    malformed = AnalysisManager(archive).analyze(bad_obj["object_id"], policy="metadata-only")
    assert malformed["state"] == "COMPLETED" and malformed["discovered"]


def test_zip_path_safety_rejects_absolute_and_windows_escape(tmp_path):
    analyzer = ZipAnalyzer(); archive = Archive(tmp_path / "archive"); source = tmp_path / "paths.zip"; source.write_bytes(zip_bytes({"/absolute": b"a", "C:\\drive": b"b", "ok.txt": b"c"}))
    members, warnings = analyzer.list_members(source, AnalysisLimits())
    assert [x["logical_path"] for x in members] == ["ok.txt"] and len(warnings) == 2


def test_mountless_iso_and_fat_directory_discovery(tmp_path):
    iso = bytearray(20 * 2048); pvd = 16 * 2048; iso[pvd + 1:pvd + 6] = b"CD001"
    root = pvd + 156; iso[root] = 34; iso[root + 2:root + 6] = (18).to_bytes(4, "little"); iso[root + 10:root + 18] = (2048).to_bytes(8, "little"); iso[root + 25] = 2; iso[root + 32] = 1
    entry = 18 * 2048; name = b"HELLO.TXT;1"; length = 33 + len(name) + (len(name) % 2); iso[entry] = length; iso[entry + 2:entry + 6] = (19).to_bytes(4, "little"); iso[entry + 10:entry + 18] = (5).to_bytes(8, "little"); iso[entry + 32] = len(name); iso[entry + 33:entry + 33 + len(name)] = name; iso[19 * 2048:19 * 2048 + 5] = b"hello"
    iso_path = tmp_path / "fixture.iso"; iso_path.write_bytes(iso); iso_members, _ = ISO9660Analyzer().list_members(iso_path, AnalysisLimits()); assert any(x["logical_path"] == "HELLO.TXT" for x in iso_members)
    fat = bytearray(1536); fat[11:13] = (512).to_bytes(2, "little"); fat[13] = 1; fat[14:16] = (1).to_bytes(2, "little"); fat[16] = 1; fat[17:19] = (16).to_bytes(2, "little"); fat[22:24] = (1).to_bytes(2, "little"); fat[54:59] = b"FAT12"; fat[510:512] = b"\x55\xaa"; fat[1024:1032] = b"TEST    "; fat[1032:1035] = b"TXT"; fat[1035] = 0; fat[1052:1056] = (4).to_bytes(4, "little")
    fat_path = tmp_path / "fixture.img"; fat_path.write_bytes(fat); fat_members, _ = FATAnalyzer().list_members(fat_path, AnalysisLimits()); assert fat_members[0]["logical_path"] == "TEST.TXT"
