import io
import json
import time
import zipfile

import pytest

from rab.analysis import AnalysisLimits, AnalysisManager, AnalyzerAdapter, FATAnalyzer, ISO9660Analyzer, LhaAnalyzer, MalformedInput, PartitionAnalyzer, ZipAnalyzer
from rab.identity import IdentityCatalogue
from rab.hashing import hash_file
from rab.model import IngestRequest, Rights
from rab.store import Archive
from rab.api import CatalogueAPI
from rab.catalogue import Catalogue
from rab.products import ProductBuilder
from rab.web import WebApplication


def fat12_bytes(payload=b"DATA", *, filename=b"TEST    TXT"):
    image = bytearray(4 * 512); image[11:13] = (512).to_bytes(2, "little"); image[13] = 1; image[14:16] = (1).to_bytes(2, "little"); image[16] = 1; image[17:19] = (16).to_bytes(2, "little"); image[19:21] = (4).to_bytes(2, "little"); image[21] = 0xf8; image[22:24] = (1).to_bytes(2, "little"); image[54:62] = b"FAT12   "; image[510:512] = b"\x55\xaa"
    image[512:515] = b"\xf8\xff\xff"; image[515:517] = b"\xff\x0f"; image[1024:1035] = filename; image[1035] = 0x20; image[1050:1052] = (2).to_bytes(2, "little"); image[1052:1056] = len(payload).to_bytes(4, "little"); image[1536:1536 + len(payload)] = payload; return bytes(image)


def mbr_bytes(partition):
    image = bytearray(512 + len(partition)); image[446 + 4] = 0x01; image[446 + 8:446 + 12] = (1).to_bytes(4, "little"); image[446 + 12:446 + 16] = (len(partition) // 512).to_bytes(4, "little"); image[510:512] = b"\x55\xaa"; image[512:] = partition; return bytes(image)


def fat16_bytes(payload=b"F16"):
    image = bytearray(fat12_bytes(payload)); image[54:62] = b"FAT16   "; image[512:520] = b"\xf8\xff\xff\xff\xff\xff\0\0"; return bytes(image)


def fat32_bytes(payload=b"F32"):
    image = bytearray(4 * 512); image[11:13] = (512).to_bytes(2, "little"); image[13] = 1; image[14:16] = (1).to_bytes(2, "little"); image[16] = 1; image[32:36] = (4).to_bytes(4, "little"); image[36:40] = (1).to_bytes(4, "little"); image[44:48] = (2).to_bytes(4, "little"); image[82:90] = b"FAT32   "; image[510:512] = b"\x55\xaa"; image[512:516] = b"\xf8\xff\xff\x0f"; image[516:520] = b"\xff\xff\xff\x0f"; image[520:524] = b"\xff\xff\xff\x0f"; image[524:528] = b"\xff\xff\xff\x0f"; image[1024:1035] = b"THIRTY2 TXT"; image[1035] = 0x20; image[1050:1052] = (3).to_bytes(2, "little"); image[1052:1056] = len(payload).to_bytes(4, "little"); image[1536:1536 + len(payload)] = payload; return bytes(image)


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
    assert job["state"] == "COMPLETE_WITH_WARNINGS" and job["materialized_count"] == 0
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
    assert malformed["state"] == "UNSUPPORTED" and malformed["discovered"]


def test_zip_path_safety_rejects_absolute_and_windows_escape(tmp_path):
    analyzer = ZipAnalyzer(); archive = Archive(tmp_path / "archive"); source = tmp_path / "paths.zip"; output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as container:
        container.writestr("/absolute", b"a"); container.writestr("C:\\drive", b"b"); container.writestr("ok.txt", b"c"); link = zipfile.ZipInfo("escape-link"); link.create_system = 3; link.external_attr = 0o120777 << 16; container.writestr(link, "../../outside")
    source.write_bytes(output.getvalue())
    members, warnings = analyzer.list_members(source, AnalysisLimits())
    assert [x["logical_path"] for x in members] == ["ok.txt"] and len(warnings) == 3


def test_mountless_iso_and_fat_directory_discovery(tmp_path):
    iso = bytearray(20 * 2048); pvd = 16 * 2048; iso[pvd + 1:pvd + 6] = b"CD001"
    root = pvd + 156; iso[root] = 34; iso[root + 2:root + 6] = (18).to_bytes(4, "little"); iso[root + 10:root + 18] = (2048).to_bytes(8, "little"); iso[root + 25] = 2; iso[root + 32] = 1
    entry = 18 * 2048; name = b"HELLO.TXT;1"; length = 33 + len(name) + (len(name) % 2); iso[entry] = length; iso[entry + 2:entry + 6] = (19).to_bytes(4, "little"); iso[entry + 10:entry + 18] = (5).to_bytes(8, "little"); iso[entry + 32] = len(name); iso[entry + 33:entry + 33 + len(name)] = name; iso[19 * 2048:19 * 2048 + 5] = b"hello"
    iso_path = tmp_path / "fixture.iso"; iso_path.write_bytes(iso); iso_members, _ = ISO9660Analyzer().list_members(iso_path, AnalysisLimits()); iso_file = next(x for x in iso_members if x["logical_path"] == "HELLO.TXT"); iso_out = tmp_path / "iso-out"; ISO9660Analyzer().materialize_member(iso_path, iso_file, iso_out, AnalysisLimits()); assert iso_out.read_bytes() == b"hello"
    fat_path = tmp_path / "fixture.img"; fat_path.write_bytes(fat12_bytes()); fat_members, _ = FATAnalyzer().list_members(fat_path, AnalysisLimits()); assert fat_members[0]["logical_path"] == "TEST.TXT"
    extracted = tmp_path / "extracted"; FATAnalyzer().materialize_member(fat_path, fat_members[0], extracted, AnalysisLimits()); assert extracted.read_bytes() == b"DATA"
    for name, image, payload in (("fat16", fat16_bytes(), b"F16"), ("fat32", fat32_bytes(), b"F32")):
        source = tmp_path / (name + ".img"); source.write_bytes(image); members, _ = FATAnalyzer().list_members(source, AnalysisLimits()); output = tmp_path / (name + ".out"); FATAnalyzer().materialize_member(source, members[0], output, AnalysisLimits()); assert output.read_bytes() == payload and members[0]["filesystem"] == name


def test_partition_fat_containment_exact_bytes_cas_convergence_and_rights(tmp_path):
    archive = Archive(tmp_path / "archive"); existing_path = tmp_path / "existing.bin"; existing_path.write_bytes(b"DATA")
    existing = archive.ingest(IngestRequest(existing_path, "fixture", "existing.bin", Rights.UNKNOWN, "application/octet-stream"))
    image_path = tmp_path / "usb.img"; image_path.write_bytes(mbr_bytes(fat12_bytes()))
    root = archive.ingest(IngestRequest(image_path, "fixture-device", "usb.img", Rights.RESTRICTED, "application/octet-stream")); before = hash_file(image_path)
    job = AnalysisManager(archive).analyze(root["object_id"], policy="preserve", limits=AnalysisLimits(max_single_bytes=4096, max_bytes=8192))
    assert job["state"] == "COMPLETE" and any(x.get("representation") == "PARTITION" for x in job["discovered"]), job.get("errors")
    child = next(x for x in job["discovered"] if x.get("logical_path") == "TEST.TXT")
    assert child["object_id"] == existing["object_id"] and archive.verify(root["object_id"], record_event=False)["outcome"] == "PASS"
    assert any(x["rights"] == "RESTRICTED" for x in archive.show(existing["object_id"])["occurrences"])
    assert before == hash_file(image_path)


def test_mbr_gpt_superfloppy_and_retro_recognition(tmp_path):
    mbr = tmp_path / "mbr.img"; mbr.write_bytes(mbr_bytes(fat12_bytes())); members, _ = PartitionAnalyzer().list_members(mbr, AnalysisLimits()); assert members[0]["metadata"]["table"] == "MBR"
    gpt = bytearray(40 * 512); gpt[512:520] = b"EFI PART"; gpt[512 + 72:512 + 80] = (2).to_bytes(8, "little"); gpt[512 + 80:512 + 84] = (1).to_bytes(4, "little"); gpt[512 + 84:512 + 88] = (128).to_bytes(4, "little"); gpt[1024:1040] = b"T" * 16; gpt[1056:1064] = (3).to_bytes(8, "little"); gpt[1064:1072] = (5).to_bytes(8, "little"); gpt_path = tmp_path / "gpt.img"; gpt_path.write_bytes(gpt); assert PartitionAnalyzer().list_members(gpt_path, AnalysisLimits())[0][0]["metadata"]["table"] == "GPT"
    superfloppy = tmp_path / "fat.img"; superfloppy.write_bytes(fat12_bytes()); assert not PartitionAnalyzer().probe(superfloppy) and FATAnalyzer().probe(superfloppy)
    adf = tmp_path / "disk.adf"; adf.write_bytes(b"DOS" + b"\0" * (901120 - 3)); d64 = tmp_path / "disk.d64"; d64.write_bytes(b"\0" * 174848); capabilities = AnalysisManager(Archive(tmp_path / "caps")).analyzers
    assert any(x.analyzer_id == "amiga-adf" and x.probe(adf) for x in capabilities) and any(x.analyzer_id == "commodore-disk" and x.probe(d64) for x in capabilities)


def test_lifecycle_idempotence_versions_tool_missing_timeout_and_malformed(tmp_path):
    archive = Archive(tmp_path / "archive"); root = ingest_zip(archive, zip_bytes({"x": b"x"})); manager = AnalysisManager(archive)
    plan = manager.plan(root["object_id"]); first = manager.analyze(root["object_id"]); second = manager.analyze(root["object_id"])
    assert plan["state"] == "PLANNED" and first["job_id"] == second["job_id"] and len(manager.jobs()) == 1
    class V2(ZipAnalyzer): version = "2"
    changed = AnalysisManager(archive, analyzers=[V2()]).analyze(root["object_id"]); assert changed["analysis_key"] != first["analysis_key"]
    lha = tmp_path / "fixture.lha"; lha.write_bytes(b"\0\0-lh5-" + b"x" * 20); lha_obj = archive.ingest(IngestRequest(lha, "fixture", "fixture.lha", Rights.UNKNOWN, "application/octet-stream")); assert AnalysisManager(archive, analyzers=[LhaAnalyzer()]).analyze(lha_obj["object_id"])["state"] == "TOOL_MISSING"
    class Slow(AnalyzerAdapter):
        analyzer_id = "slow"
        def probe(self, path, *, name=""): return True
        def list_members(self, path, limits): time.sleep(.02); return [], []
    timed = AnalysisManager(archive, analyzers=[Slow()]).analyze(root["object_id"], limits=AnalysisLimits(subprocess_timeout=.001), force=True); assert timed["state"] == "TIMEOUT", timed.get("errors")
    class Broken(Slow):
        analyzer_id = "broken"
        def list_members(self, path, limits): raise MalformedInput("fixture malformed")
    assert AnalysisManager(archive, analyzers=[Broken()]).analyze(root["object_id"], force=True)["state"] == "MALFORMED"


def test_analysis_api_web_products_and_observations_are_private_and_deterministic(tmp_path):
    archive = Archive(tmp_path / "archive"); root = ingest_zip(archive, zip_bytes({"nested/a.txt": b"same", "nested/b.txt": b"same"})); manager = AnalysisManager(archive); job = manager.analyze(root["object_id"], policy="preserve")
    api = CatalogueAPI(Catalogue(archive)); sha = root["object_id"].removeprefix("sha256:")
    assert api.dispatch("GET", "/api/v1/analysis/capabilities")[0] == 200 and api.dispatch("GET", f"/api/v1/objects/{sha}/tree")[0] == 200 and api.dispatch("GET", f"/api/v1/objects/{sha}/observations")[0] == 200
    public = api.dispatch("GET", "/api/v1/analysis/jobs/" + job["job_id"])[1]; assert str(archive.root) not in json.dumps(public)
    assert WebApplication(archive).dispatch("GET", "/retro/analysis/" + job["job_id"])[0] == 200
    first = ProductBuilder(archive).build("contained-manifest"); second = ProductBuilder(archive).build("contained-manifest"); assert first["content_sha256"] == second["content_sha256"]
    assert ProductBuilder(archive).build("analysis-coverage")["record_count"] >= 1 and ProductBuilder(archive).build("duplicate-content")["record_count"] == 1
