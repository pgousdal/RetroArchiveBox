import json

import pytest

from rab.api import CatalogueAPI
from rab.analysis import AnalysisManager
from rab.catalogue import Catalogue
from rab.errors import PolicyError, RabError
from rab.media import OpticalAdapter, OpticalManager, OpticalOutcome
from rab.model import Rights
from rab.physical_registry import PhysicalMediaRegistry
from rab.store import Archive
from rab.web import WebApplication


class _OpticalRunner:
    def __init__(self, *, mixed=False, fail=False, partial=False, different=False, payload=None): self.mixed = mixed; self.fail = fail; self.partial = partial; self.different = different; self.payload = payload
    def __call__(self, command, **kwargs):
        class Result:
            returncode = 0; stderr = ""
            stdout = ""
        result = Result()
        if command[0] == "lsblk": result.stdout = json.dumps({"blockdevices": [{"path": "/dev/sr0", "type": "rom", "size": 4096, "model": "Fixture CD"}]})
        elif command[0] == "blkid": result.stdout = "" if self.mixed else "TYPE=iso9660\nLABEL=RABTEST\nBLOCK_SIZE=2048\n"
        elif command[0] == "dd":
            output = next(x.removeprefix("of=") for x in command if x.startswith("of=")); open(output, "wb").write(self.payload if self.payload is not None else b"O" * 4096)
            if self.different: open(output, "wb").write(b"P" * 4096)
            if self.fail: result.returncode = 1
        return result


def test_optical_inspection_planning_capture_duplicate_and_api(tmp_path):
    archive = Archive(tmp_path / "archive"); adapter = OpticalAdapter(runner=_OpticalRunner(), which=lambda _: None); manager = OpticalManager(archive, adapter=adapter)
    medium = PhysicalMediaRegistry(archive).register("optical_disc")
    inspection = manager.inspect("/dev/sr0")
    assert inspection["medium_type"] == "data-cd" and inspection["filesystem"] == "iso9660"
    first = manager.capture("/dev/sr0", physical_medium_id=medium["physical_medium_id"], rights=Rights.UNKNOWN)
    second = manager.capture("/dev/sr0", physical_medium_id=medium["physical_medium_id"], repeat_of=first["job_id"], rights=Rights.RESTRICTED)
    assert first["state"] == OpticalOutcome.COMPLETE.value and second["object_id"] == first["object_id"]
    assert len(list(archive.objects.rglob("master"))) == 1
    assert len(archive.show(first["object_id"])["occurrences"]) == 2
    assert len(PhysicalMediaRegistry(archive).captures(medium["physical_medium_id"])) == 2
    api = CatalogueAPI(Catalogue(archive))
    assert api.dispatch("GET", "/api/v1/media/optical/jobs")[0] == 200
    web = WebApplication(archive)
    assert web.dispatch("GET", "/retro/optical")[0] == 200


def test_optical_audio_mixed_mode_requires_track_tool_and_malformed_output_fails(tmp_path):
    mixed = OpticalAdapter(runner=_OpticalRunner(mixed=True), which=lambda _: None)
    plan = mixed.plan(mixed.inspect("/dev/sr0"))
    assert plan["state"] == OpticalOutcome.TOOL_MISSING.value
    class Broken:
        returncode = 0; stdout = "not json"; stderr = ""
    with pytest.raises(RabError): OpticalAdapter(runner=lambda *_args, **_kwargs: Broken(), which=lambda _: None).devices()


def test_optical_partial_repeat_and_track_evidence(tmp_path):
    partial = OpticalManager(Archive(tmp_path / "partial"), adapter=OpticalAdapter(runner=_OpticalRunner(fail=True, partial=True), which=lambda _: None))
    first = partial.capture("/dev/sr0", physical_medium_id="disc-1")
    assert first["state"] == OpticalOutcome.COMPLETE_WITH_WARNINGS and first["capture"]["outcome"] == OpticalOutcome.PARTIAL
    runner = _OpticalRunner(); archive = Archive(tmp_path / "repeat"); manager = OpticalManager(archive, adapter=OpticalAdapter(runner=runner, which=lambda _: None))
    clean = manager.capture("/dev/sr0", physical_medium_id="disc-1")
    manager.adapter.runner = _OpticalRunner(different=True)
    repeat = manager.capture("/dev/sr0", physical_medium_id="disc-1", repeat_of=clean["job_id"])
    assert repeat["repeat_comparison"]["byte_identical"] is False and repeat["object_id"] != clean["object_id"]
    api = CatalogueAPI(Catalogue(archive)); status, jobs = api.dispatch("GET", "/api/v1/media/optical/jobs")
    assert status == 200 and all("device" not in job for job in jobs)


def test_optical_track_probe_is_explicit_and_non_mutating(tmp_path):
    toc = lambda device: {"medium_type": "mixed-mode", "mixed_mode": True, "tracks": [{"number": 1, "track_type": "data"}, {"number": 2, "track_type": "audio"}], "sessions": 1}
    adapter = OpticalAdapter(runner=_OpticalRunner(), which=lambda _: None, toc_reader=toc)
    inspection = adapter.inspect("/dev/sr0"); plan = adapter.plan(inspection)
    assert len(inspection.tracks) == 2 and inspection.mixed_mode and plan["state"] == OpticalOutcome.TOOL_MISSING.value


def test_optical_iso_capture_flows_into_contained_analysis(tmp_path):
    iso = bytearray(20 * 2048); pvd = 16 * 2048; iso[pvd + 1:pvd + 6] = b"CD001"; root = pvd + 156; iso[root] = 34; iso[root + 2:root + 6] = (18).to_bytes(4, "little"); iso[root + 10:root + 18] = (2048).to_bytes(8, "little"); iso[root + 25] = 2; iso[root + 32] = 1; name = b"HELLO.TXT;1"; entry = 18 * 2048; length = 33 + len(name) + len(name) % 2; iso[entry] = length; iso[entry + 2:entry + 6] = (19).to_bytes(4, "little"); iso[entry + 10:entry + 18] = (7).to_bytes(8, "little"); iso[entry + 32] = len(name); iso[entry + 33:entry + 33 + len(name)] = name; iso[19 * 2048:19 * 2048 + 7] = b"fixture"
    archive = Archive(tmp_path / "archive"); manager = OpticalManager(archive, adapter=OpticalAdapter(runner=_OpticalRunner(payload=bytes(iso)), which=lambda _: None)); capture = manager.capture("/dev/sr0"); job = AnalysisManager(archive).analyze(capture["object_id"], policy="preserve")
    assert job["state"] == "COMPLETE" and any(x.get("analyzer_id") == "iso9660" for x in job["analyzers"]), job["analyzers"]
