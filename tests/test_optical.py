import json

import pytest

from rab.api import CatalogueAPI
from rab.catalogue import Catalogue
from rab.errors import PolicyError, RabError
from rab.media import OpticalAdapter, OpticalManager, OpticalOutcome
from rab.model import Rights
from rab.store import Archive
from rab.web import WebApplication


class _OpticalRunner:
    def __init__(self, *, mixed=False): self.mixed = mixed
    def __call__(self, command, **kwargs):
        class Result:
            returncode = 0; stderr = ""
            stdout = ""
        result = Result()
        if command[0] == "lsblk": result.stdout = json.dumps({"blockdevices": [{"path": "/dev/sr0", "type": "rom", "size": 4096, "model": "Fixture CD"}]})
        elif command[0] == "blkid": result.stdout = "" if self.mixed else "TYPE=iso9660\nLABEL=RABTEST\nBLOCK_SIZE=2048\n"
        elif command[0] == "dd":
            output = next(x.removeprefix("of=") for x in command if x.startswith("of=")); open(output, "wb").write(b"O" * 4096)
        return result


def test_optical_inspection_planning_capture_duplicate_and_api(tmp_path):
    archive = Archive(tmp_path / "archive"); adapter = OpticalAdapter(runner=_OpticalRunner(), which=lambda _: None); manager = OpticalManager(archive, adapter=adapter)
    inspection = manager.inspect("/dev/sr0")
    assert inspection["medium_type"] == "data-cd" and inspection["filesystem"] == "iso9660"
    first = manager.capture("/dev/sr0", rights=Rights.UNKNOWN)
    second = manager.capture("/dev/sr0", rights=Rights.RESTRICTED)
    assert first["state"] == OpticalOutcome.COMPLETE.value and second["object_id"] == first["object_id"]
    assert len(list(archive.objects.rglob("master"))) == 1
    assert len(archive.show(first["object_id"])["occurrences"]) == 2
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
