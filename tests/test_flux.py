import json

import pytest

from rab.api import CatalogueAPI
from rab.catalogue import Catalogue
from rab.errors import PolicyError, RabError
from rab.flux import FluxDecoder, FluxManager, FloppyProfile, GreaseweazleAdapter
from rab.store import Archive
from rab.web import WebApplication


class Runner:
    def __init__(self, *, fail=False, partial=False):
        self.fail = fail
        self.partial = partial
        self.commands = []

    def __call__(self, command, **kwargs):
        self.commands.append(command)

        class Result:
            returncode = 0
            stdout = ""
            stderr = ""

        result = Result()
        if self.fail and command[1] == "read":
            result.returncode = 1
            if self.partial:
                Path = __import__("pathlib").Path
                Path(command[-1]).write_bytes(b"SCP-PARTIAL")
            return result
        if command[1] == "info":
            result.stdout = "Host Tools: 1.23\nDevice:\n  Port: /dev/serial/by-id/gw\nModel: Greaseweazle V4.1\nFirmware: 1.2\nSerial: FIXTURE\n"
        elif command[1] == "read":
            Path = __import__("pathlib").Path
            Path(command[-1]).write_bytes(b"SCP-FIXTURE-RAW-FLUX")
            result.stderr = "T0.0: 80 sectors\nT1.0: weak bits observed\n"
        return result


def test_greaseweazle_read_only_capture_duplicate_and_surfaces(tmp_path):
    runner = Runner()
    adapter = GreaseweazleAdapter(runner=runner, which=lambda _: "/usr/bin/gw")
    manager = FluxManager(Archive(tmp_path / "archive"), adapter=adapter)
    first = manager.capture("/dev/serial/by-id/gw", profile=FloppyProfile.DD35.value, platform_hint="amiga", physical_medium_id="disk-1", verification="fast")
    second = manager.capture("/dev/serial/by-id/gw", profile=FloppyProfile.DD35.value)
    assert first["state"] == "COMPLETE"
    assert first["object_id"] == second["object_id"]
    assert first["capture"]["capture_mode_read_only"] is True
    assert first["capture"]["hardware_write_protection"] == "unknown"
    assert first["platform_hint"] == "amiga" and first["physical_medium_id"] == "disk-1" and first["rights"] == "UNKNOWN"
    assert "write" not in " ".join(runner.commands[-1])
    assert len(manager.archive.show(first["object_id"])["occurrences"]) == 2
    assert manager.jobs()[0]["capture"]["weak_track_observations"]
    api = CatalogueAPI(Catalogue(manager.archive))
    assert api.dispatch("GET", "/api/v1/media/flux/adapters")[0] == 200
    assert api.dispatch("GET", "/api/v1/media/flux/jobs")[0] == 200
    assert WebApplication(manager.archive).dispatch("GET", "/retro/flux")[0] == 200


def test_flux_rejects_write_and_unknown_profile(tmp_path):
    adapter = GreaseweazleAdapter(runner=Runner(), which=lambda _: "/usr/bin/gw")
    with pytest.raises(PolicyError):
        adapter.capture("/dev/gw", tmp_path / "bad.img")
    with pytest.raises(PolicyError):
        FluxManager(Archive(tmp_path / "archive"), adapter=adapter).capture("/dev/gw", profile="amiga")


def test_flux_tool_missing_and_malformed_output(tmp_path):
    missing = GreaseweazleAdapter(which=lambda _: None)
    assert missing.capabilities()["available"] is False
    assert missing.devices() == []
    broken = GreaseweazleAdapter(runner=lambda *_args, **_kwargs: type("R", (), {"returncode": 0, "stdout": "bad", "stderr": ""})(), which=lambda _: "/usr/bin/gw")
    assert broken.info("/dev/gw")["available"] is True


def test_partial_capture_is_preserved_and_repeat_differences_are_evidence(tmp_path):
    partial_adapter = GreaseweazleAdapter(runner=Runner(fail=True, partial=True), which=lambda _: "/usr/bin/gw")
    partial_manager = FluxManager(Archive(tmp_path / "partial"), adapter=partial_adapter)
    partial = partial_manager.capture("/dev/gw", profile=FloppyProfile.DD35.value)
    assert partial["state"] == "COMPLETE_WITH_WARNINGS" and partial["capture"]["outcome"] == "PARTIAL"
    first_runner = Runner(); archive = Archive(tmp_path / "repeat"); manager = FluxManager(archive, adapter=GreaseweazleAdapter(runner=first_runner, which=lambda _: "/usr/bin/gw"))
    first = manager.capture("/dev/gw", profile=FloppyProfile.DD35.value, physical_medium_id="disk-1")
    class DifferentRunner(Runner):
        def __call__(self, command, **kwargs):
            result = super().__call__(command, **kwargs)
            if command[1] == "read": __import__("pathlib").Path(command[-1]).write_bytes(b"SCP-DIFFERENT")
            return result
    manager.adapter = GreaseweazleAdapter(runner=DifferentRunner(), which=lambda _: "/usr/bin/gw")
    second = manager.capture("/dev/gw", profile=FloppyProfile.DD35.value, physical_medium_id="disk-1", repeat_of=first["job_id"])
    assert second["repeat_comparison"]["byte_identical"] is False and second["object_id"] != first["object_id"]


def test_flux_decoder_keeps_raw_and_creates_distinct_derivative(tmp_path):
    runner = Runner()
    archive = Archive(tmp_path / "archive")
    manager = FluxManager(archive, adapter=GreaseweazleAdapter(runner=runner, which=lambda _: "/usr/bin/gw"),
                          decoders={"fixture": FluxDecoder("fixture-amiga-adf", "adf", runner=lambda source, destination, **_: (destination.write_bytes(b"ADF-FIXTURE") or type("R", (), {"returncode": 0})()))})
    capture = manager.capture("/dev/gw", profile=FloppyProfile.DD35.value)
    derived = manager.decode(capture["object_id"], "adf")
    assert derived["object_id"] != capture["object_id"]
    assert archive.object_dir(archive.resolve(capture["object_id"])) .joinpath("master").read_bytes() == b"SCP-FIXTURE-RAW-FLUX"
    assert archive.show(derived["object_id"])["preservation_state"] == "DERIVATIVE"
    assert any(x["relationship"] == "DERIVED_FROM" for x in __import__("rab.identity", fromlist=["IdentityCatalogue"]).IdentityCatalogue(archive).relationships(derived["object_id"]))
