import json

import pytest

from rab.api import CatalogueAPI
from rab.catalogue import Catalogue
from rab.errors import PolicyError
from rab.media import MediaManager
from rab.model import Rights
from rab.removable import RemovableManager
from rab.store import Archive
from rab.web import WebApplication


class FixtureRemovable:
    def __init__(self, data=b"whole device", safety="SAFE_CANDIDATE"): self.data, self.safety, self.calls = data, safety, 0
    def capabilities(self): return {"adapter_id": "fixture-removable", "available": True, "kind": "whole-block-device", "write_source": False}
    def devices(self): return [{"path": "/dev/fixture-usb", "type": "disk", "size": len(self.data), "rm": True, "removable": True, "safety": self.safety, "mounted_children": ["/media/usb"] if self.safety == "MOUNTED" else [], "model": "Fixture USB", "transport": "usb", "ro": False}]
    def inspect(self, device): return self.devices()[0]
    def capture(self, device, destination, *, timeout=86400):
        self.calls += 1; destination.parent.mkdir(parents=True, exist_ok=True); destination.write_bytes(self.data)
        return {"device": device, "bytes": len(self.data), "outcome": "COMPLETE", "capture_mode_read_only": True}


def test_removable_whole_device_capture_repeat_dedup_and_redaction(tmp_path):
    archive = Archive(tmp_path / "archive"); adapter = FixtureRemovable(); manager = RemovableManager(archive, media=MediaManager(archive, adapter=adapter))
    source = b"whole device"; first = manager.capture("/dev/fixture-usb", physical_medium_id="usb-1", vendor="Vendor", rights=Rights.UNKNOWN)
    adapter.data = b"different whole device"; second = manager.capture("/dev/fixture-usb", physical_medium_id="usb-1", repeat_of=first["job_id"])
    assert first["representation_kind"] == "WHOLE_DEVICE_IMAGE" and second["repeat_comparison"]["byte_identical"] is False
    assert first["object_id"] != second["object_id"] and source == b"whole device"
    api = CatalogueAPI(Catalogue(archive)); status, jobs = api.dispatch("GET", "/api/v1/removable/jobs")
    assert status == 200 and all("device" not in x and "operator_notes" not in x for x in jobs)
    assert WebApplication(archive).dispatch("GET", "/retro/removable")[0] == 200


def test_removable_mounted_or_unsafe_device_refused(tmp_path):
    archive = Archive(tmp_path / "archive"); adapter = FixtureRemovable(safety="MOUNTED"); manager = RemovableManager(archive, media=MediaManager(archive, adapter=adapter))
    assert manager.plan("/dev/fixture-usb")["allowed"] is False
    assert adapter.calls == 0


def test_removable_unknown_media_is_still_capturable(tmp_path):
    archive = Archive(tmp_path / "archive"); adapter = FixtureRemovable(data=b"unknown unpartitioned bytes"); manager = RemovableManager(archive, media=MediaManager(archive, adapter=adapter))
    result = manager.capture("/dev/fixture-usb", physical_medium_id="unknown-usb")
    inventory = manager.inventory(result["job_id"])
    assert result["state"] == "COMPLETED" and inventory["inventory"]["partition_table"] == "unknown"
