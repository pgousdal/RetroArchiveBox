import json
from pathlib import Path

import pytest

from rab.api import CatalogueAPI
from rab.catalogue import Catalogue
from rab.errors import PolicyError
from rab.local_ingest import IngestManager, IngestJobState, ProvenanceClass
from rab.media import BlockDeviceAdapter, MediaAdapter, MediaManager
from rab.model import Rights
from rab.store import Archive
from rab.web import WebApplication


def test_local_file_unknown_and_duplicate_provenance(tmp_path):
    archive = Archive(tmp_path / "archive"); source = tmp_path / "mystery.bin"; source.write_bytes(b"unknown local bytes")
    manager = IngestManager(archive, stability_seconds=0)
    first = manager.ingest_file(source, category="purchased", rights=Rights.UNKNOWN, provenance=ProvenanceClass.PURCHASED_DOWNLOAD, notes="operator purchase record")
    second = manager.ingest_file(source, category="personal", rights=Rights.RESTRICTED, provenance=ProvenanceClass.PERSONAL_COPY)
    assert first["state"] == IngestJobState.COMPLETED and second["duplicate"] is True
    assert first["object_id"] == second["object_id"] and source.read_bytes() == b"unknown local bytes"
    shown = archive.show(first["object_id"])
    assert len(shown["occurrences"]) == 2
    assert all(not x["source_path"].startswith("/") for x in shown["occurrences"])
    assert {x["provenance_classification"] for x in shown["occurrences"]} == {"purchased_download", "personal_copy"}
    assert first["rights"] == "UNKNOWN" and second["rights"] == "RESTRICTED"


def test_inbox_scan_readiness_symlinks_and_api_web_status(tmp_path):
    archive = Archive(tmp_path / "archive"); root = tmp_path / "inbox"; manager = IngestManager(archive, inbox_root=root, stability_seconds=0)
    manager.initialize(); (root / "purchased" / "ready.bin").write_bytes(b"ready"); (root / "purchased" / "partial.part").write_bytes(b"partial")
    outside = tmp_path / "outside"; outside.write_bytes(b"outside")
    try: (root / "purchased" / "escape.bin").symlink_to(outside)
    except OSError: pass
    results = manager.scan_inbox("purchased")
    assert len(results) == 1 and results[0]["state"] == IngestJobState.COMPLETED
    api = CatalogueAPI(Catalogue(archive))
    assert api.dispatch("GET", "/api/v1/ingest/status")[0] == 200
    jobs_status, jobs_payload = api.dispatch("GET", "/api/v1/ingest/jobs")
    assert jobs_status == 200 and "original_path" not in json.dumps(jobs_payload)
    web = WebApplication(archive)
    status, _, body, _ = web.dispatch("GET", "/retro/ingest")
    assert status == 200 and "COMPLETED" in body


class _FakeMedia(MediaAdapter):
    adapter_id = "fixture-block"
    def capabilities(self): return {"adapter_id": self.adapter_id, "available": True, "kind": "fixture"}
    def devices(self): return [{"path": "/dev/fixture0", "type": "disk", "size": 8, "ro": True}]
    def inspect(self, device):
        if device != "/dev/fixture0": raise PolicyError("not a safe fixture device")
        return self.devices()[0]
    def capture(self, device, destination, *, timeout=86400):
        self.inspect(device); destination.parent.mkdir(parents=True, exist_ok=True); destination.write_bytes(b"whole device image")
        return {"device": device, "capture_tool": "fixture", "bytes": destination.stat().st_size}


def test_physical_capture_uses_generic_adapter_and_ingest(tmp_path):
    archive = Archive(tmp_path / "archive"); manager = MediaManager(archive, adapter=_FakeMedia())
    job = manager.capture("/dev/fixture0", rights=Rights.UNKNOWN, provenance=ProvenanceClass.ORIGINAL_PHYSICAL_OWNED, notes="fixture only")
    assert job["object_id"].startswith("sha256:") and job["state"] == IngestJobState.COMPLETED
    assert archive.show(job["object_id"])["occurrences"][0]["provenance_classification"] == "original_physical_owned"
    assert len(list(archive.objects.rglob("master"))) == 1
    assert not list((archive.root / "media" / "staging").rglob("device.img"))


def test_block_device_capture_refuses_active_root(tmp_path, monkeypatch):
    adapter = BlockDeviceAdapter()
    monkeypatch.setattr(adapter, "devices", lambda: [{"path": "/dev/sda", "type": "disk", "size": 100}])
    monkeypatch.setattr(adapter, "_root_source", lambda: "/dev/sda2")
    with pytest.raises(PolicyError): adapter.capture("/dev/sda", tmp_path / "image")
