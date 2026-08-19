import json

import pytest

from rab.api import CatalogueAPI
from rab.catalogue import Catalogue
from rab.errors import PolicyError
from rab.flux import FluxManager
from rab.media import MediaManager
from rab.physical import PhysicalMediaOrchestrator
from rab.store import Archive
from rab.web import WebApplication


class FixtureBlock:
    def __init__(self, *, safe=True, count=1): self.safe, self.count, self.captures = safe, count, 0
    def devices(self): return [{"path": f"/dev/fixture{n}", "type": "disk", "size": 13, "rm": True, "removable": True, "safety": "SAFE_CANDIDATE" if self.safe else "PROTECTED", "model": "Fixture USB"} for n in range(self.count)]
    def capabilities(self): return {"adapter_id": "fixture-block", "available": True, "kind": "fixture", "write_source": False}
    def inspect(self, device): return next(x for x in self.devices() if x["path"] == device)
    def capture(self, device, destination, *, timeout=86400):
        self.captures += 1; self.inspect(device); destination.parent.mkdir(parents=True, exist_ok=True); destination.write_bytes(b"fixture whole-device")
        return {"device": device, "bytes": destination.stat().st_size, "capture_tool": "fixture"}


class EmptyOptical:
    def devices(self): return []


class EmptyFlux:
    def devices(self): return []


def orchestrator(tmp_path, *, safe=True, count=1):
    archive = Archive(tmp_path / "archive")
    block_adapter = FixtureBlock(safe=safe, count=count)
    return PhysicalMediaOrchestrator(archive, optical=EmptyOptical(), block=MediaManager(archive, adapter=block_adapter), flux=EmptyFlux()), block_adapter, archive


def test_unified_discovery_dry_run_is_non_mutating_and_routes_block_plan(tmp_path):
    manager, adapter, archive = orchestrator(tmp_path)
    candidates = manager.public_candidates()
    assert candidates[0]["candidate_id"] == "block:0"
    assert "device" not in candidates[0]
    result = manager.ingest(candidate_id="block:/dev/fixture0", dry_run=True)
    assert result["capture_performed"] is False and result["plan"]["capture"]["method"] == "block-device-dd"
    assert adapter.captures == 0 and not list(archive.root.rglob("*"))


def test_confirmation_capture_duplicate_and_session_report(tmp_path):
    manager, adapter, archive = orchestrator(tmp_path)
    first = manager.ingest(candidate_id="block:/dev/fixture0", confirm=True, metadata={"collection": "Fixture USB", "volume": "1"})
    second = manager.ingest(candidate_id="block:/dev/fixture0", confirm=True)
    assert first["report"]["preservation"] == "COMPLETE"
    assert first["report"]["object_id"] == second["report"]["object_id"]
    assert len(archive.show(first["report"]["object_id"])["occurrences"]) == 2
    assert adapter.captures == 2 and len(manager.sessions()) == 2
    assert manager.sessions()[0]["successful_captures"] == 1


def test_ambiguous_and_unsafe_candidates_fail_closed(tmp_path):
    manager, _, _ = orchestrator(tmp_path, count=2)
    with pytest.raises(PolicyError, match="multiple candidates"):
        manager.ingest(dry_run=True)
    unsafe, _, _ = orchestrator(tmp_path / "unsafe", safe=False)
    with pytest.raises(PolicyError, match="no safe"):
        unsafe.ingest(dry_run=True)


def test_noninteractive_requires_confirmation_and_status_surfaces_redact_paths(tmp_path):
    manager, _, archive = orchestrator(tmp_path)
    with pytest.raises(PolicyError, match="confirmation"):
        manager.ingest(candidate_id="block:/dev/fixture0", interactive=False)
    api = CatalogueAPI(Catalogue(archive)); status, payload = api.dispatch("GET", "/api/v1/media/status")
    assert status == 200 and "/dev/fixture0" not in json.dumps(payload)
    web_status, _, body, _ = WebApplication(archive).dispatch("GET", "/retro/physical-media")
    assert web_status == 200 and "Unified Physical Media" in body and "/dev/fixture0" not in body


def test_batch_session_processes_multiple_media_without_reusing_session_job(tmp_path):
    manager, adapter, archive = orchestrator(tmp_path)
    result = manager.ingest(candidate_id="block:/dev/fixture0", confirm=True, batch=True, max_media=2, interactive=False)
    assert result["state"] == "COMPLETED" and result["session"]["media_count"] == 2
    assert adapter.captures == 2 and len(archive.show(result["session"]["media"][0]["report"]["object_id"])["occurrences"]) == 2
