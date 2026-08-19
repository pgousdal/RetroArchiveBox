import json
from pathlib import Path

import pytest

from rab.api import CatalogueAPI
from rab.bootstrap import BootstrapOrchestrator, BootstrapState
from rab.catalogue import Catalogue
from rab.cli import parser, run
from rab.sources import SourceDefinition
from rab.store import Archive
from rab.transports import TransportResolver
from rab.web import WebApplication


class _FTP:
    payload = b"bootstrap fixture bytes"
    def __enter__(self): return self
    def __exit__(self, *_args): return False
    def connect(self, *_args, **_kwargs): pass
    def login(self): pass
    def set_pasv(self, value): assert value is True
    def retrbinary(self, command, callback, blocksize=8192):
        assert command in {"RETR /bootstrap/file.bin", "RETR /bootstrap/second.bin"}; callback(self.payload)


def _source():
    return SourceDefinition.from_dict({"id": "bootstrap-fixture", "name": "Bootstrap fixture", "class": "MIRROR",
        "backend": "ftp", "location": "ftp://fixture.invalid/bootstrap/", "bulk_acquisition": "allowed",
        "rights_default": "REDISTRIBUTABLE", "enabled": True, "mirror_authorized": True,
        "minimum_free_space_bytes": 0})


def test_bootstrap_lifecycle_report_resume_and_idempotent_rerun(tmp_path, monkeypatch):
    monkeypatch.setattr("rab.acquisition.ftplib.FTP", _FTP)
    archive = Archive(tmp_path / "archive"); orchestrator = BootstrapOrchestrator(archive)
    source = _source(); first = orchestrator.start(source, ["file.bin"])
    assert first["state"] == BootstrapState.COMPLETED
    report = orchestrator.store.report(first["job_id"])
    assert report["schema"] == "rab-bootstrap-report-v1" and report["items"]["completed"] == 1
    api = CatalogueAPI(Catalogue(archive))
    assert api.dispatch("GET", "/api/v1/acquisition/bootstrap/jobs")[0] == 200
    assert api.dispatch("GET", "/api/v1/acquisition/bootstrap/jobs/" + first["job_id"] + "/report")[0] == 200
    web = WebApplication(archive)
    assert web.dispatch("GET", "/retro/bootstrap/" + first["job_id"])[0] == 200
    second = orchestrator.start(source, ["file.bin"])
    assert second["state"] == BootstrapState.COMPLETED and len(second["skipped_items"]) == 1
    assert len(list(archive.objects.rglob("master"))) == 1

    interrupted = BootstrapOrchestrator(archive)
    original_fetch = interrupted.resolver.fetch
    interrupted.resolver.fetch = lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt())
    with pytest.raises(KeyboardInterrupt): interrupted.start(source, ["second.bin"])
    jobs = interrupted.store.list(); pending = next(x for x in jobs if x["items"] == ["second.bin"])
    assert pending["state"] == BootstrapState.INTERRUPTED
    interrupted.resolver.fetch = original_fetch
    resumed = interrupted.resume(source, pending["job_id"])
    assert resumed["state"] == BootstrapState.COMPLETED


def test_bootstrap_plan_and_read_only_api_web_status(tmp_path):
    archive = Archive(tmp_path / "archive"); Catalogue(archive).rebuild(); source = _source()
    orchestrator = BootstrapOrchestrator(archive)
    plan = orchestrator.plan(source, ["file.bin"])
    assert plan["schema"] == "rab-bootstrap-plan-v1" and plan["transport_plan"]["selected"]["transport"] == "ftp"
    parsed = parser().parse_args(["--root", str(tmp_path / "archive"), "acquisition", "bootstrap", "plan", "bootstrap-fixture", "--path", "file.bin"])
    # CLI source lookup is configuration-backed; the fixture plan above covers
    # execution and the parser assertion protects the public command shape.
    assert parsed.bootstrap_command == "plan"
    api = CatalogueAPI(Catalogue(archive))
    assert api.dispatch("GET", "/api/v1/acquisition/bootstrap/jobs")[0] == 200
    web = WebApplication(archive)
    status, _, body, _ = web.dispatch("GET", "/retro/bootstrap")
    assert status == 200 and "No bootstrap jobs" in body
