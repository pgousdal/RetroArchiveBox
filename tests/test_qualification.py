import json

import pytest

from rab.api import CatalogueAPI
from rab.catalogue import Catalogue
from rab.errors import IntegrityError
from rab.qualification import QualificationManager, QualificationProfile, SeedPlanManager
from rab.store import Archive
from rab.web import WebApplication


def test_local_seed_qualification_storage_inbox_and_hardware_gates(tmp_path):
    manager = QualificationManager(Archive(tmp_path / "archive"))
    report = manager.run(expected_local_seed_bytes=1)
    states = {item["check_id"]: item["state"] for item in report["checks"]}
    assert report["schema"] == "rab-qualification-run-v1"
    assert states["host"] == "PASS" and states["storage"] == "PASS" and states["inbox"] == "PASS"
    assert states["optical"] == "NOT_PERFORMED" and states["flux"] == "NOT_PERFORMED"
    assert report["readiness"]["level"] == "FIXTURE_QUALIFIED"
    assert manager.report(report["qualification_id"])["qualification_id"] == report["qualification_id"]


def test_backup_acknowledgement_enables_minimal_local_seed_readiness(tmp_path):
    manager = QualificationManager(Archive(tmp_path / "archive"))
    manager.acknowledge_backup(replica="offline-replica-1", last_backup="fixture", restore_test="PASS", operator="fixture")
    report = manager.run(profile=QualificationProfile.LOCAL_SEED_MINIMAL.value, expected_local_seed_bytes=1)
    assert report["readiness"]["level"] == "LOCAL_SEED_READY"
    assert report["checks"][-2]["check_id"] == "backup" and report["checks"][-2]["state"] == "PASS"


def test_qualification_evidence_is_versioned_and_immutable(tmp_path):
    manager = QualificationManager(Archive(tmp_path / "archive")); report = manager.run(only="host")
    with pytest.raises(IntegrityError):
        manager._write_immutable(manager.runs_root / (report["qualification_id"] + ".json"), {**report, "profile": "changed"})
    assert len(manager.runs()) == 1


def test_profile_gate_and_public_api_web_redaction(tmp_path):
    archive = Archive(tmp_path / "archive"); manager = QualificationManager(archive)
    report = manager.run(profile=QualificationProfile.LOCAL_SEED_OPTICAL.value)
    assert "optical" in report["readiness"]["blocking"]
    api_status, api_payload = CatalogueAPI(Catalogue(archive)).dispatch("GET", "/api/v1/qualification/status")
    assert api_status == 200 and str(archive.root) not in json.dumps(api_payload) and "/dev/" not in json.dumps(api_payload)
    web_status, _, body, _ = WebApplication(archive).dispatch("GET", "/retro/qualification")
    assert web_status == 200 and "Qualification" in body and "NOT_PERFORMED" in body


def test_seed_plan_is_operator_planning_metadata(tmp_path):
    plans = SeedPlanManager(Archive(tmp_path / "archive"))
    plans.create("owned-media", collection="Owned media")
    value = plans.add("owned-media", label="Unknown CD #17", category="optical", expected_count=1, provenance="unknown")
    assert value["entries"][0]["label"] == "Unknown CD #17" and value["entries"][0]["status"] == "PLANNED"
    assert plans.list()[0]["plan_id"] == "owned-media"
