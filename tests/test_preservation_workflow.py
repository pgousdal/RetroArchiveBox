import io
import json
import zipfile

import pytest

from rab.api import CatalogueAPI
from rab.catalogue import Catalogue
from rab.cli import parser
from rab.errors import PolicyError
from rab.model import IngestRequest, Rights
from rab.malware_provider import FixtureProvider, MalwareProviderManager
from rab.malware import MalwareStore
from rab.physical import CandidateSafety
from rab.physical_registry import PhysicalMediaRegistry
from rab.preservation import PreservationWorkflow, WorkflowState
from rab.store import Archive
from rab.web import WebApplication


def _zip_bytes():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("Games/fixture.adf", b"DOS\0" + b"\0" * 1020)
        archive.writestr("README.txt", b"public-domain synthetic fixture\n")
    return output.getvalue()


class FakeMedia:
    def __init__(self, archive, *, data=None, kind="block", candidates=1, disagree=False):
        self.archive, self.data, self.kind, self.disagree = archive, data or _zip_bytes(), kind, disagree
        self.capture_calls = 0
        self._candidates = [self._candidate(index) for index in range(candidates)]

    def _candidate(self, index):
        return {"candidate_id": f"{self.kind}:fixture-{index}", "kind": self.kind, "display_description": "synthetic candidate", "device": f"/dev/private-fixture-{index}", "available": True, "medium_present": True, "safety": CandidateSafety.SAFE_CANDIDATE.value, "device_summary": {}, "limitations": [], "requires_operator_selection": len(getattr(self, "_candidates", [])) > 1, "suggested_action": "PLAN"}

    def public_candidates(self): return [{key: value for key, value in x.items() if key != "device"} for x in self._candidates]
    def candidate(self, candidate_id=None):
        if candidate_id:
            for item in self._candidates:
                if item["candidate_id"] == candidate_id: return item
            raise PolicyError("candidate not found")
        if len(self._candidates) != 1: raise PolicyError("multiple candidates detected; use --candidate")
        return self._candidates[0]
    def plan(self, candidate, **kwargs):
        return {"schema": "fixture-plan", "candidate": {"kind": candidate["kind"]}, "inspection": {"size": len(self.data)}, "capture": {"method": {"optical": "optical-data", "block": "block-device-dd", "flux": "greaseweazle-flux"}[candidate["kind"]], "representation": "fixture", "expected_size": len(self.data), "profile": kwargs.get("profile"), "drive": kwargs.get("drive")}, "verification": {"policy": kwargs.get("verification")}, "provenance": kwargs.get("provenance"), "rights": kwargs.get("rights"), "adapter_state": "COMPLETE", "limitations": [], "metadata": kwargs.get("metadata", {})}
    def _capture(self, candidate, plan, *, physical_medium_id=None, repeat_of=None):
        self.capture_calls += 1; data = self.data + (b"different" if self.disagree and self.capture_calls > 1 else b"")
        staging = self.archive.root / f"fixture-{self.capture_calls}.bin"; staging.parent.mkdir(parents=True, exist_ok=True); staging.write_bytes(data)
        result = self.archive.ingest(IngestRequest(staging, "fixture-capture", "synthetic-medium", Rights(plan["rights"]), "application/octet-stream", "synthetic", None, plan["provenance"], {"physical_medium_id": physical_medium_id}))
        job_id = f"fixture{self.capture_calls:02d}"; job = {"schema": "fixture-capture-v1", "job_id": job_id, "physical_medium_id": physical_medium_id, "object_id": result["object_id"], "state": "COMPLETE", "repeat_of": repeat_of}
        jobs = self.archive.root / "media" / "jobs"; jobs.mkdir(parents=True, exist_ok=True); self.archive._atomic_json(jobs / (job_id + ".json"), job); staging.unlink()
        return job


def _prepared(tmp_path, *, profile="quick", kind="block", disagree=False, candidates=1, malware=None):
    archive = Archive(tmp_path / "archive"); media = FakeMedia(archive, kind=kind, disagree=disagree, candidates=candidates)
    manager = PreservationWorkflow(archive, media=media, malware=malware(archive) if callable(malware) else malware); run = manager.create(profile=profile)
    run = manager.prepare(run["run_id"], candidate_id=(f"{kind}:fixture-0" if candidates > 1 else None), title="Synthetic", provenance="original_physical_owned", rights="UNKNOWN", drive="A", floppy_profile="unknown")
    return archive, media, manager, run


def test_state_machine_events_cancellation_and_privacy(tmp_path):
    archive = Archive(tmp_path / "archive"); manager = PreservationWorkflow(archive, media=FakeMedia(archive)); run = manager.create(operator="private operator", metadata={"device_path": "/dev/secret"})
    with pytest.raises(PolicyError): manager.transition(run["run_id"], WorkflowState.COMPLETE)
    cancelled = manager.cancel(run["run_id"]); assert cancelled["state"] == "CANCELLED"
    events = manager.events(run["run_id"]); assert [x["sequence"] for x in events] == [1, 2] and events[0]["event_type"] == "workflow_created"
    assert "private operator" not in json.dumps(manager.public(cancelled)) and "/dev/secret" not in json.dumps(manager.public(cancelled))


@pytest.mark.parametrize("kind", ["optical", "block", "flux"])
def test_fixture_media_workflows_and_immutable_master(tmp_path, kind):
    archive, media, manager, run = _prepared(tmp_path, kind=kind); assert run["state"] == "READY_TO_CAPTURE"
    completed = manager.execute(run["run_id"]); assert completed["state"] in {"COMPLETE", "COMPLETE_WITH_WARNINGS"}
    master = archive.object_dir(archive.resolve(completed["preservation_objects"][0])) / "master"; before = master.read_bytes()
    assert manager.resume(run["run_id"])["preservation_objects"] == completed["preservation_objects"] and media.capture_calls == 1
    assert master.read_bytes() == before and manager.report(run["run_id"])["safe_to_remove"] is True
    assert PhysicalMediaRegistry(archive).captures(completed["physical_medium_id"])[0]["object_id"] == completed["preservation_objects"][0]


def test_conservative_repeat_disagreement_requires_review_and_keeps_both(tmp_path):
    archive, media, manager, run = _prepared(tmp_path, profile="conservative", disagree=True)
    result = manager.execute(run["run_id"]); assert result["state"] == "NEEDS_OPERATOR" and len(result["preservation_objects"]) == 2
    assert len(manager.review()) == 1 and all((archive.object_dir(archive.resolve(x)) / "master").is_file() for x in result["preservation_objects"])


def test_ambiguous_device_fails_closed_and_space_failure(tmp_path, monkeypatch):
    archive = Archive(tmp_path / "archive"); manager = PreservationWorkflow(archive, media=FakeMedia(archive, candidates=2)); run = manager.create()
    assert manager.prepare(run["run_id"])["state"] == "NEEDS_OPERATOR"
    _, _, manager, run = _prepared(tmp_path / "other")
    monkeypatch.setattr("rab.preservation.shutil.disk_usage", lambda _path: type("U", (), {"free": 1})())
    assert manager.execute(run["run_id"])["state"] == "FAILED"


def test_synthetic_end_to_end_report_api_web_products_and_rights(tmp_path):
    archive, media, manager, run = _prepared(tmp_path, profile="standard"); master = manager.execute(run["run_id"])
    assert master["state"] == "COMPLETE_WITH_WARNINGS"  # fixture hosts normally lack optional scanners
    report = manager.report(run["run_id"]); assert report["contained_objects"] >= 2 and report["rights"] == "UNKNOWN" and report["provenance"] == "original_physical_owned"
    assert len(list(archive.objects.rglob("master"))) >= 2 and media.capture_calls == 1
    product = manager.products.build("preservation-run-report"); assert product["record_count"] == 1
    status, payload = CatalogueAPI(Catalogue(archive)).dispatch("GET", f"/api/v1/preservation/runs/{run['run_id']}")
    assert status == 200 and "/dev/private" not in json.dumps(payload)
    web = WebApplication(archive); assert web.dispatch("GET", "/retro/preservation")[0] == 200
    detail = web.dispatch("GET", f"/retro/preservation/{run['run_id']}"); assert detail[0] == 200 and "/dev/private" not in detail[2]


def test_resume_after_ingest_skips_capture_and_doctor_progress(tmp_path):
    archive, media, manager, run = _prepared(tmp_path); result = media._capture(manager._private_candidate(run), run["plan"], physical_medium_id=run["physical_medium_id"])
    run = manager.show(run["run_id"]); run["captures"] = [result]; run["preservation_objects"] = [result["object_id"]]; manager._save(run)
    finished = manager.resume(run["run_id"]); assert media.capture_calls == 1 and finished["state"] in {"COMPLETE", "COMPLETE_WITH_WARNINGS"}
    assert manager.progress()["preserved"] == 1 and manager.doctor()["overall"] in {"PASS", "WARN"}


def test_preserve_cli_is_above_expert_commands():
    args = parser().parse_args(["preserve", "next", "--candidate", "block:fixture", "--title", "Synthetic", "--non-interactive", "--yes"])
    assert args.command == "preserve" and args.preserve_command == "next" and args.non_interactive
    expert = parser().parse_args(["media", "optical", "jobs"])
    assert expert.command == "media" and expert.optical_command == "jobs"


@pytest.mark.parametrize("scenario,expected", [("clean", "NO_DETECTIONS_OBSERVED"), ("detected", "MALWARE_DETECTED")])
def test_preservation_external_provider_success_and_detection_do_not_fail(tmp_path, scenario, expected):
    def provider(archive): return MalwareProviderManager(archive, providers={"avbox": FixtureProvider(scenario)})
    archive, _, manager, run = _prepared(tmp_path, profile="standard", malware=provider)
    completed = manager.execute(run["run_id"])
    assert completed["state"] in {"COMPLETE", "COMPLETE_WITH_WARNINGS"} and MalwareStore(archive).status(completed["preservation_objects"][0])["state"] == expected
    assert manager.report(run["run_id"])["malware_analysis"][0]["status"] == "IMPORTED"
