import json

from rab.api import CatalogueAPI
from rab.catalogue import Catalogue
from rab.cli import parser, run
from rab.local_ingest import ProvenanceClass
from rab.model import Rights
from rab.media import MediaManager
from rab.physical_registry import PhysicalMediaRegistry
from rab.products import ProductBuilder
from rab.removable import RemovableManager
from rab.store import Archive
from rab.web import WebApplication


class _FixtureDevice:
    def __init__(self, data=b"same captured bytes"): self.data, self.calls = data, 0
    def capabilities(self): return {"adapter_id": "fixture", "write_source": False}
    def inspect(self, _device): return {"safety": "SAFE_CANDIDATE", "size": len(self.data), "mounted_children": []}
    def capture(self, device, destination, **_kwargs):
        self.calls += 1; destination.parent.mkdir(parents=True, exist_ok=True); destination.write_bytes(self.data)
        return {"device": device, "outcome": "COMPLETE", "capture_mode_read_only": True}


def test_physical_registry_ids_sets_observations_evidence_and_privacy(tmp_path):
    archive = Archive(tmp_path / "archive"); registry = PhysicalMediaRegistry(archive)
    physical_set = registry.register_set("Fixture set", expected_count=3)
    first = registry.register("optical_disc", provenance=ProvenanceClass.ORIGINAL_PHYSICAL_OWNED, rights=Rights.UNKNOWN, metadata={"title": "Unknown CD #17", "operator_notes": "private note", "vendor": "Fixture"}, set_id=physical_set["physical_set_id"], set_position=1, total_media_count=3)
    second = registry.register("optical_disc", provenance=ProvenanceClass.VENDOR_MEDIA, rights=Rights.RESTRICTED, metadata={"title": "Unknown CD #17"}, set_id=physical_set["physical_set_id"], set_position=2, total_media_count=3)
    assert first["physical_medium_id"] != second["physical_medium_id"] and first["rights"] == "UNKNOWN"
    registry.update(first["physical_medium_id"], metadata={"platform": "amiga"})
    registry.observe(first["physical_medium_id"], "scratched", note="private observation", observer="operator")
    evidence = tmp_path / "label.txt"; evidence.write_text("fixture label", encoding="utf-8")
    registry.add_evidence(first["physical_medium_id"], evidence, rights=Rights.RESTRICTED)
    shown = registry.show(first["physical_medium_id"])
    assert shown["metadata"]["title"] == "Unknown CD #17" and shown["metadata"]["platform"] == "amiga"
    assert len(registry.observations(first["physical_medium_id"])) == 1 and len(shown["evidence_objects"]) == 1
    assert registry.show_set(physical_set["physical_set_id"])["completeness"]["complete"] is False
    api = CatalogueAPI(Catalogue(archive)); status, public = api.dispatch("GET", "/api/v1/physical/" + first["physical_medium_id"])
    assert status == 200 and "operator_notes" not in json.dumps(public) and "private note" not in json.dumps(public)
    assert WebApplication(archive).dispatch("GET", "/retro/physical")[0] == 200
    detail = WebApplication(archive).dispatch("GET", "/retro/physical/" + first["physical_medium_id"])
    assert detail[0] == 200 and "private note" not in detail[2]


def test_physical_capture_linkage_and_inventory_product(tmp_path):
    archive = Archive(tmp_path / "archive"); registry = PhysicalMediaRegistry(archive); medium = registry.register("removable_flash", provenance="vendor_media")
    jobs = archive.root / "media" / "jobs"; jobs.mkdir(parents=True); (jobs / "a.json").write_text(json.dumps({"job_id": "a", "physical_medium_id": medium["physical_medium_id"], "state": "COMPLETED", "object_id": "sha256:" + "0" * 64}), encoding="utf-8")
    assert registry.captures(medium["physical_medium_id"])[0]["job_id"] == "a"
    product = ProductBuilder(archive).build("physical-media")
    assert product["record_count"] == 1
    (jobs / "legacy.json").write_text(json.dumps({"job_id": "legacy", "state": "COMPLETED", "object_id": None}), encoding="utf-8")
    assert json.loads((jobs / "legacy.json").read_text(encoding="utf-8")).get("physical_medium_id") is None


def test_registered_medium_repeat_capture_cas_convergence_disagreement_and_safety(tmp_path):
    archive = Archive(tmp_path / "archive"); registry = PhysicalMediaRegistry(archive)
    first_copy = registry.register("removable_flash", provenance="original_physical_owned", rights="UNKNOWN")
    second_copy = registry.register("removable_flash", provenance="pirate_copy", rights="RESTRICTED")
    assert first_copy["physical_medium_id"] != second_copy["physical_medium_id"]
    adapter = _FixtureDevice(); manager = RemovableManager(archive, media=MediaManager(archive, adapter=adapter))
    first = manager.capture("/dev/fixture", physical_medium_id=first_copy["physical_medium_id"])
    identical = manager.capture("/dev/fixture", physical_medium_id=first_copy["physical_medium_id"], repeat_of=first["job_id"])
    other_copy = manager.capture("/dev/fixture", physical_medium_id=second_copy["physical_medium_id"])
    assert first["object_id"] == identical["object_id"] == other_copy["object_id"]
    assert len(list(archive.objects.rglob("master"))) == 1 and len(registry.captures(first_copy["physical_medium_id"])) == 2
    adapter.data = b"different captured bytes"
    different = manager.capture("/dev/fixture", physical_medium_id=first_copy["physical_medium_id"], repeat_of=identical["job_id"])
    assert different["object_id"] != first["object_id"] and different["repeat_comparison"]["differing_capture_preserved"] is True
    relationships = [json.loads(x.read_text(encoding="utf-8")) for x in (archive.root / "identity-metadata" / "relationships").glob("*.json")]
    assert any(x["relationship"] == "CAPTURED_AS" and x["subject_id"] == first_copy["physical_medium_id"] for x in relationships)
    assert registry.show(second_copy["physical_medium_id"])["provenance"] == "pirate_copy"
    assert registry.show(first_copy["physical_medium_id"])["rights"] == "UNKNOWN"
    before = archive.object_dir(archive.resolve(first["object_id"])).joinpath("master").read_bytes()
    registry.observe(first_copy["physical_medium_id"], "clean"); registry.observe(first_copy["physical_medium_id"], "scratched")
    registry.update(first_copy["physical_medium_id"], metadata={"title": "Fixture"})
    assert len(registry.observations(first_copy["physical_medium_id"])) == 2 and len(registry.revisions(first_copy["physical_medium_id"])) == 1
    assert archive.object_dir(archive.resolve(first["object_id"])).joinpath("master").read_bytes() == before
    capture_product = ProductBuilder(archive).build("capture-status"); rebuilt = ProductBuilder(archive).build("capture-status")
    assert capture_product["record_count"] == 2 and capture_product["content_sha256"] == rebuilt["content_sha256"]


def test_intake_defaults_public_evidence_and_recursive_capture_redaction(tmp_path):
    archive = Archive(tmp_path / "archive"); registry = PhysicalMediaRegistry(archive)
    registry.intake_begin(provenance="original_physical_owned", platform="amiga", vendor="Fixture vendor", operator="Private Person")
    medium = registry.register("optical_disc", metadata={"title": "Fixture", "printed_serial_number": "SECRET", "operator_notes": "/private/note"})
    assert medium["provenance"] == "original_physical_owned" and medium["rights"] == "UNKNOWN" and medium["metadata"]["platform"] == "amiga"
    registry.intake_end(); assert registry.intake_status()["state"] == "INACTIVE"
    evidence = tmp_path / "receipt.txt"; evidence.write_text("fixture-only receipt", encoding="utf-8")
    registry.add_evidence(medium["physical_medium_id"], evidence, evidence_type="purchase_receipt")
    relationships = [json.loads(x.read_text(encoding="utf-8")) for x in (archive.root / "identity-metadata" / "relationships").glob("*.json")]
    assert any(x["relationship"] == "EVIDENCE_FOR" for x in relationships)
    status, public_evidence = CatalogueAPI(Catalogue(archive)).dispatch("GET", f'/api/v1/physical/{medium["physical_medium_id"]}/evidence')
    assert status == 200 and public_evidence == []
    redacted = registry.public_capture({"device": "/dev/private", "adapter": {"serial": "SECRET", "command": ["dd"]}, "capture": {"device_info": {"path": "/dev/private"}}, "object_id": "sha256:x"})
    assert "/dev/private" not in json.dumps(redacted) and "SECRET" not in json.dumps(redacted)


def test_physical_cli_registration_and_intake_defaults(tmp_path):
    root = tmp_path / "archive"; cli = parser()
    started = run(cli.parse_args(["--root", str(root), "physical", "intake", "begin", "--provenance", "vendor_media", "--platform", "amiga"]))
    registered = run(cli.parse_args(["--root", str(root), "physical", "register", "--class", "removable_flash", "--title", "Fixture USB"]))
    shown = run(cli.parse_args(["--root", str(root), "physical", "show", registered["physical_medium_id"]]))
    assert started["state"] == "ACTIVE" and shown["provenance"] == "vendor_media" and shown["metadata"]["platform"] == "amiga"
    assert run(cli.parse_args(["--root", str(root), "physical", "intake", "end"]))["state"] == "COMPLETED"
