import json
from pathlib import Path

from rab.sources import SourceRegistry


ROOT = Path(__file__).parents[1]


def test_malware_profiles_cannot_delete_clean_or_repair():
    for path in (ROOT / "config" / "malware-profiles").glob("*.json"):
        profile = json.loads(path.read_text())
        assert profile["delete"] is False
        assert profile["clean"] is False
        assert profile["repair"] is False
        assert profile["on_detection"] == "preserve-and-record"


def test_archive_org_is_targeted_only():
    source = json.loads((ROOT / "config/sources/archive-org.json").read_text())
    assert source["bulk_acquisition"] == "targeted-only"


def test_emulator_master_input_is_read_only():
    for path in (ROOT / "config" / "emulator-profiles").glob("*.json"):
        profile = json.loads(path.read_text())
        assert profile["input"] == "read-only"
        assert profile["writable_layer"] == "disposable-overlay"


def test_provisioning_has_no_ppa_or_pipe_to_shell():
    provisioning = "\n".join(
        path.read_text(errors="replace")
        for path in (ROOT / "ansible").rglob("*")
        if path.is_file()
    ).lower()
    assert "apt_repository" not in provisioning
    assert "ppa:" not in provisioning
    assert "curl | sh" not in provisioning
    assert "wget | sh" not in provisioning


def test_source_policy_always_declares_bulk_acquisition_and_rights():
    for path in (ROOT / "config" / "sources").glob("*.json"):
        source = json.loads(path.read_text())
        assert source["bulk_acquisition"] in {
            "allowed", "permission-required", "targeted-only", "prohibited"
        }
        assert source["rights_default"] in {
            "REDISTRIBUTABLE", "PRIVATE_LICENSED", "RESTRICTED", "UNKNOWN"
        }


def test_runtime_registry_validates_all_shipped_sources():
    sources = SourceRegistry(ROOT / "config" / "sources").load()
    assert {"aminet", "archive-org", "manual", "torrent-import"} <= sources.keys()


def test_no_destructive_sync_flags_or_preservation_bypass():
    implementation = (ROOT / "src/rab/acquisition.py").read_text()
    assert '"--delete"' not in implementation
    assert "archive.ingest(" in implementation
    assert "shutil.copyfile(" not in implementation
