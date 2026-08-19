import json
from pathlib import Path

from rab.api import CatalogueAPI
from rab.catalogue import Catalogue
from rab.local_ingest import ProvenanceClass, WatchedInboxManager
from rab.model import Rights
from rab.store import Archive
from rab.web import WebApplication


def config(path, **overrides):
    value = {"inboxes": [{"inbox_id": "purchased", "path": str(path / "purchased"), "provenance": "purchased_download", "rights": "UNKNOWN", "stability_seconds": 0, "min_age_seconds": 0}]}
    value["inboxes"][0].update(overrides)
    return value


def test_watched_inbox_stable_unknown_and_duplicate_occurrence(tmp_path):
    root = tmp_path / "inbox"; (root / "purchased").mkdir(parents=True)
    payload = root / "purchased" / "mystery.bin"; payload.write_bytes(b"unknown bytes")
    config_path = tmp_path / "inboxes.json"; config_path.write_text(json.dumps(config(root)), encoding="utf-8")
    archive = Archive(tmp_path / "archive")
    manager = WatchedInboxManager(archive, config_path=config_path)
    first = manager.scan_once()[0]
    assert first["state"] == "COMPLETED" and first["provenance_classification"] == "purchased_download"
    before = payload.read_bytes(); assert payload.read_bytes() == before
    assert manager.scan_once() == []
    (root / "purchased" / "copy.bin").write_bytes(before)
    duplicate = manager.scan_once()[0]
    assert duplicate["duplicate"] is True
    assert len(archive.show(first["object_id"])["occurrences"]) == 2
    assert archive.show(first["object_id"])["occurrences"][0]["rights"] == Rights.UNKNOWN.value


def test_watched_inbox_waits_for_stability_and_temp_suffix(tmp_path):
    root = tmp_path / "inbox"; (root / "unknown").mkdir(parents=True)
    changing = root / "unknown" / "growing.bin"; changing.write_bytes(b"a")
    partial = root / "unknown" / "growing.bin.part"; partial.write_bytes(b"partial")
    calls = []

    def change_during_wait(seconds):
        calls.append(seconds)
        if len(calls) == 1: changing.write_bytes(b"ab")

    policy = config(root); policy["inboxes"][0].update({"inbox_id": "unknown", "path": str(root / "unknown"), "provenance": "unknown", "stability_seconds": 1})
    path = tmp_path / "inboxes.json"; path.write_text(json.dumps(policy), encoding="utf-8")
    manager = WatchedInboxManager(Archive(tmp_path / "archive"), config_path=path, sleep=change_during_wait)
    assert manager.scan_once() == []
    assert manager.status()["states"]["WAITING_STABLE"] == 1
    assert calls
    assert manager.scan_once()[0]["state"] == "COMPLETED"


def test_post_success_move_and_explicit_delete(tmp_path):
    root = tmp_path / "inbox"; (root / "purchased").mkdir(parents=True)
    value = config(root, post_success="MOVE_TO_PROCESSED")
    path = tmp_path / "inboxes.json"; path.write_text(json.dumps(value), encoding="utf-8")
    archive = Archive(tmp_path / "archive"); source = root / "purchased" / "move.bin"; source.write_bytes(b"move")
    result = WatchedInboxManager(archive, config_path=path).scan_once()[0]
    assert not source.exists() and (root / "purchased.processed" / "move.bin").read_bytes() == b"move"
    assert result["inbox"]["post_success"] == "MOVED_TO_PROCESSED"

    delete_root = tmp_path / "delete-inbox"; (delete_root / "purchased").mkdir(parents=True)
    delete_config = tmp_path / "delete.json"; delete_config.write_text(json.dumps(config(delete_root, post_success="DELETE_AFTER_VERIFIED_INGEST")), encoding="utf-8")
    delete_source = delete_root / "purchased" / "delete.bin"; delete_source.write_bytes(b"delete")
    delete_result = WatchedInboxManager(archive, config_path=delete_config).scan_once()[0]
    assert not delete_source.exists() and delete_result["inbox"]["post_success"] == "DELETED_AFTER_VERIFIED_INGEST"


def test_recursive_tree_sidecar_malformed_api_and_retro_web(tmp_path):
    root = tmp_path / "inbox"; tree = root / "unknown" / "tree"; tree.mkdir(parents=True)
    (tree / "demo.bin").write_bytes(b"tree")
    (tree / "demo.bin.rab.json").write_text('{"notes": "tree note"}', encoding="utf-8")
    malformed = root / "unknown" / "bad.bin"; malformed.write_bytes(b"bad"); (root / "unknown" / "bad.bin.rab.json").write_text("not-json", encoding="utf-8")
    sidecar_payload = root / "unknown" / "meta.bin"; sidecar_payload.write_bytes(b"metadata"); (root / "unknown" / "meta.bin.rab.json").write_text('{"vendor": "fixture", "notes": "private"}', encoding="utf-8")
    value = config(root, recursive=True); value["inboxes"][0]["inbox_id"] = "unknown"; value["inboxes"][0]["path"] = str(root / "unknown"); value["inboxes"][0]["provenance"] = "unknown"
    path = tmp_path / "inboxes.json"; path.write_text(json.dumps(value), encoding="utf-8")
    archive = Archive(tmp_path / "archive"); manager = WatchedInboxManager(archive, config_path=path)
    results = manager.scan_once()
    assert any(x.get("schema") == "rab-tree-ingest-job-v1" for x in results)
    assert any(x.get("inbox", {}).get("warnings") for x in results if x.get("inbox"))
    assert any(x.get("operator_metadata", {}).get("vendor") == "fixture" for x in results if x.get("operator_metadata"))
    api = CatalogueAPI(Catalogue(archive)); assert api.dispatch("GET", "/api/v1/ingest/inboxes")[0] == 200; api_status, api_payload = api.dispatch("GET", "/api/v1/ingest/inbox/status"); assert api_status == 200 and str(root) not in json.dumps(api_payload)
    status, _, body, _ = WebApplication(archive).dispatch("GET", "/retro/inboxes")
    assert status == 200 and "unknown" in body and "tree" in body


def test_failure_is_bounded_and_source_remains(tmp_path, monkeypatch):
    root = tmp_path / "inbox"; (root / "purchased").mkdir(parents=True); source = root / "purchased" / "fail.bin"; source.write_bytes(b"fail")
    path = tmp_path / "inboxes.json"; path.write_text(json.dumps(config(root, max_retries=1)), encoding="utf-8")
    manager = WatchedInboxManager(Archive(tmp_path / "archive"), config_path=path)
    monkeypatch.setattr(manager, "_process", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("temporary")))
    result = manager.scan_once()[0]
    assert result["state"] == "FAILED" and source.read_bytes() == b"fail"
    assert manager.scan_once() == []


def test_restart_recovers_after_archive_ingest_before_watcher_state(tmp_path, monkeypatch):
    root = tmp_path / "inbox"; (root / "unknown").mkdir(parents=True); source = root / "unknown" / "crash.bin"; source.write_bytes(b"crash recovery")
    value = config(root, retry_delay_seconds=0); value["inboxes"][0].update({"inbox_id": "unknown", "path": str(root / "unknown"), "provenance": "unknown"})
    path = tmp_path / "inboxes.json"; path.write_text(json.dumps(value), encoding="utf-8")
    archive = Archive(tmp_path / "archive"); manager = WatchedInboxManager(archive, config_path=path)
    original = manager._process
    def ingest_then_crash(*args, **kwargs):
        original_result = original(*args, **kwargs)
        raise RuntimeError("simulated watcher crash")
    monkeypatch.setattr(manager, "_process", ingest_then_crash)
    assert manager.scan_once()[0]["state"] == "RETRY_WAIT"
    assert len(list(archive.objects.rglob("master"))) == 1
    monkeypatch.setattr(manager, "_process", original)
    recovered = manager.scan_once()[0]
    assert recovered["state"] == "COMPLETED" and manager.scan_once() == []
    assert len(archive.show(recovered["object_id"])["occurrences"]) == 1
