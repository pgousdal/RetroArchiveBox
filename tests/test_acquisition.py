import hashlib
import json
import stat

import pytest

from rab.acquisition import Acquisition, preserve_torrent, torrent_infohash
from rab.errors import IntegrityError, PolicyError, RabError
from rab.sources import SourceDefinition, SourceRegistry
from rab.store import Archive


def source(**changes):
    value = {
        "id": "aminet", "name": "Aminet fixture", "class": "COOPERATIVE_MIRROR",
        "backend": "rsync", "bulk_acquisition": "allowed", "rights_default": "UNKNOWN",
        "location": "rsync://example.invalid/aminet/", "enabled": True,
        "mirror_authorized": True, "concurrency": 2,
    }
    value.update(changes)
    return SourceDefinition.from_dict(value)


def fixture(directory, payload=b"lha-v1", readme=b"Short: NComm 3.07\nAuthor: John Doe\nVersion: 3.07\n"):
    path = directory / "comm" / "term"
    path.mkdir(parents=True, exist_ok=True)
    if payload is not None:
        (path / "ncomm307.lha").write_bytes(payload)
    if readme is not None:
        (path / "ncomm307.readme").write_bytes(readme)


def test_registry_policy_and_all_source_classes(tmp_path):
    unsafe = {
        "id": "co-op", "name": "Coop", "class": "COOPERATIVE_MIRROR", "backend": "rsync",
        "bulk_acquisition": "allowed", "rights_default": "UNKNOWN", "location": "rsync://x/y"
    }
    with pytest.raises(PolicyError):
        SourceDefinition.from_dict(unsafe)
    disabled = source(enabled=False)
    with pytest.raises(PolicyError):
        disabled.validate_policy(bulk=True)
    classes = {x.value for x in __import__("rab.model", fromlist=["SourceClass"]).SourceClass}
    assert classes == {"MIRROR", "COOPERATIVE_MIRROR", "ARCHIVE_COLLECTION", "HISTORICAL_MIRROR", "INGEST", "PRESERVATION_DATABASE", "PHYSICAL_MEDIA"}


def test_new_complete_search_show_get_and_idempotence(tmp_path):
    upstream = tmp_path / "upstream"; fixture(upstream)
    archive = Archive(tmp_path / "archive"); acq = Acquisition(archive)
    result = acq.sync_aminet(source(), upstream)
    assert result["packages"][0]["completeness"] == "COMPLETE"
    package = acq.show_package("aminet:comm/term/ncomm307")
    assert package["preservation_complete"] is True
    assert package["metadata"]["version"] == "3.07"
    assert len(list(archive.objects.rglob("master"))) == 2
    assert len(list((archive.root / "source-metadata/packages").rglob("generation-*.json"))) == 1
    assert package["payload"]["occurrences"][0]["rights"] == "UNKNOWN"
    with archive.db() as db:
        detail = json.loads(db.execute("SELECT detail FROM source_events WHERE event_type='SOURCE_INGEST' LIMIT 1").fetchone()[0])
    assert detail["source_class"] == "COOPERATIVE_MIRROR"
    assert detail["rights"] == "UNKNOWN"
    assert acq.search_packages("ncomm 3.07")[0]["package_id"].startswith("aminet:")
    out = tmp_path / "out"
    acq.get_package(package["package_id"], out, True)
    assert (out / "ncomm307.lha").read_bytes() == b"lha-v1"
    assert (out / "ncomm307.readme").read_bytes().startswith(b"Short:")
    occurrences = sum(len(archive.show(x["payload_sha256"])["occurrences"]) for x in [package])
    acq.sync_aminet(source(), upstream)
    assert len(list(archive.objects.rglob("master"))) == 2
    assert len(acq.show_package(package["package_id"])["generations"]) == 1
    assert len(archive.show(package["payload_object"])["occurrences"]) == occurrences


@pytest.mark.parametrize(("payload", "readme", "state"), [
    (b"payload", None, "README_MISSING"), (None, b"Short: orphan\n", "PAYLOAD_MISSING")
])
def test_incomplete_companions_are_preserved(tmp_path, payload, readme, state):
    upstream = tmp_path / "upstream"; fixture(upstream, payload, readme)
    archive = Archive(tmp_path / "archive"); acq = Acquisition(archive)
    acq.sync_aminet(source(), upstream)
    package = acq.show_package("aminet:comm/term/ncomm307")
    assert package["completeness"] == state and not package["preservation_complete"]
    assert len(list(archive.objects.rglob("master"))) == 1


def test_two_paths_deduplicate_with_independent_provenance(tmp_path):
    upstream = tmp_path / "upstream"; fixture(upstream)
    other = upstream / "util" / "misc"; other.mkdir(parents=True)
    (other / "copy.lha").write_bytes(b"lha-v1")
    (other / "copy.readme").write_bytes(b"Short: copy\n")
    archive = Archive(tmp_path / "archive"); acq = Acquisition(archive)
    acq.sync_aminet(source(), upstream)
    one = acq.show_package("aminet:comm/term/ncomm307")
    two = acq.show_package("aminet:util/misc/copy")
    assert one["payload_object"] == two["payload_object"]
    assert len(archive.show(one["payload_object"])["occurrences"]) == 2


def test_version_matrix_and_deletion_never_remove_masters(tmp_path):
    upstream = tmp_path / "upstream"; fixture(upstream)
    archive = Archive(tmp_path / "archive"); acq = Acquisition(archive); src = source()
    acq.sync_aminet(src, upstream)
    readme = upstream / "comm/term/ncomm307.readme"; payload = upstream / "comm/term/ncomm307.lha"
    readme.write_bytes(b"Short: changed readme\n"); acq.sync_aminet(src, upstream)
    payload.write_bytes(b"lha-v2"); acq.sync_aminet(src, upstream)
    readme.write_bytes(b"Short: changed both\n"); payload.write_bytes(b"lha-v3"); acq.sync_aminet(src, upstream)
    package = acq.show_package("aminet:comm/term/ncomm307")
    assert len(package["generations"]) == 4
    assert len(list(archive.objects.rglob("master"))) == 6
    payload.unlink(); readme.unlink(); acq.sync_aminet(src, upstream)
    assert acq.show_package(package["package_id"])["upstream_present"] == 0
    assert len(list(archive.objects.rglob("master"))) == 6


def test_partial_corrupt_and_recovery(tmp_path):
    archive = Archive(tmp_path / "archive"); acq = Acquisition(archive); src = source()
    partial = tmp_path / "thing.part"; partial.write_bytes(b"partial")
    with pytest.raises(IntegrityError):
        acq.ingest_completed(src, "thing.lha", partial, "application/x-lha")
    complete = tmp_path / "thing.complete"; complete.write_bytes(b"good")
    with pytest.raises(IntegrityError):
        acq.ingest_completed(src, "thing.lha", complete, "application/x-lha", expected_sha256="0" * 64)
    assert not list(archive.objects.rglob("master"))
    identity = acq.ingest_completed(src, "thing.lha", complete, "application/x-lha")
    assert archive.verify(identity)["outcome"] == "PASS"
    assert stat.S_IMODE((archive.object_dir(identity.split(":")[1]) / "master").stat().st_mode) == 0o444


def test_rsync_plan_is_staging_only_and_non_destructive(tmp_path):
    archive = Archive(tmp_path / "archive"); acq = Acquisition(archive)
    command = acq.plan_rsync(source(), tmp_path / "staging")
    assert "--delete" not in command and "--partial" in command
    with pytest.raises(PolicyError):
        acq.plan_rsync(source(), archive.objects)


def test_crash_between_ingest_and_package_link_converges(tmp_path):
    upstream = tmp_path / "upstream"; fixture(upstream)
    archive = Archive(tmp_path / "archive"); acq = Acquisition(archive); src = source()
    payload = upstream / "comm/term/ncomm307.lha"
    first = acq.ingest_completed(src, "comm/term/ncomm307.lha", payload, "application/x-lha")
    acq.sync_aminet(src, upstream)
    package = acq.show_package("aminet:comm/term/ncomm307")
    assert package["payload_object"] == first
    assert len(archive.show(first)["occurrences"]) == 1
    assert package["completeness"] == "COMPLETE"


def test_torrent_metadata_and_infohash_are_preserved(tmp_path):
    info = b"d6:lengthi4e4:name8:test.bine"
    data = b"d8:announce14:http://tracker4:info" + info + b"e"
    path = tmp_path / "test.torrent"; path.write_bytes(data)
    src = source(id="torrent-import", name="Torrent", class_="INGEST")
    # Python keyword-friendly override is not a source field.
    values = src.public(); values["class"] = "INGEST"; values.pop("class_", None)
    values["backend"] = "bittorrent"; values["bulk_acquisition"] = "prohibited"; values.pop("location", None)
    torrent_source = SourceDefinition.from_dict(values)
    archive = Archive(tmp_path / "archive")
    result = preserve_torrent(Acquisition(archive), torrent_source, path, "bootstrap/test.torrent")
    assert result["infohash_v1"] == hashlib.sha1(info).hexdigest()
    assert torrent_infohash(data) == result["infohash_v1"]
    sha = result["object_id"].split(":")[1]
    assert (archive.object_dir(sha) / "master").read_bytes() == data
