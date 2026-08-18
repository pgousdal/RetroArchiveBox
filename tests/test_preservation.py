import json
import stat

import pytest

from rab.errors import IntegrityError, PolicyError
from rab.model import IngestRequest, Rights
from rab.store import Archive


def request(path, *, source="manual", source_path="disk.adf", rights=Rights.UNKNOWN, derived_from=None):
    return IngestRequest(path, source, source_path, rights, "application/octet-stream", path.name, derived_from)


def test_ingest_verify_export_is_byte_identical(tmp_path):
    source = tmp_path / "input.adf"
    source.write_bytes(b"preservation bytes\x00\xff")
    archive = Archive(tmp_path / "archive")
    ingested = archive.ingest(request(source))
    identity = ingested["object_id"]

    assert archive.verify(identity)["outcome"] == "PASS"
    output = tmp_path / "output.adf"
    archive.export_original(identity, output)
    assert output.read_bytes() == source.read_bytes()
    assert archive.show(identity)["occurrences"][0]["rights"] == "UNKNOWN"


def test_identical_content_deduplicates_but_provenance_does_not(tmp_path):
    first = tmp_path / "one.bin"
    second = tmp_path / "two.bin"
    first.write_bytes(b"same")
    second.write_bytes(b"same")
    archive = Archive(tmp_path / "archive")
    a = archive.ingest(request(first, source="physical", source_path="DISC-001/track01"))
    b = archive.ingest(request(second, source="mirror", source_path="pub/two.bin"))

    assert a["object_id"] == b["object_id"]
    shown = archive.show(a["object_id"])
    assert len(shown["occurrences"]) == 2
    assert len(list(archive.objects.rglob("master"))) == 1
    assert len(list(archive.objects.rglob("occurrences/*.json"))) == 2


def test_master_and_sidecars_are_read_only_and_events_append(tmp_path):
    source = tmp_path / "object.bin"
    source.write_bytes(b"artifact")
    archive = Archive(tmp_path / "archive")
    identity = archive.ingest(request(source))["object_id"]
    sha = identity.split(":", 1)[1]
    directory = archive.object_dir(sha)
    archive.verify(identity)
    archive.verify(identity)

    assert stat.S_IMODE((directory / "master").stat().st_mode) == 0o444
    assert stat.S_IMODE((directory / "manifest.json").stat().st_mode) == 0o444
    events = list((directory / "events").glob("*.json"))
    assert len(events) == 3
    assert [json.loads(p.read_text())["event_type"] for p in events].count("FIXITY_CHECK") == 2


def test_derivative_requires_existing_parent(tmp_path):
    source = tmp_path / "converted.bin"
    source.write_bytes(b"converted")
    archive = Archive(tmp_path / "archive")
    with pytest.raises(Exception):
        archive.ingest(request(source, derived_from="sha256:" + "0" * 64))


def test_export_never_overwrites(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"original")
    archive = Archive(tmp_path / "archive")
    identity = archive.ingest(request(source))["object_id"]
    output = tmp_path / "existing.bin"
    output.write_bytes(b"keep")
    with pytest.raises(PolicyError):
        archive.export_original(identity, output)
    assert output.read_bytes() == b"keep"


def test_fixity_failure_is_recorded_and_never_cleaned(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"original")
    archive = Archive(tmp_path / "archive")
    identity = archive.ingest(request(source))["object_id"]
    sha = identity.split(":", 1)[1]
    master = archive.object_dir(sha) / "master"
    master.chmod(0o644)
    master.write_bytes(b"tampered")
    with pytest.raises(IntegrityError):
        archive.verify(identity)
    assert master.read_bytes() == b"tampered"
    assert archive.show(identity)["events"][-1]["outcome"] == "FAIL"

