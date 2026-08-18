import hashlib
import json
import stat
import urllib.error
from pathlib import Path

import pytest

from rab.acquisition import Acquisition, preserve_torrent, torrent_infohash
from rab.errors import IntegrityError, PolicyError, RabError
from rab.sources import SourceDefinition, SourceRegistry
from rab.store import Archive


class _FixtureResponse:
    def __init__(self, body, status, headers=None):
        self.body = body
        self.status = status
        self.headers = {"Content-Length": str(len(body)), **(headers or {})}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, size=-1):
        if size < 0:
            body, self.body = self.body, b""
            return body
        body, self.body = self.body[:size], self.body[size:]
        return body


class _FixtureOpener:
    def __init__(self, payload, *, ignore_range=False, redirect=False):
        self.payload = payload
        self.ignore_range = ignore_range
        self.redirect = redirect
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        if self.redirect:
            raise urllib.error.HTTPError(request.full_url, 302, "redirect", {"Location": "/payload.bin"}, None)
        range_header = request.headers.get("Range")
        if range_header and not self.ignore_range:
            start = int(range_header.removeprefix("bytes=").split("-", 1)[0])
            return _FixtureResponse(self.payload[start:], 206,
                                    {"Content-Range": f"bytes {start}-{len(self.payload)-1}/{len(self.payload)}"})
        return _FixtureResponse(self.payload, 200)


def http_source(**changes):
    value = {
        "id": "http-fixture", "name": "HTTP fixture", "class": "MIRROR",
        "backend": "http", "bulk_acquisition": "allowed", "rights_default": "UNKNOWN",
        "location": "http://fixture.invalid", "enabled": True,
        "minimum_free_space_bytes": 0,
    }
    value.update(changes)
    return SourceDefinition.from_dict(value)


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
    archive = Archive(tmp_path / "archive"); acq = Acquisition(archive)
    src = source()
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
    fixture(upstream, b"lha-v3", b"Short: returned\n")
    acq.sync_aminet(src, upstream)
    returned = acq.show_package(package["package_id"])
    assert returned["upstream_present"] == 1
    assert any(event["event_type"] == "SOURCE_REAPPEARANCE" for event in returned["events"])


def test_partial_corrupt_and_recovery(tmp_path):
    archive = Archive(tmp_path / "archive"); acq = Acquisition(archive); src = source()
    partial = acq.staging / "thing.part"; partial.write_bytes(b"partial")
    with pytest.raises(IntegrityError):
        acq.ingest_completed(src, "thing.lha", partial, "application/x-lha")
    complete = acq.staging / "thing.complete"; complete.write_bytes(b"good")
    with pytest.raises(IntegrityError):
        acq.ingest_completed(src, "thing.lha", complete, "application/x-lha", expected_sha256="0" * 64)
    assert not list(archive.objects.rglob("master"))
    identity = acq.ingest_completed(src, "thing.lha", complete, "application/x-lha")
    assert archive.verify(identity)["outcome"] == "PASS"
    assert stat.S_IMODE((archive.object_dir(identity.split(":")[1]) / "master").stat().st_mode) == 0o444
    outside = tmp_path / "outside.complete"; outside.write_bytes(b"outside")
    with pytest.raises(PolicyError):
        acq.ingest_completed(src, "outside.lha", outside, "application/x-lha")


def test_rsync_plan_is_staging_only_and_non_destructive(tmp_path):
    archive = Archive(tmp_path / "archive"); acq = Acquisition(archive)
    command = acq.plan_rsync(source(), archive.root / "source-staging" / "staging")
    assert "--delete" not in command and "--partial" in command
    assert "--bwlimit" not in command
    assert "--bwlimit" in acq.plan_rsync(source(rate_limit_bytes_per_second=2048), archive.root / "source-staging" / "limited")
    with pytest.raises(PolicyError):
        acq.plan_rsync(source(), archive.objects)
    with pytest.raises(PolicyError):
        acq.plan_rsync(source(), archive.root / "source-staging" / "ok", "../escape")


def test_rsync_execution_uses_staging_then_m1_ingest(tmp_path, monkeypatch):
    archive = Archive(tmp_path / "archive"); acq = Acquisition(archive)
    src = source(companion_rules={"required_suffix": ".readme"})

    def fake_run(command, **kwargs):
        destination = Path(command[-1]); fixture(destination)
        assert "--delete" not in command
        return type("Result", (), {"returncode": 0, "stderr": ""})()

    monkeypatch.setattr("rab.acquisition.subprocess.run", fake_run)
    result = acq.run_rsync(src, scope="comm/term")
    assert result["outcome"] == "PASS"
    assert result["synchronized"]["packages"][0]["completeness"] == "COMPLETE"
    assert len(list(archive.objects.rglob("master"))) == 2


def test_http_resume_restart_checksum_and_atomic_promotion(tmp_path, monkeypatch):
    payload = b"http bytes that must be resumed exactly"
    opener = _FixtureOpener(payload)
    monkeypatch.setattr("rab.acquisition.urllib.request.build_opener", lambda *_handlers: opener)
    archive = Archive(tmp_path / "archive"); acq = Acquisition(archive); src = http_source()
    partial = acq.staging / src.id / (hashlib.sha256("payload.bin".encode()).hexdigest() + ".part")
    partial.parent.mkdir(parents=True, exist_ok=True); partial.write_bytes(payload[:9])
    identity = acq.acquire_http(src, "payload.bin", hashlib.sha256(payload).hexdigest(), len(payload))
    assert (archive.object_dir(identity.split(":", 1)[1]) / "master").read_bytes() == payload
    assert not partial.exists()
    assert opener.requests[0].headers["Range"] == "bytes=9-"


def test_http_server_ignoring_range_restarts_without_append(tmp_path, monkeypatch):
    payload = b"server ignored range; do not append"
    opener = _FixtureOpener(payload, ignore_range=True)
    monkeypatch.setattr("rab.acquisition.urllib.request.build_opener", lambda *_handlers: opener)
    archive = Archive(tmp_path / "archive"); acq = Acquisition(archive); src = http_source()
    partial = acq.staging / src.id / (hashlib.sha256("payload.bin".encode()).hexdigest() + ".part")
    partial.parent.mkdir(parents=True, exist_ok=True); partial.write_bytes(b"stale-prefix")
    identity = acq.acquire_http(src, "payload.bin", hashlib.sha256(payload).hexdigest(), len(payload))
    assert archive.show(identity)["size"] == len(payload)


def test_http_redirect_policy_and_checksum_failure(tmp_path, monkeypatch):
    payload = b"redirected payload"
    opener = _FixtureOpener(payload, redirect=True)
    monkeypatch.setattr("rab.acquisition.urllib.request.build_opener", lambda *_handlers: opener)
    archive = Archive(tmp_path / "archive"); acq = Acquisition(archive)
    with pytest.raises(RabError):
        acq.acquire_http(http_source(retries=0), "redirect", "0" * 64)
    assert not list(archive.objects.rglob("master"))


def test_http_staging_limit_and_unchanged_resync_event_suppression(tmp_path, monkeypatch):
    payload = b"limited payload"
    opener = _FixtureOpener(payload)
    monkeypatch.setattr("rab.acquisition.urllib.request.build_opener", lambda *_handlers: opener)
    archive = Archive(tmp_path / "archive"); acq = Acquisition(archive)
    limited = http_source(staging_limit_bytes=1)
    with pytest.raises(RabError):
        acq.acquire_http(limited, "payload.bin")
    src = http_source()
    acq.acquire_http(src, "payload.bin", hashlib.sha256(payload).hexdigest())
    with archive.db() as db:
        first = db.execute("SELECT count(*) FROM source_events").fetchone()[0]
    acq.acquire_http(src, "payload.bin", hashlib.sha256(payload).hexdigest())
    with archive.db() as db:
        second = db.execute("SELECT count(*) FROM source_events").fetchone()[0]
    assert first == second


def test_crash_between_ingest_and_package_link_converges(tmp_path):
    upstream = tmp_path / "upstream"; fixture(upstream)
    archive = Archive(tmp_path / "archive"); acq = Acquisition(archive); src = source()
    payload = upstream / "comm/term/ncomm307.lha"
    staged = acq._stage_file(src, "comm/term/ncomm307.lha", payload)
    first = acq.ingest_completed(src, "comm/term/ncomm307.lha", staged, "application/x-lha")
    acq.sync_aminet(src, upstream)
    package = acq.show_package("aminet:comm/term/ncomm307")
    assert package["payload_object"] == first
    assert len(archive.show(first)["occurrences"]) == 1
    assert package["completeness"] == "COMPLETE"


def test_torrent_metadata_and_infohash_are_preserved(tmp_path):
    info = b"d6:lengthi4e4:name8:test.bine"
    data = b"d8:announce14:http://tracker4:info" + info + b"e"
    path = tmp_path / "test.torrent"; path.write_bytes(data)
    src = source(id="torrent-import", name="Torrent")
    # Python keyword-friendly override is not a source field.
    values = src.public(); values["class"] = "INGEST"
    values["backend"] = "bittorrent"; values["bulk_acquisition"] = "prohibited"; values.pop("location", None)
    torrent_source = SourceDefinition.from_dict(values)
    archive = Archive(tmp_path / "archive")
    result = preserve_torrent(Acquisition(archive), torrent_source, path, "bootstrap/test.torrent")
    assert result["infohash_v1"] == hashlib.sha1(info).hexdigest()
    assert torrent_infohash(data) == result["infohash_v1"]
    sha = result["object_id"].split(":")[1]
    assert (archive.object_dir(sha) / "master").read_bytes() == data


def test_torrent_payload_client_is_staging_only_and_piece_verified(tmp_path, monkeypatch):
    info = b"d6:lengthi4e4:name8:test.bine"
    data = b"d4:inf o".replace(b" ", b"") + info + b"e"
    path = tmp_path / "test.torrent"; path.write_bytes(data)
    values = source(id="torrent-client", name="Torrent").public()
    values.update({"class": "INGEST", "backend": "bittorrent", "bulk_acquisition": "prohibited",
                   "torrent_client": "aria2c"})
    values.pop("location", None)
    torrent_source = SourceDefinition.from_dict(values)
    archive = Archive(tmp_path / "archive"); seen = {}

    def fake_run(command, **kwargs):
        seen["command"] = command
        destination = Path(next(arg.split("=", 1)[1] for arg in command if arg.startswith("--dir=")))
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "file.bin").write_bytes(b"torrent payload")
        return type("Result", (), {"returncode": 0, "stderr": ""})()

    monkeypatch.setattr("rab.acquisition.shutil.which", lambda name: "/usr/bin/aria2c")
    monkeypatch.setattr("rab.acquisition.subprocess.run", fake_run)
    result = Acquisition(archive).acquire_torrent(torrent_source, path, "bootstrap/test.torrent")
    assert result["payloads"][0]["source_path"] == "file.bin"
    command = result["command"]
    destination = Path(next(arg.split("=", 1)[1] for arg in command if arg.startswith("--dir=")))
    assert destination.is_relative_to(archive.root / "source-staging")
    assert "--check-integrity=true" in command
    assert "--" in command
    assert len(list(archive.objects.rglob("master"))) == 2
