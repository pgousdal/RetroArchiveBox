import json
import functools
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from rab.acquisition import Acquisition
from rab.api import CatalogueAPI
from rab.catalogue import Catalogue
from rab.cli import parser, run
from rab.errors import PolicyError, RabError
from rab.model import Rights
from rab.sources import SourceDefinition, SourceRegistry
from rab.store import Archive
from rab.transports import AcquisitionPurpose, TransportResolver, TransportState


def source_with_endpoints(**changes):
    value = {
        "id": "transport-fixture", "name": "Transport fixture", "class": "MIRROR",
        "backend": "http", "location": "http://primary.invalid/root/",
        "bulk_acquisition": "allowed", "rights_default": "REDISTRIBUTABLE",
        "enabled": True, "mirror_authorized": True,
        "endpoints": [
            {"transport": "bittorrent", "endpoint": "bittorrent://fixture.invalid/snapshot"},
            {"transport": "rsync", "endpoint": "rsync://fixture.invalid/module"},
            {"transport": "https", "endpoint": "https://fixture.invalid/root/"},
            {"transport": "http", "endpoint": "http://fixture.invalid/root/"},
            {"transport": "ftp", "endpoint": "ftp://fixture.invalid/root/"}
        ]
    }
    value.update(changes)
    return SourceDefinition.from_dict(value)


def test_transport_preference_and_explainable_overrides(monkeypatch):
    monkeypatch.setattr("rab.transports.shutil.which", lambda name: "/usr/bin/" + name)
    resolver = TransportResolver()
    source = source_with_endpoints()
    bootstrap = resolver.plan(source, AcquisitionPurpose.BOOTSTRAP)
    sync = resolver.plan(source, AcquisitionPurpose.SYNCHRONIZATION)
    assert bootstrap["selected"]["transport"] == "bittorrent"
    assert sync["selected"]["transport"] == "rsync"
    overridden = source_with_endpoints(transport_policy={"synchronization": ["https", "rsync"]})
    assert resolver.plan(overridden, "synchronization")["selected"]["transport"] == "https"
    prohibited = source_with_endpoints(transport_policy={"prohibited": ["rsync"]})
    result = resolver.plan(prohibited, "synchronization")
    assert result["selected"]["transport"] == "https"
    assert any(x["reason"] == "source policy prohibits transport" for x in result["rejected"])


def test_transport_unavailable_and_ambiguity_are_explicit(monkeypatch):
    monkeypatch.setattr("rab.transports.shutil.which", lambda name: None)
    source = source_with_endpoints(endpoints=[{"transport": "rsync", "endpoint": "rsync://fixture.invalid/a"},
                                               {"transport": "https", "endpoint": "https://fixture.invalid/a"}])
    result = TransportResolver().plan(source, "synchronization")
    assert result["selected"]["transport"] == "https"
    assert any(x["reason"] == "runtime dependency unavailable" for x in result["rejected"])
    ambiguous = source_with_endpoints(endpoints=[{"transport": "http", "endpoint": "http://a.invalid"},
                                                  {"transport": "http", "endpoint": "http://b.invalid"}],
                                      transport_policy={"bootstrap": ["http"]})
    assert TransportResolver().plan(ambiguous, "bootstrap")["state"] == TransportState.AMBIGUOUS.value
    assert TransportResolver().plan(source_with_endpoints(enabled=False), "bootstrap")["state"] == TransportState.POLICY_BLOCKED.value


class _FTPFixture:
    payload = b"same bytes from FTP"
    calls = []

    def __enter__(self): return self
    def __exit__(self, *_args): return False
    def connect(self, host, port, timeout): self.calls.append(("connect", host, port, timeout))
    def login(self): self.calls.append(("login",))
    def set_pasv(self, value): self.calls.append(("pasv", value))
    def retrbinary(self, command, callback, blocksize=8192):
        self.calls.append(("retr", command, blocksize)); callback(self.payload)


def ftp_source():
    return SourceDefinition.from_dict({"id": "ftp-fixture", "name": "FTP fixture", "class": "MIRROR",
        "backend": "ftp", "location": "ftp://fixture.invalid/pub/", "bulk_acquisition": "allowed",
        "rights_default": "REDISTRIBUTABLE", "enabled": True, "mirror_authorized": True,
        "minimum_free_space_bytes": 0})


def test_ftp_binary_acquisition_provenance_deduplication_and_cleanup(tmp_path, monkeypatch):
    monkeypatch.setattr("rab.acquisition.ftplib.FTP", _FTPFixture)
    archive = Archive(tmp_path / "archive"); acquisition = Acquisition(archive); source = ftp_source()
    expected = __import__("hashlib").sha256(_FTPFixture.payload).hexdigest()
    object_id = acquisition.acquire_ftp(source, "dir/file.bin", expected_sha256=expected, expected_size=len(_FTPFixture.payload), acquisition_context={"purpose": "bootstrap"})
    assert archive.show(object_id)["size"] == len(_FTPFixture.payload)
    assert _FTPFixture.calls[2][0] == "pasv" and _FTPFixture.calls[3][1] == "RETR /pub/dir/file.bin"
    assert not list((archive.root / "source-staging" / source.id).glob("*.part"))
    with archive.db() as db:
        detail = json.loads(db.execute("SELECT detail FROM source_events WHERE event_type='SOURCE_INGEST'").fetchone()[0])
    assert detail["transport"] == "ftp" and detail["purpose"] == "bootstrap"
    other = tmp_path / "same.bin"; other.write_bytes(_FTPFixture.payload)
    manual = SourceDefinition.from_dict({"id": "manual-copy", "name": "Manual", "class": "INGEST", "backend": "manual", "bulk_acquisition": "prohibited", "rights_default": "UNKNOWN"})
    staged = acquisition._stage_file(manual, "same.bin", other)
    acquisition.ingest_completed(manual, "same.bin", staged, "application/octet-stream")
    assert len(list(archive.objects.rglob("master"))) == 1


def test_ftp_failure_and_path_traversal_do_not_create_masters(tmp_path, monkeypatch):
    class Broken(_FTPFixture):
        def retrbinary(self, *_args, **_kwargs): raise TimeoutError("fixture timeout")
    monkeypatch.setattr("rab.acquisition.ftplib.FTP", Broken)
    archive = Archive(tmp_path / "archive"); acquisition = Acquisition(archive)
    with pytest.raises(RabError): acquisition.acquire_ftp(ftp_source(), "file.bin")
    with pytest.raises(PolicyError): acquisition.acquire_ftp(ftp_source(), "../escape")
    monkeypatch.setattr("rab.acquisition.ftplib.FTP", _FTPFixture)
    with pytest.raises(PolicyError): acquisition.acquire_ftp(SourceDefinition.from_dict({**ftp_source().public(), "staging_limit_bytes": 4}), "file.bin")
    assert not list(archive.objects.rglob("master"))


def test_transport_plan_is_dry_run_and_cli_compatible(tmp_path, monkeypatch):
    archive = Archive(tmp_path / "archive"); source = source_with_endpoints()
    result = TransportResolver().fetch(Acquisition(archive), source, "bootstrap", path="not-downloaded", dry_run=True)
    assert result["dry_run"] is True and result["plan"]["selected"] is not None
    assert not list(archive.objects.rglob("master"))


def test_transport_cli_and_api_read_plan_boundaries(tmp_path):
    parsed = parser().parse_args(["--root", str(tmp_path / "archive"), "acquisition", "transports"])
    assert {x["transport"] for x in run(parsed)} == {"bittorrent", "rsync", "https", "http", "ftp"}
    archive = Archive(tmp_path / "api-archive"); Catalogue(archive).rebuild()
    api = CatalogueAPI(Catalogue(archive), SourceRegistry(Path(__file__).parents[1] / "config" / "sources"))
    assert api.dispatch("GET", "/api/v1/acquisition/transports")[0] == 200
    status, value = api.dispatch("GET", "/api/v1/acquisition/sources/aminet")
    assert status == 200 and "plans" in value and "endpoints" in value["source"]
    assert api.dispatch("GET", "/api/v1/acquisition/plan/unknown")[0] == 404


def test_http_and_ftp_identical_bytes_converge_to_one_master(tmp_path, monkeypatch):
    payload = _FTPFixture.payload; (tmp_path / "same.bin").write_bytes(payload)
    handler = functools.partial(SimpleHTTPRequestHandler, directory=str(tmp_path))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    import threading
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        http_source = SourceDefinition.from_dict({"id": "http-fixture", "name": "HTTP fixture", "class": "MIRROR",
            "backend": "http", "location": f"http://127.0.0.1:{server.server_port}/", "bulk_acquisition": "allowed",
            "rights_default": "REDISTRIBUTABLE", "enabled": True, "mirror_authorized": True, "minimum_free_space_bytes": 0})
        monkeypatch.setattr("rab.acquisition.ftplib.FTP", _FTPFixture)
        archive = Archive(tmp_path / "archive"); acquisition = Acquisition(archive)
        expected = __import__("hashlib").sha256(payload).hexdigest()
        acquisition.acquire_http(http_source, "same.bin", expected_sha256=expected, expected_size=len(payload))
        acquisition.acquire_ftp(ftp_source(), "same.bin", expected_sha256=expected, expected_size=len(payload))
        assert len(list(archive.objects.rglob("master"))) == 1
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)
