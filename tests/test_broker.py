import json

import pytest

from rab.acquisition import Acquisition
from rab.api import CatalogueAPI
from rab.authority import Authority
from rab.broker import (BrokerError, ConsumerContext, DeliveryMode, ResourceBroker,
                        ResourceDefinition, ResourceKind, ResolutionState)
from rab.catalogue import Catalogue
from rab.model import IngestRequest, Rights
from rab.sources import SourceDefinition
from rab.store import Archive


def _source():
    return SourceDefinition.from_dict({"id": "aminet", "name": "Aminet", "class": "MIRROR", "backend": "manual",
        "bulk_acquisition": "allowed", "rights_default": "REDISTRIBUTABLE", "enabled": True,
        "mirror_authorized": True, "platforms": ["Amiga"]})


def _archive(tmp_path):
    upstream = tmp_path / "upstream" / "comm" / "term"; upstream.mkdir(parents=True)
    (upstream / "ncomm307.lha").write_bytes(b"payload")
    (upstream / "ncomm307.readme").write_bytes(b"Name: NComm\nVersion: 3.07\n")
    archive = Archive(tmp_path / "archive")
    Acquisition(archive).sync_aminet(_source(), tmp_path / "upstream")
    Catalogue(archive).rebuild()
    return archive


def test_aminet_resolve_pin_materialize_and_rebuild(tmp_path):
    archive = _archive(tmp_path); broker = ResourceBroker(archive)
    definition = broker.register_package("aminet:comm/term/ncomm307")
    assert definition["resource_id"] == "aminet:comm/term/ncomm307"
    resolved = broker.resolve(platform="amiga", name="NComm", version="3.07")
    assert resolved["resolution"]["state"] == "RESOLVED"
    assert {x["role"] for x in resolved["objects"]} == {"payload", "readme"}
    lock = broker.pin(definition["resource_id"], context=ConsumerContext(delivery_mode=DeliveryMode.MATERIALIZE))
    path = tmp_path / "archive" / "consumer-state" / "test-consumer" / "workspaces" / "aminet"
    materialized = broker.materialize(definition["resource_id"], "test-consumer", path)
    assert all(x["path"].startswith(str(path)) for x in materialized["objects"])
    lock_path = tmp_path / "resources.lock.json"; lock_path.write_text(json.dumps(lock), encoding="utf-8")
    assert broker.verify_manifest(lock_path)["outcome"] == "PASS"
    before = {x: x.read_bytes() for x in archive.objects.rglob("master")}
    archive.db_path.unlink(); Catalogue(archive).rebuild(); assert ResourceBroker(archive).rebuild()["resources"] == 1
    assert ResourceBroker(archive).resolve("aminet:comm/term/ncomm307")["preservation_objects"]
    assert before == {x: x.read_bytes() for x in archive.objects.rglob("master")}


def test_rights_delivery_is_separate_from_resolution(tmp_path):
    archive = _archive(tmp_path); broker = ResourceBroker(archive)
    package = broker.register_package("aminet:comm/term/ncomm307")
    sha = package["objects"][0]["sha256"]
    resource = broker.register(ResourceDefinition("resource:restricted", ResourceKind.ROM, "Restricted", objects=({"role": "payload", "sha256": sha},), rights=Rights.RESTRICTED))
    resolved = broker.resolve(resource["resource_id"], context=ConsumerContext(rights_context="public"))
    assert resolved["resolution"]["state"] == "RESOLVED" and resolved["resolution"]["delivery"]["state"] == "RIGHTS_DENIED"
    with pytest.raises(BrokerError) as exc:
        broker.pin(resource["resource_id"], context=ConsumerContext(rights_context="public"))
    assert exc.value.state == ResolutionState.RIGHTS_DENIED


def test_ambiguity_and_dependency_cycle(tmp_path):
    broker = ResourceBroker(_archive(tmp_path))
    broker.register(ResourceDefinition("resource:a", ResourceKind.TOOL, "Same", version="1", objects=()))
    broker.register(ResourceDefinition("resource:b", ResourceKind.TOOL, "Same", version="1", objects=()))
    with pytest.raises(BrokerError) as exc: broker.resolve(name="Same", version="1")
    assert exc.value.state == ResolutionState.AMBIGUOUS
    broker.register(ResourceDefinition("resource:c", ResourceKind.TOOL, "C", dependencies=("resource:d",)))
    with pytest.raises(Exception): broker.register(ResourceDefinition("resource:d", ResourceKind.TOOL, "D", dependencies=("resource:c",)))


def test_materialization_path_escape_is_rejected(tmp_path):
    archive = _archive(tmp_path); broker = ResourceBroker(archive)
    broker.register_package("aminet:comm/term/ncomm307")
    with pytest.raises(Exception): broker.materialize("aminet:comm/term/ncomm307", "test-consumer", tmp_path / "outside")


def test_resource_set_generation_and_many_consumers_one_master(tmp_path):
    archive = _archive(tmp_path); broker = ResourceBroker(archive)
    package = broker.register_package("aminet:comm/term/ncomm307")
    broker.registry.path = tmp_path / "consumers.json"
    broker.registry.path.write_text(json.dumps({"consumers": [
        {"consumer_id": "a", "enabled": True}, {"consumer_id": "b", "enabled": True}]}), encoding="utf-8")
    first = broker.define_set("amiga:test", [{"role": "package", "resource_id": package["resource_id"]}])
    second = broker.define_set("amiga:test", [{"role": "package", "resource_id": package["resource_id"]}])
    assert second["generation"] == first["generation"] + 1
    assert broker.show_set("amiga:test", first["generation"])["generation"] == 1
    broker.materialize(package["resource_id"], "a")
    reused = broker.materialize(package["resource_id"], "b")
    assert any(x["reused"] is False for x in reused["objects"])
    assert len(list(archive.objects.rglob("master"))) == 2


def test_broker_api_has_structured_response_and_bounded_errors(tmp_path):
    archive = _archive(tmp_path); broker = ResourceBroker(archive)
    definition = broker.register_package("aminet:comm/term/ncomm307")
    api = CatalogueAPI(Catalogue(archive))
    status, payload = api.dispatch("GET", "/api/v1/resources/" + definition["resource_id"])
    assert status == 200 and "preservation_objects" in payload and "/objects/" not in json.dumps(payload)
    assert api.dispatch("POST", "/api/v1/resources/resolve", body={"name": "NComm", "version": "3.07"})[0] == 200
    assert api.dispatch("GET", "/api/v1/resources/sha256:not-a-hash")[0] == 404
    assert api.dispatch("GET", "/api/v1/resources?name=" + "x" * 5000)[0] == 403


def test_authority_constraint_is_evidence_not_identity(tmp_path):
    archive = Archive(tmp_path / "archive")
    payload = tmp_path / "payload"; payload.write_bytes(b"test")
    object_id = archive.ingest(IngestRequest(payload, "manual", "payload", Rights.REDISTRIBUTABLE, "application/octet-stream"))["object_id"]
    dat = tmp_path / "authority.dat"
    dat.write_text('<datafile><header><name>TOSEC Test</name></header><game name="Demo"><rom name="demo" size="4" crc="81dc9bdb" md5="098f6bcd4621d373cade4e832627b4f6" sha1="a94a8fe5ccb19ba61c4c0873d391e987982fbb3d3" /></game></datafile>', encoding="ascii")
    Authority(archive).import_tosec(dat, release="test-release")
    broker = ResourceBroker(archive)
    broker.register(ResourceDefinition("resource:authority-demo", ResourceKind.ROM, "Demo", objects=({"role": "payload", "sha256": object_id},), rights=Rights.REDISTRIBUTABLE))
    resolved = broker.resolve("resource:authority-demo", authority={"TOSEC": "EXACT_MATCH"})
    assert resolved["authority_assertions"][0]["result"] == "EXACT_MATCH"
    assert broker.pin("resource:authority-demo", authority={"TOSEC": "EXACT_MATCH"})["authority"]
