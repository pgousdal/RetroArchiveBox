import json
import pytest

from rab.api import CatalogueAPI
from rab.authority import Authority
from rab.catalogue import Catalogue
from rab.errors import PolicyError
from rab.identity import IdentityCatalogue, IdentityLevel, RelationshipType
from rab.model import IngestRequest, Rights
from rab.products import ProductBuilder
from rab.store import Archive
from rab.web import WebApplication


def _archive(tmp_path):
    archive = Archive(tmp_path / "archive")
    amiga = tmp_path / "demo.adf"; amiga.write_bytes(b"A" * 901120)
    c64 = tmp_path / "demo.d64"; c64.write_bytes(b"C" * 174848)
    a = archive.ingest(IngestRequest(amiga, "amiga-fixture", "demo.adf", Rights.REDISTRIBUTABLE, "application/octet-stream", "Amiga demo"))["object_id"]
    c = archive.ingest(IngestRequest(c64, "c64-fixture", "demo.d64", Rights.UNKNOWN, "application/octet-stream", "C64 demo"))["object_id"]
    Catalogue(archive).rebuild()
    return archive, a, c


def test_universal_identity_hashes_profiles_authority_and_relationships(tmp_path):
    archive, amiga, c64 = _archive(tmp_path); identity = IdentityCatalogue(archive)
    first = identity.rebuild(); assert first["objects"] == 2
    a = identity.show(amiga); c = identity.show(c64)
    assert a["format_id"] == "adf" and a["platform_family"] == "amiga"
    assert c["format_id"] == "d64" and c["platform_family"] == "commodore-8-bit" and c["platform"] == "c64"
    assert set(identity.hashes(amiga)) == {"object_id", "size", "crc32", "md5", "sha1", "sha256", "blake3"}
    release = identity.define_logical(IdentityLevel.RELEASE, "Demo release", version="1", platform="amiga", identity_id="identity:release:demo")
    work = identity.define_logical(IdentityLevel.WORK, "Demo work", identity_id="identity:work:demo")
    identity.add_relationship(amiga, RelationshipType.MEMBER_OF_RELEASE, release["identity_id"], {"source": "fixture"})
    identity.add_relationship(release["identity_id"], RelationshipType.RELEASE_OF_WORK, work["identity_id"], {"source": "fixture"})
    assert len(identity.relationships(amiga)) == 1
    with pytest.raises(PolicyError):
        identity.add_relationship(work["identity_id"], RelationshipType.RELEASE_OF_WORK, release["identity_id"], {"source": "cycle"})
    assert identity.show(c64)["rights"] == ["UNKNOWN"]

    h = identity.hashes(c64)
    dat = tmp_path / "c64.dat"
    dat.write_text('<datafile><header><name>C64 identity fixture</name></header><game name="Demo"><rom name="demo.d64" size="%s" crc="%s" md5="%s" sha1="%s" /></game></datafile>' % (h["size"], h["crc32"], h["md5"], h["sha1"]), encoding="ascii")
    Authority(archive).import_tosec(dat, release="identity-fixture")
    identity.rebuild()
    assert identity.show(c64)["authorities"][0]["authority"] == "TOSEC"


def test_identity_rebuild_and_products_are_deterministic(tmp_path):
    archive, amiga, c64 = _archive(tmp_path); identity = IdentityCatalogue(archive); identity.rebuild()
    products = ProductBuilder(archive, identity=identity)
    all_product = products.build("identity")
    amiga_product = products.build("identity", platform="amiga", format_id="adf")
    c64_product = products.build("identity", platform="c64", format_id="d64")
    fixity = products.build("fixity")
    assert all_product["record_count"] == 2 and amiga_product["record_count"] == 1 and c64_product["record_count"] == 1
    assert fixity["record_count"] == 2
    product_before = products.read(all_product["path_id"])
    semantic_before = [identity.show(x) for x in (amiga, c64)]
    identity.db_path.unlink(); identity.rebuild()
    product_after = ProductBuilder(archive, identity=identity).build("identity")
    assert product_before == ProductBuilder(archive, identity=identity).read(product_after["path_id"])
    assert semantic_before == [identity.show(x) for x in (amiga, c64)]
    assert (archive.object_dir(amiga.removeprefix("sha256:")) / "master").read_bytes() == b"A" * 901120


def test_identity_api_and_retroweb_are_metadata_only(tmp_path):
    archive, amiga, _ = _archive(tmp_path); identity = IdentityCatalogue(archive); identity.rebuild(); ProductBuilder(archive, identity=identity).build("identity")
    api = CatalogueAPI(Catalogue(archive))
    assert api.dispatch("GET", "/api/v1/identity/status")[0] == 200
    assert api.dispatch("GET", "/api/v1/objects/" + amiga + "/identity")[0] == 200
    assert api.dispatch("GET", "/api/v1/objects/" + amiga + "/hashes")[0] == 200
    assert api.dispatch("GET", "/api/v1/products")[0] == 200
    web = WebApplication(archive)
    status, _, body, _ = web.dispatch("GET", "/retro/identity/" + amiga)
    assert status == 200 and "blake3" in body and "<script" not in body.lower()
