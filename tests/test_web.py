import json
import threading
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen

from rab.broker import ResourceBroker, ResourceDefinition, ResourceKind
from rab.catalogue import Catalogue
from rab.model import Rights
from rab.sources import SourceDefinition
from rab.sources import SourceRegistry
from rab.store import Archive
from rab.acquisition import Acquisition
from rab.web import WebApplication, build_web_server


def _source():
    return SourceDefinition.from_dict({"id": "aminet", "name": "Aminet", "class": "MIRROR", "backend": "manual",
        "bulk_acquisition": "allowed", "rights_default": "REDISTRIBUTABLE", "enabled": True,
        "mirror_authorized": True, "platforms": ["Amiga"]})


def _archive(tmp_path):
    upstream = tmp_path / "upstream" / "comm" / "term"; upstream.mkdir(parents=True)
    (upstream / "ncomm307.lha").write_bytes(b"payload bytes")
    (upstream / "ncomm307.readme").write_bytes(b"Name: NComm\nVersion: 3.07\n<html>historical</html>\n")
    archive = Archive(tmp_path / "archive")
    Acquisition(archive).sync_aminet(_source(), tmp_path / "upstream")
    Catalogue(archive).rebuild()
    ResourceBroker(archive).register_package("aminet:comm/term/ncomm307")
    return archive


def _app(tmp_path):
    return WebApplication(_archive(tmp_path), SourceRegistry(Path(__file__).parents[1] / "config" / "sources"))


def test_server_rendered_home_search_resource_and_readme(tmp_path):
    app = _app(tmp_path)
    before = {path.relative_to(app.catalogue.archive.root): path.read_bytes() for path in app.catalogue.archive.objects.rglob("*") if path.is_file()}
    status, content_type, home, _ = app.dispatch("GET", "/web/")
    assert status == 200 and content_type.startswith("text/html")
    assert "Search:" in home and "<script" not in home.lower()
    status, _, result, _ = app.dispatch("GET", "/web/search?q=ncomm")
    assert status == 200 and "NComm" in result and 'href="/web/resource/' in result
    resource_id = quote("aminet:comm/term/ncomm307", safe="")
    status, _, page, _ = app.dispatch("GET", "/retro/resource/" + resource_id)
    assert status == 200 and "ncomm307" in page and "<link" not in page and "<script" not in page.lower()
    definition = app.broker.show("aminet:comm/term/ncomm307")
    readme = next(x["sha256"] for x in definition["objects"] if x["role"] == "readme")
    status, _, text, _ = app.dispatch("GET", "/retro/readme/" + quote(readme, safe=""))
    assert status == 200 and "&lt;html&gt;historical&lt;/html&gt;" in text
    after = {path.relative_to(app.catalogue.archive.root): path.read_bytes() for path in app.catalogue.archive.objects.rglob("*") if path.is_file()}
    assert before == after


def test_web_download_uses_broker_rights_and_range_server(tmp_path):
    app = _app(tmp_path)
    definition = app.broker.show("aminet:comm/term/ncomm307")
    payload = next(x["sha256"] for x in definition["objects"] if x["role"] == "payload")
    status, content_type, body, download = app.dispatch("GET", "/web/download/" + quote(payload, safe=""))
    assert status == 200 and body is None and download["object_id"] == payload
    assert download["filename"].endswith(".lha")
    assert "/objects/" in download["path"]  # internal to the delivery service only


def test_web_filters_browse_sets_and_is_read_only(tmp_path):
    app = _app(tmp_path); prefix = "/web"
    for route in ("/platforms", "/platform/amiga", "/sources", "/source/aminet"):
        status, _, body, _ = app.dispatch("GET", prefix + route)
        assert status == 200 and "<html" in body.lower()
    assert "Acquisition transports" in app.dispatch("GET", prefix + "/source/aminet")[2]
    resource_id = "aminet:comm/term/ncomm307"
    set_value = app.broker.define_set("amiga:ncomm", [{"role": "package", "resource_id": resource_id}])
    # Rebuild the broker index before the read-only web process sees the set.
    app.broker.read_only = False; app.broker.rebuild(); app.broker.read_only = True
    status, _, body, _ = app.dispatch("GET", prefix + "/set/" + quote(set_value["set_id"], safe=""))
    assert status == 200 and "Members" in body and resource_id not in body
    assert 'href="/web/search"' in body
    assert app.dispatch("POST", "/web/search")[0] == 405


def test_web_invalid_and_malicious_routes_are_bounded(tmp_path):
    app = _app(tmp_path)
    assert app.dispatch("GET", "/web/resource/../../etc/passwd")[0] in {404, 409}
    assert app.dispatch("GET", "/web/search?limit=not-a-number")[0] == 403
    status, _, body, _ = app.dispatch("GET", "/web/search?q=%3Cscript%3Ealert(1)%3C/script%3E")
    assert status == 200 and "<script>" not in body and "&lt;script&gt;" in body
    assert "fetch(" not in body and "type=\"module\"" not in body


def test_web_http_server_streams_without_exposing_service_path(tmp_path):
    archive = _archive(tmp_path)
    server = build_web_server(archive, SourceRegistry(Path(__file__).parents[1] / "config" / "sources"), "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        base = "http://127.0.0.1:%d" % server.server_port
        home = urlopen(base + "/retro/").read().decode("utf-8")
        assert "Search:" in home and "<script" not in home.lower()
        descriptor = ResourceBroker(archive).show("aminet:comm/term/ncomm307")
        payload = next(x["sha256"] for x in descriptor["objects"] if x["role"] == "payload")
        response = urlopen(Request(base + "/retro/download/" + quote(payload, safe=""), headers={"Range": "bytes=0-2"}))
        assert response.status == 206 and response.read() == b"pay"
        assert "/objects/" not in response.headers.get("Content-Disposition", "")
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)


def test_web_rights_display_does_not_offer_denied_link(tmp_path):
    archive = _archive(tmp_path); broker = ResourceBroker(archive)
    package = broker.show("aminet:comm/term/ncomm307")
    broker.register(ResourceDefinition("resource:private-web", ResourceKind.ROM, "Private web item",
        objects=tuple({"role": x["role"], "sha256": x["sha256"]} for x in package["objects"]), rights=Rights.PRIVATE_LICENSED))
    app = WebApplication(archive, SourceRegistry(Path(__file__).parents[1] / "config" / "sources"))
    status, _, body, _ = app.dispatch("GET", "/web/resource/" + quote("resource:private-web", safe=""))
    assert status == 200 and "redistribution denied" in body and "/web/download/" not in body
    assert app.dispatch("GET", "/web/download/" + quote(package["objects"][0]["sha256"], safe=""))[0] == 200
