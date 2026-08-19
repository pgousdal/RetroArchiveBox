from __future__ import annotations

import json
import re
import os
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from .catalogue import Catalogue
from .errors import RabError
from .errors import IntegrityError, PolicyError
from .authority import Authority
from .redump import RedumpAuthority
from .additional_authorities import AdditionalAuthority
from .broker import BrokerError, ConsumerContext, ConsumerRegistry, DeliveryMode, ResourceBroker, ResolutionState


class CatalogueAPI:
    """Read-only, bounded API facade shared by HTTP and tests."""
    def __init__(self, catalogue: Catalogue, registry=None, consumer_registry=None):
        self.catalogue, self.registry = catalogue, registry
        self.broker = ResourceBroker(catalogue.archive, registry=consumer_registry)

    def dispatch(self, method: str, path: str, query: dict[str, list[str]] | None = None, body: dict | None = None):
        if method not in {"GET", "POST"} or (method == "POST" and not urlparse(path).path.rstrip("/").endswith("/resources/resolve")):
            return 405, {"error": "method_not_allowed"}
        if len(path) > 8192:
            return 414, {"error": "request_too_large"}
        parsed = urlparse(path)
        query = query or parse_qs(parsed.query)
        route = parsed.path.rstrip("/")
        try:
            return self._dispatch(route, query, body or {})
        except BrokerError as exc:
            code = 409 if exc.state == ResolutionState.AMBIGUOUS else 403 if exc.state in {ResolutionState.RIGHTS_DENIED, ResolutionState.POLICY_BLOCKED} else 404
            return code, {"error": exc.state.value, "message": str(exc)}
        except RabError:
            return 404, {"error": "not_found"}
        except ValueError:
            return 400, {"error": "invalid_request"}

    def _dispatch(self, route, query, body):
        if route == "/api/v1/status":
            status = self.catalogue.status(read_only=True)
            status["preservation_store"] = self.catalogue.archive.objects.is_dir()
            status["catalogue_available"] = True
            return 200, status
        if route == "/api/v1/sources":
            return 200, [x.public() for x in self.registry.load().values()] if self.registry else []
        if route == "/api/v1/authorities":
            return 200, Authority(self.catalogue.archive).list()
        if route == "/api/v1/consumers":
            return 200, self.broker.registry.list()
        if route == "/api/v1/resources":
            allowed = {"platform", "ecosystem", "os", "architecture", "hardware", "kind", "name", "version", "title", "source"}
            return 200, self.broker.search(**{k: query[k][0] for k in allowed if k in query})
        if route == "/api/v1/resources/resolve":
            request = {**body, **{k: v[0] for k, v in query.items() if v}}
            resource_id = request.pop("resource_id", None)
            context = ConsumerContext(consumer_id=request.pop("consumer_id", "test-consumer"),
                                      delivery_mode=DeliveryMode(request.pop("delivery_mode", "MANIFEST_ONLY")),
                                      rights_context=request.pop("rights_context", "local-owner"))
            return 200, self.broker.resolve(resource_id, context=context, authority=request.pop("authority", None), **request)
        m = re.fullmatch(r"/api/v1/resources/(.+)/(content|pin|materialize)", route)
        if m:
            resource_id, action = unquote(m.group(1)), m.group(2)
            if action == "content":
                resolved = self.broker.resolve(resource_id, context=ConsumerContext(delivery_mode=DeliveryMode.STREAM))
                item = resolved["objects"][0]
                return 200, {"download": self._public_download(self.download_object(item["sha256"], public=False))}
            if action == "pin":
                return 200, self.broker.pin(resource_id)
            return 200, self.broker.materialize(resource_id, body.get("consumer_id", "test-consumer"))
        m = re.fullmatch(r"/api/v1/resources/(.+)", route)
        if m:
            return 200, self.broker.show(unquote(m.group(1)))
        m = re.fullmatch(r"/api/v1/resource-sets/(.+)", route)
        if m:
            return 200, self.broker.show_set(unquote(m.group(1)))
        m = re.fullmatch(r"/api/v1/authorities/([0-9a-f]{64})/records", route)
        if m:
            return 200, AdditionalAuthority(self.catalogue.archive).records(m.group(1))
        if route.startswith("/api/v1/authorities/"):
            dataset = unquote(route.removeprefix("/api/v1/authorities/"))
            rows = [x for x in Authority(self.catalogue.archive).list()
                    if x["dataset_id"].startswith(dataset) or x["release_identity"] == dataset]
            return (200, rows[0]) if rows else (404, {"error": "not_found"})
        m = re.fullmatch(r"/api/v1/redump/discs/([0-9a-f]{64})(/tracks)?", route)
        if m:
            disc = RedumpAuthority(self.catalogue.archive).show_disc(m.group(1))
            return 200, disc["tracks"] if m.group(2) else disc
        if route == "/api/v1/search":
            q = query.get("q", [""])[0]
            try:
                limit = min(max(int(query.get("limit", [25])[0]), 1), 100)
                offset = max(int(query.get("offset", [0])[0]), 0)
            except ValueError:
                return 400, {"error": "invalid_pagination"}
            return 200, self.catalogue.search(q, platform=query.get("platform", [None])[0],
                source=query.get("source", [None])[0], format_id=query.get("format", [None])[0],
                rights=query.get("rights", [None])[0], limit=limit, offset=offset)
        m = re.fullmatch(r"/api/v1/objects/(?:sha256:)?([0-9a-f]{64})", route)
        if m:
            result = self.catalogue.show_object("sha256:" + m.group(1))
            return (200, result) if result else (404, {"error": "not_found"})
        m = re.fullmatch(r"/api/v1/objects/(?:sha256:)?([0-9a-f]{64})/assertions", route)
        if m:
            return 200, Authority(self.catalogue.archive).assertions(m.group(1))
        m = re.fullmatch(r"/api/v1/objects/(?:sha256:)?([0-9a-f]{64})/download", route)
        if m:
            return 200, {"download": self._public_download(self.download_object("sha256:" + m.group(1), public=False))}
        prefix = "/api/v1/packages/"
        if route.startswith(prefix):
            if route.endswith("/download"):
                bits = route[len(prefix):-len("/download")].rstrip("/").split("/", 1)
                if len(bits) != 2 or not re.fullmatch(r"[a-z0-9-]+", bits[0]):
                    return 400, {"error": "invalid_package_id"}
                package = self.catalogue.show_package(bits[0] + ":" + unquote(bits[1]))
                asset = query.get("asset", ["payload"])[0]
                object_id = package.get("payload_object") if asset == "payload" else package.get("readme_object") if asset == "readme" else None
                if not object_id:
                    return 404, {"error": "asset_not_found"}
                return 200, {"download": self._public_download(self.download_object(object_id, public=False))}
            bits = route[len(prefix):].split("/", 1)
            if len(bits) != 2 or not re.fullmatch(r"[a-z0-9-]+", bits[0]):
                return 400, {"error": "invalid_package_id"}
            result = self.catalogue.show_package(bits[0] + ":" + unquote(bits[1]))
            return (200, result) if result else (404, {"error": "not_found"})
        return 404, {"error": "not_found"}

    def download_object(self, identifier: str, *, public: bool = False) -> dict:
        sha = self.catalogue.archive.resolve(identifier)
        row = self.catalogue.show_object("sha256:" + sha, read_only=True)
        rights = {x["rights"] for x in row.get("occurrences", [])}
        if public and (not rights or rights - {"REDISTRIBUTABLE"}):
            raise PolicyError("object is not authorized for public redistribution")
        # API workers are read-only; fixity checks must not append events.
        self.catalogue.archive.verify(sha, record_event=False)
        master = self.catalogue.archive.object_dir(sha) / "master"
        if not master.is_file() or master.is_symlink():
            raise IntegrityError("preservation master is unavailable")
        names = [x.get("source_path", "") for x in row.get("occurrences", [])]
        filename = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(names[0] if names else sha)) or sha
        return {"object_id": "sha256:" + sha, "path": str(master), "filename": filename,
                "size": master.stat().st_size, "rights": sorted(rights)}

    def read_object_text(self, identifier: str, *, maximum: int = 512 * 1024) -> str:
        """Read a bounded textual object through the same verified boundary."""
        download = self.download_object(identifier, public=False)
        with open(download["path"], "rb") as handle:
            data = handle.read(maximum + 1)
        if len(data) > maximum:
            data = data[:maximum] + b"\n[truncated by RAB]\n"
        return data.decode("latin-1", errors="replace")

    @staticmethod
    def _public_download(value: dict) -> dict:
        return {key: value[key] for key in ("object_id", "filename", "size", "rights")}


def run_server(archive, registry, host="127.0.0.1", port=8000):
    build_server(archive, registry, host, port).serve_forever()


def build_server(archive, registry, host="127.0.0.1", port=8000):
    catalogue = Catalogue(archive)
    catalogue.validate_readonly()
    consumer_path = Path(__file__).parents[2] / "config" / "consumers.json"
    api = CatalogueAPI(catalogue, registry, ConsumerRegistry(consumer_path) if consumer_path.is_file() else None)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            try:
                status, payload = api.dispatch("GET", self.path)
                download = payload.get("download") if isinstance(payload, dict) else None
                if download:
                    self._send_file(api.download_object(download["object_id"], public=False) | download)
                    return
                body = json.dumps(payload, sort_keys=True).encode()
                self.send_response(status); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
            except (RabError, OSError) as exc:
                body = json.dumps({"error": str(exc)}).encode()
                self.send_response(403 if isinstance(exc, PolicyError) else 404)
                self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body)
        def do_POST(self):  # noqa: N802
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length > 1024 * 1024:
                    self.send_error(413, "request too large"); return
                body = json.loads(self.rfile.read(length) or b"{}")
                status, payload = api.dispatch("POST", self.path, body=body)
                encoded = json.dumps(payload, sort_keys=True).encode()
                self.send_response(status); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded))); self.end_headers(); self.wfile.write(encoded)
            except (RabError, OSError, ValueError, json.JSONDecodeError):
                self.send_error(400, "invalid request")
        def _send_file(self, download):
            path = download["path"]; size = download["size"]; start, end = 0, size - 1
            value = self.headers.get("Range")
            if value:
                match = re.fullmatch(r"bytes=(\d*)-(\d*)", value)
                if not match:
                    self.send_error(416, "invalid range"); return
                start = int(match.group(1) or 0); end = int(match.group(2) or end)
                if start > end or start >= size:
                    self.send_error(416, "range unsatisfiable"); return
                end = min(end, size - 1)
                self.send_response(206); self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
            else:
                self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f"attachment; filename=\"{download['filename']}\"")
            self.send_header("Content-Length", str(end - start + 1)); self.end_headers()
            with open(path, "rb") as handle:
                handle.seek(start); remaining = end - start + 1
                while remaining:
                    chunk = handle.read(min(1024 * 1024, remaining))
                    if not chunk: break
                    self.wfile.write(chunk); remaining -= len(chunk)
        def log_message(self, *_):
            return

    return ThreadingHTTPServer((host, port), Handler)
