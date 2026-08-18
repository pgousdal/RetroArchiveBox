from __future__ import annotations

import json
import re
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from .catalogue import Catalogue
from .errors import RabError
from .errors import IntegrityError, PolicyError


class CatalogueAPI:
    """Read-only, bounded API facade shared by HTTP and tests."""
    def __init__(self, catalogue: Catalogue, registry=None):
        self.catalogue, self.registry = catalogue, registry

    def dispatch(self, method: str, path: str, query: dict[str, list[str]] | None = None):
        if method != "GET":
            return 405, {"error": "method_not_allowed"}
        if len(path) > 8192:
            return 414, {"error": "request_too_large"}
        parsed = urlparse(path)
        query = query or parse_qs(parsed.query)
        route = parsed.path.rstrip("/")
        try:
            return self._dispatch(route, query)
        except RabError:
            return 404, {"error": "not_found"}

    def _dispatch(self, route, query):
        if route == "/api/v1/status":
            status = self.catalogue.status(read_only=True)
            status["preservation_store"] = self.catalogue.archive.objects.is_dir()
            status["catalogue_available"] = True
            return 200, status
        if route == "/api/v1/sources":
            return 200, [x.public() for x in self.registry.load().values()] if self.registry else []
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
        row = self.catalogue.show_object("sha256:" + sha)
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

    @staticmethod
    def _public_download(value: dict) -> dict:
        return {key: value[key] for key in ("object_id", "filename", "size", "rights")}


def run_server(archive, registry, host="127.0.0.1", port=8000):
    build_server(archive, registry, host, port).serve_forever()


def build_server(archive, registry, host="127.0.0.1", port=8000):
    catalogue = Catalogue(archive)
    catalogue.validate_readonly()
    api = CatalogueAPI(catalogue, registry)

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
