from __future__ import annotations

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from .catalogue import Catalogue
from .errors import RabError


class CatalogueAPI:
    """Read-only, bounded API facade shared by HTTP and tests."""
    def __init__(self, catalogue: Catalogue, registry=None):
        self.catalogue, self.registry = catalogue, registry

    def dispatch(self, method: str, path: str, query: dict[str, list[str]] | None = None):
        if method != "GET":
            return 405, {"error": "method_not_allowed"}
        parsed = urlparse(path)
        query = query or parse_qs(parsed.query)
        route = parsed.path.rstrip("/")
        try:
            return self._dispatch(route, query)
        except RabError:
            return 404, {"error": "not_found"}

    def _dispatch(self, route, query):
        if route == "/api/v1/status":
            return 200, self.catalogue.status()
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
        prefix = "/api/v1/packages/"
        if route.startswith(prefix):
            bits = route[len(prefix):].split("/", 1)
            if len(bits) != 2 or not re.fullmatch(r"[a-z0-9-]+", bits[0]):
                return 400, {"error": "invalid_package_id"}
            result = self.catalogue.show_package(bits[0] + ":" + unquote(bits[1]))
            return (200, result) if result else (404, {"error": "not_found"})
        return 404, {"error": "not_found"}


def run_server(archive, registry, host="127.0.0.1", port=8000):
    catalogue = Catalogue(archive)
    catalogue.initialize()
    api = CatalogueAPI(catalogue, registry)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            status, payload = api.dispatch("GET", self.path)
            body = json.dumps(payload, sort_keys=True).encode()
            self.send_response(status); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        def log_message(self, *_):
            return

    ThreadingHTTPServer((host, port), Handler).serve_forever()
