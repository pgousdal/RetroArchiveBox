"""Conservative, server-rendered read-only RAB web interface."""
from __future__ import annotations

import html
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse

from .api import CatalogueAPI
from .broker import BrokerError, ConsumerContext, DeliveryMode, ResourceBroker, ResolutionState
from .errors import PolicyError, RabError
from .bootstrap import BootstrapStore
from .identity import IdentityCatalogue
from .products import ProductBuilder


CSS = """body { font-family: Arial, Helvetica, sans-serif; margin: 1em; max-width: 60em; color: #111; background: #fff; }
h1 { border-bottom: 2px solid #333; padding-bottom: .2em; }
h2 { margin-top: 1.4em; }
a { color: #003399; }
label { display: inline-block; margin: .25em .5em .25em 0; }
input, select { margin-left: .2em; }
table { border-collapse: collapse; margin: 1em 0; max-width: 100%; }
th, td { border: 1px solid #888; padding: .35em; text-align: left; vertical-align: top; }
th { background: #eee; }
.notice { border: 1px solid #888; padding: .6em; }
.muted { color: #555; }
pre { white-space: pre-wrap; word-wrap: break-word; border: 1px solid #aaa; padding: .8em; overflow: auto; }
"""


def _e(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _url(path: str, **params) -> str:
    query = urlencode({key: value for key, value in params.items() if value not in (None, "")})
    return path + ("?" + query if query else "")


class WebApplication:
    """HTML facade. It owns presentation only; catalogue and broker own policy."""

    def __init__(self, archive, registry=None, *, retro_only: bool = False):
        from .broker import ConsumerRegistry
        from pathlib import Path
        self.catalogue = __import__("rab.catalogue", fromlist=["Catalogue"]).Catalogue(archive)
        self.api = CatalogueAPI(self.catalogue, registry,
                                ConsumerRegistry(Path(__file__).parents[2] / "config" / "consumers.json"))
        self.broker = ResourceBroker(archive, registry=self.api.broker.registry, read_only=True)
        self.retro_only = retro_only

    def dispatch(self, method: str, path: str):
        if method != "GET":
            return 405, "text/html; charset=utf-8", self.page("Method Not Allowed", "<p>Read-only web interface.</p>"), None
        if len(path) > 8192:
            return 414, "text/html; charset=utf-8", self.page("Request Too Large", "<p>The request is too large.</p>"), None
        parsed = urlparse(path); query = parse_qs(parsed.query); route = parsed.path.rstrip("/") or "/"
        retro = self.retro_only or route == "/retro" or route.startswith("/retro/") or query.get("view", [""])[0] == "retro"
        if route.startswith("/static/"):
            if route == "/static/rab.css" and not retro:
                return 200, "text/css; charset=utf-8", CSS, None
            return 404, "text/html; charset=utf-8", self.page("Not Found", "<p>Not found.</p>", retro=True), None
        if retro and route.startswith("/web"):
            return 404, "text/html; charset=utf-8", self.page("Not Found", "<p>Not found.</p>", retro=True), None
        route = route.removeprefix("/retro").removeprefix("/web") or "/"
        try:
            if route == "/": return self.home(retro)
            if route == "/search": return self.search(query, retro)
            if route == "/platforms": return self.platforms(retro)
            if route.startswith("/platform/"): return self.platform(unquote(route.removeprefix("/platform/")), query, retro)
            if route == "/sources": return self.sources(retro)
            if route == "/bootstrap": return self.bootstrap(retro)
            if route.startswith("/bootstrap/"): return self.bootstrap_job(unquote(route.removeprefix("/bootstrap/")), retro)
            if route.startswith("/identity/"): return self.identity(unquote(route.removeprefix("/identity/")), retro)
            if route == "/products": return self.products(retro)
            if route.startswith("/source/"): return self.source(unquote(route.removeprefix("/source/")), retro)
            if route.startswith("/resource/"): return self.resource(unquote(route.removeprefix("/resource/")), retro)
            if route.startswith("/set/"): return self.resource_set(unquote(route.removeprefix("/set/")), retro)
            if route.startswith("/readme/"): return self.readme(unquote(route.removeprefix("/readme/")), retro)
            if route.startswith("/download/"): return self.download(unquote(route.removeprefix("/download/")))
            return 404, "text/html; charset=utf-8", self.page("Not Found", "<p>The requested page was not found.</p>", retro), None
        except BrokerError as exc:
            status = 409 if exc.state == ResolutionState.AMBIGUOUS else 403 if exc.state in {ResolutionState.RIGHTS_DENIED, ResolutionState.POLICY_BLOCKED} else 404
            return status, "text/html; charset=utf-8", self.page(_e(exc.state.value), "<p>" + _e(str(exc)) + "</p>", retro), None
        except PolicyError as exc:
            return 403, "text/html; charset=utf-8", self.page("Forbidden", "<p>" + _e(str(exc)) + "</p>", retro), None
        except (RabError, ValueError, KeyError):
            return 404, "text/html; charset=utf-8", self.page("Not Found", "<p>The requested archive item was not found.</p>", retro), None
        except Exception:
            return 500, "text/html; charset=utf-8", self.page("Server Error", "<p>RAB could not complete the read-only request.</p>", retro), None

    def page(self, title: str, content: str, retro: bool = False) -> str:
        prefix = "/retro" if retro else "/web"
        style = "" if retro else '<link rel="stylesheet" type="text/css" href="/static/rab.css" />'
        nav = ('<p><a href="' + prefix + '/">Home</a> | <a href="' + prefix + '/search">Search</a> | '
               '<a href="' + prefix + '/platforms">Platforms</a> | <a href="' + prefix + '/sources">Sources</a></p>')
        return '<!DOCTYPE html><html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8" /><title>' + _e(title) + ' - RAB</title>' + style + '</head><body><h1>Retro Archive Box</h1>' + nav + '<h2>' + _e(title) + '</h2>' + content + '<hr /><p class="muted">Read-only archive view. RAB owns preserved bytes; consumers own use.</p></body></html>'

    def home(self, retro):
        stats = self.broker.stats()
        content = '<p>Preservation-first archive browser.</p><form action="' + ("/retro" if retro else "/web") + '/search" method="get"><label for="q">Search:</label><input type="text" id="q" name="q" size="32" /><input type="submit" value="Search" /></form>'
        content += '<h3>Browse</h3><ul><li><a href="' + ("/retro" if retro else "/web") + '/platforms">Platforms</a></li><li><a href="' + ("/retro" if retro else "/web") + '/sources">Sources</a></li><li><a href="' + ("/retro" if retro else "/web") + '/search">Resources</a></li><li><a href="' + ("/retro" if retro else "/web") + '/bootstrap">Bootstrap status</a></li><li><a href="' + ("/retro" if retro else "/web") + '/products">Derived products</a></li></ul>'
        content += '<p class="muted">Indexed resources: ' + _e(stats.get("resources", 0)) + '; resource sets: ' + _e(stats.get("resource_sets", 0)) + '.</p>'
        return 200, "text/html; charset=utf-8", self.page("Home", content, retro), None

    def search(self, query, retro):
        q = query.get("q", [""])[0][:256]; platform = query.get("platform", [""])[0]; source = query.get("source", [""])[0]
        try:
            limit = min(max(int(query.get("limit", [25])[0]), 1), 50); offset = max(int(query.get("offset", [0])[0]), 0)
        except ValueError: raise BrokerError(ResolutionState.POLICY_BLOCKED, "invalid pagination")
        result = self.catalogue.search(q, platform=platform or None, source=source or None, limit=limit, offset=offset, read_only=True)
        rows = []
        for item in result.get("results", []):
            rid = item.get("package_id") or item.get("object_id")
            if not rid: continue
            try: rows.append(self.broker.show(rid))
            except RabError: continue
        prefix = "/retro" if retro else "/web"; content = '<form action="' + prefix + '/search" method="get"><label for="q">Search:</label><input type="text" id="q" name="q" value="' + _e(q) + '" size="32" /><label>Platform:<input type="text" name="platform" value="' + _e(platform) + '" /></label><label>Source:<input type="text" name="source" value="' + _e(source) + '" /></label><input type="submit" value="Search" /></form>'
        if not rows: content += '<p>No matching resources.</p>'
        else:
            content += '<table><tr><th>Name</th><th>Version</th><th>Platform</th><th>Kind</th><th>Availability</th><th>Rights</th></tr>'
            for item in rows:
                rid = item["resource_id"]; content += '<tr><td><a href="' + prefix + '/resource/' + quote(rid, safe="") + '">' + _e(item.get("name") or rid) + '</a></td><td>' + _e(item.get("version")) + '</td><td>' + _e(item.get("platform")) + '</td><td>' + _e(item.get("kind")) + '</td><td>' + _e(item.get("availability")) + '</td><td>' + _e(item.get("rights")) + '</td></tr>'
            content += '</table>'
        links = []
        if offset: links.append('<a href="' + _url(prefix + '/search', q=q, platform=platform, source=source, offset=max(0, offset-limit), limit=limit) + '">Previous</a>')
        if result.get("returned", 0) == limit: links.append('<a href="' + _url(prefix + '/search', q=q, platform=platform, source=source, offset=offset+limit, limit=limit) + '">Next</a>')
        if links: content += '<p>' + ' | '.join(links) + '</p>'
        return 200, "text/html; charset=utf-8", self.page("Search", content, retro), None

    def platforms(self, retro):
        with self.catalogue.archive.db() as db:
            values = [x[0] for x in db.execute("SELECT DISTINCT platform_id FROM cat_platforms ORDER BY platform_id")]
        prefix = "/retro" if retro else "/web"; content = '<ul>' + ''.join('<li><a href="' + prefix + '/platform/' + quote(x, safe="") + '">' + _e(x) + '</a></li>' for x in values) + '</ul>' if values else '<p>No platform metadata is indexed.</p>'
        return 200, "text/html; charset=utf-8", self.page("Platforms", content, retro), None

    def platform(self, value, query, retro):
        query = dict(query); query["platform"] = [value]; return self.search(query, retro)

    def sources(self, retro):
        values = self.api.registry.load().values() if self.api.registry else []
        prefix = "/retro" if retro else "/web"; content = '<ul>' + ''.join('<li><a href="' + prefix + '/source/' + quote(x.id, safe="") + '">' + _e(x.name) + '</a></li>' for x in values) + '</ul>'
        return 200, "text/html; charset=utf-8", self.page("Sources", content, retro), None

    def source(self, source_id, retro):
        source = self.api.registry.get(source_id) if self.api.registry else None; prefix = "/retro" if retro else "/web"
        content = '<p><strong>' + _e(source.name) + '</strong></p><dl><dt>Source ID</dt><dd>' + _e(source.id) + '</dd><dt>Class</dt><dd>' + _e(source.source_class.value) + '</dd><dt>Platforms</dt><dd>' + _e(', '.join(source.platforms)) + '</dd></dl><h3>Acquisition transports</h3><ul>' + ''.join('<li>' + _e(x["transport"]) + ': ' + _e(x["endpoint"]) + '</li>' for x in source.endpoints) + '</ul><p><a href="' + _url(prefix + '/search', source=source.id) + '">Browse this source</a></p>'
        return 200, "text/html; charset=utf-8", self.page("Source", content, retro), None

    def bootstrap(self, retro):
        jobs = BootstrapStore(self.catalogue.archive, read_only=True).list(); prefix = "/retro" if retro else "/web"
        content = '<p>Read-only bootstrap status.</p><ul>' + ''.join('<li><a href="' + prefix + '/bootstrap/' + quote(x["job_id"], safe="") + '">' + _e(x["job_id"]) + '</a>: ' + _e(x.get("state")) + ' (' + _e(x.get("source")) + ')</li>' for x in jobs) + '</ul>' if jobs else '<p>No bootstrap jobs recorded.</p>'
        return 200, "text/html; charset=utf-8", self.page("Bootstrap Jobs", content, retro), None

    def bootstrap_job(self, job_id, retro):
        job = BootstrapStore(self.catalogue.archive, read_only=True).read(job_id); prefix = "/retro" if retro else "/web"
        content = '<dl><dt>Job</dt><dd><code>' + _e(job["job_id"]) + '</code></dd><dt>Source</dt><dd>' + _e(job["source"]) + '</dd><dt>State</dt><dd>' + _e(job["state"]) + '</dd><dt>Transport</dt><dd>' + _e((job.get("plan", {}).get("selected") or {}).get("transport")) + '</dd><dt>Bytes</dt><dd>' + _e(job.get("bytes_transferred", 0)) + '</dd></dl><h3>Progress</h3><p>Completed: ' + _e(len(job.get("completed_items", []))) + '; deduplicated: ' + _e(len(job.get("skipped_items", []))) + '; failed: ' + _e(len(job.get("failed_items", []))) + '</p><p><a href="' + prefix + '/bootstrap">All bootstrap jobs</a></p>'
        return 200, "text/html; charset=utf-8", self.page("Bootstrap Job", content, retro), None

    def identity(self, identifier, retro):
        value = IdentityCatalogue(self.catalogue.archive, read_only=True).show(identifier); prefix = "/retro" if retro else "/web"
        hashes = '<br />'.join(_e(key + ": " + str(value[key])) for key in ("crc32", "md5", "sha1", "sha256", "blake3"))
        content = '<dl><dt>Object</dt><dd><code>' + _e(value["object_id"]) + '</code></dd><dt>Size</dt><dd>' + _e(value["size"]) + '</dd><dt>Format</dt><dd>' + _e(value["format_id"]) + '</dd><dt>Platform family</dt><dd>' + _e(value["platform_family"]) + '</dd><dt>Platform</dt><dd>' + _e(value["platform"]) + '</dd><dt>Hashes</dt><dd><code>' + hashes + '</code></dd></dl><h3>Relationships</h3><ul>' + ''.join('<li>' + _e(x["relationship"]) + ': ' + _e(x["object_id"]) + '</li>' for x in value["relationships"]) + '</ul><p><a href="' + prefix + '/resource/' + quote(value["object_id"], safe="") + '">Resource view</a></p>'
        return 200, "text/html; charset=utf-8", self.page("Universal Identity", content, retro), None

    def products(self, retro):
        values = ProductBuilder(self.catalogue.archive, identity=IdentityCatalogue(self.catalogue.archive, read_only=True)).list(); prefix = "/retro" if retro else "/web"
        content = '<p>Metadata-only derived products. Payload rights are unchanged.</p><ul>' + ''.join('<li>' + _e(x["product"]) + ': ' + _e(x["record_count"]) + ' records (' + _e(x["path_id"]) + ')</li>' for x in values) + '</ul>'
        return 200, "text/html; charset=utf-8", self.page("Derived Products", content, retro), None

    def resource(self, resource_id, retro):
        item = self.broker.show(resource_id); prefix = "/retro" if retro else "/web"; analysis = item.get("malware_analysis", {}); content = '<dl><dt>Resource ID</dt><dd><code>' + _e(item["resource_id"]) + '</code></dd><dt>Name</dt><dd>' + _e(item.get("name")) + '</dd><dt>Version</dt><dd>' + _e(item.get("version")) + '</dd><dt>Kind</dt><dd>' + _e(item.get("kind")) + '</dd><dt>Platform</dt><dd>' + _e(item.get("platform")) + '</dd><dt>Availability</dt><dd>' + _e(item.get("availability")) + '</dd><dt>Rights</dt><dd>' + _e(item.get("rights")) + '</dd><dt>Malware analysis</dt><dd>' + _e(analysis.get("status", "NOT_SCANNED")) + '</dd></dl>'
        if analysis.get("observations"):
            content += '<h3>Malware observations</h3><table><tr><th>Scanner</th><th>Result</th><th>Scanned</th><th>Detections</th></tr>'
            for observation in analysis["observations"]:
                detections = ', '.join(_e(x.get("name")) for x in observation.get("detections", [])) or '-'
                content += '<tr><td>' + _e(observation.get("scanner_id")) + '</td><td>' + _e(observation.get("result")) + '</td><td>' + _e(observation.get("scanned_at")) + '</td><td>' + detections + '</td></tr>'
            content += '</table>'
        content += '<h3>Objects</h3><table><tr><th>Role</th><th>Identity</th><th>Size</th><th>Hashes</th><th>Action</th></tr>'
        for obj in item.get("objects", []):
            oid = obj.get("sha256", ""); hashes = '<br />'.join(_e(k + ": " + str(v)) for k, v in obj.get("hashes", {}).items()); actions = ''
            if obj.get("available") and item.get("rights") == "REDISTRIBUTABLE":
                actions = '<a href="' + prefix + '/download/' + quote(oid, safe="") + '">Download</a>'
                if obj.get("role") == "readme": actions += ' | <a href="' + prefix + '/readme/' + quote(oid, safe="") + '">View text</a>'
            elif obj.get("available"):
                actions = '<span class="muted">Preserved locally; redistribution denied</span>'
            content += '<tr><td>' + _e(obj.get("role")) + '</td><td><code>' + _e(oid) + '</code></td><td>' + _e(obj.get("size")) + '</td><td><small>' + hashes + '</small></td><td>' + actions + '</td></tr>'
        content += '</table>'
        if IdentityCatalogue(self.catalogue.archive, read_only=True).db_path.is_file():
            content += '<h3>Universal identity</h3><ul>'
            for obj in item.get("objects", []):
                try:
                    identity = IdentityCatalogue(self.catalogue.archive, read_only=True).show(obj["sha256"])
                    content += '<li><a href="' + prefix + '/identity/' + quote(obj["sha256"], safe="") + '">' + _e(obj["sha256"]) + '</a>: ' + _e(identity.get("format_id")) + ' / ' + _e(identity.get("platform_family")) + '</li>'
                except RabError:
                    continue
            content += '</ul>'
        if item.get("provenance") or item.get("metadata", {}).get("source_path"):
            content += '<h3>Provenance</h3><p>' + _e(item.get("metadata", {}).get("source_path")) + '</p>'
        if item.get("authority_assertions"):
            content += '<h3>Authority evidence</h3><ul>' + ''.join('<li>' + _e((x.get("authority") or x.get("authority_id")) + " / " + x.get("result", "") + " / " + x.get("release_identity", x.get("release", ""))) + '</li>' for x in item["authority_assertions"]) + '</ul>'
        if item.get("dependencies"): content += '<h3>Dependencies</h3><ul>' + ''.join('<li><a href="' + prefix + '/resource/' + quote(x, safe="") + '">' + _e(x) + '</a></li>' for x in item["dependencies"]) + '</ul>'
        return 200, "text/html; charset=utf-8", self.page("Resource", content, retro), None

    def resource_set(self, set_id, retro):
        value = self.broker.show_set(set_id); prefix = "/retro" if retro else "/web"; content = '<dl><dt>Set ID</dt><dd><code>' + _e(value["resource_id"]) + '</code></dd><dt>Generation</dt><dd>' + _e(value["generation"]) + '</dd></dl><h3>Members</h3><table><tr><th>Role</th><th>Resource</th><th>Availability</th><th>Rights</th></tr>'
        for relation, item in zip(value["contents"], value["resolved_contents"]): content += '<tr><td>' + _e(relation.get("role")) + '</td><td><a href="' + prefix + '/resource/' + quote(item["resource_id"], safe="") + '">' + _e(item.get("name") or item["resource_id"]) + '</a></td><td>' + _e(item.get("availability")) + '</td><td>' + _e(item.get("rights")) + '</td></tr>'
        content += '</table>'; return 200, "text/html; charset=utf-8", self.page("Resource Set", content, retro), None

    def readme(self, identifier, retro):
        resolved = self.broker.resolve(identifier, context=ConsumerContext(delivery_mode=DeliveryMode.STREAM, rights_context="public"))
        if resolved["resolution"]["delivery"]["state"] != "RESOLVED_AND_DELIVERABLE":
            raise BrokerError(ResolutionState.RIGHTS_DENIED, "This text is preserved locally but cannot be redistributed.")
        text = self.api.read_object_text(identifier); return 200, "text/html; charset=utf-8", self.page("Text View", '<p>Historical text is displayed as data; it is not interpreted as HTML.</p><pre>' + _e(text) + '</pre><p><a href="' + ("/retro" if retro else "/web") + '/download/' + quote(identifier, safe="") + '">Download original bytes</a></p>', retro), None

    def download(self, identifier):
        resolved = self.broker.resolve(identifier, context=ConsumerContext(delivery_mode=DeliveryMode.STREAM, rights_context="public"))
        if resolved["resolution"]["delivery"]["state"] != "RESOLVED_AND_DELIVERABLE": raise BrokerError(ResolutionState.RIGHTS_DENIED, "This resource is preserved locally but cannot be redistributed.")
        item = self.api.download_object(identifier, public=True)
        return 200, "application/octet-stream", None, item


def run_web_server(archive, registry, host="127.0.0.1", port=8080, *, retro_only=False):
    build_web_server(archive, registry, host, port, retro_only=retro_only).serve_forever()


def build_web_server(archive, registry, host="127.0.0.1", port=8080, *, retro_only=False):
    app = WebApplication(archive, registry, retro_only=retro_only)
    app.catalogue.validate_readonly()
    app.broker.initialize()
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            try:
                status, content_type, body, download = app.dispatch("GET", self.path)
                if download:
                    self._send_file(download); return
                data = (body or "").encode("utf-8"); self.send_response(status); self.send_header("Content-Type", content_type); self.send_header("X-Content-Type-Options", "nosniff"); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
            except OSError:
                self.send_error(404, "not found")
        def do_POST(self):  # noqa: N802
            self.send_error(405, "read-only interface")
        def _send_file(self, download):
            size = download["size"]; start, end = 0, size - 1; value = self.headers.get("Range")
            if value:
                match = re.fullmatch(r"bytes=(\d*)-(\d*)", value)
                if not match: self.send_error(416, "invalid range"); return
                start = int(match.group(1) or 0); end = int(match.group(2) or end)
                if start > end or start >= size: self.send_error(416, "range unsatisfiable"); return
                end = min(end, size - 1); self.send_response(206); self.send_header("Content-Range", "bytes %d-%d/%d" % (start, end, size))
            else: self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream"); self.send_header("Content-Disposition", 'attachment; filename="' + re.sub(r"[^A-Za-z0-9._-]", "_", download["filename"]) + '"'); self.send_header("Content-Length", str(end - start + 1)); self.end_headers()
            with open(download["path"], "rb") as handle:
                handle.seek(start); remaining = end - start + 1
                while remaining:
                    chunk = handle.read(min(1024 * 1024, remaining))
                    if not chunk: break
                    self.wfile.write(chunk); remaining -= len(chunk)
        def log_message(self, *_): return
    return ThreadingHTTPServer((host, port), Handler)
