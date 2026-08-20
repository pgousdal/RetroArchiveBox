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
from .local_ingest import IngestManager, WatchedInboxManager
from .media import MediaManager, OpticalManager
from .flux import FluxManager
from .physical import PhysicalMediaOrchestrator
from .qualification import QualificationManager
from .analysis import AnalysisManager
from .malware import MalwareStore
from .removable import RemovableManager
from .physical_registry import PhysicalMediaRegistry
from .tree_ingest import TreeIngestManager
from .preservation import PreservationWorkflow


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
            if route == "/ingest": return self.ingest_jobs(retro)
            if route == "/inboxes": return self.inboxes(retro)
            if route == "/media": return self.media_jobs(retro)
            if route == "/physical-media": return self.physical_media(retro)
            if route == "/preservation": return self.preservation(retro)
            if route.startswith("/preservation/"): return self.preservation_detail(unquote(route.removeprefix("/preservation/")), retro)
            if route == "/qualification": return self.qualification(retro)
            if route == "/analysis": return self.analysis(retro)
            if route.startswith("/analysis/"): return self.analysis_detail(unquote(route.removeprefix("/analysis/")), retro)
            if route == "/malware": return self.malware(retro)
            if route == "/removable": return self.removable(retro)
            if route == "/physical": return self.physical(retro)
            if route.startswith("/physical/"): return self.physical_detail(unquote(route.removeprefix("/physical/")), retro)
            if route == "/optical": return self.optical_jobs(retro)
            if route == "/flux": return self.flux_jobs(retro)
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
        content += '<h3>Browse</h3><ul><li><a href="' + ("/retro" if retro else "/web") + '/preservation">Preservation workflows</a></li><li><a href="' + ("/retro" if retro else "/web") + '/platforms">Platforms</a></li><li><a href="' + ("/retro" if retro else "/web") + '/sources">Sources</a></li><li><a href="' + ("/retro" if retro else "/web") + '/search">Resources</a></li><li><a href="' + ("/retro" if retro else "/web") + '/bootstrap">Bootstrap status</a></li><li><a href="' + ("/retro" if retro else "/web") + '/ingest">Local ingest</a></li><li><a href="' + ("/retro" if retro else "/web") + '/media">Media captures</a></li><li><a href="' + ("/retro" if retro else "/web") + '/removable">Removable media</a></li><li><a href="' + ("/retro" if retro else "/web") + '/physical-media">Unified physical media</a></li><li><a href="' + ("/retro" if retro else "/web") + '/qualification">Qualification</a></li><li><a href="' + ("/retro" if retro else "/web") + '/analysis">Contained analysis</a></li><li><a href="' + ("/retro" if retro else "/web") + '/malware">Malware evidence</a></li><li><a href="' + ("/retro" if retro else "/web") + '/optical">Optical captures</a></li><li><a href="' + ("/retro" if retro else "/web") + '/flux">Flux captures</a></li><li><a href="' + ("/retro" if retro else "/web") + '/products">Derived products</a></li></ul>'
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

    def ingest_jobs(self, retro):
        jobs = IngestManager(self.catalogue.archive, read_only=True).jobs(); trees = TreeIngestManager(self.catalogue.archive).jobs(); prefix = "/retro" if retro else "/web"
        watch = WatchedInboxManager(self.catalogue.archive, read_only=True).status()
        content = '<p>Read-only local ingest status. Watcher state: ' + _e(watch.get("watcher", {}).get("last_scan", "NOT_RUNNING")) + '.</p><p><a href="' + prefix + '/inboxes">Configured inboxes and pending files</a></p><ul>' + ''.join('<li>' + _e(x["job_id"]) + ': ' + _e(x.get("state")) + ' / ' + _e(x.get("provenance_classification")) + ' / ' + _e(x.get("object_id")) + '</li>' for x in jobs) + '</ul>' if jobs else '<p>No local file ingest jobs recorded.</p>'
        if trees: content += '<h3>Tree ingest</h3><ul>' + ''.join('<li>' + _e(x["job_id"]) + ': ' + _e(x.get("state")) + ' / ' + _e(x.get("manifest_sha256")) + '</li>' for x in trees) + '</ul>'
        return 200, "text/html; charset=utf-8", self.page("Local Ingest", content, retro), None

    def inboxes(self, retro):
        value = WatchedInboxManager(self.catalogue.archive, read_only=True).status(); prefix = "/retro" if retro else "/web"
        content = '<p>Read-only watched inbox status. Source files remain in place by default.</p><p>Last scan: ' + _e(value.get("watcher", {}).get("last_scan", "NOT_RUN")) + '</p><table><tr><th>Inbox</th><th>Enabled</th><th>Provenance</th><th>Rights</th><th>Recursive</th><th>Path</th></tr>'
        for item in value.get("inboxes", []): content += '<tr><td>' + _e(item.get("inbox_id")) + '</td><td>' + _e(item.get("enabled")) + '</td><td>' + _e(item.get("provenance")) + '</td><td>' + _e(item.get("rights")) + '</td><td>' + _e(item.get("recursive")) + '</td><td>' + _e(item.get("inbox_id")) + '</td></tr>'
        content += '</table><h3>File states</h3><ul>' + ''.join('<li>' + _e(item.get("logical_path")) + ': ' + _e(item.get("status")) + (' / ' + _e(item.get("object_id")) if item.get("object_id") else '') + (' / ' + _e(item.get("error")) if item.get("error") else '') + '</li>' for item in value.get("file_states", [])) + '</ul><h3>Summary</h3><ul>' + ''.join('<li>' + _e(key) + ': ' + _e(item) + '</li>' for key, item in value.get("states", {}).items()) + '</ul>'
        return 200, "text/html; charset=utf-8", self.page("Watched Inboxes", content, retro), None

    def media_jobs(self, retro):
        jobs = MediaManager(self.catalogue.archive).jobs(); content = '<p>Read-only physical capture status.</p><ul>' + ''.join('<li>' + _e(x["job_id"]) + ': ' + _e(x.get("state")) + ' / ' + _e(x.get("object_id")) + '</li>' for x in jobs) + '</ul>' if jobs else '<p>No media capture jobs recorded.</p>'
        return 200, "text/html; charset=utf-8", self.page("Media Captures", content, retro), None

    def physical_media(self, retro):
        manager = PhysicalMediaOrchestrator(self.catalogue.archive); candidates = manager.public_candidates(); sessions = manager.public_sessions(); content = '<p>Read-only physical-media discovery. Capture remains operator-local and always requires confirmation.</p><h3>Candidates</h3><table><tr><th>ID</th><th>Type</th><th>Available</th><th>Present</th><th>Safety</th><th>Action</th></tr>'
        content += ''.join('<tr><td>' + _e(x.get("candidate_id")) + '</td><td>' + _e(x.get("kind")) + '</td><td>' + _e(x.get("available")) + '</td><td>' + _e(x.get("medium_present")) + '</td><td>' + _e(x.get("safety")) + '</td><td>' + _e(x.get("suggested_action")) + '</td></tr>' for x in candidates) + '</table><h3>Sessions</h3><ul>'
        content += ''.join('<li>' + _e(x.get("session_id")) + ': ' + _e(x.get("state")) + ' / ' + _e(x.get("successful_captures")) + ' preserved / warnings ' + _e(x.get("warnings_count")) + ' / failures ' + _e(x.get("failures_count")) + '</li>' for x in sessions) or '<li>No physical ingest sessions recorded.</li>'
        content += '</ul>'
        return 200, "text/html; charset=utf-8", self.page("Unified Physical Media", content, retro), None

    def qualification(self, retro):
        value = QualificationManager(self.catalogue.archive).public_status(); checks = value.get("check_states", {}); prefix = "/retro" if retro else "/web"
        content = '<p>Read-only qualification evidence. Implemented is not physically qualified.</p><p>Readiness: <strong>' + _e(value.get("readiness", {}).get("level")) + '</strong> / profile ' + _e(value.get("readiness", {}).get("profile")) + '</p><p>Runs recorded: ' + _e(value.get("runs")) + '; latest: ' + _e(value.get("latest")) + '</p><h3>Backup/replica</h3><p>' + _e(value.get("backup", {}).get("state")) + ': ' + _e(value.get("backup", {}).get("limitations")) + '</p><h3>Checks</h3><ul>' + ''.join('<li>' + _e(item) + ': ' + _e(state) + '</li>' for item, state in checks.items()) + '</ul>'
        return 200, "text/html; charset=utf-8", self.page("Qualification", content, retro), None

    def analysis(self, retro):
        value = AnalysisManager(self.catalogue.archive); status = value.status(); jobs = value.jobs(); content = '<p>Read-only contained-object analysis. Containers remain preservation masters; analysis is bounded and policy-controlled.</p><p>Jobs: ' + _e(status.get("jobs")) + '; completed: ' + _e(status.get("completed")) + '; warnings/limits: ' + _e(status.get("warnings")) + '</p><table><tr><th>Job</th><th>Root</th><th>Policy</th><th>State</th><th>Discovered</th><th>Materialized</th><th>Limits</th></tr>'
        prefix = "/retro" if retro else "/web"; content += ''.join('<tr><td><a href="' + prefix + '/analysis/' + _e(x.get("job_id")) + '">' + _e(x.get("job_id")) + '</a></td><td><code>' + _e(x.get("root_object")) + '</code></td><td>' + _e(x.get("policy")) + '</td><td>' + _e(x.get("state")) + '</td><td>' + _e(len(x.get("discovered", []))) + '</td><td>' + _e(x.get("materialized_count", 0)) + '</td><td>' + _e(x.get("limits_reached", [])) + '</td></tr>' for x in jobs) + '</table><h3>Capabilities</h3><ul>' + ''.join('<li>' + _e(x.get("analyzer_id")) + ' ' + _e(x.get("version")) + ': ' + _e(x.get("capability")) + ' / ' + _e("available" if x.get("available") else "tool missing") + '</li>' for x in value.capabilities()) + '</ul>'
        return 200, "text/html; charset=utf-8", self.page("Contained Analysis", content, retro), None

    def analysis_detail(self, job_id, retro):
        manager = AnalysisManager(self.catalogue.archive); job = manager.public_job(manager.show(job_id)); content = '<p>State: <strong>' + _e(job.get("state")) + '</strong>; root: <code>' + _e(job.get("root_object")) + '</code></p><h3>Contained-object tree</h3><ul>'
        content += ''.join('<li>' + _e(x.get("logical_path")) + ' — ' + _e(x.get("representation")) + ' — <code>' + _e(x.get("object_id") or x.get("hashes", {}).get("sha256")) + '</code> — ' + _e(x.get("status")) + '</li>' for x in job.get("discovered", [])) or '<li>No contained objects.</li>'
        content += '</ul><h3>Format observations</h3><ul>' + ''.join('<li>' + _e(x.get("analyzer_id")) + ' ' + _e(x.get("version")) + '</li>' for x in job.get("analyzers", [])) + '</ul><p>Warnings: ' + _e(job.get("warnings_count")) + '; errors: ' + _e(job.get("error_count")) + '; limits: ' + _e(job.get("limits_reached", [])) + '</p>'
        return 200, "text/html; charset=utf-8", self.page("Analysis " + job_id, content, retro), None

    def malware(self, retro):
        store = MalwareStore(self.catalogue.archive, read_only=True, extended=True); observations = [store.public_observation(x) for x in store.observations()]; content = '<p>Malware results are timestamped observations, not preservation truth. NOT_DETECTED is not CLEAN.</p><table><tr><th>Object</th><th>Scanner</th><th>Class</th><th>Definitions</th><th>Coverage</th><th>Result</th><th>Detections</th></tr>'
        content += ''.join('<tr><td><code>' + _e(x.get("object_sha256")) + '</code></td><td>' + _e(x.get("scanner_product", x.get("scanner_id"))) + '</td><td>' + _e(x.get("scanner_class")) + '</td><td>' + _e(x.get("definitions_identity", x.get("signature_version"))) + '</td><td>' + _e(x.get("coverage")) + '</td><td>' + _e(x.get("result")) + '</td><td>' + _e(', '.join(y.get("name", "") for y in x.get("detections", []))) + '</td></tr>' for x in observations) + '</table>'
        return 200, "text/html; charset=utf-8", self.page("Malware Evidence", content, retro), None

    def removable(self, retro):
        manager = RemovableManager(self.catalogue.archive); devices = manager.devices(); jobs = manager.jobs(); content = '<p>Read-only removable-media status. Whole-device capture is operator-local and source media must be unmounted.</p><h3>Devices</h3><table><tr><th>Type</th><th>Model</th><th>Size</th><th>Removable</th><th>Safety</th><th>Mounted children</th></tr>'
        content += ''.join('<tr><td>' + _e(x.get("transport")) + '</td><td>' + _e(x.get("model")) + '</td><td>' + _e(x.get("size")) + '</td><td>' + _e(x.get("removable")) + '</td><td>' + _e(x.get("safety")) + '</td><td>' + _e(x.get("mounted_children")) + '</td></tr>' for x in devices) + '</table><h3>Capture jobs</h3><ul>'
        content += ''.join('<li>' + _e(x.get("job_id")) + ': ' + _e(x.get("state")) + ' / ' + _e(x.get("object_id")) + ' / ' + _e(x.get("provenance_classification")) + '</li>' for x in jobs) or '<li>No removable capture jobs recorded.</li>'
        return 200, "text/html; charset=utf-8", self.page("Removable Media", content + '</ul>', retro), None

    def physical(self, retro):
        records = PhysicalMediaRegistry(self.catalogue.archive).list(); prefix = "/retro" if retro else "/web"; content = '<p>Read-only physical-medium registry. A physical object is not its capture hash.</p><table><tr><th>Physical ID</th><th>Class</th><th>Title</th><th>Provenance</th><th>Rights</th><th>Captures</th><th>Observations</th></tr>'
        registry = PhysicalMediaRegistry(self.catalogue.archive)
        content += ''.join('<tr><td><a href="' + prefix + '/physical/' + _e(x.get("physical_medium_id")) + '"><code>' + _e(x.get("physical_medium_id")) + '</code></a></td><td>' + _e(x.get("media_class")) + '</td><td>' + _e(x.get("metadata", {}).get("title")) + '</td><td>' + _e(x.get("provenance")) + '</td><td>' + _e(x.get("rights")) + '</td><td>' + _e(len(registry.captures(x["physical_medium_id"]))) + '</td><td>' + _e(len(registry.observations(x["physical_medium_id"]))) + '</td></tr>' for x in records) + '</table>'
        return 200, "text/html; charset=utf-8", self.page("Physical Media Registry", content, retro), None

    def preservation(self, retro):
        manager = PreservationWorkflow(self.catalogue.archive); prefix = "/retro" if retro else "/web"
        runs = manager.list(); review = manager.review(); progress = manager.progress()
        content = '<p>Read-only end-to-end preservation status. Device control remains operator-local.</p><p>Registered: ' + _e(progress.get("registered")) + '; preserved: ' + _e(progress.get("preserved")) + '; needs review: ' + _e(progress.get("needs_review")) + '</p><table><tr><th>Run</th><th>Medium</th><th>Profile</th><th>State</th><th>Masters</th><th>Warnings</th></tr>'
        content += ''.join('<tr><td><a href="' + prefix + '/preservation/' + _e(x.get("run_id")) + '">' + _e(x.get("run_id")) + '</a></td><td><code>' + _e(x.get("physical_medium_id")) + '</code></td><td>' + _e(x.get("profile")) + '</td><td>' + _e(x.get("state")) + '</td><td>' + _e(len(x.get("preservation_objects", []))) + '</td><td>' + _e(len(x.get("warnings", []))) + '</td></tr>' for x in runs) + '</table><h3>Needs review</h3><ul>' + (''.join('<li>' + _e(x.get("run_id")) + ': ' + _e(x.get("review_reasons")) + '</li>' for x in review) or '<li>No runs need review.</li>') + '</ul>'
        return 200, "text/html; charset=utf-8", self.page("Preservation", content, retro), None

    def preservation_detail(self, run_id, retro):
        manager = PreservationWorkflow(self.catalogue.archive); run = manager.public(manager.show(run_id)); report = manager.public_report(manager.report(run_id)); events = manager.events(run_id)
        content = '<dl><dt>Run</dt><dd><code>' + _e(run_id) + '</code></dd><dt>State</dt><dd>' + _e(run.get("state")) + '</dd><dt>Physical medium</dt><dd><code>' + _e(run.get("physical_medium_id")) + '</code></dd><dt>Profile</dt><dd>' + _e(run.get("profile")) + '</dd><dt>Capture strategy</dt><dd>' + _e(report.get("capture_strategy")) + '</dd><dt>Repeatability</dt><dd>' + _e(report.get("repeatability")) + '</dd><dt>Contained objects</dt><dd>' + _e(report.get("contained_objects")) + '</dd><dt>Rights</dt><dd>' + _e(report.get("rights")) + '</dd></dl><h3>Timeline</h3><ol>'
        content += ''.join('<li>' + _e(x.get("recorded_at")) + ' — ' + _e(x.get("event_type")) + ' (' + _e(x.get("outcome")) + ')</li>' for x in events) + '</ol><h3>Preservation objects</h3><ul>' + ''.join('<li><code>' + _e(x) + '</code></li>' for x in report.get("preservation_objects", [])) + '</ul><h3>Warnings</h3><ul>' + (''.join('<li>' + _e(x) + '</li>' for x in report.get("warnings", [])) or '<li>None.</li>') + '</ul>'
        return 200, "text/html; charset=utf-8", self.page("Preservation Run", content, retro), None

    def physical_detail(self, media_id, retro):
        registry = PhysicalMediaRegistry(self.catalogue.archive); record = registry.public(registry.show(media_id)); captures = [registry.public_capture(x) for x in registry.captures(media_id)]; observations = registry.observations(media_id); evidence = registry.public_evidence(media_id)
        metadata = record.get("metadata", {}); membership = record.get("set", {}); content = '<p><code>' + _e(media_id) + '</code></p><h3>Description</h3><dl><dt>Class</dt><dd>' + _e(record.get("media_class")) + '</dd><dt>Title</dt><dd>' + _e(metadata.get("title")) + '</dd><dt>Platform</dt><dd>' + _e(metadata.get("platform")) + '</dd><dt>Provenance</dt><dd>' + _e(record.get("provenance")) + '</dd><dt>Rights</dt><dd>' + _e(record.get("rights")) + '</dd><dt>Set</dt><dd>' + _e(membership.get("set_id")) + ' / ' + _e(membership.get("position")) + '</dd></dl><h3>Capture history</h3><ul>'
        content += ''.join('<li>' + _e(x.get("created_at")) + ': ' + _e(x.get("state")) + ' — <code>' + _e(x.get("object_id")) + '</code> (' + _e(x.get("representation_kind")) + ')</li>' for x in captures) or '<li>Never captured.</li>'
        content += '</ul><h3>Condition observations</h3><ul>' + (''.join('<li>' + _e(x.get("recorded_at")) + ': ' + _e(x.get("observation_type")) + '</li>' for x in observations) or '<li>No observations.</li>') + '</ul><h3>Public evidence</h3><ul>' + (''.join('<li>' + _e(x.get("evidence_type")) + ': <code>' + _e(x.get("object_id")) + '</code></li>' for x in evidence) or '<li>No public evidence.</li>') + '</ul>'
        return 200, "text/html; charset=utf-8", self.page(metadata.get("title") or media_id, content, retro), None

    def optical_jobs(self, retro):
        jobs = OpticalManager(self.catalogue.archive).jobs(); content = '<p>Read-only optical capture status.</p><ul>' + ''.join('<li>' + _e(x["job_id"]) + ': ' + _e(x.get("state")) + ' / ' + _e(x.get("object_id")) + '</li>' for x in jobs) + '</ul>' if jobs else '<p>No optical capture jobs recorded.</p>'
        return 200, "text/html; charset=utf-8", self.page("Optical Captures", content, retro), None

    def flux_jobs(self, retro):
        jobs = FluxManager(self.catalogue.archive).jobs(); prefix = "/retro" if retro else "/web"
        content = '<p>Read-only flux preservation status. Raw flux is retained as preservation evidence.</p>'
        content += '<ul>' + ''.join('<li>' + _e(x.get("job_id")) + ': ' + _e(x.get("state")) + ' / ' + _e(x.get("capture_format")) + ' / ' + _e(x.get("object_id")) + '</li>' for x in jobs) + '</ul>' if jobs else '<p>No flux capture jobs recorded.</p>'
        return 200, "text/html; charset=utf-8", self.page("Flux Captures", content, retro), None

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
