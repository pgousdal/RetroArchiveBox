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
from .malware import MalwareStore, aggregate
from .transports import AcquisitionPurpose, TransportResolver
from .bootstrap import BootstrapStore
from .identity import IdentityCatalogue
from .products import ProductBuilder
from .local_ingest import IngestManager, WatchedInboxManager
from .media import MediaManager, OpticalManager
from .flux import FluxManager
from .physical import PhysicalMediaOrchestrator
from .qualification import QualificationManager
from .analysis import AnalysisManager
from .tree_ingest import TreeIngestManager


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
        if route == "/api/v1/acquisition/transports":
            return 200, TransportResolver().capabilities()
        identity = IdentityCatalogue(self.catalogue.archive, read_only=True)
        if route == "/api/v1/identity/status":
            return 200, identity.status()
        if route == "/api/v1/products":
            return 200, ProductBuilder(self.catalogue.archive, identity=identity).list()
        local_ingest = IngestManager(self.catalogue.archive, read_only=True)
        if route == "/api/v1/ingest/status": return 200, local_ingest.status()
        watched_inbox = WatchedInboxManager(self.catalogue.archive, read_only=True)
        if route == "/api/v1/ingest/inboxes": return 200, [self._public_inbox(x) for x in watched_inbox.list_inboxes()]
        if route == "/api/v1/ingest/inbox/status": return 200, self._public_inbox_status(watched_inbox.status())
        if route == "/api/v1/ingest/watcher": return 200, watched_inbox.status()["watcher"]
        if route == "/api/v1/ingest/jobs": return 200, [self._public_ingest_job(x) for x in local_ingest.jobs()]
        m = re.fullmatch(r"/api/v1/ingest/jobs/([0-9a-f]+)", route)
        if m: return 200, self._public_ingest_job(local_ingest.show(m.group(1)))
        if route == "/api/v1/ingest/trees": return 200, TreeIngestManager(self.catalogue.archive).jobs()
        media = MediaManager(self.catalogue.archive)
        if route == "/api/v1/media/devices": return 200, media.devices()
        if route == "/api/v1/media/jobs": return 200, [self._public_media_job(x) for x in media.jobs()]
        m = re.fullmatch(r"/api/v1/media/jobs/([0-9a-f]+)", route)
        if m: return 200, self._public_media_job(media.show(m.group(1)))
        optical = OpticalManager(self.catalogue.archive)
        if route == "/api/v1/media/optical/devices": return 200, optical.devices()
        if route == "/api/v1/media/optical/jobs": return 200, optical.jobs()
        m = re.fullmatch(r"/api/v1/media/optical/jobs/([0-9a-f]+)", route)
        if m: return 200, optical.show(m.group(1))
        flux = FluxManager(self.catalogue.archive)
        if route == "/api/v1/media/flux/adapters": return 200, flux.adapters()
        if route == "/api/v1/media/flux/devices": return 200, flux.devices()
        if route == "/api/v1/media/flux/profiles": return 200, flux.profiles()
        if route == "/api/v1/media/flux/jobs": return 200, [self._public_flux_job(x) for x in flux.jobs()]
        m = re.fullmatch(r"/api/v1/media/flux/jobs/([0-9a-f]+)", route)
        if m: return 200, self._public_flux_job(flux.show(m.group(1)))
        physical = PhysicalMediaOrchestrator(self.catalogue.archive)
        if route == "/api/v1/media/status": return 200, {"candidates": physical.public_candidates(), "sessions": physical.public_sessions()}
        if route == "/api/v1/media/candidates": return 200, physical.public_candidates()
        if route == "/api/v1/media/sessions": return 200, physical.public_sessions()
        qualification = QualificationManager(self.catalogue.archive)
        if route == "/api/v1/qualification/status": return 200, qualification.public_status()
        if route == "/api/v1/qualification/runs": return 200, [{key: value for key, value in item.items() if key in {"qualification_id", "recorded_at", "profile", "readiness"}} for item in qualification.runs()]
        m = re.fullmatch(r"/api/v1/qualification/runs/([0-9a-f-]+)", route)
        if m: return 200, qualification.public_report(qualification.report(m.group(1)))
        analysis = AnalysisManager(self.catalogue.archive)
        if route == "/api/v1/analysis/status": return 200, analysis.status()
        if route == "/api/v1/analysis/jobs": return 200, [analysis.public_job(x) for x in analysis.jobs()]
        m = re.fullmatch(r"/api/v1/analysis/jobs/([0-9a-f]+)", route)
        if m: return 200, analysis.public_job(analysis.show(m.group(1)))
        m = re.fullmatch(r"/api/v1/analysis/objects/(.+)/relationships", route)
        if m: return 200, analysis.relationships(unquote(m.group(1)))
        if route.startswith("/api/v1/products/"):
            product_path = unquote(route.removeprefix("/api/v1/products/"))
            matches = [x for x in ProductBuilder(self.catalogue.archive, identity=identity).list() if x.get("path_id") == product_path]
            return (200, matches[0]) if matches else (404, {"error": "not_found"})
        bootstrap_store = BootstrapStore(self.catalogue.archive, read_only=True)
        if route == "/api/v1/acquisition/bootstrap/jobs":
            return 200, bootstrap_store.list()
        m = re.fullmatch(r"/api/v1/acquisition/bootstrap/jobs/([0-9a-f]+)/report", route)
        if m:
            return 200, bootstrap_store.report(m.group(1))
        m = re.fullmatch(r"/api/v1/acquisition/bootstrap/jobs/([0-9a-f]+)", route)
        if m:
            return 200, bootstrap_store.read(m.group(1))
        m = re.fullmatch(r"/api/v1/acquisition/sources/([a-z0-9-]+)", route)
        if m:
            if not self.registry: return 404, {"error": "not_found"}
            source = self.registry.get(m.group(1)); resolver = TransportResolver(torrent_client=source.torrent_client)
            return 200, {"source": source.public(), "plans": {purpose.value: resolver.plan(source, purpose) for purpose in AcquisitionPurpose}}
        m = re.fullmatch(r"/api/v1/acquisition/plan/([a-z0-9-]+)", route)
        if m:
            if not self.registry: return 404, {"error": "not_found"}
            source = self.registry.get(m.group(1)); purpose = AcquisitionPurpose(query.get("purpose", [AcquisitionPurpose.SYNCHRONIZATION.value])[0])
            return 200, TransportResolver(torrent_client=source.torrent_client).plan(source, purpose)
        if route == "/api/v1/authorities":
            return 200, Authority(self.catalogue.archive).list()
        if route == "/api/v1/consumers":
            return 200, self.broker.registry.list()
        malware = MalwareStore(self.catalogue.archive, read_only=True, extended=True)
        if route == "/api/v1/malware/status":
            return 200, malware.stats()
        if route == "/api/v1/malware/scanners":
            return 200, [malware.public_scanner_status(x) for x in malware.scanners_status()]
        if route == "/api/v1/malware/profiles": return 200, malware.scanner_profiles()
        if route == "/api/v1/malware/analysis-sets": return 200, malware.analysis_sets()
        if route == "/api/v1/malware/analysis-jobs": return 200, [malware.public_analysis_job(x) for x in malware.analysis_jobs()]
        m = re.fullmatch(r"/api/v1/malware/analysis-jobs/([0-9a-f]+)", route)
        if m:
            values = [x for x in malware.analysis_jobs() if x.get("job_id") == m.group(1)]
            return (200, malware.public_analysis_job(values[0])) if values else (404, {"error": "not_found"})
        m = re.fullmatch(r"/api/v1/malware/scanners/([a-z0-9-]+)", route)
        if m:
            return 200, malware.public_scanner_status(malware.scanner_status(m.group(1)))
        m = re.fullmatch(r"/api/v1/malware/observations/([0-9a-f]+)", route)
        if m:
            return 200, malware.public_observation(malware.show(m.group(1)))
        m = re.fullmatch(r"/api/v1/resources/(.+)/malware", route)
        if m:
            descriptor = self.broker.show(unquote(m.group(1)))
            observations = [malware.public_observation(observation) for item in descriptor.get("objects", []) for observation in malware.observations(item["sha256"])]
            return 200, {"state": aggregate(x["result"] for x in observations).value if observations else "UNKNOWN", "observations": observations, "count": len(observations)}
        if route == "/api/v1/resources":
            allowed = {"platform", "ecosystem", "os", "architecture", "hardware", "kind", "name", "version", "title", "source"}
            return 200, self.broker.search(**{k: query[k][0] for k in allowed if k in query})
        if route == "/api/v1/resources/resolve":
            request = {**body, **{k: v[0] for k, v in query.items() if v}}
            resource_id = request.pop("resource_id", None)
            context = ConsumerContext(consumer_id=request.pop("consumer_id", "test-consumer"),
                                      delivery_mode=DeliveryMode(request.pop("delivery_mode", "MANIFEST_ONLY")),
                                      rights_context=request.pop("rights_context", "local-owner"),
                                      malware_policy=request.pop("malware_policy", "allow"))
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
        m = re.fullmatch(r"/api/v1/objects/(?:sha256:)?([0-9a-f]{64})/(identity|hashes|relationships)", route)
        if m:
            identifier = "sha256:" + m.group(1)
            if m.group(2) == "identity": return 200, identity.show(identifier)
            if m.group(2) == "hashes": return 200, identity.hashes(identifier)
            return 200, identity.relationships(identifier)
        m = re.fullmatch(r"/api/v1/objects/(?:sha256:)?([0-9a-f]{64})/malware(?:/(observations))?", route)
        if m:
            identifier = "sha256:" + m.group(1)
            return 200, [malware.public_observation(x) for x in malware.observations(identifier)] if m.group(2) else {**malware.status(identifier), "observations": [malware.public_observation(x) for x in malware.status(identifier)["observations"]]}
        m = re.fullmatch(r"/api/v1/objects/(?:sha256:)?([0-9a-f]{64})/malware/compare", route)
        if m: return 200, {**malware.compare("sha256:" + m.group(1)), "observations": [malware.public_observation(x) for x in malware.compare("sha256:" + m.group(1))["observations"]]}
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

    @staticmethod
    def _public_ingest_job(job):
        value = {**job, "source_descriptor": {k: v for k, v in job.get("source_descriptor", {}).items() if k != "original_path"}}
        if job.get("inbox"):
            value["source_descriptor"] = {"category": value["source_descriptor"].get("category"), "description": "watched inbox"}
            value.pop("operator_metadata", None)
        return value

    @staticmethod
    def _public_media_job(job):
        value = {**job}
        if isinstance(value.get("capture"), dict):
            value["capture"] = {k: v for k, v in value["capture"].items() if k != "command"}
        return value

    @staticmethod
    def _public_flux_job(job):
        value = {**job}
        if isinstance(value.get("capture"), dict):
            value["capture"] = {k: v for k, v in value["capture"].items() if k not in {"command", "tool_output"}}
        if isinstance(value.get("adapter"), dict):
            value["adapter"] = {k: v for k, v in value["adapter"].items() if k != "raw_info"}
        return value

    @staticmethod
    def _public_inbox(value):
        return {key: item for key, item in value.items() if key != "path"}

    @classmethod
    def _public_inbox_status(cls, value):
        return {**value, "inboxes": [cls._public_inbox(x) for x in value.get("inboxes", [])]}

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
