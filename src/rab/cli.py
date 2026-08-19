from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .errors import RabError
from .model import IngestRequest, Rights
from .acquisition import Acquisition, preserve_torrent
from .sources import SourceRegistry
from .store import Archive
from .catalogue import Catalogue
from .api import run_server
from .authority import Authority
from .redump import RedumpAuthority
from .additional_authorities import AdditionalAuthority
from .broker import ConsumerContext, ConsumerRegistry, DeliveryMode, ResourceBroker, ResourceKind
from .web import run_web_server
from .malware import MalwareStore
from .transports import AcquisitionPurpose, TransportResolver


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rab", description="Retro Archive Box")
    p.add_argument("--root", type=Path, default=Path(os.environ.get("RAB_ROOT", "/var/lib/rab")))
    p.add_argument("--sources", type=Path, default=Path(os.environ.get(
        "RAB_SOURCES", Path(__file__).parents[2] / "config" / "sources")))
    sub = p.add_subparsers(dest="command", required=True)

    ingest = sub.add_parser("ingest", help="ingest an immutable object")
    ingest.add_argument("path", type=Path)
    ingest.add_argument("--source", required=True)
    ingest.add_argument("--source-path", required=True)
    ingest.add_argument("--rights", required=True, choices=[x.value for x in Rights])
    ingest.add_argument("--media-type", required=True)
    ingest.add_argument("--title")
    ingest.add_argument("--derived-from")

    search = sub.add_parser("search")
    search.add_argument("query")
    search.add_argument("--platform")
    search.add_argument("--source")
    search.add_argument("--format", dest="format_id")
    search.add_argument("--rights")
    search.add_argument("--authority")
    search.add_argument("--tosec-match", action="store_true")
    search.add_argument("--limit", type=int, default=25)
    search.add_argument("--offset", type=int, default=0)
    search.add_argument("--json", action="store_true")
    show = sub.add_parser("show")
    show.add_argument("object")
    show.add_argument("--json", action="store_true")
    verify = sub.add_parser("verify")
    verify.add_argument("object")
    export = sub.add_parser("export")
    export.add_argument("object")
    export.add_argument("--preset", choices=["original"], default="original")
    export.add_argument("--output", type=Path, required=True)
    audit = sub.add_parser("audit")
    audit.add_argument("--fixity", action="store_true")
    sub.add_parser("doctor")
    source = sub.add_parser("source", help="inspect and operate configured sources")
    source_sub = source.add_subparsers(dest="source_command", required=True)
    source_sub.add_parser("list")
    source_show = source_sub.add_parser("show")
    source_show.add_argument("source_id")
    source_sub.add_parser("validate")
    source_status = source_sub.add_parser("status")
    source_status.add_argument("source_id")
    source_plan = source_sub.add_parser("plan")
    source_plan.add_argument("source_id")
    source_plan.add_argument("--scope")
    source_plan.add_argument("--path", action="append", dest="paths")
    source_sync = source_sub.add_parser("sync")
    source_sync.add_argument("source_id")
    source_sync.add_argument("--directory", type=Path)
    source_sync.add_argument("--scope")
    source_sync.add_argument("--path", action="append", dest="paths")
    source_sync.add_argument("--dry-run", action="store_true")
    torrent = sub.add_parser("torrent", help="preserve BitTorrent metadata")
    torrent_sub = torrent.add_subparsers(dest="torrent_command", required=True)
    torrent_import = torrent_sub.add_parser("import")
    torrent_import.add_argument("path", type=Path)
    torrent_import.add_argument("--source", required=True)
    torrent_import.add_argument("--source-path", required=True)
    torrent_import.add_argument("--download", action="store_true")
    get = sub.add_parser("get", help="export a logical package")
    get.add_argument("package")
    get.add_argument("--output", type=Path, required=True)
    get.add_argument("--with-readme", action="store_true")
    catalogue = sub.add_parser("catalogue")
    catalogue_sub = catalogue.add_subparsers(dest="catalogue_command", required=True)
    catalogue_sub.add_parser("rebuild")
    catalogue_sub.add_parser("status")
    catalogue_sub.add_parser("verify")
    authority = sub.add_parser("authority", help="inspect external authority datasets and assertions")
    authority_sub = authority.add_subparsers(dest="authority_command", required=True)
    authority_sub.add_parser("list")
    authority_show = authority_sub.add_parser("show")
    authority_show.add_argument("dataset")
    authority_import = authority_sub.add_parser("import")
    authority_import.add_argument("path", type=Path)
    authority_import.add_argument("--release")
    authority_import.add_argument("--source")
    authority_import.add_argument("--member", action="append", dest="members")
    authority_import.add_argument("--release-version")
    authority_import.add_argument("--release-date")
    authority_sub.add_parser("rebuild")
    authority_sub.add_parser("verify")
    authority_match = authority_sub.add_parser("match")
    authority_match.add_argument("object")
    authority_match.add_argument("--dataset")
    authority_assertions = authority_sub.add_parser("assertions")
    authority_assertions.add_argument("object")
    redump = authority_sub.add_parser("redump")
    redump_sub = redump.add_subparsers(dest="redump_command", required=True)
    redump_import = redump_sub.add_parser("import")
    redump_import.add_argument("dat", type=Path)
    redump_import.add_argument("cues", type=Path)
    redump_import.add_argument("--release", required=True)
    redump_import.add_argument("--dat-source", required=True)
    redump_import.add_argument("--cues-source", required=True)
    redump_disc = redump_sub.add_parser("disc")
    redump_disc.add_argument("disc_id")
    redump_tracks = redump_sub.add_parser("tracks")
    redump_tracks.add_argument("disc_id")
    for authority_name in ("nointro", "mame"):
        additional = authority_sub.add_parser(authority_name)
        additional_sub = additional.add_subparsers(dest="additional_command", required=True)
        additional_import = additional_sub.add_parser("import")
        additional_import.add_argument("path", type=Path)
        additional_import.add_argument("--release", required=True)
        additional_import.add_argument("--source", required=True)
        additional_records = additional_sub.add_parser("records")
        additional_records.add_argument("--dataset")
    api = sub.add_parser("api", help="run the read-only catalogue API")
    api.add_argument("--host", default="127.0.0.1")
    api.add_argument("--port", type=int, default=8000)
    web = sub.add_parser("web", help="run the server-rendered read-only web interface")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=8080)
    web.add_argument("--retro-only", action="store_true")
    malware = sub.add_parser("malware", help="inspect and operate malware analysis")
    malware_sub = malware.add_subparsers(dest="malware_command", required=True)
    malware_status = malware_sub.add_parser("status"); malware_status.add_argument("identifier", nargs="?")
    malware_scanners = malware_sub.add_parser("scanners")
    malware_scanner = malware_sub.add_parser("scanner"); malware_scanner.add_argument("scanner_id")
    malware_scan = malware_sub.add_parser("scan"); malware_scan.add_argument("identifier"); malware_scan.add_argument("--scanner", required=True); malware_scan.add_argument("--timeout", type=int, default=300)
    malware_observations = malware_sub.add_parser("observations"); malware_observations.add_argument("identifier", nargs="?")
    malware_show = malware_sub.add_parser("show"); malware_show.add_argument("observation_id")
    malware_sub.add_parser("verify")
    malware_sub.add_parser("rebuild")
    acquisition = sub.add_parser("acquisition", help="plan and perform policy-selected acquisition")
    acquisition_sub = acquisition.add_subparsers(dest="acquisition_command", required=True)
    acquisition_sub.add_parser("transports")
    acquisition_plan = acquisition_sub.add_parser("plan")
    acquisition_plan.add_argument("source_id"); acquisition_plan.add_argument("--purpose", choices=[x.value for x in AcquisitionPurpose], default=AcquisitionPurpose.SYNCHRONIZATION.value)
    acquisition_fetch = acquisition_sub.add_parser("fetch")
    acquisition_fetch.add_argument("source_id"); acquisition_fetch.add_argument("--purpose", choices=[x.value for x in AcquisitionPurpose], default=AcquisitionPurpose.SYNCHRONIZATION.value)
    acquisition_fetch.add_argument("--path", required=True); acquisition_fetch.add_argument("--expected-sha256"); acquisition_fetch.add_argument("--expected-size", type=int); acquisition_fetch.add_argument("--dry-run", action="store_true")
    resource = sub.add_parser("resource", help="resolve and deliver consumer resources")
    resource_sub = resource.add_subparsers(dest="resource_command", required=True)
    resource_search = resource_sub.add_parser("search")
    for name in ("platform", "ecosystem", "os", "architecture", "hardware", "kind", "name", "version", "title", "source"):
        resource_search.add_argument("--" + name)
    resource_search.add_argument("--json", action="store_true")
    resource_show = resource_sub.add_parser("show"); resource_show.add_argument("resource_id")
    resource_resolve = resource_sub.add_parser("resolve"); resource_resolve.add_argument("resource_id", nargs="?")
    for name in ("platform", "ecosystem", "os", "architecture", "hardware", "kind", "name", "version", "title", "source"):
        resource_resolve.add_argument("--" + name)
    resource_resolve.add_argument("--consumer", default="test-consumer"); resource_resolve.add_argument("--delivery-mode", choices=[x.value for x in DeliveryMode], default="MANIFEST_ONLY")
    resource_pin = resource_sub.add_parser("pin"); resource_pin.add_argument("resource_id"); resource_pin.add_argument("--consumer", default="test-consumer")
    materialize = resource_sub.add_parser("materialize"); materialize.add_argument("resource_id"); materialize.add_argument("--consumer", default="test-consumer"); materialize.add_argument("--output", type=Path)
    resource_verify = resource_sub.add_parser("verify-lock"); resource_verify.add_argument("manifest", type=Path)
    resource_verify_object = resource_sub.add_parser("verify"); resource_verify_object.add_argument("resource_id")
    resource_set = sub.add_parser("resource-set", help="inspect resource sets")
    resource_set_sub = resource_set.add_subparsers(dest="resource_set_command", required=True)
    resource_set_show = resource_set_sub.add_parser("show"); resource_set_show.add_argument("set_id")
    resource_set_resolve = resource_set_sub.add_parser("resolve"); resource_set_resolve.add_argument("set_id")
    consumer = sub.add_parser("consumer", help="inspect broker consumers")
    consumer_sub = consumer.add_subparsers(dest="consumer_command", required=True); consumer_sub.add_parser("list"); consumer_sub.add_parser("status")
    return p


def run(args: argparse.Namespace) -> dict | list:
    archive = Archive(args.root)
    registry = SourceRegistry(args.sources)
    if args.command == "ingest":
        return archive.ingest(IngestRequest(
            args.path, args.source, args.source_path, Rights(args.rights),
            args.media_type, args.title, args.derived_from,
        ))
    if args.command == "search":
        catalogue = Catalogue(archive); catalogue.rebuild()
        return catalogue.search(args.query, platform=args.platform, source=args.source,
                                format_id=args.format_id, rights=args.rights,
                                authority=args.authority, authority_match=args.tosec_match,
                                limit=args.limit, offset=args.offset)
    if args.command == "show":
        catalogue = Catalogue(archive); catalogue.rebuild()
        if ":" in args.object and not args.object.startswith("sha256:"):
            return catalogue.show_package(args.object)
        return catalogue.show_object(args.object)
    if args.command == "verify":
        return archive.verify(args.object)
    if args.command == "export":
        return archive.export_original(args.object, args.output)
    if args.command == "audit":
        return archive.audit()
    if args.command == "doctor":
        return archive.doctor()
    if args.command == "source":
        if args.source_command == "list":
            return [x.public() for x in registry.load().values()]
        if args.source_command == "show":
            return registry.get(args.source_id).public()
        if args.source_command == "validate":
            sources = registry.load()
            return {"outcome": "PASS", "sources": sorted(sources), "count": len(sources)}
        if args.source_command == "status":
            source = registry.get(args.source_id)
            Acquisition(archive)
            with archive.db() as db:
                objects = db.execute("SELECT status,count(*) count FROM source_objects WHERE source_id=? GROUP BY status", (source.id,)).fetchall()
                packages = db.execute("SELECT completeness,count(*) count FROM packages WHERE source_id=? GROUP BY completeness", (source.id,)).fetchall()
            return {"source": source.public(), "objects": [dict(x) for x in objects], "packages": [dict(x) for x in packages]}
        if args.source_command == "plan":
            return Acquisition(archive).plan_source(registry.get(args.source_id), scope=args.scope, paths=args.paths)
        if args.source_command == "sync":
            source = registry.get(args.source_id)
            acquisition = Acquisition(archive)
            if args.directory:
                return acquisition.sync_aminet(source, args.directory)
            if source.backend.value in {"http", "https"}:
                if source.companion_rules.get("required_suffix") == ".readme":
                    return acquisition.acquire_http_aminet(source, args.paths or [])
                objects = acquisition.acquire_http_paths(source, args.paths or [])
                return {"source": source.id, "objects": objects, "outcome": "PASS"}
            return acquisition.run_rsync(source, dry_run=args.dry_run, scope=args.scope)
    if args.command == "torrent":
        source = registry.get(args.source)
        acquisition = Acquisition(archive)
        if args.download:
            return acquisition.acquire_torrent(source, args.path, args.source_path)
        return preserve_torrent(acquisition, source, args.path, args.source_path)
    if args.command == "get":
        return Acquisition(archive).get_package(args.package, args.output, args.with_readme)
    if args.command == "catalogue":
        catalogue = Catalogue(archive)
        if args.catalogue_command == "rebuild":
            return catalogue.rebuild()
        if args.catalogue_command == "status":
            return catalogue.status()
        return catalogue.verify()
    if args.command == "authority":
        authority = Authority(archive)
        if args.authority_command == "redump":
            redump_authority = RedumpAuthority(archive)
            if args.redump_command == "import":
                return redump_authority.import_dataset(
                    args.dat, args.cues, release=args.release, dat_source=args.dat_source,
                    cues_source=args.cues_source,
                )
            disc = redump_authority.show_disc(args.disc_id)
            return disc if args.redump_command == "disc" else disc["tracks"]
        if args.authority_command in {"nointro", "mame"}:
            additional_authority = AdditionalAuthority(archive)
            authority_id = "NO_INTRO" if args.authority_command == "nointro" else "MAME"
            if args.additional_command == "import":
                return additional_authority.import_file(args.path, authority_id=authority_id,
                                                        release=args.release, source=args.source)
            return additional_authority.records(args.dataset, authority_id)
        if args.authority_command == "list":
            return authority.list()
        if args.authority_command == "show":
            rows = [x for x in authority.list() if x["dataset_id"].startswith(args.dataset) or x["release_identity"] == args.dataset]
            if not rows:
                raise RabError(f"authority dataset not found: {args.dataset}")
            return rows[0]
        if args.authority_command == "import":
            return authority.import_tosec(args.path, release=args.release, source=args.source, members=args.members,
                                          release_version=args.release_version, release_date=args.release_date)
        if args.authority_command == "rebuild":
            return authority.rebuild()
        if args.authority_command == "verify":
            return authority.verify()
        if args.authority_command == "match":
            return authority.match(args.object, args.dataset)
        return authority.assertions(args.object)
    if args.command == "api":
        run_server(archive, registry, args.host, args.port)
        return {"outcome": "STOPPED"}
    if args.command == "web":
        run_web_server(archive, registry, args.host, args.port, retro_only=args.retro_only)
        return {"outcome": "STOPPED"}
    if args.command == "malware":
        malware_store = MalwareStore(archive)
        if args.malware_command == "status":
            return malware_store.status(args.identifier) if args.identifier else malware_store.stats()
        if args.malware_command == "scanners":
            return malware_store.scanners_status()
        if args.malware_command == "scanner":
            return malware_store.scanner_status(args.scanner_id)
        if args.malware_command == "scan":
            return malware_store.scan(args.identifier, args.scanner, timeout=args.timeout)
        if args.malware_command == "observations":
            return malware_store.observations(args.identifier)
        if args.malware_command == "show":
            return malware_store.show(args.observation_id)
        if args.malware_command == "verify":
            return malware_store.verify()
        return malware_store.rebuild()
    if args.command == "acquisition":
        resolver = TransportResolver()
        if args.acquisition_command == "transports":
            return resolver.capabilities()
        source = registry.get(args.source_id)
        if args.acquisition_command == "plan":
            return resolver.plan(source, args.purpose)
        return resolver.fetch(Acquisition(archive), source, args.purpose, path=args.path,
                              expected_sha256=args.expected_sha256, expected_size=args.expected_size,
                              dry_run=args.dry_run)
    if args.command == "resource" or args.command == "resource-set" or args.command == "consumer":
        broker = ResourceBroker(archive, registry=ConsumerRegistry(Path(__file__).parents[2] / "config" / "consumers.json"))
        if args.command == "consumer":
            return broker.registry.list() if args.consumer_command == "list" else broker.stats()
        if args.command == "resource-set":
            return broker.show_set(args.set_id)
        if args.resource_command == "show":
            return broker.show(args.resource_id)
        if args.resource_command == "search":
            values = {name: getattr(args, name) for name in ("platform", "ecosystem", "os", "architecture", "hardware", "kind", "name", "version", "title", "source") if getattr(args, name) is not None}
            return broker.search(**values)
        if args.resource_command == "resolve":
            if args.resource_id and ":" in args.resource_id and not args.resource_id.startswith(("sha256:", "resource:")):
                broker.register_package(args.resource_id)
            values = {name: getattr(args, name) for name in ("platform", "ecosystem", "os", "architecture", "hardware", "kind", "name", "version", "title", "source") if getattr(args, name) is not None}
            return broker.resolve(args.resource_id, context=ConsumerContext(consumer_id=args.consumer, delivery_mode=DeliveryMode(args.delivery_mode)), **values)
        if args.resource_command == "pin":
            return broker.pin(args.resource_id, context=ConsumerContext(consumer_id=args.consumer))
        if args.resource_command == "materialize":
            return broker.materialize(args.resource_id, args.consumer, args.output)
        if args.resource_command == "verify":
            descriptor = broker.show(args.resource_id)
            for item in descriptor["objects"]:
                archive.verify(item["sha256"], record_event=False)
            return {"outcome": "PASS", "resource_id": args.resource_id, "objects": descriptor["preservation_objects"]}
        return broker.verify_manifest(args.manifest)
    raise AssertionError(args.command)


def main(argv: list[str] | None = None) -> int:
    try:
        result = run(parser().parse_args(argv))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if not isinstance(result, dict) or result.get("outcome") != "FAIL" else 1
    except (RabError, OSError) as exc:
        print(f"rab: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
