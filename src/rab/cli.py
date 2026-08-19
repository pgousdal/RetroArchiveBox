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
from .bootstrap import BootstrapOrchestrator, BootstrapStore
from .identity import IdentityCatalogue
from .products import ProductBuilder
from .local_ingest import IngestManager, ProvenanceClass, WatchedInboxManager
from .media import MediaManager, OpticalManager
from .flux import FluxManager, FloppyProfile, VerificationPolicy
from .physical import PhysicalMediaOrchestrator
from .qualification import QualificationManager, QualificationProfile, SeedPlanManager
from .analysis import AnalysisLimits, AnalysisManager
from .tree_ingest import TreeIngestManager


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
    qualify = sub.add_parser("qualify", help="run local-first host/storage/media qualification")
    qualify_sub = qualify.add_subparsers(dest="qualify_command", required=True)
    qualify_sub.add_parser("status")
    for name in ("host", "storage", "optical", "block", "flux", "inbox", "physical-media"):
        check = qualify_sub.add_parser(name); check.add_argument("--profile", choices=[x.value for x in QualificationProfile], default=QualificationProfile.LOCAL_SEED_MINIMAL.value); check.add_argument("--operator"); check.add_argument("--expected-local-seed-bytes", type=int)
    local_seed = qualify_sub.add_parser("local-seed"); local_seed.add_argument("--profile", choices=[x.value for x in QualificationProfile], default=QualificationProfile.LOCAL_SEED_MINIMAL.value); local_seed.add_argument("--operator"); local_seed.add_argument("--expected-local-seed-bytes", type=int)
    qualify_report = qualify_sub.add_parser("report"); qualify_report.add_argument("qualification_id")
    backup_ack = qualify_sub.add_parser("backup-ack"); backup_ack.add_argument("--replica"); backup_ack.add_argument("--last-backup"); backup_ack.add_argument("--restore-test", choices=["PASS", "FAIL", "NOT_PERFORMED"], default="NOT_PERFORMED"); backup_ack.add_argument("--operator")
    seed = sub.add_parser("seed", help="plan local-first seed material")
    seed_sub = seed.add_subparsers(dest="seed_command", required=True)
    seed_create = seed_sub.add_parser("create"); seed_create.add_argument("plan_id"); seed_create.add_argument("--collection"); seed_create.add_argument("--notes", default="")
    seed_add = seed_sub.add_parser("add"); seed_add.add_argument("plan_id"); seed_add.add_argument("--label", required=True); seed_add.add_argument("--category", required=True); seed_add.add_argument("--expected-count", type=int); seed_add.add_argument("--nominal-bytes", type=int); seed_add.add_argument("--provenance", default="unknown"); seed_add.add_argument("--notes", default="")
    seed_show = seed_sub.add_parser("show"); seed_show.add_argument("plan_id")
    seed_sub.add_parser("list")
    analyze = sub.add_parser("analyze", help="bounded non-mutating contained-object analysis")
    analyze_sub = analyze.add_subparsers(dest="analyze_command", required=True)
    analyze_sub.add_parser("status")
    analyze_jobs = analyze_sub.add_parser("jobs")
    analyze_object = analyze_sub.add_parser("object"); analyze_object.add_argument("object_id"); analyze_object.add_argument("--policy", choices=["metadata-only", "identify", "preserve", "archival"], default="metadata-only"); analyze_object.add_argument("--max-depth", type=int, default=3); analyze_object.add_argument("--max-files", type=int, default=1000); analyze_object.add_argument("--max-bytes", type=int, default=256 * 1024 * 1024); analyze_object.add_argument("--max-single-bytes", type=int, default=64 * 1024 * 1024); analyze_object.add_argument("--max-members", type=int, default=10000); analyze_object.add_argument("--max-ratio", type=int, default=1000); analyze_object.add_argument("--max-seconds", type=float, default=30.0)
    analyze_show = analyze_sub.add_parser("show"); analyze_show.add_argument("job_id")
    analyze_relationships = analyze_sub.add_parser("relationships"); analyze_relationships.add_argument("object_id")
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
    malware_profiles = malware_sub.add_parser("profiles")
    malware_scanner = malware_sub.add_parser("scanner"); malware_scanner.add_argument("scanner_id")
    malware_scan = malware_sub.add_parser("scan"); malware_scan.add_argument("identifier"); malware_scan.add_argument("--scanner", required=True); malware_scan.add_argument("--timeout", type=int, default=300)
    malware_observations = malware_sub.add_parser("observations"); malware_observations.add_argument("identifier", nargs="?")
    malware_show = malware_sub.add_parser("show"); malware_show.add_argument("observation_id")
    malware_analyze = malware_sub.add_parser("analyze"); malware_analyze.add_argument("identifier"); malware_analyze.add_argument("--profile", default="current-free"); malware_analyze.add_argument("--scanner", action="append", dest="scanner_ids"); malware_analyze.add_argument("--max-scanners", type=int, default=16); malware_analyze.add_argument("--timeout", type=int, default=300)
    malware_compare = malware_sub.add_parser("compare"); malware_compare.add_argument("identifier")
    malware_sub.add_parser("analysis-sets")
    malware_sub.add_parser("analysis-jobs")
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
    bootstrap = acquisition_sub.add_parser("bootstrap")
    bootstrap_sub = bootstrap.add_subparsers(dest="bootstrap_command", required=True)
    bootstrap_plan = bootstrap_sub.add_parser("plan"); bootstrap_plan.add_argument("source_id"); bootstrap_plan.add_argument("--path", action="append", required=True)
    bootstrap_start = bootstrap_sub.add_parser("start"); bootstrap_start.add_argument("source_id"); bootstrap_start.add_argument("--path", action="append", required=True)
    bootstrap_status = bootstrap_sub.add_parser("status"); bootstrap_status.add_argument("job_id")
    bootstrap_resume = bootstrap_sub.add_parser("resume"); bootstrap_resume.add_argument("job_id"); bootstrap_resume.add_argument("source_id")
    bootstrap_report = bootstrap_sub.add_parser("report"); bootstrap_report.add_argument("job_id")
    identity = sub.add_parser("identity", help="inspect universal object identities")
    identity_sub = identity.add_subparsers(dest="identity_command", required=True)
    identity_sub.add_parser("status")
    identity_show = identity_sub.add_parser("show"); identity_show.add_argument("identifier")
    identity_hashes = identity_sub.add_parser("hashes"); identity_hashes.add_argument("identifier")
    identity_sub.add_parser("rebuild")
    identity_relationships = identity_sub.add_parser("relationships"); identity_relationships.add_argument("identifier")
    identity_search = identity_sub.add_parser("search"); identity_search.add_argument("--platform"); identity_search.add_argument("--format", dest="format_id"); identity_search.add_argument("--authority"); identity_search.add_argument("--hash-algorithm", dest="hash_algorithm")
    product = sub.add_parser("product", help="build deterministic derived metadata products")
    product_sub = product.add_subparsers(dest="product_command", required=True)
    product_sub.add_parser("list")
    product_build = product_sub.add_parser("build"); product_build.add_argument("product", choices=["identity", "fixity", "authority-crosswalk", "containment"]); product_build.add_argument("--platform"); product_build.add_argument("--format", dest="format_id"); product_build.add_argument("--authority"); product_build.add_argument("--hash-algorithm", dest="hash_algorithm")
    local = sub.add_parser("local-ingest", help="operate local import inbox and file ingest")
    local_sub = local.add_subparsers(dest="local_command", required=True)
    local_sub.add_parser("status"); local_sub.add_parser("jobs")
    local_show = local_sub.add_parser("show"); local_show.add_argument("job_id")
    local_file = local_sub.add_parser("file"); local_file.add_argument("path", type=Path); local_file.add_argument("--category", choices=IngestManager.CATEGORIES, default="unknown"); local_file.add_argument("--provenance", choices=[x.value for x in ProvenanceClass], default=ProvenanceClass.UNKNOWN.value); local_file.add_argument("--rights", choices=[x.value for x in Rights], default=Rights.UNKNOWN.value); local_file.add_argument("--notes", default="")
    inbox_scan = local_sub.add_parser("inbox-scan"); inbox_scan.add_argument("--category", choices=IngestManager.CATEGORIES)
    inbox = local_sub.add_parser("inbox", help="inspect and operate configured watched inboxes")
    inbox_sub = inbox.add_subparsers(dest="inbox_command", required=True)
    inbox_sub.add_parser("list")
    inbox_sub.add_parser("status")
    inbox_scan_command = inbox_sub.add_parser("scan"); inbox_scan_command.add_argument("--config", type=Path); inbox_scan_command.add_argument("--stability", type=float, default=1.0); inbox_scan_command.add_argument("--min-age", type=float, default=0.0); inbox_scan_command.add_argument("--post-success", choices=["LEAVE", "MOVE_TO_PROCESSED", "DELETE_AFTER_VERIFIED_INGEST"], default="LEAVE")
    inbox_watch = inbox_sub.add_parser("watch"); inbox_watch.add_argument("--config", type=Path); inbox_watch.add_argument("--interval", type=float, default=30.0); inbox_watch.add_argument("--stability", type=float, default=1.0); inbox_watch.add_argument("--min-age", type=float, default=0.0); inbox_watch.add_argument("--post-success", choices=["LEAVE", "MOVE_TO_PROCESSED", "DELETE_AFTER_VERIFIED_INGEST"], default="LEAVE"); inbox_watch.add_argument("--once", action="store_true"); inbox_watch.add_argument("--loop", action="store_true"); inbox_watch.add_argument("--max-cycles", type=int)
    tree = local_sub.add_parser("tree"); tree.add_argument("directory", type=Path); tree.add_argument("--category", choices=IngestManager.CATEGORIES, default="unknown"); tree.add_argument("--provenance", choices=[x.value for x in ProvenanceClass], default=ProvenanceClass.UNKNOWN.value); tree.add_argument("--rights", choices=[x.value for x in Rights], default=Rights.UNKNOWN.value); tree.add_argument("--notes", default="")
    media = sub.add_parser("media", help="inspect and capture physical media")
    media_sub = media.add_subparsers(dest="media_command", required=True)
    media_sub.add_parser("devices")
    media_inspect = media_sub.add_parser("inspect"); media_inspect.add_argument("device")
    media_capture = media_sub.add_parser("capture"); media_capture.add_argument("device"); media_capture.add_argument("--provenance", choices=[x.value for x in ProvenanceClass], default=ProvenanceClass.ORIGINAL_PHYSICAL_OWNED.value); media_capture.add_argument("--rights", choices=[x.value for x in Rights], default=Rights.UNKNOWN.value); media_capture.add_argument("--notes", default="")
    media_sub.add_parser("jobs")
    media_show = media_sub.add_parser("show"); media_show.add_argument("job_id")
    physical_ingest = media_sub.add_parser("ingest", help="unified safe physical-media ingest")
    physical_ingest.add_argument("--candidate"); physical_ingest.add_argument("--verification", choices=["fast", "standard", "archival"], default="standard"); physical_ingest.add_argument("--provenance", choices=[x.value for x in ProvenanceClass], default=ProvenanceClass.ORIGINAL_PHYSICAL_OWNED.value); physical_ingest.add_argument("--rights", choices=[x.value for x in Rights], default=Rights.UNKNOWN.value); physical_ingest.add_argument("--profile", choices=[x.value for x in FloppyProfile]); physical_ingest.add_argument("--drive"); physical_ingest.add_argument("--tracks"); physical_ingest.add_argument("--title"); physical_ingest.add_argument("--vendor"); physical_ingest.add_argument("--collection"); physical_ingest.add_argument("--volume"); physical_ingest.add_argument("--notes", default=""); physical_ingest.add_argument("--batch", action="store_true"); physical_ingest.add_argument("--max-media", type=int); physical_ingest.add_argument("--dry-run", action="store_true"); physical_ingest.add_argument("--non-interactive", action="store_true"); physical_ingest.add_argument("--confirm", action="store_true"); physical_ingest.add_argument("--json", action="store_true")
    optical = media_sub.add_parser("optical")
    optical_sub = optical.add_subparsers(dest="optical_command", required=True)
    optical_sub.add_parser("devices")
    optical_inspect = optical_sub.add_parser("inspect"); optical_inspect.add_argument("device")
    optical_capture = optical_sub.add_parser("capture"); optical_capture.add_argument("device"); optical_capture.add_argument("--provenance", choices=[x.value for x in ProvenanceClass], default=ProvenanceClass.ORIGINAL_PHYSICAL_OWNED.value); optical_capture.add_argument("--rights", choices=[x.value for x in Rights], default=Rights.UNKNOWN.value); optical_capture.add_argument("--notes", default=""); optical_capture.add_argument("--verification", choices=["fast", "standard", "archival"], default="standard")
    optical_sub.add_parser("jobs")
    optical_show = optical_sub.add_parser("show"); optical_show.add_argument("job_id")
    flux = media_sub.add_parser("flux")
    flux_sub = flux.add_subparsers(dest="flux_command", required=True)
    flux_sub.add_parser("adapters"); flux_sub.add_parser("devices"); flux_sub.add_parser("profiles")
    flux_inspect = flux_sub.add_parser("inspect"); flux_inspect.add_argument("device")
    flux_plan = flux_sub.add_parser("plan"); flux_plan.add_argument("--profile", choices=[x.value for x in FloppyProfile], default=FloppyProfile.UNKNOWN.value); flux_plan.add_argument("--drive", default="A"); flux_plan.add_argument("--tracks", default="c=0-79:h=0-1"); flux_plan.add_argument("--revolutions", type=int, default=3)
    flux_capture = flux_sub.add_parser("capture"); flux_capture.add_argument("device"); flux_capture.add_argument("--profile", choices=[x.value for x in FloppyProfile], default=FloppyProfile.UNKNOWN.value); flux_capture.add_argument("--drive", default="A"); flux_capture.add_argument("--tracks", default="c=0-79:h=0-1"); flux_capture.add_argument("--revolutions", type=int, default=3); flux_capture.add_argument("--verification", choices=[x.value for x in VerificationPolicy], default=VerificationPolicy.STANDARD.value); flux_capture.add_argument("--provenance", choices=[x.value for x in ProvenanceClass], default=ProvenanceClass.UNKNOWN.value); flux_capture.add_argument("--rights", choices=[x.value for x in Rights], default=Rights.UNKNOWN.value); flux_capture.add_argument("--notes", default="")
    flux_sub.add_parser("jobs")
    flux_show = flux_sub.add_parser("show"); flux_show.add_argument("job_id")
    flux_decode = flux_sub.add_parser("decode"); flux_decode.add_argument("object"); flux_decode.add_argument("--format", dest="format_id", required=True, choices=["adf", "d64", "g64"])
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
        return {**archive.doctor(), "qualification": QualificationManager(archive).status()}
    if args.command == "qualify":
        manager = QualificationManager(archive)
        if args.qualify_command == "status": return manager.status()
        if args.qualify_command == "report": return manager.report(args.qualification_id)
        if args.qualify_command == "backup-ack": return manager.acknowledge_backup(replica=args.replica, last_backup=args.last_backup, restore_test=args.restore_test, operator=args.operator)
        only = None if args.qualify_command == "local-seed" else args.qualify_command
        return manager.run(profile=args.profile, only=only, operator=args.operator, expected_local_seed_bytes=args.expected_local_seed_bytes)
    if args.command == "seed":
        plans = SeedPlanManager(archive)
        if args.seed_command == "create": return plans.create(args.plan_id, collection=args.collection, notes=args.notes)
        if args.seed_command == "add": return plans.add(args.plan_id, label=args.label, category=args.category, expected_count=args.expected_count, nominal_bytes=args.nominal_bytes, provenance=args.provenance, notes=args.notes)
        if args.seed_command == "show": return plans.show(args.plan_id)
        return plans.list()
    if args.command == "analyze":
        manager = AnalysisManager(archive)
        if args.analyze_command == "status": return manager.status()
        if args.analyze_command == "jobs": return manager.jobs()
        if args.analyze_command == "show": return manager.show(args.job_id)
        if args.analyze_command == "relationships": return manager.relationships(args.object_id)
        limits = AnalysisLimits(max_depth=args.max_depth, max_files=args.max_files, max_bytes=args.max_bytes, max_single_bytes=args.max_single_bytes, max_members=args.max_members, max_ratio=args.max_ratio, max_seconds=args.max_seconds)
        return manager.analyze(args.object_id, policy=args.policy, limits=limits)
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
        malware_store = MalwareStore(archive, extended=True)
        if args.malware_command == "status":
            return malware_store.status(args.identifier) if args.identifier else malware_store.stats()
        if args.malware_command == "scanners":
            return malware_store.scanners_status()
        if args.malware_command == "profiles": return malware_store.scanner_profiles()
        if args.malware_command == "scanner":
            return malware_store.scanner_status(args.scanner_id)
        if args.malware_command == "scan":
            return malware_store.scan(args.identifier, args.scanner, timeout=args.timeout)
        if args.malware_command == "analyze": return malware_store.run_analysis(args.identifier, profile=args.profile, scanner_ids=args.scanner_ids, max_scanners=args.max_scanners, timeout=args.timeout)
        if args.malware_command == "compare": return malware_store.compare(args.identifier)
        if args.malware_command == "analysis-sets": return malware_store.analysis_sets()
        if args.malware_command == "analysis-jobs": return malware_store.analysis_jobs()
        if args.malware_command == "observations":
            return malware_store.observations(args.identifier)
        if args.malware_command == "show":
            return malware_store.show(args.observation_id)
        if args.malware_command == "verify":
            return malware_store.verify()
        return malware_store.rebuild()
    if args.command == "acquisition":
        if args.acquisition_command == "bootstrap":
            orchestrator = BootstrapOrchestrator(archive)
            if args.bootstrap_command == "status": return orchestrator.store.read(args.job_id)
            if args.bootstrap_command == "report": return orchestrator.store.report(args.job_id)
            source = registry.get(args.source_id)
            if args.bootstrap_command == "plan": return orchestrator.plan(source, args.path)
            return orchestrator.start(source, args.path) if args.bootstrap_command == "start" else orchestrator.resume(source, args.job_id)
        resolver = TransportResolver()
        if args.acquisition_command == "transports":
            return resolver.capabilities()
        source = registry.get(args.source_id)
        if args.acquisition_command == "plan":
            return resolver.plan(source, args.purpose)
        return resolver.fetch(Acquisition(archive), source, args.purpose, path=args.path,
                              expected_sha256=args.expected_sha256, expected_size=args.expected_size,
                              dry_run=args.dry_run)
    if args.command == "identity":
        identity_db = IdentityCatalogue(archive)
        if args.identity_command == "status": return identity_db.status()
        if args.identity_command == "show": return identity_db.show(args.identifier)
        if args.identity_command == "hashes": return identity_db.hashes(args.identifier)
        if args.identity_command == "relationships": return identity_db.relationships(args.identifier)
        if args.identity_command == "search": return identity_db.search(platform=args.platform, format_id=args.format_id, authority=args.authority, hash_algorithm=args.hash_algorithm)
        return identity_db.rebuild()
    if args.command == "product":
        products = ProductBuilder(archive)
        if args.product_command == "list": return products.list()
        return products.build(args.product, platform=args.platform, format_id=args.format_id, authority=args.authority, hash_algorithm=args.hash_algorithm)
    if args.command == "local-ingest":
        manager = IngestManager(archive)
        if args.local_command == "status": return manager.status()
        if args.local_command == "jobs": return manager.jobs()
        if args.local_command == "show": return manager.show(args.job_id)
        if args.local_command == "file": return manager.ingest_file(args.path, category=args.category, rights=Rights(args.rights), provenance=args.provenance, notes=args.notes)
        if args.local_command == "tree": return TreeIngestManager(archive).ingest(args.directory, category=args.category, rights=Rights(args.rights), provenance=args.provenance, notes=args.notes)
        if args.local_command == "inbox":
            watched = WatchedInboxManager(archive, config_path=args.config if hasattr(args, "config") else None, default_stability_seconds=getattr(args, "stability", 1.0), default_min_age_seconds=getattr(args, "min_age", 0.0), default_post_success=getattr(args, "post_success", "LEAVE"))
            if args.inbox_command == "list": return watched.list_inboxes()
            if args.inbox_command == "status": return watched.status()
            if args.inbox_command == "scan": return watched.scan_once()
            return watched.watch(interval_seconds=args.interval, once=args.once or not args.loop, max_cycles=args.max_cycles)
        return manager.scan_inbox(args.category)
    if args.command == "media":
        if args.media_command == "ingest":
            metadata = {key: value for key, value in {"title": args.title, "vendor": args.vendor, "collection": args.collection, "volume": args.volume, "notes": args.notes}.items() if value not in (None, "")}
            return PhysicalMediaOrchestrator(archive).ingest(candidate_id=args.candidate, verification=args.verification, provenance=args.provenance, rights=args.rights, profile=args.profile, drive=args.drive, tracks=args.tracks, metadata=metadata, dry_run=args.dry_run, confirm=args.confirm, interactive=not args.non_interactive, batch=args.batch, max_media=args.max_media)
        if args.media_command == "optical":
            manager = OpticalManager(archive)
            if args.optical_command == "devices": return manager.devices()
            if args.optical_command == "inspect": return manager.inspect(args.device)
            if args.optical_command == "capture": return manager.capture(args.device, rights=Rights(args.rights), provenance=args.provenance, notes=args.notes, verification=args.verification)
            if args.optical_command == "jobs": return manager.jobs()
            return manager.show(args.job_id)
        if args.media_command == "flux":
            manager = FluxManager(archive)
            if args.flux_command == "adapters": return manager.adapters()
            if args.flux_command == "devices": return manager.devices()
            if args.flux_command == "profiles": return manager.profiles()
            if args.flux_command == "inspect": return manager.inspect(args.device)
            if args.flux_command == "plan": return {"adapter": manager.adapter.capabilities(), "profile": manager.profiles()[args.profile], "drive": args.drive, "tracks": args.tracks, "revolutions": args.revolutions, "read_only": True}
            if args.flux_command == "capture": return manager.capture(args.device, profile=args.profile, drive=args.drive, tracks=args.tracks, revolutions=args.revolutions, rights=Rights(args.rights), provenance=args.provenance, notes=args.notes, verification=args.verification)
            if args.flux_command == "jobs": return manager.jobs()
            if args.flux_command == "decode": return manager.decode(args.object, args.format_id)
            return manager.show(args.job_id)
        manager = MediaManager(archive)
        if args.media_command == "devices": return manager.devices()
        if args.media_command == "inspect": return manager.inspect(args.device)
        if args.media_command == "capture": return manager.capture(args.device, rights=Rights(args.rights), provenance=args.provenance, notes=args.notes)
        if args.media_command == "jobs": return manager.jobs()
        return manager.show(args.job_id)
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
        values = list(argv) if argv is not None else sys.argv[1:]
        for index in range(len(values) - 1):
            if values[index:index + 2] == ["ingest", "inbox"]:
                values[index:index + 2] = ["local-ingest", "inbox"]
                break
        result = run(parser().parse_args(values))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if not isinstance(result, dict) or result.get("outcome") != "FAIL" else 1
    except (RabError, OSError) as exc:
        print(f"rab: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
