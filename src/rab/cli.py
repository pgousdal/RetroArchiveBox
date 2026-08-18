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
    api = sub.add_parser("api", help="run the read-only catalogue API")
    api.add_argument("--host", default="127.0.0.1")
    api.add_argument("--port", type=int, default=8000)
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
