from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .errors import RabError
from .model import IngestRequest, Rights
from .store import Archive


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rab", description="Retro Archive Box")
    p.add_argument("--root", type=Path, default=Path(os.environ.get("RAB_ROOT", "/var/lib/rab")))
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
    show = sub.add_parser("show")
    show.add_argument("object")
    verify = sub.add_parser("verify")
    verify.add_argument("object")
    export = sub.add_parser("export")
    export.add_argument("object")
    export.add_argument("--preset", choices=["original"], default="original")
    export.add_argument("--output", type=Path, required=True)
    audit = sub.add_parser("audit")
    audit.add_argument("--fixity", action="store_true")
    sub.add_parser("doctor")
    return p


def run(args: argparse.Namespace) -> dict | list:
    archive = Archive(args.root)
    if args.command == "ingest":
        return archive.ingest(IngestRequest(
            args.path, args.source, args.source_path, Rights(args.rights),
            args.media_type, args.title, args.derived_from,
        ))
    if args.command == "search":
        return archive.search(args.query)
    if args.command == "show":
        return archive.show(args.object)
    if args.command == "verify":
        return archive.verify(args.object)
    if args.command == "export":
        return archive.export_original(args.object, args.output)
    if args.command == "audit":
        return archive.audit()
    if args.command == "doctor":
        return archive.doctor()
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
