# Retro Archive Box

Retro Archive Box (RAB) is a Debian-first, preservation-first archive for
historic microcomputer software and media. Preservation masters are immutable;
analysis, repair, conversion, emulator use, and convenient packaging happen on
explicit derivatives or disposable copies.

This repository currently implements the acceptance-critical preservation
core and M2 acquisition framework: content-addressed ingest, independent occurrences/provenance, rights,
sidecar manifests, append-only PREMIS-inspired events, fixity verification,
byte-identical original export, policy checks, appliance diagnostics, and an
Ansible provisioning baseline, a typed source registry, safe staging
acquisition, Aminet payload-plus-original-readme packages, and preservation of
BitTorrent metadata.

## Quick start

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
export RAB_ROOT="$PWD/var/rab"
rab doctor
rab ingest ./example.adf --source manual --source-path example.adf \
  --rights UNKNOWN --media-type application/x-amiga-disk-format
rab search example
rab verify sha256:HASH
rab export sha256:HASH --output ./exported.adf
rab source validate
rab source list
rab source plan aminet --path util/misc/rsync-2.5.5_bin.lha --path util/misc/rsync-2.5.5_bin.readme
rab show aminet:comm/term/ncomm307
rab get aminet:comm/term/ncomm307 --output ./package --with-readme
pytest
```

## M3 catalogue

`rab catalogue rebuild` derives a typed SQLite catalogue and FTS5 index from
preservation manifests, occurrence/package sidecars, and event records. The
catalogue database is disposable: deleting it and rebuilding restores the same
semantic records without touching preservation masters. Use `rab catalogue
status`, `rab catalogue verify`, structured `rab search`, and `rab show ...
--json` for inspection. The read-only API runs on localhost with `rab api`.
Format identification and historical-text extraction are derived metadata only.
M3 does not claim museum-grade status.

The catalogue schema currently migrates v1 to v2 transactionally (v2 records
format evidence). A corrupt or missing catalogue is disposable and can be
recreated with `rab catalogue rebuild`; unsupported future schemas are refused.
The API service validates an existing catalogue without writing it, binds to
127.0.0.1 by default, and is disabled by default in Ansible. Its download
endpoints accept only stable object/package IDs, stream verified masters, and
allow local operator access while refusing non-redistributable objects for any
future public-serving mode. The API never accepts filesystem paths.

The database is an index, not the sole metadata store. Each object directory
contains a canonical manifest and append-only JSON Lines event log sufficient
to reconstruct the principal preservation catalogue.

See [docs/architecture.md](docs/architecture.md) and
[docs/roadmap.md](docs/roadmap.md) for boundaries and milestone status.
