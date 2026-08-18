# Retro Archive Box

Retro Archive Box (RAB) is a Debian-first, preservation-first archive for
historic microcomputer software and media. Preservation masters are immutable;
analysis, repair, conversion, emulator use, and convenient packaging happen on
explicit derivatives or disposable copies.

This repository currently implements the acceptance-critical preservation
core, M2 acquisition framework, generic authorities, and Redump optical-disc
model: content-addressed ingest, independent occurrences/provenance, rights,
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

M3.2 production qualification was performed on the disposable Debian 13
`ubb-debian13-qualification` VM (x86_64, kernel 6.12). Ansible completed with
14 changes on the first final run and 0 changes on the identical second run.
The API ran as `rab`, bound to `127.0.0.1:8000`, and its optional LAN profile
was separately qualified through an authenticated nginx proxy. The proxy is
opt-in, requires an operator-created htpasswd file outside Git, and does not
change RAB rights policy. The default profile never installs or starts LAN
exposure. The API download boundary is read-only and streams verified masters;
it never accepts server filesystem paths. LAN TLS certificates remain an
operator/reverse-proxy responsibility; Basic Auth qualification was restricted
to the disposable trusted test network.

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

## M4.1 authority assertions

`rab authority import FILE.dat` preserves the original TOSEC DAT through M1,
records immutable dataset/release provenance, and builds a disposable indexed
authority catalogue. `rab authority rebuild` reconstructs it from preserved
authority objects and metadata; assertions are not an `object.verified`
boolean. `EXACT_MATCH` requires hash and size evidence; collisions and
conflicts remain visible. TOSEC recognition is independent of source provenance
and rights. A TOSEC-organized Archive.org collection is an acquisition source,
not authority data. M4.1 does not claim museum-grade status.

### Bounded official TOSEC qualification

M4.1a qualified the official TOSEC release published 2025-03-13 from
`https://www.tosecdev.org/downloads/category/59-2025-03-13?download=117:tosec-dat-pack-complete-4743-tosec-v2025-03-13`.
The preserved artifact is `TOSEC - DAT Pack - Complete (4743)
(TOSEC-v2025-03-13).zip`, 100,621,631 bytes. Five DAT members were selected
for parsing: Commodore Amiga Games ADF, Commodore C64 Adventure D64, Atari ST
Applications RAW, Atari ST Games ST, and Sinclair ZX Spectrum Games TAP.
The full ZIP was preserved through M1; only those members were indexed.

The bounded import produced 88,030 records. All selected records supplied
valid SHA-1, MD5, CRC32, and non-negative size values. The real pack uses the
standard Logiqx external `DOCTYPE`; the parser accepts that declaration without
fetching it and still rejects XML entities. A multi-ROM Atari ST RAW DAT and
UTF-8 names were parsed successfully. Real content `EXACT_MATCH` remains
`NOT QUALIFIED` because no legally suitable matching content object was
available; no content set was downloaded.

## M4.2 Redump optical authority

RAB treats Redump as optical-structure authority, not as a flat hash list.
Official Redump DAT and CUE artifacts cross M1 independently; parsed Redump
disc/session/track tables are disposable. `rab authority redump import DAT CUES`
indexes canonical disc metadata, track order, data/audio type, mode, sector
size/count, LBA/index information, and per-track Redump hashes. A complete
disc match requires structural and per-track evidence. An ISO or one matching
data track cannot identify a mixed-mode disc. Redump identification never
changes preservation identity or redistribution rights.
