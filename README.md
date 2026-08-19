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

## Consumer Resource Broker v1

The broker is the single generic delivery contract for future ATM, WTM, UTM,
UBB, DRD, and other consumers. Stable logical IDs resolve to descriptors with
immutable `sha256:` object IDs, package/set relationships, provenance, rights,
availability, authority evidence, and future malware state. It never exposes an
object-store path. Use `rab resource resolve`, `pin`, `materialize`, and
`verify-lock`, `rab resource-set show`, and `rab consumer list`; the API provides
the corresponding stable-ID resources and resource-set routes.

Definitions and immutable set generations are JSON sidecars under
`resource-metadata`; broker SQLite tables are disposable and rebuildable.
Pinned `rab-resource-manifest-v1` files contain exact IDs, rights snapshots,
dependencies, authority evidence, and delivery context, never payload bytes or
filesystem paths. Delivery may stream, copy, materialize outside `objects`, or
return a manifest only. Non-redistributable resources may resolve but are not
public-deliverable. Consumer caches are disposable, exact-hash keyed, and
isolated per consumer. RAB owns preservation identity and bytes; consumers own
runtime behavior. A materialized copy is not a preservation master, and one
master may serve many consumers. Malware is currently `NOT_SCANNED`, not a
fabricated clean result. Museum-grade status remains unclaimed.

See [docs/architecture.md](docs/architecture.md) and
[docs/roadmap.md](docs/roadmap.md) for boundaries and milestone status.

## M6.7 Flux ingest

`rab media flux` provides a read-only Greaseweazle foundation. Captures use
the official `gw read --raw` path and retain SCP raw flux as the preservation
master. A successful ADF or D64 decode does not replace the flux master;
flux, ADF, D64, G64, and future IPF objects have separate byte identities.
Separate flux reads may differ byte-for-byte while still being consistent
reads, so repeat verification compares decoded and track evidence rather than
requiring equal raw hashes. Greaseweazle V4.1 and real floppy qualification
are not performed until hardware is available.

Flux capture jobs also retain physical-medium IDs, platform hints, first/repeat
attempt metadata, capture hashes, and repeat comparisons. A nonzero tool result
with useful partial SCP output is preserved as `PARTIAL` with warnings rather
than deleted or called complete; differing repeat captures remain separate
evidence. Platform hints do not create platform identity.

## M6.8 Watched inbox ingest

The opt-in `rab-inbox-watch.service` continuously reconciles configured inboxes
through the existing local ingest and `Archive.ingest` path. Default inboxes
are `downloads`, `purchased`, `personal`, and `unknown`; provenance is a policy
hint and never grants rights. Files must be regular, remain stable across two
observations, satisfy minimum-age/size policy, and avoid configured temporary
suffixes. Unknown files are valid preservation objects.

Source files are left untouched by default. Explicit policies may move a file
to a sibling processed directory or delete it only after verified ingest.
Duplicate bytes create one CAS master and another provenance occurrence.
Watcher state is restart-safe and disposable; local-ingest jobs, object
manifests, occurrences, and preservation events remain the authoritative
records. The API and RetroWeb expose only safe logical inbox/job information,
not private filesystem paths or purchase metadata.

## M6.9 Unified physical media ingest

`rab media ingest --dry-run` discovers optical, removable block, and
Greaseweazle candidates, inspects them, and prints a unified preservation plan
without capture or mutation. `rab media ingest --candidate ID` routes the
confirmed operation to the existing adapter; capture still requires explicit
confirmation. `--batch` groups multiple medium jobs into an operational
session. Block devices remain whole-device and fail-closed, optical mixed-mode
media remains track-aware/unsupported when M6.5 cannot safely capture it, and
flux capture remains SCP raw evidence with explicit drive/profile selection.

The operator workflow deliberately asks rather than guesses when safety or
media selection is ambiguous. Candidate/session status is read-only through
the API and `/retro/physical-media`. Physical qualification is fixture-only;
real optical, USB, Greaseweazle, and Debian 13 hardware qualification remain
unperformed.

## M6.10 Local-first seed qualification

`rab qualify local-seed` records versioned host, disposable storage, inbox,
adapter discovery, unified-UX, capacity, and backup-policy evidence. Readiness
is profile-specific: `local-seed-optical`, `local-seed-usb`,
`local-seed-floppy`, and `local-seed-full` do not block one another, while
missing hardware remains `NOT_PERFORMED`. Fixture-tested software is not
physical qualification. `rab qualify status`, `report`, and `backup-ack`
provide machine-readable operator evidence; `rab seed create/add/status`
provides optional planning metadata for unknown or known local material.

Recommended order: qualify host/storage, preserve owned/local media, preserve
purchased downloads through the watched inbox, audit/fixity/backup the seed,
then opt in to large online bootstrap. A backup acknowledgement without a
successful restore test is reported as `WARNING`; RAB does not pretend to
implement or verify replicas.

## M6.11 Contained object analysis

`rab analyze object <object-id>` analyzes a disposable copy of a preserved
object. `metadata-only` is the conservative default; `identify` materializes
bounded temporary bytes for hashing, while `preserve` and `archival` promote
materialized regular files through the normal `Archive.ingest` boundary.
Containers never replace their parents. Preserved children receive universal
hashes and `CONTAINS` relationship evidence with logical paths and analyzer
identity. ZIP, TAR, gzip, bzip2, xz, ISO9660, FAT12/16 inspection, Amiga/C64
image boundaries, and LHA limitation reporting are provided without executing
contained programs or mounting source media.

Recursion, files, expanded bytes, member count, single-object size,
compression ratio, and elapsed time are bounded. Traversal, symlink, special
file, malformed archive, and archive-bomb conditions stop safely and remain
analysis evidence. Analysis may fail without invalidating preservation.

## M7.1 Historical and native malware evidence

RAB preserves malware observations rather than cleaning content. Existing
ClamAV remains available, while scanner classes now include current host,
current isolated, historical Linux, native retro, and rule engines. YARA is a
bounded optional rule-engine adapter based on its documented `yara RULES
TARGET` interface. Historical Linux and native Amiga/DOS/Atari profiles use
fixture/operator-supplied runners; no proprietary scanner binaries or
definitions are bundled. LMD is recorded as not automation-qualified because
its official distribution includes response/remediation features, and current
KVRT automation/licensing was not qualified.

Observations retain scanner/adapter class, coverage, definitions/ruleset
identity, target representation/logical path, timestamps, limitations, and
remediation capability. `NOT_DETECTED` is not `CLEAN`; conflicting engines are
preserved and aggregate as `CONFLICTING`. Historical scanner snapshots and
signature sets should themselves enter RAB through ordinary preservation and
rights policy. Scanner analysis always receives a disposable copy and never
replaces a master.

## Retro-Compatible Web v1

RAB provides an optional server-rendered read-only web interface through
`rab web`, `/web`, and the austere `/retro` view. Search, browse, resource
inspection, README text viewing, resource sets, and permitted downloads use
ordinary HTML hyperlinks and forms. Core functionality requires zero
JavaScript, Node/npm, frameworks, CDNs, external fonts, analytics, or tracking.
The normal view uses a small local conservative stylesheet; the retro view
remains useful without CSS.

The web layer delegates catalogue search, Resource Broker resolution, authority
evidence, rights decisions, fixity, and streaming downloads to existing RAB
services. It exposes no preservation paths and provides no ingest, deletion,
administration, policy mutation, or arbitrary filesystem access. Historical
README bytes are bounded, decoded safely, and escaped as text. Stable resource
URLs use logical IDs and survive derived-state rebuilds.

RAB Web follows progressive enhancement. Core archive functionality is delivered
as server-rendered HTML and does not require JavaScript.

Normal and retro views are compatibility targets, not browser qualifications.
No specific vintage browser is claimed tested by this milestone. The optional
retro HTTP listener is disabled by default, explicitly bound by Ansible, and
read-only for trusted-LAN use only. HTTP provides no confidentiality and must
not be exposed to an untrusted network. Museum-grade status remains unclaimed.

## M5 Malware Preservation & Analysis

Malware analysis is evidence about preserved bytes, never a transformation of
them. Each scan creates an immutable, versioned observation containing the
object SHA-256, scanner/vendor/product/version data, signature metadata,
execution environment, result, detections, coverage, provenance, and raw-result
reference. JSON observation and raw-result sidecars are authoritative;
`malware.sqlite3` is disposable and rebuildable. Scanner processes receive a
temporary read-only copy under `malware-analysis`, never an object-store master.

The generic adapter contract provides capability detection, bounded list-based
execution, timeout handling, safe output normalization, and destructive-option
rejection. ClamAV is implemented for normal Debian `clamscan` use. ESET, Avast,
Sophos, and Bitdefender adapters report truthful availability or license/install
limitations; no proprietary software or credentials are included. Aggregate
states are `UNKNOWN`, `CLEAN_OBSERVED`, `SUSPICIOUS`, `MALWARE_DETECTED`, and
`ANALYSIS_FAILED`; independent observations remain visible and clean means only
observed clean under specified evidence.

`rab malware` provides status, scanner capability, scan, observation, verify,
and rebuild commands. Read-only API routes expose scanner and observation
metadata, and Resource Broker descriptors include malware state/observations.
Consumers may use `allow`, `deny-detected`, or `require-analysis` delivery
policy without changing rights policy. RetroWeb displays escaped detection
names and status without JavaScript and never grants a denied download.
ZIP/TAR extraction is optional and bounded against traversal, links, file-count,
size, and depth abuse. Native-platform scanners and behavioral analysis remain
future disposable-environment work. The original M5 baseline did not perform
real ClamAV qualification because `clamscan` was unavailable; M5.1 records the
later bounded runtime qualification. No live malware was acquired.

## M5.1 Operational ClamAV Qualification

M5.1 adds explicit Debian-family provisioning for `clamav` and
`clamav-freshclam`, both disabled by default through `rab_clamav_enabled` and
`rab_clamav_freshclam_enabled`. Enabling the scanner does not enable signature
updates or background archive scans. Signature updates are an explicit
operator-controlled lifecycle; RAB startup never requires an Internet update.

Real ClamAV execution was qualified in the available Ubuntu 26.04 x86_64
environment using official Ubuntu `1.5.3+dfsg-0ubuntu0.26.04.1` packages
extracted outside the repository. A clean fixture normalized to `CLEAN` and the
standard EICAR test artifact normalized to `DETECTED` using a local deterministic
ClamAV HDB signature. Raw output, scanner version, database SHA-256 provenance,
and immutable observations were retained. Both preservation masters were
byte-identical before and after scanning. This is real ClamAV runtime evidence,
not Debian 13 VM provisioning qualification; Debian production qualification
remains not performed.

## M6.1 Acquisition Transport & Bootstrap Policy

Acquisition now treats one logical source as a set of policy-controlled
transport endpoints. Bootstrap defaults to BitTorrent, rsync, HTTPS, HTTP,
then FTP. Synchronization defaults to rsync, HTTPS/HTTP, FTP, then BitTorrent
snapshots. Source policy may override, prohibit, or declare transports
unavailable; equal candidates are reported ambiguous rather than guessed.
`rab acquisition transports`, `plan`, and `fetch` expose the decision and its
rejected-candidate evidence before any transfer.

Existing M2 HTTP, rsync, and BitTorrent staging/ingest paths remain the actual
acquisition boundary. FTP adds anonymous passive binary transfer with bounded
staging and normal RAB ingest. Transport provenance is recorded separately from
logical source identity, including purpose, endpoint, and transport-specific
evidence. Identical bytes converge through the existing SHA-256 object store;
transport choice never changes preservation identity.

Transport is not authority. An official endpoint or preferred protocol does
not establish authenticity, rights, malware safety, or authority status. No
large collection was downloaded for M6.1. Current qualification used local
fixtures and existing bounded HTTP behavior; rsync is available as version
`3.4.1`, while `aria2c` was unavailable in the development environment and no
public FTP endpoint was qualified. RetroWeb exposes source endpoint metadata
read-only; it is not an acquisition control panel.

## M6.2 Acquisition Runtime Qualification & Bootstrap

M6.2 adds resumable generic bootstrap jobs over the M6.1 transport resolver.
`rab acquisition bootstrap plan/start/status/resume/report` uses the selected
bootstrap transport, processes explicit bounded items, persists operational job
state under `bootstrap-metadata`, skips already-present source paths on rerun,
and emits `rab-bootstrap-report-v1`. Reports distinguish acquired,
deduplicated, and failed items and retain the selected transport plan/version.
API and RetroWeb expose status only; bootstrap mutation remains CLI/operator
local. Aria2 remains an acquisition client, not a daemon or archive store, and
is explicitly provisioned through the existing official Debian package path.

M6.2 also supports magnet metadata through the existing BitTorrent boundary,
with preserved magnet provenance and infohash evidence. A bounded local
BitTorrent runtime attempt was made in the available Ubuntu environment but
did not complete successfully; `aria2c` was not installed system-wide and no
BitTorrent runtime qualification is claimed. No large public collection was
downloaded. Museum-grade status remains unclaimed.

## M6.3 Universal Identity & Derived Products

M6.3 adds a platform-agnostic, rebuildable identity catalogue over immutable
RAB objects. SHA-256 remains the canonical preservation/CAS identity; streamed
CRC32, MD5, SHA-1, SHA-256, and BLAKE3 values are interoperability metadata.
Identity levels distinguish byte, media, release, and work identity. Generic
data-driven format profiles classify small Amiga and Commodore 64 fixtures
without making the core schema platform-specific. Typed evidence-backed
relationships represent derivation, representations, releases, works, and
authority matches without conflating byte identity.

The derived product engine emits deterministic metadata-only identity, fixity,
and authority-crosswalk JSONL products with platform/format/authority filters.
Products and identity state are disposable and rebuildable; publishing identity
metadata never grants payload redistribution rights. CLI, API, and RetroWeb
expose metadata only and never expose preservation paths. Physical media,
drop-folder ingest, broader platform profiles, public product publication,
large synchronization, and further hash/database expansion remain future work.

## M6.4 Local & Physical Media Ingest Foundation

M6.4 adds generic local-file and physical-media ingest jobs. Local inbox
categories are `downloads`, `purchased`, `personal`, and `unknown`; visible
files must be stable, `.part` files and symlinks are ignored, and source bytes
are never deleted. Each job records provenance classification, explicit rights,
operator notes, hashes, duplicate/convergence state, resulting object, malware
state, identity state, warnings, and errors. Provenance such as
`purchased_download`, `personal_dump`, `pirate_copy`, and
`original_physical_owned` is evidence/history, not a redistribution decision.

The generic `MediaAdapter` boundary currently implements safe read-only Linux
whole-block-device inspection/capture using `lsblk` and `dd`. It enumerates
whole disks, refuses the active root device, never mounts or writes the source,
captures only to controlled staging, and passes the image through normal
`Archive.ingest`. Optical, flux, tape, cartridge, and filesystem-content
adapters remain future work. CLI, read-only API, and RetroWeb expose job/status
metadata without arbitrary paths or remote capture controls. Rights, malware,
identity, authority, and preservation identity remain separate.

M6.6 also provides `rab local-ingest tree <directory>` for copied directory
trees whose original block device is unavailable. It preserves deterministic
relative hierarchy manifests, ingests regular files through the same CAS,
records symlink/special-file metadata without following or opening them, and
converges contained files with existing objects. A tree ingest is not a
replacement for whole-device capture.

## M6.5 Optical Media Ingest

M6.5 adds a Linux optical-drive foundation while preserving the distinction
between a physical medium and any captured byte representation. The optical
adapter inspects drive/media evidence through `lsblk`/`blkid`, plans a simple
single-session data capture as a block-aligned ISO-like representation, and
explicitly returns `TOOL_MISSING`/`UNSUPPORTED` for audio, mixed-mode,
multisession, or unknown media when track-aware tools are unavailable. It never
silently claims an ISO is a complete audio or multisession preservation.

Optical jobs record inspection/layout limitations, drive, tool/version,
strategy, verification evidence, provenance, and resulting preservation object.
Simple captures pass through controlled staging, `IngestManager`, identity,
malware state, and immutable `Archive.ingest`; duplicate physical captures add
occurrences without adding masters. `rab media optical ...`, read-only API
routes, and RetroWeb status expose the workflow. Optical tooling (`cdrdao` and
`cdparanoia`) is optional Debian provisioning, disabled by default. No optical
drive or real disc was available for qualification in this environment; only
synthetic fixtures were used. Museum-grade status remains unclaimed.

Optical job hardening retains physical-medium IDs, media/platform hints,
capture-attempt/repeat metadata, hashes, and read-error evidence. Useful
partial sector output is preserved as `PARTIAL` with warnings rather than
deleted or called complete. Injected TOC/track evidence can route audio,
mixed-mode, and multisession layouts to explicit track-aware
`TOOL_MISSING`/`UNSUPPORTED` plans; ISO is not treated as universal CD
preservation.

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

## M4.3 Additional authorities

RAB now classifies authority purpose rather than applying a global trust
ranking. TOSEC is `IDENTIFICATION`; Redump is `STRUCTURAL_VERIFICATION` for
complete optical layouts; No-Intro is `IDENTIFICATION` for ROM-like components;
SPS is `DUMP_VERIFICATION` for format-specific floppy preservation evidence;
MAME is `EMULATION_REFERENCE` plus component identification; FDB is a
`HISTORICAL_CATALOGUE`/`HISTORICAL_MANIFEST`. These purposes are contextual,
not a ranking. MAME component recognition does not verify a preservation dump,
and a No-Intro match does not identify optical structure.

The MAME adapter preserves official software-list XML through M1 and keeps ROM
and disk components, parts, interfaces, regions and canonical metadata
separate. No-Intro's parser is implemented for standard DAT/XML component data,
but official DAT download qualification is currently not qualified because the
public DAT-o-MATIC flow requires a dynamic token POST that did not produce a
download in this environment. No SPS public machine-readable authority
artifact was available under the qualification policy. No unofficial packs or
content collections were substituted.
