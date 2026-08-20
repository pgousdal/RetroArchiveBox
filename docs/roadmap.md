# v0.1 milestone status

Repository-audit note (2026-08-18): the implementation and 11-test baseline
contained the reported M0/M1 preservation core, but Git history contained only
one commit named `M0: Initial commit`; it did not record a distinct M1 commit.
Milestone claims below therefore reflect inspected code and validation rather
than inferred commit history.

## Implemented foundation

- Debian packaging/provisioning baseline and a systemd fixity timer
- SHA-256 content-addressed masters with BLAKE3, SHA-1, MD5, and CRC32
- immutable payload permissions, import/export verification, and fixity audit
- independent source occurrences, rights metadata, derivatives, sidecars
- append-only event records without update/delete operations
- CLI: `ingest`, `search`, `show`, `verify`, `export`, `audit`, `doctor`
- source, malware, and emulator policy configuration examples

## Required before claiming museum grade

- hardened filesystem/object-lock strategy and three-copy replica tracking
- database reconstruction command and tested disaster-recovery exercise
- generic acquisition workers and complete initial source registry review
- atomic Aminet payload + `.readme` logical package ingest
- versioned authority dataset import/assertion model
- static malware worker and disposable native emulator lab orchestration
- optical BIN/CUE and per-track model, drive qualification, Redump evidence
- BagIt and other export presets with rights/malware gates
- API/Web UI, full-text extraction/indexing, and collections
- end-to-end Debian VM CI including idempotent second Ansible run

No release should call itself museum-grade until these are demonstrated.

## M4 external authority programme

M4.1 adds the generic, rebuildable authority dataset model and the first TOSEC
adapter. Official TOSEC DAT/archive bytes cross M1 before parsing. Dataset and
release identity are immutable; parsed records, indexes, and assertions are
disposable. Assertions retain release, canonical name, result, matching method,
hash evidence, and provenance. `EXACT_MATCH` is not a source or rights claim,
and a filename alone cannot produce it. Historical releases are never
overwritten.

M4.3 is reserved for additional authorities. Historical
Amiga FDB datasets remain historical catalogues/manifests. Archive.org direct
item/collection archaeology, explicit collection authorization, official
torrent transport selection, and TOSEC content bootstrapping remain future M7
requirements. Expanded Amiga, neo-retro, and FPGA/recreation scope is recorded
in `config/platforms.json`; M4.1 does not claim those ecosystems are covered by
TOSEC.

### M4.1a real TOSEC qualification (2026-08-18)

The official TOSECdev `TOSEC-v2025-03-13` DAT Pack was downloaded once and
preserved through M1. The 100,621,631-byte ZIP was not an acquisition content
collection. Five bounded DAT members covering Commodore Amiga, Commodore C64,
Atari ST (including multi-ROM RAW), and Sinclair ZX Spectrum were parsed,
producing 88,030 indexed records. All selected records had SHA-1, MD5, CRC32,
and valid sizes. The artifact hashes and exact member list are recorded in
`docs/architecture.md`.

The real parser accepted TOSEC's standard Logiqx external `DOCTYPE` without
external resolution and retained UTF-8 and canonical names. `authority verify`
passed. Deleting the derived authority database and rebuilding solely from the
preserved ZIP produced semantically equivalent datasets, records, mappings,
and assertions. The indexed hash query plan used `records_hash_size`.

No legally suitable existing content object matched a selected real record;
real content `EXACT_MATCH` is therefore **NOT QUALIFIED**, without downloading
content or manufacturing a match. Deterministic synthetic match and rights
tests pass. M4.1 is **COMPLETE** for the qualified authority-data scope, with
that explicit real-content limitation. M4.2 and M4.3 remain untouched.

### M4.2 Redump optical authority

M4.2 adds Redump through the generic authority preservation and assertion
boundary without flattening optical identity into one file hash. Official
Redump DAT and CUE artifacts are independently preserved through M1; the
disposable authority index represents 596 Amiga CD discs and 942 ordered
session/track records. Data/audio tracks, MODE1/MODE2 sector geometry,
multi-track and multi-session layouts, INDEX information, per-track hashes,
partial representations, conflicts, and conservative platform mapping are
implemented and tested.

Bounded qualification used only the official Redump Amiga CD DAT/CUE endpoints.
Authority verify passed, derived database deletion/rebuild was semantically
equivalent, and preservation non-mutation passed. No disc images were fetched;
real legal disc `EXACT_MATCH` is **NOT QUALIFIED**. M4.2 is **COMPLETE** for the
qualified authority-data and synthetic structural-matching scope. Physical
drive qualification, dumping, conversion, Redump submission evidence, and
M4.3 authorities remain future work. Museum-grade status remains unclaimed.

### M4.3 additional authority integration (2026-08-18)

M4.3 adds contextual authority-purpose classification and an indexed component
adapter for No-Intro-style ROM DAT/XML and official MAME software-list XML.
MAME was qualified from official `mamedev/mame` commit
`17e1e9419edc5c483bc6a4a387c7e1d7b7341e32` using Amiga floppy and CD lists:
792 entries and 801 components, including 779 ROM and 22 disk components.
The artifacts crossed M1, authority verify passed, rebuild from preserved
artifacts was semantically equivalent, and preservation non-mutation passed.

No-Intro's official DAT-o-MATIC catalog was investigated. Its standard DAT
download is a dynamic token POST flow that was not successfully acquired by
the bounded non-authenticated qualification client, so No-Intro real-data
qualification is **NOT QUALIFIED**. The parser/model and deterministic tests
remain implemented; no third-party collection was used.

SPS is classified as `DUMP_VERIFICATION`, with explicit IPF/sector/track/flux
representation boundaries, but no legitimate public machine-readable SPS
authority artifact was available. SPS real qualification is **NOT QUALIFIED**;
no restricted library, membership area, tool or IPF was bypassed.

FDB remains historical catalogue/manifest evidence. M4.3 is **COMPLETE** for
the accessible official-authority scope, with No-Intro and SPS limitations
explicitly retained. Physical dumping, malware, and Archive.org work remain
future milestones. Museum-grade status remains **NO**.

## Consumer Resource Broker v1 (2026-08-19)

The generic broker is complete for the offline qualification scope. It adds
stable logical resource IDs, typed descriptors, source-independent exact and
constrained resolution with explicit ambiguity/availability/policy states,
package and multi-object resources, immutable resource-set generations,
rights-aware consumer contexts, exact pin/lock manifests, authority constraints,
dependency-cycle rejection, stable-ID streaming, isolated materialization,
exact-object cache reuse, and rebuildable derived state. Consumer state is
disposable and outside the preservation object tree. `test-consumer` is the only
enabled reference consumer; ATM, WTM, UTM, UBB, and DRD remain generic,
documented consumers, not RAB integrations.

Qualification is deterministic and offline: an Aminet payload/readme resolves,
pins, materializes byte-identically, reuses cache, and survives broker rebuild;
rights resolution is separate from delivery; path isolation and ambiguity/
dependency guards are tested. Ansible creates no consumer state unless
explicitly configured. Malware analysis and approved on-demand acquisition are
hooks only. Museum-grade status: NO.

## Retro-Compatible Web v1 (2026-08-19)

RAB now includes a conservative server-rendered HTML presentation layer backed
by the existing catalogue and Resource Broker. Normal `/web` and austere
`/retro` views provide home, search with traditional pagination, platform/source
browsing, stable resource pages, Aminet payload/README relationships, escaped
README text viewing, resource-set pages, authority evidence, rights-aware
downloads, and future-compatible malware status display. Core functionality
requires zero JavaScript; no SPA, frontend framework, Node/npm, CDN, telemetry,
or external runtime dependency was added. The normal view has a small local CSS
enhancement, while retro HTML remains useful without CSS.

The service is read-only and reuses existing verified broker/API boundaries.
Normal and optional retro HTTP services are disabled by default in Ansible. The
retro profile is explicitly bound trusted-LAN HTTP only; HTTP provides no
confidentiality and must not be exposed publicly. No specific historical
browser has been qualified or claimed. Museum-grade status remains NO.

## M5 Malware Preservation & Analysis (2026-08-19)

M5 adds the generic rebuildable malware evidence plane. Immutable observation
sidecars retain object identity, scanner/product/version and signature
metadata, execution environment, result, detections, coverage, provenance,
warnings/errors, and raw reports. Scanners run only against temporary read-only
copies; preservation masters remain byte-identical. `malware.sqlite3` is
disposable and rebuildable. Aggregate states are `UNKNOWN`, `CLEAN_OBSERVED`,
`SUSPICIOUS`, `MALWARE_DETECTED`, and `ANALYSIS_FAILED`, with independent
observations preserved rather than majority-voted or collapsed.

The generic command adapter and ClamAV normalization are implemented. ESET,
Avast, Sophos, and Bitdefender are represented as truthful capability/license
states only; no proprietary runtime qualification is claimed. CLI, read-only
API, Resource Broker delivery-policy hooks, and zero-JavaScript RetroWeb status
display are integrated. Bounded ZIP/TAR extraction protects against traversal,
links, depth, count, and expanded-size abuse. Native-platform scanning,
behavioral analysis, live malware, and automatic background scanning remain
future work. At the original M5 baseline `clamscan` was not installed, so real
qualification was not performed; M5.1 records the later bounded runtime
qualification. Museum-grade status remains **NO**.

## M5.1 Operational ClamAV Qualification (2026-08-19)

M5.1 hardens the ClamAV path with explicit official-package provisioning for
`clamav` and `clamav-freshclam`, independent signature-update policy, ClamAV
version/signature metadata parsing, raw-evidence retention, and failure-safe
observation behavior. Both package installation and freshclam are disabled by
default; no automatic archive scanning or destructive action is introduced.

Real ClamAV execution was qualified on the available Ubuntu 26.04 x86_64
environment using official Ubuntu ClamAV 1.5.3 packages outside the repository.
A clean fixture produced `CLEAN`; the standard EICAR test artifact produced
`DETECTED` using a local deterministic HDB signature. Observations retained
scanner version and database SHA-256 provenance, and clean/EICAR preservation
masters were byte-identical before and after scanning. API, Resource Broker,
RetroWeb, policy, catalogue rebuild, malware-index rebuild, failure, and
read-only paths were exercised. Debian 13 provisioning/idempotence was not
available and is **NOT PERFORMED**. Official continuously updated signature
database qualification, commercial engines, native scanners, and behavioral
analysis remain future work. M5.1 is complete for this demonstrated scope;
museum-grade status remains **NO**.

## M6.1 Acquisition Transport & Bootstrap Policy (2026-08-19)

M6.1 makes acquisition transports first-class without creating a second
acquisition subsystem. One logical source may expose multiple endpoints and a
purpose-aware resolver selects bootstrap or synchronization transport using
documented defaults, source overrides, prohibitions, runtime availability, and
ambiguity handling. Existing HTTP, rsync, and BitTorrent staging/ingest paths
are reused; anonymous passive binary FTP is implemented through the same staging
and ingest boundary. Transport and logical-source provenance are recorded
separately, and identical bytes still deduplicate as one preservation master.

CLI planning/fetch, API read/plan routes, source endpoint inspection, FTP
failure/path protections, cross-transport deduplication, and deterministic
policy tests are included. HTTP regression and prior BitTorrent/rsync tests
remain passing. The available rsync binary was `3.4.1`; `aria2c` was unavailable
and no public FTP endpoint was qualified. FTP qualification is local-fixture
only. No large public collection, automatic synchronization, Archive.org work,
or consumer integration was started. Museum-grade status remains **NO**.

## M6.2 Acquisition Runtime Qualification & Bootstrap Orchestration (2026-08-19)

M6.2 adds generic resumable bootstrap jobs on top of M6.1 transport policy.
Jobs persist source, purpose, selected transport plan, item progress, bytes,
deduplication, failures, lifecycle state, and versioned machine-readable
reports. CLI start/resume/report commands are operator-local; API and RetroWeb
are read-only status surfaces. Existing staging, verification, `Archive.ingest`,
rights, malware, and deduplication boundaries remain unchanged. Aria2 is
explicitly reportable/provisioned through the official Debian package path with
no daemon/RPC exposure. Magnet metadata support and bounded BitTorrent file
limits were added to the existing M2 path.

The available environment is Ubuntu 26.04 x86_64 with rsync `3.4.1`; aria2c is
not system-installed. An isolated official Ubuntu aria2 runtime attempt against
a small local web-seeded torrent did not complete, so BitTorrent runtime
qualification is **NOT QUALIFIED**. Deterministic bootstrap, interruption/
resume, idempotent rerun, local HTTP/FTP convergence, provenance, API,
RetroWeb, and staging-safety tests pass. No Debian 13 provisioning or remote
rsync qualification was performed. M6.3 hash/catalogue work remains out of
scope. Museum-grade status remains **NO**.

## M6.3 Universal Identity, Hash Catalogue & Derived Products Foundation (2026-08-19)

M6.3 adds a generic universal identity layer rather than an Amiga-specific
database. Immutable SHA-256 CAS identity remains authoritative while streamed
CRC32, MD5, SHA-1, SHA-256, and BLAKE3 interoperability hashes are indexed in
rebuildable `identity.sqlite3`. BYTE, MEDIA, RELEASE, and WORK levels are
explicitly separated. Data-driven format profiles qualify Amiga ADF and C64 D64
without platform-specific core architecture. Evidence-backed typed
relationships, existing TOSEC/Redump references, rights/malware references, and
source provenance remain distinct.

Deterministic metadata-only identity, fixity, and authority-crosswalk JSONL
products are generated by one product engine with platform/format/authority
filters. Deleting identity state and products and rebuilding leaves masters
unchanged and produces equivalent records. API, CLI, and zero-JavaScript
RetroWeb expose identity/product metadata without payload-path leakage or
rights bypass. Physical-media auto-ingest, watched drop folders, optical/USB/
flux qualification, broader identification, public product publication, and
large synchronization remain future work. Museum-grade status remains **NO**.

## M6.4 Local & Physical Media Ingest Foundation (2026-08-19)

M6.4 adds generic local inbox ingest, provenance classifications, persistent
ingest jobs, duplicate convergence, identity/malware integration, and a
fail-closed whole-block-device capture adapter. Purchased downloads, arbitrary
unknown files, personal copies, historical/pirate copies, and original physical
media are preserved through the existing staging and `Archive.ingest` boundary;
provenance does not grant rights. `lsblk`/`dd` capture is read-only against the
source, refuses the active root device, and is operator-local. API and RetroWeb
are status-only. Generated fixtures qualify local file and fake-device paths;
no removable hardware was available, so real hardware qualification is NOT
PERFORMED. Future optical/flux capture, filesystem extraction, watched-folder
services, USB imaging production privileges, and broader platform identification
remain open. Museum-grade status remains **NO**.

M6.6 additionally establishes generic tree ingest for copied filesystem
hierarchies. Whole-device images remain the preservation representation for
removable media; tree ingest is a separate deterministic manifest/file path.

## M6.5 Optical Media Ingest (2026-08-19)

M6.5 adds the generic Linux optical inspection/capture foundation. Physical
media, sessions/tracks, capture representations, verification evidence,
limitations, provenance, identity, malware, and rights remain distinct. Simple
single-session data optical media has an ISO-like block capture path through
the existing local-ingest and CAS boundary. Audio, mixed-mode, multisession,
and unknown layouts explicitly require track-aware tooling or remain
unsupported; no silent ISO flattening is performed. Optional Debian `cdrdao`
and `cdparanoia` provisioning is disabled by default. CLI/API/RetroWeb status
and deterministic synthetic fixture tests are implemented. No drive or real
disc was available, so real optical/hardware/Debian provisioning qualification
is **NOT PERFORMED**. Physical media, optical tool qualification, flux capture,
and filesystem extraction remain follow-on work. Museum-grade status remains
**NO**.

The optical foundation also retains physical-medium/repeat metadata and useful
partial sector captures, and accepts injected TOC/session/track evidence for
safe strategy planning. Real optical drive/media qualification remains
**NOT PERFORMED**.

## M6.7 Flux / Greaseweazle Ingest Foundation (2026-08-19)

M6.7 adds a generic flux adapter boundary above the existing physical-media
and `Archive.ingest` contracts. The Greaseweazle adapter records tool,
firmware/device evidence where available, enforces RAB read-only capture, and
preserves SCP raw flux as the master. Generic decoder records can derive ADF
and D64 objects without replacing the raw evidence; G64, IPF/SPS, and future
adapters remain honest extension points. Floppy geometry profiles are data,
not Amiga/C64 subsystems.

Deterministic fixtures cover adapter discovery, malformed/missing tools,
safe command policy, duplicate convergence, universal hashes, weak-track
evidence, decode success/failure, identity relationships, API, and RetroWeb.
Verification distinguishes raw byte identity from decoded semantic and
track/flux consistency; repeat captures are not required to hash identically.
Flux container malware coverage is recorded as `CONTAINER_ONLY`, not as a
fabricated clean result. Provenance and rights remain independent and an
operator may preserve unknown, copied, or pirate-declared media without
automatic inference. M6.7 is complete for software/fixture scope only.

Debian 13 provisioning qualification, real Greaseweazle V4.1 detection,
real Amiga/C64 capture, and real repeat-read qualification are **NOT
PERFORMED**. Follow-ons include M6.8 watched inbox production, M6.9 unified
operator UX/auto-detection, real hardware qualification, deeper optical
qualification, recursive filesystem analysis, tape/cartridge capture, and
public derived-product publication. Museum-grade status remains **NO**.

The flux foundation retains physical-medium/platform hints, repeat-attempt
comparisons, and useful partial SCP captures without changing the
software/fixture-only qualification boundary.

## M6.8 Watched Inbox Production Service (2026-08-19)

M6.8 turns the existing local inbox scan into an opt-in periodic service. It
supports extensible inbox policies, stable-file detection, atomic producer
suffixes, provenance/rights separation, exact duplicate convergence, durable
fingerprint state, exclusive claims, bounded retries, source-preserving
post-success policies, optional safe sidecars, recursive `TreeIngestManager`
handoff, free-space/staging limits, identity/catalogue integration, and
non-destructive malware hooks. CLI, read-only API, RetroWeb, JSON schema,
systemd, and Ansible status/configuration are included.

Deterministic qualification uses generated harmless files only. It covers
stability changes, temporary suffixes, unknown files, duplicate occurrences,
source non-mutation, move/delete opt-ins, malformed sidecars, recursive tree
ingest, failure visibility, API redaction, and RetroWeb display. A local CLI
qualification demonstrated a purchased file becoming stable, preserving exact
bytes once, retaining the source, and recording `purchased_download`.

The watcher state file is disposable operational evidence; preservation
objects, occurrences, jobs, and append-only events remain authoritative. Real
Debian 13 service execution and long-running production soak are **NOT
PERFORMED**. Next milestone: M6.9 Unified Physical Media Operator UX /
Auto-Detection. Later hardware qualification, contained-object discovery,
deeper optical qualification, tape/cartridge adapters, and public derived
products remain open. Museum-grade status remains **NO**.

## M6.9 Unified Physical Media Operator UX / Auto-Detection (2026-08-19)

M6.9 adds a thin unified discovery, plan, confirmation, routing, reporting,
and batch-session layer over the existing optical, block-device, and
Greaseweazle managers. It normalizes candidates, keeps block safety
fail-closed, requires explicit selection for conservative sources, supports
dry-run and machine-readable plans, preserves duplicate physical occurrences,
and exposes read-only API/RetroWeb status. It does not rewrite any technical
capture engine or add a daemon/framework.

Fixture qualification covers optical/block/flux candidate models, no/ambiguous
candidates, unsafe block rejection, routing, dry-run non-mutation, explicit
confirmation, operator metadata, duplicate physical occurrences, batch
sessions, API redaction, and RetroWeb status. The local environment has no
qualified physical optical drive, removable USB medium, or Greaseweazle V4.1;
real optical, USB, Amiga/C64, Greaseweazle, and Debian 13 physical-host
qualification are **NOT PERFORMED**. Remaining work includes physical
qualification command coverage, contained-object analysis, deeper optical
capture, tape/cartridge adapters, and public derived products. Museum-grade
status remains **NO**.

The removable-media preservation path now retains complete whole-device
representation, mounted-child/storage safety evidence, physical-medium and
repeat metadata, partial/error captures, non-mounting inventory, and
operator-local `rab removable` status/capture surfaces. Real disposable USB or
SD hardware qualification remains **NOT PERFORMED**.

## M6.11 Contained Object Discovery & Recursive Analysis Foundation (2026-08-19)

M6.11 adds bounded disposable-copy analysis, generic analyzer registration,
metadata-only/identify/preserve/archival policies, ZIP/TAR/compression,
mountless ISO9660/FAT inspection, traversal/symlink/archive-bomb protections,
recursive analysis jobs, universal hashes, typed containment relationships,
dedup convergence, malware coverage evidence, containment product output,
CLI/API/RetroWeb surfaces, and generated attack fixtures. Containers remain
preservation masters and analysis failure never invalidates them.

LHA/LZH materialization is intentionally not claimed without a qualified
toolchain. Real CD, USB, floppy-derived filesystem, Debian 13 dependency, and
production-soak qualification are **NOT PERFORMED**. Future work includes
native filesystem analyzers, contained-object malware analysis, real local
seed recursive analysis, deeper optical formats, online bootstrap activation,
and public derived products. Museum-grade status remains **NO**.

## M7.1 Historical & Native Malware Analysis Framework (2026-08-19)

M7.1 extends the M5 malware evidence plane with scanner classes, explicit
coverage, `NOT_DETECTED` and conflict semantics, definitions/ruleset identity,
historical Linux and native-retro runner contracts, YARA capability, LMD/KVRT
investigation states, multi-engine jobs, immutable analysis sets, broker
conflict handling, API/RetroWeb views, and fixture qualification. ClamAV and
the existing disposable read-only copy boundary remain the current operational
path. No proprietary engines, historical binaries, definitions, or real retro
runtime were bundled.

Fixture qualification covers historical/native/rule observations, temporal
rescan evidence, unavailable engines, definitions missing, coverage, conflicts,
remediation-disabled behavior, master non-mutation, API redaction, and
RetroWeb. YARA current upstream CLI behavior was inspected. LMD official
material was inspected but its response/remediation model is not accepted as
an automatic RAB engine; current KVRT official automation/licensing was not
qualified. Real ClamAV/YARA/LMD/KVRT, historical Linux, Amiga/DOS/Atari
native, and Debian 13 qualification remain **NOT PERFORMED**. Follow-ons are
M7.1a current free-engine qualification, M7.1b historical snapshots, M7.1c
Amiga native runtime, M7.1d DOS native runtime, and later Atari/native malware
and public metadata products. Museum-grade status remains **NO**.

## M6.10 Local-First Seed Readiness & Physical Qualification (2026-08-19)

M6.10 adds immutable qualification runs, explicit readiness levels and
profiles, disposable storage/inbox smoke tests, capacity headroom checks,
backup/replica acknowledgement warnings, adapter-specific NOT_PERFORMED
gates, seed planning metadata, CLI/API/RetroWeb reporting, and doctor status
integration. It reuses existing capture, ingest, identity, malware, catalogue,
broker, and physical UX boundaries without adding a capture engine or backup
product.

The available environment qualifies only deterministic host/storage/inbox and
unified dry-run behavior. Optical, valuable USB, Greaseweazle, Amiga/C64, and
Debian 13 physical-host qualification remain **NOT PERFORMED**. No backup
replica or restore implementation is claimed. `FIXTURE_QUALIFIED` is therefore
the conservative software state unless the operator records the required
acknowledgement and real profile-specific evidence. Recommended follow-ons are
real physical-host qualification, first local seed ingestion, contained-object
discovery, native malware expansion, deeper optical qualification, online
bootstrap activation, and public derived products. Museum-grade status remains
**NO**.

## M3 catalogue, search & API

M3 adds a disposable, versioned SQLite/FTS5 catalogue, deterministic rebuild
from preservation metadata, generic relationships and platform evidence,
format identification, safe historical-text extraction, structured bounded
search, JSON CLI inspection, and a read-only localhost API. The hard acceptance
property is semantic equivalence after deleting `catalogue.sqlite3` and running
`rab catalogue rebuild`; preservation-tree state is unchanged. API download,
authentication, authority matching, malware assertions, and the Web UI remain
future work. M3 is catalogue-complete for the current scope, not museum-grade.

### M3.1 hardening status

The v1→v2 catalogue migration, corrupt-database recovery, read-only API
runtime validation, stable-ID streaming downloads, range handling, and
rights-aware export boundary are implemented. The API remains bound to
localhost and disabled by default in Debian provisioning. Clean Debian 13
qualification and the opt-in authenticated nginx boundary were completed on
the disposable `ubb-debian13-qualification` VM; hostile-network TLS remains an
operator reverse-proxy responsibility. No museum-grade claim is made.

## M3.2 production closure evidence

The final Debian 13 run provisioned with 14 changes and the identical second
run with 0 changes. The `rab-api.service` process ran as `rab` with
`NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`, `ProtectHome`,
`ReadOnlyPaths`, and `UMask=0077`. The actual listener was
`127.0.0.1:8000`; source workers and API were not enabled by default. A tiny
payload/README package rebuilt to schema 2, verified successfully, searched
through FTS, and was served byte-identically, including HTTP 206 ranges. A
corrupt disposable catalogue was rebuilt and remained API-usable. Hashes of
masters, manifests, occurrence/event sidecars, and package metadata were
identical before and after the workflow.

The optional LAN profile is explicit (`rab_api_lan_enabled=true` plus
`rab_api_enabled=true`), installs nginx, requires an external hashed htpasswd
file, and proxies only `/api/` to the loopback backend. Unauthenticated access
returned 401, authenticated status/search/package/download access succeeded,
and payload/README bytes and ranges matched. Disabling the profile removed the
LAN listener while local API access remained healthy. Qualification used a
trusted isolated network without TLS; real hostile-network deployment must
place operator-supplied TLS at the reverse proxy. Authentication does not
grant redistribution rights.

## M2 qualification status

M2.2 includes the generic registry/acquisition boundary, deterministic Aminet
package synchronization, original companion-readme preservation,
version/deletion/recovery semantics, and a BitTorrent metadata foundation.
At that point remaining M2 gaps included live-network qualification, resource
hardening, and production torrent-client integration. Those areas are covered
by M2.3 below; the broad M2 acceptance scope is now complete, while FTP remains
an explicitly deferred non-blocking backend.

## M6.10 physical media intake and evidence

Implemented for deterministic fixture qualification: opaque physical-medium
and set identities, audited revisions, append-only conditions, CAS-backed
evidence, intake defaults, optical/removable/flux linkage, read-only API and
RetroWeb, redaction, and rebuildable reports. No real optical drive, block
device, or Greaseweazle hardware was exercised. Deep image analysis remains
M6.11. Museum-grade status remains **NO**.

## M2.3 qualification update (2026-08-18)

A bounded live qualification completed against the official Aminet mirror
`http://de.aminet.net/aminet/`, using explicit HTTP paths rather than a crawl.
The run acquired two real packages (`util/misc/rsync-2.5.5_bin` and
`util/cli/mirror`) and each original `.readme`, producing four immutable
objects and two COMPLETE logical packages. Exports matched direct upstream
downloads byte-for-byte. Re-running both package paths produced no additional
masters or occurrences; fixity audited four objects with zero failures.

The repository Aminet definition remains disabled and requires an explicit
operator-reviewed policy copy for a live run. The official mirror listing
identifies `de.aminet.net` as supporting HTTP and RSYNC; RAB uses conservative
HTTP paths for bounded qualification. FTP remains modeled but deferred because
it adds no capability to this qualified Aminet path. The aria2-backed torrent
content backend is implemented and tested with a deterministic client stub;
actual torrent-client execution remains an operational follow-up, not a reason
to weaken preservation or claim live torrent evidence. M2 is complete for the
defined acceptance scope; it is not museum-grade.
