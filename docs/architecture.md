# Architecture and preservation boundary

RAB separates the preservation plane from the convenience and analysis plane.

## Catalogue and API (M3)

`rab catalogue rebuild` reconstructs SQLite tables and an FTS5 index from
content-addressed manifests plus immutable occurrence, source-event, and
package-generation sidecars. SQLite supplies transactions, foreign keys,
migrations, FTS5, and concurrent reads without another daemon. No preservation
master is stored in the database. `status` reports indexed counts and `verify`
reports dangling or missing references; neither repairs preservation data.

The catalogue models objects, occurrences, packages, immutable generations,
generic relationships, rights, events, and many-to-many platform evidence.
Format identification and defensive text decoding are derived records; original
bytes remain authoritative. The read-only localhost API provides bounded
status/search/source/object/package lookups and no arbitrary file or write API.
The database can always be removed and rebuilt.

Catalogue schema upgrades are sequential and transactional; the shipped v1 to
v2 migration adds derived format evidence and leaves preservation records
untouched. A read-only API process validates rather than migrates the database,
so catalogue write ownership remains with the CLI/worker. The API is localhost
only by default and the Ansible unit is disabled unless explicitly enabled.
Object/package download requests resolve stable catalogue IDs, run fixity and
rights checks, then stream the preservation master with a sanitized filename.
No caller-supplied path is accepted. Local operator access is distinct from
future public redistribution: only REDISTRIBUTABLE occurrences may be served
in a public mode; PRIVATE_LICENSED, RESTRICTED, and UNKNOWN remain blocked.
Range requests are bounded to the object and streamed in chunks.

## Retro-Compatible Web v1

The web interface is a presentation layer, not another catalogue. A small
stdlib `http.server` service renders HTML from the existing `CatalogueAPI`,
`Catalogue`, and `ResourceBroker` boundaries. It has no JavaScript dependency,
client-side router, SPA, Node/npm pipeline, framework, CDN, external font,
analytics, or tracking. The normal `/web` view uses a small local conservative
stylesheet; `/retro` and the `--retro-only` listener omit it and use basic
document flow. Both views use ordinary GET forms, real hyperlinks, headings,
tables, and escaped server-rendered content.

RAB Web follows progressive enhancement. Core archive functionality is delivered
as server-rendered HTML and does not require JavaScript.

Routes cover home, bounded search/pagination, catalogue-derived platform and
configured source browsing, stable resource and resource-set pages, bounded
README text views, and rights-permitted object downloads. Resource pages expose
logical IDs, versions, kinds, availability, rights, hashes, provenance,
relationships, dependencies, malware status, and authority assertions without
object-store paths. Download responses delegate fixity, rights, filename
sanitization, streaming, and Range handling to the existing controlled
boundary.

The web process is read-only: catalogue and broker derived state must be built
by the operator/CLI before service startup, and web POST requests are rejected.
There are no administration, source, ingest, deletion, policy, materialization,
or arbitrary-path routes. Errors are simple bounded HTML without traces,
filesystem paths, SQL, or secrets. Stable logical URLs do not contain SQLite
row IDs and remain meaningful after derived-state rebuilds.

`rab-web.service` is disabled by default. `rab-retro-http.service` is a
separate, disabled-by-default optional profile for explicitly trusted LANs. It
binds only to the configured address and provides no confidentiality: HTTP must
not be exposed to the public Internet. This compatibility exception does not
weaken the authenticated API or reverse-proxy profile. Intended compatibility
includes conservative Netscape, IE, Amiga, Atari, classic Mac, and text-browser
families, but no vintage client is claimed qualified until actually tested.

## Malware Preservation & Analysis (M5)

Malware analysis is a separate evidence plane:

```text
immutable preservation master
        |
        +--> disposable read-only analysis copy --> scanner adapter
        |                                             |
        +--> immutable observation + raw report <-----+
```

`MalwareObservation` is versioned as `rab-malware-observation-v1`. It retains
object SHA-256, observation identity, scanner/vendor/product, scanner and
engine versions, signature version/date, timestamp, execution environment,
method, result, detections, coverage, warnings/errors, provenance, and a raw
result reference. Observations are never updated in place; later scans create
new sidecars. `malware.sqlite3` is only a derived index and `rab malware
rebuild` reconstructs it from observation sidecars/raw evidence.

The generic `ScannerAdapter` contract exposes capability, invocation, timeout,
output parsing, and normalized results. `CommandScanner` uses argument lists,
`shell=False`, bounded timeouts, and rejects destructive/quarantine/repair
options. The scanner target is copied from a verified master into a disposable
workspace, made read-only, and removed after execution. No scanner receives an
object-store path or write access to a master. Unknown output is
`INCONCLUSIVE`/`ERROR`, never clean.

ClamAV is the first operational Linux adapter (`clamscan`, exit/status and
`FOUND` output normalization). ESET, Avast, Sophos, and Bitdefender are generic
commercial adapter identities with capability detection; products may return
`LICENSE_REQUIRED` or `SUPPORTED_NOT_INSTALLED`. RAB does not bypass
licensing, install proprietary binaries, or embed credentials. The default
policy is preserve-and-record with no automatic background scan or quarantine.

Aggregate state is deterministic and evidence-preserving: any `DETECTED` is
`MALWARE_DETECTED`; otherwise `SUSPICIOUS` or `INCONCLUSIVE` is `SUSPICIOUS`;
clean with no failure is `CLEAN_OBSERVED`; only errors/unsupported observations
are `ANALYSIS_FAILED`; no observations is `UNKNOWN`. Clean means observed clean
under named scanner/signature evidence, not malware-free. Broker delivery may
use `allow`, `deny-detected`, or `require-analysis`; rights remain independent,
and detection never deletes, hides, or changes preservation identity.

Container scanning records `container-only` coverage. Optional ZIP/TAR
extraction is outside preservation storage and rejects absolute/traversal and
backslash paths, links/special files, excessive depth, file count, and expanded
size. It does not imply every nested or unsupported format was examined. Future
Amiga, DOS, Windows, Mac, and other native scanners consume Resource Broker
materialized copies in disposable emulators/VMs; masters are never writable or
mounted into those environments.

## Consumer Resource Broker v1

The broker is a derived consumer plane above M1 preservation and the M2/M3
catalogue. A resource is distinct from an object: it may name one object, a
package generation, multiple related files, or a resource set. Initial generic
kinds cover software packages, disk images, optical discs, ROMs, firmware,
operating-system media, BBS software, tools, drivers, documentation, and sets.
IDs such as `aminet:comm/term/ncomm307`,
`resource:amiga:kickstart:3.1:a1200`, `resource-set:amiga:a1200-os31:1`, and
`sha256:<64 hex>` are logical contracts; storage paths are never exposed.

Resolution is deterministic and evidence-bearing. Exact IDs and constrained
queries return `RESOLVED`, `NOT_FOUND`, `AMBIGUOUS`, `RIGHTS_DENIED`,
`UNAVAILABLE`, `INCOMPLETE`, or `POLICY_BLOCKED`; multiple candidates are
never silently selected. Descriptors include sizes/hashes, provenance, rights,
authority assertions, availability, dependencies, delivery policy, and a
future-compatible malware status enum. Version strings are exact strings.
TOSEC/Redump requirements are optional evidence constraints and never alter
preservation identity.

Consumers provide an ID, type, local/remote status, purpose, delivery mode,
rights context, and optional machine profile. Rights are separate from
recognition: local-owner delivery may be policy-permitted for private material,
while public delivery requires `REDISTRIBUTABLE`. Modes are `STREAM`, `COPY`,
`MATERIALIZE`, and `MANIFEST_ONLY`. Existing verified chunked downloads are
reused for streaming; materialization copies in chunks and preserves structured
relationships without flattening BIN/CUE or similar assets.

Pinning produces `rab-resource-manifest-v1`, a commit-friendly lock containing
the resource ID, exact object IDs/hashes, package generation, consumer context,
rights snapshot, dependencies, authority evidence, and delivery mode. Resource
sets retain roles and individual identities; later content creates a new
generation. Definitions and set generations are immutable JSON sidecars under
`resource-metadata`; broker SQLite and consumer caches are disposable. Rebuild
therefore restores logical resolution without touching masters. Workspaces are
controlled beneath `consumer-state/<consumer>` and reject traversal, symlink
escape, unsafe names, and collisions. Broker operational events do not append
ordinary-read preservation events. BBS use stops at staging; Time Machine and
DRD consumers own runtime behavior. Malware analysis and approved on-demand
acquisition are future policy hooks only.

## Production exposure qualification

The Debian 13 qualification appliance proved first/second Ansible runs of
14/0 changes, the `rab` service identity, effective systemd hardening, and a
loopback-only backend listener. The optional LAN profile installs nginx only
when `rab_api_lan_enabled` is explicitly true, requires an external htpasswd
file, proxies only `/api/` to `127.0.0.1:8000`, and returns 404 elsewhere.
Unauthenticated requests receive 401; authenticated requests can use the same
catalogue and streaming download service. Disabling the profile removes the
proxy configuration and stops nginx while the loopback API remains available.
The qualification used a trusted isolated test network; hostile-network LAN
use requires operator-supplied TLS at the reverse proxy. Authentication never
implies redistribution rights.

```text
source occurrence -> verified staging copy -> immutable SHA-256 object
                                             | manifest + occurrences + events
                                             +-> read-only analysis/export input
                                                   -> disposable copy/overlay
                                                   -> derivative (when retained)
```

The SQLite catalogue is disposable indexing infrastructure. Critical identity,
fixity, provenance, rights, relationship, and event data are stored in the
content-addressed object tree. One payload is stored for byte-identical content;
every acquisition remains an independent occurrence.

Payload permissions are a guard, not the entire immutability design. Production
deployment should place the object tree on snapshot-capable storage, expose it
read-only to Web/API/emulator services, and grant write access only to a narrow
ingest service account. Append-only/offline replication remains necessary.

## Policy invariants

- Detection creates an event and never deletes, cleans, or repairs a master.
- Export verifies the input and the emitted bytes.
- Existing export paths are never silently overwritten.
- Changed content becomes another object. A retained transformation must carry
  an explicit `derived_from` relationship.
- Emulator inputs are read-only and sessions use disposable overlays.
- Source accessibility is not acquisition permission or redistribution rights.

## Generic source and acquisition architecture

Source definitions are typed JSON policies loaded by `SourceRegistry`. They
separate accessibility from authority: a cooperative mirror with an `allowed`
bulk policy is invalid unless `mirror_authorized` is explicit, and a bulk run
also requires the source to be enabled. Supported source classes are MIRROR,
COOPERATIVE_MIRROR, ARCHIVE_COLLECTION, HISTORICAL_MIRROR, INGEST,
PRESERVATION_DATABASE, and PHYSICAL_MEDIA. Initial backends are rsync,
HTTP/HTTPS, and BitTorrent metadata/import; FTP is represented but is not yet a
production crawler. HTTP acquisition is bounded to explicit paths for
qualification and package pairing.

Acquisition writes only to `source-staging`. Completed transfers are hashed and
optionally checked against an expected SHA-256 before calling the existing M1
`Archive.ingest` boundary. `.part` files are rejected. HTTP uses timeouts, an
identifiable User-Agent, bounded retries/backoff, explicit redirect policy,
free-space/staging-limit preflight, and Range resume where the server supports
it. Configured HTTP bandwidth limits are enforced by streaming throttling.
rsync uses partial/delayed updates against staging and never uses deletion flags
or targets preservation storage. Source state is separate
from preservation state, so upstream disappearance records an event and marks
the occurrence/package absent without deleting any object.

## Aminet packages

An Aminet logical ID such as `aminet:comm/term/ncomm307` links independently
preserved `comm/term/ncomm307.lha` and `comm/term/ncomm307.readme` objects.
Neither is concatenated or rewritten. Parsed Latin-1 readme fields are catalogue
metadata only. Completeness is COMPLETE, PAYLOAD_MISSING, README_MISSING, or
ACQUISITION_FAILED. Each changed payload/readme pairing creates a package
generation; old objects and relationships remain reconstructable. Identical
re-syncs add neither package generations nor redundant occurrences.
Immutable per-generation JSON sidecars under `source-metadata/packages` retain
these relationships independently of the catalogue database; structured source
events are likewise written as immutable sidecars under `source-metadata/events`.

## BitTorrent bootstrap and polite operation

RAB preserves the original `.torrent` as an immutable object, calculates the
BitTorrent v1 infohash from the exact bencoded `info` dictionary bytes, and
records a source event linking metadata, provenance, and import. This supports
an operator-managed torrent bootstrap followed by later policy-permitted source
synchronization. When explicitly requested, the BitTorrent backend invokes
Debian-packaged `aria2c` with a staging-only destination, continuation,
piece-integrity checking, no seeding, bounded connections, and optional download
limit. Missing client binaries fail after metadata preservation.

Provisioning installs Debian rsync and a hardened `rab-source@.service` template,
but deliberately installs no source timer and starts no mirror. Scheduling is
source-specific operator policy; the shipped Aminet definition suggests weekly
operation, remains disabled, and contains conservative concurrency/retry hints.

## Generic external authorities (M4.1)

Official TOSEC DAT/archive bytes first cross the M1 boundary. Immutable dataset
metadata under `authority-metadata/datasets` records release identity, source
object, hashes, parser version, rights, and import status. Parsed records, hash
indexes, and assertions live in disposable `authority.sqlite3`; deleting it and
running `rab authority rebuild` reparses preserved source objects.

Assertions retain authority, release, object identity, result, matching method,
matched hashes, canonical name, and evidence. Matching uses SHA-1+size, then
MD5+size, then CRC32+size. Filename matching is never exact identity; ambiguous
records and stronger-hash conflicts remain visible. TOSEC XML DAT headers and
`game`/`rom` records are supported, including canonical name, system/category,
ROM name, size, CRC32, MD5, SHA-1, status, and extra attributes. Unsafe XML
declarations and malformed input fail in a controlled way after preservation.

The generic authority type leaves room for Redump, SPS, No-Intro, and MAME.
Amiga FDB files are historical catalogues/manifests, not verification
authorities. TOSEC assertions never change content rights. `config/platforms.json`
records the broader Amiga, neo-retro, and FPGA/recreation scope without forcing
mappings. Archive.org direct-item and explicitly authorized collection
archaeology, torrent transport selection, and mixed-mode track preservation
remain future M7 requirements.

## M4.1a real TOSEC qualification

The official TOSECdev release dated 2025-03-13 was downloaded once from the
TOSECdev download page and preserved as an M1 object. Its ZIP contains 4,743
DAT files and 10,892 total files; the bounded RAB qualification selected five
DATs rather than importing the whole 406,387,879-byte uncompressed DAT corpus:

- `Commodore Amiga - Games - [ADF] (TOSEC-v2025-01-30_CM).dat`
- `Commodore C64 - Games - Adventure - [D64] (TOSEC-v2025-02-16_CM).dat`
- `Atari ST - Applications - [RAW] (TOSEC-v2023-06-14_CM).dat`
- `Atari ST - Games - [ST] (TOSEC-v2025-01-15_CM).dat`
- `Sinclair ZX Spectrum - Games - [TAP] (TOSEC-v2025-01-15_CM).dat`

The preserved ZIP is 100,621,631 bytes with SHA-256
`769dbd9cc6b28787a094fcaea83dd9ad91decfdec7de50db4af163fe96b9f25e`, BLAKE3
`e96c9b91c9a8bd642bdb559bef83ec751879bfa981048e36a272beb9f3aeef1c`, SHA-1
`7f4c244233dc369ad4804a58ae1827a0aeaa02da`, MD5
`1c5b728e6bb73cc58ebb731057cff1d5`, and CRC32 `f5ba5318`. The selected import
created 88,030 records. SHA-1, MD5, and CRC32 were present on all 88,030;
there were no invalid sizes or duplicate SHA-1+size combinations. The pack
had no `status` attributes in the selected subset. The Atari ST RAW DAT
contained 14 multi-ROM game records and 2,352 ROM records; all other selected
DATs were single-ROM records. UTF-8 names including `François`, `Hlípa`, and
`æ`, plus TOSEC bracket/status-like name syntax, were preserved byte-for-byte.

Real DATs use the Logiqx external `DOCTYPE` declaration. RAB now accepts that
declaration with stdlib `ElementTree`, which does not fetch the external DTD,
while rejecting `ENTITY` declarations. Input remains size-bounded and no
filesystem or shell access is derived from names. The real parser required no
other format-specific workaround.

The real indexed query plan uses `records_hash_size` for SHA-1+size lookups;
ordinary matching does not load or scan every authority record in Python.
`authority verify` passed, and deleting `authority.sqlite3` followed by
`rab authority rebuild` yielded 88,030 records and semantically equivalent
datasets, records, mappings, and assertions. The only assertion in the
qualification root was `NO_MATCH` for the preserved ZIP object itself. No
legally suitable matching content object was available, so real content
`EXACT_MATCH` is explicitly **NOT QUALIFIED**. Synthetic exact, rights,
ambiguity, conflict, and historical-release tests remain required and pass.

## Redump optical authority (M4.2)

TOSEC and Redump share the generic authority dataset, preservation, assertion,
verification, and rebuild boundary, but their record models remain distinct.
TOSEC records are flat file/hash records. Redump records are physical-disc
descriptions assembled from official Redump DAT metadata and official CUE
layout artifacts:

```text
Redump dataset
  disc: canonical title/system/category
    session: session number
      track: number, data/audio type, mode, sector size/count,
             INDEX/PREGAP/POSTGAP, file name, CRC32/MD5/SHA-1
```

`redump_discs`, `redump_files`, `redump_tracks`, and `redump_signatures` are
disposable authority tables in `authority.sqlite3`. CUE/BIN, CCD/IMG/SUB, CHD,
ISO data-track extractions, and future physical observations can be represented
as optical representations without claiming byte equivalence. M4.2 does not
implement ripping or conversion.

The Redump adapter selects candidates through indexed track-count/layout
signatures and then compares ordered sessions/tracks, type/mode, sector
geometry, LBA/index data, size, and supplied hashes. Full-disc `EXACT_MATCH`
requires all observed tracks to correspond structurally and have sufficient
hash evidence. Partial representations return `NOT_APPLICABLE`; same-layout
hash or structural disagreement returns `CONFLICT`; multiple valid records
remain `AMBIGUOUS`. Title, filename, volume label, or one matching track is
never sufficient.

### Bounded real Redump qualification

The official Redump project endpoints were used, not a mirror or content set:
`http://redump.org/datfile/acd/` and `http://redump.org/cues/acd/`. The selected
release is `Commodore - Amiga CD - Datfile (596) (2026-06-02 00-27-14).zip`
plus the matching `Commodore - Amiga CD - Cuesheets (596) (2026-06-02 00-27-14).zip`.
The DAT artifact is 109,464 bytes and the CUE artifact is 161,358 bytes; both
were preserved as separate M1 objects. Their SHA-256 values are
`8361cf99242082adc1819e27ba36696f2ebf934124d3aafd8b759675d2f00442` and
`4969e78c91f0386995fbc788566f20668c5c2e0f742280e1c6a23c1b41115234`.
The DAT BLAKE3/SHA-1/MD5/CRC32 values are
`bbcf7b90d91ec6362a50265b2f1d45a1c1aaa86c0bb4cb310337b3f4ef27dfd3`,
`57e17d6fcb0e9e55192b3dbcc9523906e7a6fc82`, `1554b3cec548e10e11b3c9514f46d4ca`,
and `07293b0b`; the CUE values are
`7c619b9a9842e9d04c157d441332d950cf1519d2c86318b2caa7b5bfecc849d4`,
`276cd8c89d747f0a6b516ac72d8be64a9e8716fc`, `bb4bd2441f234a049e223f5ee04ff624`,
and `af129d60`.

The real import produced 596 discs and 942 tracks, all with CRC32, MD5, and
SHA-1. It observed 599 data tracks, 343 audio tracks, 593 MODE1/2352 tracks,
and 6 MODE2/2352 tracks. Sixty-one discs were multi-track and three used more
than one session. All discs had matching official CUE members. Pregap/postgap
was absent from this bounded Amiga subset, while INDEX 01 and multi-session
layout were present. The Redump platform name `Commodore Amiga CD` maps once,
conservatively, to RAB `amiga`; no architecture claim is inferred.

`authority verify` passed. Deleting `authority.sqlite3` and rebuilding from
the two preserved source objects reconstructed 596 discs and 942 tracks with
semantic equivalence. Existing object masters and sidecars remained unchanged.
No copyrighted disc image was downloaded, so a real legal disc
`EXACT_MATCH` is **NOT QUALIFIED**. Synthetic single-track, mixed-mode,
partial, conflict, ordering, rights, API, and rebuild tests remain
network-independent.

## Authority purpose and evidence scope (M4.3)

Authority purpose is contextual and is never converted into a global ranking:

| Authority | Purpose | What it can establish |
|---|---|---|
| TOSEC | `IDENTIFICATION` | broad historical file/software identification |
| Redump | `STRUCTURAL_VERIFICATION` | complete optical disc/session/track evidence |
| No-Intro | `IDENTIFICATION` | ROM/cartridge/firmware component identity |
| SPS/CAPS/IPF | `DUMP_VERIFICATION` | format-specific floppy preservation evidence |
| MAME | `EMULATION_REFERENCE`, `IDENTIFICATION` | emulation-list component reference |
| FDB | `HISTORICAL_CATALOGUE`, `HISTORICAL_MANIFEST` | historical inventory/discovery clues |

An assertion exposes its authority and `authority_purpose` independently.
Cross-authority disagreement is retained as independent assertions. Rights and
future malware observations are separate state and are never changed by an
authority match. FDB remains historical evidence, not dump verification.

## Component authorities (M4.3)

`component_records` is the disposable indexed component model used by No-Intro
and MAME. It preserves entry ID, canonical name, original system, component
type, component name, size, CRC32, MD5, SHA-1, and raw metadata. MAME `ROM` and
`DISK` components remain distinct; a component match is explicitly marked
`component_only` and does not identify a complete software entry or an optical
disc. MAME CHD references therefore remain independent of Redump optical
identity and RAB preservation SHA-256.

MAME candidate lookup uses indexed SHA-1/size, MD5/size, or CRC32/size queries
where those fields exist. Disk components may have SHA-1 without a size. The
No-Intro adapter uses the same component model and conservative hash semantics.
No filename-only match is possible.

## No-Intro and SPS qualification boundaries

The official No-Intro DAT-o-MATIC service is public and documents its standard
DAT/P-C/XML outputs, anti-piracy policy and system-specific organization. Its
current download action is a stateful dynamic POST/token flow; the qualification
environment could inspect the official catalog but could not obtain the
official DAT artifact through a simple non-authenticated automated request.
RAB therefore does not claim real No-Intro qualification and does not use an
Archive.org No-Intro collection as a substitute.

The official SPS/Softpres site did not provide a usable public machine-readable
authority artifact in this qualification environment. RAB classifies SPS as
`DUMP_VERIFICATION` and keeps the future representation boundary explicit:
filesystem extraction, sector image, track image, flux/low-level image and IPF
are distinct representations and are not automatically equivalent. No SPS IPF
library, tool, membership area, or copyrighted image was bypassed or imported.
SPS real qualification is **NOT QUALIFIED** pending a legitimate public
authority-data route.

## Bounded official MAME qualification

Official MAME metadata was read from the `mamedev/mame` repository at commit
`17e1e9419edc5c483bc6a4a387c7e1d7b7341e32`. The bounded preserved subset was
`hash/amiga_flop.xml` (410,553 bytes) and `hash/amiga_cd.xml` (15,524 bytes),
both obtained from official raw GitHub URLs at that commit. SHA-256 values are
`39f82788640d4de030182fa5f16b541e58d9f9fd2b13814b7cb850cc8a8d5400` and
`b65a05f8d7841d1791cac6e792283917c6da8c81ffe5db99b8d048bad0fcc23a`.

The real MAME import produced 792 software entries and 801 components: 779
ROM components and 22 disk components. SHA-1 coverage was 801/801, CRC32
coverage 779/801, and MD5 was absent from this subset. Parts, interfaces,
`dataarea`/`diskarea`, supported status, descriptions, years, publishers and
other original metadata were preserved. `authority verify` passed; deleting
the authority DB and rebuilding from the two M1 objects produced semantic
equivalence and byte-identical preservation objects. No content images were
downloaded, so real legal content `EXACT_MATCH` is **NOT QUALIFIED**.
