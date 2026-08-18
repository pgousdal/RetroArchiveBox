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
