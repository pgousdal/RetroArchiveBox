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

M4.2 is reserved for Redump and M4.3 for additional authorities. Historical
Amiga FDB datasets remain historical catalogues/manifests. Archive.org direct
item/collection archaeology, explicit collection authorization, official
torrent transport selection, and TOSEC content bootstrapping remain future M7
requirements. Expanded Amiga, neo-retro, and FPGA/recreation scope is recorded
in `config/platforms.json`; M4.1 does not claim those ecosystems are covered by
TOSEC.

M4.1 implementation status: the generic framework and deterministic synthetic
qualification are implemented. Bounded qualification against a real official
TOSEC release was not performed in this environment, so M4.1 remains
**INCOMPLETE / NOT QUALIFIED** and no museum-grade claim is made.

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
