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

## M3 catalogue, search & API

M3 adds a disposable, versioned SQLite/FTS5 catalogue, deterministic rebuild
from preservation metadata, generic relationships and platform evidence,
format identification, safe historical-text extraction, structured bounded
search, JSON CLI inspection, and a read-only localhost API. The hard acceptance
property is semantic equivalence after deleting `catalogue.sqlite3` and running
`rab catalogue rebuild`; preservation-tree state is unchanged. API download,
authentication, authority matching, malware assertions, and the Web UI remain
future work. M3 is catalogue-complete for the current scope, not museum-grade.

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
