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

## M2 qualification status

M2.2 includes the generic registry/acquisition boundary, deterministic Aminet
package synchronization, original companion-readme preservation,
version/deletion/recovery semantics, and a BitTorrent metadata foundation.
Remaining M2 gaps include production operational experience with reviewed
Aminet authorization, bandwidth-limit enforcement (the policy field exists), a
production FTP crawler, invoking an external torrent client, and live-network
qualification. The broad M2 programme is not claimed complete beyond the local,
deterministic acceptance scope.
