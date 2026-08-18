# v0.1 milestone status

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

