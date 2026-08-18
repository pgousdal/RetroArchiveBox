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
rab show aminet:comm/term/ncomm307
rab get aminet:comm/term/ncomm307 --output ./package --with-readme
pytest
```

The database is an index, not the sole metadata store. Each object directory
contains a canonical manifest and append-only JSON Lines event log sufficient
to reconstruct the principal preservation catalogue.

See [docs/architecture.md](docs/architecture.md) and
[docs/roadmap.md](docs/roadmap.md) for boundaries and milestone status.
