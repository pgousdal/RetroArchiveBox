# Verification authority configuration

Exact imported Redump, TOSEC, SPS/CAPS, No-Intro, MAME, and upstream dataset
artifacts belong in the preservation store. An authority assertion must record
the dataset object identity and version; a bare boolean is invalid.

Official TOSEC DATs are `VERIFICATION_AUTHORITY` data. Archive.org collections
labelled TOSEC are acquisition sources only and cannot create TOSEC assertions.
Historical Amiga FDB files are `HISTORICAL_CATALOGUE` or
`HISTORICAL_MANIFEST`, not verification authorities.

Redump DAT and CUE artifacts are `VERIFICATION_AUTHORITY` data describing
disc structure. A preserved ISO/data-track extraction is not automatically a
complete Redump disc representation, and Redump identification does not grant
redistribution rights.

Purpose classifications are maintained in `purposes.json`. They describe what
an authority's evidence applies to; they are not a cross-authority trust
ranking. MAME component identification and No-Intro ROM identification do not
establish Redump optical structure. SPS remains modeled as floppy
`DUMP_VERIFICATION` pending a legitimate public machine-readable source.
