# Verification authority configuration

Exact imported Redump, TOSEC, SPS/CAPS, No-Intro, MAME, and upstream dataset
artifacts belong in the preservation store. An authority assertion must record
the dataset object identity and version; a bare boolean is invalid.

Official TOSEC DATs are `VERIFICATION_AUTHORITY` data. Archive.org collections
labelled TOSEC are acquisition sources only and cannot create TOSEC assertions.
Historical Amiga FDB files are `HISTORICAL_CATALOGUE` or
`HISTORICAL_MANIFEST`, not verification authorities.
