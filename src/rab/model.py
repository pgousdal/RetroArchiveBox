from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class Rights(StrEnum):
    REDISTRIBUTABLE = "REDISTRIBUTABLE"
    PRIVATE_LICENSED = "PRIVATE_LICENSED"
    RESTRICTED = "RESTRICTED"
    UNKNOWN = "UNKNOWN"


class AuthorityPurpose(StrEnum):
    IDENTIFICATION = "IDENTIFICATION"
    STRUCTURAL_VERIFICATION = "STRUCTURAL_VERIFICATION"
    DUMP_VERIFICATION = "DUMP_VERIFICATION"
    HISTORICAL_CATALOGUE = "HISTORICAL_CATALOGUE"
    HISTORICAL_MANIFEST = "HISTORICAL_MANIFEST"
    EMULATION_REFERENCE = "EMULATION_REFERENCE"


class PreservationState(StrEnum):
    MASTER = "MASTER"
    DERIVATIVE = "DERIVATIVE"


class SourceClass(StrEnum):
    MIRROR = "MIRROR"
    COOPERATIVE_MIRROR = "COOPERATIVE_MIRROR"
    ARCHIVE_COLLECTION = "ARCHIVE_COLLECTION"
    PRESERVATION_DATABASE = "PRESERVATION_DATABASE"
    HISTORICAL_MIRROR = "HISTORICAL_MIRROR"
    INGEST = "INGEST"
    PHYSICAL_MEDIA = "PHYSICAL_MEDIA"


class Backend(StrEnum):
    RSYNC = "rsync"
    HTTP = "http"
    HTTPS = "https"
    FTP = "ftp"
    BITTORRENT = "bittorrent"
    MANUAL = "manual"
    PHYSICAL_MEDIA = "physical-media"
    ARCHIVE_ORG_TARGETED = "archive-org-targeted"


class Completeness(StrEnum):
    COMPLETE = "COMPLETE"
    PAYLOAD_MISSING = "PAYLOAD_MISSING"
    README_MISSING = "README_MISSING"
    ACQUISITION_FAILED = "ACQUISITION_FAILED"


@dataclass(frozen=True)
class IngestRequest:
    path: Path
    source: str
    source_path: str
    rights: Rights
    media_type: str
    title: str | None = None
    derived_from: str | None = None
    provenance_classification: str = "unknown"
    provenance: dict | None = None
