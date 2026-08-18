from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class Rights(StrEnum):
    REDISTRIBUTABLE = "REDISTRIBUTABLE"
    PRIVATE_LICENSED = "PRIVATE_LICENSED"
    RESTRICTED = "RESTRICTED"
    UNKNOWN = "UNKNOWN"


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


@dataclass(frozen=True)
class IngestRequest:
    path: Path
    source: str
    source_path: str
    rights: Rights
    media_type: str
    title: str | None = None
    derived_from: str | None = None

