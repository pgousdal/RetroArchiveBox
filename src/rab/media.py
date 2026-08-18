from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class RepresentationKind(StrEnum):
    LOGICAL_EXTRACTION = "LOGICAL_EXTRACTION"
    SECTOR_IMAGE = "SECTOR_IMAGE"
    TRACK_IMAGE = "TRACK_IMAGE"
    FLUX_IMAGE = "FLUX_IMAGE"
    PRESERVATION_FORMAT = "PRESERVATION_FORMAT"


class RepresentationRelation(StrEnum):
    COMPLETE_DISC_REPRESENTATION = "COMPLETE_DISC_REPRESENTATION"
    TRACK_REPRESENTATION = "TRACK_REPRESENTATION"
    DATA_TRACK_EXTRACTION = "DATA_TRACK_EXTRACTION"
    LOSSLESS_DERIVATIVE = "LOSSLESS_DERIVATIVE"
    FILESYSTEM_EXTRACTION = "FILESYSTEM_EXTRACTION"


@dataclass(frozen=True)
class MediaRepresentation:
    object_id: str
    kind: RepresentationKind
    media_family: str
    source_object: str | None = None
    relation: RepresentationRelation | None = None
    evidence: dict | None = None
