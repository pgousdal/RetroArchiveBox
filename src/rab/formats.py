from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FormatIdentification:
    format_id: str
    method: str
    confidence: float


def identify_format(data: bytes, *, name: str = "", media_type: str = "") -> FormatIdentification:
    lower = (name or "").lower()
    if data.startswith(b"PK\x03\x04"):
        return FormatIdentification("zip", "magic", 1.0)
    if data.startswith(b"\x1f\x8b"):
        return FormatIdentification("gzip", "magic", 1.0)
    if data.startswith(b"BZh"):
        return FormatIdentification("bzip2", "magic", 1.0)
    if data.startswith(b"\xfd7zXZ\x00"):
        return FormatIdentification("xz", "magic", 1.0)
    if data.startswith(b"7z\xbc\xaf'\x1c"):
        return FormatIdentification("7z", "magic", 1.0)
    if lower.endswith((".lha", ".lzh")):
        return FormatIdentification("lha", "extension", 0.8)
    if len(data) >= 2 and data[2:5] in {b"-lh", b"-lz", b"-pm"}:
        return FormatIdentification("lha", "structural", 0.98)
    if data.startswith(b"DMS!"):
        return FormatIdentification("dms", "magic", 1.0)
    if data.startswith(b"RDSK"):
        return FormatIdentification("hdf", "magic", 0.98)
    if data.startswith(b"GCR-1541"):
        return FormatIdentification("g64", "magic", 1.0)
    if data.startswith(b"C64 tape image file"):
        return FormatIdentification("t64", "magic", 1.0)
    if data.startswith(b"MSA"):
        return FormatIdentification("msa", "magic", 1.0)
    if data.startswith(b"\x96\x02"):
        return FormatIdentification("atr", "magic", 0.98)
    if data.startswith(b"FORM") and len(data) >= 12:
        return FormatIdentification("iff", "structural", 0.99)
    if len(data) >= 32774 and data[32769:32774] == b"CD001":
        return FormatIdentification("iso", "magic", 1.0)
    if len(data) >= 512 and data[257:262] == b"ustar":
        return FormatIdentification("tar", "structural", 1.0)
    if data.startswith(b"d") and b"4:info" in data[:4096]:
        return FormatIdentification("torrent", "structural", 0.95)
    if lower.endswith((".readme", ".txt", ".nfo", ".diz")) or media_type.startswith("text/"):
        return FormatIdentification("text", "source-metadata", 0.9)
    if lower.endswith((".adf", ".adz")) or len(data) in {901120, 911360, 176400, 180224}:
        return FormatIdentification("adf", "extension" if lower.endswith((".adf", ".adz")) else "structural", 0.8)
    if lower.endswith(".cue"):
        return FormatIdentification("cue", "extension", 0.8)
    if lower.endswith(".bin"):
        return FormatIdentification("bin", "extension", 0.45)
    if len(data) in {174848, 175531, 196608, 197376}:
        return FormatIdentification("d64", "structural", 0.85)
    if len(data) in {349696, 351062}:
        return FormatIdentification("d71", "structural", 0.85)
    if len(data) in {819200, 822400}:
        return FormatIdentification("d81", "structural", 0.85)
    if len(data) in {368640, 737280, 1474560}:
        return FormatIdentification("raw-disk-image", "size", 0.5)
    if len(data) > 0 and all(byte in {9, 10, 13} or 32 <= byte < 127 for byte in data[: min(len(data), 4096)]):
        return FormatIdentification("text", "content", 0.65)
    return FormatIdentification("binary", "fallback", 0.2)
