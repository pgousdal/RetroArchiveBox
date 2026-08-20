"""Bounded, non-mutating structural and contained-object analysis.

Analyzers receive disposable read-only copies. Exact recovered bytes enter the
normal CAS; observations and jobs are sidecars and never replace masters.
"""
from __future__ import annotations

import bz2
import gzip
import hashlib
import json
import lzma
import shutil
import stat
import tarfile
import tempfile
import time
import uuid
import zipfile
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath

from .errors import PolicyError, RabError
from .formats import identify_format
from .hashing import hash_file
from .identity import IdentityCatalogue, RelationshipType
from .malware import MalwareStore
from .media import RepresentationKind
from .model import IngestRequest, Rights


def _now(): return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


POLICIES = {"metadata-only", "identify", "preserve", "archival"}


class AnalysisState(StrEnum):
    PLANNED = "PLANNED"
    RUNNING = "RUNNING"
    COMPLETE = "COMPLETE"
    COMPLETE_WITH_WARNINGS = "COMPLETE_WITH_WARNINGS"
    PARTIAL = "PARTIAL"
    UNSUPPORTED = "UNSUPPORTED"
    TOOL_MISSING = "TOOL_MISSING"
    TIMEOUT = "TIMEOUT"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    MALFORMED = "MALFORMED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class AnalysisLimits:
    max_depth: int = 3
    max_files: int = 1000
    max_bytes: int = 256 * 1024 * 1024
    max_single_bytes: int = 64 * 1024 * 1024
    max_members: int = 10000
    max_ratio: int = 1000
    max_seconds: float = 30.0
    max_nested: int = 32
    subprocess_timeout: float = 30.0
    max_output_bytes: int = 64 * 1024
    follow_symlinks: bool = False

    def validate(self):
        numeric = (self.max_depth, self.max_files, self.max_bytes, self.max_single_bytes, self.max_members, self.max_ratio, self.max_seconds, self.max_nested, self.subprocess_timeout, self.max_output_bytes)
        if any(x <= 0 for x in numeric): raise PolicyError("analysis limits must be positive")


class LimitReached(Exception): pass
class ToolMissing(Exception): pass
class MalformedInput(Exception): pass


class AnalyzerAdapter:
    analyzer_id = "generic"
    implementation = "rab"
    version = "1"
    supported_formats = ()
    supported_representations = (RepresentationKind.UNKNOWN_DATA.value,)
    capability = "inventory-and-extract"
    confidence = 1.0
    external_tool = None
    deterministic = True
    available = True

    def probe(self, path: Path, *, name: str = "") -> bool: raise NotImplementedError
    def list_members(self, path: Path, limits: AnalysisLimits) -> tuple[list[dict], list[str]]: raise NotImplementedError
    def materialize_member(self, path: Path, member: dict, destination: Path, limits: AnalysisLimits) -> None: raise NotImplementedError

    def describe(self):
        return {"analyzer_id": self.analyzer_id, "implementation": self.implementation, "version": self.version,
                "supported_formats": list(self.supported_formats), "supported_representations": list(self.supported_representations),
                "capability": self.capability, "confidence": self.confidence, "external_tool": self.external_tool,
                "external_tool_required": bool(self.external_tool), "deterministic": self.deterministic,
                "available": self.available, "read_only": True}


ContainerAnalyzer = AnalyzerAdapter  # compatibility with the original M6.11 API


def _safe_logical(name: str) -> str:
    if not isinstance(name, str) or "\x00" in name: raise PolicyError("unsafe member name")
    normalized = name.replace("\\", "/"); path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts or (path.parts and ":" in path.parts[0]): raise PolicyError("member path escapes analysis root")
    return "/".join(x for x in path.parts if x not in {"", "."}) or "member"


def _bounded_copy(source, destination: Path, maximum: int):
    total = 0; destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as output:
        while True:
            chunk = source.read(min(1024 * 1024, maximum - total + 1))
            if not chunk: break
            total += len(chunk)
            if total > maximum: raise LimitReached("max_single_bytes")
            output.write(chunk)
    destination.chmod(0o440)


def _bounded_region(source, destination: Path, offset: int, size: int, maximum: int):
    if size < 0 or offset < 0 or size > maximum: raise LimitReached("max_single_bytes")
    source.seek(offset); total = 0; destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as output:
        while total < size:
            chunk = source.read(min(1024 * 1024, size - total))
            if not chunk: raise MalformedInput("member ended before declared size")
            total += len(chunk); output.write(chunk)
    destination.chmod(0o440)


class ZipAnalyzer(AnalyzerAdapter):
    analyzer_id, supported_formats = "zip", ("zip",)
    supported_representations = (RepresentationKind.ARCHIVE.value,)
    def probe(self, path, *, name=""):
        try:
            with path.open("rb") as source: magic = source.read(4)
            return magic.startswith(b"PK") or zipfile.is_zipfile(path)
        except OSError: return False
    def list_members(self, path, limits):
        members, warnings = [], []
        try:
            with zipfile.ZipFile(path) as archive:
                infos = archive.infolist()
                if len(infos) > limits.max_members: raise LimitReached("max_members")
                for info in infos:
                    try: logical = _safe_logical(info.filename)
                    except PolicyError as exc: warnings.append(str(exc)); continue
                    mode = (info.external_attr >> 16) & 0o170000
                    if mode == stat.S_IFLNK or info.is_dir(): warnings.append("member skipped: symlink or directory " + logical); continue
                    ratio = info.file_size / max(info.compress_size, 1)
                    if info.file_size > limits.max_single_bytes or ratio > limits.max_ratio: warnings.append("LIMIT_EXCEEDED: " + logical); continue
                    members.append({"logical_path": logical, "raw_name": info.filename.encode("utf-8", "surrogatepass").hex(), "size": info.file_size, "compressed_size": info.compress_size, "metadata": {"date_time": info.date_time}, "name": info.filename, "representation": RepresentationKind.FILE.value})
        except zipfile.BadZipFile as exc: raise MalformedInput("malformed ZIP archive") from exc
        return members, warnings
    def materialize_member(self, path, member, destination, limits):
        with zipfile.ZipFile(path) as archive, archive.open(member["name"]) as source: _bounded_copy(source, destination, limits.max_single_bytes)


class TarAnalyzer(AnalyzerAdapter):
    analyzer_id, supported_formats = "tar", ("tar", "gzip", "bzip2", "xz")
    supported_representations = (RepresentationKind.ARCHIVE.value,)
    def probe(self, path, *, name=""):
        try: return tarfile.is_tarfile(path)
        except OSError: return False
    def list_members(self, path, limits):
        members, warnings = [], []
        try:
            with tarfile.open(path, "r:*") as archive:
                infos = archive.getmembers()
                if len(infos) > limits.max_members: raise LimitReached("max_members")
                for info in infos:
                    try: logical = _safe_logical(info.name)
                    except PolicyError as exc: warnings.append(str(exc)); continue
                    if not info.isfile() or info.issym() or info.islnk(): warnings.append("member skipped: non-regular " + logical); continue
                    if info.size > limits.max_single_bytes: warnings.append("LIMIT_EXCEEDED: " + logical); continue
                    members.append({"logical_path": logical, "raw_name": info.name.encode("utf-8", "surrogatepass").hex(), "size": info.size, "metadata": {"mode": info.mode, "mtime": info.mtime}, "name": info.name, "representation": RepresentationKind.FILE.value})
        except tarfile.TarError as exc: raise MalformedInput("malformed TAR archive") from exc
        return members, warnings
    def materialize_member(self, path, member, destination, limits):
        with tarfile.open(path, "r:*") as archive:
            info = archive.getmember(member["name"]); source = archive.extractfile(info)
            if source is None: raise MalformedInput("TAR member is not readable")
            with source: _bounded_copy(source, destination, limits.max_single_bytes)


class SingleStreamAnalyzer(AnalyzerAdapter):
    supported_representations = (RepresentationKind.ARCHIVE.value,)
    def __init__(self, analyzer_id, opener, suffixes, magic): self.analyzer_id, self.opener, self.suffixes, self.magic, self.supported_formats = analyzer_id, opener, suffixes, magic, (analyzer_id,)
    def probe(self, path, *, name=""):
        with path.open("rb") as source: prefix = source.read(len(self.magic))
        return prefix == self.magic or (any(name.lower().endswith(x) for x in self.suffixes) and prefix == self.magic)
    def list_members(self, path, limits): return [{"logical_path": _safe_logical(Path(path).stem), "size": None, "metadata": {}, "name": Path(path).name, "representation": RepresentationKind.FILE.value}], []
    def materialize_member(self, path, member, destination, limits):
        with self.opener(path) as source: _bounded_copy(source, destination, limits.max_single_bytes)


class LhaAnalyzer(AnalyzerAdapter):
    analyzer_id, supported_formats, capability, available, external_tool = "lha", ("lha", "lzh"), "recognition", False, "lhasa"
    supported_representations = (RepresentationKind.ARCHIVE.value,)
    def probe(self, path, *, name=""):
        with path.open("rb") as source: data = source.read(16)
        return identify_format(data, name=name).format_id == "lha"
    def list_members(self, path, limits): raise ToolMissing("qualified LHA/LZH extraction tool is unavailable")
    def materialize_member(self, path, member, destination, limits): raise ToolMissing("qualified LHA/LZH extraction tool is unavailable")


class SevenZipAnalyzer(LhaAnalyzer):
    analyzer_id, supported_formats, external_tool = "7z", ("7z",), "7z"
    def probe(self, path, *, name=""):
        with path.open("rb") as source: return source.read(6) == b"7z\xbc\xaf'\x1c"
    def list_members(self, path, limits): raise ToolMissing("qualified 7z extraction tool is unavailable")


class PartitionAnalyzer(AnalyzerAdapter):
    analyzer_id, supported_formats = "partition-table", ("mbr", "gpt")
    supported_representations = (RepresentationKind.WHOLE_DEVICE_IMAGE.value,)
    capability = "partition-inventory-and-extract"
    sector = 512
    def _kind(self, path):
        with path.open("rb") as source:
            first = source.read(1024)
        if len(first) >= 1024 and first[512:520] == b"EFI PART": return "gpt"
        if len(first) >= 512 and first[510:512] == b"\x55\xaa":
            for index in range(4):
                entry = first[446 + index * 16:462 + index * 16]
                if len(entry) == 16 and entry[4] and int.from_bytes(entry[12:16], "little"): return "mbr"
        return None
    def probe(self, path, *, name=""): return self._kind(path) is not None
    def list_members(self, path, limits):
        kind = self._kind(path); size = path.stat().st_size; members = []; warnings = []
        with path.open("rb") as source:
            if kind == "mbr":
                source.seek(446)
                for number in range(1, 5):
                    entry = source.read(16); ptype = entry[4]; start = int.from_bytes(entry[8:12], "little"); sectors = int.from_bytes(entry[12:16], "little"); offset = start * self.sector; length = sectors * self.sector
                    if not ptype or not sectors: continue
                    if offset + length > size: warnings.append(f"partition {number} exceeds image bounds"); continue
                    members.append({"logical_path": f"partition-{number}.img", "size": length, "name": str(number), "metadata": {"partition_number": number, "byte_offset": offset, "byte_length": length, "partition_type": f"0x{ptype:02x}", "table": "MBR"}, "representation": RepresentationKind.PARTITION.value})
            elif kind == "gpt":
                source.seek(512); header = source.read(92)
                entry_lba = int.from_bytes(header[72:80], "little"); count = min(int.from_bytes(header[80:84], "little"), limits.max_members); entry_size = int.from_bytes(header[84:88], "little")
                if entry_size < 128 or entry_size > 4096: raise MalformedInput("invalid GPT entry size")
                source.seek(entry_lba * self.sector)
                for index in range(count):
                    entry = source.read(entry_size)
                    if len(entry) != entry_size: raise MalformedInput("truncated GPT entries")
                    if entry[:16] == b"\0" * 16: continue
                    first = int.from_bytes(entry[32:40], "little"); last = int.from_bytes(entry[40:48], "little"); offset = first * self.sector; length = (last - first + 1) * self.sector
                    if last < first or offset + length > size: warnings.append(f"partition {index + 1} exceeds image bounds"); continue
                    type_guid = entry[:16].hex(); members.append({"logical_path": f"partition-{index + 1}.img", "size": length, "name": str(index + 1), "metadata": {"partition_number": index + 1, "byte_offset": offset, "byte_length": length, "partition_type_guid": type_guid, "table": "GPT"}, "representation": RepresentationKind.PARTITION.value})
        return members, warnings
    def materialize_member(self, path, member, destination, limits):
        with path.open("rb") as source: _bounded_region(source, destination, member["metadata"]["byte_offset"], member["size"], limits.max_single_bytes)


class ISO9660Analyzer(AnalyzerAdapter):
    analyzer_id, supported_formats, sector = "iso9660", ("iso", "iso9660"), 2048
    supported_representations = (RepresentationKind.SECTOR_IMAGE.value, RepresentationKind.FILESYSTEM.value)
    def probe(self, path, *, name=""):
        if path.stat().st_size < 17 * self.sector: return False
        with path.open("rb") as handle: handle.seek(16 * self.sector + 1); return handle.read(5) == b"CD001"
    def list_members(self, path, limits):
        with path.open("rb") as source:
            source.seek(16 * self.sector + 156); root = source.read(34)
            if len(root) < 34 or not root[0]: raise MalformedInput("malformed ISO9660 root directory")
            queue = [(int.from_bytes(root[2:6], "little"), int.from_bytes(root[10:18], "little"), "")]; members, warnings, seen = [], [], set()
            while queue:
                extent, size, prefix = queue.pop(0)
                if (extent, size) in seen: warnings.append("ISO9660 directory loop skipped"); continue
                seen.add((extent, size)); source.seek(extent * self.sector); data = source.read(min(size, limits.max_bytes)); offset = 0
                while offset < len(data):
                    length = data[offset]
                    if not length: offset = ((offset // self.sector) + 1) * self.sector; continue
                    record = data[offset:offset + length]
                    if len(record) < length or length < 34: warnings.append("malformed ISO9660 directory record"); break
                    raw = record[33:33 + record[32]]
                    if raw not in {b"\x00", b"\x01"}:
                        decoded = raw.decode("ascii", "replace").rstrip(";1"); logical = _safe_logical((prefix + "/" + decoded).strip("/")); is_dir = bool(record[25] & 2); child_extent = int.from_bytes(record[2:6], "little"); child_size = int.from_bytes(record[10:18], "little")
                        item = {"logical_path": logical, "raw_name": raw.hex(), "size": child_size, "metadata": {"extent": child_extent, "flags": record[25]}, "name": logical, "filesystem": "iso9660", "representation": RepresentationKind.DIRECTORY.value if is_dir else RepresentationKind.FILE.value}; members.append(item)
                        if is_dir: queue.append((child_extent, child_size, logical))
                        if len(members) >= limits.max_files: raise LimitReached("max_files")
                    offset += length
            return members, warnings
    def materialize_member(self, path, member, destination, limits):
        if member["representation"] == RepresentationKind.DIRECTORY.value: raise PolicyError("directory is structural, not an exact byte object")
        with path.open("rb") as source: _bounded_region(source, destination, member["metadata"]["extent"] * self.sector, member["size"], limits.max_single_bytes)


class FATAnalyzer(AnalyzerAdapter):
    analyzer_id, supported_formats = "fat", ("fat12", "fat16", "fat32")
    supported_representations = (RepresentationKind.FILESYSTEM.value, RepresentationKind.PARTITION.value, RepresentationKind.DISK_IMAGE.value)
    def _bpb(self, path):
        with path.open("rb") as source: b = source.read(512)
        if len(b) < 512 or b[510:512] != b"\x55\xaa": return None
        bps = int.from_bytes(b[11:13], "little"); spc = b[13]; reserved = int.from_bytes(b[14:16], "little"); fats = b[16]; root_entries = int.from_bytes(b[17:19], "little"); total = int.from_bytes(b[19:21], "little") or int.from_bytes(b[32:36], "little"); spf = int.from_bytes(b[22:24], "little") or int.from_bytes(b[36:40], "little")
        if not total and bps: total = path.stat().st_size // bps
        if bps not in {512, 1024, 2048, 4096} or not spc or spc & (spc - 1) or not reserved or not fats or not total or not spf: return None
        root_sectors = ((root_entries * 32) + bps - 1) // bps; data_sectors = total - (reserved + fats * spf + root_sectors); clusters = data_sectors // spc
        label = b[82:90] if root_entries == 0 else b[54:62]; kind = "fat12" if clusters < 4085 else "fat16" if clusters < 65525 else "fat32"
        if label.startswith(b"FAT12"): kind = "fat12"
        elif label.startswith(b"FAT16"): kind = "fat16"
        elif label.startswith(b"FAT32"): kind = "fat32"
        return {"bytes_per_sector": bps, "sectors_per_cluster": spc, "reserved": reserved, "fats": fats, "root_entries": root_entries, "total_sectors": total, "sectors_per_fat": spf, "root_sectors": root_sectors, "data_offset": (reserved + fats * spf + root_sectors) * bps, "root_offset": (reserved + fats * spf) * bps, "root_cluster": int.from_bytes(b[44:48], "little") if kind == "fat32" else None, "kind": kind}
    def probe(self, path, *, name=""): return self._bpb(path) is not None
    @staticmethod
    def _fat_entry(table, cluster, kind):
        if kind == "fat12":
            offset = cluster + cluster // 2
            if offset + 2 > len(table): raise MalformedInput("FAT12 entry outside table")
            value = int.from_bytes(table[offset:offset + 2], "little"); return (value >> 4) & 0xfff if cluster & 1 else value & 0xfff
        width = 2 if kind == "fat16" else 4; offset = cluster * width
        if offset + width > len(table): raise MalformedInput("FAT entry outside table")
        value = int.from_bytes(table[offset:offset + width], "little"); return value & (0xffff if kind == "fat16" else 0x0fffffff)
    def _chain(self, source, bpb, first, limits):
        if first < 2: return b""
        source.seek(bpb["reserved"] * bpb["bytes_per_sector"]); table = source.read(bpb["sectors_per_fat"] * bpb["bytes_per_sector"]); cluster_size = bpb["bytes_per_sector"] * bpb["sectors_per_cluster"]; out = bytearray(); seen = set(); current = first; eoc = 0xff8 if bpb["kind"] == "fat12" else 0xfff8 if bpb["kind"] == "fat16" else 0x0ffffff8
        while current < eoc:
            if current in seen or len(seen) >= limits.max_members: raise MalformedInput("FAT cluster loop or chain limit")
            seen.add(current); offset = bpb["data_offset"] + (current - 2) * cluster_size
            if offset + cluster_size > source.seek(0, 2): raise MalformedInput("FAT cluster outside image")
            source.seek(offset); out.extend(source.read(cluster_size))
            if len(out) > limits.max_single_bytes and len(seen) > 1: raise LimitReached("max_single_bytes")
            current = self._fat_entry(table, current, bpb["kind"])
            if current in {0, 1}: break
        return bytes(out)
    def list_members(self, path, limits):
        bpb = self._bpb(path)
        if not bpb: raise MalformedInput("unsupported or malformed FAT filesystem")
        members, warnings, count = [], [], 0
        with path.open("rb") as source:
            def directory(data, prefix, ancestry):
                nonlocal count
                lfn = []
                for offset in range(0, len(data), 32):
                    entry = data[offset:offset + 32]
                    if len(entry) < 32 or entry[0] == 0: break
                    if entry[0] == 0xe5: lfn = []; continue
                    if entry[11] == 0x0f:
                        chars = entry[1:11] + entry[14:26] + entry[28:32]; lfn.append(chars); continue
                    if entry[11] & 0x08: lfn = []; continue
                    raw = entry[:11]; base = raw[:8].decode("cp437", "replace").rstrip(); ext = raw[8:11].decode("cp437", "replace").rstrip(); name = base + (("." + ext) if ext else ""); lfn = []
                    if name in {".", ".."}: continue
                    logical = _safe_logical((prefix + "/" + name).strip("/")); first = (int.from_bytes(entry[20:22], "little") << 16) | int.from_bytes(entry[26:28], "little"); size = int.from_bytes(entry[28:32], "little"); is_dir = bool(entry[11] & 0x10); count += 1
                    if count > limits.max_files: raise LimitReached("max_files")
                    item = {"logical_path": logical, "raw_name": raw.hex(), "size": size, "metadata": {"first_cluster": first, "attributes": entry[11], "filesystem": bpb["kind"]}, "name": logical, "filesystem": bpb["kind"], "representation": RepresentationKind.DIRECTORY.value if is_dir else RepresentationKind.FILE.value}; members.append(item)
                    if is_dir and first >= 2 and first not in ancestry: directory(self._chain(source, bpb, first, limits), logical, ancestry | {first})
            if bpb["kind"] == "fat32": directory(self._chain(source, bpb, bpb["root_cluster"], limits), "", {bpb["root_cluster"]})
            else: source.seek(bpb["root_offset"]); directory(source.read(bpb["root_entries"] * 32), "", set())
        return members, warnings
    def materialize_member(self, path, member, destination, limits):
        if member["representation"] == RepresentationKind.DIRECTORY.value: raise PolicyError("directory is structural, not an exact byte object")
        bpb = self._bpb(path)
        with path.open("rb") as source: data = self._chain(source, bpb, member["metadata"]["first_cluster"], limits)[:member["size"]]
        if len(data) != member["size"]: raise MalformedInput("FAT file ended before declared size")
        destination.parent.mkdir(parents=True, exist_ok=True); destination.write_bytes(data); destination.chmod(0o440)


class ImageAnalyzer(AnalyzerAdapter):
    capability = "recognition"
    supported_representations = (RepresentationKind.DISK_IMAGE.value,)
    def __init__(self, analyzer_id, formats, test, confidence=.85): self.analyzer_id, self.supported_formats, self.test, self.confidence = analyzer_id, tuple(formats), test, confidence
    def probe(self, path, *, name=""):
        with path.open("rb") as source: data = source.read(min(path.stat().st_size, 1024 * 1024))
        return self.test(data, path.stat().st_size)
    def list_members(self, path, limits): return [], ["recognized format; filesystem decoder is not qualified"]
    def materialize_member(self, path, member, destination, limits): raise ToolMissing("filesystem decoder is not qualified")


def default_analyzers():
    return [PartitionAnalyzer(), ISO9660Analyzer(), FATAnalyzer(), ZipAnalyzer(), TarAnalyzer(), SingleStreamAnalyzer("gzip", gzip.open, (".gz", ".tgz"), b"\x1f\x8b"), SingleStreamAnalyzer("bzip2", bz2.open, (".bz2", ".tbz2"), b"BZh"), SingleStreamAnalyzer("xz", lzma.open, (".xz", ".txz"), b"\xfd7zXZ\x00"), LhaAnalyzer(), SevenZipAnalyzer(),
            ImageAnalyzer("amiga-adf", ("adf",), lambda data, size: size in {901120, 911360, 176400, 180224} and data[:3] in {b"DOS", b"PFS", b"SFS"}, .95),
            ImageAnalyzer("commodore-disk", ("d64", "d71", "d81"), lambda data, size: size in {174848, 175531, 196608, 197376, 349696, 351062, 819200, 822400}),
            ImageAnalyzer("atari-disk", ("atr", "st", "msa"), lambda data, size: data[:2] == b"\x96\x02" or data[:3] == b"MSA" or size in {368640, 737280, 1474560}),
            ImageAnalyzer("generic-img", ("img", "ima"), lambda data, size: size in {163840, 180224, 320000, 327680, 360448, 368640, 720896, 737280, 1228800, 1440000, 1474560}, .55)]


class AnalysisManager:
    VERSION = 1
    def __init__(self, archive, *, analyzers=None):
        self.archive = archive; self.root = archive.root / "analysis"; self.jobs_root = self.root / "jobs"; self.observations_root = self.root / "observations"; self.analyzers = analyzers or default_analyzers()
    def jobs(self): return [json.loads(x.read_text(encoding="utf-8")) for x in sorted(self.jobs_root.glob("*.json"))] if self.jobs_root.is_dir() else []
    def show(self, job_id):
        if not isinstance(job_id, str) or not all(x in "0123456789abcdef" for x in job_id): raise PolicyError("invalid analysis job id")
        path = self.jobs_root / (job_id + ".json")
        if not path.is_file(): raise RabError("analysis job not found")
        return json.loads(path.read_text(encoding="utf-8"))
    def capabilities(self): return [x.describe() for x in self.analyzers]
    def status(self):
        jobs = self.jobs(); complete = {AnalysisState.COMPLETE.value, AnalysisState.COMPLETE_WITH_WARNINGS.value, "COMPLETED", "COMPLETED_WITH_WARNINGS"}
        states = {state: sum(x.get("state") == state for x in jobs) for state in AnalysisState}
        return {"jobs": len(jobs), "completed": sum(x.get("state") in complete for x in jobs), "warnings": sum(bool(x.get("limits_reached") or x.get("warnings")) for x in jobs), "states": states, "capabilities": len(self.analyzers)}
    def relationships(self, identifier): return IdentityCatalogue(self.archive, read_only=True).relationships(identifier)
    def observations(self, identifier):
        sha = self.archive.resolve(identifier); values = []
        for path in sorted(self.observations_root.glob("*.json")) if self.observations_root.is_dir() else []:
            item = json.loads(path.read_text(encoding="utf-8"))
            if item.get("object_id") == "sha256:" + sha: values.append(item)
        return values
    def contained(self, identifier):
        sha = self.archive.resolve(identifier); target = "sha256:" + sha; values = []
        for job in self.jobs():
            for item in job.get("discovered", []):
                if item.get("parent_object") == target or job.get("root_object") == target: values.append(item)
        return values
    def tree(self, identifier):
        root = "sha256:" + self.archive.resolve(identifier); nodes = {root: {"object_id": root, "children": []}}
        for job in self.jobs():
            for item in job.get("discovered", []):
                parent = item.get("parent_object") or root; child = {key: value for key, value in item.items() if key not in {"analyzer"}}
                nodes.setdefault(parent, {"object_id": parent, "children": []})["children"].append(child)
        nodes[root]["children"].sort(key=lambda x: (x.get("logical_path", ""), x.get("object_id", ""))); return nodes[root]
    @staticmethod
    def public_job(job):
        value = {key: data for key, data in job.items() if key not in {"errors", "operator", "warnings", "workspace", "commands"}}
        value["warnings_count"] = len(job.get("warnings", [])); value["error_count"] = len(job.get("errors", [])); return value
    def _matching(self, source, name):
        matches = []
        for analyzer in self.analyzers:
            try:
                if analyzer.probe(source, name=name): matches.append(analyzer)
            except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile, MalformedInput): continue
        return matches
    def _key(self, root_id, policy, limits, recursive):
        value = {"root": root_id, "policy": policy, "limits": asdict(limits), "recursive": recursive, "analyzers": self.capabilities()}
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    def plan(self, identifier, *, policy="metadata-only", limits=None, recursive=True):
        if policy not in POLICIES: raise PolicyError("unknown analysis policy")
        limits = limits or AnalysisLimits(); limits.validate(); root_id = "sha256:" + self.archive.resolve(identifier); key = self._key(root_id, policy, limits, recursive)
        return {"schema": "rab-analysis-plan-v1", "analysis_key": key, "job_id": key[:32], "root_object": root_id, "policy": policy, "recursive": recursive, "limits": asdict(limits), "analyzers": self.capabilities(), "state": AnalysisState.PLANNED.value}
    def retry(self, job_id):
        old = self.show(job_id); return self.analyze(old["root_object"], policy=old["policy"], limits=AnalysisLimits(**old["limits"]), recursive=old.get("recursive", True), force=True, retry_of=job_id)
    def analyze(self, identifier, *, policy="metadata-only", limits=None, rights=None, recursive=True, force=False, retry_of=None):
        plan = self.plan(identifier, policy=policy, limits=limits, recursive=recursive); limits = limits or AnalysisLimits(); base_id = plan["job_id"]
        existing = self.jobs_root / (base_id + ".json")
        if existing.is_file() and not force: return json.loads(existing.read_text(encoding="utf-8"))
        job_id = uuid.uuid4().hex if force else base_id; workspace = Path(tempfile.mkdtemp(prefix="rab-analysis-", dir=self.archive.root)); root_id = plan["root_object"]
        job = {"schema": "rab-analysis-job-v1", "version": self.VERSION, "job_id": job_id, "analysis_key": plan["analysis_key"], "retry_of": retry_of, "root_object": root_id, "policy": policy, "recursive": recursive, "limits": asdict(limits), "state": AnalysisState.PLANNED.value, "started_at": _now(), "completed_at": None, "analyzers": [], "format_observation_ids": [], "discovered": [], "materialized": [], "relationships": [], "limits_reached": [], "warnings": [], "errors": [], "malware": [], "identity": []}
        self.jobs_root.mkdir(parents=True, exist_ok=True); self.archive._atomic_json(self.jobs_root / (job_id + ".json"), job); job["state"] = AnalysisState.RUNNING.value; self.archive._atomic_json(self.jobs_root / (job_id + ".json"), job)
        started = time.monotonic(); materialized_count = 0; expanded = 0; nested_count = 0
        try:
            sha = self.archive.resolve(root_id); source = self.archive.object_dir(sha) / "master"; before = hash_file(source); analysis_source = workspace / "root"; shutil.copyfile(source, analysis_source); analysis_source.chmod(0o440)
            if rights is None:
                observed = [Rights(x.get("rights", Rights.UNKNOWN.value)) for x in self.archive.show(root_id).get("occurrences", [])]
                rank = {Rights.REDISTRIBUTABLE: 0, Rights.UNKNOWN: 1, Rights.PRIVATE_LICENSED: 2, Rights.RESTRICTED: 3}; inherited_rights = max(observed, key=lambda x: rank[x]) if observed else Rights.UNKNOWN
            else: inherited_rights = Rights(rights)
            if inherited_rights == Rights.REDISTRIBUTABLE and any(x.get("rights") != Rights.REDISTRIBUTABLE.value for x in self.archive.show(root_id).get("occurrences", [])): raise PolicyError("analysis may not broaden source rights")
            def observe(object_id, analyzer, detected_format, evidence, confidence):
                observation_id = uuid.uuid4().hex; value = {"schema": "rab-analysis-observation-v1", "observation_id": observation_id, "job_id": job_id, "object_id": object_id, "recorded_at": _now(), "analyzer": analyzer.describe() if analyzer else {"analyzer_id": "rab-format-detector", "version": "1"}, "detected_format": detected_format, "confidence": confidence, "evidence": evidence}
                self.observations_root.mkdir(parents=True, exist_ok=True); self.archive._atomic_json(self.observations_root / (observation_id + ".json"), value); job["format_observation_ids"].append(observation_id)
            def visit(path, parent_id, logical_name, depth):
                nonlocal materialized_count, expanded, nested_count
                if depth > limits.max_depth: raise LimitReached("max_depth")
                if depth:
                    nested_count += 1
                    if nested_count > limits.max_nested: raise LimitReached("max_nested")
                if time.monotonic() - started > limits.max_seconds: raise TimeoutError("analysis total timeout")
                matches = self._matching(path, logical_name); generic = identify_format(path.read_bytes()[:1024 * 1024], name=logical_name); observe(parent_id, None, generic.format_id, {"method": generic.method, "name": logical_name}, generic.confidence)
                if not matches:
                    job["discovered"].append({"logical_path": logical_name, "depth": depth, "format": generic.format_id, "representation": RepresentationKind.UNKNOWN_DATA.value, "parent_object": parent_id, "materializable": False}); return False
                analyzer = matches[0]
                for candidate in matches: observe(parent_id, candidate, candidate.supported_formats[0] if candidate.supported_formats else candidate.analyzer_id, {"probe": True, "name": logical_name}, candidate.confidence)
                if analyzer.describe() not in job["analyzers"]: job["analyzers"].append(analyzer.describe())
                if not analyzer.available: raise ToolMissing(f"{analyzer.analyzer_id} requires {analyzer.external_tool}")
                mark = time.monotonic(); members, warnings = analyzer.list_members(path, limits)
                if time.monotonic() - mark > limits.subprocess_timeout: raise TimeoutError("analyzer timeout")
                job["warnings"].extend(warnings)
                for member in members:
                    if len(job["discovered"]) >= limits.max_files: raise LimitReached("max_files")
                    item = {"logical_path": member["logical_path"], "raw_name": member.get("raw_name"), "depth": depth + 1, "size": member.get("size"), "representation": member.get("representation", RepresentationKind.FILE.value), "format": member.get("filesystem"), "analyzer": analyzer.describe(), "parent_object": parent_id, "metadata": member.get("metadata", {}), "status": "DISCOVERED"}; job["discovered"].append(item)
                    if member.get("representation") == RepresentationKind.DIRECTORY.value or policy == "metadata-only": continue
                    if member.get("size") is not None and member["size"] > limits.max_single_bytes: raise LimitReached("max_single_bytes")
                    destination = workspace / f"member-{materialized_count:06d}.bin"
                    analyzer.materialize_member(path, member, destination, limits); actual = destination.stat().st_size
                    if member.get("size") is not None and actual != member["size"]: raise MalformedInput("extracted size differs from declared size")
                    if actual > max(path.stat().st_size, 1) * limits.max_ratio: destination.unlink(missing_ok=True); raise LimitReached("max_ratio")
                    if time.monotonic() - started > limits.max_seconds: destination.unlink(missing_ok=True); raise TimeoutError("analysis total timeout")
                    if expanded + actual > limits.max_bytes: destination.unlink(missing_ok=True); raise LimitReached("max_bytes")
                    materialized_count += 1; expanded += actual; item["status"] = "MATERIALIZED"; item["hashes"] = hash_file(destination); job["materialized"].append({"logical_path": member["logical_path"], "hashes": item["hashes"]})
                    child_id = None
                    if policy in {"preserve", "archival"}:
                        try: self.archive.resolve(item["hashes"]["sha256"]); already_preserved = True
                        except RabError: already_preserved = False
                        child = self.archive.ingest(IngestRequest(destination, "analysis:" + analyzer.analyzer_id, "contained/" + member["logical_path"], inherited_rights, "application/octet-stream", Path(member["logical_path"]).name, None if already_preserved else parent_id, "contained", {"analyzer": analyzer.describe(), "depth": depth + 1, "logical_path": member["logical_path"], "contained_in": parent_id}))
                        child_id = child["object_id"]; item.update({"status": "PRESERVED", "object_id": child_id}); malware = MalwareStore(self.archive, read_only=True).status(child_id)["state"] if (self.archive.root / "malware.sqlite3").is_file() else "NOT_SCANNED"; job["malware"].append({"object_id": child_id, "state": malware, "coverage": "ELIGIBLE_NOT_SCANNED"})
                        relation = IdentityCatalogue(self.archive).add_relationship(parent_id, RelationshipType.CONTAINS, child_id, {"analyzer": analyzer.describe(), "logical_path": member["logical_path"], "raw_name": member.get("raw_name"), "depth": depth + 1, "exact_bytes": True}); item["relationship_id"] = relation["relationship_id"]; job["relationships"].append(relation["relationship_id"])
                    if recursive and depth + 1 <= limits.max_depth and policy in {"identify", "preserve", "archival"} and self._matching(destination, member["logical_path"]): visit(destination, child_id or parent_id, member["logical_path"], depth + 1)
                return True
            supported = visit(analysis_source, root_id, source.name, 0)
            if hash_file(source) != before: raise RabError("preservation master changed during analysis")
            try: job["identity"] = [IdentityCatalogue(self.archive).rebuild()]
            except Exception as exc: job["warnings"].append("identity integration incomplete: " + str(exc))
            job["state"] = AnalysisState.UNSUPPORTED.value if not supported else AnalysisState.COMPLETE_WITH_WARNINGS.value if job["warnings"] else AnalysisState.COMPLETE.value
        except ToolMissing as exc: job["state"] = AnalysisState.TOOL_MISSING.value; job["warnings"].append(str(exc))
        except LimitReached as exc: job["state"] = AnalysisState.LIMIT_EXCEEDED.value; job["limits_reached"].append(str(exc))
        except TimeoutError as exc: job["state"] = AnalysisState.TIMEOUT.value; job["warnings"].append(str(exc))
        except MalformedInput as exc: job["state"] = AnalysisState.MALFORMED.value; job["errors"].append(str(exc))
        except Exception as exc: job["state"] = AnalysisState.FAILED.value; job["errors"].append(str(exc))
        finally:
            job["completed_at"] = _now(); job["expanded_bytes"] = expanded; job["materialized_count"] = materialized_count; self.archive._atomic_json(self.jobs_root / (job_id + ".json"), job); shutil.rmtree(workspace, ignore_errors=True)
        return job

    def analyze_physical(self, media_id, **kwargs):
        from .physical_registry import PhysicalMediaRegistry
        captures = [x for x in PhysicalMediaRegistry(self.archive).captures(media_id) if x.get("object_id")]
        if not captures: raise RabError("physical medium has no preserved capture")
        return [self.analyze(x["object_id"], **kwargs) for x in captures]
