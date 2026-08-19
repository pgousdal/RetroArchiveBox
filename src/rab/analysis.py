"""Bounded, non-mutating contained-object discovery.

Analyzers consume disposable copies.  They never write to the preservation
object tree except when the explicit PRESERVE policy calls Archive.ingest.
"""
from __future__ import annotations

import bz2
import gzip
import json
import lzma
import os
import shutil
import stat
import tarfile
import tempfile
import time
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .errors import PolicyError, RabError
from .formats import identify_format
from .hashing import hash_file
from .identity import IdentityCatalogue, RelationshipType
from .malware import MalwareStore
from .model import IngestRequest, Rights
from .store import Archive


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


POLICIES = {"metadata-only", "identify", "preserve", "archival"}


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
    follow_symlinks: bool = False


class ContainerAnalyzer:
    analyzer_id = "generic"
    version = "1"
    supported_formats = ()

    def probe(self, path: Path, *, name: str = "") -> bool: raise NotImplementedError
    def list_members(self, path: Path, limits: AnalysisLimits) -> tuple[list[dict], list[str]]: raise NotImplementedError
    def materialize_member(self, path: Path, member: dict, destination: Path, limits: AnalysisLimits) -> None: raise NotImplementedError

    def describe(self):
        return {"analyzer_id": self.analyzer_id, "version": self.version, "supported_formats": list(self.supported_formats)}


def _safe_logical(name: str) -> str:
    if not isinstance(name, str) or "\x00" in name: raise PolicyError("unsafe member name")
    name = name.replace("\\", "/")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or (path.parts and ":" in path.parts[0]): raise PolicyError("member path escapes analysis root")
    return "/".join(x for x in path.parts if x not in {"", "."}) or "member"


def _bounded_copy(source, destination: Path, maximum: int):
    total = 0; destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as output:
        while True:
            chunk = source.read(min(1024 * 1024, maximum - total + 1))
            if not chunk: break
            total += len(chunk)
            if total > maximum: raise LimitReached("single extracted object limit reached")
            output.write(chunk)
    destination.chmod(0o440)


def _bounded_region(source, destination: Path, size: int, maximum: int):
    if size > maximum: raise LimitReached("single extracted object limit reached")
    total = 0; destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as output:
        while total < size:
            chunk = source.read(min(1024 * 1024, size - total))
            if not chunk: raise PolicyError("filesystem member ended before declared size")
            total += len(chunk); output.write(chunk)
    destination.chmod(0o440)


class LimitReached(Exception): pass


class ZipAnalyzer(ContainerAnalyzer):
    analyzer_id, supported_formats = "zip", ("zip",)

    def probe(self, path, *, name=""):
        try: return zipfile.is_zipfile(path)
        except OSError: return False

    def list_members(self, path, limits):
        members, warnings = [], []
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > limits.max_members: return [], ["ANALYSIS_LIMIT_REACHED: member count"]
            for info in infos:
                try: logical = _safe_logical(info.filename)
                except PolicyError as exc: warnings.append(str(exc)); continue
                mode = (info.external_attr >> 16) & 0o170000
                symlink = mode == stat.S_IFLNK
                if symlink or info.is_dir(): warnings.append("member skipped: symlink or directory " + logical); continue
                compressed = max(info.compress_size, 1); ratio = info.file_size / compressed
                if info.file_size > limits.max_single_bytes or ratio > limits.max_ratio: warnings.append("ANALYSIS_LIMIT_REACHED: " + logical); continue
                members.append({"logical_path": logical, "size": info.file_size, "compressed_size": info.compress_size, "metadata": {"date_time": info.date_time}, "name": info.filename})
        return members, warnings

    def materialize_member(self, path, member, destination, limits):
        with zipfile.ZipFile(path) as archive, archive.open(member["name"]) as source: _bounded_copy(source, destination, limits.max_single_bytes)


class TarAnalyzer(ContainerAnalyzer):
    analyzer_id, supported_formats = "tar", ("tar", "gzip", "bzip2", "xz")

    def probe(self, path, *, name=""):
        try: return tarfile.is_tarfile(path)
        except OSError: return False

    def list_members(self, path, limits):
        members, warnings = [], []
        with tarfile.open(path, "r:*") as archive:
            infos = archive.getmembers()
            if len(infos) > limits.max_members: return [], ["ANALYSIS_LIMIT_REACHED: member count"]
            for info in infos:
                try: logical = _safe_logical(info.name)
                except PolicyError as exc: warnings.append(str(exc)); continue
                if not info.isfile() or info.issym() or info.islnk(): warnings.append("member skipped: non-regular " + logical); continue
                if info.size > limits.max_single_bytes: warnings.append("ANALYSIS_LIMIT_REACHED: " + logical); continue
                members.append({"logical_path": logical, "size": info.size, "metadata": {"mode": info.mode, "mtime": info.mtime}, "name": info.name})
        return members, warnings

    def materialize_member(self, path, member, destination, limits):
        with tarfile.open(path, "r:*") as archive:
            info = archive.getmember(member["name"]); source = archive.extractfile(info)
            if source is None: raise PolicyError("tar member is not readable")
            with source: _bounded_copy(source, destination, limits.max_single_bytes)


class SingleStreamAnalyzer(ContainerAnalyzer):
    def __init__(self, analyzer_id, opener, suffixes): self.analyzer_id, self.opener, self.suffixes = analyzer_id, opener, suffixes; self.supported_formats = (analyzer_id,)
    def probe(self, path, *, name=""): return any(name.lower().endswith(x) for x in self.suffixes)
    def list_members(self, path, limits): return [{"logical_path": Path(path).stem, "size": path.stat().st_size, "metadata": {}, "name": Path(path).name}], []
    def materialize_member(self, path, member, destination, limits):
        with self.opener(path) as source: _bounded_copy(source, destination, limits.max_single_bytes)


class LhaAnalyzer(ContainerAnalyzer):
    analyzer_id, supported_formats = "lha", ("lha", "lzh")
    def probe(self, path, *, name=""):
        if name.lower().endswith((".lha", ".lzh")): return True
        with path.open("rb") as source: return identify_format(source.read(16), name=name).format_id == "lha"
    def list_members(self, path, limits): return [], ["LHA member listing/materialization requires a qualified lha/lhasa adapter"]
    def materialize_member(self, path, member, destination, limits): raise PolicyError("LHA materialization unavailable")


class ImageAnalyzer(ContainerAnalyzer):
    def __init__(self, analyzer_id, signatures): self.analyzer_id, self.signatures, self.supported_formats = analyzer_id, signatures, (analyzer_id,)
    def probe(self, path, *, name=""):
        with path.open("rb") as handle: data = handle.read(1024 * 1024)
        return any(test(data) for test in self.signatures)
    def list_members(self, path, limits): return [], ["filesystem analyzer is inspection-only for this format"]
    def materialize_member(self, path, member, destination, limits): raise PolicyError("filesystem materialization unavailable")


class ISO9660Analyzer(ContainerAnalyzer):
    analyzer_id, supported_formats = "iso9660", ("iso", "iso9660")
    sector = 2048

    def probe(self, path, *, name=""):
        with path.open("rb") as handle: handle.seek(16 * self.sector + 1); return handle.read(5) == b"CD001"

    def _directories(self, path, limits):
        with path.open("rb") as source:
            source.seek(16 * self.sector + 156); root = source.read(34)
            if len(root) < 34 or not root[0]: return [], ["malformed ISO9660 root directory"]
            queue = [(int.from_bytes(root[2:6], "little"), int.from_bytes(root[10:18], "little"), "")]; members = []; warnings = []
            while queue and len(members) < limits.max_files:
                extent, size, prefix = queue.pop(0); source.seek(extent * self.sector); data = source.read(min(size, limits.max_bytes))
                offset = 0
                while offset < len(data):
                    length = data[offset]
                    if not length: offset = ((offset // self.sector) + 1) * self.sector; continue
                    record = data[offset:offset + length]
                    if len(record) < length or length < 34: warnings.append("malformed ISO9660 directory record"); break
                    name_length = record[32]; raw_name = record[33:33 + name_length]
                    if raw_name not in {b"\x00", b"\x01"}:
                        name = raw_name.decode("ascii", "replace").rstrip(";1"); logical = (prefix + "/" + name).strip("/")
                        is_dir = bool(record[25] & 2); child_extent = int.from_bytes(record[2:6], "little"); child_size = int.from_bytes(record[10:18], "little")
                        try: logical = _safe_logical(logical)
                        except PolicyError as exc: warnings.append(str(exc)); logical = None
                        if logical:
                            item = {"logical_path": logical, "size": child_size, "metadata": {"extent": child_extent, "flags": record[25]}, "name": logical, "filesystem": "iso9660"}; members.append(item)
                            if is_dir and len(queue) < limits.max_files: queue.append((child_extent, child_size, logical))
                    offset += length
            if len(members) >= limits.max_files: warnings.append("ANALYSIS_LIMIT_REACHED: filesystem entries")
            return members, warnings

    def list_members(self, path, limits): return self._directories(path, limits)
    def materialize_member(self, path, member, destination, limits):
        if member["metadata"]["flags"] & 2: raise PolicyError("ISO9660 directory is not materializable as a regular object")
        with path.open("rb") as source:
            source.seek(member["metadata"]["extent"] * self.sector); _bounded_region(source, destination, member["size"], limits.max_single_bytes)


class FATAnalyzer(ContainerAnalyzer):
    analyzer_id, supported_formats = "fat", ("fat12", "fat16", "fat32")

    def probe(self, path, *, name=""):
        with path.open("rb") as source: data = source.read(90)
        return len(data) >= 62 and data[510:512] == b"\x55\xaa" or data[54:59] in {b"FAT12", b"FAT16"}

    def _root(self, path):
        with path.open("rb") as source:
            bpb = source.read(90)
            bps = int.from_bytes(bpb[11:13], "little"); reserved = int.from_bytes(bpb[14:16], "little"); fats = bpb[16]; root_entries = int.from_bytes(bpb[17:19], "little"); spf = int.from_bytes(bpb[22:24], "little")
            if not bps or not root_entries or not spf or bpb[54:59] not in {b"FAT12", b"FAT16"}: return [], ["unsupported or malformed FAT filesystem"]
            offset = (reserved + fats * spf) * bps; source.seek(offset); records = source.read(root_entries * 32); members = []
            for index in range(0, len(records), 32):
                entry = records[index:index + 32]
                if len(entry) < 32 or entry[0] in {0x00, 0xe5} or entry[11] & 0x08: continue
                raw = entry[:11]; name = raw[:8].decode("ascii", "replace").rstrip(); ext = raw[8:11].decode("ascii", "replace").rstrip(); logical = name + (("." + ext) if ext else "")
                if entry[11] & 0x10: continue
                size = int.from_bytes(entry[28:32], "little")
                members.append({"logical_path": _safe_logical(logical), "size": size, "metadata": {"offset": offset + index, "attributes": entry[11]}, "name": logical, "filesystem": "fat"})
            return members, []

    def list_members(self, path, limits):
        members, warnings = self._root(path)
        return ([x for x in members if x["size"] <= limits.max_single_bytes][:limits.max_files], warnings + (["ANALYSIS_LIMIT_REACHED: filesystem entries"] if len(members) > limits.max_files else []))

    def materialize_member(self, path, member, destination, limits):
        with path.open("rb") as source:
            # Root-directory-only fixture support; full FAT cluster traversal is a later analyzer.
            source.seek(member["metadata"]["offset"]); _bounded_copy(source, destination, 0)
        raise PolicyError("FAT cluster materialization requires a qualified filesystem traversal")


def default_analyzers():
    return [ZipAnalyzer(), TarAnalyzer(), SingleStreamAnalyzer("gzip", gzip.open, (".gz", ".tgz")), SingleStreamAnalyzer("bzip2", bz2.open, (".bz2", ".tbz2")), SingleStreamAnalyzer("xz", lzma.open, (".xz", ".txz")), LhaAnalyzer(), ISO9660Analyzer(), FATAnalyzer(), ImageAnalyzer("amiga-adf", (lambda data: len(data) in {901120, 911360, 176400, 180224},)), ImageAnalyzer("c64-d64", (lambda data: len(data) in {174848, 175531, 196608, 197376},))]


class AnalysisManager:
    VERSION = 1

    def __init__(self, archive, *, analyzers=None):
        self.archive = archive; self.root = archive.root / "analysis"; self.jobs_root = self.root / "jobs"; self.analyzers = analyzers or default_analyzers()

    def jobs(self): return [json.loads(x.read_text(encoding="utf-8")) for x in sorted(self.jobs_root.glob("*.json"))] if self.jobs_root.is_dir() else []
    def show(self, job_id):
        path = self.jobs_root / (job_id + ".json")
        if not path.is_file(): raise RabError("analysis job not found")
        return json.loads(path.read_text(encoding="utf-8"))
    def status(self):
        jobs = self.jobs(); return {"jobs": len(jobs), "completed": sum(x.get("state") == "COMPLETED" for x in jobs), "warnings": sum(bool(x.get("limits_reached") or x.get("warnings")) for x in jobs)}
    def relationships(self, identifier): return IdentityCatalogue(self.archive, read_only=True).relationships(identifier)

    @staticmethod
    def public_job(job):
        value = {key: data for key, data in job.items() if key not in {"errors", "operator", "warnings"}}
        value["warnings_count"] = len(job.get("warnings", [])); value["error_count"] = len(job.get("errors", []))
        return value

    def _analyzer(self, source, name):
        for analyzer in self.analyzers:
            try:
                if analyzer.probe(source, name=name): return analyzer
            except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile): continue
        return None

    def analyze(self, identifier, *, policy="metadata-only", limits=None, rights=Rights.UNKNOWN, recursive=True):
        if policy not in POLICIES: raise PolicyError("unknown analysis policy")
        limits = limits or AnalysisLimits(); if_not = self.archive.resolve(identifier); root_id = "sha256:" + if_not
        job_id = uuid.uuid4().hex; workspace = Path(tempfile.mkdtemp(prefix=job_id + "-", dir=self.archive.root))
        job = {"schema": "rab-analysis-job-v1", "version": self.VERSION, "job_id": job_id, "root_object": root_id, "policy": policy, "limits": limits.__dict__, "state": "ANALYSING", "started_at": _now(), "completed_at": None, "analyzers": [], "discovered": [], "materialized": [], "relationships": [], "limits_reached": [], "warnings": [], "errors": [], "malware": [], "identity": []}
        self.jobs_root.mkdir(parents=True, exist_ok=True); self.archive._atomic_json(self.jobs_root / (job_id + ".json"), job)
        started = time.monotonic(); materialized_count = 0; expanded = 0
        try:
            source = self.archive.object_dir(if_not) / "master"; analysis_source = workspace / "root"; shutil.copyfile(source, analysis_source); analysis_source.chmod(0o440)
            def visit(path, parent_id, logical_name, depth):
                nonlocal materialized_count, expanded
                if depth > limits.max_depth: job["limits_reached"].append("max_depth"); return
                if time.monotonic() - started > limits.max_seconds: job["limits_reached"].append("max_seconds"); return
                analyzer = self._analyzer(path, logical_name)
                if not analyzer: job["discovered"].append({"logical_path": logical_name, "depth": depth, "format": identify_format(path.read_bytes()[:1024 * 1024], name=logical_name).format_id, "materializable": False}); return
                if analyzer.analyzer_id not in job["analyzers"]: job["analyzers"].append(analyzer.describe())
                members, warnings = analyzer.list_members(path, limits); job["warnings"].extend(warnings)
                if len(job["discovered"]) + len(members) > limits.max_files: job["limits_reached"].append("max_files"); return
                for index, member in enumerate(members):
                    if materialized_count >= limits.max_files or expanded >= limits.max_bytes: job["limits_reached"].append("max_files" if materialized_count >= limits.max_files else "max_bytes"); return
                    item = {"logical_path": member["logical_path"], "depth": depth + 1, "size": member.get("size"), "analyzer": analyzer.describe(), "parent_object": parent_id, "status": "DISCOVERED"}
                    job["discovered"].append(item)
                    if policy == "metadata-only": continue
                    destination = workspace / (f"member-{materialized_count:06d}.bin");
                    try: analyzer.materialize_member(path, member, destination, limits)
                    except LimitReached as exc: job["limits_reached"].append(str(exc)); continue
                    except Exception as exc: item["status"] = "MATERIALIZATION_FAILED"; job["warnings"].append(str(exc)); continue
                    materialized_count += 1; expanded += destination.stat().st_size; item["status"] = "MATERIALIZED"; item["hashes"] = hash_file(destination)
                    child_id = None
                    if policy in {"preserve", "archival"}:
                        child = self.archive.ingest(IngestRequest(destination, "analysis:" + analyzer.analyzer_id, "contained/" + member["logical_path"], rights, "application/octet-stream", Path(member["logical_path"]).name, None, "contained", {"analyzer": analyzer.describe(), "depth": depth + 1, "logical_path": member["logical_path"]}))
                        child_id = child["object_id"]; item["status"] = "PRESERVED"; item["object_id"] = child_id; job["malware"].append({"object_id": child_id, "state": MalwareStore(self.archive, read_only=True).status(child_id)["state"] if (self.archive.root / "malware.sqlite3").is_file() else "NOT_SCANNED", "coverage": "NOT_SCANNED"})
                        relation = IdentityCatalogue(self.archive).add_relationship(parent_id, RelationshipType.CONTAINS, child_id, {"analyzer": analyzer.describe(), "logical_path": member["logical_path"], "depth": depth + 1})
                        item["relationship_id"] = relation["relationship_id"]; job["relationships"].append(relation["relationship_id"])
                    if recursive and depth + 1 <= limits.max_depth and policy in {"identify", "preserve", "archival"} and self._analyzer(destination, member["logical_path"]): visit(destination, child_id or parent_id, member["logical_path"], depth + 1)
            visit(analysis_source, root_id, source.name, 0)
            try:
                job["identity"] = [IdentityCatalogue(self.archive).rebuild()]
            except Exception as exc:
                job["warnings"].append("identity integration incomplete: " + str(exc))
            job["state"] = "COMPLETED_WITH_WARNINGS" if job["warnings"] or job["limits_reached"] else "COMPLETED"
        except Exception as exc:
            job["state"] = "FAILED"; job["errors"].append(str(exc))
        finally:
            job["completed_at"] = _now(); job["expanded_bytes"] = expanded; job["materialized_count"] = materialized_count; self.archive._atomic_json(self.jobs_root / (job_id + ".json"), job); shutil.rmtree(workspace, ignore_errors=True)
        return job
