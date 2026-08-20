"""Fail-closed whole-device capture boundary for future physical media work."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from .errors import PolicyError, RabError
from .local_ingest import IngestJobState, IngestManager, ProvenanceClass
from .model import Rights
from .inventory import inventory_image
from .hashing import hash_file


class RepresentationKind(StrEnum):
    PHYSICAL_MEDIUM = "PHYSICAL_MEDIUM"
    LOGICAL_EXTRACTION = "LOGICAL_EXTRACTION"
    SECTOR_IMAGE = "SECTOR_IMAGE"
    FILESYSTEM_IMAGE = "FILESYSTEM_IMAGE"
    TRACK_IMAGE = "TRACK_IMAGE"
    FLUX_IMAGE = "FLUX_IMAGE"
    FLUX_CAPTURE = "FLUX_CAPTURE"
    FILE = "FILE"
    ARCHIVE = "ARCHIVE"
    WHOLE_DEVICE_IMAGE = "WHOLE_DEVICE_IMAGE"
    PARTITION = "PARTITION"
    PRESERVATION_FORMAT = "PRESERVATION_FORMAT"
    FILESYSTEM = "FILESYSTEM"
    OPTICAL_SESSION = "OPTICAL_SESSION"
    OPTICAL_TRACK = "OPTICAL_TRACK"
    DISK_IMAGE = "DISK_IMAGE"
    DIRECTORY = "DIRECTORY"
    EXECUTABLE = "EXECUTABLE"
    DOCUMENT = "DOCUMENT"
    AUDIO_TRACK = "AUDIO_TRACK"
    UNKNOWN_CONTAINER = "UNKNOWN_CONTAINER"
    UNKNOWN_DATA = "UNKNOWN_DATA"


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


class OpticalOutcome(StrEnum):
    COMPLETE = "COMPLETE"
    COMPLETE_WITH_WARNINGS = "COMPLETE_WITH_WARNINGS"
    PARTIAL = "PARTIAL"
    UNREADABLE = "UNREADABLE"
    UNSUPPORTED = "UNSUPPORTED"
    TOOL_MISSING = "TOOL_MISSING"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    READ_ERROR = "READ_ERROR"


@dataclass(frozen=True)
class OpticalTrack:
    number: int
    track_type: str
    start_lba: int | None = None
    end_lba: int | None = None
    session: int | None = None
    evidence: dict | None = None


@dataclass(frozen=True)
class OpticalInspection:
    device: str
    medium_type: str
    block_size: int | None
    capacity_bytes: int | None
    volume_label: str | None
    filesystem: str | None
    sessions: int | None
    tracks: tuple[OpticalTrack, ...]
    mixed_mode: bool
    limitations: tuple[str, ...]
    tools: dict


@dataclass(frozen=True)
class OpticalRepresentation:
    medium_id: str
    representation_kind: RepresentationKind
    capture_object_ids: tuple[str, ...]
    inspection: dict
    verification: dict
    derived_from: str | None = None


def _now(): return datetime.now(UTC).isoformat()


class MediaAdapter:
    adapter_id = "unknown"

    def capabilities(self) -> dict:
        return {"adapter_id": self.adapter_id, "available": False, "kind": "unsupported"}

    def inspect(self, device: str) -> dict: raise NotImplementedError
    def capture(self, device: str, destination: Path, *, timeout: int = 86400) -> dict: raise NotImplementedError


class BlockDeviceAdapter(MediaAdapter):
    adapter_id = "linux-block-device-dd"

    def capabilities(self):
        return {"adapter_id": self.adapter_id, "available": True, "kind": "whole-block-device", "tool": "dd", "write_source": False}

    def _lsblk(self) -> list[dict]:
        try:
            result = subprocess.run(["lsblk", "--json", "--bytes", "--output", "NAME,KNAME,PATH,TYPE,SIZE,RM,RO,TRAN,FSTYPE,LABEL,UUID,PARTTYPE,PKNAME,MOUNTPOINTS,MODEL,SERIAL"], check=True, capture_output=True, text=True, timeout=15, shell=False)
            return json.loads(result.stdout).get("blockdevices", [])
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            raise RabError("unable to enumerate block devices") from exc

    def devices(self) -> list[dict]:
        devices = [x for x in self._lsblk() if x.get("type") in {"disk", "loop"}]
        root = self._root_source(); storage = self._mount_source(str(self.archive_root)) if hasattr(self, "archive_root") else None; swap = self._swap_devices()
        for device in devices:
            path = device.get("path", "")
            mounted_children = self._mounted_children(device)
            protected = bool(root and (path == root or root.startswith(path))) or bool(storage and (path == storage or storage.startswith(path))) or path in swap
            device["removable"] = bool(device.get("rm"))
            device["mounted_children"] = mounted_children
            device["safety"] = "PROTECTED" if protected else "MOUNTED" if mounted_children else "SAFE_CANDIDATE" if device["removable"] else "NON_REMOVABLE"
            device["source_reported_read_only"] = bool(device.get("ro"))
        return devices

    def _mounted_children(self, device: dict) -> list[str]:
        values = []
        for child in device.get("children") or []:
            mounts = child.get("mountpoints") or ([child.get("mountpoint")] if child.get("mountpoint") else [])
            values.extend([str(x) for x in mounts if x])
            values.extend(self._mounted_children(child))
        mounts = device.get("mountpoints") or ([device.get("mountpoint")] if device.get("mountpoint") else [])
        values.extend([str(x) for x in mounts if x])
        return sorted(set(values))

    @staticmethod
    def _mount_source(path: str) -> str | None:
        try:
            result = subprocess.run(["findmnt", "-n", "-o", "SOURCE", path], check=False, capture_output=True, text=True, timeout=5, shell=False)
            return result.stdout.strip() or None
        except (OSError, subprocess.SubprocessError): return None

    def inspect(self, device: str) -> dict:
        if not device.startswith("/dev/") or any(x in device for x in ("\x00", "\n", "\r")): raise PolicyError("invalid block device path")
        matches = [x for x in self.devices() if x.get("path") == device]
        if not matches: raise PolicyError("device is not an enumerated whole block device")
        if matches[0].get("safety") in {"PROTECTED", "MOUNTED"}: raise PolicyError("device or child partition is not safely unmounted")
        return matches[0]

    def _root_source(self) -> str | None:
        try:
            result = subprocess.run(["findmnt", "-n", "-o", "SOURCE", "/"], check=False, capture_output=True, text=True, timeout=5, shell=False)
            return result.stdout.strip() or None
        except OSError: return None

    def _swap_devices(self) -> set[str]:
        try:
            result = subprocess.run(["swapon", "--noheadings", "--raw", "--output", "NAME"], check=False, capture_output=True, text=True, timeout=5, shell=False)
            return {x.strip() for x in result.stdout.splitlines() if x.strip()}
        except OSError: return set()

    def capture(self, device: str, destination: Path, *, timeout: int = 86400) -> dict:
        info = self.inspect(device); root_source = self._root_source()
        if root_source and (device == root_source or (root_source.startswith(device) and root_source[len(device):len(device) + 1] in {"p", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"})):
            raise PolicyError("refusing to capture the active root device")
        destination = destination.resolve(); destination.parent.mkdir(parents=True, exist_ok=True)
        if info.get("safety") != "SAFE_CANDIDATE": raise PolicyError("device is not a safe removable candidate")
        command = ["dd", f"if={device}", f"of={destination}", "bs=4M", "iflag=fullblock", "status=none"]
        try:
            result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout, shell=False)
        except subprocess.TimeoutExpired as exc:
            if destination.is_file() and destination.stat().st_size: return {"device": device, "capture_tool": "dd", "command": command, "bytes": destination.stat().st_size, "outcome": "PARTIAL", "read_errors": ["capture timed out after partial output"], "capture_mode_read_only": True}
            raise RabError("device capture timed out") from exc
        if result.returncode:
            if destination.is_file() and destination.stat().st_size: return {"device": device, "capture_tool": "dd", "command": command, "bytes": destination.stat().st_size, "outcome": "PARTIAL", "read_errors": [(result.stderr or "device capture failed")[-2000:]], "capture_mode_read_only": True}
            destination.unlink(missing_ok=True); raise RabError("device capture failed: " + (result.stderr or "").strip()[-1000:])
        actual = destination.stat().st_size; expected = int(info.get("size") or 0)
        if expected and actual != expected:
            destination.unlink(missing_ok=True); raise RabError(f"whole-device capture size mismatch: expected {expected}, got {actual}")
        return {"device": device, "device_info": info, "capture_tool": "dd", "command": command, "bytes": actual, "expected_bytes": expected or None, "source_reported_read_only": info.get("source_reported_read_only", False), "capture_mode_read_only": True, "outcome": "COMPLETE", "read_errors": []}


class MediaManager:
    def __init__(self, archive, *, adapter: MediaAdapter | None = None):
        self.archive = archive; self.adapter = adapter or BlockDeviceAdapter(); self.root = archive.root / "media"; self.jobs_root = self.root / "jobs"
        if isinstance(self.adapter, BlockDeviceAdapter): self.adapter.archive_root = archive.root

    def devices(self): return self.adapter.devices() if hasattr(self.adapter, "devices") else []
    def inspect(self, device): return self.adapter.inspect(device)
    def jobs(self):
        return [json.loads(x.read_text(encoding="utf-8")) for x in sorted(self.jobs_root.glob("*.json"))] if self.jobs_root.is_dir() else []
    def show(self, job_id):
        if not re.fullmatch(r"[0-9a-f]+", job_id): raise PolicyError("invalid media job id")
        path = self.jobs_root / (job_id + ".json")
        if not path.is_file(): raise RabError("media job not found")
        return json.loads(path.read_text(encoding="utf-8"))

    def capture(self, device: str, *, physical_medium_id=None, repeat_of=None, platform_hint=None, vendor=None, title=None, collection=None, media_number=None, rights: Rights = Rights.UNKNOWN, provenance: ProvenanceClass | str = ProvenanceClass.ORIGINAL_PHYSICAL_OWNED, notes: str = "", verification: str = "standard"):
        if physical_medium_id and physical_medium_id.startswith("rab-media-"):
            from .physical_registry import PhysicalMediaRegistry
            PhysicalMediaRegistry(self.archive).show(physical_medium_id)
        self.jobs_root.mkdir(parents=True, exist_ok=True); job_id = uuid.uuid4().hex; staging = self.root / "staging" / job_id / "device.img"
        job = {"schema": "rab-media-capture-job-v1", "job_id": job_id, "state": IngestJobState.CAPTURING.value, "created_at": _now(), "device": device, "physical_medium_id": physical_medium_id or "physical-removable:" + uuid.uuid4().hex, "capture_attempt": "REPEAT" if repeat_of else "FIRST", "repeat_of": repeat_of, "platform_hint": platform_hint, "vendor": vendor, "title": title, "collection": collection, "media_number": media_number, "provenance_classification": ProvenanceClass(provenance).value, "rights": Rights(rights).value, "operator_notes": notes, "representation_kind": RepresentationKind.WHOLE_DEVICE_IMAGE.value, "adapter": self.adapter.capabilities(), "verification_policy": verification, "verification": {"policy": verification, "status": "NOT_PERFORMED", "methods": []}, "warnings": [], "errors": [], "object_id": None}
        self.archive._atomic_json(self.jobs_root / (job_id + ".json"), job)
        try:
            capture = self.adapter.capture(device, staging)
            if repeat_of:
                previous = self.show(repeat_of); previous_sha = previous.get("hashes", {}).get("sha256"); current_sha = hash_file(staging)["sha256"]
                job["repeat_comparison"] = {"repeat_of": repeat_of, "byte_identical": previous_sha == current_sha, "raw_capture_hashes_compared": bool(previous_sha), "differing_capture_preserved": previous_sha != current_sha}
            job.update({"capture": capture, "state": IngestJobState.INGESTING.value})
            checks = ["capture_completed", "byte_count"]
            if verification == "fast": job["verification"] = {"policy": verification, "status": "PASS", "methods": checks}
            else:
                job["verification"] = {"policy": verification, "status": "LIMITED", "methods": checks, "limitations": "repeat-read verification not implemented"}
            manager = IngestManager(self.archive)
            job["hashes"] = hash_file(staging)
            result = manager.ingest_staged(staging, category="personal", rights=rights, provenance=provenance, notes=notes, original_path=device)
            outcome = capture.get("outcome", "COMPLETE")
            job.update({"object_id": result["object_id"], "ingest_job_id": result["job_id"], "state": "COMPLETED_WITH_WARNINGS" if outcome == "PARTIAL" else result["state"], "completed_at": _now(), "inventory": inventory_image(staging)})
        except Exception as exc:
            job["state"] = IngestJobState.FAILED.value; job["errors"].append(str(exc)); job["completed_at"] = _now(); raise
        finally:
            if staging.is_file(): staging.unlink(missing_ok=True)
            try: staging.parent.rmdir()
            except OSError: pass
            job["updated_at"] = _now(); self.archive._atomic_json(self.jobs_root / (job_id + ".json"), job)
        if physical_medium_id and physical_medium_id.startswith("rab-media-") and job.get("object_id"):
            PhysicalMediaRegistry(self.archive).link_capture(physical_medium_id, job)
        return job


class OpticalAdapter(MediaAdapter):
    """Linux optical-drive adapter; command runner is injectable for fixtures."""
    adapter_id = "linux-optical-v1"

    def __init__(self, *, runner=None, which=None, toc_reader=None):
        self.runner = runner or self._run
        self.which = which or shutil.which
        self.toc_reader = toc_reader

    @staticmethod
    def _run(command, **kwargs):
        return subprocess.run(command, check=False, capture_output=True, text=True, timeout=kwargs.get("timeout", 30), shell=False)

    def capabilities(self):
        return {"adapter_id": self.adapter_id, "available": True, "kind": "optical-drive", "inspection": ["lsblk", "blkid", "udev"], "capture": ["dd"], "track_capture": bool(self.which("cdrdao")), "supported_media": ["CD", "CD-R", "CD-RW", "DVD", "BD"], "write_operations": False}

    @staticmethod
    def _tool_version(tool: str) -> str | None:
        try:
            result = subprocess.run([tool, "--version"], check=False, capture_output=True, text=True, timeout=5, shell=False)
            return (result.stdout or result.stderr).splitlines()[0][:256] if result.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired): return None

    def _lsblk(self):
        try:
            result = self.runner(["lsblk", "--json", "--bytes", "--output", "NAME,KNAME,PATH,TYPE,SIZE,RM,RO,MODEL,SERIAL"], timeout=15)
            if result.returncode: raise RabError("optical drive enumeration failed")
            return json.loads(result.stdout).get("blockdevices", [])
        except (OSError, ValueError, TypeError) as exc:
            raise RabError("malformed optical drive enumeration") from exc

    def devices(self):
        return [x for x in self._lsblk() if x.get("type") == "rom"]

    def inspect(self, device: str):
        if not device.startswith("/dev/") or any(x in device for x in ("\x00", "\n", "\r")): raise PolicyError("invalid optical device path")
        candidates = [x for x in self.devices() if x.get("path") == device]
        if not candidates: raise PolicyError("device is not an enumerated optical drive")
        info = candidates[0]; blkid = self.runner(["blkid", "-o", "export", device], timeout=15)
        fields = {}
        if blkid.returncode == 0:
            for line in blkid.stdout.splitlines():
                if "=" in line:
                    key, value = line.split("=", 1); fields[key] = value
        filesystem = fields.get("TYPE"); medium = "data-cd" if filesystem == "iso9660" else "dvd-rom" if filesystem == "udf" else "unknown-optical"
        toc = self.toc_reader(device) if self.toc_reader else {}
        tracks = tuple(OpticalTrack(int(x.get("number", index + 1)), str(x.get("track_type", "unknown")), x.get("start_lba"), x.get("end_lba"), x.get("session"), x) for index, x in enumerate(toc.get("tracks", [])))
        sessions = toc.get("sessions")
        mixed = bool(toc.get("mixed_mode")) or bool(tracks and any(x.track_type.lower().startswith("audio") for x in tracks) and any("data" in x.track_type.lower() for x in tracks))
        if toc.get("medium_type"): medium = toc["medium_type"]
        return OpticalInspection(device, medium, int(fields["BLOCK_SIZE"]) if fields.get("BLOCK_SIZE", "").isdigit() else 2048,
            int(info["size"]) if str(info.get("size", "")).isdigit() else None, fields.get("LABEL"), filesystem,
            sessions, tracks, mixed, tuple(toc.get("limitations", ())) + (("TOC/session inspection unavailable",) if not tracks else ()),
            {"lsblk": "lsblk", "blkid": "blkid", "dd": self._tool_version("dd"), "cdrdao": self.which("cdrdao"), "vendor": info.get("vendor"), "model": info.get("model"), "revision": info.get("revision"), "serial": info.get("serial"), "transport": info.get("tran")})

    def plan(self, inspection: OpticalInspection):
        if inspection.medium_type in {"audio-cd", "mixed-mode", "unknown-optical"} or inspection.mixed_mode or len(inspection.tracks) > 1:
            return {"strategy": "TRACK_AWARE", "state": OpticalOutcome.TOOL_MISSING.value if not self.which("cdrdao") else OpticalOutcome.UNSUPPORTED.value, "reason": "track-aware optical tooling is unavailable or not qualified"}
        return {"strategy": "ISO_SECTOR", "state": OpticalOutcome.COMPLETE.value, "block_size": inspection.block_size or 2048, "reason": "single data representation", "representation_kind": RepresentationKind.SECTOR_IMAGE.value}

    def capture(self, device: str, destination: Path, *, timeout: int = 86400):
        inspection = self.inspect(device); plan = self.plan(inspection)
        if plan["state"] != OpticalOutcome.COMPLETE.value: raise PolicyError(plan["state"] + ": " + plan["reason"])
        destination.parent.mkdir(parents=True, exist_ok=True)
        command = ["dd", "if=" + device, "of=" + str(destination), "bs=" + str(plan["block_size"]), "iflag=fullblock", "status=none"]
        try:
            result = self.runner(command, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            if destination.is_file() and destination.stat().st_size: return {"inspection": inspection.__dict__, "plan": plan, "capture_tool": "dd", "command": command, "bytes": destination.stat().st_size, "outcome": OpticalOutcome.PARTIAL.value, "read_errors": ["capture timed out after partial output"], "verification": {"policy": "standard", "status": "PARTIAL"}}
            raise RabError("optical capture timed out") from exc
        if result.returncode:
            if destination.is_file() and destination.stat().st_size: return {"inspection": inspection.__dict__, "plan": plan, "capture_tool": "dd", "command": command, "bytes": destination.stat().st_size, "outcome": OpticalOutcome.PARTIAL.value, "read_errors": [(result.stderr or "optical tool returned failure")[-2000:]], "verification": {"policy": "standard", "status": "PARTIAL"}}
            destination.unlink(missing_ok=True); raise RabError("optical capture failed")
        if destination.stat().st_size % plan["block_size"]:
            destination.unlink(missing_ok=True); raise RabError("optical capture is not block aligned")
        return {"inspection": inspection.__dict__, "plan": plan, "capture_tool": "dd", "tool_version": self._tool_version("dd"), "command": command, "bytes": destination.stat().st_size, "outcome": OpticalOutcome.COMPLETE.value, "verification": {"policy": "fast", "status": "PASS", "checks": ["capture_completed", "block_alignment"], "repeat_read": False}}


class OpticalManager:
    def __init__(self, archive, *, adapter: OpticalAdapter | None = None):
        self.archive = archive; self.adapter = adapter or OpticalAdapter(); self.root = archive.root / "media" / "optical"; self.jobs_root = self.root / "jobs"

    def devices(self): return self.adapter.devices()
    def inspect(self, device): return self.adapter.inspect(device).__dict__
    def jobs(self): return [json.loads(x.read_text(encoding="utf-8")) for x in sorted(self.jobs_root.glob("*.json"))] if self.jobs_root.is_dir() else []
    def show(self, job_id):
        if not re.fullmatch(r"[0-9a-f]+", job_id): raise PolicyError("invalid optical job id")
        path = self.jobs_root / (job_id + ".json")
        if not path.is_file(): raise RabError("optical job not found")
        return json.loads(path.read_text(encoding="utf-8"))

    def capture(self, device: str, *, physical_medium_id=None, repeat_of=None, platform_hint=None, title=None, media_number=None, rights: Rights = Rights.UNKNOWN, provenance: ProvenanceClass | str = ProvenanceClass.ORIGINAL_PHYSICAL_OWNED, notes: str = "", verification: str = "standard"):
        if physical_medium_id and physical_medium_id.startswith("rab-media-"):
            from .physical_registry import PhysicalMediaRegistry
            PhysicalMediaRegistry(self.archive).show(physical_medium_id)
        self.jobs_root.mkdir(parents=True, exist_ok=True); job_id = uuid.uuid4().hex; stage = self.root / "staging" / job_id / "disc.iso"
        job = {"schema": "rab-optical-capture-job-v1", "job_id": job_id, "state": "INSPECTING", "device": device, "physical_medium_id": physical_medium_id or "physical-optical:" + uuid.uuid4().hex, "capture_attempt": "REPEAT" if repeat_of else "FIRST", "repeat_of": repeat_of, "platform_hint": platform_hint, "title": title, "media_number": media_number, "provenance_classification": ProvenanceClass(provenance).value, "rights": Rights(rights).value, "operator_notes": notes, "representation_kind": RepresentationKind.SECTOR_IMAGE.value, "created_at": _now(), "verification_policy": verification, "verification": {"policy": verification, "status": "NOT_PERFORMED"}, "warnings": [], "errors": [], "representations": []}
        self.archive._atomic_json(self.jobs_root / (job_id + ".json"), job)
        try:
            inspection = self.adapter.inspect(device); plan = self.adapter.plan(inspection); job.update({"inspection": inspection.__dict__, "plan": plan})
            if plan["state"] != OpticalOutcome.COMPLETE.value: job["state"] = plan["state"]; raise PolicyError(plan["reason"])
            capture = self.adapter.capture(device, stage); job["inventory"] = inventory_image(stage); job["state"] = "INGESTING"
            if repeat_of:
                previous = self.show(repeat_of); previous_sha = previous.get("hashes", {}).get("sha256") or previous.get("capture", {}).get("sha256")
                job["repeat_comparison"] = {"repeat_of": repeat_of, "byte_identical": previous_sha == hash_file(stage)["sha256"], "raw_capture_hashes_compared": bool(previous_sha), "differing_capture_preserved": previous_sha != hash_file(stage)["sha256"]}
            result = IngestManager(self.archive).ingest_staged(stage, category="personal", rights=rights, provenance=provenance, notes=notes, original_path=device)
            capture_outcome = capture.get("outcome", OpticalOutcome.COMPLETE.value)
            job.update({"state": OpticalOutcome.COMPLETE_WITH_WARNINGS.value if capture_outcome == OpticalOutcome.PARTIAL.value else OpticalOutcome.COMPLETE.value, "object_id": result["object_id"], "ingest_job_id": result["job_id"], "capture": capture, "hashes": hash_file(stage), "representations": [{"object_id": result["object_id"], "kind": RepresentationKind.SECTOR_IMAGE.value}], "completed_at": _now()})
        except Exception as exc:
            job["errors"].append(str(exc)); job.setdefault("state", OpticalOutcome.FAILED.value)
            if job["state"] == "INSPECTING": job["state"] = OpticalOutcome.FAILED.value
            job["completed_at"] = _now(); raise
        finally:
            if stage.is_file(): stage.unlink(missing_ok=True)
            try: stage.parent.rmdir()
            except OSError: pass
            job["updated_at"] = _now(); self.archive._atomic_json(self.jobs_root / (job_id + ".json"), job)
        if physical_medium_id and physical_medium_id.startswith("rab-media-") and job.get("object_id"):
            PhysicalMediaRegistry(self.archive).link_capture(physical_medium_id, job)
        return job
