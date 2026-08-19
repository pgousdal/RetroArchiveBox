"""Fail-closed whole-device capture boundary for future physical media work."""
from __future__ import annotations

import json
import subprocess
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from .errors import PolicyError, RabError
from .local_ingest import IngestJobState, IngestManager, ProvenanceClass
from .model import Rights


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
            result = subprocess.run(["lsblk", "--json", "--bytes", "--output", "NAME,KNAME,PATH,TYPE,SIZE,RM,RO,MOUNTPOINTS,MODEL,SERIAL"], check=True, capture_output=True, text=True, timeout=15, shell=False)
            return json.loads(result.stdout).get("blockdevices", [])
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            raise RabError("unable to enumerate block devices") from exc

    def devices(self) -> list[dict]:
        return [x for x in self._lsblk() if x.get("type") in {"disk", "loop"}]

    def inspect(self, device: str) -> dict:
        if not device.startswith("/dev/") or any(x in device for x in ("\x00", "\n", "\r")): raise PolicyError("invalid block device path")
        matches = [x for x in self.devices() if x.get("path") == device]
        if not matches: raise PolicyError("device is not an enumerated whole block device")
        return matches[0]

    def _root_source(self) -> str | None:
        try:
            result = subprocess.run(["findmnt", "-n", "-o", "SOURCE", "/"], check=False, capture_output=True, text=True, timeout=5, shell=False)
            return result.stdout.strip() or None
        except OSError: return None

    def capture(self, device: str, destination: Path, *, timeout: int = 86400) -> dict:
        info = self.inspect(device); root_source = self._root_source()
        if root_source and (device == root_source or (root_source.startswith(device) and root_source[len(device):len(device) + 1] in {"p", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"})):
            raise PolicyError("refusing to capture the active root device")
        destination = destination.resolve(); destination.parent.mkdir(parents=True, exist_ok=True)
        command = ["dd", f"if={device}", f"of={destination}", "bs=4M", "iflag=fullblock", "status=none"]
        try:
            result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout, shell=False)
        except subprocess.TimeoutExpired as exc:
            destination.unlink(missing_ok=True); raise RabError("device capture timed out") from exc
        if result.returncode:
            destination.unlink(missing_ok=True); raise RabError("device capture failed: " + (result.stderr or "").strip()[-1000:])
        return {"device": device, "device_info": info, "capture_tool": "dd", "command": command, "bytes": destination.stat().st_size}


class MediaManager:
    def __init__(self, archive, *, adapter: MediaAdapter | None = None):
        self.archive = archive; self.adapter = adapter or BlockDeviceAdapter(); self.root = archive.root / "media"; self.jobs_root = self.root / "jobs"

    def devices(self): return self.adapter.devices() if isinstance(self.adapter, BlockDeviceAdapter) else []
    def inspect(self, device): return self.adapter.inspect(device)
    def jobs(self):
        return [json.loads(x.read_text(encoding="utf-8")) for x in sorted(self.jobs_root.glob("*.json"))] if self.jobs_root.is_dir() else []
    def show(self, job_id):
        path = self.jobs_root / (job_id + ".json")
        if not path.is_file(): raise RabError("media job not found")
        return json.loads(path.read_text(encoding="utf-8"))

    def capture(self, device: str, *, rights: Rights = Rights.UNKNOWN, provenance: ProvenanceClass | str = ProvenanceClass.ORIGINAL_PHYSICAL_OWNED, notes: str = ""):
        self.jobs_root.mkdir(parents=True, exist_ok=True); job_id = uuid.uuid4().hex; staging = self.root / "staging" / job_id / "device.img"
        job = {"schema": "rab-media-capture-job-v1", "job_id": job_id, "state": IngestJobState.CAPTURING.value, "created_at": _now(), "device": device, "adapter": self.adapter.capabilities(), "warnings": [], "errors": [], "object_id": None}
        self.archive._atomic_json(self.jobs_root / (job_id + ".json"), job)
        try:
            capture = self.adapter.capture(device, staging)
            job.update({"capture": capture, "state": IngestJobState.INGESTING.value})
            manager = IngestManager(self.archive)
            result = manager.ingest_staged(staging, category="personal", rights=rights, provenance=provenance, notes=notes, original_path=device)
            job.update({"object_id": result["object_id"], "ingest_job_id": result["job_id"], "state": result["state"], "completed_at": _now()})
        except Exception as exc:
            job["state"] = IngestJobState.FAILED.value; job["errors"].append(str(exc)); job["completed_at"] = _now(); raise
        finally:
            if staging.is_file(): staging.unlink(missing_ok=True)
            try: staging.parent.rmdir()
            except OSError: pass
            job["updated_at"] = _now(); self.archive._atomic_json(self.jobs_root / (job_id + ".json"), job)
        return job
