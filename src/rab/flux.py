"""Generic raw-flux preservation and Greaseweazle adapter boundary.

The adapter deliberately treats the SCP file as evidence.  Decoders create
ordinary RAB derivative objects and never replace that evidence.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from .errors import PolicyError, RabError
from .identity import IdentityCatalogue, RelationshipType
from .inventory import inventory_image
from .hashing import hash_file
from .local_ingest import IngestJobState, IngestManager, ProvenanceClass
from .model import IngestRequest, Rights
from .media import MediaAdapter


class FluxOutcome(StrEnum):
    COMPLETE = "COMPLETE"
    COMPLETE_WITH_WARNINGS = "COMPLETE_WITH_WARNINGS"
    FAILED = "FAILED"
    TOOL_MISSING = "TOOL_MISSING"
    TIMEOUT = "TIMEOUT"


class FluxTimeoutError(RabError):
    """A bounded adapter invocation exceeded its preservation deadline."""


class VerificationPolicy(StrEnum):
    FAST = "fast"
    STANDARD = "standard"
    ARCHIVAL = "archival"


class FloppyProfile(StrEnum):
    DD35 = "3.5-dd"
    HD35 = "3.5-hd"
    DD525 = "5.25-dd"
    UNKNOWN = "unknown"


FLOPPY_PROFILES = {
    FloppyProfile.DD35.value: {"size": "3.5", "density": "DD", "tracks": 80, "sides": 2, "rpm": 300},
    FloppyProfile.HD35.value: {"size": "3.5", "density": "HD", "tracks": 80, "sides": 2, "rpm": 300},
    FloppyProfile.DD525.value: {"size": "5.25", "density": "DD", "tracks": 40, "sides": 2, "rpm": 300},
    FloppyProfile.UNKNOWN.value: {"size": None, "density": None, "tracks": None, "sides": None, "rpm": None},
}


def _now() -> str:
    return datetime.now(UTC).isoformat()


class GreaseweazleAdapter(MediaAdapter):
    adapter_id = "greaseweazle"

    def __init__(self, *, runner=None, which=None, executable="gw"):
        self.runner = runner or self._run
        self.which = which or shutil.which
        self.executable = executable

    @staticmethod
    def _run(command, **kwargs):
        return subprocess.run(command, check=False, capture_output=True, text=True,
                              timeout=kwargs.get("timeout", 30), shell=False)

    def _path(self):
        return self.which(self.executable)

    def capabilities(self):
        path = self._path()
        return {"adapter_id": self.adapter_id, "available": bool(path), "kind": "flux",
                "executable": path, "capture_format": "scp", "supported_capture_formats": ["scp"],
                "supported_decode_formats": ["adf", "d64"], "external_decode_formats": ["g64", "ipf"],
                "read_only_capture": True, "write_operations": False,
                "hardware_write_protection": "unknown"}

    def _invoke(self, command, *, timeout=30):
        try:
            result = self.runner(command, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise FluxTimeoutError("Greaseweazle command timed out") from exc
        except (OSError, ValueError, TypeError) as exc:
            raise RabError("Greaseweazle command could not execute") from exc
        return result

    def info(self, device: str | None = None):
        if not self._path():
            return {"adapter_id": self.adapter_id, "available": False, "hardware_write_protection": "unknown"}
        command = [self.executable, "info"]
        if device:
            _validate_device(device); command.extend(["--device", device])
        result = self._invoke(command)
        output = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
        if result.returncode:
            raise RabError("Greaseweazle info failed")
        values = {"adapter_id": self.adapter_id, "available": True, "hardware_write_protection": "unknown",
                  "raw_info": output[:4096]}
        patterns = {"tool_version": r"Host Tools:\s*(.+)", "device": r"Device:\s*\n\s*Port:\s*(.+)",
                    "model": r"Model:\s*(.+)", "firmware_version": r"Firmware:\s*(.+)",
                    "serial": r"Serial:\s*(.+)"}
        for key, pattern in patterns.items():
            match = re.search(pattern, output, re.MULTILINE)
            if match: values[key] = match.group(1).strip()
        return values

    def devices(self):
        value = self.info()
        return [] if not value.get("available") else [value]

    def inspect(self, device: str):
        _validate_device(device)
        return self.info(device)

    def capture(self, device: str, destination: Path, *, drive="A", tracks="c=0-79:h=0-1",
                revolutions=3, timeout=86400, profile=None):
        _validate_device(device)
        if not self._path(): raise RabError("Greaseweazle tool is unavailable")
        if destination.suffix.lower() != ".scp": raise PolicyError("raw flux capture must use SCP")
        if revolutions < 1 or revolutions > 32: raise PolicyError("revolutions outside safe bound")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", drive): raise PolicyError("invalid Greaseweazle drive")
        if not re.fullmatch(r"[cChH0-9=,:.-]+", tracks): raise PolicyError("invalid track selection")
        command = [self.executable, "read", "--device", device, "--drive", drive,
                   "--raw", "--revs", str(revolutions), "--tracks", tracks, str(destination)]
        if any(token in {"write", "erase", "clean", "update"} for token in command):
            raise PolicyError("Greaseweazle write operation rejected")
        destination.parent.mkdir(parents=True, exist_ok=True)
        result = self._invoke(command, timeout=timeout)
        if result.returncode or not destination.is_file():
            destination.unlink(missing_ok=True)
            raise RabError("Greaseweazle flux capture failed")
        output = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
        weak = [line.strip() for line in output.splitlines() if re.search(r"weak|unstable|missing|error|anomal", line, re.I)]
        return {"command": command, "tool": self.executable, "format": "scp", "bytes": destination.stat().st_size,
                "drive": drive, "tracks": tracks, "revolutions": revolutions, "profile": profile,
                "read_errors": weak, "weak_track_observations": weak, "capture_mode_read_only": True,
                "hardware_write_protection": "unknown", "tool_output": output[-8192:]}


def _validate_device(device):
    if not device or len(device) > 256 or any(x in device for x in ("\x00", "\n", "\r")):
        raise PolicyError("invalid Greaseweazle device")


class FluxDecoder:
    decoder_id = "generic"

    def __init__(self, decoder_id, output_format, *, command=None, applicable=None, runner=None, tool_version=None):
        self.decoder_id, self.output_format, self.command = decoder_id, output_format, command
        self.applicable = applicable or (lambda profile: True); self.runner = runner; self.tool_version = tool_version

    def describe(self):
        return {"decoder_id": self.decoder_id, "output_format": self.output_format,
                "input_representations": ["FLUX_IMAGE"], "tool_version": self.tool_version,
                "available": bool(self.command or self.runner)}

    def decode(self, source: Path, destination: Path, *, profile=None, timeout=3600):
        if not self.applicable(profile): return {"outcome": "NOT_APPLICABLE"}
        if self.runner: result = self.runner(source, destination, profile=profile, timeout=timeout)
        elif self.command:
            command = [str(x).replace("{input}", str(source)).replace("{output}", str(destination)) for x in self.command]
            if any(x.lower() in {"write", "erase", "clean", "update"} for x in command): raise PolicyError("decoder write operation rejected")
            result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout, shell=False)
        else: return {"outcome": "UNAVAILABLE"}
        if getattr(result, "returncode", 0) or not destination.is_file(): return {"outcome": "FAILED", "error": "decoder failed"}
        return {"outcome": "COMPLETE", "bytes": destination.stat().st_size, "tool_version": self.tool_version}


class FluxManager:
    def __init__(self, archive, *, adapter=None, decoders=None):
        self.archive, self.adapter = archive, adapter or GreaseweazleAdapter()
        self.root, self.jobs_root = archive.root / "media" / "flux", archive.root / "media" / "flux" / "jobs"
        self.decoders = decoders or {
            "amiga-adf": FluxDecoder("amiga-adf", "adf", command=("gw", "convert", "--format=amiga.amigados", "{input}", "{output}")),
            "commodore-d64": FluxDecoder("commodore-d64", "d64", command=("gw", "convert", "--format=c64", "{input}", "{output}")),
            "commodore-g64": FluxDecoder("commodore-g64", "g64"),
        }

    def adapters(self): return [self.adapter.capabilities()]
    def devices(self): return self.adapter.devices()
    def inspect(self, device): return self.adapter.inspect(device)
    def profiles(self): return {key: dict(value) for key, value in FLOPPY_PROFILES.items()}
    def jobs(self): return [json.loads(x.read_text(encoding="utf-8")) for x in sorted(self.jobs_root.glob("*.json"))] if self.jobs_root.is_dir() else []
    def show(self, job_id):
        path = self.jobs_root / (job_id + ".json")
        if not path.is_file(): raise RabError("flux job not found")
        return json.loads(path.read_text(encoding="utf-8"))

    def capture(self, device, *, physical_medium_id=None, profile=FloppyProfile.UNKNOWN.value, drive="A",
                tracks="c=0-79:h=0-1", sides="0,1", revolutions=3, rights=Rights.UNKNOWN,
                provenance=ProvenanceClass.UNKNOWN, notes="", verification=VerificationPolicy.STANDARD):
        if profile not in FLOPPY_PROFILES: raise PolicyError("unknown floppy profile")
        self.jobs_root.mkdir(parents=True, exist_ok=True); job_id = uuid.uuid4().hex
        stage = self.root / "staging" / job_id / "capture.scp"
        job = {"schema": "rab-flux-capture-job-v1", "job_id": job_id, "physical_medium_id": physical_medium_id or "physical-floppy:" + uuid.uuid4().hex,
               "adapter_id": self.adapter.adapter_id, "state": IngestJobState.CAPTURING.value, "created_at": _now(),
               "selected_drive": drive, "expected_media_profile": profile, "sides": sides, "track_range": tracks,
               "revolutions": revolutions, "capture_format": "scp", "rab_capture_read_only": True,
               "hardware_write_protection": "unknown", "verification": {"policy": str(verification), "status": "NOT_PERFORMED"},
               "derived_representation_ids": [], "authority_observations": [], "malware_analysis": {"coverage": "CONTAINER_ONLY"}, "errors": []}
        self.archive._atomic_json(self.jobs_root / (job_id + ".json"), job)
        try:
            job["adapter"] = self.adapter.info(device); job["capture"] = self.adapter.capture(device, stage, drive=drive, tracks=tracks, revolutions=revolutions, profile=profile)
            job["inventory"] = inventory_image(stage); job["hashes"] = hash_file(stage); job["state"] = IngestJobState.INGESTING.value
            result = IngestManager(self.archive).ingest_staged(stage, category="personal", rights=rights, provenance=provenance, notes=notes, original_path=device, logical_path=job_id + ".scp")
            job.update({"object_id": result["object_id"], "ingest_job_id": result["job_id"], "state": FluxOutcome.COMPLETE.value,
                        "verification": self._verification(verification, job["capture"]), "completed_at": _now()})
        except FluxTimeoutError as exc:
            job.update({"state": FluxOutcome.TIMEOUT.value, "errors": [str(exc)]}); raise
        except Exception as exc:
            state = FluxOutcome.TOOL_MISSING.value if "unavailable" in str(exc).lower() else FluxOutcome.FAILED.value
            job.update({"state": state, "errors": [str(exc)]}); raise
        finally:
            if stage.is_file(): stage.unlink(missing_ok=True)
            job["updated_at"] = _now(); self.archive._atomic_json(self.jobs_root / (job_id + ".json"), job)
        return job

    @staticmethod
    def _verification(policy, capture):
        policy = VerificationPolicy(policy).value
        checks = ["capture_completed", "expected_track_range"]
        if policy == "fast": return {"policy": policy, "status": "PASS", "checks": checks, "raw_byte_identity": "single_capture_only"}
        return {"policy": policy, "status": "LIMITED", "checks": checks, "semantic_consistency": "NOT_PERFORMED",
                "raw_byte_identity": "not_a_repeat_read_rule", "limitations": "repeat capture requires operator workflow"}

    def decode(self, identifier, format_id, *, profile=None, rights=Rights.UNKNOWN):
        decoder = next((x for x in self.decoders.values() if x.output_format == format_id or x.decoder_id == format_id), None)
        if not decoder: raise RabError("flux decoder not found")
        source_sha = self.archive.resolve(identifier); source = self.archive.object_dir(source_sha) / "master"
        target = self.root / "derived" / (uuid.uuid4().hex + "." + decoder.output_format); target.parent.mkdir(parents=True, exist_ok=True)
        outcome = decoder.decode(source, target, profile=profile)
        if outcome["outcome"] != "COMPLETE": return {"source_object": "sha256:" + source_sha, "decoder": decoder.describe(), "result": outcome}
        result = self.archive.ingest(IngestRequest(target, "flux-decoder:" + decoder.decoder_id, target.name, rights,
                                                   "application/octet-stream", target.name, "sha256:" + source_sha,
                                                   "derived", {"decoder": decoder.describe()}))
        IdentityCatalogue(self.archive).add_relationship(result["object_id"], RelationshipType.DERIVED_FROM, "sha256:" + source_sha, {"decoder": decoder.describe(), "raw_flux_retained": True})
        target.unlink(missing_ok=True)
        return {"source_object": "sha256:" + source_sha, "decoder": decoder.describe(), "result": outcome, "object_id": result["object_id"]}
