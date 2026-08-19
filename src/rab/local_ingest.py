"""Generic local inbox ingest jobs converging on Archive.ingest."""
from __future__ import annotations

import json
import shutil
import time
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from .errors import PolicyError, RabError
from .hashing import hash_file
from .identity import IdentityCatalogue
from .malware import MalwareStore
from .model import IngestRequest, Rights


class ProvenanceClass(StrEnum):
    ORIGINAL_PHYSICAL_OWNED = "original_physical_owned"
    VENDOR_MEDIA = "vendor_media"
    PURCHASED_DOWNLOAD = "purchased_download"
    PERSONAL_DUMP = "personal_dump"
    PERSONAL_COPY = "personal_copy"
    BACKUP_COPY = "backup_copy"
    HISTORICAL_COPY = "historical_copy"
    PIRATE_COPY = "pirate_copy"
    UNKNOWN = "unknown"


class IngestJobState(StrEnum):
    PLANNED = "PLANNED"
    WAITING_FOR_MEDIA = "WAITING_FOR_MEDIA"
    CAPTURING = "CAPTURING"
    STAGED = "STAGED"
    INGESTING = "INGESTING"
    ANALYSING = "ANALYSING"
    IDENTIFYING = "IDENTIFYING"
    COMPLETED = "COMPLETED"
    COMPLETED_WITH_WARNINGS = "COMPLETED_WITH_WARNINGS"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


def _now() -> str:
    return datetime.now(UTC).isoformat()


class IngestManager:
    CATEGORIES = ("downloads", "purchased", "personal", "unknown")

    def __init__(self, archive, *, inbox_root: Path | None = None, stability_seconds: float = 1.0, read_only: bool = False):
        self.archive = archive; self.read_only = read_only; self.root = archive.root / "local-ingest"; self.jobs_root = self.root / "jobs"
        self.inbox_root = (inbox_root or archive.root / "inbox").resolve(); self.stability_seconds = stability_seconds

    def initialize(self):
        if self.read_only: return
        self.archive.initialize()
        self.jobs_root.mkdir(parents=True, exist_ok=True)
        for category in self.CATEGORIES:
            path = self.inbox_root / category; path.mkdir(parents=True, exist_ok=True); path.chmod(0o750)

    def _write(self, job):
        self.initialize(); self.archive._atomic_json(self.jobs_root / (job["job_id"] + ".json"), job); return job

    def jobs(self):
        self.initialize(); return [json.loads(x.read_text(encoding="utf-8")) for x in sorted(self.jobs_root.glob("*.json"))] if self.jobs_root.is_dir() else []

    def show(self, job_id: str):
        self.initialize(); path = self.jobs_root / (job_id + ".json")
        if not path.is_file(): raise RabError("ingest job not found")
        return json.loads(path.read_text(encoding="utf-8"))

    def _stable(self, path: Path) -> bool:
        first = path.stat()
        if self.stability_seconds: time.sleep(self.stability_seconds)
        second = path.stat(); return first.st_size == second.st_size and first.st_mtime_ns == second.st_mtime_ns

    @staticmethod
    def _validate_source(path: Path):
        path = path.resolve()
        if path.is_symlink() or not path.is_file(): raise PolicyError("local ingest requires a regular non-symlink file")
        return path

    def ingest_file(self, path: Path, *, category: str = "unknown", rights: Rights = Rights.UNKNOWN,
                    provenance: ProvenanceClass | str = ProvenanceClass.UNKNOWN, notes: str = "",
                    source_description: str | None = None) -> dict:
        if category not in self.CATEGORIES: raise PolicyError("unknown local inbox category")
        source = self._validate_source(path); provenance = ProvenanceClass(provenance); self.initialize()
        job_id = uuid.uuid4().hex; stage = self.root / "staging" / job_id; stage.mkdir(parents=True, exist_ok=False)
        staged = stage / source.name; shutil.copyfile(source, staged); staged.chmod(0o440)
        return self.ingest_staged(staged, job_id=job_id, category=category, rights=rights, provenance=provenance,
                                  notes=notes, source_description=source_description, original_path=str(source))

    def ingest_staged(self, staged: Path, *, job_id: str | None = None, category: str = "unknown",
                      rights: Rights = Rights.UNKNOWN, provenance: ProvenanceClass | str = ProvenanceClass.UNKNOWN,
                      notes: str = "", source_description: str | None = None, original_path: str | None = None) -> dict:
        self.initialize(); staged = self._validate_source(staged); job_id = job_id or uuid.uuid4().hex; provenance = ProvenanceClass(provenance)
        job = {"schema": "rab-local-ingest-job-v1", "job_id": job_id, "created_at": _now(), "started_at": _now(),
               "completed_at": None, "state": IngestJobState.INGESTING.value, "source_type": "local-file",
               "source_descriptor": {"category": category, "original_path": original_path, "description": source_description, "notes": notes},
               "provenance_classification": provenance.value, "rights": rights.value, "bytes": staged.stat().st_size,
               "object_id": None, "hashes": hash_file(staged), "duplicate": False, "warnings": [], "errors": [],
               "malware_state": "UNKNOWN", "identity_state": "PENDING"}
        self._write(job)
        with self.archive.db() as db:
            existing = db.execute("SELECT sha256 FROM objects WHERE sha256=?", (job["hashes"]["sha256"],)).fetchone()
        job["duplicate"] = bool(existing); source_id = "local-inbox:" + category
        source_path = category + "/" + Path(original_path or staged.name).name
        try:
            result = self.archive.ingest(IngestRequest(staged, source_id, source_path, rights,
                "application/octet-stream", staged.name, None, provenance.value,
                {"category": category, "notes": notes, "description": source_description}))
            job["object_id"] = result["object_id"]; job["state"] = IngestJobState.IDENTIFYING.value
            try:
                IdentityCatalogue(self.archive).rebuild(); job["identity_state"] = "AVAILABLE"
            except Exception as exc:
                job["warnings"].append("identity integration pending: " + str(exc)); job["identity_state"] = "PENDING"
            job["malware_state"] = MalwareStore(self.archive, read_only=True).status(result["object_id"])["state"] if (self.archive.root / "malware.sqlite3").is_file() else "UNKNOWN"
            job["state"] = IngestJobState.COMPLETED_WITH_WARNINGS.value if job["warnings"] else IngestJobState.COMPLETED.value
        except Exception as exc:
            job["state"] = IngestJobState.FAILED.value; job["errors"].append(str(exc)); raise
        finally:
            job["completed_at"] = _now(); self._write(job)
            if staged.is_file() and staged.is_relative_to(self.root.resolve()): staged.unlink(missing_ok=True)
        return job

    def scan_inbox(self, category: str | None = None) -> list[dict]:
        self.initialize(); categories = [category] if category else list(self.CATEGORIES); results = []
        for name in categories:
            if name not in self.CATEGORIES: raise PolicyError("unknown local inbox category")
            for path in sorted((self.inbox_root / name).rglob("*")):
                if path.is_symlink() or not path.is_file() or path.name.endswith(".part"): continue
                if self._stable(path): results.append(self.ingest_file(path, category=name))
        return results

    def status(self):
        jobs = self.jobs(); return {"jobs": len(jobs), "completed": sum(x["state"] == "COMPLETED" for x in jobs), "failed": sum(x["state"] == "FAILED" for x in jobs), "inboxes": {x: str(self.inbox_root / x) for x in self.CATEGORIES}}
