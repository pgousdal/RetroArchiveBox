"""Deterministic filesystem-tree ingest without packaging or symlink traversal."""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .errors import PolicyError, RabError
from .local_ingest import IngestManager, ProvenanceClass
from .model import Rights


def _now(): return datetime.now(UTC).isoformat()


class TreeIngestManager:
    def __init__(self, archive):
        self.archive = archive; self.root = archive.root / "tree-ingest"; self.jobs_root = self.root / "jobs"

    def ingest(self, directory: Path, *, category: str = "unknown", rights: Rights = Rights.UNKNOWN,
               provenance: ProvenanceClass | str = ProvenanceClass.UNKNOWN, notes: str = "") -> dict:
        root = directory.resolve()
        if not root.is_dir() or root.is_symlink(): raise PolicyError("tree ingest requires a regular directory")
        self.jobs_root.mkdir(parents=True, exist_ok=True); job_id = uuid.uuid4().hex
        job = {"schema": "rab-tree-ingest-job-v1", "job_id": job_id, "state": "INGESTING", "root_name": root.name, "created_at": _now(), "entries": [], "errors": [], "rights": rights.value, "provenance_classification": ProvenanceClass(provenance).value}
        manager = IngestManager(self.archive); self.archive._atomic_json(self.jobs_root / (job_id + ".json"), job)
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                job["entries"].append({"path": relative, "type": "symlink", "target": path.readlink().as_posix()}); continue
            if path.is_dir():
                job["entries"].append({"path": relative, "type": "directory"}); continue
            if not path.is_file():
                job["entries"].append({"path": relative, "type": "special", "status": "REJECTED"}); continue
            try:
                result = manager.ingest_file(path, category=category, rights=rights, provenance=provenance, notes=notes, source_description="tree:" + root.name, logical_path=relative)
                job["entries"].append({"path": relative, "type": "file", "object_id": result["object_id"], "duplicate": result["duplicate"], "size": result["bytes"]})
            except Exception as exc:
                job["errors"].append({"path": relative, "error": str(exc)})
        job["state"] = "COMPLETED_WITH_WARNINGS" if job["errors"] else "COMPLETED"; job["completed_at"] = _now()
        manifest = json.dumps(job["entries"], sort_keys=True, separators=(",", ":")).encode()
        job["manifest_sha256"] = hashlib.sha256(manifest).hexdigest(); self.archive._atomic_json(self.jobs_root / (job_id + ".json"), job)
        return job

    def jobs(self):
        return [json.loads(x.read_text(encoding="utf-8")) for x in sorted(self.jobs_root.glob("*.json"))] if self.jobs_root.is_dir() else []
