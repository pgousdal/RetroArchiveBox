"""Resumable, generic bootstrap orchestration over M6.1 transports."""
from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .errors import PolicyError, RabError
from .store import now
from .transports import AcquisitionPurpose, TransportResolver, TransportState


class BootstrapState:
    PLANNED = "PLANNED"
    RUNNING = "RUNNING"
    INTERRUPTED = "INTERRUPTED"
    COMPLETED = "COMPLETED"
    COMPLETED_WITH_ERRORS = "COMPLETED_WITH_ERRORS"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class BootstrapStore:
    def __init__(self, archive, *, read_only: bool = False):
        self.archive = archive
        self.read_only = read_only
        self.root = archive.root / "bootstrap-metadata"
        self.jobs_root = self.root / "jobs"
        self.reports_root = self.root / "reports"

    def _init(self):
        if self.read_only: return
        self.jobs_root.mkdir(parents=True, exist_ok=True); self.reports_root.mkdir(parents=True, exist_ok=True)

    def write(self, job: dict):
        self._init(); path = self.jobs_root / (job["job_id"] + ".json")
        self.archive._atomic_json(path, job)
        return job

    def read(self, job_id: str) -> dict:
        if not re.fullmatch(r"[0-9a-f]{32}", job_id): raise RabError("invalid bootstrap job id")
        self._init(); path = self.jobs_root / (job_id + ".json")
        if not path.is_file(): raise RabError("bootstrap job not found")
        return json.loads(path.read_text(encoding="utf-8"))

    def list(self) -> list[dict]:
        self._init()
        if not self.jobs_root.is_dir(): return []
        return [json.loads(path.read_text(encoding="utf-8")) for path in sorted(self.jobs_root.glob("*.json"))]

    def report(self, job_id: str) -> dict:
        if not re.fullmatch(r"[0-9a-f]{32}", job_id): raise RabError("invalid bootstrap job id")
        self._init(); path = self.reports_root / (job_id + ".json")
        if not path.is_file():
            job = self.read(job_id); return BootstrapOrchestrator(self.archive).make_report(job)
        return json.loads(path.read_text(encoding="utf-8"))

    def write_report(self, report: dict):
        self._init(); path = self.reports_root / (report["job_id"] + ".json")
        if path.exists():
            existing = json.loads(path.read_text(encoding="utf-8"))
            if existing != report: raise PolicyError("bootstrap report is immutable")
            return existing
        self.archive._atomic_json(path, report); path.chmod(0o444); return report


class BootstrapOrchestrator:
    def __init__(self, archive, *, resolver: TransportResolver | None = None):
        self.archive = archive
        self.resolver = resolver or TransportResolver()
        self.store = BootstrapStore(archive)

    def plan(self, source, items: list[str], purpose: AcquisitionPurpose | str = AcquisitionPurpose.BOOTSTRAP) -> dict:
        if not items: raise PolicyError("bootstrap requires at least one item")
        purpose = AcquisitionPurpose(purpose)
        return {"schema": "rab-bootstrap-plan-v1", "source": source.id, "purpose": purpose.value,
                "items": list(items), "transport_plan": self.resolver.plan(source, purpose)}

    def start(self, source, items: list[str], *, purpose: AcquisitionPurpose | str = AcquisitionPurpose.BOOTSTRAP) -> dict:
        plan = self.plan(source, items, purpose)
        job = {"schema": "rab-bootstrap-job-v1", "job_id": uuid.uuid4().hex,
               "source": source.id, "purpose": plan["purpose"], "items": plan["items"],
               "plan": plan["transport_plan"], "started_at": now(), "updated_at": now(),
               "state": BootstrapState.PLANNED, "completed_items": [], "skipped_items": [],
               "failed_items": [], "bytes_transferred": 0, "discovered_item_count": len(plan["items"]),
               "actual_transports": []}
        self.store.write(job)
        try:
            return self._run(source, job)
        except KeyboardInterrupt:
            job["state"] = BootstrapState.INTERRUPTED; job["updated_at"] = now(); self.store.write(job)
            raise

    def resume(self, source, job_id: str) -> dict:
        job = self.store.read(job_id)
        if job["state"] in {BootstrapState.COMPLETED, BootstrapState.COMPLETED_WITH_ERRORS, BootstrapState.CANCELLED}:
            return job
        if job["state"] == BootstrapState.RUNNING:
            job["state"] = BootstrapState.INTERRUPTED
        try:
            return self._run(source, job)
        except KeyboardInterrupt:
            job["state"] = BootstrapState.INTERRUPTED; job["updated_at"] = now(); self.store.write(job)
            raise

    def _run(self, source, job: dict) -> dict:
        if job["plan"].get("state") != TransportState.AVAILABLE.value:
            job["state"] = BootstrapState.FAILED
            job["failed_items"] = [{"item": None, "error": job["plan"].get("evidence", "transport unavailable")}]
            job["updated_at"] = now(); self.store.write(job); self.store.write_report(self.make_report(job)); return job
        job["state"] = BootstrapState.RUNNING; job["updated_at"] = now(); self.store.write(job)
        completed = {x["item"] for x in job["completed_items"] + job["skipped_items"]}
        from .acquisition import Acquisition
        acquisition = Acquisition(self.archive)
        for item in job["items"]:
            if item in completed: continue
            source_path = Path(item).name if item.startswith("/") else item
            try:
                existing = self._existing(source.id, source_path)
                if existing:
                    record = {"item": item, "status": "DEDUPLICATED", "object_id": "sha256:" + existing}
                    job["skipped_items"].append(record); completed.add(item); self._save_progress(job); continue
                result = self.resolver.fetch(acquisition, source, job["purpose"], path=item, plan=job["plan"])
                objects = self._objects(result)
                job["completed_items"].append({"item": item, "status": "ACQUIRED", "result": result, "objects": objects})
                transport = job["plan"].get("selected", {}).get("transport")
                if transport and transport not in job["actual_transports"]: job["actual_transports"].append(transport)
                job["bytes_transferred"] += sum(self.archive.show(x)["size"] for x in objects if self._exists(x))
            except Exception as exc:
                job["failed_items"].append({"item": item, "error": str(exc)})
            completed.add(item); self._save_progress(job)
        job["state"] = BootstrapState.COMPLETED_WITH_ERRORS if job["failed_items"] else BootstrapState.COMPLETED
        job["updated_at"] = now(); self.store.write(job); self.store.write_report(self.make_report(job)); return job

    def _save_progress(self, job):
        job["updated_at"] = now(); self.store.write(job)

    def _existing(self, source_id: str, source_path: str) -> str | None:
        with self.archive.db() as db:
            row = db.execute("SELECT sha256 FROM source_objects WHERE source_id=? AND source_path=? AND status='PRESENT'", (source_id, source_path)).fetchone()
        return row[0] if row else None

    def _exists(self, identifier: str) -> bool:
        try: self.archive.show(identifier); return True
        except RabError: return False

    @staticmethod
    def _objects(result: dict) -> list[str]:
        objects = []
        if result.get("object_id"): objects.append(result["object_id"])
        for item in result.get("payloads", []):
            if item.get("object_id"): objects.append(item["object_id"])
        return sorted(set(objects))

    def make_report(self, job: dict) -> dict:
        return {"schema": "rab-bootstrap-report-v1", "job_id": job["job_id"], "source": job["source"],
                "purpose": job["purpose"], "state": job["state"], "started_at": job["started_at"],
                "updated_at": job["updated_at"], "transport_plan": job["plan"],
                "transport": (job["plan"].get("selected") or {}).get("transport"),
                "transport_version": (job["plan"].get("selected") or {}).get("capability", {}).get("version"),
                "actual_transports": job.get("actual_transports", []),
                "items": {"total": len(job["items"]), "completed": len(job["completed_items"]),
                          "deduplicated": len(job["skipped_items"]), "failed": len(job["failed_items"])},
                "bytes_transferred": job["bytes_transferred"],
                "objects": [obj for item in job["completed_items"] for obj in item.get("objects", [])] + [x["object_id"] for x in job["skipped_items"] if x.get("object_id")],
                "completed_items": job["completed_items"], "skipped_items": job["skipped_items"],
                "failed_items": job["failed_items"]}
