"""Unified, fail-closed operator orchestration over existing media managers."""
from __future__ import annotations

import json
import socket
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from .authority import Authority
from .errors import PolicyError, RabError
from .flux import FluxManager, FloppyProfile, VerificationPolicy
from .local_ingest import ProvenanceClass
from .malware import MalwareStore
from .media import MediaManager, OpticalManager, OpticalOutcome
from .model import Rights


def _now():
    return datetime.now(UTC).isoformat()


class CandidateKind(StrEnum):
    OPTICAL = "optical"
    BLOCK = "block"
    FLUX = "flux"


class CandidateSafety(StrEnum):
    SAFE_CANDIDATE = "SAFE_CANDIDATE"
    PROTECTED = "PROTECTED"
    NON_REMOVABLE = "NON_REMOVABLE"
    UNKNOWN = "UNKNOWN"
    UNAVAILABLE = "UNAVAILABLE"


class SessionState(StrEnum):
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    INTERRUPTED = "INTERRUPTED"


class PhysicalMediaOrchestrator:
    """Discovery/planning/session layer. Adapters retain all capture logic."""
    VERSION = 1

    def __init__(self, archive, *, optical=None, block=None, flux=None, input_fn=input, output_fn=print):
        self.archive = archive
        self.optical = optical or OpticalManager(archive)
        self.block = block or MediaManager(archive)
        self.flux = flux or FluxManager(archive)
        self.input_fn, self.output_fn = input_fn, output_fn
        self.root = archive.root / "physical-ingest"
        self.sessions_root = self.root / "sessions"

    @staticmethod
    def _candidate(kind, candidate_id, description, *, device=None, available=True, present=False,
                   safety=CandidateSafety.UNKNOWN, summary=None, confidence="LOW", limitations=(),
                   requires_selection=True, suggested_action="INSPECT"):
        return {"candidate_id": candidate_id, "kind": kind.value, "display_description": description,
                "device": device, "available": available, "medium_present": present,
                "device_summary": summary or {}, "safety": str(safety), "confidence": confidence,
                "limitations": list(limitations), "requires_operator_selection": requires_selection,
                "suggested_action": suggested_action}

    def discover(self) -> list[dict]:
        candidates = []
        try:
            optical_devices = self.optical.devices()
            for item in optical_devices:
                device = item.get("path")
                try:
                    inspection = self.optical.inspect(device)
                    inspection = inspection if isinstance(inspection, dict) else inspection
                    present = inspection.get("medium_type") not in {None, "unknown-optical"}
                    summary = {key: inspection.get(key) for key in ("medium_type", "volume_label", "filesystem", "capacity_bytes", "device")}
                    limitations = inspection.get("limitations", ())
                except Exception as exc:
                    present, summary, limitations = False, item, ("inspection unavailable: " + str(exc),)
                candidates.append(self._candidate(CandidateKind.OPTICAL, "optical:" + str(device), "Optical drive " + str(device), device=device, present=present, safety=CandidateSafety.SAFE_CANDIDATE, summary=summary, confidence="HIGH" if present else "MEDIUM", limitations=limitations, requires_selection=len(optical_devices) != 1, suggested_action="PLAN" if present else "WAIT_FOR_MEDIA"))
        except Exception:
            pass
        try:
            for item in self.block.devices():
                device = item.get("path")
                removable = bool(item.get("removable") or item.get("rm"))
                safety = CandidateSafety(item.get("safety", CandidateSafety.UNKNOWN.value)) if item.get("safety") in CandidateSafety._value2member_map_ else CandidateSafety.UNKNOWN
                candidates.append(self._candidate(CandidateKind.BLOCK, "block:" + str(device), "Removable block device " + str(device), device=device, present=True, available=removable and safety == CandidateSafety.SAFE_CANDIDATE, safety=safety, summary={key: item.get(key) for key in ("model", "serial", "size", "transport", "ro", "label", "fstype")}, confidence="HIGH" if removable else "LOW", limitations=("whole-device capture only",) if removable else ("not removable or safety is uncertain",), requires_selection=True, suggested_action="PLAN" if removable and safety == CandidateSafety.SAFE_CANDIDATE else "REJECT"))
        except Exception:
            pass
        try:
            for item in self.flux.devices():
                device = item.get("device") or item.get("port") or item.get("serial")
                candidates.append(self._candidate(CandidateKind.FLUX, "flux:" + str(device or self.flux.adapter.adapter_id), "Greaseweazle flux adapter", device=device, present=bool(item.get("available", True)), safety=CandidateSafety.SAFE_CANDIDATE, summary={key: item.get(key) for key in ("model", "firmware_version", "serial", "tool_version", "device")}, confidence="MEDIUM", limitations=("drive and floppy profile may require explicit selection",), requires_selection=True, suggested_action="PLAN"))
        except Exception:
            pass
        return candidates

    def public_candidates(self) -> list[dict]:
        result = []
        for item in self.discover():
            value = {key: data for key, data in item.items() if key != "device"}
            value["device_summary"] = {key: data for key, data in value.get("device_summary", {}).items() if key not in {"device", "path"}}
            result.append(value)
        return result

    def candidate(self, candidate_id: str | None = None) -> dict:
        candidates = self.discover()
        if candidate_id:
            for item in candidates:
                if item["candidate_id"] == candidate_id: return item
            raise PolicyError("candidate not found; run 'rab media ingest --dry-run'")
        usable = [x for x in candidates if x["available"] and x["medium_present"] and x["safety"] == CandidateSafety.SAFE_CANDIDATE.value and not x["requires_operator_selection"]]
        if len(usable) != 1:
            safe = [x for x in candidates if x["available"] and x["medium_present"] and x["safety"] == CandidateSafety.SAFE_CANDIDATE.value]
            if len(safe) > 1: raise PolicyError("multiple candidates detected; use --candidate")
            if safe and not usable: raise PolicyError("candidate requires explicit selection; use --candidate")
            if not usable: raise PolicyError("no safe physical-media candidate is available")
            raise PolicyError("no safe physical-media candidate is available")
        return usable[0]

    def inspect(self, candidate: dict) -> dict:
        kind = CandidateKind(candidate["kind"]); device = candidate.get("device")
        if kind is CandidateKind.OPTICAL: value = self.optical.inspect(device); return value if isinstance(value, dict) else value
        if kind is CandidateKind.BLOCK: return self.block.inspect(device)
        return self.flux.inspect(device)

    def plan(self, candidate: dict, *, verification: str = "standard", profile: str | None = None,
             drive: str | None = None, tracks: str | None = None, provenance: str = ProvenanceClass.ORIGINAL_PHYSICAL_OWNED.value,
             rights: str = Rights.UNKNOWN.value, metadata: dict | None = None) -> dict:
        kind = CandidateKind(candidate["kind"]); inspection = self.inspect(candidate); limitations = list(candidate.get("limitations", ()))
        if kind is CandidateKind.OPTICAL:
            optical_inspection = inspection
            plan = self.optical.adapter.plan(self.optical.adapter.inspect(candidate["device"]))
            representation = "ISO-like data capture" if plan.get("strategy") == "ISO_SECTOR" else "track-aware optical capture"
            method = "optical-data" if plan.get("strategy") == "ISO_SECTOR" else "optical-track-aware"
            expected_size = optical_inspection.get("capacity_bytes")
            limitations.extend([plan.get("reason")] if plan.get("reason") else [])
            state = plan.get("state")
        elif kind is CandidateKind.BLOCK:
            if candidate["safety"] != CandidateSafety.SAFE_CANDIDATE.value: raise PolicyError("block device rejected by safety policy")
            representation, method, expected_size, state = "whole-device image", "block-device-dd", inspection.get("size"), "COMPLETE"
            limitations.append("source is never mounted or written")
        else:
            if not drive and not profile: limitations.append("Greaseweazle drive and floppy profile require operator selection")
            representation, method, expected_size, state = "SCP raw flux", "greaseweazle-flux", None, "REQUIRES_OPERATOR_SELECTION" if not drive or not profile else "COMPLETE"
        return {"schema": "rab-physical-ingest-plan-v1", "version": self.VERSION, "candidate": {key: value for key, value in candidate.items() if key != "device"}, "inspection": inspection, "capture": {"method": method, "representation": representation, "expected_size": expected_size, "profile": profile, "drive": drive, "tracks": tracks}, "verification": {"policy": verification}, "provenance": provenance, "rights": rights, "analysis": {"identity": True, "authority": True, "malware": True}, "limitations": [x for x in limitations if x], "adapter_state": state, "requires_confirmation": True, "metadata": metadata or {}}

    def _confirm(self, plan: dict, *, confirm: bool, interactive: bool) -> bool:
        if confirm: return True
        if not interactive: raise PolicyError("capture requires explicit confirmation in non-interactive mode")
        self.output_fn(json.dumps(plan, indent=2, sort_keys=True))
        return self.input_fn("Proceed with preservation capture? [y/N] ").strip().lower() in {"y", "yes"}

    def _capture(self, candidate: dict, plan: dict):
        kind = CandidateKind(candidate["kind"]); capture = plan["capture"]
        provenance, rights = ProvenanceClass(plan["provenance"]), Rights(plan["rights"])
        notes = json.dumps(plan.get("metadata", {}), sort_keys=True)
        if kind is CandidateKind.OPTICAL:
            return self.optical.capture(candidate["device"], rights=rights, provenance=provenance, notes=notes, verification=plan["verification"]["policy"])
        if kind is CandidateKind.BLOCK:
            return self.block.capture(candidate["device"], rights=rights, provenance=provenance, notes=notes)
        if not capture.get("profile") or not capture.get("drive"): raise PolicyError("Greaseweazle capture requires explicit --profile and --drive")
        profile = capture["profile"]
        return self.flux.capture(candidate["device"], profile=profile, drive=capture.get("drive") or "A", tracks=capture.get("tracks") or "c=0-79:h=0-1", rights=rights, provenance=provenance, notes=notes, verification=plan["verification"]["policy"])

    def _post_capture(self, result: dict, plan: dict) -> dict:
        object_id = result.get("object_id")
        duplicate = False
        if result.get("ingest_job_id"):
            try:
                job = json.loads((self.archive.root / "local-ingest" / "jobs" / (result["ingest_job_id"] + ".json")).read_text(encoding="utf-8")); duplicate = bool(job.get("duplicate"))
            except (OSError, ValueError): pass
        byte_count = int(result.get("capture", {}).get("bytes", result.get("bytes", 0)) or 0)
        if not byte_count and result.get("ingest_job_id"):
            try: byte_count = int(json.loads((self.archive.root / "local-ingest" / "jobs" / (result["ingest_job_id"] + ".json")).read_text(encoding="utf-8")).get("bytes", 0))
            except (OSError, ValueError): pass
        report = {"preservation": "COMPLETE" if object_id else "FAILED", "object_id": object_id, "bytes": byte_count, "verification": result.get("verification", {"status": "NOT_REPORTED"}), "identity": "PENDING", "authority": "NOT_CHECKED", "malware": "NOT_SCANNED", "catalogue": "PENDING", "existing_bytes": "REUSED" if duplicate else "NEW" if object_id else "UNKNOWN", "provenance": plan["provenance"], "warnings": []}
        if not object_id: return report
        try:
            from .identity import IdentityCatalogue
            IdentityCatalogue(self.archive).rebuild(); report["identity"] = "AVAILABLE"
        except Exception as exc: report["warnings"].append("identity: " + str(exc)); report["identity"] = "PARTIAL"
        try:
            assertions = Authority(self.archive).assertions(object_id, read_only=True)
            report["authority"] = "MATCHED" if any(x.get("result") == "EXACT_MATCH" for x in assertions) else "CHECKED_NO_MATCH" if assertions else "NOT_CHECKED"
        except Exception as exc: report["warnings"].append("authority: " + str(exc))
        try:
            report["malware"] = MalwareStore(self.archive, read_only=True).status(object_id)["state"] if (self.archive.root / "malware.sqlite3").is_file() else "NOT_SCANNED"
        except Exception as exc: report["warnings"].append("malware: " + str(exc)); report["malware"] = "PARTIAL"
        try:
            from .catalogue import Catalogue
            Catalogue(self.archive).rebuild(); report["catalogue"] = "COMPLETE"
        except Exception as exc: report["warnings"].append("catalogue: " + str(exc)); report["catalogue"] = "PARTIAL"
        return report

    def sessions(self) -> list[dict]:
        return [json.loads(x.read_text(encoding="utf-8")) for x in sorted(self.sessions_root.glob("*.json"))] if self.sessions_root.is_dir() else []

    def public_sessions(self) -> list[dict]:
        return [{"session_id": session.get("session_id"), "state": session.get("state"), "started_at": session.get("started_at"), "completed_at": session.get("completed_at"), "collection": session.get("collection"), "media_count": session.get("media_count"), "successful_captures": session.get("successful_captures"), "duplicates": session.get("duplicates"), "warnings_count": len(session.get("warnings", [])), "failures_count": len(session.get("failures", [])), "bytes_preserved": session.get("bytes_preserved")} for session in self.sessions()]

    def _session(self, session_id: str, *, operator=None, collection=None, persist=True) -> dict:
        if persist: self.sessions_root.mkdir(parents=True, exist_ok=True)
        return {"schema": "rab-physical-ingest-session-v1", "session_id": session_id, "state": SessionState.ACTIVE.value, "started_at": _now(), "completed_at": None, "operator": operator, "host": socket.gethostname(), "collection": collection, "media": [], "media_count": 0, "successful_captures": 0, "duplicates": 0, "warnings": [], "failures": [], "bytes_preserved": 0}

    def ingest(self, *, candidate_id=None, verification="standard", provenance=ProvenanceClass.ORIGINAL_PHYSICAL_OWNED.value, rights=Rights.UNKNOWN.value, profile=None, drive=None, tracks=None, metadata=None, dry_run=False, confirm=False, interactive=True, batch=False, session_id=None, max_media=None) -> dict:
        session_id = session_id or "physical-ingest-" + uuid.uuid4().hex[:12]
        session = self._session(session_id, collection=(metadata or {}).get("collection"), persist=not dry_run)
        if not dry_run: self.archive._atomic_json(self.sessions_root / (session_id + ".json"), session)
        processed = 0
        while True:
            candidate = self.candidate(candidate_id)
            if candidate["kind"] == CandidateKind.BLOCK.value and candidate["safety"] != CandidateSafety.SAFE_CANDIDATE.value: raise PolicyError("device rejected because it is not a safe removable candidate")
            plan = self.plan(candidate, verification=verification, profile=profile, drive=drive, tracks=tracks, provenance=provenance, rights=rights, metadata=metadata)
            if dry_run: return {"session_id": session_id, "candidate": {key: value for key, value in candidate.items() if key != "device"}, "plan": plan, "capture_performed": False}
            if not self._confirm(plan, confirm=confirm, interactive=interactive): return {"session_id": session_id, "state": "CANCELLED", "plan": plan, "capture_performed": False}
            try:
                result = self._capture(candidate, plan); report = self._post_capture(result, plan); entry = {"candidate_id": candidate["candidate_id"], "kind": candidate["kind"], "result": result, "report": report, "completed_at": _now()}; session["media"].append(entry); session["media_count"] += 1; session["successful_captures"] += int(bool(result.get("object_id"))); session["duplicates"] += int(report.get("existing_bytes") == "REUSED"); session["bytes_preserved"] += int(report.get("bytes", 0)); session["warnings"].extend(report.get("warnings", [])); self.archive._atomic_json(self.sessions_root / (session_id + ".json"), session)
            except KeyboardInterrupt:
                session["state"] = SessionState.INTERRUPTED.value; session["completed_at"] = _now(); break
            except Exception as exc:
                session["failures"].append({"candidate_id": candidate["candidate_id"], "error": str(exc)}); session["media_count"] += 1
                if not batch:
                    session["state"] = SessionState.INTERRUPTED.value; session["completed_at"] = _now(); self.archive._atomic_json(self.sessions_root / (session_id + ".json"), session); raise
                self.archive._atomic_json(self.sessions_root / (session_id + ".json"), session)
            processed += 1
            if not batch or (max_media is not None and processed >= max_media): break
            candidate_id = candidate["candidate_id"]
            if interactive:
                self.input_fn("Remove the medium, insert the next medium, then press Enter (Ctrl-C to stop): ")
        if session["state"] == SessionState.ACTIVE.value: session["state"] = SessionState.COMPLETED.value
        session["completed_at"] = _now(); self.archive._atomic_json(self.sessions_root / (session_id + ".json"), session)
        return {"session_id": session_id, "state": session["state"], "session": session, "report": session["media"][-1]["report"] if session["media"] else None}
