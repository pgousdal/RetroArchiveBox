"""Persistent, fail-closed orchestration of RAB physical preservation subsystems."""
from __future__ import annotations

import json
import shutil
import uuid
from datetime import UTC, datetime
from enum import StrEnum

from .analysis import AnalysisLimits, AnalysisManager
from .errors import PolicyError, RabError
from .identity import IdentityCatalogue
from .local_ingest import ProvenanceClass
from .malware_provider import MalwareProviderManager
from .model import Rights
from .physical import CandidateKind, CandidateSafety, PhysicalMediaOrchestrator
from .physical_registry import PhysicalMediaClass, PhysicalMediaRegistry
from .products import ProductBuilder


def _now(): return datetime.now(UTC).isoformat()


class WorkflowState(StrEnum):
    CREATED = "CREATED"; WAITING_FOR_MEDIA = "WAITING_FOR_MEDIA"; MEDIA_DETECTED = "MEDIA_DETECTED"
    INSPECTING = "INSPECTING"; NEEDS_METADATA = "NEEDS_METADATA"; READY_TO_CAPTURE = "READY_TO_CAPTURE"
    CAPTURING = "CAPTURING"; VERIFYING = "VERIFYING"; PRESERVED = "PRESERVED"
    ANALYZING = "ANALYZING"; MALWARE_ANALYSIS = "MALWARE_ANALYSIS"; IDENTIFYING = "IDENTIFYING"
    BUILDING_PRODUCTS = "BUILDING_PRODUCTS"; COMPLETE = "COMPLETE"; NEEDS_OPERATOR = "NEEDS_OPERATOR"
    COMPLETE_WITH_WARNINGS = "COMPLETE_WITH_WARNINGS"; PARTIAL = "PARTIAL"; UNSUPPORTED = "UNSUPPORTED"
    TOOL_MISSING = "TOOL_MISSING"; DEVICE_REMOVED = "DEVICE_REMOVED"; FAILED = "FAILED"; CANCELLED = "CANCELLED"


TERMINAL = {WorkflowState.COMPLETE, WorkflowState.COMPLETE_WITH_WARNINGS, WorkflowState.PARTIAL,
            WorkflowState.UNSUPPORTED, WorkflowState.FAILED, WorkflowState.CANCELLED}
TRANSITIONS = {
    WorkflowState.CREATED: {WorkflowState.WAITING_FOR_MEDIA, WorkflowState.MEDIA_DETECTED, WorkflowState.NEEDS_OPERATOR, WorkflowState.CANCELLED},
    WorkflowState.WAITING_FOR_MEDIA: {WorkflowState.MEDIA_DETECTED, WorkflowState.CANCELLED},
    WorkflowState.MEDIA_DETECTED: {WorkflowState.INSPECTING, WorkflowState.NEEDS_OPERATOR, WorkflowState.CANCELLED},
    WorkflowState.INSPECTING: {WorkflowState.NEEDS_METADATA, WorkflowState.READY_TO_CAPTURE, WorkflowState.NEEDS_OPERATOR, WorkflowState.TOOL_MISSING, WorkflowState.UNSUPPORTED, WorkflowState.FAILED, WorkflowState.CANCELLED},
    WorkflowState.NEEDS_METADATA: {WorkflowState.READY_TO_CAPTURE, WorkflowState.NEEDS_OPERATOR, WorkflowState.CANCELLED},
    WorkflowState.READY_TO_CAPTURE: {WorkflowState.CAPTURING, WorkflowState.NEEDS_OPERATOR, WorkflowState.FAILED, WorkflowState.CANCELLED},
    WorkflowState.CAPTURING: {WorkflowState.VERIFYING, WorkflowState.PARTIAL, WorkflowState.DEVICE_REMOVED, WorkflowState.FAILED, WorkflowState.CANCELLED},
    WorkflowState.DEVICE_REMOVED: {WorkflowState.PARTIAL, WorkflowState.FAILED, WorkflowState.CANCELLED},
    WorkflowState.VERIFYING: {WorkflowState.PRESERVED, WorkflowState.NEEDS_OPERATOR, WorkflowState.PARTIAL, WorkflowState.FAILED, WorkflowState.CANCELLED},
    WorkflowState.PRESERVED: {WorkflowState.ANALYZING, WorkflowState.IDENTIFYING, WorkflowState.BUILDING_PRODUCTS, WorkflowState.COMPLETE, WorkflowState.COMPLETE_WITH_WARNINGS, WorkflowState.CANCELLED},
    WorkflowState.ANALYZING: {WorkflowState.MALWARE_ANALYSIS, WorkflowState.IDENTIFYING, WorkflowState.COMPLETE_WITH_WARNINGS, WorkflowState.NEEDS_OPERATOR, WorkflowState.FAILED, WorkflowState.CANCELLED},
    WorkflowState.MALWARE_ANALYSIS: {WorkflowState.IDENTIFYING, WorkflowState.COMPLETE_WITH_WARNINGS, WorkflowState.CANCELLED},
    WorkflowState.IDENTIFYING: {WorkflowState.BUILDING_PRODUCTS, WorkflowState.COMPLETE_WITH_WARNINGS, WorkflowState.CANCELLED},
    WorkflowState.BUILDING_PRODUCTS: {WorkflowState.COMPLETE, WorkflowState.COMPLETE_WITH_WARNINGS, WorkflowState.CANCELLED},
    WorkflowState.NEEDS_OPERATOR: {WorkflowState.READY_TO_CAPTURE, WorkflowState.ANALYZING, WorkflowState.MALWARE_ANALYSIS, WorkflowState.IDENTIFYING, WorkflowState.CANCELLED},
    WorkflowState.TOOL_MISSING: {WorkflowState.READY_TO_CAPTURE, WorkflowState.COMPLETE_WITH_WARNINGS, WorkflowState.CANCELLED},
}


PROFILES = {
    "quick": {"capture_repeats": 1, "require_repeat_match": False, "analysis_policy": "metadata-only", "malware_profile": None, "products": ("capture-status", "provenance-inventory")},
    "standard": {"capture_repeats": 1, "require_repeat_match": False, "analysis_policy": "preserve", "malware_profile": "current-standard", "products": ("capture-status", "contained-manifest", "analysis-coverage", "provenance-inventory")},
    "conservative": {"capture_repeats": 2, "require_repeat_match": True, "analysis_policy": "archival", "malware_profile": "retro-standard", "products": ("fixity", "capture-status", "contained-manifest", "format-inventory", "analysis-coverage", "provenance-inventory")},
}


class PreservationWorkflow:
    """Durable workflow above existing capture managers; never reads a live medium after ingest."""
    VERSION = 1
    def __init__(self, archive, *, media=None, registry=None, analysis=None, malware=None, identity=None, products=None):
        self.archive = archive; self.media = media or PhysicalMediaOrchestrator(archive)
        self.registry = registry or PhysicalMediaRegistry(archive); self.analysis = analysis or AnalysisManager(archive)
        self.malware = malware or MalwareProviderManager(archive); self.identity = identity or IdentityCatalogue(archive)
        self.products = products or ProductBuilder(archive); self.root = archive.root / "preservation-workflows"
        self.runs_root = self.root / "runs"; self.events_root = self.root / "events"; self.reports_root = self.root / "reports"

    def _path(self, run_id):
        if not isinstance(run_id, str) or not run_id.startswith("rab-preserve-") or not run_id[13:].isalnum(): raise PolicyError("invalid preservation run id")
        return self.runs_root / (run_id + ".json")

    def show(self, run_id):
        path = self._path(run_id)
        if not path.is_file(): raise RabError("preservation run not found")
        return json.loads(path.read_text(encoding="utf-8"))

    def list(self): return [json.loads(x.read_text(encoding="utf-8")) for x in sorted(self.runs_root.glob("*.json"))] if self.runs_root.is_dir() else []
    def events(self, run_id):
        self.show(run_id); root = self.events_root / run_id
        return [json.loads(x.read_text(encoding="utf-8")) for x in sorted(root.glob("*.json"))] if root.is_dir() else []

    def _save(self, run): run["updated_at"] = _now(); self.archive._atomic_json(self._path(run["run_id"]), run)
    def _event(self, run, event_type, *, outcome="PASS", detail=None):
        sequence = len(self.events(run["run_id"])) + 1; item = {"schema": "rab-preservation-event-v1", "event_id": uuid.uuid4().hex, "run_id": run["run_id"], "sequence": sequence, "recorded_at": _now(), "event_type": event_type, "outcome": outcome, "detail": detail or {}}
        path = self.events_root / run["run_id"] / f"{sequence:06d}-{item['event_id']}.json"; self.archive._atomic_json(path, item); path.chmod(0o444); run["event_count"] = sequence; return item

    def transition(self, run_id, state, *, event_type=None, detail=None):
        run = self.show(run_id); old, new = WorkflowState(run["state"]), WorkflowState(state)
        if new not in TRANSITIONS.get(old, set()): raise PolicyError(f"invalid preservation transition: {old.value} -> {new.value}")
        self._event(run, event_type or "workflow_state_changed", detail={"from": old.value, "to": new.value, **(detail or {})}); run["state"] = new.value
        if new in TERMINAL: run["completed_at"] = _now()
        self._save(run); return run

    def create(self, *, physical_medium_id=None, intake_session_id=None, profile="standard", operator=None, metadata=None):
        if profile not in PROFILES: raise PolicyError("unknown preservation profile")
        if physical_medium_id: self.registry.show(physical_medium_id)
        run_id = "rab-preserve-" + uuid.uuid4().hex
        run = {"schema": "rab-preservation-run-v1", "version": self.VERSION, "run_id": run_id, "state": WorkflowState.CREATED.value, "created_at": _now(), "updated_at": _now(), "completed_at": None, "physical_medium_id": physical_medium_id, "intake_session_id": intake_session_id, "operator": operator, "profile": profile, "metadata": metadata or {}, "candidate": None, "plan": None, "captures": [], "preservation_objects": [], "analysis_jobs": [], "malware_jobs": [], "identity": [], "products": [], "warnings": [], "failures": [], "operator_decisions": [], "review_reasons": [], "event_count": 0}
        self._save(run); self._event(run, "workflow_created", detail={"profile": profile}); self._save(run); return run

    @staticmethod
    def _media_class(kind): return {"optical": PhysicalMediaClass.OPTICAL_DISC.value, "block": PhysicalMediaClass.REMOVABLE_FLASH.value, "flux": PhysicalMediaClass.FLOPPY_DISK.value}.get(kind, PhysicalMediaClass.UNKNOWN.value)
    def devices(self): return self.media.public_candidates()

    def prepare(self, run_id, *, candidate_id=None, physical_medium_id=None, title=None, platform=None,
                provenance=ProvenanceClass.UNKNOWN.value, rights=Rights.UNKNOWN.value, media_class=None,
                drive=None, floppy_profile=None, tracks=None):
        run = self.show(run_id)
        if run["state"] == WorkflowState.CREATED.value:
            try: candidate = self.media.candidate(candidate_id)
            except PolicyError as exc:
                run["warnings"].append(str(exc)); self._save(run); return self.transition(run_id, WorkflowState.NEEDS_OPERATOR, event_type="operator_review_requested", detail={"reason": str(exc)})
            self.transition(run_id, WorkflowState.MEDIA_DETECTED, event_type="medium_detected", detail={"kind": candidate["kind"]}); run = self.transition(run_id, WorkflowState.INSPECTING, event_type="inspection_started")
        else: candidate = self._private_candidate(run)
        media_id = physical_medium_id or run.get("physical_medium_id")
        if media_id: self.registry.show(media_id)
        else:
            record = self.registry.register(media_class or self._media_class(candidate["kind"]), provenance=provenance, rights=rights, metadata={key: value for key, value in {"title": title, "platform": platform}.items() if value})
            media_id = record["physical_medium_id"]
        profile = PROFILES[run["profile"]]
        verification = "conservative" if profile["capture_repeats"] > 1 else run["profile"]
        plan = self.media.plan(candidate, verification=verification, profile=floppy_profile, drive=drive, tracks=tracks, provenance=provenance, rights=rights, metadata={"title": title, "platform": platform})
        run = self.show(run_id); run["physical_medium_id"] = media_id; run["intake_session_id"] = self.registry.show(media_id).get("intake_session_id")
        run["candidate"] = {key: value for key, value in candidate.items() if key != "device"}; run["candidate_private"] = {"device": candidate.get("device")}; run["plan"] = plan
        if plan.get("adapter_state") in {"REQUIRES_OPERATOR_SELECTION", "TOOL_MISSING", "UNSUPPORTED"}:
            run["review_reasons"].append("capture strategy is not safely executable: " + str(plan.get("adapter_state"))); self._save(run)
            return self.transition(run_id, WorkflowState.NEEDS_OPERATOR, event_type="operator_review_requested")
        self._event(run, "strategy_selected", detail={"method": plan["capture"]["method"]}); self._save(run)
        return self.transition(run_id, WorkflowState.READY_TO_CAPTURE, event_type="plan_ready")

    def _private_candidate(self, run):
        candidate = dict(run.get("candidate") or {}); candidate.update(run.get("candidate_private") or {})
        if not candidate: raise PolicyError("workflow has no selected candidate")
        return candidate

    def _space_check(self, run):
        expected = (run.get("plan") or {}).get("capture", {}).get("expected_size")
        if expected is None: return {"state": "WARN", "required_bytes": None, "free_bytes": shutil.disk_usage(self.archive.root).free}
        required = int(expected) * 2 + 64 * 1024 * 1024; free = shutil.disk_usage(self.archive.root).free
        if free < required: raise PolicyError(f"insufficient storage: require {required} bytes, have {free}")
        return {"state": "PASS", "required_bytes": required, "free_bytes": free}

    def execute(self, run_id):
        run = self.show(run_id)
        if WorkflowState(run["state"]) in TERMINAL or run["state"] == WorkflowState.NEEDS_OPERATOR.value: return run
        if not run.get("preservation_objects"):
            if run["state"] != WorkflowState.READY_TO_CAPTURE.value: raise PolicyError("workflow is not ready to capture")
            try: space = self._space_check(run)
            except PolicyError as exc:
                run["failures"].append(str(exc)); self._save(run); return self.transition(run_id, WorkflowState.FAILED, event_type="storage_check_failed")
            self.transition(run_id, WorkflowState.CAPTURING, event_type="capture_started", detail={"storage": space}); run = self.show(run_id)
            candidate = self._private_candidate(run); previous = None
            try:
                for _ in range(PROFILES[run["profile"]]["capture_repeats"]):
                    result = self.media._capture(candidate, run["plan"], physical_medium_id=run["physical_medium_id"], repeat_of=previous)
                    run = self.show(run_id); run["captures"].append({key: value for key, value in result.items() if key not in {"device", "source", "source_path", "command", "staging_path"}})
                    if result.get("object_id") and result["object_id"] not in run["preservation_objects"]: run["preservation_objects"].append(result["object_id"])
                    previous = result.get("job_id") or previous; self._event(run, "capture_complete", detail={"job_id": result.get("job_id"), "object_id": result.get("object_id")}); self._save(run)
            except Exception as exc:
                run = self.show(run_id); run["failures"].append(str(exc)); self._save(run)
                target = WorkflowState.PARTIAL if run["preservation_objects"] else WorkflowState.FAILED
                return self.transition(run_id, target, event_type="capture_failed", detail={"error": str(exc)})
            self.transition(run_id, WorkflowState.VERIFYING, event_type="verification_started"); run = self.show(run_id)
            if len(run["preservation_objects"]) > 1 and PROFILES[run["profile"]]["require_repeat_match"]:
                run["review_reasons"].append("repeated captures disagree"); self._save(run)
                return self.transition(run_id, WorkflowState.NEEDS_OPERATOR, event_type="repeat_disagreement")
            for object_id in run["preservation_objects"]: self.archive.verify(object_id, record_event=False)
            self.transition(run_id, WorkflowState.PRESERVED, event_type="archive_ingested"); run = self.show(run_id)
        return self._downstream(run)

    def _downstream(self, run):
        profile = PROFILES[run["profile"]]; warnings = []
        if not run["analysis_jobs"]:
            self.transition(run["run_id"], WorkflowState.ANALYZING, event_type="analysis_started"); run = self.show(run["run_id"])
            for object_id in run["preservation_objects"]:
                job = self.analysis.analyze(object_id, policy=profile["analysis_policy"], limits=AnalysisLimits(), recursive=True)
                run["analysis_jobs"].append(job["job_id"])
                if job.get("state") not in {"COMPLETE", "COMPLETED"}: warnings.append("analysis " + job.get("state", "UNKNOWN"))
            self._event(run, "analysis_complete", outcome="WARN" if warnings else "PASS", detail={"jobs": run["analysis_jobs"]}); self._save(run)
        self.transition(run["run_id"], WorkflowState.MALWARE_ANALYSIS, event_type="malware_started"); run = self.show(run["run_id"])
        if profile["malware_profile"] and not run["malware_jobs"]:
            targets = list(run["preservation_objects"])
            for analysis_id in run["analysis_jobs"]:
                targets.extend(x.get("object_id") for x in self.analysis.show(analysis_id).get("discovered", []) if x.get("object_id"))
            for object_id in list(dict.fromkeys(targets))[:256]:
                request = self.malware.submit(object_id, profile=profile["malware_profile"])
                if request.get("provider_job_id"): request = self.malware.poll(request["request_id"])
                run["malware_jobs"].append(request["request_id"])
                if request.get("state") not in {"IMPORTED", "COMPLETE"}: warnings.append("malware analysis " + request.get("state", "PENDING_PROVIDER"))
        self._event(run, "malware_complete", outcome="WARN" if warnings else "PASS"); self._save(run)
        self.transition(run["run_id"], WorkflowState.IDENTIFYING, event_type="identity_started"); run = self.show(run["run_id"])
        if not run["identity"]: run["identity"].append(self.identity.rebuild()); self._event(run, "identity_complete"); self._save(run)
        self.transition(run["run_id"], WorkflowState.BUILDING_PRODUCTS, event_type="products_started"); run = self.show(run["run_id"])
        if not run["products"]:
            for product in profile["products"]:
                try: run["products"].append(self.products.build(product))
                except Exception as exc: warnings.append(product + ": " + str(exc))
        run["warnings"].extend(x for x in warnings if x not in run["warnings"]); self._event(run, "products_complete", outcome="WARN" if warnings else "PASS"); self._save(run)
        target = WorkflowState.COMPLETE_WITH_WARNINGS if run["warnings"] else WorkflowState.COMPLETE
        self.transition(run["run_id"], target, event_type="workflow_complete"); self.report(run["run_id"], rebuild=True); return self.show(run["run_id"])

    def resume(self, run_id):
        run = self.show(run_id)
        if run["state"] in {x.value for x in TERMINAL}: return run
        if run.get("preservation_objects") and run["state"] != WorkflowState.PRESERVED.value:
            run["state"] = WorkflowState.PRESERVED.value; self._event(run, "crash_recovery", detail={"capture_reused": True}); self._save(run)
        return self._downstream(self.show(run_id)) if run.get("preservation_objects") else self.execute(run_id)

    def cancel(self, run_id, *, reason="operator requested cancellation"):
        run = self.show(run_id)
        if WorkflowState(run["state"]) in TERMINAL: return run
        return self.transition(run_id, WorkflowState.CANCELLED, event_type="workflow_cancelled", detail={"reason": reason, "preserved_objects_retained": list(run["preservation_objects"])})

    def review(self, run_id=None):
        if run_id: return {"run": self.public(self.show(run_id)), "events": self.events(run_id)}
        return [self.public(x) for x in self.list() if x.get("state") in {WorkflowState.NEEDS_OPERATOR.value, WorkflowState.PARTIAL.value} or x.get("review_reasons")]

    def report(self, run_id, *, rebuild=False):
        path = self.reports_root / (run_id + ".json")
        if path.is_file() and not rebuild: return json.loads(path.read_text(encoding="utf-8"))
        run = self.show(run_id); analyses = [self.analysis.show(x) for x in run["analysis_jobs"]]
        fixity = []
        for object_id in run["preservation_objects"]:
            item = self.archive.show(object_id); fixity.append({key: item[key] for key in ("sha256", "blake3", "sha1", "md5", "crc32", "size")})
        malware_requests = []
        for request_id in run["malware_jobs"]:
            try:
                request = self.malware.show(request_id); malware_requests.append({"provider": request["provider_id"], "request_id": request_id, "profile": request["requested_profile"], "status": request["state"], "observations": len(request.get("observations", []))})
            except RabError: malware_requests.append({"request_id": request_id, "status": "LEGACY_OR_UNAVAILABLE"})
        report = {"schema": "rab-preservation-report-v1", "run_id": run_id, "state": run["state"], "physical_medium": self.registry.public(self.registry.show(run["physical_medium_id"])) if run.get("physical_medium_id") else None, "profile": run["profile"], "capture_strategy": (run.get("plan") or {}).get("capture", {}).get("method"), "capture_count": len(run["captures"]), "repeatability": "DISAGREEMENT" if len(run["preservation_objects"]) > 1 else "CONFIRMED" if len(run["captures"]) > 1 else "NOT_REPEATED", "preservation_objects": run["preservation_objects"], "fixity": fixity, "analysis_states": [x.get("state") for x in analyses], "contained_objects": sum(len(x.get("discovered", [])) for x in analyses), "cas_objects_materialized": sum(len(x.get("materialized", [])) for x in analyses), "malware_jobs": len(run["malware_jobs"]), "malware_analysis": malware_requests, "products": [x.get("product") for x in run["products"]], "provenance": (self.registry.public(self.registry.show(run["physical_medium_id"])) if run.get("physical_medium_id") else {}).get("provenance"), "rights": (self.registry.public(self.registry.show(run["physical_medium_id"])) if run.get("physical_medium_id") else {}).get("rights"), "warnings": list(run["warnings"]), "failures": list(run["failures"]), "needs_operator": bool(run["review_reasons"]), "review_reasons": list(run["review_reasons"]), "safe_to_remove": run["state"] in {x.value for x in TERMINAL}}
        self.archive._atomic_json(path, report); return report

    @staticmethod
    def public(run):
        hidden = {"operator", "metadata", "candidate_private", "failures", "operator_decisions"}
        private_keys = {"device", "device_path", "path", "source_path", "staging", "staging_path", "command", "serial", "operator_notes", "purchase_notes"}
        def clean(value):
            if isinstance(value, dict): return {key: clean(item) for key, item in value.items() if key not in private_keys}
            if isinstance(value, list): return [clean(x) for x in value]
            return value
        value = clean({key: data for key, data in run.items() if key not in hidden}); value["failure_count"] = len(run.get("failures", [])); return value

    def public_report(self, report):
        return {key: value for key, value in report.items() if key not in {"failures"}}

    def doctor(self, *, media_class=None):
        checks = []
        try: self.archive.initialize(); checks.append({"check": "preservation_store", "state": "PASS" if self.archive.objects.is_dir() else "FAIL"})
        except Exception as exc: checks.append({"check": "preservation_store", "state": "FAIL", "detail": str(exc)})
        try: self.identity.rebuild(); checks.append({"check": "catalogue_identity", "state": "PASS"})
        except Exception as exc: checks.append({"check": "catalogue_identity", "state": "FAIL", "detail": str(exc)})
        candidates = self.devices(); checks.append({"check": "media_adapters", "state": "PASS" if candidates else "WARN", "candidate_count": len(candidates)})
        for kind in ("optical", "block", "flux"):
            state = "PASS" if any(x.get("kind") == kind and x.get("available") for x in candidates) else "NOT_APPLICABLE" if media_class and kind not in media_class else "WARN"
            checks.append({"check": kind, "state": state})
        capabilities = self.analysis.capabilities(); checks.append({"check": "analysis", "state": "PASS" if any(x.get("available") for x in capabilities) else "WARN", "available": sum(bool(x.get("available")) for x in capabilities)})
        malware = self.malware.doctor(); checks.append({"check": "malware_provider", "state": malware["outcome"], "providers": malware["providers"]})
        overall = "FAIL" if any(x["state"] == "FAIL" for x in checks) else "WARN" if any(x["state"] == "WARN" for x in checks) else "PASS"
        return {"schema": "rab-preservation-doctor-v1", "overall": overall, "checks": checks}

    def progress(self):
        runs = self.list(); registry = self.registry.list(); by_media = {x.get("physical_medium_id"): x for x in runs if x.get("physical_medium_id")}
        return {"registered": len(registry), "preserved": sum(bool(x.get("preservation_objects")) for x in by_media.values()), "complete": sum(x.get("state") == "COMPLETE" for x in by_media.values()), "complete_with_warnings": sum(x.get("state") == "COMPLETE_WITH_WARNINGS" for x in by_media.values()), "needs_review": len(self.review()), "not_yet_captured": sum(x["physical_medium_id"] not in by_media or not by_media[x["physical_medium_id"]].get("preservation_objects") for x in registry), "sets": [{"physical_set_id": x["physical_set_id"], **x["completeness"]} for x in self.registry.sets()]}

    def eject(self, candidate_id):
        candidate = self.media.candidate(candidate_id)
        return {"candidate_id": candidate_id, "state": "SAFE_TO_REMOVE", "action": "OPERATOR_EJECT_REQUIRED", "reason": "RAB did not mount the source and does not unmount or eject devices implicitly"}
