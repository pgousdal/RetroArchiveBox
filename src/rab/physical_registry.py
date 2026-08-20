"""Durable physical-object identity, intake, sets, observations and evidence."""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from .errors import IntegrityError, PolicyError, RabError
from .identity import IdentityCatalogue, RelationshipType
from .local_ingest import ProvenanceClass
from .model import IngestRequest, Rights


def _now(): return datetime.now(UTC).isoformat()


class PhysicalMediaClass(StrEnum):
    OPTICAL_DISC = "optical_disc"
    FLOPPY_DISK = "floppy_disk"
    REMOVABLE_FLASH = "removable_flash"
    HARD_DISK = "hard_disk"
    MAGNETIC_TAPE = "magnetic_tape"
    CARTRIDGE = "cartridge"
    MEMORY_CARD = "memory_card"
    OTHER = "other"
    UNKNOWN = "unknown"


class ConditionType(StrEnum):
    SEALED = "sealed"
    CLEAN = "clean"
    SCRATCHED = "scratched"
    DIRTY = "dirty"
    LABEL_DAMAGE = "label_damage"
    CRACKED = "cracked"
    WARPED = "warped"
    MOULD = "mould"
    OXIDATION = "oxidation"
    WRITE_PROTECTED = "write_protected"
    WRITE_PROTECT_UNKNOWN = "write_protect_unknown"
    READ_ERROR_OBSERVED = "read_error_observed"
    VISUALLY_MODIFIED = "visually_modified"
    HANDWRITTEN = "handwritten"
    OTHER = "other"


PRIVATE_METADATA = {"operator_notes", "purchase_notes", "receipt", "printed_serial_number", "serial_number", "barcode", "acquisition_source_description"}
PRIVATE_CAPTURE_KEYS = {"device", "device_path", "source_path", "original_path", "staging", "staging_path", "operator_notes", "command", "executable", "serial", "device_info", "raw_info", "tool_output"}
PUBLIC_METADATA = {"platform", "platform_family", "title", "label", "media_number", "set_title", "set_position", "total_media_count", "publisher", "vendor", "product_number", "catalog_number", "handwritten_label", "volume_label", "medium_subtype", "nominal_capacity", "physical_format", "write_protect_state", "approximate_acquisition_date"}


class PhysicalMediaRegistry:
    VERSION = 1

    def __init__(self, archive):
        self.archive = archive
        self.root = archive.root / "physical-media"
        self.records_root = self.root / "records"
        self.revisions_root = self.root / "revisions"
        self.observations_root = self.root / "observations"
        self.sets_root = self.root / "sets"
        self.sessions_root = self.root / "intake-sessions"

    @staticmethod
    def _id(value):
        if not isinstance(value, str) or not re.fullmatch(r"rab-media-[0-9a-f]{32}", value): raise PolicyError("invalid physical-medium id")
        return value

    @staticmethod
    def _set_id(value):
        if not isinstance(value, str) or not re.fullmatch(r"rab-media-set-[0-9a-f]{32}", value): raise PolicyError("invalid physical-set id")
        return value

    def _immutable(self, path, value):
        encoded = json.dumps(value, indent=2, sort_keys=True) + "\n"
        if path.exists() and path.read_text(encoding="utf-8") != encoded: raise IntegrityError("physical evidence identity conflict")
        if not path.exists(): self.archive._atomic_json(path, value); path.chmod(0o444)

    def _current_session(self):
        path = self.sessions_root / "active.json"
        if not path.is_file(): return None
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if value.get("state") == "ACTIVE" else None

    def intake_begin(self, *, provenance=ProvenanceClass.UNKNOWN, rights=Rights.UNKNOWN, platform=None, vendor=None, operator=None):
        if self._current_session(): raise PolicyError("a physical intake session is already active")
        value = {"schema": "rab-physical-intake-session-v1", "session_id": "rab-intake-" + uuid.uuid4().hex, "state": "ACTIVE", "started_at": _now(), "defaults": {"provenance": ProvenanceClass(provenance).value, "rights": Rights(rights).value, "platform": platform, "vendor": vendor}, "operator": operator}
        self.sessions_root.mkdir(parents=True, exist_ok=True); self.archive._atomic_json(self.sessions_root / "active.json", value)
        self._immutable(self.sessions_root / (value["session_id"] + ".json"), value); return value

    def intake_status(self): return self._current_session() or {"state": "INACTIVE"}

    def intake_end(self):
        value = self._current_session()
        if not value: raise RabError("no active physical intake session")
        value = {**value, "state": "COMPLETED", "ended_at": _now()}; self.archive._atomic_json(self.sessions_root / "active.json", value)
        self._immutable(self.sessions_root / (value["session_id"] + "-completed.json"), value); return value

    def register_set(self, title, *, edition=None, expected_count=None, notes=""):
        if expected_count is not None and expected_count < 1: raise PolicyError("set expected count must be positive")
        set_id = "rab-media-set-" + uuid.uuid4().hex
        value = {"schema": "rab-physical-set-v1", "physical_set_id": set_id, "title": title, "edition": edition, "expected_count": expected_count, "operator_notes": notes, "created_at": _now()}
        self._immutable(self.sets_root / (set_id + ".json"), value); return value

    def show_set(self, set_id):
        self._set_id(set_id); path = self.sets_root / (set_id + ".json")
        if not path.is_file(): raise RabError("physical set not found")
        value = json.loads(path.read_text(encoding="utf-8")); value["members"] = [x for x in self.list() if x.get("set", {}).get("set_id") == set_id]
        value["completeness"] = self._set_completeness(value); return value

    def sets(self): return [self.show_set(x.stem) for x in sorted(self.sets_root.glob("rab-media-set-*.json"))] if self.sets_root.is_dir() else []

    @staticmethod
    def _set_completeness(value):
        expected = value.get("expected_count"); positions = {str(x.get("set", {}).get("position")) for x in value.get("members", []) if x.get("set", {}).get("position") is not None}
        return {"expected_count": expected, "member_count": len(value.get("members", [])), "known_positions": sorted(positions), "complete": bool(expected is not None and len(positions) >= expected)}

    def register(self, media_class: str, *, provenance=None, rights=None, metadata=None, set_id=None, set_position=None, total_media_count=None):
        session = self._current_session(); defaults = (session or {}).get("defaults", {}); metadata = dict(metadata or {})
        if defaults.get("platform") is not None: metadata.setdefault("platform", defaults["platform"])
        if defaults.get("vendor") is not None: metadata.setdefault("vendor", defaults["vendor"])
        media_class = PhysicalMediaClass(media_class).value
        provenance = ProvenanceClass(provenance if provenance is not None else defaults.get("provenance", ProvenanceClass.UNKNOWN)).value
        rights = Rights(rights if rights is not None else defaults.get("rights", Rights.UNKNOWN)).value
        if set_id is not None: self.show_set(set_id)
        if total_media_count is not None and total_media_count < 1: raise PolicyError("total media count must be positive")
        media_id = "rab-media-" + uuid.uuid4().hex; timestamp = _now()
        value = {"schema": "rab-physical-medium-v1", "version": self.VERSION, "physical_medium_id": media_id, "media_class": media_class, "created_at": timestamp, "updated_at": timestamp, "provenance": provenance, "rights": rights, "metadata": metadata, "set": {"set_id": set_id, "position": set_position, "total_media_count": total_media_count}, "intake_session_id": (session or {}).get("session_id"), "revision_ids": [], "observation_ids": [], "evidence_objects": []}
        self.records_root.mkdir(parents=True, exist_ok=True); self.archive._atomic_json(self.records_root / (media_id + ".json"), value); return value

    def show(self, media_id):
        self._id(media_id); path = self.records_root / (media_id + ".json")
        if not path.is_file(): raise RabError("physical medium not found")
        return json.loads(path.read_text(encoding="utf-8"))

    def list(self): return [json.loads(x.read_text(encoding="utf-8")) for x in sorted(self.records_root.glob("rab-media-*.json"))] if self.records_root.is_dir() else []

    def update(self, media_id, *, metadata=None, provenance=None, rights=None, set_id=None, set_position=None, total_media_count=None):
        value = self.show(media_id)
        if set_id is not None: self.show_set(set_id)
        revision_id = uuid.uuid4().hex; timestamp = _now()
        changes = {"metadata": metadata or {}, "provenance": ProvenanceClass(provenance).value if provenance is not None else None, "rights": Rights(rights).value if rights is not None else None, "set_id": set_id, "set_position": set_position, "total_media_count": total_media_count}
        revision = {"schema": "rab-physical-medium-revision-v1", "revision_id": revision_id, "physical_medium_id": media_id, "recorded_at": timestamp, "previous_revision_id": value["revision_ids"][-1] if value["revision_ids"] else None, "before_sha256": hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest(), "changes": changes}
        self._immutable(self.revisions_root / (revision_id + ".json"), revision)
        value["metadata"] = {**value.get("metadata", {}), **(metadata or {})}
        if provenance is not None: value["provenance"] = ProvenanceClass(provenance).value
        if rights is not None: value["rights"] = Rights(rights).value
        if set_id is not None: value["set"]["set_id"] = set_id
        if set_position is not None: value["set"]["position"] = set_position
        if total_media_count is not None: value["set"]["total_media_count"] = total_media_count
        value.update({"updated_at": timestamp, "revision_ids": value["revision_ids"] + [revision_id]})
        self.archive._atomic_json(self.records_root / (media_id + ".json"), value); return value

    def revisions(self, media_id):
        value = self.show(media_id); return [json.loads((self.revisions_root / (x + ".json")).read_text(encoding="utf-8")) for x in value.get("revision_ids", [])]

    def observe(self, media_id, observation_type: str, *, note="", observer=None):
        value = self.show(media_id); observation_type = ConditionType(observation_type).value; observation_id = uuid.uuid4().hex
        item = {"schema": "rab-physical-observation-v1", "observation_id": observation_id, "physical_medium_id": media_id, "recorded_at": _now(), "observer": observer, "observation_type": observation_type, "note": note}
        self._immutable(self.observations_root / (observation_id + ".json"), item); value["observation_ids"].append(observation_id); value["updated_at"] = _now(); self.archive._atomic_json(self.records_root / (media_id + ".json"), value); return item

    def observations(self, media_id):
        value = self.show(media_id); return [json.loads((self.observations_root / (x + ".json")).read_text(encoding="utf-8")) for x in value.get("observation_ids", []) if (self.observations_root / (x + ".json")).is_file()]

    def add_evidence(self, media_id, path: Path, *, rights=Rights.UNKNOWN, note="", evidence_type="other", public=False):
        value = self.show(media_id); source = path.resolve()
        if not source.is_file() or source.is_symlink(): raise PolicyError("evidence requires a regular file")
        result = self.archive.ingest(IngestRequest(source, "physical-evidence", "physical/" + media_id + "/" + source.name, Rights(rights), "application/octet-stream", source.name, None, "physical_evidence", {"physical_medium_id": media_id, "evidence_type": evidence_type}))
        item = {"object_id": result["object_id"], "evidence_type": evidence_type, "note": note, "public": bool(public), "recorded_at": _now()}
        value["evidence_objects"].append(item); value["updated_at"] = _now(); self.archive._atomic_json(self.records_root / (media_id + ".json"), value)
        IdentityCatalogue(self.archive).add_relationship(media_id, RelationshipType.EVIDENCE_FOR, result["object_id"], {"evidence_type": evidence_type, "recorded_at": item["recorded_at"]}); return item

    def link_capture(self, media_id, job):
        self.show(media_id)
        if job.get("object_id"): IdentityCatalogue(self.archive).add_relationship(media_id, RelationshipType.CAPTURED_AS, job["object_id"], {"capture_job_id": job["job_id"], "capture_schema": job["schema"], "recorded_at": job.get("completed_at") or job.get("updated_at")})

    def captures(self, media_id):
        self.show(media_id); results = []
        for root in (self.archive.root / "media" / "jobs", self.archive.root / "media" / "optical" / "jobs", self.archive.root / "media" / "flux" / "jobs"):
            for path in sorted(root.glob("*.json")) if root.is_dir() else []:
                try:
                    job = json.loads(path.read_text(encoding="utf-8"))
                    if job.get("physical_medium_id") == media_id: results.append(job)
                except (OSError, ValueError): pass
        return sorted(results, key=lambda x: (x.get("created_at", ""), x.get("job_id", "")))

    @staticmethod
    def public_capture(job):
        def clean(value):
            if isinstance(value, dict): return {key: clean(item) for key, item in value.items() if key not in PRIVATE_CAPTURE_KEYS}
            if isinstance(value, list): return [clean(x) for x in value]
            return value
        return clean(job)

    @staticmethod
    def public(value):
        result = {key: item for key, item in value.items() if key not in {"metadata", "evidence_objects", "revision_ids", "observation_ids"}}
        result["metadata"] = {key: item for key, item in value.get("metadata", {}).items() if key in PUBLIC_METADATA and key not in PRIVATE_METADATA}
        result["evidence_count"] = len(value.get("evidence_objects", [])); result["revision_count"] = len(value.get("revision_ids", [])); result["observation_count"] = len(value.get("observation_ids", [])); return result

    def public_evidence(self, media_id): return [{"object_id": x["object_id"], "evidence_type": x.get("evidence_type", "other"), "recorded_at": x.get("recorded_at")} for x in self.show(media_id).get("evidence_objects", []) if x.get("public")]
