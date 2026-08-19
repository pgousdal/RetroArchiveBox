"""Consumer Resource Broker v1.

This module is deliberately a derived, policy-aware view over the immutable
catalogue.  Resource definitions and set generations are JSON sidecars so the
broker index can be deleted and rebuilt without touching preservation data.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Iterable

from .errors import IntegrityError, PolicyError, RabError
from .hashing import hash_file
from .model import Rights


class ResourceKind(StrEnum):
    SOFTWARE_PACKAGE = "software-package"
    DISK_IMAGE = "disk-image"
    OPTICAL_DISC = "optical-disc"
    ROM = "rom"
    FIRMWARE = "firmware"
    OPERATING_SYSTEM_MEDIA = "operating-system-media"
    BBS_SOFTWARE = "bbs-software"
    DRIVER = "driver"
    TOOL = "tool"
    DOCUMENTATION = "documentation"
    RESOURCE_SET = "resource-set"


class ResolutionState(StrEnum):
    RESOLVED = "RESOLVED"
    NOT_FOUND = "NOT_FOUND"
    AMBIGUOUS = "AMBIGUOUS"
    RIGHTS_DENIED = "RIGHTS_DENIED"
    UNAVAILABLE = "UNAVAILABLE"
    INCOMPLETE = "INCOMPLETE"
    POLICY_BLOCKED = "POLICY_BLOCKED"


class Availability(StrEnum):
    AVAILABLE_LOCAL = "AVAILABLE_LOCAL"
    AVAILABLE_REMOTE = "AVAILABLE_REMOTE"
    PARTIALLY_AVAILABLE = "PARTIALLY_AVAILABLE"
    MISSING = "MISSING"
    REQUIRES_ACQUISITION = "REQUIRES_ACQUISITION"


class DeliveryMode(StrEnum):
    STREAM = "STREAM"
    COPY = "COPY"
    MATERIALIZE = "MATERIALIZE"
    MANIFEST_ONLY = "MANIFEST_ONLY"


class Representation(StrEnum):
    ORIGINAL = "ORIGINAL"
    DERIVATIVE_OK = "DERIVATIVE_OK"
    SPECIFIC_DERIVATIVE = "SPECIFIC_DERIVATIVE"


class MalwareStatus(StrEnum):
    NOT_SCANNED = "NOT_SCANNED"
    NOT_DETECTED = "NOT_DETECTED"
    DETECTED = "DETECTED"
    SUSPICIOUS = "SUSPICIOUS"
    ERROR = "ERROR"
    UNSUPPORTED = "UNSUPPORTED"


ResourceType = ResourceKind
ResolutionStatus = ResolutionState


class BrokerError(RabError):
    def __init__(self, state: ResolutionState, message: str):
        super().__init__(message)
        self.state = state


@dataclass(frozen=True)
class ConsumerContext:
    consumer_id: str = "test-consumer"
    consumer_type: str = "reference"
    local: bool = True
    purpose: str = "local-runtime"
    delivery_mode: DeliveryMode = DeliveryMode.MANIFEST_ONLY
    rights_context: str = "local-owner"
    machine_profile_id: str | None = None

    def as_dict(self) -> dict:
        return {"consumer_id": self.consumer_id, "consumer_type": self.consumer_type,
                "local": self.local, "purpose": self.purpose,
                "delivery_mode": self.delivery_mode.value,
                "rights_context": self.rights_context,
                "machine_profile_id": self.machine_profile_id}


@dataclass(frozen=True)
class ResourceDefinition:
    resource_id: str
    kind: ResourceKind
    name: str
    version: str | None = None
    platform: str | None = None
    ecosystem: str | None = None
    os: str | None = None
    architecture: str | None = None
    hardware: str | None = None
    objects: tuple[dict, ...] = ()
    package_id: str | None = None
    dependencies: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    availability: Availability = Availability.AVAILABLE_LOCAL
    rights: Rights = Rights.UNKNOWN
    authority_requirements: dict = field(default_factory=dict)
    malware_status: MalwareStatus = MalwareStatus.NOT_SCANNED
    metadata: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"schema": "rab-resource-definition-v1", "resource_id": self.resource_id,
                "kind": self.kind.value, "name": self.name, "version": self.version,
                "platform": self.platform, "ecosystem": self.ecosystem, "os": self.os,
                "architecture": self.architecture, "hardware": self.hardware,
                "objects": list(self.objects), "package_id": self.package_id,
                "dependencies": list(self.dependencies), "tags": list(self.tags),
                "availability": self.availability.value, "rights": self.rights.value,
                "authority_requirements": self.authority_requirements,
                "malware_status": self.malware_status.value, "metadata": self.metadata}


# Public vocabulary alias used by consumers that refer to the model simply as
# Resource rather than ResourceDefinition.
Resource = ResourceDefinition


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _safe_id(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512 or "\x00" in value:
        raise RabError("invalid resource id")
    if value.startswith("sha256:"):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            raise RabError("invalid resource id")
    elif any(x in value for x in ("/../", "\\", "\n", "\r")):
        raise RabError("invalid resource id")
    return value


class ConsumerRegistry:
    def __init__(self, path: Path | None = None):
        self.path = path

    def list(self) -> list[dict]:
        values = {"test-consumer": {"consumer_id": "test-consumer", "display_name": "Reference consumer",
                                    "enabled": True, "allowed_delivery_modes": [x.value for x in DeliveryMode],
                                    "local": True, "rights_policy": "local-owner"}}
        if self.path and self.path.is_file():
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            for item in raw if isinstance(raw, list) else raw.get("consumers", []):
                if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", item.get("consumer_id", "")):
                    raise RabError("invalid consumer id")
                values[item["consumer_id"]] = item
        return [values[x] for x in sorted(values)]

    def get(self, consumer_id: str) -> dict:
        for item in self.list():
            if item["consumer_id"] == consumer_id:
                if not item.get("enabled", False):
                    raise PolicyError("consumer is disabled")
                return item
        raise BrokerError(ResolutionState.POLICY_BLOCKED, "unknown consumer")


class ResourceBroker:
    VERSION = 1

    def __init__(self, archive, *, registry: ConsumerRegistry | None = None, read_only: bool = False):
        self.archive = archive
        self.registry = registry or ConsumerRegistry()
        self.read_only = read_only
        self.root = archive.root / "resource-metadata"
        self.resources = self.root / "resources"
        self.sets = self.root / "sets"
        self.state = archive.root / "consumer-state"

    def initialize(self) -> None:
        if self.read_only:
            if not self.archive.db_path.is_file():
                raise RabError("broker state is unavailable; run 'rab resource search' or rebuild")
            with self.archive.db() as db:
                required = {"broker_resources", "broker_sets"}
                present = {x[0] for x in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if not required <= present:
                    raise RabError("broker state is unavailable; rebuild broker state")
            return
        self.archive.initialize()
        self.resources.mkdir(parents=True, exist_ok=True); self.sets.mkdir(parents=True, exist_ok=True)
        with self.archive.db() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS broker_resources (resource_id TEXT PRIMARY KEY, definition TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS broker_sets (set_id TEXT NOT NULL, generation INTEGER NOT NULL, definition TEXT NOT NULL, recorded_at TEXT NOT NULL, PRIMARY KEY(set_id,generation));
            CREATE TABLE IF NOT EXISTS broker_events (event_id TEXT PRIMARY KEY, event_type TEXT NOT NULL, occurred_at TEXT NOT NULL, resource_id TEXT, consumer_id TEXT, detail TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS broker_resources_kind ON broker_resources(resource_id);
            """)
        self.rebuild()

    def rebuild(self) -> dict:
        self.archive.initialize(); self.resources.mkdir(parents=True, exist_ok=True); self.sets.mkdir(parents=True, exist_ok=True)
        with self.archive.db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS broker_resources (resource_id TEXT PRIMARY KEY, definition TEXT NOT NULL, updated_at TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS broker_sets (set_id TEXT NOT NULL, generation INTEGER NOT NULL, definition TEXT NOT NULL, recorded_at TEXT NOT NULL, PRIMARY KEY(set_id,generation))")
            db.execute("DELETE FROM broker_resources"); db.execute("DELETE FROM broker_sets")
            for path in sorted(self.resources.glob("*.json")):
                value = json.loads(path.read_text(encoding="utf-8")); _safe_id(value["resource_id"])
                db.execute("INSERT INTO broker_resources VALUES (?,?,?)", (value["resource_id"], json.dumps(value, sort_keys=True), value.get("created_at", "")))
            for path in sorted(self.sets.glob("*.json")):
                value = json.loads(path.read_text(encoding="utf-8")); _safe_id(value["set_id"])
                db.execute("INSERT INTO broker_sets VALUES (?,?,?,?)", (value["set_id"], int(value["generation"]), json.dumps(value, sort_keys=True), value["recorded_at"]))
        return self.stats()

    def register(self, resource: ResourceDefinition) -> dict:
        _safe_id(resource.resource_id)
        self._check_cycles(resource)
        if resource.resource_id.startswith("sha256:") and not resource.objects:
            objects = ({"role": "payload", "sha256": resource.resource_id},)
            resource = ResourceDefinition(**{**resource.__dict__, "objects": objects})
        value = resource.as_dict(); value["created_at"] = _now()
        target = self.resources / (re.sub(r"[^A-Za-z0-9_.-]", "_", resource.resource_id) + ".json")
        if target.exists():
            existing = json.loads(target.read_text(encoding="utf-8"))
            if {k: v for k, v in existing.items() if k != "created_at"} != {k: v for k, v in value.items() if k != "created_at"}:
                raise PolicyError("resource definition is immutable")
            self.rebuild(); return existing
        self.archive._atomic_json(target, value); target.chmod(0o444); self.rebuild(); return value

    def _check_cycles(self, candidate: ResourceDefinition) -> None:
        graph = {x["resource_id"]: set(x.get("dependencies", [])) for x in self._definitions()} if self.archive.db_path.is_file() else {}
        graph[candidate.resource_id] = set(candidate.dependencies)
        def visit(node, active, done):
            if node in active: raise PolicyError("resource dependency cycle")
            if node in done: return
            active.add(node)
            for child in graph.get(node, ()): visit(child, active, done)
            active.remove(node); done.add(node)
        visit(candidate.resource_id, set(), set())

    def register_package(self, package_id: str, *, kind: ResourceKind = ResourceKind.SOFTWARE_PACKAGE,
                         name: str | None = None, version: str | None = None, **metadata) -> dict:
        self.initialize()
        with self.archive.db() as db:
            row = db.execute("SELECT * FROM packages WHERE package_id=?", (package_id,)).fetchone()
        if row is None: raise BrokerError(ResolutionState.NOT_FOUND, "package not found")
        generations = self.archive.db()
        with generations as db:
            latest = db.execute("SELECT * FROM package_generations WHERE package_id=? ORDER BY generation DESC LIMIT 1", (package_id,)).fetchone()
        stem = Path(package_id.split(":", 1)[1]).name
        objects = tuple(x for x in ({"role": "payload", "filename": stem + ".lha", "sha256": latest["payload_sha256"]} if latest["payload_sha256"] else None,
                                    {"role": "readme", "filename": stem + ".readme", "sha256": latest["readme_sha256"]} if latest["readme_sha256"] else None) if x)
        info = json.loads(latest["metadata"]); info.update(metadata)
        info["generation"] = int(latest["generation"])
        return self.register(ResourceDefinition(package_id, kind, name or info.get("name") or info.get("package_name") or info.get("short") or package_id.rsplit("/", 1)[-1],
            version or info.get("version"), platform=(info.get("platforms") or [None])[0], ecosystem=(info.get("platforms") or [None])[0],
            objects=objects, package_id=package_id, availability=Availability.AVAILABLE_LOCAL if row["upstream_present"] else Availability.REQUIRES_ACQUISITION,
            rights=self._package_rights(objects), metadata=info))

    def _package_rights(self, objects: Iterable[dict]) -> Rights:
        values = []
        with self.archive.db() as db:
            for item in objects:
                row = db.execute("SELECT rights FROM occurrences WHERE sha256=? ORDER BY acquired_at DESC LIMIT 1", (item["sha256"],)).fetchone()
                if row: values.append(Rights(row[0]))
        return next((x for x in (Rights.RESTRICTED, Rights.PRIVATE_LICENSED, Rights.UNKNOWN, Rights.REDISTRIBUTABLE) if x in values), Rights.UNKNOWN)

    def define_set(self, set_id: str, contents: list[dict], *, metadata: dict | None = None) -> dict:
        _safe_id(set_id)
        self.initialize()
        with self.archive.db() as db:
            row = db.execute("SELECT max(generation) FROM broker_sets WHERE set_id=?", (set_id,)).fetchone()
        generation = int(row[0] or 0) + 1
        value = {"schema": "rab-resource-set-v1", "set_id": set_id, "generation": generation,
                 "resource_id": f"resource-set:{set_id}:{generation}", "contents": contents,
                 "metadata": metadata or {}, "recorded_at": _now()}
        target = self.sets / (re.sub(r"[^A-Za-z0-9_.-]", "_", set_id) + f"-generation-{generation:06d}.json")
        self.archive._atomic_json(target, value); target.chmod(0o444); self.rebuild(); return value

    def _definitions(self) -> list[dict]:
        self.initialize()
        with self.archive.db() as db:
            return [json.loads(x[0]) for x in db.execute("SELECT definition FROM broker_resources ORDER BY resource_id")]

    def show(self, resource_id: str) -> dict:
        _safe_id(resource_id); self.initialize()
        if resource_id.startswith("resource-set:"):
            bits = resource_id.removeprefix("resource-set:").rsplit(":", 1)
            return self.show_set(bits[0], int(bits[1]))
        with self.archive.db() as db:
            row = db.execute("SELECT definition FROM broker_resources WHERE resource_id=?", (resource_id,)).fetchone()
        if row is None and resource_id.startswith("sha256:"):
            if self.read_only:
                sha = resource_id.removeprefix("sha256:")
                obj = self.archive.show(resource_id)
                value = ResourceDefinition(resource_id, ResourceKind.DISK_IMAGE, obj.get("title") or resource_id,
                    objects=({"role": "payload", "sha256": resource_id},), rights=self._rights_for_sha(sha)).as_dict()
                return self._descriptor(value)
            return self.register(ResourceDefinition(resource_id, ResourceKind.DISK_IMAGE, resource_id,
                objects=({"role":"payload","sha256":resource_id},), rights=self._rights_for_sha(resource_id.removeprefix("sha256:"))))
        if row is None: raise BrokerError(ResolutionState.NOT_FOUND, "resource not found")
        value = json.loads(row[0]); return self._descriptor(value)

    def _descriptor(self, value: dict) -> dict:
        objects = []
        for item in value.get("objects", []):
            sha = item.get("sha256", "").removeprefix("sha256:")
            try:
                obj = self.archive.show("sha256:" + sha); available = (self.archive.object_dir(sha) / "master").is_file()
                objects.append({**item, "sha256": "sha256:" + sha, "size": obj["size"], "hashes": {k: obj[k] for k in ("sha256", "blake3", "sha1", "md5", "crc32")}, "available": available,
                                "preservation_state": obj["preservation_state"], "provenance": [{"source": x["source"], "source_path": x["source_path"]} for x in obj.get("occurrences", [])]})
            except RabError:
                objects.append({**item, "sha256": "sha256:" + sha, "available": False})
        value = {**value, "objects": objects, "malware_analysis": {"status": value.get("malware_status", MalwareStatus.NOT_SCANNED.value)},
                 "availability": self._availability(value, objects).value, "delivery_policy": self._delivery_policy(value)}
        value["preservation_objects"] = [x["sha256"] for x in objects]
        value["authority_assertions"] = self._authority(objects)
        return value

    def _rights_for_sha(self, sha: str) -> Rights:
        try:
            values = [Rights(x["rights"]) for x in self.archive.show("sha256:" + sha).get("occurrences", [])]
        except RabError:
            return Rights.UNKNOWN
        return next((x for x in (Rights.RESTRICTED, Rights.PRIVATE_LICENSED, Rights.UNKNOWN, Rights.REDISTRIBUTABLE) if x in values), Rights.UNKNOWN)

    def _availability(self, value, objects) -> Availability:
        if not objects: return Availability.MISSING
        present = sum(bool(x.get("available")) for x in objects)
        if present == len(objects): return Availability.AVAILABLE_LOCAL
        if present: return Availability.PARTIALLY_AVAILABLE
        return value.get("availability", Availability.MISSING) if value.get("availability") != Availability.AVAILABLE_LOCAL.value else Availability.MISSING

    def _authority(self, objects) -> list[dict]:
        try:
            from .authority import Authority
            return [x for item in objects for x in Authority(self.archive).assertions(item["sha256"], read_only=self.read_only) if x.get("result") == "EXACT_MATCH"]
        except RabError: return []

    @staticmethod
    def _delivery_policy(value):
        rights = value.get("rights", Rights.UNKNOWN.value)
        return {"rights": rights, "local_owner": rights in {Rights.REDISTRIBUTABLE.value, Rights.PRIVATE_LICENSED.value},
                "public": rights == Rights.REDISTRIBUTABLE.value, "malware_status": value.get("malware_status", MalwareStatus.NOT_SCANNED.value)}

    def search(self, **query) -> dict:
        fields = {"platform", "ecosystem", "os", "architecture", "hardware", "kind", "name", "version", "title", "source"}
        if any(k not in fields and v is not None for k, v in query.items()): raise BrokerError(ResolutionState.POLICY_BLOCKED, "invalid query field")
        if len(json.dumps(query)) > 4096: raise BrokerError(ResolutionState.POLICY_BLOCKED, "query too large")
        if query.get("version") is not None and (not isinstance(query["version"], str) or len(query["version"]) > 128 or not re.fullmatch(r"[A-Za-z0-9._+()\-/ ]+", query["version"])):
            raise BrokerError(ResolutionState.POLICY_BLOCKED, "invalid version")
        definitions = self._definitions()
        # Existing logical package generations are safe broker inputs.  Index
        # them lazily so a consumer can resolve a catalogue package without a
        # source-specific registration step.
        known = {x["resource_id"] for x in definitions}
        if self.archive.db_path.is_file():
            with self.archive.db() as db:
                package_ids = [x[0] for x in db.execute("SELECT package_id FROM packages ORDER BY package_id")]
            for package_id in package_ids:
                if package_id not in known:
                    self.register_package(package_id); known.add(package_id)
            definitions = self._definitions()
        matches = []
        for value in definitions:
            hay = value.get("name", "") + " " + value.get("resource_id", "") + " " + json.dumps(value.get("metadata", {}))
            good = True
            for key, wanted in query.items():
                if wanted is None: continue
                actual = value.get(key) or (value.get("metadata", {}).get(key) if key != "kind" else None)
                if key == "title": actual = value.get("name")
                if key == "source": actual = value.get("package_id", "").split(":", 1)[0]
                if key == "kind":
                    try: wanted = ResourceKind(wanted).value if not isinstance(wanted, ResourceKind) else wanted.value
                    except ValueError as exc: raise BrokerError(ResolutionState.POLICY_BLOCKED, "invalid resource kind") from exc
                if actual is None or str(actual).lower() != str(wanted).lower(): good = False; break
            if good: matches.append(self._descriptor(value))
        return {"state": ResolutionState.RESOLVED.value if len(matches) == 1 else ResolutionState.NOT_FOUND.value if not matches else ResolutionState.AMBIGUOUS.value, "results": matches}

    def resolve(self, resource_id: str | None = None, *, context: ConsumerContext | None = None,
                representation: Representation = Representation.ORIGINAL, authority: dict | None = None, **query) -> dict:
        context = context or ConsumerContext()
        if resource_id:
            descriptor = self.show(resource_id)
            candidates = [descriptor]
        else:
            result = self.search(**query); candidates = result["results"]
            if len(candidates) != 1:
                raise BrokerError(ResolutionState(result["state"]), "resource resolution is " + result["state"].lower())
            descriptor = candidates[0]
        if descriptor["availability"] in {Availability.MISSING.value, Availability.REQUIRES_ACQUISITION.value}:
            raise BrokerError(ResolutionState.UNAVAILABLE, "resource bytes are unavailable")
        if descriptor["availability"] == Availability.PARTIALLY_AVAILABLE or any(not x.get("available") for x in descriptor["objects"]):
            raise BrokerError(ResolutionState.INCOMPLETE, "resource is incomplete")
        if authority:
            for name, required in authority.items():
                if required == "EXACT_MATCH" and not any((x.get("authority_id") or x.get("authority")) == name.upper() and x.get("result") == required for x in descriptor["authority_assertions"]):
                    raise BrokerError(ResolutionState.POLICY_BLOCKED, "authority requirement not satisfied")
        if representation == Representation.ORIGINAL and any(x.get("preservation_state") == "DERIVATIVE" for x in descriptor["objects"]):
            raise BrokerError(ResolutionState.POLICY_BLOCKED, "original representation required")
        delivery = self._delivery(descriptor, context)
        descriptor["resolution"] = {"state": ResolutionState.RESOLVED.value, "requested": {**query, "resource_id": resource_id},
                                     "evidence": {"resource_id": descriptor["resource_id"], "objects": descriptor["preservation_objects"],
                                                   "authority": descriptor["authority_assertions"]}, "delivery": delivery}
        return descriptor

    def _delivery(self, descriptor, context):
        rights = descriptor.get("rights", Rights.UNKNOWN.value); public = context.rights_context in {"public", "redistribution"}
        if public and rights != Rights.REDISTRIBUTABLE.value: return {"state": "RIGHTS_DENIED", "mode": context.delivery_mode.value}
        if not context.local and rights != Rights.REDISTRIBUTABLE.value: return {"state": "RESOLVED_LOCAL_ONLY", "mode": context.delivery_mode.value}
        return {"state": "RESOLVED_AND_DELIVERABLE", "mode": context.delivery_mode.value}

    def pin(self, resource_id: str, *, context: ConsumerContext | None = None, authority: dict | None = None, dependencies: list[dict] | None = None) -> dict:
        resolved = self.resolve(resource_id, context=context, authority=authority)
        if resolved["resolution"]["delivery"]["state"] == "RIGHTS_DENIED": raise BrokerError(ResolutionState.RIGHTS_DENIED, "delivery rights denied")
        value = {"schema": "rab-resource-manifest-v1", "resource_id": resource_id, "resolved_at": _now(),
                 "consumer_context": (context or ConsumerContext()).as_dict(), "objects": resolved["objects"],
                 "object_ids": resolved["preservation_objects"], "rights": resolved["rights"],
                 "authority": resolved["authority_assertions"], "authority_requirements": authority or {},
                 "dependencies": dependencies or [{"resource_id": x} for x in resolved.get("dependencies", [])],
                 "delivery_mode": (context or ConsumerContext()).delivery_mode.value, "generation": resolved.get("metadata", {}).get("generation")}
        self._event("RESOURCE_PINNED", resource_id, value["consumer_context"]["consumer_id"], value)
        return value

    def materialize(self, resource_id: str, consumer_id: str, destination: Path | None = None, *, context: ConsumerContext | None = None) -> dict:
        self.registry.get(consumer_id); context = context or ConsumerContext(consumer_id=consumer_id, delivery_mode=DeliveryMode.MATERIALIZE)
        resolved = self.resolve(resource_id, context=context)
        if resolved["resolution"]["delivery"]["state"] != "RESOLVED_AND_DELIVERABLE": raise BrokerError(ResolutionState.RIGHTS_DENIED, "delivery rights denied")
        root = (destination or self.state / consumer_id / "workspaces" / re.sub(r"[^A-Za-z0-9_.-]", "_", resource_id)).resolve()
        allowed = (self.state / consumer_id / "workspaces").resolve()
        if destination and not root.is_relative_to(allowed): raise PolicyError("destination escapes consumer workspace")
        root.mkdir(parents=True, exist_ok=True); outputs = []
        for item in resolved["objects"]:
            sha = item["sha256"].removeprefix("sha256:"); source = self.archive.object_dir(sha) / "master"
            if not source.is_file() or source.is_symlink(): raise IntegrityError("preservation master is unavailable")
            name = self._filename(item.get("filename") or item.get("role") or sha)
            target = root / name
            if target.exists() and hash_file(target)["sha256"] == sha: reused = True
            else:
                if target.exists() or target.is_symlink(): raise PolicyError("refusing workspace collision")
                tmp = root / ("." + uuid.uuid4().hex + ".part"); shutil.copyfile(source, tmp); os.replace(tmp, target); reused = False
            if hash_file(target)["sha256"] != sha: raise IntegrityError("materialized resource failed verification")
            outputs.append({"role": item.get("role"), "sha256": "sha256:" + sha, "filename": name, "path": str(target), "reused": reused})
        result = {"resource_id": resource_id, "consumer_id": consumer_id, "workspace_id": str(root.relative_to(self.state)), "created_at": _now(), "status": "PASS", "objects": outputs}
        self._event("RESOURCE_CACHE_REUSED" if outputs and all(x["reused"] for x in outputs) else "RESOURCE_MATERIALIZED", resource_id, consumer_id, result)
        return result

    @staticmethod
    def _filename(value: str) -> str:
        value = os.path.basename(value).replace("\x00", "")
        value = re.sub(r"[^A-Za-z0-9._-]", "_", value)
        return value.strip(".") or "resource.bin"

    def verify_manifest(self, path: Path) -> dict:
        value = json.loads(path.read_text(encoding="utf-8"))
        if value.get("schema") != "rab-resource-manifest-v1": raise RabError("unsupported resource manifest")
        descriptor = self.show(value["resource_id"])
        expected = sorted(value.get("object_ids", [])); actual = sorted(descriptor["preservation_objects"])
        if expected != actual: raise IntegrityError("resource lock no longer matches pinned objects")
        for sha in expected: self.archive.verify(sha, record_event=False)
        return {"outcome": "PASS", "resource_id": value["resource_id"], "objects": expected}

    def show_set(self, set_id: str, generation: int | None = None) -> dict:
        self.initialize()
        with self.archive.db() as db:
            row = db.execute("SELECT definition FROM broker_sets WHERE set_id=? AND generation=?", (set_id, generation)) .fetchone() if generation else db.execute("SELECT definition FROM broker_sets WHERE set_id=? ORDER BY generation DESC LIMIT 1", (set_id,)).fetchone()
        if not row: raise BrokerError(ResolutionState.NOT_FOUND, "resource set not found")
        value = json.loads(row[0]); value["resolved_contents"] = [self.show(x["resource_id"]) for x in value["contents"]]
        return value

    def _event(self, kind, resource_id, consumer_id, detail):
        self.initialize()
        with self.archive.db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS broker_events (event_id TEXT PRIMARY KEY,event_type TEXT NOT NULL,occurred_at TEXT NOT NULL,resource_id TEXT,consumer_id TEXT,detail TEXT NOT NULL)")
            db.execute("INSERT INTO broker_events VALUES (?,?,?,?,?,?)", (str(uuid.uuid4()), kind, _now(), resource_id, consumer_id, json.dumps(detail, sort_keys=True)))

    def stats(self) -> dict:
        if not self.archive.db_path.is_file(): return {"resources": 0, "sets": 0}
        with self.archive.db() as db:
            resources = db.execute("SELECT count(*) FROM sqlite_master WHERE name='broker_resources'").fetchone()[0]
            count = db.execute("SELECT count(*) FROM broker_resources").fetchone()[0] if resources else 0
            sets = db.execute("SELECT count(*) FROM sqlite_master WHERE name='broker_sets'").fetchone()[0]
            scount = db.execute("SELECT count(*) FROM broker_sets").fetchone()[0] if sets else 0
        return {"resources": count, "resource_sets": scount, "consumers": len(self.registry.list())}
