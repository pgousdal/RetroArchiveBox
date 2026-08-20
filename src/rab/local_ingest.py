"""Generic local inbox ingest jobs converging on Archive.ingest."""
from __future__ import annotations

import json
import fnmatch
import os
import shutil
import time
import uuid
from dataclasses import dataclass, field
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
    DOWNLOADED = "downloaded"
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
                    source_description: str | None = None, logical_path: str | None = None) -> dict:
        if not category or any(x in category for x in ("/", "\\", "\x00")): raise PolicyError("unsafe local inbox category")
        source = self._validate_source(path); provenance = ProvenanceClass(provenance); self.initialize()
        job_id = uuid.uuid4().hex; stage = self.root / "staging" / job_id; stage.mkdir(parents=True, exist_ok=False)
        before = source.stat()
        staged = stage / source.name
        shutil.copyfile(source, staged)
        after = source.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            staged.unlink(missing_ok=True)
            raise RabError("source changed while it was being staged")
        staged.chmod(0o440)
        return self.ingest_staged(staged, job_id=job_id, category=category, rights=rights, provenance=provenance,
                                  notes=notes, source_description=source_description, original_path=str(source), logical_path=logical_path)

    def ingest_staged(self, staged: Path, *, job_id: str | None = None, category: str = "unknown",
                      rights: Rights = Rights.UNKNOWN, provenance: ProvenanceClass | str = ProvenanceClass.UNKNOWN,
                      notes: str = "", source_description: str | None = None, original_path: str | None = None, logical_path: str | None = None) -> dict:
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
        logical = logical_path or Path(original_path or staged.name).name
        relative = Path(logical)
        if relative.is_absolute() or ".." in relative.parts or "\\" in logical or "\x00" in logical:
            raise PolicyError("unsafe local ingest logical path")
        source_path = category + "/" + logical
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


@dataclass(frozen=True)
class InboxPolicy:
    """A configured acquisition boundary; rights are deliberately separate."""
    inbox_id: str
    path: Path
    enabled: bool = True
    provenance: ProvenanceClass = ProvenanceClass.UNKNOWN
    rights: Rights = Rights.UNKNOWN
    recursive: bool = False
    stability_seconds: float = 1.0
    min_age_seconds: float = 0.0
    max_file_size: int | None = None
    include_patterns: tuple[str, ...] = ()
    exclude_patterns: tuple[str, ...] = ()
    temporary_suffixes: tuple[str, ...] = (".part", ".partial", ".tmp", ".crdownload")
    post_success: str = "LEAVE"
    post_failure: str = "LEAVE"
    malware_policy: str = "none"
    identity_enabled: bool = True
    catalogue_enabled: bool = True
    max_retries: int = 3
    retry_delay_seconds: float = 5.0
    staging_limit_bytes: int | None = None
    free_space_reserve_bytes: int = 0

    @classmethod
    def from_dict(cls, value: dict, root: Path) -> "InboxPolicy":
        allowed = {"inbox_id", "path", "enabled", "provenance", "rights", "recursive", "stability_seconds", "min_age_seconds", "max_file_size", "include_patterns", "exclude_patterns", "temporary_suffixes", "post_success", "post_failure", "malware_policy", "identity_enabled", "catalogue_enabled", "max_retries", "retry_delay_seconds", "staging_limit_bytes", "free_space_reserve_bytes"}
        unknown = set(value) - allowed
        if unknown: raise PolicyError("unknown inbox policy fields: " + ",".join(sorted(unknown)))
        inbox_id = str(value.get("inbox_id", "")).strip()
        if not inbox_id or any(x in inbox_id for x in ("/", "\\", "\x00")): raise PolicyError("invalid inbox id")
        raw_path = Path(str(value.get("path", inbox_id)))
        path = (raw_path if raw_path.is_absolute() else root / raw_path).resolve()
        post_success = str(value.get("post_success", "LEAVE")).upper()
        if post_success not in {"LEAVE", "MOVE_TO_PROCESSED", "DELETE_AFTER_VERIFIED_INGEST"}: raise PolicyError("invalid post-success policy")
        if str(value.get("post_failure", "LEAVE")).upper() not in {"LEAVE", "REVIEW_REQUIRED"}: raise PolicyError("invalid post-failure policy")
        return cls(inbox_id, path, bool(value.get("enabled", True)), ProvenanceClass(value.get("provenance", ProvenanceClass.UNKNOWN.value)), Rights(value.get("rights", Rights.UNKNOWN.value)), bool(value.get("recursive", False)), float(value.get("stability_seconds", 1.0)), float(value.get("min_age_seconds", 0.0)), int(value["max_file_size"]) if value.get("max_file_size") is not None else None, tuple(map(str, value.get("include_patterns", []))), tuple(map(str, value.get("exclude_patterns", []))), tuple(map(str, value.get("temporary_suffixes", cls.temporary_suffixes))), post_success, str(value.get("post_failure", "LEAVE")).upper(), str(value.get("malware_policy", "none")), bool(value.get("identity_enabled", True)), bool(value.get("catalogue_enabled", True)), int(value.get("max_retries", 3)), float(value.get("retry_delay_seconds", 5.0)), int(value["staging_limit_bytes"]) if value.get("staging_limit_bytes") is not None else None, int(value.get("free_space_reserve_bytes", 0)))

    def public(self) -> dict:
        return {"inbox_id": self.inbox_id, "path": str(self.path), "enabled": self.enabled, "provenance": self.provenance.value, "rights": self.rights.value, "recursive": self.recursive, "stability_seconds": self.stability_seconds, "min_age_seconds": self.min_age_seconds, "max_file_size": self.max_file_size, "include_patterns": list(self.include_patterns), "exclude_patterns": list(self.exclude_patterns), "temporary_suffixes": list(self.temporary_suffixes), "post_success": self.post_success, "post_failure": self.post_failure, "malware_policy": self.malware_policy}


class WatchedInboxManager:
    """Restart-safe periodic reconciliation above the existing IngestManager."""
    VERSION = 1
    DEFAULTS = {
        "downloads": {"provenance": ProvenanceClass.DOWNLOADED.value},
        "purchased": {"provenance": ProvenanceClass.PURCHASED_DOWNLOAD.value},
        "personal": {"provenance": ProvenanceClass.PERSONAL_COPY.value},
        "unknown": {"provenance": ProvenanceClass.UNKNOWN.value},
    }

    def __init__(self, archive, *, inbox_root: Path | None = None, config_path: Path | None = None, sleep=time.sleep, clock=time.time, read_only: bool = False, lock_stale_seconds: float = 3600, default_stability_seconds: float = 1.0, default_min_age_seconds: float = 0.0, default_post_success: str = "LEAVE"):
        self.archive = archive; self.root = archive.root / "local-ingest"; self.state_path = self.root / "inbox-state.json"; self.claims = self.root / "claims"; self.inbox_root = (inbox_root or archive.root / "inbox").resolve(); self.config_path = config_path; self.sleep = sleep; self.clock = clock; self.read_only = read_only; self.lock_stale_seconds = lock_stale_seconds; self.default_stability_seconds = default_stability_seconds; self.default_min_age_seconds = default_min_age_seconds; self.default_post_success = default_post_success

    def initialize(self):
        if self.read_only: return
        IngestManager(self.archive, inbox_root=self.inbox_root, read_only=False).initialize(); self.claims.mkdir(parents=True, exist_ok=True)

    def policies(self) -> list[InboxPolicy]:
        if self.config_path and self.config_path.is_file():
            data = json.loads(self.config_path.read_text(encoding="utf-8")); values = data.get("inboxes", data) if isinstance(data, dict) else data
            if not isinstance(values, list): raise PolicyError("inbox configuration must contain an inbox list")
            return [InboxPolicy.from_dict({"stability_seconds": self.default_stability_seconds, "min_age_seconds": self.default_min_age_seconds, "post_success": self.default_post_success, **x}, self.inbox_root) for x in values]
        return [InboxPolicy.from_dict({"inbox_id": key, "path": key, "stability_seconds": self.default_stability_seconds, "min_age_seconds": self.default_min_age_seconds, "post_success": self.default_post_success, **value}, self.inbox_root) for key, value in self.DEFAULTS.items()]

    def list_inboxes(self) -> list[dict]:
        return [dict(x.public(), exists=x.path.is_dir()) for x in self.policies()]

    def _state(self) -> dict:
        if not self.state_path.is_file(): return {"schema": "rab-inbox-state-v1", "version": self.VERSION, "files": {}, "watcher": {}}
        try: return json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError): return {"schema": "rab-inbox-state-v1", "version": self.VERSION, "files": {}, "watcher": {}}

    def _save(self, state):
        if not self.read_only: self.archive._atomic_json(self.state_path, state)

    @staticmethod
    def _sidecar(path: Path) -> Path: return Path(str(path) + ".rab.json")

    def _metadata(self, path: Path) -> tuple[dict, list[str]]:
        sidecar = self._sidecar(path)
        if not sidecar.is_file(): return {}, []
        try:
            value = json.loads(sidecar.read_text(encoding="utf-8"))
            if not isinstance(value, dict): raise ValueError("sidecar must be an object")
            allowed = {"provenance", "rights", "vendor", "product", "purchase_date", "title", "version", "platform", "notes"}
            if set(value) - allowed: raise ValueError("unknown sidecar field")
            for key, item in value.items():
                if not isinstance(item, (str, int, float, bool)) and item is not None: raise ValueError("sidecar values must be scalar")
            return value, []
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return {}, ["malformed sidecar: " + str(exc)]

    @staticmethod
    def _matches(policy: InboxPolicy, relative: str) -> bool:
        name = Path(relative).name
        if any(name.endswith(x) for x in policy.temporary_suffixes): return False
        if policy.include_patterns and not any(fnmatch.fnmatch(relative, x) or fnmatch.fnmatch(name, x) for x in policy.include_patterns): return False
        return not any(fnmatch.fnmatch(relative, x) or fnmatch.fnmatch(name, x) for x in policy.exclude_patterns)

    def _claim(self, key: str):
        token = self.claims / (uuid.uuid5(uuid.NAMESPACE_URL, key).hex + ".lock")
        try:
            fd = os.open(token, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600); os.write(fd, f"{os.getpid()} {self.clock()}".encode()); os.close(fd); return token
        except FileExistsError:
            try:
                if self.clock() - token.stat().st_mtime > self.lock_stale_seconds: token.unlink(); return self._claim(key)
            except OSError: pass
            return None

    def _stable(self, path: Path, policy: InboxPolicy) -> tuple[bool, dict]:
        first = path.stat(); now = self.clock(); evidence = {"size": first.st_size, "mtime_ns": first.st_mtime_ns, "observed_at": now, "minimum_age": max(0.0, now - first.st_mtime)}
        if policy.max_file_size is not None and first.st_size > policy.max_file_size: raise PolicyError("maximum file size exceeded")
        if evidence["minimum_age"] < policy.min_age_seconds: return False, evidence | {"reason": "minimum_age"}
        if policy.stability_seconds: self.sleep(policy.stability_seconds)
        second = path.stat(); evidence.update({"second_size": second.st_size, "second_mtime_ns": second.st_mtime_ns})
        return (first.st_size == second.st_size and first.st_mtime_ns == second.st_mtime_ns), evidence

    def _space_ok(self, policy: InboxPolicy, size: int) -> bool:
        usage = shutil.disk_usage(self.archive.root)
        if policy.staging_limit_bytes is not None and size > policy.staging_limit_bytes: return False
        return usage.free - size >= policy.free_space_reserve_bytes

    def _stable_tree(self, path: Path, policy: InboxPolicy) -> tuple[bool, dict]:
        def snapshot():
            return sorted((x.relative_to(path).as_posix(), x.stat().st_size, x.stat().st_mtime_ns) for x in path.rglob("*") if x.is_file() and not x.is_symlink())
        first = snapshot(); first_time = self.clock()
        if policy.stability_seconds: self.sleep(policy.stability_seconds)
        second = snapshot()
        return first == second, {"entries": len(second), "observed_at": first_time, "stable": first == second}

    @staticmethod
    def _under_completed_tree(path: Path, policy: InboxPolicy, state: dict) -> bool:
        for parent in path.parents:
            if parent == policy.path: break
            if parent.is_relative_to(policy.path):
                key = policy.inbox_id + ":" + parent.relative_to(policy.path).as_posix()
                if state["files"].get(key, {}).get("status") == "COMPLETED": return True
        return False

    def _post_success(self, path: Path, policy: InboxPolicy, object_id: str):
        if policy.post_success == "LEAVE": return "LEAVE"
        if policy.post_success == "DELETE_AFTER_VERIFIED_INGEST":
            self.archive.verify(object_id, record_event=False); path.unlink(); return "DELETED_AFTER_VERIFIED_INGEST"
        target = (policy.path.parent / (policy.inbox_id + ".processed") / path.relative_to(policy.path)).resolve()
        if not target.is_relative_to((policy.path.parent / (policy.inbox_id + ".processed")).resolve()): raise PolicyError("unsafe processed path")
        if target.exists(): raise PolicyError("processed destination already exists")
        target.parent.mkdir(parents=True, exist_ok=True); path.rename(target); return "MOVED_TO_PROCESSED"

    def _process(self, policy: InboxPolicy, path: Path, relative: str, state: dict, key: str, evidence: dict, warnings: list[str]):
        if not self._space_ok(policy, path.stat().st_size): raise RabError("insufficient staging space or configured staging limit")
        sidecar, side_warnings = self._metadata(path); warnings.extend(side_warnings)
        provenance = ProvenanceClass(sidecar.get("provenance", policy.provenance.value)); rights = Rights(sidecar.get("rights", policy.rights.value))
        result = IngestManager(self.archive, inbox_root=self.inbox_root, stability_seconds=0).ingest_file(path, category=policy.inbox_id, rights=rights, provenance=provenance, notes="", source_description="watched inbox:" + policy.inbox_id, logical_path=relative)
        if policy.malware_policy.startswith("scan:"):
            try:
                from .malware_provider import MalwareProviderManager
                request = MalwareProviderManager(self.archive).submit(result["object_id"], profile=policy.malware_policy.split(":", 1)[1])
                result["malware_state"] = request["state"]
            except Exception as exc:
                warnings.append("malware analysis incomplete: " + str(exc))
        if policy.catalogue_enabled:
            try:
                from .catalogue import Catalogue
                Catalogue(self.archive).rebuild()
            except Exception as exc:
                warnings.append("catalogue update incomplete: " + str(exc))
        result["operator_metadata"] = sidecar
        result["inbox"] = {"inbox_id": policy.inbox_id, "relative_path": relative, "stability": evidence, "post_success": self._post_success(path, policy, result["object_id"]), "warnings": warnings}
        job_path = self.root / "jobs" / (result["job_id"] + ".json"); self.archive._atomic_json(job_path, result)
        return result

    def _recover_completed(self, path: Path, policy: InboxPolicy, relative: str):
        """Recover the narrow crash window after Archive.ingest and before watcher state."""
        try: fingerprint = hash_file(path)["sha256"]
        except OSError: return None
        for job_path in sorted((self.root / "jobs").glob("*.json")):
            try: job = json.loads(job_path.read_text(encoding="utf-8"))
            except (OSError, ValueError): continue
            source = job.get("source_descriptor", {})
            if job.get("state") in {IngestJobState.COMPLETED.value, IngestJobState.COMPLETED_WITH_WARNINGS.value} and source.get("original_path") == str(path) and job.get("hashes", {}).get("sha256") == fingerprint:
                self._post_success(path, policy, job["object_id"])
                return job
        return None

    def scan_once(self) -> list[dict]:
        self.initialize(); state = self._state(); state.setdefault("files", {}); results = []; counts = {"discovered": 0, "waiting_stable": 0, "ready": 0, "processing": 0, "completed": 0, "duplicate": 0, "failed": 0, "retry_pending": 0, "bytes_pending": 0, "bytes_ingested": 0}
        for policy in self.policies():
            if not policy.enabled: continue
            policy.path.mkdir(parents=True, exist_ok=True)
            iterator = policy.path.rglob("*") if policy.recursive else policy.path.iterdir()
            for path in sorted(iterator):
                try:
                    if path.is_symlink() or not path.is_relative_to(policy.path) or path.name.endswith(".rab.json"): continue
                    relative = path.relative_to(policy.path).as_posix(); key = policy.inbox_id + ":" + relative; counts["discovered"] += 1
                    if path.is_dir():
                        if not policy.recursive or self._under_completed_tree(path, policy, state): continue
                        if not self._matches(policy, relative): continue
                        ready, evidence = self._stable_tree(path, policy)
                        state["files"][key] = {"status": "READY" if ready else "WAITING_STABLE", "fingerprint": str(evidence), "evidence": evidence, "updated_at": _now()}
                        if not ready: counts["waiting_stable"] += 1; continue
                        claim = self._claim(key)
                        if not claim: counts["processing"] += 1; continue
                        try:
                            from .tree_ingest import TreeIngestManager
                            tree_job = TreeIngestManager(self.archive).ingest(path, category=policy.inbox_id, rights=policy.rights, provenance=policy.provenance)
                            state["files"][key].update({"status": "COMPLETED", "tree_job_id": tree_job["job_id"], "completed_at": _now()}); results.append(tree_job); counts["completed"] += 1
                        except Exception as exc:
                            state["files"][key].update({"status": "FAILED", "last_error": str(exc)}); results.append({"state": "FAILED", "path": relative, "error": str(exc)}); counts["failed"] += 1
                        finally: claim.unlink(missing_ok=True)
                        continue
                    if not path.is_file(): continue
                    if policy.recursive and self._under_completed_tree(path, policy, state): continue
                    if not self._matches(policy, relative): continue
                    stat = path.stat(); fingerprint = f"{stat.st_size}:{stat.st_mtime_ns}"
                    old = state["files"].get(key, {})
                    if old.get("fingerprint") == fingerprint and old.get("status") in {"COMPLETED", "IGNORED", "FAILED"}: continue
                    if old.get("fingerprint") == fingerprint and old.get("status") == "RETRY_WAIT" and self.clock() < old.get("next_retry", 0): counts["retry_pending"] += 1; continue
                    ready, evidence = self._stable(path, policy)
                    state["files"][key] = {"status": "READY" if ready else "WAITING_STABLE", "fingerprint": fingerprint, "evidence": evidence, "updated_at": _now(), "retries": old.get("retries", 0)}
                    if not ready: counts["waiting_stable"] += 1; counts["bytes_pending"] += stat.st_size; continue
                    counts["ready"] += 1; claim = self._claim(key)
                    if not claim: counts["processing"] += 1; continue
                    try:
                        recovered = self._recover_completed(path, policy, relative)
                        if recovered:
                            state["files"][key].update({"status": "COMPLETED", "job_id": recovered["job_id"], "object_id": recovered["object_id"], "duplicate": recovered.get("duplicate", False), "recovered": True, "completed_at": _now()}); counts["completed"] += 1; results.append(recovered); continue
                        state["files"][key]["status"] = "PROCESSING"; self._save(state)
                        result = self._process(policy, path, relative, state, key, evidence, [])
                        state["files"][key].update({"status": "COMPLETED", "job_id": result["job_id"], "object_id": result["object_id"], "duplicate": result["duplicate"], "completed_at": _now()}); counts["completed"] += 1; counts["bytes_ingested"] += result["bytes"]; counts["duplicate"] += int(result["duplicate"]); results.append(result)
                        self.archive.append_event(result["object_id"].removeprefix("sha256:"), "INBOX_DUPLICATE" if result["duplicate"] else "INBOX_INGEST_COMPLETED", "PASS", {"inbox_id": policy.inbox_id, "relative_path": relative, "job_id": result["job_id"]})
                    except Exception as exc:
                        retries = old.get("retries", 0) + 1; permanent = isinstance(exc, (PolicyError, ValueError)) or retries >= policy.max_retries; state["files"][key].update({"status": "FAILED" if permanent else "RETRY_WAIT", "retries": retries, "last_error": str(exc), "next_retry": self.clock() + policy.retry_delay_seconds * (2 ** min(retries - 1, 6))}); counts["failed"] += int(permanent); counts["retry_pending"] += int(not permanent); results.append({"state": state["files"][key]["status"], "path": relative, "error": str(exc)})
                    finally:
                        claim.unlink(missing_ok=True)
                except (OSError, PolicyError) as exc:
                    if "key" in locals() and path.is_file(): state["files"][key] = {"status": "FAILED", "fingerprint": fingerprint if "fingerprint" in locals() else "", "last_error": str(exc), "updated_at": _now()}
                    results.append({"state": "FAILED", "path": str(path.name), "error": str(exc)}); counts["failed"] += 1
        state["watcher"] = {"last_scan": _now(), "counts": counts}; self._save(state); return results

    def status(self) -> dict:
        state = self._state(); values = list(state.get("files", {}).values()); counts = state.get("watcher", {}).get("counts", {})
        files = [{"logical_path": key, "status": value.get("status"), "size": value.get("evidence", {}).get("size"), "job_id": value.get("job_id"), "object_id": value.get("object_id"), "error": value.get("last_error"), "retries": value.get("retries", 0)} for key, value in sorted(state.get("files", {}).items())]
        statuses = {x.get("status") for x in values if x.get("status")}
        return {"watcher": state.get("watcher", {}), "configured_inboxes": len(self.policies()), "files": len(values), "states": {key: sum(x.get("status") == key for x in values) for key in statuses}, "metrics": counts, "inboxes": self.list_inboxes(), "file_states": files}

    def watch(self, *, interval_seconds: float = 30.0, once: bool = False, max_cycles: int | None = None, stop_event=None):
        cycles = 0
        while True:
            self.scan_once(); cycles += 1
            if once or (max_cycles is not None and cycles >= max_cycles) or (stop_event and stop_event.is_set()): return self.status()
            self.sleep(interval_seconds)
