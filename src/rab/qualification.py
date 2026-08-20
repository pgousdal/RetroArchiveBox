"""Local-first seed qualification and readiness evidence.

Qualification is operational evidence. It never changes preservation identity
and hardware absence is reported as NOT_PERFORMED rather than PASS.
"""
from __future__ import annotations

import json
import os
import platform
import stat
import shutil
import socket
import subprocess
import tempfile
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from .broker import ResourceBroker
from .catalogue import Catalogue
from .errors import IntegrityError, PolicyError, RabError
from .hashing import hash_file
from .identity import IdentityCatalogue
from .local_ingest import WatchedInboxManager
from .malware import MalwareResult, MalwareStore, ScanResult, StaticScanner
from .model import IngestRequest, Rights
from .physical import PhysicalMediaOrchestrator
from .store import Archive


def _now():
    return datetime.now(UTC).isoformat()


class CheckState(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_PERFORMED = "NOT_PERFORMED"
    SKIPPED = "SKIPPED"
    WARNING = "WARNING"


class ReadinessLevel(StrEnum):
    DEVELOPMENT = "DEVELOPMENT"
    FIXTURE_QUALIFIED = "FIXTURE_QUALIFIED"
    LOCAL_SEED_READY = "LOCAL_SEED_READY"
    ONLINE_BOOTSTRAP_READY = "ONLINE_BOOTSTRAP_READY"
    PRODUCTION_QUALIFIED = "PRODUCTION_QUALIFIED"


class QualificationProfile(StrEnum):
    LOCAL_SEED_MINIMAL = "local-seed-minimal"
    LOCAL_SEED_OPTICAL = "local-seed-optical"
    LOCAL_SEED_USB = "local-seed-usb"
    LOCAL_SEED_FLOPPY = "local-seed-floppy"
    LOCAL_SEED_FULL = "local-seed-full"


PROFILE_REQUIREMENTS = {
    QualificationProfile.LOCAL_SEED_MINIMAL.value: (),
    QualificationProfile.LOCAL_SEED_OPTICAL.value: ("optical",),
    QualificationProfile.LOCAL_SEED_USB.value: ("block",),
    QualificationProfile.LOCAL_SEED_FLOPPY.value: ("flux",),
    QualificationProfile.LOCAL_SEED_FULL.value: ("optical", "block", "flux"),
}


class QualificationManager:
    VERSION = 1

    def __init__(self, archive, *, orchestrator=None, clock=None):
        self.archive = archive
        self.root = archive.root / "qualification"
        self.runs_root = self.root / "runs"
        self.backup_root = self.root / "backup-acknowledgements"
        self.seed_root = archive.root / "seed-plans"
        self.orchestrator = orchestrator or PhysicalMediaOrchestrator(archive)
        self.clock = clock or (lambda: datetime.now(UTC))

    def _write_immutable(self, path: Path, value: dict):
        encoded = json.dumps(value, indent=2, sort_keys=True) + "\n"
        if path.exists():
            if path.read_text(encoding="utf-8") != encoded: raise IntegrityError("qualification evidence identity conflict")
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name("." + path.name + ".tmp")
        temporary.write_text(encoded, encoding="utf-8"); os.replace(temporary, path); path.chmod(0o444)

    @staticmethod
    def _check(name, state, evidence=None, warnings=None, limitations=None):
        return {"check_id": name, "state": CheckState(state).value, "evidence": evidence or {}, "warnings": warnings or [], "limitations": limitations or []}

    def _host(self):
        root = self.archive.root
        evidence = {"hostname": socket.gethostname(), "os": platform.platform(), "system": platform.system(), "release": platform.release(), "architecture": platform.machine(), "python": platform.python_version(), "rab_root": str(root), "root_writable": os.access(root if root.exists() else root.parent, os.W_OK), "uid": os.getuid() if hasattr(os, "getuid") else None, "groups": list(os.getgroups()) if hasattr(os, "getgroups") else []}
        try:
            root_stat = os.stat(root if root.exists() else root.parent); volume = os.statvfs(root if root.exists() else root.parent)
            evidence["root_mode"] = stat.filemode(root_stat.st_mode); evidence["filesystem"] = {"block_size": volume.f_bsize, "free_bytes": volume.f_bavail * volume.f_frsize, "free_inodes": volume.f_favail}
            mount = subprocess.run(["findmnt", "-n", "-o", "FSTYPE,OPTIONS", str(root if root.exists() else root.parent)], check=False, capture_output=True, text=True, timeout=5, shell=False)
            evidence["mount"] = mount.stdout.strip() or None
        except (OSError, subprocess.SubprocessError): evidence["filesystem"] = {}
        try:
            evidence["os_release"] = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines() if "=" in line)
        except OSError: evidence["os_release"] = {}
        tools = {}
        for tool in ("python3", "dd", "lsblk", "blkid", "rsync", "aria2c", "cdrdao", "gw"):
            path = shutil.which(tool); tools[tool] = {"available": bool(path), "path": path}
            if path:
                try:
                    result = subprocess.run([path, "--version"], check=False, capture_output=True, text=True, timeout=5, shell=False)
                    tools[tool]["version"] = (result.stdout or result.stderr).splitlines()[0][:256] if result.returncode == 0 else None
                except (OSError, subprocess.SubprocessError): tools[tool]["version"] = None
        evidence["tools"] = tools
        required = all(tools[x]["available"] for x in ("python3", "dd", "lsblk", "blkid")) and evidence["root_writable"]
        return self._check("host", CheckState.PASS if required else CheckState.FAIL, evidence, limitations=["Debian 13 physical-host execution is not established by this run"] if required else [])

    def _storage(self, run_id):
        sandbox = Path(tempfile.mkdtemp(prefix=run_id + "-", dir=self.root.parent))
        try:
            archive = Archive(sandbox); source = sandbox / "source.bin"; source.write_bytes(b"RAB qualification fixture bytes\n")
            request = IngestRequest(source, "qualification", "fixture.bin", Rights.UNKNOWN, "application/octet-stream", "fixture")
            first = archive.ingest(request); second = archive.ingest(IngestRequest(source, "qualification-duplicate", "duplicate.bin", Rights.RESTRICTED, "application/octet-stream", "fixture"))
            exported = sandbox / "export.bin"; archive.export_original(first["object_id"], exported)
            fixity = archive.verify(first["object_id"], record_event=False); audit = archive.audit()
            identity = IdentityCatalogue(archive).rebuild(); catalogue = Catalogue(archive).rebuild()
            before = hash_file(archive.object_dir(archive.resolve(first["object_id"])) / "master")
            malware = MalwareStore(archive, scanners={"fixture": StaticScanner("fixture", ScanResult(MalwareResult.CLEAN, method="container", coverage="container-only"))})
            malware.scan_object(first["object_id"], "fixture")
            broker = ResourceBroker(archive); broker.show(first["object_id"]); ResourceBroker(archive, read_only=True).show(first["object_id"])
            after = hash_file(archive.object_dir(archive.resolve(first["object_id"])) / "master")
            checks = {"staging_write": True, "archive_ingest": True, "sha256": first["object_id"].startswith("sha256:"), "duplicate_convergence": first["object_id"] == second["object_id"], "duplicate_occurrence": len(archive.show(first["object_id"])["occurrences"]) == 2, "export_exact": exported.read_bytes() == source.read_bytes(), "fixity": fixity["outcome"] == "PASS", "audit": audit["outcome"] == "PASS", "identity_rebuild": identity.get("objects", 0) == 1, "catalogue_rebuild": catalogue.get("objects", 0) == 1, "malware_non_mutation": before == after, "broker_read": True}
            state = CheckState.PASS if all(checks.values()) else CheckState.FAIL
            return self._check("storage", state, {"checks": checks, "object_id": first["object_id"], "bytes": source.stat().st_size, "sandbox": "disposable"})
        except Exception as exc:
            return self._check("storage", CheckState.FAIL, warnings=[str(exc)], limitations=["disposable storage smoke test failed"])
        finally:
            shutil.rmtree(sandbox, ignore_errors=True)

    def _inbox(self, run_id):
        sandbox = Path(tempfile.mkdtemp(prefix=run_id + "-inbox-", dir=self.root.parent))
        try:
            inbox = sandbox / "inbox" / "purchased"; inbox.mkdir(parents=True); payload = inbox / "fixture.bin"; payload.write_bytes(b"inbox qualification")
            config = sandbox / "inboxes.json"; config.write_text(json.dumps({"inboxes": [{"inbox_id": "purchased", "path": str(inbox), "provenance": "purchased_download", "stability_seconds": 0, "min_age_seconds": 0}]}), encoding="utf-8")
            result = WatchedInboxManager(Archive(sandbox / "archive"), config_path=config).scan_once(); passed = len(result) == 1 and result[0].get("provenance_classification") == "purchased_download" and payload.read_bytes() == b"inbox qualification"
            return self._check("inbox", CheckState.PASS if passed else CheckState.FAIL, {"completed": len(result), "source_unchanged": payload.exists(), "provenance": result[0].get("provenance_classification") if result else None})
        except Exception as exc: return self._check("inbox", CheckState.FAIL, warnings=[str(exc)])
        finally: shutil.rmtree(sandbox, ignore_errors=True)

    def _hardware(self, kind):
        candidates = [x for x in self.orchestrator.discover() if x.get("kind") == kind]
        if not candidates: return self._check(kind, CheckState.NOT_PERFORMED, limitations=["no hardware/media candidate detected; real qualification requires expendable test media"])
        return self._check(kind, CheckState.NOT_PERFORMED, {"candidates": [{key: value for key, value in x.items() if key != "device"} for x in candidates]}, limitations=["discovery is not hardware qualification; capture procedure was not performed"])

    def _physical_ux(self):
        before = self.root.exists(), len(list(self.runs_root.glob("*.json"))) if self.runs_root.is_dir() else 0
        try:
            self.orchestrator.public_candidates()
            after = self.root.exists(), len(list(self.runs_root.glob("*.json"))) if self.runs_root.is_dir() else 0
            return self._check("physical_ux", CheckState.PASS if before == after else CheckState.FAIL, {"dry_run_non_mutating": before == after})
        except Exception as exc: return self._check("physical_ux", CheckState.FAIL, warnings=[str(exc)])

    def backup_acknowledgement(self):
        values = []
        if self.backup_root.is_dir():
            for path in sorted(self.backup_root.glob("*.json")):
                try: values.append(json.loads(path.read_text(encoding="utf-8")))
                except (OSError, ValueError): pass
        return sorted(values, key=lambda x: x.get("recorded_at", ""))[-1] if values else None

    def acknowledge_backup(self, *, replica: str | None = None, last_backup: str | None = None, restore_test: str = "NOT_PERFORMED", operator: str | None = None):
        value = {"schema": "rab-backup-acknowledgement-v1", "acknowledgement_id": uuid.uuid4().hex, "recorded_at": _now(), "operator": operator, "primary": str(self.archive.root), "replica_configured": bool(replica), "replica": replica, "last_backup": last_backup, "restore_test": restore_test, "warning": "RAB does not implement or verify the replica"}
        self._write_immutable(self.backup_root / (value["acknowledgement_id"] + ".json"), value); return value

    def _backup(self):
        value = self.backup_acknowledgement()
        if not value: return self._check("backup", CheckState.WARNING, limitations=["no operator backup/replica acknowledgement; museum-grade replication is not established"])
        state = CheckState.PASS if value.get("replica_configured") and value.get("restore_test") == "PASS" else CheckState.WARNING
        return self._check("backup", state, {key: value.get(key) for key in ("replica_configured", "last_backup", "restore_test")}, limitations=["replica evidence is operator acknowledgement only"])

    def _capacity(self, expected_local_seed_bytes=None):
        usage = shutil.disk_usage(self.archive.root)
        evidence = {"free_bytes": usage.free, "total_bytes": usage.total, "expected_local_seed_bytes": expected_local_seed_bytes}
        if expected_local_seed_bytes is None: return self._check("capacity", CheckState.WARNING, evidence, limitations=["expected local seed size was not supplied"])
        return self._check("capacity", CheckState.PASS if usage.free >= expected_local_seed_bytes else CheckState.WARNING, evidence, limitations=["capacity estimate is advisory, not a guarantee"])

    def _readiness(self, checks, profile):
        states = {x["check_id"]: x["state"] for x in checks}; requirements = PROFILE_REQUIREMENTS.get(profile, ())
        critical = ("host", "storage", "inbox") + tuple(requirements)
        if any(states.get(x) == CheckState.FAIL.value for x in critical): level = ReadinessLevel.DEVELOPMENT.value
        elif all(states.get(x) == CheckState.PASS.value for x in critical) and states.get("backup") == CheckState.PASS.value: level = ReadinessLevel.LOCAL_SEED_READY.value
        elif states.get("host") == CheckState.PASS.value and states.get("storage") == CheckState.PASS.value: level = ReadinessLevel.FIXTURE_QUALIFIED.value
        else: level = ReadinessLevel.DEVELOPMENT.value
        return {"level": level, "profile": profile, "required_checks": list(critical), "blocking": [x for x in critical if states.get(x) != CheckState.PASS.value], "online_bootstrap": "DISABLED_BY_POLICY"}

    def run(self, profile: str = QualificationProfile.LOCAL_SEED_MINIMAL.value, *, only: str | None = None, operator: str | None = None, expected_local_seed_bytes: int | None = None) -> dict:
        profile = QualificationProfile(profile).value; run_id = "qualification-" + uuid.uuid4().hex[:12]
        self.root.mkdir(parents=True, exist_ok=True)
        checks = []
        if only in (None, "host"): checks.append(self._host())
        if only in (None, "storage"): checks.append(self._storage(run_id))
        if only in (None, "inbox"): checks.append(self._inbox(run_id))
        if only in (None, "optical"): checks.append(self._hardware("optical"))
        if only in (None, "block"): checks.append(self._hardware("block"))
        if only in (None, "flux"): checks.append(self._hardware("flux"))
        if only in (None, "physical-media"): checks.append(self._physical_ux())
        if only is None: checks.extend((self._backup(), self._capacity(expected_local_seed_bytes)))
        readiness = self._readiness(checks, profile)
        value = {"schema": "rab-qualification-run-v1", "version": self.VERSION, "qualification_id": run_id, "host": {"hostname": socket.gethostname(), "architecture": platform.machine(), "os": platform.platform()}, "rab": {"version": "0.1.0", "commit": os.environ.get("RAB_COMMIT", "unknown")}, "recorded_at": _now(), "operator": operator, "profile": profile, "checks": checks, "readiness": readiness, "warnings": [warning for check in checks for warning in check.get("warnings", [])], "limitations": [limitation for check in checks for limitation in check.get("limitations", [])]}
        self._write_immutable(self.runs_root / (run_id + ".json"), value); return value

    def runs(self):
        values = [json.loads(x.read_text(encoding="utf-8")) for x in self.runs_root.glob("*.json")] if self.runs_root.is_dir() else []
        return sorted(values, key=lambda x: x.get("recorded_at", ""))

    def report(self, qualification_id):
        path = self.runs_root / (qualification_id + ".json")
        if not path.is_file(): raise RabError("qualification report not found")
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def public_report(value):
        result = {key: item for key, item in value.items() if key not in {"operator"}}
        result["host"] = {key: value for key, value in value.get("host", {}).items() if key not in {"hostname"}}
        checks = []
        for check in value.get("checks", []):
            item = {key: data for key, data in check.items() if key != "evidence"}
            evidence = check.get("evidence", {})
            if check.get("check_id") == "host":
                evidence = {key: data for key, data in evidence.items() if key not in {"tools", "rab_root"}}
            elif check.get("check_id") in {"optical", "block", "flux"}:
                evidence = {key: data for key, data in evidence.items() if key != "candidates"}
            item["evidence"] = evidence; checks.append(item)
        result["checks"] = checks
        return result

    def status(self):
        runs = self.runs(); latest = runs[-1] if runs else None
        return {"latest": latest["qualification_id"] if latest else None, "readiness": latest["readiness"] if latest else {"level": ReadinessLevel.DEVELOPMENT.value}, "check_states": {x["check_id"]: x["state"] for x in latest.get("checks", [])} if latest else {}, "runs": len(runs), "backup": self._backup()}

    def public_status(self):
        value = self.status(); value["backup"] = {key: item for key, item in value["backup"].items() if key not in {"evidence"}}
        return value


class SeedPlanManager:
    """Operator planning metadata; it is not preservation identity."""
    def __init__(self, archive): self.archive, self.root = archive, archive.root / "seed-plans"
    def create(self, plan_id: str, *, collection: str | None = None, notes: str = ""):
        if not plan_id or any(x in plan_id for x in ("/", "\\", "\x00")): raise PolicyError("invalid seed plan id")
        value = {"schema": "rab-seed-plan-v1", "plan_id": plan_id, "version": 1, "created_at": _now(), "updated_at": _now(), "collection": collection, "notes": notes, "entries": []}
        target = self.root / (plan_id + ".json")
        if target.exists(): raise PolicyError("seed plan already exists")
        self.archive._atomic_json(target, value); return value
    def show(self, plan_id):
        path = self.root / (plan_id + ".json")
        if not path.is_file(): raise RabError("seed plan not found")
        return json.loads(path.read_text(encoding="utf-8"))
    def add(self, plan_id: str, *, label: str, category: str, expected_count: int | None = None, nominal_bytes: int | None = None, provenance: str = "unknown", notes: str = ""):
        value = self.show(plan_id); value["version"] += 1; value["updated_at"] = _now(); value["entries"].append({"entry_id": uuid.uuid4().hex, "label": label, "category": category, "expected_count": expected_count, "nominal_bytes": nominal_bytes, "provenance": provenance, "notes": notes, "status": "PLANNED", "jobs": []}); self.archive._atomic_json(self.root / (plan_id + ".json"), value); return value
    def list(self): return [json.loads(x.read_text(encoding="utf-8")) for x in sorted(self.root.glob("*.json"))] if self.root.is_dir() else []
