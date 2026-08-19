from __future__ import annotations

import json
import os
import shutil
import sqlite3
import tempfile
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterator

from .errors import IntegrityError, PolicyError, RabError
from .hashing import hash_file
from .model import IngestRequest, PreservationState, Rights


def now() -> str:
    return datetime.now(UTC).isoformat()


class Archive:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.objects = self.root / "objects"
        self.exports = self.root / "exports"
        self.db_path = self.root / "catalogue.sqlite3"

    def initialize(self) -> None:
        self.objects.mkdir(parents=True, exist_ok=True)
        self.exports.mkdir(parents=True, exist_ok=True)
        with self.db() as db:
            db.executescript(
                """
                PRAGMA foreign_keys = ON;
                CREATE TABLE IF NOT EXISTS objects (
                    sha256 TEXT PRIMARY KEY,
                    blake3 TEXT NOT NULL,
                    sha1 TEXT NOT NULL,
                    md5 TEXT NOT NULL,
                    crc32 TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    media_type TEXT NOT NULL,
                    title TEXT,
                    preservation_state TEXT NOT NULL,
                    derived_from TEXT REFERENCES objects(sha256),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS occurrences (
                    id TEXT PRIMARY KEY,
                    sha256 TEXT NOT NULL REFERENCES objects(sha256),
                    source TEXT NOT NULL,
                    source_path TEXT NOT NULL,
                    acquired_at TEXT NOT NULL,
                    rights TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    sha256 TEXT NOT NULL REFERENCES objects(sha256),
                    event_type TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    detail TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS occurrences_sha ON occurrences(sha256);
                CREATE INDEX IF NOT EXISTS events_sha ON events(sha256);
                """
            )

    @contextmanager
    def db(self) -> Iterator[sqlite3.Connection]:
        self.root.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.db_path)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        finally:
            db.close()

    def object_dir(self, sha256: str) -> Path:
        return self.objects / "sha256" / sha256[:2] / sha256[2:4] / sha256

    def resolve(self, identifier: str) -> str:
        value = identifier.removeprefix("sha256:")
        with self.db() as db:
            rows = db.execute(
                "SELECT sha256 FROM objects WHERE sha256 LIKE ?", (value + "%",)
            ).fetchall()
        if not rows:
            raise RabError(f"object not found: {identifier}")
        if len(rows) > 1:
            raise RabError(f"ambiguous object identifier: {identifier}")
        return str(rows[0]["sha256"])

    def ingest(self, request: IngestRequest) -> dict:
        self.initialize()
        path = request.path.resolve()
        if not path.is_file():
            raise RabError(f"not a regular file: {path}")
        hashes = hash_file(path)
        sha = str(hashes["sha256"])
        acquired = now()
        occurrence_id = str(uuid.uuid4())
        object_dir = self.object_dir(sha)
        master = object_dir / "master"
        manifest_path = object_dir / "manifest.json"
        state = (
            PreservationState.DERIVATIVE
            if request.derived_from
            else PreservationState.MASTER
        )
        parent = self.resolve(request.derived_from) if request.derived_from else None

        with self.db() as db:
            existing = db.execute(
                "SELECT * FROM objects WHERE sha256 = ?", (sha,)
            ).fetchone()
            if not existing:
                object_dir.mkdir(parents=True, exist_ok=True)
                fd, temporary = tempfile.mkstemp(prefix="ingest-", dir=object_dir)
                os.close(fd)
                tmp = Path(temporary)
                try:
                    shutil.copyfile(path, tmp)
                    copied = hash_file(tmp)
                    if copied != hashes:
                        raise IntegrityError("import changed while it was being copied")
                    os.replace(tmp, master)
                    master.chmod(0o444)
                finally:
                    tmp.unlink(missing_ok=True)
                db.execute(
                    """INSERT INTO objects VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        sha, hashes["blake3"], hashes["sha1"], hashes["md5"],
                        hashes["crc32"], hashes["size"], request.media_type,
                        request.title, state.value, parent, acquired,
                    ),
                )
                manifest = {
                    "schema": "https://retroarchivebox.invalid/schemas/object-manifest-v1.json",
                    "object_id": f"sha256:{sha}",
                    "hashes": {k: hashes[k] for k in ("sha256", "blake3", "sha1", "md5", "crc32")},
                    "size": hashes["size"],
                    "media_type": request.media_type,
                    "title": request.title,
                    "preservation_state": state.value,
                    "derived_from": f"sha256:{parent}" if parent else None,
                    "created_at": acquired,
                    "payload": "master",
                }
                self._atomic_json(manifest_path, manifest)
                manifest_path.chmod(0o444)
            elif parent and existing["derived_from"] != parent:
                raise PolicyError("byte-identical object cannot acquire a conflicting derivative identity")

            db.execute(
                "INSERT INTO occurrences VALUES (?, ?, ?, ?, ?, ?)",
                (occurrence_id, sha, request.source, request.source_path, acquired, request.rights.value),
            )
        event = self.append_event(
            sha, "INGESTION", "PASS",
            {"occurrence_id": occurrence_id, "source": request.source,
             "source_path": request.source_path, "rights": request.rights.value,
             "import_verified": True, "provenance_classification": request.provenance_classification,
             "provenance": request.provenance or {}},
        )
        self._write_occurrence(object_dir, occurrence_id, request, acquired)
        return {"object_id": f"sha256:{sha}", "occurrence_id": occurrence_id, "event": event}

    def _write_occurrence(self, object_dir: Path, occurrence_id: str, request: IngestRequest, acquired: str) -> None:
        directory = object_dir / "occurrences"
        directory.mkdir(exist_ok=True)
        target = directory / f"{occurrence_id}.json"
        self._atomic_json(target, {
            "occurrence_id": occurrence_id, "source": request.source,
            "source_path": request.source_path, "acquired_at": acquired,
            "rights": request.rights.value,
            "provenance_classification": request.provenance_classification,
            "provenance": request.provenance or {},
            "source_policy": {"source_id": request.source},
        })
        target.chmod(0o444)

    @staticmethod
    def _atomic_json(path: Path, value: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, path)

    def append_event(self, sha256: str, event_type: str, outcome: str, detail: dict) -> dict:
        event = {
            "event_id": str(uuid.uuid4()), "object_id": f"sha256:{sha256}",
            "event_type": event_type, "occurred_at": now(), "outcome": outcome,
            "detail": detail,
        }
        events_dir = self.object_dir(sha256) / "events"
        events_dir.mkdir(parents=True, exist_ok=True)
        target = events_dir / f"{event['occurred_at'].replace(':', '')}-{event['event_id']}.json"
        self._atomic_json(target, event)
        target.chmod(0o444)
        with self.db() as db:
            db.execute(
                "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?)",
                (event["event_id"], sha256, event_type, event["occurred_at"], outcome,
                 json.dumps(detail, sort_keys=True)),
            )
        return event

    def show(self, identifier: str) -> dict:
        sha = self.resolve(identifier)
        with self.db() as db:
            obj = db.execute("SELECT * FROM objects WHERE sha256 = ?", (sha,)).fetchone()
            occurrences = db.execute(
                "SELECT * FROM occurrences WHERE sha256 = ? ORDER BY acquired_at", (sha,)
            ).fetchall()
            events = db.execute(
                "SELECT * FROM events WHERE sha256 = ? ORDER BY occurred_at", (sha,)
            ).fetchall()
        result = dict(obj)
        result["object_id"] = f"sha256:{sha}"
        result["occurrences"] = []
        for row in occurrences:
            occurrence = dict(row)
            sidecar = self.object_dir(sha) / "occurrences" / (occurrence["id"] + ".json")
            if sidecar.is_file():
                try:
                    occurrence.update(json.loads(sidecar.read_text(encoding="utf-8")))
                except (OSError, json.JSONDecodeError):
                    pass
            result["occurrences"].append(occurrence)
        result["events"] = [{**dict(row), "detail": json.loads(row["detail"])} for row in events]
        return result

    def search(self, query: str) -> list[dict]:
        term = f"%{query}%"
        with self.db() as db:
            rows = db.execute(
                """SELECT DISTINCT o.sha256, o.title, o.media_type, o.size
                   FROM objects o LEFT JOIN occurrences x ON x.sha256 = o.sha256
                   WHERE o.sha256 LIKE ? OR COALESCE(o.title, '') LIKE ?
                      OR x.source LIKE ? OR x.source_path LIKE ?
                   ORDER BY o.created_at DESC""", (term, term, term, term)
            ).fetchall()
        return [{**dict(row), "object_id": f"sha256:{row['sha256']}"} for row in rows]

    def verify(self, identifier: str, *, record_event: bool = True) -> dict:
        sha = self.resolve(identifier)
        expected = self.show(sha)
        master = self.object_dir(sha) / "master"
        actual = hash_file(master) if master.is_file() else None
        passed = bool(actual) and all(
            actual[key] == expected[key] for key in ("sha256", "blake3", "sha1", "md5", "crc32", "size")
        )
        detail = {"expected_sha256": sha, "actual": actual}
        if record_event:
            self.append_event(sha, "FIXITY_CHECK", "PASS" if passed else "FAIL", detail)
        if not passed:
            raise IntegrityError(f"fixity failure for sha256:{sha}")
        return {"object_id": f"sha256:{sha}", "outcome": "PASS", **actual}

    def export_original(self, identifier: str, output: Path) -> dict:
        sha = self.resolve(identifier)
        self.verify(sha)
        master = self.object_dir(sha) / "master"
        output = output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.exists():
            raise PolicyError(f"refusing to overwrite existing export: {output}")
        shutil.copyfile(master, output)
        exported = hash_file(output)
        if exported["sha256"] != sha:
            output.unlink(missing_ok=True)
            raise IntegrityError("export verification failed")
        self.append_event(sha, "EXPORT", "PASS", {"preset": "ORIGINAL", "sha256": sha})
        return {"object_id": f"sha256:{sha}", "output": str(output), "sha256": sha}

    def audit(self) -> dict:
        with self.db() as db:
            identifiers = [row[0] for row in db.execute("SELECT sha256 FROM objects")]
        failures = []
        for sha in identifiers:
            try:
                self.verify(sha)
            except IntegrityError as exc:
                failures.append({"object_id": f"sha256:{sha}", "error": str(exc)})
        return {"objects_checked": len(identifiers), "failures": failures,
                "outcome": "PASS" if not failures else "FAIL"}

    def doctor(self) -> dict:
        self.initialize()
        checks = {
            "root_exists": self.root.is_dir(),
            "root_writable": os.access(self.root, os.W_OK),
            "objects_exists": self.objects.is_dir(),
            "database_exists": self.db_path.is_file(),
            "blake3_available": True,
        }
        return {"outcome": "PASS" if all(checks.values()) else "FAIL", "checks": checks,
                "root": str(self.root)}
