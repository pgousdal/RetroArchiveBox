from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Iterable

from .errors import IntegrityError, RabError
from .formats import identify_format
from .store import Archive, now
from .textmeta import extract_text


class Catalogue:
    """Rebuildable catalogue service; preservation sidecars remain authoritative."""

    VERSION = 2

    @staticmethod
    def _platform_id(value) -> str:
        return str(value).strip().lower().replace(" ", "-")

    def __init__(self, archive: Archive):
        self.archive = archive

    def initialize(self) -> None:
        try:
            self._initialize()
        except sqlite3.DatabaseError as exc:
            raise RabError("catalogue database is invalid; run 'rab catalogue rebuild'") from exc

    def _initialize(self) -> None:
        self.archive.initialize()
        with self.archive.db() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS source_objects (
                    source_id TEXT NOT NULL, source_path TEXT NOT NULL, sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL, status TEXT NOT NULL, seen_at TEXT NOT NULL,
                    PRIMARY KEY(source_id, source_path)
                );
                CREATE TABLE IF NOT EXISTS source_events (
                    id TEXT PRIMARY KEY, source_id TEXT NOT NULL, source_path TEXT,
                    event_type TEXT NOT NULL, occurred_at TEXT NOT NULL,
                    outcome TEXT NOT NULL, detail TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS packages (
                    package_id TEXT PRIMARY KEY, source_id TEXT NOT NULL, source_path TEXT NOT NULL,
                    completeness TEXT NOT NULL, payload_sha256 TEXT, readme_sha256 TEXT,
                    metadata TEXT NOT NULL, current_generation INTEGER NOT NULL,
                    upstream_present INTEGER NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS package_generations (
                    package_id TEXT NOT NULL, generation INTEGER NOT NULL,
                    payload_sha256 TEXT, readme_sha256 TEXT, completeness TEXT NOT NULL,
                    metadata TEXT NOT NULL, recorded_at TEXT NOT NULL,
                    PRIMARY KEY(package_id, generation)
                );
                CREATE TABLE IF NOT EXISTS cat_schema (version INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS cat_objects (
                    sha256 TEXT PRIMARY KEY, blake3 TEXT NOT NULL, sha1 TEXT NOT NULL,
                    md5 TEXT NOT NULL, crc32 TEXT NOT NULL, size INTEGER NOT NULL,
                    media_type TEXT NOT NULL, title TEXT, format TEXT NOT NULL,
                    detection_method TEXT NOT NULL, confidence REAL NOT NULL,
                    preservation_state TEXT NOT NULL, derived_from TEXT,
                    created_at TEXT NOT NULL, format_evidence TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS cat_occurrences (
                    id TEXT PRIMARY KEY, sha256 TEXT NOT NULL, source_id TEXT NOT NULL,
                    source_path TEXT NOT NULL, acquired_at TEXT NOT NULL, rights TEXT NOT NULL,
                    source_state TEXT NOT NULL, policy_snapshot TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cat_packages (
                    package_id TEXT PRIMARY KEY, source_id TEXT NOT NULL, source_path TEXT NOT NULL,
                    completeness TEXT NOT NULL, current_generation INTEGER NOT NULL,
                    upstream_present INTEGER NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cat_generations (
                    package_id TEXT NOT NULL, generation INTEGER NOT NULL,
                    payload_sha256 TEXT, readme_sha256 TEXT, completeness TEXT NOT NULL,
                    metadata TEXT NOT NULL, recorded_at TEXT NOT NULL,
                    PRIMARY KEY(package_id, generation)
                );
                CREATE TABLE IF NOT EXISTS cat_relationships (
                    subject_type TEXT NOT NULL, subject_id TEXT NOT NULL,
                    predicate TEXT NOT NULL, object_type TEXT NOT NULL,
                    object_id TEXT NOT NULL, evidence TEXT NOT NULL,
                    PRIMARY KEY(subject_type, subject_id, predicate, object_type, object_id)
                );
                CREATE TABLE IF NOT EXISTS cat_platforms (
                    entity_type TEXT NOT NULL, entity_id TEXT NOT NULL,
                    platform_id TEXT NOT NULL, evidence TEXT NOT NULL,
                    PRIMARY KEY(entity_type, entity_id, platform_id)
                );
                CREATE TABLE IF NOT EXISTS cat_metadata (
                    entity_type TEXT NOT NULL, entity_id TEXT NOT NULL,
                    field TEXT NOT NULL, value TEXT NOT NULL, encoding TEXT NOT NULL,
                    status TEXT NOT NULL,
                    PRIMARY KEY(entity_type, entity_id, field)
                );
                CREATE TABLE IF NOT EXISTS cat_events (
                    event_id TEXT PRIMARY KEY, event_type TEXT NOT NULL,
                    occurred_at TEXT NOT NULL, outcome TEXT NOT NULL,
                    entity_type TEXT, entity_id TEXT, detail TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS cat_occurrences_sha ON cat_occurrences(sha256);
                CREATE INDEX IF NOT EXISTS cat_occurrences_source ON cat_occurrences(source_id, source_path);
                CREATE INDEX IF NOT EXISTS cat_generations_payload ON cat_generations(payload_sha256);
                CREATE INDEX IF NOT EXISTS cat_platforms_platform ON cat_platforms(platform_id);
                CREATE VIRTUAL TABLE IF NOT EXISTS cat_fts USING fts5(
                    entity_type UNINDEXED, entity_id UNINDEXED, content
                );
                """
            )
            row = db.execute("SELECT version FROM cat_schema LIMIT 1").fetchone()
            if row is None:
                db.execute("INSERT INTO cat_schema VALUES (?)", (self.VERSION,))
            else:
                try:
                    version = int(row[0])
                except (TypeError, ValueError) as exc:
                    raise RabError("invalid catalogue schema version") from exc
                if version > self.VERSION:
                    raise RabError(f"unsupported future catalogue schema version: {version}")
                if version < 1:
                    raise RabError(f"unsupported catalogue schema version: {version}")
                if version == 1:
                    # v2 is a real, transactional upgrade of v1.  The column is
                    # derived evidence and does not alter preservation records.
                    columns = {x[1] for x in db.execute("PRAGMA table_info(cat_objects)")}
                    if "format_evidence" not in columns:
                        db.execute("ALTER TABLE cat_objects ADD COLUMN format_evidence TEXT NOT NULL DEFAULT ''")
                    db.execute("CREATE INDEX IF NOT EXISTS cat_objects_format ON cat_objects(format)")
                    db.execute("UPDATE cat_schema SET version=2")

    def validate_readonly(self) -> dict:
        """Validate an existing catalogue without creating or modifying it."""
        if not self.archive.db_path.is_file():
            raise RabError("catalogue database is missing; run 'rab catalogue rebuild'")
        try:
            with self.archive.db() as db:
                version = db.execute("SELECT version FROM cat_schema LIMIT 1").fetchone()
                if version is None or int(version[0]) != self.VERSION:
                    raise RabError("catalogue schema requires migration/rebuild")
                required = {"cat_objects", "cat_occurrences", "cat_packages", "cat_generations", "cat_fts"}
                present = {x[0] for x in db.execute("SELECT name FROM sqlite_master WHERE type IN ('table','index')")}
                missing = sorted(required - present)
                if missing:
                    raise RabError("catalogue is incomplete; run 'rab catalogue rebuild'")
                return {"schema": self.VERSION, "available": True}
        except sqlite3.DatabaseError as exc:
            raise RabError("catalogue database is invalid; run 'rab catalogue rebuild'") from exc

    def _sidecars(self, pattern: str) -> list[Path]:
        return sorted(self.archive.root.glob(pattern))

    def _manifests(self) -> list[tuple[Path, dict]]:
        result = []
        for path in sorted(self.archive.objects.glob("sha256/*/*/*/manifest.json")):
            try:
                result.append((path, json.loads(path.read_text(encoding="utf-8"))))
            except (OSError, json.JSONDecodeError) as exc:
                raise IntegrityError(f"invalid preservation manifest: {path}: {exc}") from exc
        return result

    def _source_events(self) -> list[dict]:
        events = []
        for path in sorted((self.archive.root / "source-metadata" / "events").rglob("*.json")):
            try:
                events.append(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError) as exc:
                raise IntegrityError(f"invalid source event sidecar: {path}") from exc
        return sorted(events, key=lambda x: (x.get("occurred_at", ""), x.get("event_id", "")))

    def _generations(self) -> list[dict]:
        generations = []
        for path in sorted((self.archive.root / "source-metadata" / "packages").rglob("generation-*.json")):
            try:
                generations.append(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError) as exc:
                raise IntegrityError(f"invalid package generation sidecar: {path}") from exc
        return sorted(generations, key=lambda x: (x["package_id"], int(x["generation"])))

    def _object_events(self, sha256: str) -> list[dict]:
        events = []
        for path in sorted((self.archive.object_dir(sha256) / "events").glob("*.json")):
            try:
                events.append(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError) as exc:
                raise IntegrityError(f"invalid object event sidecar: {path}") from exc
        return events

    def _occurrences(self, sha256: str) -> list[dict]:
        occurrences = []
        for path in sorted((self.archive.object_dir(sha256) / "occurrences").glob("*.json")):
            try:
                occurrence = json.loads(path.read_text(encoding="utf-8"))
                occurrence.setdefault("source_policy", {"source_id": occurrence.get("source")})
                occurrences.append(occurrence)
            except (OSError, json.JSONDecodeError) as exc:
                raise IntegrityError(f"invalid occurrence sidecar: {path}") from exc
        return occurrences

    @staticmethod
    def _package_state(package_id: str, generations: list[dict], events: list[dict]) -> tuple[dict, bool]:
        own = [x for x in generations if x["package_id"] == package_id]
        if not own:
            raise IntegrityError(f"package has no generations: {package_id}")
        latest = max(own, key=lambda x: int(x["generation"]))
        present = True
        for event in events:
            if event.get("detail", {}).get("package_id") == package_id or event.get("source_path") == latest["source_path"]:
                if event.get("event_type") == "UPSTREAM_DISAPPEARANCE":
                    present = False
                elif event.get("event_type") == "SOURCE_REAPPEARANCE":
                    present = True
        return latest, present

    def _insert_base_index(self, db: sqlite3.Connection, manifests: list[tuple[Path, dict]],
                           source_events: list[dict], generations: list[dict]) -> None:
        """Restore the legacy M1/M2 index tables when the entire DB was removed."""
        for path, manifest in manifests:
            sha = manifest["object_id"].removeprefix("sha256:")
            hashes = manifest["hashes"]
            db.execute("INSERT OR IGNORE INTO objects VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (sha, hashes["blake3"], hashes["sha1"], hashes["md5"], hashes["crc32"],
                        manifest["size"], manifest.get("media_type", "application/octet-stream"),
                        manifest.get("title"), manifest["preservation_state"],
                        (manifest.get("derived_from") or "").removeprefix("sha256:") or None,
                        manifest["created_at"]))
            for occurrence in self._occurrences(sha):
                db.execute("INSERT OR IGNORE INTO occurrences VALUES (?, ?, ?, ?, ?, ?)",
                           (occurrence["occurrence_id"], sha, occurrence["source"], occurrence["source_path"],
                            occurrence["acquired_at"], occurrence.get("rights", "UNKNOWN")))
            for event in self._object_events(sha):
                db.execute("INSERT OR IGNORE INTO events VALUES (?, ?, ?, ?, ?, ?)",
                           (event["event_id"], sha, event["event_type"], event["occurred_at"],
                            event["outcome"], json.dumps(event.get("detail", {}), sort_keys=True)))
        event_by_object = defaultdict(list)
        for event in source_events:
            db.execute("INSERT OR IGNORE INTO source_events VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (event["event_id"], event.get("source_id", ""), event.get("source_path"),
                        event["event_type"], event["occurred_at"], event["outcome"],
                        json.dumps(event.get("detail", {}), sort_keys=True)))
            object_id = event.get("detail", {}).get("object_id", "")
            if object_id.startswith("sha256:"):
                event_by_object[object_id.removeprefix("sha256:")].append(event)
        for sha, events in event_by_object.items():
            for event in events:
                detail = event.get("detail", {})
                path = event.get("source_path") or ""
                db.execute("INSERT OR IGNORE INTO events VALUES (?, ?, ?, ?, ?, ?)",
                           (event["event_id"], sha, event["event_type"], event["occurred_at"],
                            event["outcome"], json.dumps({**detail, "source_path": path}, sort_keys=True)))
        for generation in generations:
            package_id = generation["package_id"]
            db.execute("INSERT OR IGNORE INTO package_generations VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (package_id, generation["generation"],
                        (generation.get("payload_object") or "").removeprefix("sha256:") or None,
                        (generation.get("readme_object") or "").removeprefix("sha256:") or None,
                        generation["completeness"], json.dumps(generation.get("metadata", {}), sort_keys=True),
                        generation["recorded_at"]))
        by_source_path = {}
        for sha, manifest in ((m[1]["object_id"].removeprefix("sha256:"), m[1]) for m in manifests):
            for occurrence in self._occurrences(sha):
                by_source_path[(occurrence["source"], occurrence["source_path"])] = (sha, occurrence)
        for (source, path), (sha, occurrence) in by_source_path.items():
            status = "PRESENT"
            if any(e.get("source_id") == source and e.get("source_path") == path and e.get("event_type") == "UPSTREAM_DISAPPEARANCE" for e in source_events):
                status = "MISSING"
            size = db.execute("SELECT size FROM objects WHERE sha256=?", (sha,)).fetchone()[0]
            db.execute("INSERT OR REPLACE INTO source_objects VALUES (?, ?, ?, ?, ?, ?)",
                       (source, path, sha, size, status, occurrence["acquired_at"]))
        package_ids = sorted({x["package_id"] for x in generations})
        for package_id in package_ids:
            latest, present = self._package_state(package_id, generations, source_events)
            source, path = package_id.split(":", 1)
            db.execute("INSERT OR REPLACE INTO packages VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (package_id, source, path, latest["completeness"], latest.get("payload_object", "").removeprefix("sha256:") or None,
                        latest.get("readme_object", "").removeprefix("sha256:") or None,
                        json.dumps(latest.get("metadata", {}), sort_keys=True), latest["generation"], int(present), latest["recorded_at"]))

    def rebuild(self) -> dict:
        try:
            self.initialize()
        except RabError as exc:
            message = str(exc)
            if "database is invalid" not in message:
                raise
            # The SQLite file is disposable derived state.  Remove only this
            # catalogue file, never preservation directories or sidecars.
            self.archive.db_path.unlink(missing_ok=True)
            self.initialize()
        manifests = self._manifests()
        source_events = self._source_events()
        generations = self._generations()
        policy_by_occurrence = {
            event.get("detail", {}).get("occurrence_id"): event.get("detail", {})
            for event in source_events if event.get("event_type") == "SOURCE_INGEST"
        }
        with self.archive.db() as db:
            for table in ("cat_fts", "cat_events", "cat_metadata", "cat_platforms", "cat_relationships", "cat_generations", "cat_packages", "cat_occurrences", "cat_objects"):
                db.execute(f"DELETE FROM {table}")
            for table in ("events", "occurrences", "objects", "source_objects", "source_events", "packages", "package_generations"):
                if db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
                    db.execute(f"DELETE FROM {table}")
            self._insert_base_index(db, manifests, source_events, generations)
            for path, manifest in manifests:
                sha = manifest["object_id"].removeprefix("sha256:")
                master = self.archive.object_dir(sha) / "master"
                prefix = master.open("rb").read(1024 * 1024) if master.is_file() else b""
                occurrence_names = [x.get("source_path", "") for x in self._occurrences(sha)]
                identification = identify_format(prefix, name=occurrence_names[0] if occurrence_names else manifest.get("title", ""), media_type=manifest.get("media_type", ""))
                db.execute("INSERT INTO cat_objects VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                           (sha, manifest["hashes"]["blake3"], manifest["hashes"]["sha1"], manifest["hashes"]["md5"],
                            manifest["hashes"]["crc32"], manifest["size"], manifest.get("media_type", "application/octet-stream"),
                            manifest.get("title"), identification.format_id, identification.method, identification.confidence,
                            manifest["preservation_state"], (manifest.get("derived_from") or "").removeprefix("sha256:") or None,
                            manifest["created_at"], identification.method))
                for occurrence in self._occurrences(sha):
                    policy = {**occurrence.get("source_policy", {}), **policy_by_occurrence.get(occurrence["occurrence_id"], {})}
                    source_state = "PRESENT"
                    for event in source_events:
                        if event.get("source_id") == occurrence["source"] and event.get("source_path") == occurrence["source_path"]:
                            if event.get("event_type") == "UPSTREAM_DISAPPEARANCE":
                                source_state = "MISSING"
                            elif event.get("event_type") == "SOURCE_REAPPEARANCE":
                                source_state = "PRESENT"
                    db.execute("INSERT INTO cat_occurrences VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                               (occurrence["occurrence_id"], sha, occurrence["source"], occurrence["source_path"],
                                occurrence["acquired_at"], occurrence.get("rights", "UNKNOWN"), source_state,
                                json.dumps(policy, sort_keys=True)))
                    for platform in policy.get("platforms", []):
                        db.execute("INSERT OR IGNORE INTO cat_platforms VALUES (?, ?, ?, ?)", ("OBJECT", sha, self._platform_id(platform), "source-policy"))
                for event in self._object_events(sha):
                    db.execute("INSERT INTO cat_events VALUES (?, ?, ?, ?, ?, ?, ?)",
                               (event["event_id"], event["event_type"], event["occurred_at"], event["outcome"],
                                "OBJECT", sha, json.dumps(event.get("detail", {}), sort_keys=True)))
                if identification.format_id == "text" and master.is_file():
                    extraction = extract_text(master.open("rb").read(4 * 1024 * 1024))
                    db.execute("INSERT INTO cat_metadata VALUES (?, ?, ?, ?, ?, ?)",
                               ("OBJECT", sha, "text", extraction.text, extraction.encoding, extraction.status))
                    db.execute("INSERT INTO cat_fts VALUES (?, ?, ?)", ("OBJECT", sha, extraction.text))
                db.execute("INSERT INTO cat_fts VALUES (?, ?, ?)", ("OBJECT", sha, " ".join(str(manifest.get(k, "")) for k in ("title", "media_type"))))
                if manifest.get("derived_from"):
                    parent = manifest["derived_from"].removeprefix("sha256:")
                    db.execute("INSERT INTO cat_relationships VALUES (?, ?, ?, ?, ?, ?)", ("OBJECT", sha, "DERIVED_FROM", "OBJECT", parent, "manifest"))
            for event in source_events:
                detail = event.get("detail", {})
                object_id = detail.get("object_id", "").removeprefix("sha256:")
                entity_type = "OBJECT" if object_id else "SOURCE"
                entity_id = object_id or event.get("source_id")
                db.execute("INSERT OR IGNORE INTO cat_events VALUES (?, ?, ?, ?, ?, ?, ?)",
                           (event["event_id"], event["event_type"], event["occurred_at"], event["outcome"], entity_type, entity_id,
                            json.dumps(detail, sort_keys=True)))
                if event.get("event_type") == "TORRENT_METADATA" and object_id:
                    db.execute("INSERT OR IGNORE INTO cat_relationships VALUES (?, ?, ?, ?, ?, ?)",
                               ("OBJECT", object_id, "TORRENT_INFOHASH", "INFOHASH", detail.get("infohash_v1", ""), "source-event"))
            for generation in generations:
                package_id = generation["package_id"]
                payload = (generation.get("payload_object") or "").removeprefix("sha256:") or None
                readme = (generation.get("readme_object") or "").removeprefix("sha256:") or None
                db.execute("INSERT INTO cat_generations VALUES (?, ?, ?, ?, ?, ?, ?)",
                           (package_id, generation["generation"], payload, readme, generation["completeness"],
                            json.dumps(generation.get("metadata", {}), sort_keys=True), generation["recorded_at"]))
                if payload:
                    db.execute("INSERT OR IGNORE INTO cat_relationships VALUES (?, ?, ?, ?, ?, ?)", ("OBJECT", payload, "PAYLOAD_OF", "PACKAGE", package_id, "generation"))
                if readme:
                    db.execute("INSERT OR IGNORE INTO cat_relationships VALUES (?, ?, ?, ?, ?, ?)", ("OBJECT", readme, "README_OF", "PACKAGE", package_id, "generation"))
            package_ids = sorted({x["package_id"] for x in generations})
            for package_id in package_ids:
                latest, present = self._package_state(package_id, generations, source_events)
                source, path = package_id.split(":", 1)
                metadata = latest.get("metadata", {})
                db.execute("INSERT INTO cat_packages VALUES (?, ?, ?, ?, ?, ?, ?)",
                           (package_id, source, path, latest["completeness"], latest["generation"], int(present), latest["recorded_at"]))
                readme_ids = [g.get("readme_object") for g in generations if g["package_id"] == package_id and g.get("readme_object")]
                readme_text = " ".join(x[0] for x in db.execute(
                    "SELECT value FROM cat_metadata WHERE entity_type='OBJECT' AND field='text' AND entity_id IN (%s)" %
                    ",".join("?" for _ in readme_ids), tuple(x.removeprefix("sha256:") for x in readme_ids)).fetchall()) if readme_ids else ""
                content = " ".join(str(v) for v in metadata.values()) + " " + readme_text
                db.execute("INSERT INTO cat_fts VALUES (?, ?, ?)", ("PACKAGE", package_id, content))
                for field, value in metadata.items():
                    if value is not None:
                        db.execute("INSERT OR REPLACE INTO cat_metadata VALUES (?, ?, ?, ?, ?, ?)",
                                   ("PACKAGE", package_id, field, str(value), "source", "PASS"))
                for platform in metadata.get("platforms", []):
                    db.execute("INSERT OR IGNORE INTO cat_platforms VALUES (?, ?, ?, ?)", ("PACKAGE", package_id, self._platform_id(platform), "source-metadata"))
        return self.status()

    def status(self, *, read_only: bool = False) -> dict:
        if read_only:
            self.validate_readonly()
        else:
            self.initialize()
        with self.archive.db() as db:
            def count(table): return db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            return {"schema": db.execute("SELECT version FROM cat_schema LIMIT 1").fetchone()[0],
                    "objects": count("cat_objects"), "occurrences": count("cat_occurrences"),
                    "packages": count("cat_packages"), "generations": count("cat_generations"),
                    "relationships": count("cat_relationships"), "platforms": count("cat_platforms"),
                    "indexed_documents": count("cat_fts")}

    def semantic(self) -> dict:
        self.initialize()
        with self.archive.db() as db:
            result = {}
            for table in ("cat_objects", "cat_occurrences", "cat_packages", "cat_generations", "cat_relationships", "cat_platforms", "cat_metadata"):
                rows = [dict(row) for row in db.execute(f"SELECT * FROM {table} ORDER BY 1, 2, 3, 4").fetchall()]
                result[table] = rows
            return result

    def verify(self) -> dict:
        self.initialize()
        failures = []
        manifests = self._manifests()
        with self.archive.db() as db:
            for _, manifest in manifests:
                sha = manifest["object_id"].removeprefix("sha256:")
                row = db.execute("SELECT * FROM cat_objects WHERE sha256=?", (sha,)).fetchone()
                if row is None or row["sha256"] != sha:
                    failures.append({"type": "manifest_missing_from_catalogue", "sha256": sha})
                elif any(row[field] != manifest.get("hashes", {}).get(field) for field in ("blake3", "sha1", "md5", "crc32")):
                    failures.append({"type": "catalogue_hash_mismatch", "sha256": sha})
            for row in db.execute("SELECT sha256 FROM cat_objects").fetchall():
                if not (self.archive.object_dir(row[0]) / "manifest.json").is_file():
                    failures.append({"type": "catalogue_object_missing_manifest", "sha256": row[0]})
            for row in db.execute("SELECT id,sha256 FROM cat_occurrences").fetchall():
                if db.execute("SELECT 1 FROM cat_objects WHERE sha256=?", (row[1],)).fetchone() is None:
                    failures.append({"type": "dangling_occurrence", "id": row[0]})
            for row in db.execute("SELECT package_id,generation,payload_sha256,readme_sha256 FROM cat_generations").fetchall():
                for field in ("payload_sha256", "readme_sha256"):
                    if row[field] and db.execute("SELECT 1 FROM cat_objects WHERE sha256=?", (row[field],)).fetchone() is None:
                        failures.append({"type": "dangling_generation", "package_id": row[0], "generation": row[1], "field": field})
            for row in db.execute("SELECT package_id,current_generation FROM cat_packages").fetchall():
                if db.execute("SELECT 1 FROM cat_generations WHERE package_id=? AND generation=?", row).fetchone() is None:
                    failures.append({"type": "invalid_current_generation", "package_id": row[0]})
            for row in db.execute("SELECT subject_type,subject_id,object_type,object_id FROM cat_relationships").fetchall():
                for kind, ident in ((row[0], row[1]), (row[2], row[3])):
                    table = "cat_objects" if kind == "OBJECT" else "cat_packages" if kind == "PACKAGE" else None
                    if table and db.execute(f"SELECT 1 FROM {table} WHERE " + ("sha256" if table == "cat_objects" else "package_id") + "=?", (ident,)).fetchone() is None:
                        failures.append({"type": "dangling_relationship", "entity": ident})
        return {"outcome": "PASS" if not failures else "FAIL", "failures": failures,
                "objects_checked": len(manifests)}

    def search(self, query: str, *, platform: str | None = None,
               source: str | None = None, format_id: str | None = None,
               rights: str | None = None, limit: int = 25, offset: int = 0) -> dict:
        self.initialize()
        limit = max(1, min(limit, 100)); offset = max(0, offset)
        terms = [term for term in query.split() if term]
        match = " AND ".join(f'"{term.replace(chr(34), "")}"' for term in terms)
        with self.archive.db() as db:
            rows = db.execute("SELECT entity_type,entity_id FROM cat_fts WHERE cat_fts MATCH ?", (match,)).fetchall() if match else []
            package_ids = []
            object_ids = []
            for row in rows:
                (package_ids if row[0] == "PACKAGE" else object_ids).append(row[1])
            if source:
                package_ids = [x for x in package_ids if x.startswith(source + ":")]
            if platform:
                package_ids = [x for x in package_ids if db.execute("SELECT 1 FROM cat_platforms WHERE entity_type='PACKAGE' AND entity_id=? AND platform_id=?", (x, self._platform_id(platform))).fetchone()]
            if format_id:
                package_ids = [x for x in package_ids if db.execute("SELECT 1 FROM cat_generations g JOIN cat_packages p ON p.package_id=g.package_id JOIN cat_objects o ON o.sha256=g.payload_sha256 WHERE p.package_id=? AND o.format=?", (x, format_id)).fetchone()]
            if rights:
                package_ids = [x for x in package_ids if db.execute("SELECT 1 FROM cat_generations g JOIN cat_occurrences o ON o.sha256 IN (g.payload_sha256,g.readme_sha256) WHERE g.package_id=? AND o.rights=?", (x, rights)).fetchone()]
            results = []
            had_packages = bool(package_ids)
            for package_id in sorted(set(package_ids))[offset:offset + limit]:
                results.append(self.show_package(package_id))
            if not had_packages:
                for sha in sorted(set(object_ids))[offset:offset + limit]:
                    results.append(self.show_object(sha))
            return {"results": results, "limit": limit, "offset": offset, "returned": len(results)}

    def show_object(self, sha256: str) -> dict:
        self.initialize()
        sha256 = self.archive.resolve(sha256)
        with self.archive.db() as db:
            obj = db.execute("SELECT * FROM cat_objects WHERE sha256=?", (sha256,)).fetchone()
            if obj is None:
                raise RabError(f"object not found in catalogue: {sha256}")
            result = dict(obj)
            result["occurrences"] = [dict(x) for x in db.execute("SELECT * FROM cat_occurrences WHERE sha256=? ORDER BY acquired_at", (sha256,))]
            result["relationships"] = [dict(x) for x in db.execute("SELECT * FROM cat_relationships WHERE subject_id=? OR object_id=?", (sha256, sha256))]
            result["metadata"] = [dict(x) for x in db.execute("SELECT * FROM cat_metadata WHERE entity_id=?", (sha256,))]
            result["events"] = [dict(x) for x in db.execute("SELECT * FROM cat_events WHERE entity_id=? ORDER BY occurred_at", (sha256,))]
            result["object_id"] = f"sha256:{sha256}"
            return result

    def show_package(self, package_id: str) -> dict:
        self.initialize()
        with self.archive.db() as db:
            package = db.execute("SELECT * FROM cat_packages WHERE package_id=?", (package_id,)).fetchone()
            if package is None:
                raise RabError(f"package not found in catalogue: {package_id}")
            result = dict(package)
            result["generations"] = [dict(x) for x in db.execute("SELECT * FROM cat_generations WHERE package_id=? ORDER BY generation", (package_id,))]
            result["relationships"] = [dict(x) for x in db.execute("SELECT * FROM cat_relationships WHERE object_id=? OR subject_id=?", (package_id, package_id))]
            result["metadata"] = [dict(x) for x in db.execute("SELECT * FROM cat_metadata WHERE entity_id=?", (package_id,))]
            result["events"] = [dict(x) for x in db.execute("SELECT * FROM cat_events WHERE entity_id=? ORDER BY occurred_at", (package_id,))]
            result["payload_object"] = f"sha256:{result['generations'][-1]['payload_sha256']}" if result["generations"][-1]["payload_sha256"] else None
            result["readme_object"] = f"sha256:{result['generations'][-1]['readme_sha256']}" if result["generations"][-1]["readme_sha256"] else None
            result["preservation_complete"] = result["completeness"] == "COMPLETE"
            return result
