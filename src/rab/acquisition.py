from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from .errors import IntegrityError, PolicyError, RabError
from .hashing import hash_file
from .model import Completeness, IngestRequest
from .sources import SourceDefinition
from .store import Archive, now


def parse_aminet_readme(data: bytes) -> dict:
    text = data.decode("latin-1")
    fields: dict[str, str] = {}
    mapping = {
        "short": "short_description", "author": "author", "uploader": "uploader",
        "type": "category", "version": "version", "architecture": "architecture",
        "requires": "requirements", "date": "upload_date", "name": "package_name",
    }
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        target = mapping.get(key.strip().lower())
        if target and value.strip() and target not in fields:
            fields[target] = value.strip()
    return fields


class Acquisition:
    """Source state and staging coordinator. Archive.ingest remains the only master writer."""

    def __init__(self, archive: Archive):
        self.archive = archive
        archive.initialize()
        self.staging = archive.root / "source-staging"
        self.staging.mkdir(parents=True, exist_ok=True)
        with archive.db() as db:
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
                CREATE INDEX IF NOT EXISTS packages_source_path ON packages(source_id, source_path);
                """
            )

    def event(self, source: str, path: str | None, kind: str, outcome: str, detail: dict) -> None:
        event_id = str(uuid.uuid4())
        occurred = now()
        record = {"event_id": event_id, "source_id": source, "source_path": path,
                  "event_type": kind, "occurred_at": occurred, "outcome": outcome, "detail": detail}
        with self.archive.db() as db:
            db.execute("INSERT INTO source_events VALUES (?, ?, ?, ?, ?, ?, ?)", (
                event_id, source, path, kind, occurred, outcome, json.dumps(detail, sort_keys=True)
            ))
        target = self.archive.root / "source-metadata" / "events" / source / f"{occurred.replace(':', '')}-{event_id}.json"
        self.archive._atomic_json(target, record)
        target.chmod(0o444)

    def _current(self, source: str, path: str):
        with self.archive.db() as db:
            return db.execute("SELECT * FROM source_objects WHERE source_id=? AND source_path=?", (source, path)).fetchone()

    def ingest_completed(self, source: SourceDefinition, source_path: str, completed: Path,
                         media_type: str, title: str | None = None,
                         expected_sha256: str | None = None) -> str:
        source.validate_policy()
        if completed.name.endswith(".part") or not completed.is_file():
            raise IntegrityError("partial or absent acquisition cannot be ingested")
        hashes = hash_file(completed)
        if expected_sha256 and hashes["sha256"] != expected_sha256:
            self.event(source.id, source_path, "TRANSFER_VERIFY", "FAIL", {
                "expected_sha256": expected_sha256, "actual_sha256": hashes["sha256"]})
            raise IntegrityError(f"transfer checksum mismatch for {source_path}")
        current = self._current(source.id, source_path)
        if current and current["sha256"] == hashes["sha256"] and current["status"] == "PRESENT":
            return f"sha256:{hashes['sha256']}"
        result = self.archive.ingest(IngestRequest(
            completed, source.id, source_path, source.rights_default, media_type, title
        ))
        sha = result["object_id"].split(":", 1)[1]
        with self.archive.db() as db:
            db.execute("""INSERT INTO source_objects VALUES (?, ?, ?, ?, 'PRESENT', ?)
                ON CONFLICT(source_id, source_path) DO UPDATE SET
                sha256=excluded.sha256,size=excluded.size,status='PRESENT',seen_at=excluded.seen_at""",
                (source.id, source_path, sha, hashes["size"], now()))
        self.event(source.id, source_path, "SOURCE_INGEST", "PASS", {
            "object_id": result["object_id"], "occurrence_id": result["occurrence_id"],
            "source_class": source.source_class.value,
            "bulk_acquisition": source.bulk_acquisition,
            "rights": source.rights_default.value,
            "mirror_authorized": source.mirror_authorized,
        })
        return result["object_id"]

    def acquire_http(self, source: SourceDefinition, relative_path: str,
                     expected_sha256: str | None = None) -> str:
        if source.backend.value not in {"http", "https"} or not source.location:
            raise PolicyError("HTTP acquisition requires an HTTP(S) source")
        target_dir = self.staging / source.id
        target_dir.mkdir(parents=True, exist_ok=True)
        partial = target_dir / (hashlib.sha256(relative_path.encode()).hexdigest() + ".part")
        url = source.location.rstrip("/") + "/" + relative_path.lstrip("/")
        for attempt in range(source.retries + 1):
            try:
                offset = partial.stat().st_size if partial.exists() else 0
                request = urllib.request.Request(url, headers={
                    "User-Agent": "RetroArchiveBox/0.2 (+preservation; operator-configured)",
                    **({"Range": f"bytes={offset}-"} if offset else {}),
                })
                with urllib.request.urlopen(request, timeout=source.timeout) as response:
                    mode = "ab" if offset and response.status == 206 else "wb"
                    with partial.open(mode) as output:
                        shutil.copyfileobj(response, output)
                complete = partial.with_suffix(".complete")
                os.replace(partial, complete)
                try:
                    return self.ingest_completed(source, relative_path, complete,
                                                 "application/octet-stream", expected_sha256=expected_sha256)
                finally:
                    complete.unlink(missing_ok=True)
            except (OSError, urllib.error.URLError, IntegrityError) as exc:
                self.event(source.id, relative_path, "ACQUISITION", "FAIL", {"attempt": attempt + 1, "error": str(exc)})
                if attempt == source.retries:
                    raise RabError(f"acquisition failed for {relative_path}: {exc}") from exc
                time.sleep(min(2 ** attempt, 8))
        raise AssertionError("unreachable")

    def plan_rsync(self, source: SourceDefinition, destination: Path) -> list[str]:
        source.validate_policy(bulk=True)
        if source.backend.value != "rsync" or not source.location:
            raise PolicyError("rsync plan requires an rsync source")
        # Staging only: deliberately no --delete and never an object-store destination.
        if self.archive.objects == destination.resolve() or self.archive.objects in destination.resolve().parents:
            raise PolicyError("rsync destination cannot be preservation storage")
        command = ["rsync", "--archive", "--partial", "--delay-updates", "--timeout", str(source.timeout)]
        if source.rate_limit:
            command.extend(["--bwlimit", str(max(1, source.rate_limit // 1024))])
        command.extend([source.location, str(destination)])
        return command

    def run_rsync(self, source: SourceDefinition, *, dry_run: bool = False) -> dict:
        destination = self.staging / source.id / "mirror"
        destination.mkdir(parents=True, exist_ok=True)
        command = self.plan_rsync(source, destination)
        if dry_run:
            return {"source": source.id, "command": command, "dry_run": True}
        result = subprocess.run(command, check=False, capture_output=True, text=True)
        if result.returncode:
            self.event(source.id, None, "RSYNC", "FAIL", {"returncode": result.returncode, "stderr": result.stderr[-2000:]})
            raise RabError(f"rsync failed with exit code {result.returncode}")
        synchronized = self.sync_aminet(source, destination) if source.companion_rules.get("required_suffix") == ".readme" else None
        return {"source": source.id, "staging": str(destination), "outcome": "PASS",
                "synchronized": synchronized}

    def mark_missing(self, source_id: str, present_paths: set[str]) -> int:
        disappeared: list[str] = []
        with self.archive.db() as db:
            rows = db.execute("SELECT source_path,status FROM source_objects WHERE source_id=?", (source_id,)).fetchall()
            for row in rows:
                if row["source_path"] not in present_paths and row["status"] != "MISSING":
                    db.execute("UPDATE source_objects SET status='MISSING',seen_at=? WHERE source_id=? AND source_path=?",
                               (now(), source_id, row["source_path"]))
                    disappeared.append(row["source_path"])
        for path in disappeared:
            self.event(source_id, path, "UPSTREAM_DISAPPEARANCE", "RECORDED", {})
        return len(disappeared)

    def sync_aminet(self, source: SourceDefinition, directory: Path,
                    expected: dict[str, str] | None = None) -> dict:
        source.validate_policy()
        expected = expected or {}
        files = {p.relative_to(directory).as_posix(): p for p in directory.rglob("*") if p.is_file() and not p.name.endswith(".part")}
        stems = {p[:-4] for p in files if p.lower().endswith(".lha")} | {p[:-7] for p in files if p.lower().endswith(".readme")}
        results = []
        present: set[str] = {
            path for path in files
            if path.lower().endswith(".lha") or path.lower().endswith(".readme")
        }
        for stem in sorted(stems):
            payload_path, readme_path = stem + ".lha", stem + ".readme"
            payload = readme = None
            failed = False
            try:
                if payload_path in files:
                    payload = self.ingest_completed(source, payload_path, files[payload_path], "application/x-lha", expected_sha256=expected.get(payload_path)).split(":", 1)[1]
                if readme_path in files:
                    readme = self.ingest_completed(source, readme_path, files[readme_path], "text/plain", expected_sha256=expected.get(readme_path)).split(":", 1)[1]
            except (IntegrityError, RabError) as exc:
                failed = True
                self.event(source.id, stem, "AMINET_PACKAGE", "FAIL", {"error": str(exc)})
            state = (Completeness.ACQUISITION_FAILED if failed else Completeness.COMPLETE if payload and readme
                     else Completeness.PAYLOAD_MISSING if readme else Completeness.README_MISSING)
            metadata = {"source_path": stem, "filename": Path(payload_path).name,
                        "path": str(Path(stem).parent), "size": files[payload_path].stat().st_size if payload_path in files else None}
            if readme and readme_path in files:
                metadata.update(parse_aminet_readme(files[readme_path].read_bytes()))
            package_id = f"{source.id}:{stem}"
            self._package(package_id, source.id, stem, state, payload, readme, metadata)
            results.append({"package_id": package_id, "completeness": state.value})
        missing = self.mark_missing(source.id, present)
        disappeared_packages: list[tuple[str, str]] = []
        with self.archive.db() as db:
            rows = db.execute("SELECT package_id FROM packages WHERE source_id=? AND upstream_present=1", (source.id,)).fetchall()
            for row in rows:
                if row["package_id"].split(":", 1)[1] not in stems:
                    db.execute("UPDATE packages SET upstream_present=0,updated_at=? WHERE package_id=?", (now(), row["package_id"]))
                    disappeared_packages.append((row["package_id"].split(":", 1)[1], row["package_id"]))
        for source_path, package_id in disappeared_packages:
            self.event(source.id, source_path, "UPSTREAM_DISAPPEARANCE", "RECORDED", {"package_id": package_id})
        return {"source": source.id, "packages": results, "upstream_disappearances": missing}

    def _package(self, package_id: str, source: str, path: str, state: Completeness,
                 payload: str | None, readme: str | None, metadata: dict) -> None:
        encoded = json.dumps(metadata, sort_keys=True)
        with self.archive.db() as db:
            old = db.execute("SELECT * FROM packages WHERE package_id=?", (package_id,)).fetchone()
            unchanged = old and old["payload_sha256"] == payload and old["readme_sha256"] == readme and old["completeness"] == state.value
            if unchanged:
                db.execute("UPDATE packages SET upstream_present=1,updated_at=? WHERE package_id=?", (now(), package_id))
                return
            generation = (old["current_generation"] + 1) if old else 1
            db.execute("INSERT INTO package_generations VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (package_id, generation, payload, readme, state.value, encoded, now()))
            db.execute("""INSERT INTO packages VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                ON CONFLICT(package_id) DO UPDATE SET completeness=excluded.completeness,
                payload_sha256=excluded.payload_sha256,readme_sha256=excluded.readme_sha256,
                metadata=excluded.metadata,current_generation=excluded.current_generation,
                upstream_present=1,updated_at=excluded.updated_at""",
                (package_id, source, path, state.value, payload, readme, encoded, generation, now()))
        record = {"package_id": package_id, "source_id": source, "source_path": path,
                  "generation": generation, "payload_object": f"sha256:{payload}" if payload else None,
                  "readme_object": f"sha256:{readme}" if readme else None,
                  "completeness": state.value, "metadata": metadata, "recorded_at": now()}
        target = self.archive.root / "source-metadata" / "packages" / source / path / f"generation-{generation:06d}.json"
        self.archive._atomic_json(target, record)
        target.chmod(0o444)

    def show_package(self, package_id: str) -> dict:
        with self.archive.db() as db:
            row = db.execute("SELECT * FROM packages WHERE package_id=?", (package_id,)).fetchone()
            if not row:
                raise RabError(f"package not found: {package_id}")
            generations = db.execute("SELECT * FROM package_generations WHERE package_id=? ORDER BY generation", (package_id,)).fetchall()
            events = db.execute("SELECT * FROM source_events WHERE source_id=? AND (source_path=? OR source_path LIKE ? OR json_extract(detail,'$.package_id')=?) ORDER BY occurred_at",
                                (row["source_id"], row["source_path"], row["source_path"] + ".%", package_id)).fetchall()
        result = dict(row)
        result["metadata"] = json.loads(result["metadata"])
        result["preservation_complete"] = result["completeness"] == Completeness.COMPLETE.value
        result["payload_object"] = f"sha256:{result['payload_sha256']}" if result["payload_sha256"] else None
        result["readme_object"] = f"sha256:{result['readme_sha256']}" if result["readme_sha256"] else None
        result["payload"] = self.archive.show(result["payload_object"]) if result["payload_object"] else None
        result["readme"] = self.archive.show(result["readme_object"]) if result["readme_object"] else None
        result["generations"] = [{**dict(x), "metadata": json.loads(x["metadata"])} for x in generations]
        result["events"] = [{**dict(x), "detail": json.loads(x["detail"])} for x in events]
        return result

    def search_packages(self, query: str) -> list[dict]:
        with self.archive.db() as db:
            rows = db.execute("SELECT package_id,completeness,metadata FROM packages ORDER BY updated_at DESC").fetchall()
        terms = query.lower().split()
        matches = []
        for row in rows:
            haystack = (row["package_id"] + " " + row["metadata"]).lower()
            if all(term in haystack for term in terms):
                matches.append({"package_id": row["package_id"], "completeness": row["completeness"],
                                "metadata": json.loads(row["metadata"])})
        return matches

    def get_package(self, package_id: str, output: Path, with_readme: bool = False) -> dict:
        package = self.show_package(package_id)
        if not package["payload_object"]:
            raise RabError(f"package has no payload: {package_id}")
        output.mkdir(parents=True, exist_ok=True)
        payload_name = package["metadata"].get("filename") or Path(package["source_path"]).name + ".lha"
        exports = [self.archive.export_original(package["payload_object"], output / payload_name)]
        if with_readme:
            if not package["readme_object"]:
                raise RabError(f"package has no original readme: {package_id}")
            exports.append(self.archive.export_original(package["readme_object"], output / (Path(package["source_path"]).name + ".readme")))
        return {"package_id": package_id, "exports": exports}


def torrent_infohash(data: bytes) -> str:
    def parse(pos: int):
        start = pos
        token = data[pos:pos + 1]
        if token == b"i":
            end = data.index(b"e", pos)
            return int(data[pos + 1:end]), end + 1, start, end + 1
        if token == b"l":
            values, pos = [], pos + 1
            while data[pos:pos + 1] != b"e":
                value, pos, _, _ = parse(pos); values.append(value)
            return values, pos + 1, start, pos + 1
        if token == b"d":
            values, spans, pos = {}, {}, pos + 1
            while data[pos:pos + 1] != b"e":
                key, pos, _, _ = parse(pos)
                value, pos, value_start, value_end = parse(pos)
                values[key] = value; spans[key] = (value_start, value_end)
            return (values, spans), pos + 1, start, pos + 1
        colon = data.index(b":", pos)
        length = int(data[pos:colon]); begin = colon + 1; end = begin + length
        return data[begin:end], end, start, end
    parsed, end, _, _ = parse(0)
    if end != len(data) or not isinstance(parsed, tuple):
        raise RabError("invalid torrent metadata")
    values, spans = parsed
    if b"info" not in values:
        raise RabError("torrent metadata has no info dictionary")
    start, stop = spans[b"info"]
    return hashlib.sha1(data[start:stop]).hexdigest()


def preserve_torrent(acquisition: Acquisition, source: SourceDefinition, path: Path,
                     source_path: str) -> dict:
    data = path.read_bytes()
    infohash = torrent_infohash(data)
    object_id = acquisition.ingest_completed(source, source_path, path, "application/x-bittorrent", path.name)
    acquisition.event(source.id, source_path, "TORRENT_METADATA", "PASS", {"object_id": object_id, "infohash_v1": infohash})
    return {"object_id": object_id, "infohash_v1": infohash, "source": source.id, "source_path": source_path}
