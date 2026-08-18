from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirects disabled by source policy", headers, fp)


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
        self.staging.mkdir(parents=True, exist_ok=True, mode=0o750)
        self._validate_staging_root()
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

    def _validate_staging_root(self) -> None:
        if not self.staging.is_dir():
            raise PolicyError(f"staging path is not a directory: {self.staging}")
        if self.staging.stat().st_mode & 0o022:
            raise PolicyError(f"staging path is group/world writable: {self.staging}")

    def _staging_destination(self, destination: Path) -> Path:
        self._validate_staging_root()
        resolved = destination.resolve()
        try:
            resolved.relative_to(self.staging.resolve())
        except ValueError as exc:
            raise PolicyError(f"destination must be inside staging: {destination}") from exc
        if resolved == self.archive.objects.resolve() or self.archive.objects.resolve() in resolved.parents:
            raise PolicyError("destination cannot be preservation storage")
        return resolved

    def _check_space(self, source: SourceDefinition, additional: int, target: Path) -> None:
        usage = shutil.disk_usage(self.staging)
        if usage.free < max(source.minimum_free_space_bytes, additional):
            raise RabError(f"insufficient free space for staging {target}: {usage.free} bytes free")
        if source.staging_limit_bytes is not None:
            used = sum(p.stat().st_size for p in self.staging.rglob("*") if p.is_file())
            if used + additional > source.staging_limit_bytes:
                raise RabError(f"staging limit exceeded for {source.id}: {used + additional} bytes")

    def _stage_file(self, source: SourceDefinition, source_path: str, path: Path) -> Path:
        if not path.is_file() or path.is_symlink():
            raise RabError(f"source input is not a regular non-symlink file: {path}")
        relative = Path(source_path)
        if relative.is_absolute() or ".." in relative.parts:
            raise PolicyError(f"source path must be relative without traversal: {source_path}")
        target = self.staging / source.id / "imports" / relative
        self._check_space(source, path.stat().st_size, target)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.part")
        with path.open("rb") as source_handle, temporary.open("wb") as target_handle:
            shutil.copyfileobj(source_handle, target_handle, length=1024 * 1024)
        os.replace(temporary, target)
        return target

    @staticmethod
    def _require_enabled(source: SourceDefinition) -> None:
        if not source.enabled:
            raise PolicyError(f"source {source.id}: source is disabled; explicit enablement is required")

    @staticmethod
    def _validate_source_path(source_path: str) -> None:
        relative = Path(source_path)
        if not source_path or relative.is_absolute() or ".." in relative.parts:
            raise PolicyError(f"source path must be relative without traversal: {source_path}")

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
        self._validate_source_path(source_path)
        if completed.name.endswith(".part") or not completed.is_file():
            raise IntegrityError("partial or absent acquisition cannot be ingested")
        try:
            completed.resolve().relative_to(self.staging.resolve())
        except ValueError as exc:
            raise PolicyError("completed acquisition must be inside source staging") from exc
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
                     expected_sha256: str | None = None,
                     expected_size: int | None = None) -> str:
        if source.backend.value not in {"http", "https"} or not source.location:
            raise PolicyError("HTTP acquisition requires an HTTP(S) source")
        self._validate_source_path(relative_path)
        self._require_enabled(source)
        target_dir = self.staging / source.id
        target_dir.mkdir(parents=True, exist_ok=True)
        partial = target_dir / (hashlib.sha256(relative_path.encode()).hexdigest() + ".part")
        url = source.location.rstrip("/") + "/" + relative_path.lstrip("/")
        current_before = self._current(source.id, relative_path)
        known_sha = current_before["sha256"] if current_before and current_before["status"] == "PRESENT" else None
        for attempt in range(source.retries + 1):
            try:
                if known_sha is None and attempt == 0:
                    self.event(source.id, relative_path, "ACQUISITION_STARTED", "PASS", {"attempt": attempt + 1})
                offset = partial.stat().st_size if partial.exists() else 0
                request = urllib.request.Request(url, headers={
                    "User-Agent": "RetroArchiveBox/0.2 (+preservation; operator-configured)",
                    **({"Range": f"bytes={offset}-"} if offset else {}),
                })
                opener = urllib.request.build_opener() if source.allow_redirects else urllib.request.build_opener(_NoRedirect())
                with opener.open(request, timeout=source.timeout) as response:
                    status = getattr(response, "status", None)
                    if offset and status != 206:
                        # A server that ignores Range must never have its full response appended.
                        partial.unlink(missing_ok=True)
                        self.event(source.id, relative_path, "RANGE_RESUME", "RESTART", {"status": status})
                        offset = 0
                        request = urllib.request.Request(url, headers={"User-Agent": "RetroArchiveBox/0.2 (+preservation; operator-configured)"})
                        with opener.open(request, timeout=source.timeout) as fresh:
                            content_length = fresh.headers.get("Content-Length")
                            transfer_size = int(content_length) if content_length and content_length.isdigit() else 0
                            self._check_space(source, transfer_size, partial)
                            self._stream_response(fresh, partial, source, 0, expected_size)
                    else:
                        if offset and status == 206:
                            content_range = response.headers.get("Content-Range", "")
                            if not content_range.startswith(f"bytes {offset}-"):
                                raise IntegrityError("server returned an invalid range response")
                        content_length = response.headers.get("Content-Length")
                        transfer_size = int(content_length) if content_length and content_length.isdigit() else 0
                        total_size = offset + transfer_size if status == 206 else transfer_size
                        self._check_space(source, total_size, partial)
                        self._stream_response(response, partial, source, offset, expected_size)
                if expected_size is not None and partial.stat().st_size != expected_size:
                    raise IntegrityError(f"transfer size mismatch for {relative_path}")
                complete = partial.with_suffix(".complete")
                os.replace(partial, complete)
                try:
                    result = self.ingest_completed(source, relative_path, complete,
                                                   "application/octet-stream", expected_sha256=expected_sha256)
                    if known_sha != result.split(":", 1)[1]:
                        self.event(source.id, relative_path, "ACQUISITION_COMPLETED", "PASS", {"object_id": result})
                    return result
                finally:
                    complete.unlink(missing_ok=True)
            except (OSError, urllib.error.URLError, IntegrityError) as exc:
                self.event(source.id, relative_path, "ACQUISITION", "FAIL", {"attempt": attempt + 1, "error": str(exc)})
                if attempt == source.retries:
                    raise RabError(f"acquisition failed for {relative_path}: {exc}") from exc
                time.sleep(min(2 ** attempt, 8))
        raise AssertionError("unreachable")

    def _stream_response(self, response, partial: Path, source: SourceDefinition,
                         offset: int, expected_size: int | None) -> None:
        mode = "ab" if offset else "wb"
        started = time.monotonic()
        transferred = 0
        with partial.open(mode) as output:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                output.write(chunk)
                transferred += len(chunk)
                if source.rate_limit:
                    target_elapsed = transferred / source.rate_limit
                    delay = target_elapsed - (time.monotonic() - started)
                    if delay > 0:
                        time.sleep(min(delay, 1.0))

    def acquire_http_paths(self, source: SourceDefinition, paths: list[str],
                           expected: dict[str, str] | None = None) -> list[str]:
        if not paths:
            raise PolicyError("HTTP source sync requires at least one explicit path")
        return [self.acquire_http(source, path, (expected or {}).get(path)) for path in paths]

    def acquire_http_aminet(self, source: SourceDefinition, paths: list[str],
                            expected: dict[str, str] | None = None) -> dict:
        """Acquire a bounded set of Aminet paths over HTTP and link package pairs."""
        objects = {path: self.acquire_http(source, path, (expected or {}).get(path)) for path in paths}
        stems = {path[:-4] for path in paths if path.lower().endswith(".lha")} | {
            path[:-7] for path in paths if path.lower().endswith(".readme")}
        packages = []
        for stem in sorted(stems):
            payload_id = objects.get(stem + ".lha")
            readme_id = objects.get(stem + ".readme")
            metadata = {"source_path": stem, "filename": Path(stem + ".lha").name,
                        "path": str(Path(stem).parent), "size": None}
            if payload_id:
                payload = self.archive.show(payload_id)
                metadata["size"] = payload["size"]
            if readme_id:
                readme = self.archive.show(readme_id)
                metadata.update(parse_aminet_readme((self.archive.object_dir(readme["sha256"]) / "master").read_bytes()))
            state = (Completeness.COMPLETE if payload_id and readme_id else
                     Completeness.PAYLOAD_MISSING if readme_id else Completeness.README_MISSING)
            package_id = f"{source.id}:{stem}"
            self._package(package_id, source.id, stem, state,
                          payload_id.split(":", 1)[1] if payload_id else None,
                          readme_id.split(":", 1)[1] if readme_id else None, metadata)
            packages.append({"package_id": package_id, "completeness": state.value})
        return {"source": source.id, "objects": objects, "packages": packages}

    def acquire_torrent(self, source: SourceDefinition, torrent_path: Path,
                        source_path: str) -> dict:
        if source.backend.value != "bittorrent":
            raise PolicyError("torrent acquisition requires the bittorrent backend")
        self._require_enabled(source)
        metadata = preserve_torrent(self, source, torrent_path, source_path)
        client_name = source.torrent_client or "aria2c"
        client = shutil.which(client_name)
        if not client:
            self.event(source.id, source_path, "TORRENT_PAYLOAD_ACQUISITION", "FAIL",
                       {"error": f"required client not found: {client_name}"})
            raise RabError(f"BitTorrent client not installed: {client_name}; torrent metadata was preserved")
        destination = self._staging_destination(self.staging / source.id / "torrent" / metadata["infohash_v1"])
        destination.mkdir(parents=True, exist_ok=True)
        staged_torrent = self._stage_file(source, source_path, torrent_path)
        command = [client, f"--dir={destination}", "--continue=true", "--check-integrity=true",
                   "--seed-time=0", f"--max-connection-per-server={source.concurrency}",
                   "--file-allocation=none"]
        if source.rate_limit:
            command.append(f"--max-overall-download-limit={source.rate_limit}")
        command.extend(["--", str(staged_torrent)])
        self.event(source.id, source_path, "TORRENT_PAYLOAD_ACQUISITION", "STARTED",
                   {"infohash_v1": metadata["infohash_v1"], "command": command})
        result = subprocess.run(command, check=False, capture_output=True, text=True)
        if result.returncode:
            self.event(source.id, source_path, "TORRENT_PAYLOAD_ACQUISITION", "FAIL",
                       {"returncode": result.returncode, "stderr": result.stderr[-2000:]})
            raise RabError(f"torrent client failed with exit code {result.returncode}")
        payloads = []
        for candidate in sorted(destination.rglob("*")):
            if candidate.is_symlink():
                raise PolicyError(f"torrent client produced a symlink: {candidate}")
            if not candidate.is_file() or candidate.name.endswith((".part", ".torrent", ".aria2")):
                continue
            relative = candidate.relative_to(destination).as_posix()
            object_id = self.ingest_completed(source, f"torrent/{metadata['infohash_v1']}/{relative}", candidate,
                                               "application/octet-stream")
            payloads.append({"source_path": relative, "object_id": object_id})
        self.event(source.id, source_path, "TORRENT_PAYLOAD_ACQUIRED", "PASS",
                   {"infohash_v1": metadata["infohash_v1"], "payloads": payloads})
        return {**metadata, "payloads": payloads, "command": command}

    def plan_rsync(self, source: SourceDefinition, destination: Path, scope: str | None = None) -> list[str]:
        source.validate_policy(bulk=True)
        if source.backend.value != "rsync" or not source.location:
            raise PolicyError("rsync plan requires an rsync source")
        destination = self._staging_destination(destination)
        if scope is not None and (not scope or Path(scope).is_absolute() or ".." in Path(scope).parts):
            raise PolicyError("rsync scope must be a relative path without traversal")
        command = ["rsync", "--archive", "--partial", "--delay-updates", "--timeout", str(source.timeout)]
        if source.rate_limit:
            command.extend(["--bwlimit", str(max(1, source.rate_limit // 1024))])
        location = source.location.rstrip("/") + ("/" + scope.strip("/") if scope else "") + "/"
        command.extend([location, str(destination)])
        return command

    def run_rsync(self, source: SourceDefinition, *, dry_run: bool = False,
                  scope: str | None = None) -> dict:
        destination = self._staging_destination(self.staging / source.id / "mirror")
        if dry_run:
            result = self.plan_source(source, scope=scope)
            result["dry_run"] = True
            return result
        self._require_enabled(source)
        destination.mkdir(parents=True, exist_ok=True)
        command = self.plan_rsync(source, destination, scope)
        result = subprocess.run(command, check=False, capture_output=True, text=True)
        if result.returncode:
            self.event(source.id, None, "RSYNC", "FAIL", {"returncode": result.returncode, "stderr": result.stderr[-2000:]})
            raise RabError(f"rsync failed with exit code {result.returncode}")
        self.event(source.id, scope, "ACQUISITION_COMPLETED", "PASS", {"backend": "rsync", "command": command})
        synchronized = self.sync_aminet(source, destination) if source.companion_rules.get("required_suffix") == ".readme" else None
        return {"source": source.id, "staging": str(destination), "outcome": "PASS",
                "synchronized": synchronized}

    def plan_source(self, source: SourceDefinition, *, scope: str | None = None,
                    paths: list[str] | None = None) -> dict:
        destination = self.staging / source.id / "mirror"
        result = {"source": source.public(), "backend": source.backend.value,
                  "scope": scope, "paths": paths or [], "staging": str(destination),
                  "authorized": bool(source.enabled and source.mirror_authorized
                                      and source.bulk_acquisition == "allowed")}
        if source.backend.value == "rsync":
            try:
                result["command"] = self.plan_rsync(source, destination, scope)
            except PolicyError as exc:
                result["rejection"] = str(exc)
        elif source.backend.value in {"http", "https"}:
            if not paths:
                result["rejection"] = "HTTP source plan requires explicit paths"
            elif not source.enabled:
                result["rejection"] = f"source {source.id}: source is disabled; explicit enablement is required"
            else:
                result["urls"] = [source.location.rstrip("/") + "/" + p.lstrip("/") for p in paths]
        else:
            result["rejection"] = f"no planner for backend {source.backend.value}"
        return result

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
        self._require_enabled(source)
        directory = directory.resolve()
        if not directory.is_dir():
            raise RabError(f"source directory is not a directory: {directory}")
        expected = expected or {}
        files = {}
        for candidate in directory.rglob("*"):
            if candidate.is_symlink():
                raise PolicyError(f"symlink in source staging is not permitted: {candidate}")
            if candidate.is_file() and not candidate.name.endswith(".part"):
                files[candidate.relative_to(directory).as_posix()] = candidate
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
                    staged = self._stage_file(source, payload_path, files[payload_path]) if self.staging.resolve() not in files[payload_path].resolve().parents else files[payload_path]
                    payload = self.ingest_completed(source, payload_path, staged, "application/x-lha", expected_sha256=expected.get(payload_path)).split(":", 1)[1]
                if readme_path in files:
                    staged = self._stage_file(source, readme_path, files[readme_path]) if self.staging.resolve() not in files[readme_path].resolve().parents else files[readme_path]
                    readme = self.ingest_completed(source, readme_path, staged, "text/plain", expected_sha256=expected.get(readme_path)).split(":", 1)[1]
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
            reappeared = bool(old and old["upstream_present"] == 0)
            unchanged = old and old["payload_sha256"] == payload and old["readme_sha256"] == readme and old["completeness"] == state.value
            if unchanged:
                db.execute("UPDATE packages SET upstream_present=1,updated_at=? WHERE package_id=?", (now(), package_id))
                if not reappeared:
                    return
                generation = None
            else:
                generation = (old["current_generation"] + 1) if old else 1
                db.execute("INSERT INTO package_generations VALUES (?, ?, ?, ?, ?, ?, ?)",
                           (package_id, generation, payload, readme, state.value, encoded, now()))
                db.execute("""INSERT INTO packages VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                    ON CONFLICT(package_id) DO UPDATE SET completeness=excluded.completeness,
                    payload_sha256=excluded.payload_sha256,readme_sha256=excluded.readme_sha256,
                    metadata=excluded.metadata,current_generation=excluded.current_generation,
                    upstream_present=1,updated_at=excluded.updated_at""",
                    (package_id, source, path, state.value, payload, readme, encoded, generation, now()))
        if generation is None:
            self.event(source, path, "SOURCE_REAPPEARANCE", "RECORDED", {"package_id": package_id})
            return
        record = {"package_id": package_id, "source_id": source, "source_path": path,
                  "generation": generation, "payload_object": f"sha256:{payload}" if payload else None,
                  "readme_object": f"sha256:{readme}" if readme else None,
                  "completeness": state.value, "metadata": metadata, "recorded_at": now()}
        target = self.archive.root / "source-metadata" / "packages" / source / path / f"generation-{generation:06d}.json"
        self.archive._atomic_json(target, record)
        target.chmod(0o444)
        self.event(source, path, "PACKAGE_STATE", state.value, {
            "package_id": package_id, "generation": generation,
            "payload_object": f"sha256:{payload}" if payload else None,
            "readme_object": f"sha256:{readme}" if readme else None,
        })
        if reappeared:
            self.event(source, path, "SOURCE_REAPPEARANCE", "RECORDED", {"package_id": package_id})

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
    try:
        path.resolve().relative_to(acquisition.staging.resolve())
        staged = path
    except ValueError:
        staged = acquisition._stage_file(source, source_path, path)
    object_id = acquisition.ingest_completed(source, source_path, staged, "application/x-bittorrent", path.name)
    acquisition.event(source.id, source_path, "TORRENT_METADATA", "PASS", {"object_id": object_id, "infohash_v1": infohash})
    return {"object_id": object_id, "infohash_v1": infohash, "source": source.id, "source_path": source_path}
