from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from xml.etree import ElementTree

from .errors import IntegrityError, RabError
from .model import IngestRequest, Rights
from .store import Archive, now


RESULTS = {"EXACT_MATCH", "NO_MATCH", "AMBIGUOUS", "CONFLICT", "NOT_APPLICABLE", "ERROR"}
HASHES = ("sha1", "md5", "crc32")
HASH_LENGTHS = {"sha1": 40, "md5": 32, "crc32": 8}
PARSER_VERSION = "rab-tosec-2"


@dataclass(frozen=True)
class AuthorityRecord:
    name: str
    system: str
    category: str | None
    rom_name: str
    size: int
    crc32: str | None
    md5: str | None
    sha1: str | None
    status: str | None
    metadata: dict


def _text(node, name: str) -> str | None:
    value = node.findtext(name)
    return value if value is None else value


def _hash(value: str | None, kind: str) -> str | None:
    if value is None:
        return None
    value = value.strip().lower()
    return value if re.fullmatch(rf"[0-9a-f]{{{HASH_LENGTHS[kind]}}}", value) else None


def parse_tosec(data: bytes, member: str = "<data>") -> tuple[dict, list[AuthorityRecord]]:
    """Parse TOSEC XML; stdlib ElementTree ignores external DTDs, and entities are rejected."""
    if len(data) > 128 * 1024 * 1024:
        raise RabError("TOSEC DAT is too large")
    if re.search(rb"<!ENTITY", data[:1024 * 1024], re.I):
        raise RabError("unsafe XML entities in TOSEC DAT")
    try:
        root = ElementTree.fromstring(data)
    except (ElementTree.ParseError, ValueError) as exc:
        raise RabError(f"invalid TOSEC DAT XML: {member}") from exc
    header = root.find("header")
    if header is None:
        raise RabError(f"TOSEC DAT has no header: {member}")
    identity = {child.tag: child.text for child in header}
    dat_name = (identity.get("name") or "").strip()
    inferred_system = dat_name.split(" - ", 1)[0]
    records: list[AuthorityRecord] = []
    for game in root.findall("game"):
        name = game.get("name") or _text(game, "description")
        if not name:
            raise RabError(f"TOSEC game has no canonical name: {member}")
        system = game.get("system") or _text(game, "system") or inferred_system
        category = game.get("category") or _text(game, "category")
        for rom in game.findall("rom"):
            raw_size = rom.get("size")
            try:
                size = int(raw_size) if raw_size is not None else -1
            except ValueError:
                size = -1
            records.append(AuthorityRecord(
                name=name, system=system, category=category,
                rom_name=rom.get("name") or "", size=size,
                crc32=_hash(rom.get("crc"), "crc32"), md5=_hash(rom.get("md5"), "md5"),
                sha1=_hash(rom.get("sha1"), "sha1"), status=rom.get("status"),
                metadata={key: value for key, value in rom.attrib.items()
                          if key not in {"name", "size", "crc", "md5", "sha1"}},
            ))
    return identity, records


class Authority:
    """Generic authority service. The SQLite file is disposable; M1 objects and sidecars are not."""

    VERSION = 2

    def __init__(self, archive: Archive):
        self.archive = archive
        self.db_path = archive.root / "authority.sqlite3"
        self.metadata = archive.root / "authority-metadata" / "datasets"

    def initialize(self) -> None:
        self.archive.initialize()
        self.metadata.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS authority_schema (version INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS datasets (
              dataset_id TEXT PRIMARY KEY, authority_id TEXT NOT NULL, authority_type TEXT NOT NULL,
              release_identity TEXT NOT NULL, release_version TEXT, release_date TEXT,
              source_object TEXT NOT NULL, source TEXT NOT NULL, acquired_at TEXT NOT NULL,
              parser_version TEXT NOT NULL, rights TEXT NOT NULL, imported_at TEXT NOT NULL,
              status TEXT NOT NULL, error TEXT, record_count INTEGER NOT NULL,
              selected_members TEXT NOT NULL DEFAULT '[]'
            );
            CREATE TABLE IF NOT EXISTS records (
              record_id TEXT PRIMARY KEY, dataset_id TEXT NOT NULL REFERENCES datasets(dataset_id),
              canonical_name TEXT NOT NULL, system TEXT NOT NULL, category TEXT, rom_name TEXT NOT NULL,
              size INTEGER NOT NULL, crc32 TEXT, md5 TEXT, sha1 TEXT, status TEXT, metadata TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS assertions (
              assertion_id TEXT PRIMARY KEY, dataset_id TEXT NOT NULL REFERENCES datasets(dataset_id),
              object_sha256 TEXT NOT NULL, record_id TEXT, result TEXT NOT NULL, match_method TEXT NOT NULL,
              matched_hashes TEXT NOT NULL, canonical_name TEXT, metadata TEXT NOT NULL,
              evidence TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS platform_mappings (
              dataset_id TEXT NOT NULL REFERENCES datasets(dataset_id), system TEXT NOT NULL,
              platform_id TEXT NOT NULL, evidence TEXT NOT NULL,
              PRIMARY KEY(dataset_id, system, platform_id)
            );
            CREATE INDEX IF NOT EXISTS records_hash_size ON records(sha1, size, md5, crc32);
            CREATE INDEX IF NOT EXISTS records_md5_size ON records(md5, size);
            CREATE INDEX IF NOT EXISTS records_crc_size ON records(crc32, size);
            CREATE INDEX IF NOT EXISTS assertions_object ON assertions(object_sha256, dataset_id);
            """)
            row = db.execute("SELECT version FROM authority_schema LIMIT 1").fetchone()
            if row is None:
                db.execute("INSERT INTO authority_schema VALUES (?)", (self.VERSION,))
            elif row[0] == 1:
                columns = {x[1] for x in db.execute("PRAGMA table_info(datasets)")}
                if "selected_members" not in columns:
                    db.execute("ALTER TABLE datasets ADD COLUMN selected_members TEXT NOT NULL DEFAULT '[]'")
                db.execute("UPDATE authority_schema SET version=?", (self.VERSION,))
            elif row[0] != self.VERSION:
                raise RabError(f"unsupported authority schema version: {row[0]}")

    @staticmethod
    def _dataset_id(authority_id: str, release: str, source_sha: str) -> str:
        raw = f"{authority_id}\0{release}\0{source_sha}".encode()
        return hashlib.sha256(raw).hexdigest()

    def _members(self, path: Path, data: bytes, selected: set[str] | None = None) -> Iterable[tuple[str, bytes]]:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                for info in sorted(archive.infolist(), key=lambda x: x.filename):
                    if (not info.is_dir() and info.filename.lower().endswith((".dat", ".xml"))
                            and (selected is None or info.filename in selected)):
                        yield info.filename, archive.read(info)
        else:
            if selected is None or path.name in selected:
                yield path.name, data

    def import_tosec(self, path: Path, *, release: str | None = None,
                     source: str | None = None, rights: Rights = Rights.UNKNOWN,
                     members: list[str] | None = None, release_version: str | None = None,
                     release_date: str | None = None) -> dict:
        self.initialize()
        if not path.is_file():
            raise RabError(f"authority input is not a file: {path}")
        source_object = self.archive.ingest(IngestRequest(
            path, "authority:tosec", source or str(path), rights,
            "application/zip" if zipfile.is_zipfile(path) else "application/xml", path.name,
        ))["object_id"]
        source_sha = source_object.removeprefix("sha256:")
        data = path.read_bytes()
        identities: list[dict] = []
        records: list[AuthorityRecord] = []
        error = None
        try:
            seen_members = set()
            for member, content in self._members(path, data, set(members) if members else None):
                seen_members.add(member)
                identity, parsed = parse_tosec(content, member)
                identities.append(identity)
                records.extend(parsed)
            missing = sorted(set(members or []) - seen_members)
            if missing:
                raise RabError(f"selected TOSEC DAT member is missing: {missing[0]}")
        except RabError as exc:
            error = str(exc)
        identity = identities[0] if identities else {}
        release_identity = release or identity.get("name") or path.name
        dataset_id = self._dataset_id("TOSEC", release_identity, source_sha)
        metadata = {
            "dataset_id": dataset_id, "authority_id": "TOSEC", "authority_type": "VERIFICATION_AUTHORITY",
            "release_identity": release_identity, "release_version": release_version or identity.get("version"),
            "release_date": release_date or identity.get("date"), "source_object": source_object,
            "source": source or str(path), "acquired_at": now(), "parser_version": PARSER_VERSION,
            "rights": rights.value, "imported_at": now(), "status": "FAILED" if error else "IMPORTED",
            "error": error, "record_count": len(records), "selected_members": members or [],
        }
        self._write_metadata(metadata)
        with sqlite3.connect(self.db_path) as db:
            db.execute("INSERT OR REPLACE INTO datasets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       tuple(metadata[k] for k in ("dataset_id", "authority_id", "authority_type", "release_identity",
                       "release_version", "release_date", "source_object", "source", "acquired_at", "parser_version",
                       "rights", "imported_at", "status", "error", "record_count"))
                       + (json.dumps(metadata["selected_members"], sort_keys=True),))
            if not error:
                self._insert_records(db, dataset_id, records)
        if error:
            raise RabError(error)
        self.match_all(dataset_id)
        return {"dataset_id": dataset_id, "status": "IMPORTED", "records": len(records), "source_object": source_object}

    def _write_metadata(self, value: dict) -> None:
        target = self.metadata / f"{value['dataset_id']}.json"
        if target.exists() and target.read_text(encoding="utf-8") != json.dumps(value, indent=2, sort_keys=True) + "\n":
            raise IntegrityError("authority dataset metadata identity conflict")
        if not target.exists():
            target.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            target.chmod(0o444)

    @staticmethod
    def _insert_records(db, dataset_id: str, records: list[AuthorityRecord]) -> None:
        for index, record in enumerate(records):
            record_id = hashlib.sha256(json.dumps(record.__dict__, sort_keys=True).encode()).hexdigest()
            db.execute("INSERT OR IGNORE INTO records VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                       (record_id, dataset_id, record.name, record.system, record.category, record.rom_name,
                        record.size, record.crc32, record.md5, record.sha1, record.status,
                       json.dumps(record.metadata, sort_keys=True)))
            system = record.system.strip().lower()
            platform = "amiga" if system in {"amiga", "commodore amiga"} else None
            if platform:
                db.execute("INSERT OR IGNORE INTO platform_mappings VALUES (?,?,?,?)",
                           (dataset_id, record.system, platform, "exact-system-name;rab-platform-v1"))

    def _rebuild_index(self) -> None:
        if self.db_path.exists():
            self.db_path.unlink()
        self.initialize()
        for path in sorted(self.metadata.glob("*.json")):
            metadata = json.loads(path.read_text(encoding="utf-8"))
            source = metadata["source_object"].removeprefix("sha256:")
            master = self.archive.object_dir(source) / "master"
            if not master.is_file():
                raise IntegrityError(f"authority source object missing: {source}")
            records: list[AuthorityRecord] = []
            if metadata["status"] == "IMPORTED":
                for member, data in self._members(master, master.read_bytes(), set(metadata.get("selected_members") or []) or None):
                    _, parsed = parse_tosec(data, member)
                    records.extend(parsed)
            with sqlite3.connect(self.db_path) as db:
                db.execute("INSERT INTO datasets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                           tuple(metadata[k] for k in ("dataset_id", "authority_id", "authority_type", "release_identity",
                           "release_version", "release_date", "source_object", "source", "acquired_at", "parser_version",
                           "rights", "imported_at", "status", "error", "record_count"))
                           + (json.dumps(metadata.get("selected_members", []), sort_keys=True),))
                self._insert_records(db, metadata["dataset_id"], records)
        self.match_all()

    def rebuild(self) -> dict:
        self._rebuild_index()
        return self.status()

    def status(self) -> dict:
        self.initialize()
        with sqlite3.connect(self.db_path) as db:
            return {"datasets": db.execute("SELECT count(*) FROM datasets").fetchone()[0],
                    "records": db.execute("SELECT count(*) FROM records").fetchone()[0],
                    "assertions": db.execute("SELECT count(*) FROM assertions").fetchone()[0]}

    def list(self) -> list[dict]:
        self.initialize()
        with sqlite3.connect(self.db_path) as db:
            db.row_factory = sqlite3.Row
            return [dict(x) for x in db.execute("SELECT * FROM datasets ORDER BY imported_at, dataset_id")]

    def _candidate(self, db, field: str, value: str, size: int) -> list[sqlite3.Row]:
        db.row_factory = sqlite3.Row
        return db.execute(f"SELECT * FROM records WHERE {field}=? AND size=?", (value, size)).fetchall()

    def match(self, identifier: str, dataset_id: str | None = None) -> list[dict]:
        self.initialize(); sha = self.archive.resolve(identifier); obj = self.archive.show(sha)
        datasets = [dataset_id] if dataset_id else [x["dataset_id"] for x in self.list()]
        output = []
        with sqlite3.connect(self.db_path) as db:
            db.row_factory = sqlite3.Row
            for dataset in datasets:
                candidates = []
                rejected = []
                for field in ("sha1", "md5", "crc32"):
                    value = obj[field]
                    matching = db.execute(
                        f"SELECT * FROM records WHERE dataset_id=? AND {field}=? AND size=?",
                        (dataset, value, obj["size"]),
                    ).fetchall() if value else []
                    if matching:
                        # Never downgrade when an authority-supplied stronger hash disagrees.
                        stronger = HASHES[:HASHES.index(field)]
                        rejected = [r for r in matching if any(r[key] and r[key] != obj[key] for key in stronger)]
                        candidates = [r for r in matching if r not in rejected]
                        method = f"{field}+size"
                        break
                if not candidates:
                    result = "CONFLICT" if rejected else "NO_MATCH"
                    method = method if rejected else "hash+size"
                    evidence = {key: obj[key] for key in HASHES if rejected and any(r[key] for r in rejected)}
                else:
                    # A stronger supplied authority hash that disagrees prevents a weak fallback.
                    unique = {(r["canonical_name"], r["rom_name"], r["record_id"]) for r in candidates}
                    if len(unique) > 1:
                        result, method = "AMBIGUOUS", method
                    else:
                        result = "EXACT_MATCH"
                    evidence = {
                        key: obj[key] for key in HASHES
                        if any(record[key] and record[key] == obj[key] for record in candidates)
                    }
                    if result == "AMBIGUOUS":
                        evidence["candidate_record_ids"] = sorted(r["record_id"] for r in candidates)
                for record in candidates[:1] if result == "EXACT_MATCH" else [None]:
                    output.append(self._assertion(db, dataset, sha, record, result, method, evidence))
                if not candidates:
                    output.append(self._assertion(db, dataset, sha, None, result, method, evidence))
        return output

    def _assertion(self, db, dataset, sha, record, result, method, evidence) -> dict:
        imported_at = db.execute("SELECT imported_at FROM datasets WHERE dataset_id=?", (dataset,)).fetchone()[0]
        value = {"dataset_id": dataset, "object_sha256": sha, "record_id": record["record_id"] if record else None,
                 "result": result, "match_method": method, "matched_hashes": evidence,
                 "canonical_name": record["canonical_name"] if record else None,
                 "metadata": json.loads(record["metadata"]) if record else {},
                 "evidence": {"size": record["size"] if record else None, "authority_record": dict(record) if record else None,
                               "parser_version": PARSER_VERSION}, "created_at": imported_at}
        assertion_id = hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()
        value["assertion_id"] = assertion_id
        db.execute("INSERT OR REPLACE INTO assertions VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                   (assertion_id, dataset, sha, value["record_id"], result, method,
                    json.dumps(evidence, sort_keys=True), value["canonical_name"], json.dumps(value["metadata"], sort_keys=True),
                    json.dumps(value["evidence"], sort_keys=True), value["created_at"]))
        return value

    def match_all(self, dataset_id: str | None = None) -> None:
        with self.archive.db() as db:
            objects = [x[0] for x in db.execute("SELECT sha256 FROM objects")]
        with sqlite3.connect(self.db_path) as db:
            if dataset_id:
                db.execute("DELETE FROM assertions WHERE dataset_id=?", (dataset_id,))
            else:
                db.execute("DELETE FROM assertions")
        for sha in objects:
            self.match(sha, dataset_id)

    def assertions(self, identifier: str) -> list[dict]:
        self.initialize(); sha = self.archive.resolve(identifier)
        with sqlite3.connect(self.db_path) as db:
            db.row_factory = sqlite3.Row
            rows = [dict(x) for x in db.execute("SELECT * FROM assertions WHERE object_sha256=? ORDER BY created_at", (sha,))]
        for row in rows:
            for key in ("matched_hashes", "metadata", "evidence"):
                row[key] = json.loads(row[key])
        return rows

    def verify(self) -> dict:
        self.initialize(); failures = []
        with sqlite3.connect(self.db_path) as db:
            for row in db.execute("SELECT * FROM datasets"):
                source = row[6].removeprefix("sha256:")
                if not (self.archive.object_dir(source) / "master").is_file():
                    failures.append({"type": "missing_source_object", "dataset_id": row[0]})
                else:
                    try:
                        self.archive.verify(source, record_event=False)
                    except (IntegrityError, RabError):
                        failures.append({"type": "source_fixity_failure", "dataset_id": row[0]})
            if db.execute("SELECT count(*) FROM records WHERE dataset_id NOT IN (SELECT dataset_id FROM datasets)").fetchone()[0]:
                failures.append({"type": "dangling_records"})
            if db.execute("SELECT count(*) FROM assertions WHERE dataset_id NOT IN (SELECT dataset_id FROM datasets)").fetchone()[0]:
                failures.append({"type": "dangling_assertions"})
            with self.archive.db() as archive_db:
                object_ids = {row[0] for row in archive_db.execute("SELECT sha256 FROM objects")}
            if any(row[0] not in object_ids for row in db.execute("SELECT object_sha256 FROM assertions")):
                failures.append({"type": "assertion_object_missing"})
            if db.execute("SELECT count(*) FROM assertions WHERE record_id IS NOT NULL AND record_id NOT IN (SELECT record_id FROM records)").fetchone()[0]:
                failures.append({"type": "assertion_record_missing"})
            for dataset_id, expected in db.execute("SELECT dataset_id,record_count FROM datasets"):
                actual = db.execute("SELECT count(*) FROM records WHERE dataset_id=?", (dataset_id,)).fetchone()[0]
                if actual != expected:
                    failures.append({"type": "record_count_mismatch", "dataset_id": dataset_id,
                                     "expected": expected, "actual": actual})
        return {"outcome": "PASS" if not failures else "FAIL", "failures": failures}
