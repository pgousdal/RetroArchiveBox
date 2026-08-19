"""Universal, rebuildable identity catalogue over immutable RAB objects."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from .authority import Authority
from .errors import PolicyError, RabError
from .formats import identify_format
from .hashing import hash_file
from .malware import MalwareStore
from .model import Rights


class IdentityLevel(StrEnum):
    BYTE = "BYTE"
    MEDIA = "MEDIA"
    RELEASE = "RELEASE"
    WORK = "WORK"


class RelationshipType(StrEnum):
    EXACT_COPY_OF = "EXACT_COPY_OF"
    DERIVED_FROM = "DERIVED_FROM"
    CONTAINS = "CONTAINS"
    EXTRACTED_FROM = "EXTRACTED_FROM"
    REPRESENTATION_OF = "REPRESENTATION_OF"
    MEMBER_OF_RELEASE = "MEMBER_OF_RELEASE"
    RELEASE_OF_WORK = "RELEASE_OF_WORK"
    AUTHORITY_MATCH = "AUTHORITY_MATCH"


# Profiles are data, not platform-specific control flow. Unknown formats remain
# valid identity records with no inferred platform.
FORMAT_PROFILES = {
    "adf": {"family": "amiga", "media": "floppy"}, "dms": {"family": "amiga", "media": "floppy"},
    "ipf": {"family": "amiga", "media": "floppy"}, "hdf": {"family": "amiga", "media": "hard-disk"},
    "d64": {"family": "commodore-8-bit", "platform": "c64", "media": "floppy"},
    "d71": {"family": "commodore-8-bit", "platform": "c64", "media": "floppy"},
    "d81": {"family": "commodore-8-bit", "platform": "c128", "media": "floppy"},
    "g64": {"family": "commodore-8-bit", "platform": "c64", "media": "floppy"},
    "t64": {"family": "commodore-8-bit", "platform": "c64", "media": "tape"},
    "tap": {"family": "zx-spectrum", "platform": "zx-spectrum", "media": "tape"},
    "atr": {"family": "atari-8-bit", "media": "floppy"},
    "msa": {"family": "atari-st", "platform": "atari-st", "media": "floppy"},
    "st": {"family": "atari-st", "platform": "atari-st", "media": "floppy"},
    "cue": {"media": "optical"}, "bin": {"media": "optical"}, "iso": {"media": "optical"},
}


def _now() -> str:
    return datetime.now(UTC).isoformat()


class IdentityCatalogue:
    VERSION = 1

    def __init__(self, archive, *, read_only: bool = False):
        self.archive = archive
        self.read_only = read_only
        self.db_path = archive.root / "identity.sqlite3"
        self.metadata = archive.root / "identity-metadata"
        self.relationships_root = self.metadata / "relationships"
        self.logical_root = self.metadata / "logical"

    @contextmanager
    def db(self):
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def initialize(self):
        if self.read_only:
            if not self.db_path.is_file(): raise RabError("identity catalogue is unavailable; run 'rab identity rebuild'")
            return
        self.archive.initialize()
        with self.db() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS identity_schema (version INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS identity_objects (
                sha256 TEXT PRIMARY KEY, size INTEGER NOT NULL, crc32 TEXT NOT NULL,
                md5 TEXT NOT NULL, sha1 TEXT NOT NULL, blake3 TEXT NOT NULL,
                format_id TEXT NOT NULL, format_method TEXT NOT NULL, confidence REAL NOT NULL,
                platform_family TEXT, platform TEXT, media_type TEXT, title TEXT,
                rights TEXT NOT NULL, provenance TEXT NOT NULL, authorities TEXT NOT NULL,
                malware TEXT NOT NULL, recorded_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS identity_logical (
                identity_id TEXT PRIMARY KEY, level TEXT NOT NULL, name TEXT NOT NULL,
                version TEXT, platform TEXT, metadata TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS identity_relationships (
                relationship_id TEXT PRIMARY KEY, subject_id TEXT NOT NULL,
                relationship TEXT NOT NULL, object_id TEXT NOT NULL, evidence TEXT NOT NULL,
                recorded_at TEXT NOT NULL);
            """)
            row = db.execute("SELECT version FROM identity_schema LIMIT 1").fetchone()
            if row is None: db.execute("INSERT INTO identity_schema VALUES (?)", (self.VERSION,))
            elif row[0] != self.VERSION: raise RabError("unsupported identity catalogue schema")

    def rebuild(self) -> dict:
        if self.read_only: raise PolicyError("read-only identity catalogue cannot rebuild")
        self.initialize(); self.relationships_root.mkdir(parents=True, exist_ok=True); self.logical_root.mkdir(parents=True, exist_ok=True)
        with self.db() as db:
            db.execute("DELETE FROM identity_objects"); db.execute("DELETE FROM identity_logical"); db.execute("DELETE FROM identity_relationships")
            for path in sorted(self.archive.objects.glob("sha256/*/*/*/manifest.json")):
                manifest = json.loads(path.read_text(encoding="utf-8")); sha = manifest["object_id"].removeprefix("sha256:")
                master = self.archive.object_dir(sha) / "master"
                hashes = hash_file(master)
                if hashes["sha256"] != sha: raise RabError("identity rebuild found preservation fixity failure")
                names = [x.get("source_path", "") for x in self._occurrences(sha)]
                identification = identify_format(master.open("rb").read(1024 * 1024), name=names[0] if names else manifest.get("title", ""), media_type=manifest.get("media_type", ""))
                profile = FORMAT_PROFILES.get(identification.format_id, {})
                provenance = self._occurrences(sha); authorities = Authority(self.archive).assertions("sha256:" + sha, read_only=True) if (self.archive.root / "authority.sqlite3").is_file() else []
                malware = MalwareStore(self.archive, read_only=True).status("sha256:" + sha)
                rights = sorted({x.get("rights", Rights.UNKNOWN.value) for x in provenance}) or [Rights.UNKNOWN.value]
                db.execute("INSERT INTO identity_objects VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (sha, hashes["size"], hashes["crc32"], hashes["md5"], hashes["sha1"], hashes["blake3"], identification.format_id, identification.method, identification.confidence, profile.get("family"), profile.get("platform"), manifest.get("media_type"), manifest.get("title"), json.dumps(rights, sort_keys=True), json.dumps(provenance, sort_keys=True), json.dumps(authorities, sort_keys=True), json.dumps(malware, sort_keys=True), manifest["created_at"]))
            self._load_sidecars(db)
        return self.status()

    def _occurrences(self, sha: str) -> list[dict]:
        return [json.loads(path.read_text(encoding="utf-8")) for path in sorted((self.archive.object_dir(sha) / "occurrences").glob("*.json"))]

    def _load_sidecars(self, db):
        for path in sorted(self.logical_root.glob("*.json")):
            value = json.loads(path.read_text(encoding="utf-8")); db.execute("INSERT INTO identity_logical VALUES (?,?,?,?,?,?)", (value["identity_id"], value["level"], value["name"], value.get("version"), value.get("platform"), json.dumps(value.get("metadata", {}), sort_keys=True)))
        for path in sorted(self.relationships_root.glob("*.json")):
            value = json.loads(path.read_text(encoding="utf-8")); db.execute("INSERT INTO identity_relationships VALUES (?,?,?,?,?,?)", (value["relationship_id"], value["subject_id"], value["relationship"], value["object_id"], json.dumps(value.get("evidence", {}), sort_keys=True), value["recorded_at"]))

    def show(self, identifier: str) -> dict:
        self.initialize(); sha = self.archive.resolve(identifier)
        with self.db() as db:
            row = db.execute("SELECT * FROM identity_objects WHERE sha256=?", (sha,)).fetchone()
            if not row: raise RabError("identity record not found")
            value = dict(row); value["object_id"] = "sha256:" + sha
            for key in ("rights", "provenance", "authorities", "malware"): value[key] = json.loads(value[key])
            value["relationships"] = [dict(x) for x in db.execute("SELECT * FROM identity_relationships WHERE subject_id=? OR object_id=? ORDER BY relationship_id", (sha, sha))]
            return value

    def search(self, *, platform: str | None = None, format_id: str | None = None, authority: str | None = None, hash_algorithm: str | None = None) -> list[dict]:
        self.initialize(); where=[]; params=[]
        if platform: where.append("(platform=? OR platform_family=?)"); params.extend([platform, platform])
        if format_id: where.append("format_id=?"); params.append(format_id)
        with self.db() as db: rows = [dict(x) for x in db.execute("SELECT * FROM identity_objects" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY sha256", params).fetchall()]
        if authority: rows = [x for x in rows if any((a.get("authority") or a.get("authority_id")) == authority.upper() for a in json.loads(x["authorities"]))]
        if hash_algorithm and hash_algorithm not in {"crc32", "md5", "sha1", "sha256", "blake3"}: raise RabError("unsupported hash algorithm")
        return rows

    def status(self) -> dict:
        self.initialize()
        with self.db() as db:
            return {"schema": self.VERSION, "objects": db.execute("SELECT count(*) FROM identity_objects").fetchone()[0], "relationships": db.execute("SELECT count(*) FROM identity_relationships").fetchone()[0], "logical_identities": db.execute("SELECT count(*) FROM identity_logical").fetchone()[0]}

    def hashes(self, identifier: str) -> dict:
        value = self.show(identifier); return {key: value[key] for key in ("object_id", "size", "crc32", "md5", "sha1", "sha256", "blake3")}

    def define_logical(self, level: IdentityLevel | str, name: str, *, version: str | None = None, platform: str | None = None, identity_id: str | None = None, metadata: dict | None = None) -> dict:
        if self.read_only: raise PolicyError("read-only identity catalogue cannot define logical identity")
        level = IdentityLevel(level); identity_id = identity_id or "identity:" + uuid.uuid4().hex
        value = {"schema": "rab-logical-identity-v1", "identity_id": identity_id, "level": level.value, "name": name, "version": version, "platform": platform, "metadata": metadata or {}}
        self.logical_root.mkdir(parents=True, exist_ok=True); target = self.logical_root / (identity_id.replace(":", "-") + ".json")
        if target.exists() and json.loads(target.read_text(encoding="utf-8")) != value: raise PolicyError("logical identity is immutable")
        self.archive._atomic_json(target, value); self.rebuild(); return value

    def add_relationship(self, subject_id: str, relationship: RelationshipType | str, object_id: str, evidence: dict) -> dict:
        if self.read_only: raise PolicyError("read-only identity catalogue cannot add relationship")
        relationship = RelationshipType(relationship); subject_id = subject_id.removeprefix("sha256:"); object_id = object_id.removeprefix("sha256:")
        if subject_id == object_id and relationship != RelationshipType.EXACT_COPY_OF: raise PolicyError("self relationship is not valid")
        if relationship in {RelationshipType.DERIVED_FROM, RelationshipType.REPRESENTATION_OF, RelationshipType.RELEASE_OF_WORK}:
            graph = {}
            for path in self.relationships_root.glob("*.json") if self.relationships_root.is_dir() else []:
                old = json.loads(path.read_text(encoding="utf-8")); graph.setdefault(old["subject_id"], set()).add(old["object_id"])
            graph.setdefault(subject_id, set()).add(object_id)
            pending = [object_id]; seen = set()
            while pending:
                node = pending.pop()
                if node == subject_id: raise PolicyError("identity relationship cycle")
                if node in seen: continue
                seen.add(node); pending.extend(graph.get(node, ()))
        relationship_id = hashlib.sha256(f"{subject_id}\0{relationship.value}\0{object_id}\0{json.dumps(evidence, sort_keys=True)}".encode()).hexdigest()
        value = {"schema": "rab-identity-relationship-v1", "relationship_id": relationship_id, "subject_id": subject_id, "relationship": relationship.value, "object_id": object_id, "evidence": evidence, "recorded_at": _now()}
        self.relationships_root.mkdir(parents=True, exist_ok=True); target = self.relationships_root / (relationship_id + ".json")
        if target.exists() and json.loads(target.read_text(encoding="utf-8")) != value: raise PolicyError("identity relationship is immutable")
        self.archive._atomic_json(target, value); self.rebuild(); return value

    def relationships(self, identifier: str) -> list[dict]:
        return self.show(identifier)["relationships"]
