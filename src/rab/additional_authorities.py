from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path
from xml.etree import ElementTree

from .authority import Authority
from .errors import IntegrityError, RabError
from .model import IngestRequest, Rights
from .store import Archive, now


PURPOSES = {
    "NO_INTRO": "IDENTIFICATION",
    "MAME": "EMULATION_REFERENCE",
}


def _safe_xml(data: bytes, label: str) -> ElementTree.Element:
    if len(data) > 128 * 1024 * 1024 or re.search(rb"<!ENTITY", data[:1024 * 1024], re.I):
        raise RabError(f"unsafe authority XML: {label}")
    try:
        return ElementTree.fromstring(data)
    except (ElementTree.ParseError, ValueError) as exc:
        raise RabError(f"invalid authority XML: {label}") from exc


def _hash(value: str | None, length: int) -> str | None:
    return value.lower() if value and re.fullmatch(rf"[0-9a-fA-F]{{{length}}}", value) else None


class AdditionalAuthority:
    """Component-oriented adapter for No-Intro ROM data and MAME lists."""

    def __init__(self, archive: Archive):
        self.archive = archive
        self.authority = Authority(archive)
        self.observations = archive.root / "authority-metadata" / "observations"

    def initialize(self) -> None:
        self.authority.initialize()
        self.observations.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.authority.db_path) as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS component_records (
              record_id TEXT PRIMARY KEY, dataset_id TEXT NOT NULL REFERENCES datasets(dataset_id),
              authority_id TEXT NOT NULL, entry_id TEXT NOT NULL, canonical_name TEXT NOT NULL,
              system TEXT NOT NULL, component_type TEXT NOT NULL, component_name TEXT NOT NULL,
              size INTEGER, crc32 TEXT, md5 TEXT, sha1 TEXT, metadata TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS component_sha_size ON component_records(sha1,size,authority_id);
            CREATE INDEX IF NOT EXISTS component_md5_size ON component_records(md5,size,authority_id);
            CREATE INDEX IF NOT EXISTS component_crc_size ON component_records(crc32,size,authority_id);
            CREATE INDEX IF NOT EXISTS component_entry ON component_records(dataset_id,entry_id);
            """)

    @staticmethod
    def _dataset_id(authority_id: str, release: str, source_sha: str) -> str:
        return hashlib.sha256(f"{authority_id}\0{release}\0{source_sha}".encode()).hexdigest()

    def import_file(self, path: Path, *, authority_id: str, release: str,
                    source: str, rights: Rights = Rights.UNKNOWN) -> dict:
        authority_id = authority_id.upper()
        if authority_id not in PURPOSES:
            raise RabError(f"unsupported additional authority: {authority_id}")
        self.initialize()
        source_object = self.archive.ingest(IngestRequest(
            path, f"authority:{authority_id.lower()}", source, rights, "application/xml", path.name
        ))["object_id"]
        data = path.read_bytes()
        records = self._parse(data, authority_id, path.name)
        source_sha = source_object.removeprefix("sha256:")
        dataset_id = self._dataset_id(authority_id, release, source_sha)
        metadata = {
            "dataset_id": dataset_id, "authority_id": authority_id,
            "authority_type": "VERIFICATION_AUTHORITY", "authority_adapter": authority_id.lower(),
            "authority_purpose": PURPOSES[authority_id], "release_identity": release,
            "release_version": release, "release_date": None, "source_object": source_object,
            "source_objects": [source_object], "source": source, "source_objects_sources": [source],
            "acquired_at": now(), "parser_version": f"rab-{authority_id.lower()}-1",
            "rights": rights.value, "imported_at": now(), "status": "IMPORTED", "error": None,
            "record_count": len({record["entry_id"] for record in records}), "selected_members": [],
        }
        self.authority._write_metadata(metadata)
        with sqlite3.connect(self.authority.db_path) as db:
            db.execute("INSERT OR REPLACE INTO datasets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (dataset_id, authority_id, "VERIFICATION_AUTHORITY", release, release, None,
                        source_object, source, metadata["acquired_at"], metadata["parser_version"], rights.value,
                        metadata["imported_at"], "IMPORTED", None, metadata["record_count"], "[]"))
            self._insert_records(db, dataset_id, authority_id, records)
        return {"dataset_id": dataset_id, "authority": authority_id,
                "entries": metadata["record_count"], "components": len(records), "source_object": source_object}

    def _parse(self, data: bytes, authority_id: str, label: str) -> list[dict]:
        root = _safe_xml(data, label)
        if authority_id == "MAME":
            return self._parse_mame(root)
        return self._parse_nointro(root)

    @staticmethod
    def _parse_mame(root) -> list[dict]:
        if root.tag != "softwarelist":
            raise RabError("MAME authority XML has no softwarelist root")
        system = root.get("name", "")
        records = []
        for software in root.findall("software"):
            entry_id = software.get("name", "")
            name = software.findtext("description") or entry_id
            entry_metadata = {key: software.findtext(key) for key in ("year", "publisher", "notes")}
            entry_metadata["software_attributes"] = dict(software.attrib)
            for part in software.findall("part"):
                for area in list(part):
                    if area.tag not in {"dataarea", "diskarea", "romarea"}:
                        continue
                    component_type = "DISK" if area.tag == "diskarea" else "ROM"
                    for component in list(area):
                        if component.tag not in {"rom", "disk"}:
                            continue
                        size = None
                        if component.get("size"):
                            try: size = int(component.get("size"))
                            except ValueError: size = None
                        records.append({"entry_id": entry_id, "canonical_name": name, "system": system,
                                        "component_type": component_type, "component_name": component.get("name", ""),
                                        "size": size, "crc32": _hash(component.get("crc"), 8),
                                        "md5": _hash(component.get("md5"), 32), "sha1": _hash(component.get("sha1"), 40),
                                        "metadata": {"part": dict(part.attrib), "area": area.get("name"),
                                                     "interface": part.get("interface"), "entry": entry_metadata,
                                                     "component": dict(component.attrib)}})
        return records

    @staticmethod
    def _parse_nointro(root) -> list[dict]:
        if root.tag not in {"datafile", "datfile"}:
            raise RabError("No-Intro authority XML has no datafile root")
        system = (root.findtext("header/name") or "").strip()
        records = []
        for game in root.findall("game"):
            entry_id = game.get("name", "")
            for rom in game.findall("rom"):
                try: size = int(rom.get("size")) if rom.get("size") else None
                except ValueError: size = None
                records.append({"entry_id": entry_id, "canonical_name": entry_id, "system": system,
                                "component_type": "ROM", "component_name": rom.get("name", ""), "size": size,
                                "crc32": _hash(rom.get("crc"), 8), "md5": _hash(rom.get("md5"), 32),
                                "sha1": _hash(rom.get("sha1"), 40),
                                "metadata": {"status": rom.get("status"), "attributes": dict(rom.attrib)}})
        return records

    @staticmethod
    def _insert_records(db, dataset_id, authority_id, records):
        for record in records:
            record_id = hashlib.sha256(json.dumps({"dataset": dataset_id, **record}, sort_keys=True).encode()).hexdigest()
            db.execute("INSERT OR REPLACE INTO component_records VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (record_id, dataset_id, authority_id, record["entry_id"], record["canonical_name"],
                        record["system"], record["component_type"], record["component_name"], record["size"],
                        record["crc32"], record["md5"], record["sha1"], json.dumps(record["metadata"], sort_keys=True)))

    def records(self, dataset_id: str | None = None, authority_id: str | None = None) -> list[dict]:
        self.initialize()
        with sqlite3.connect(self.authority.db_path) as db:
            db.row_factory = sqlite3.Row
            rows = db.execute("SELECT * FROM component_records WHERE (? IS NULL OR dataset_id=?) AND (? IS NULL OR authority_id=?) ORDER BY record_id",
                              (dataset_id, dataset_id, authority_id, authority_id)).fetchall()
            return [dict(row) for row in rows]

    def match(self, identifier: str, *, authority_id: str | None = None, dataset_id: str | None = None,
              persist: bool = True) -> list[dict]:
        self.initialize(); sha = self.archive.resolve(identifier); obj = self.archive.show(sha)
        with sqlite3.connect(self.authority.db_path) as db:
            db.row_factory = sqlite3.Row
            result = []
            datasets = db.execute("SELECT dataset_id,authority_id FROM datasets WHERE authority_id IN ('NO_INTRO','MAME') AND (? IS NULL OR authority_id=?) AND (? IS NULL OR dataset_id=?)",
                                  (authority_id, authority_id, dataset_id, dataset_id)).fetchall()
            for dataset, aid in datasets:
                if persist:
                    value = {"authority_id": aid, "dataset_id": dataset, "object_sha256": sha}
                    observation_id = hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
                    target = self.observations / f"{observation_id}.json"
                    if not target.exists():
                        target.write_text(json.dumps({"observation_id": observation_id, **value}, sort_keys=True) + "\n", encoding="utf-8")
                        target.chmod(0o444)
                candidates = []
                for field in ("sha1", "md5", "crc32"):
                    value = obj[field]
                    if not value: continue
                    candidates = db.execute(f"SELECT * FROM component_records WHERE dataset_id=? AND {field}=? AND (size=? OR size IS NULL)",
                                            (dataset, value, obj["size"])).fetchall()
                    if candidates: break
                if len(candidates) == 1:
                    outcome, record = "EXACT_MATCH", candidates[0]
                elif len(candidates) > 1:
                    outcome, record = "AMBIGUOUS", None
                else:
                    outcome, record = "NO_MATCH", None
                result.append(self._assertion(db, dataset, aid, sha, outcome, record, "component-hash"))
            return result

    def _assertion(self, db, dataset, authority_id, sha, outcome, record, method):
        imported = db.execute("SELECT imported_at FROM datasets WHERE dataset_id=?", (dataset,)).fetchone()[0]
        value = {"dataset_id": dataset, "authority": authority_id, "authority_purpose": PURPOSES[authority_id],
                 "object_sha256": sha, "record_id": record["record_id"] if record else None,
                 "result": outcome, "match_method": method,
                 "canonical_name": record["canonical_name"] if record else None,
                 "metadata": json.loads(record["metadata"]) if record else {},
                 "evidence": {"component_type": record["component_type"] if record else None,
                              "component_name": record["component_name"] if record else None,
                              "component_only": True, "record": dict(record) if record else None},
                 "created_at": imported}
        assertion_id = hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()
        value["assertion_id"] = assertion_id
        db.execute("INSERT OR REPLACE INTO assertions VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                   (assertion_id, dataset, sha, value["record_id"], outcome, method, "{}", value["canonical_name"],
                    json.dumps(value["metadata"], sort_keys=True), json.dumps(value["evidence"], sort_keys=True), imported))
        return value

    def rebuild_into_existing(self) -> None:
        self.initialize()
        with sqlite3.connect(self.authority.db_path) as db:
            db.execute("DELETE FROM component_records")
            db.execute("DELETE FROM assertions WHERE dataset_id IN (SELECT dataset_id FROM datasets WHERE authority_id IN ('NO_INTRO','MAME'))")
        for path in sorted(self.authority.metadata.glob("*.json")):
            metadata = json.loads(path.read_text(encoding="utf-8"))
            if metadata.get("authority_id") not in PURPOSES:
                continue
            source = metadata["source_object"].removeprefix("sha256:")
            master = self.archive.object_dir(source) / "master"
            records = self._parse(master.read_bytes(), metadata["authority_id"], master.name)
            with sqlite3.connect(self.authority.db_path) as db:
                self._insert_records(db, metadata["dataset_id"], metadata["authority_id"], records)
        for path in sorted(self.observations.glob("*.json")):
            value = json.loads(path.read_text(encoding="utf-8"))
            if value.get("authority_id") in PURPOSES:
                self.match(value["object_sha256"], authority_id=value["authority_id"],
                           dataset_id=value["dataset_id"], persist=False)

    def verify(self) -> dict:
        self.initialize(); failures = []
        with self.archive.db() as archive_db:
            object_ids = {row[0] for row in archive_db.execute("SELECT sha256 FROM objects")}
        for path in sorted(self.observations.glob("*.json")):
            value = json.loads(path.read_text(encoding="utf-8"))
            if value.get("authority_id") in PURPOSES and value.get("object_sha256") not in object_ids:
                failures.append({"type": "component_observation_object_missing", "observation": path.name})
        with sqlite3.connect(self.authority.db_path) as db:
            for row in db.execute("SELECT record_id,dataset_id,size,crc32,md5,sha1 FROM component_records"):
                if db.execute("SELECT 1 FROM datasets WHERE dataset_id=?", (row[1],)).fetchone() is None:
                    failures.append({"type": "component_dataset_missing", "record_id": row[0]})
                if row[2] is not None and row[2] < 0 or (row[3] and not _hash(row[3], 8)) or (row[4] and not _hash(row[4], 32)) or (row[5] and not _hash(row[5], 40)):
                    failures.append({"type": "component_hash_invalid", "record_id": row[0]})
        return {"outcome": "PASS" if not failures else "FAIL", "failures": failures}
