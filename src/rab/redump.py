from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import zipfile
from pathlib import Path
from xml.etree import ElementTree

from .authority import Authority, PARSER_VERSION
from .errors import IntegrityError, RabError
from .model import IngestRequest, Rights
from .optical import OpticalDisc, OpticalSession, OpticalTrack, parse_cue
from .store import Archive, now


REDUMP_PARSER_VERSION = PARSER_VERSION.replace("tosec", "redump")


def _safe_xml(data: bytes, member: str) -> ElementTree.Element:
    if len(data) > 128 * 1024 * 1024 or re.search(rb"<!ENTITY", data[:1024 * 1024], re.I):
        raise RabError(f"unsafe Redump XML: {member}")
    try:
        return ElementTree.fromstring(data)
    except (ElementTree.ParseError, ValueError) as exc:
        raise RabError(f"invalid Redump XML: {member}") from exc


def _hash(value: str | None, length: int) -> str | None:
    return value.lower() if value and re.fullmatch(rf"[0-9a-fA-F]{{{length}}}", value) else None


def _dat_bytes(path: Path) -> tuple[str, bytes]:
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            members = [x for x in archive.infolist() if x.filename.lower().endswith((".dat", ".xml"))]
            if len(members) != 1:
                raise RabError("Redump DAT archive must contain exactly one DAT/XML member")
            return members[0].filename, archive.read(members[0])
    return path.name, path.read_bytes()


def _cue_members(path: Path) -> dict[str, bytes]:
    if not zipfile.is_zipfile(path):
        return {path.name: path.read_bytes()}
    with zipfile.ZipFile(path) as archive:
        return {x.filename: archive.read(x) for x in archive.infolist()
                if not x.is_dir() and x.filename.lower().endswith(".cue")}


def _layout_signature(tracks: tuple[OpticalTrack, ...]) -> str:
    return json.dumps([
        (track.session, track.number, track.track_type, track.mode, track.sector_size,
         track.sector_count, track.start_lba, track.pregap, track.postgap)
        for track in tracks
    ], separators=(",", ":"))


def _hash_signature(tracks: tuple[OpticalTrack, ...]) -> str:
    return json.dumps([(track.sha1 if hasattr(track, "sha1") else track.hashes.get("sha1"),
                        track.hashes.get("size")) for track in tracks], separators=(",", ":"))


class RedumpAuthority:
    """Redump adapter: DAT metadata and official CUE layout are distinct source evidence."""

    def __init__(self, archive: Archive):
        self.archive = archive
        self.authority = Authority(archive)
        self.observations = archive.root / "authority-metadata" / "observations"

    def initialize(self) -> None:
        self.authority.initialize()
        self.observations.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.authority.db_path) as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS redump_discs (
              disc_id TEXT PRIMARY KEY, dataset_id TEXT NOT NULL REFERENCES datasets(dataset_id),
              canonical_title TEXT NOT NULL, system TEXT NOT NULL, category TEXT,
              cue_member TEXT, metadata TEXT NOT NULL, record_index INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS redump_files (
              disc_id TEXT NOT NULL REFERENCES redump_discs(disc_id), name TEXT NOT NULL,
              size INTEGER NOT NULL, crc32 TEXT, md5 TEXT, sha1 TEXT, metadata TEXT NOT NULL,
              PRIMARY KEY(disc_id, name)
            );
            CREATE TABLE IF NOT EXISTS redump_tracks (
              disc_id TEXT NOT NULL REFERENCES redump_discs(disc_id), track_number INTEGER NOT NULL,
              session_number INTEGER NOT NULL, track_type TEXT NOT NULL, mode TEXT NOT NULL,
              sector_size INTEGER NOT NULL, sector_count INTEGER, start_lba INTEGER,
              pregap INTEGER, postgap INTEGER, indexes TEXT NOT NULL, file_name TEXT NOT NULL,
              size INTEGER, crc32 TEXT, md5 TEXT, sha1 TEXT, metadata TEXT NOT NULL,
              PRIMARY KEY(disc_id, track_number)
            );
            CREATE TABLE IF NOT EXISTS redump_signatures (
              disc_id TEXT PRIMARY KEY REFERENCES redump_discs(disc_id), track_count INTEGER NOT NULL,
              layout_signature TEXT NOT NULL, hash_signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS redump_signature_lookup ON redump_signatures(track_count, layout_signature);
            CREATE INDEX IF NOT EXISTS redump_track_hash_lookup ON redump_tracks(sha1, size, disc_id);
            """)

    @staticmethod
    def _dataset_id(release: str, dat_sha: str) -> str:
        return hashlib.sha256(f"REDUMP\0{release}\0{dat_sha}".encode()).hexdigest()

    def import_dataset(self, dat_path: Path, cues_path: Path, *, release: str,
                       dat_source: str, cues_source: str, rights: Rights = Rights.UNKNOWN) -> dict:
        self.initialize()
        dat_object = self.archive.ingest(IngestRequest(
            dat_path, "authority:redump", dat_source, rights, "application/zip", dat_path.name))["object_id"]
        cue_object = self.archive.ingest(IngestRequest(
            cues_path, "authority:redump", cues_source, rights, "application/zip", cues_path.name))["object_id"]
        dat_sha = dat_object.removeprefix("sha256:")
        member, data = _dat_bytes(dat_path)
        root = _safe_xml(data, member)
        header = root.find("header")
        if header is None or not header.findtext("name"):
            raise RabError("Redump DAT has no usable header")
        release_identity = release
        cues = _cue_members(cues_path)
        dataset_id = self._dataset_id(release_identity, dat_sha)
        metadata = {
            "dataset_id": dataset_id, "authority_id": "REDUMP", "authority_type": "VERIFICATION_AUTHORITY",
            "authority_adapter": "redump", "release_identity": release_identity,
            "release_version": header.findtext("version"), "release_date": header.findtext("date"),
            "source_object": dat_object, "source_objects": [dat_object, cue_object],
            "source": dat_source, "source_objects_sources": [dat_source, cues_source],
            "acquired_at": now(), "parser_version": REDUMP_PARSER_VERSION,
            "rights": rights.value, "imported_at": now(), "status": "IMPORTED", "error": None,
            "record_count": len(root.findall("game")), "selected_members": [],
        }
        self.authority._write_metadata(metadata)
        with sqlite3.connect(self.authority.db_path) as db:
            db.execute("INSERT OR REPLACE INTO datasets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (dataset_id, "REDUMP", "VERIFICATION_AUTHORITY", release_identity,
                        metadata["release_version"], metadata["release_date"], dat_object, dat_source,
                        metadata["acquired_at"], REDUMP_PARSER_VERSION, rights.value, metadata["imported_at"],
                        "IMPORTED", None, metadata["record_count"], "[]"))
            self._insert_discs(db, dataset_id, root, cues)
            db.execute("INSERT OR IGNORE INTO platform_mappings VALUES (?,?,?,?)",
                       (dataset_id, header.findtext("name"), "amiga", "redump-header-system;rab-platform-v1"))
        self.match_all(dataset_id)
        return {"dataset_id": dataset_id, "source_objects": [dat_object, cue_object],
                "discs": metadata["record_count"], "tracks": self.track_count(dataset_id)}

    def _insert_discs(self, db, dataset_id: str, root, cues: dict[str, bytes]) -> None:
        for index, game in enumerate(root.findall("game")):
            title = game.get("name") or game.findtext("description") or ""
            category = game.findtext("category")
            cue_name = f"{title}.cue"
            cue_data = cues.get(cue_name)
            file_records = {}
            for rom in game.findall("rom"):
                attrs = dict(rom.attrib)
                name = attrs.pop("name", "")
                try:
                    size = int(attrs.pop("size", "-1"))
                except ValueError:
                    size = -1
                file_records[name] = {"size": size, "crc32": _hash(attrs.pop("crc", None), 8),
                                      "md5": _hash(attrs.pop("md5", None), 32), "sha1": _hash(attrs.pop("sha1", None), 40),
                                      "metadata": attrs}
            disc_id = hashlib.sha256(f"{dataset_id}\0{index}\0{title}".encode()).hexdigest()
            disc = parse_cue(cue_data, member=cue_name, file_hashes=file_records) if cue_data else None
            db.execute("INSERT OR REPLACE INTO redump_discs VALUES (?,?,?,?,?,?,?,?)",
                       (disc_id, dataset_id, title, "Commodore Amiga CD", category, cue_name if disc else None,
                        json.dumps({"description": game.findtext("description"), "raw_attributes": dict(game.attrib)}, sort_keys=True), index))
            for name, record in file_records.items():
                db.execute("INSERT OR REPLACE INTO redump_files VALUES (?,?,?,?,?,?,?)",
                           (disc_id, name, record["size"], record["crc32"], record["md5"], record["sha1"],
                            json.dumps(record["metadata"], sort_keys=True)))
            tracks = disc.tracks if disc else ()
            for track in tracks:
                record = file_records.get(track.file_name, {})
                db.execute("INSERT OR REPLACE INTO redump_tracks VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                           (disc_id, track.number, track.session, track.track_type, track.mode, track.sector_size,
                            track.sector_count, track.start_lba, track.pregap, track.postgap,
                            json.dumps(track.indexes, sort_keys=True), track.file_name, record.get("size"),
                            record.get("crc32"), record.get("md5"), record.get("sha1"),
                            json.dumps(record.get("metadata", {}), sort_keys=True)))
            track_values = tuple(track for session in disc.sessions for track in session.tracks) if disc else ()
            db.execute("INSERT OR REPLACE INTO redump_signatures VALUES (?,?,?,?)",
                       (disc_id, len(track_values), _layout_signature(track_values), _hash_signature(track_values)))

    def track_count(self, dataset_id: str | None = None) -> int:
        self.initialize()
        with sqlite3.connect(self.authority.db_path) as db:
            return db.execute("SELECT count(*) FROM redump_tracks t JOIN redump_discs d ON d.disc_id=t.disc_id WHERE ? IS NULL OR d.dataset_id=?",
                              (dataset_id, dataset_id)).fetchone()[0]

    def status(self) -> dict:
        self.initialize()
        with sqlite3.connect(self.authority.db_path) as db:
            return {"discs": db.execute("SELECT count(*) FROM redump_discs").fetchone()[0],
                    "tracks": db.execute("SELECT count(*) FROM redump_tracks").fetchone()[0]}

    def list_discs(self, dataset_id: str | None = None) -> list[dict]:
        self.initialize()
        with sqlite3.connect(self.authority.db_path) as db:
            db.row_factory = sqlite3.Row
            rows = db.execute("SELECT * FROM redump_discs WHERE ? IS NULL OR dataset_id=? ORDER BY record_index", (dataset_id, dataset_id)).fetchall()
            return [dict(row) for row in rows]

    def show_disc(self, disc_id: str) -> dict:
        self.initialize()
        with sqlite3.connect(self.authority.db_path) as db:
            db.row_factory = sqlite3.Row
            disc = db.execute("SELECT * FROM redump_discs WHERE disc_id=?", (disc_id,)).fetchone()
            if disc is None:
                raise RabError(f"Redump disc not found: {disc_id}")
            result = dict(disc)
            result["metadata"] = json.loads(result["metadata"])
            result["files"] = [dict(row) for row in db.execute("SELECT * FROM redump_files WHERE disc_id=? ORDER BY name", (disc_id,))]
            result["tracks"] = [dict(row) for row in db.execute("SELECT * FROM redump_tracks WHERE disc_id=? ORDER BY track_number", (disc_id,))]
            return result

    def compare(self, observed: OpticalDisc, dataset_id: str | None = None) -> dict:
        self.initialize(); observed_tracks = observed.tracks
        layout = _layout_signature(observed_tracks)
        track_evidence = [{"track_number": track.number, "session": track.session,
                           "type": track.track_type, "mode": track.mode, "size": track.hashes.get("size"),
                           "sha1": track.hashes.get("sha1"), "md5": track.hashes.get("md5"),
                           "crc32": track.hashes.get("crc32")} for track in observed_tracks]
        with sqlite3.connect(self.authority.db_path) as db:
            db.row_factory = sqlite3.Row
            candidates = db.execute("SELECT d.* FROM redump_signatures s JOIN redump_discs d ON d.disc_id=s.disc_id WHERE s.track_count=? AND s.layout_signature=? AND (? IS NULL OR d.dataset_id=?)",
                                    (len(observed_tracks), layout, dataset_id, dataset_id)).fetchall()
            if not candidates:
                same_count = db.execute("SELECT count(*) FROM redump_signatures s JOIN redump_discs d ON d.disc_id=s.disc_id WHERE s.track_count=? AND (? IS NULL OR d.dataset_id=?)",
                                        (len(observed_tracks), dataset_id, dataset_id)).fetchone()[0]
                return {"result": "CONFLICT" if same_count else "NOT_APPLICABLE",
                        "evidence": {"observed_track_count": len(observed_tracks), "layout": layout,
                                     "tracks": track_evidence}}
            matches = []
            conflicts = []
            for candidate in candidates:
                tracks = [dict(row) for row in db.execute("SELECT * FROM redump_tracks WHERE disc_id=? ORDER BY track_number", (candidate["disc_id"],))]
                if self._tracks_match(observed_tracks, tracks):
                    matches.append(candidate)
                else:
                    conflicts.append(candidate["disc_id"])
            if len(matches) == 1:
                result = "EXACT_MATCH"
            elif len(matches) > 1:
                result = "AMBIGUOUS"
            else:
                result = "CONFLICT" if conflicts else "NO_MATCH"
            return {"result": result, "disc_id": matches[0]["disc_id"] if len(matches) == 1 else None,
                    "evidence": {"observed_track_count": len(observed_tracks), "layout": layout,
                                 "candidate_count": len(candidates), "conflicts": conflicts,
                                 "tracks": track_evidence}}

    @staticmethod
    def _observation_value(object_sha256: str, dataset_id: str, observed: OpticalDisc) -> dict:
        return {"object_sha256": object_sha256, "dataset_id": dataset_id, "title": observed.title,
                "system": observed.system, "category": observed.category, "metadata": observed.metadata,
                "sessions": [{"number": session.number, "tracks": [{
                    "number": track.number, "session": track.session, "track_type": track.track_type,
                    "mode": track.mode, "sector_size": track.sector_size, "sector_count": track.sector_count,
                    "start_lba": track.start_lba, "pregap": track.pregap, "postgap": track.postgap,
                    "indexes": track.indexes, "file_name": track.file_name, "hashes": track.hashes,
                } for track in session.tracks]} for session in observed.sessions]}

    def _write_observation(self, value: dict) -> None:
        observation_id = hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
        value = {"observation_id": observation_id, **value}
        target = self.observations / f"{observation_id}.json"
        encoded = json.dumps(value, indent=2, sort_keys=True) + "\n"
        if target.exists() and target.read_text(encoding="utf-8") != encoded:
            raise IntegrityError("optical observation identity conflict")
        if not target.exists():
            target.write_text(encoded, encoding="utf-8")
            target.chmod(0o444)

    @staticmethod
    def _observation_from_value(value: dict) -> OpticalDisc:
        sessions = []
        for session in value["sessions"]:
            tracks = [OpticalTrack(**track) for track in session["tracks"]]
            sessions.append(OpticalSession(session["number"], tuple(tracks)))
        return OpticalDisc(value["title"], value["system"], value.get("category"), tuple(sessions), value.get("metadata", {}))

    def match_observation(self, object_id: str, observed: OpticalDisc, dataset_id: str | None = None,
                          *, persist: bool = True) -> dict:
        """Persist a structural assertion for an explicitly observed RAB object."""
        result = self.compare(observed, dataset_id)
        self.initialize()
        with sqlite3.connect(self.authority.db_path) as db:
            chosen_dataset = dataset_id or db.execute(
                "SELECT dataset_id FROM datasets WHERE authority_id='REDUMP' ORDER BY imported_at DESC LIMIT 1"
            ).fetchone()[0]
            object_sha256 = self.archive.resolve(object_id)
            if persist:
                self._write_observation(self._observation_value(object_sha256, chosen_dataset, observed))
            imported_at = db.execute("SELECT imported_at FROM datasets WHERE dataset_id=?", (chosen_dataset,)).fetchone()[0]
            value = {"dataset_id": chosen_dataset, "object_sha256": object_sha256,
                     "record_id": result.get("disc_id"), "result": result["result"],
                     "match_method": "optical-structure", "matched_hashes": {},
                     "canonical_name": None, "metadata": {}, "evidence": result["evidence"],
                     "created_at": imported_at}
            if value["record_id"]:
                value["canonical_name"] = db.execute(
                    "SELECT canonical_title FROM redump_discs WHERE disc_id=?", (value["record_id"],)
                ).fetchone()[0]
            assertion_id = hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
            value["assertion_id"] = assertion_id
            db.execute("INSERT OR REPLACE INTO assertions VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                       (assertion_id, chosen_dataset, value["object_sha256"], value["record_id"], value["result"],
                        value["match_method"], "{}", value["canonical_name"], "{}",
                        json.dumps(value["evidence"], sort_keys=True), value["created_at"]))
            return value

    @staticmethod
    def _tracks_match(observed: tuple[OpticalTrack, ...], authority_tracks: list[dict]) -> bool:
        if len(observed) != len(authority_tracks):
            return False
        for actual, expected in zip(observed, authority_tracks):
            if (actual.number != expected["track_number"] or actual.session != expected["session_number"] or
                    actual.track_type != expected["track_type"] or actual.mode != expected["mode"] or
                    actual.sector_size != expected["sector_size"] or actual.start_lba != expected["start_lba"]):
                return False
            if actual.sector_count != expected["sector_count"]:
                return False
            expected_hash = expected["sha1"] or expected["md5"] or expected["crc32"]
            if expected_hash and not any(actual.hashes.get(key) == expected[key] for key in ("sha1", "md5", "crc32") if expected[key]):
                return False
        return True

    def rebuild_into_existing(self) -> None:
        """Rebuild Redump tables from preserved DAT/CUE objects after generic DB rebuild."""
        self.initialize()
        with sqlite3.connect(self.authority.db_path) as db:
            datasets = [row for row in db.execute("SELECT dataset_id FROM datasets WHERE authority_id='REDUMP'")]
            for (dataset_id,) in datasets:
                db.execute("DELETE FROM redump_signatures WHERE disc_id IN (SELECT disc_id FROM redump_discs WHERE dataset_id=?)", (dataset_id,))
                db.execute("DELETE FROM redump_tracks WHERE disc_id IN (SELECT disc_id FROM redump_discs WHERE dataset_id=?)", (dataset_id,))
                db.execute("DELETE FROM redump_files WHERE disc_id IN (SELECT disc_id FROM redump_discs WHERE dataset_id=?)", (dataset_id,))
                db.execute("DELETE FROM redump_discs WHERE dataset_id=?", (dataset_id,))
        for path in sorted(self.authority.metadata.glob("*.json")):
            metadata = json.loads(path.read_text(encoding="utf-8"))
            if metadata.get("authority_id") != "REDUMP":
                continue
            sources = metadata["source_objects"]
            dat_master = self.archive.object_dir(sources[0].removeprefix("sha256:")) / "master"
            cue_master = self.archive.object_dir(sources[1].removeprefix("sha256:")) / "master"
            member, data = _dat_bytes(dat_master)
            root = _safe_xml(data, member)
            cues = _cue_members(cue_master)
            with sqlite3.connect(self.authority.db_path) as db:
                self._insert_discs(db, metadata["dataset_id"], root, cues)
                header = root.find("header")
                if header is not None and header.findtext("name"):
                    db.execute("INSERT OR IGNORE INTO platform_mappings VALUES (?,?,?,?)",
                               (metadata["dataset_id"], header.findtext("name"), "amiga",
                                "redump-header-system;rab-platform-v1"))
        for path in sorted(self.observations.glob("*.json")):
            value = json.loads(path.read_text(encoding="utf-8"))
            self.match_observation(value["object_sha256"], self._observation_from_value(value),
                                   value["dataset_id"], persist=False)
        self.match_all()

    def match_all(self, dataset_id: str | None = None) -> None:
        # Redump assertions are only created for explicit optical observations;
        # imported source artifacts themselves are not disc observations.
        return

    def verify(self) -> dict:
        self.initialize(); failures = []
        with self.archive.db() as archive_db:
            object_ids = {row[0] for row in archive_db.execute("SELECT sha256 FROM objects")}
        for path in sorted(self.observations.glob("*.json")):
            value = json.loads(path.read_text(encoding="utf-8"))
            if value.get("object_sha256") not in object_ids:
                failures.append({"type": "observation_object_missing", "observation": path.name})
        with sqlite3.connect(self.authority.db_path) as db:
            for disc_id, dataset_id in db.execute("SELECT disc_id,dataset_id FROM redump_discs"):
                if db.execute("SELECT 1 FROM datasets WHERE dataset_id=? AND authority_id='REDUMP'", (dataset_id,)).fetchone() is None:
                    failures.append({"type": "dangling_disc", "disc_id": disc_id})
                numbers = [row[0] for row in db.execute("SELECT track_number FROM redump_tracks WHERE disc_id=? ORDER BY track_number", (disc_id,))]
                if numbers != list(range(1, len(numbers) + 1)):
                    failures.append({"type": "invalid_track_order", "disc_id": disc_id})
                for row in db.execute("SELECT size,crc32,md5,sha1 FROM redump_tracks WHERE disc_id=?", (disc_id,)):
                    if row[0] is not None and row[0] < 0 or (row[1] and not _hash(row[1], 8)) or (row[2] and not _hash(row[2], 32)) or (row[3] and not _hash(row[3], 40)):
                        failures.append({"type": "invalid_track_hash_or_size", "disc_id": disc_id})
        return {"outcome": "PASS" if not failures else "FAIL", "failures": failures}
