from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

from .errors import RabError


@dataclass(frozen=True)
class OpticalTrack:
    number: int
    session: int
    track_type: str
    mode: str
    sector_size: int
    sector_count: int | None
    start_lba: int | None
    pregap: int | None
    postgap: int | None
    indexes: dict[str, int]
    file_name: str
    hashes: dict[str, str | int | None] = field(default_factory=dict)


@dataclass(frozen=True)
class OpticalSession:
    number: int
    tracks: tuple[OpticalTrack, ...]


@dataclass(frozen=True)
class OpticalDisc:
    title: str
    system: str
    category: str | None
    sessions: tuple[OpticalSession, ...]
    metadata: dict = field(default_factory=dict)

    @property
    def tracks(self) -> tuple[OpticalTrack, ...]:
        return tuple(track for session in self.sessions for track in session.tracks)


def _time(value: str) -> int:
    match = re.fullmatch(r"(\d+):(\d{2}):(\d{2})", value)
    if not match or int(match.group(3)) >= 75:
        raise RabError(f"invalid CUE time: {value}")
    return int(match.group(1)) * 60 * 75 + int(match.group(2)) * 75 + int(match.group(3))


def _sector_size(mode: str) -> int:
    if mode == "AUDIO":
        return 2352
    match = re.fullmatch(r"MODE\d/(\d+)", mode)
    if not match:
        raise RabError(f"unsupported CUE track mode: {mode}")
    return int(match.group(1))


def parse_cue(data: bytes, *, member: str = "<cue>", file_sizes: dict[str, int] | None = None,
              file_hashes: dict[str, dict] | None = None) -> OpticalDisc:
    """Parse the structural subset of CUE needed for authority observations."""
    if len(data) > 16 * 1024 * 1024:
        raise RabError("CUE sheet is too large")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = data.decode("latin-1")
        except UnicodeDecodeError as exc:
            raise RabError(f"invalid CUE encoding: {member}") from exc
    sessions: dict[int, list[OpticalTrack]] = {}
    session_number = 1
    current_file = None
    current: dict | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        upper = line.upper()
        if upper.startswith("REM SESSION"):
            parts = line.split()
            if len(parts) != 3 or not parts[2].isdigit():
                raise RabError(f"invalid CUE session: {member}")
            session_number = int(parts[2])
            if session_number < 1:
                raise RabError(f"invalid CUE session number: {member}")
            sessions.setdefault(session_number, [])
            continue
        if upper.startswith("REM "):
            continue
        parts = shlex.split(line, posix=True)
        command = parts[0].upper()
        if command == "FILE":
            if len(parts) < 2:
                raise RabError(f"CUE FILE has no name: {member}")
            current_file = parts[1]
        elif command == "TRACK":
            if len(parts) != 3 or not parts[1].isdigit():
                raise RabError(f"invalid CUE TRACK: {member}")
            number = int(parts[1]); mode = parts[2].upper()
            if number < 1 or any(t["number"] == number for t in sessions.setdefault(session_number, [])):
                raise RabError(f"duplicate or invalid CUE track number: {member}")
            current = {"number": number, "session": session_number, "track_type": "AUDIO" if mode == "AUDIO" else "DATA",
                       "mode": mode, "sector_size": _sector_size(mode), "indexes": {}, "file_name": current_file}
            sessions[session_number].append(current)  # type: ignore[arg-type]
        elif command in {"INDEX", "PREGAP", "POSTGAP"}:
            if current is None:
                raise RabError(f"CUE {command} precedes TRACK: {member}")
            if command == "INDEX":
                if len(parts) != 3 or not parts[1].isdigit():
                    raise RabError(f"invalid CUE INDEX: {member}")
                current["indexes"][parts[1]] = _time(parts[2])
            else:
                if len(parts) != 2:
                    raise RabError(f"invalid CUE {command}: {member}")
                current[command.lower()] = _time(parts[1])
    if not sessions or any(not tracks for tracks in sessions.values()):
        raise RabError(f"CUE has no tracks: {member}")
    finalized = []
    for number, tracks in sorted(sessions.items()):
        values = []
        for track in tracks:
            if "01" not in track["indexes"]:
                raise RabError(f"CUE track has no INDEX 01: {member}")
            hashes = (file_hashes or {}).get(track["file_name"] or "", {})
            size = hashes.get("size") or (file_sizes or {}).get(track["file_name"] or "")
            count = size // track["sector_size"] if size is not None and size % track["sector_size"] == 0 else None
            values.append(OpticalTrack(
                number=track["number"], session=number, track_type=track["track_type"], mode=track["mode"],
                sector_size=track["sector_size"], sector_count=count, start_lba=track["indexes"]["01"],
                pregap=track.get("pregap"), postgap=track.get("postgap"), indexes=dict(track["indexes"]),
                file_name=track["file_name"] or "", hashes=dict(hashes),
            ))
        finalized.append(OpticalSession(number, tuple(values)))
    return OpticalDisc(title=member.rsplit("/", 1)[-1].removesuffix(".cue"), system="", category=None,
                        sessions=tuple(finalized), metadata={"cue_member": member})
