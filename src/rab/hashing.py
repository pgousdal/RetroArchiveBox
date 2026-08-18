from __future__ import annotations

import hashlib
import zlib
from pathlib import Path

from blake3 import blake3


def hash_file(path: Path) -> dict[str, str | int]:
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5(usedforsecurity=False)
    b3 = blake3()
    crc = 0
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
            b3.update(chunk)
            crc = zlib.crc32(chunk, crc)
    return {
        "sha256": sha256.hexdigest(),
        "blake3": b3.hexdigest(),
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest(),
        "crc32": f"{crc & 0xffffffff:08x}",
        "size": size,
    }

