"""Deterministic metadata-only derived product exports."""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

from .errors import PolicyError, RabError
from .identity import IdentityCatalogue


class ProductBuilder:
    VERSION = 1

    def __init__(self, archive, *, identity: IdentityCatalogue | None = None):
        self.archive = archive; self.identity = identity or IdentityCatalogue(archive)
        self.root = archive.root / "products"

    def list(self) -> list[dict]:
        index = self.root / "index.json"
        return json.loads(index.read_text(encoding="utf-8")) if index.is_file() else []

    def build(self, product: str, *, platform: str | None = None, format_id: str | None = None,
              authority: str | None = None, hash_algorithm: str | None = None) -> dict:
        if product not in {"identity", "fixity", "authority-crosswalk"}:
            raise RabError("unknown derived product")
        rows = self.identity.search(platform=platform, format_id=format_id, authority=authority, hash_algorithm=hash_algorithm)
        if product == "identity":
            records = [self._identity_row(x) | {"relationships": self.identity.relationships("sha256:" + x["sha256"])} for x in rows]
        elif product == "fixity": records = [{"object_id": "sha256:" + x["sha256"], "size": x["size"], "crc32": x["crc32"], "md5": x["md5"], "sha1": x["sha1"], "sha256": x["sha256"], "blake3": x["blake3"]} for x in rows]
        else: records = [{"object_id": "sha256:" + x["sha256"], "authorities": json.loads(x["authorities"])} for x in rows if json.loads(x["authorities"])]
        records = sorted(records, key=lambda x: x.get("object_id", ""))
        filter_key = hashlib.sha256(json.dumps({"platform": platform, "format": format_id, "authority": authority, "hash": hash_algorithm}, sort_keys=True).encode()).hexdigest()[:12]
        directory = self.root / product; directory.mkdir(parents=True, exist_ok=True)
        output = directory / (filter_key + ".jsonl")
        text = "".join(json.dumps(x, sort_keys=True, separators=(",", ":")) + "\n" for x in records)
        temporary = output.with_name("." + output.name + ".tmp"); temporary.write_text(text, encoding="utf-8"); temporary.replace(output); output.chmod(0o444)
        metadata = {"schema": "rab-derived-product-v1", "product": product, "version": self.VERSION,
                    "filters": {"platform": platform, "format": format_id, "authority": authority, "hash_algorithm": hash_algorithm},
                    "record_count": len(records), "content_sha256": hashlib.sha256(text.encode()).hexdigest(),
                    "path_id": output.relative_to(self.root).as_posix()}
        index = self.list(); index = [x for x in index if x.get("path_id") != metadata["path_id"]]; index.append(metadata); index.sort(key=lambda x: x["path_id"])
        self.archive._atomic_json(self.root / "index.json", index)
        return metadata

    @staticmethod
    def _identity_row(row: dict) -> dict:
        return {"object_id": "sha256:" + row["sha256"], "size": row["size"], "hashes": {key: row[key] for key in ("crc32", "md5", "sha1", "sha256", "blake3")},
                "format": row["format_id"], "platform_family": row["platform_family"], "platform": row["platform"], "media_type": row["media_type"], "title": row["title"], "rights": json.loads(row["rights"]), "authorities": json.loads(row["authorities"]), "malware": json.loads(row["malware"]), "relationships": []}

    def read(self, path_id: str) -> str:
        if not path_id or ".." in Path(path_id).parts or Path(path_id).is_absolute(): raise PolicyError("invalid product path")
        path = (self.root / path_id).resolve()
        if not path.is_relative_to(self.root.resolve()) or not path.is_file(): raise RabError("derived product not found")
        return path.read_text(encoding="utf-8")
