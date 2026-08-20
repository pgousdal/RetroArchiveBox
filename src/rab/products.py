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
        if product not in {"identity", "fixity", "authority-crosswalk", "containment", "physical-media", "capture-status", "set-completeness", "provenance-inventory"}:
            raise RabError("unknown derived product")
        if product in {"physical-media", "capture-status", "set-completeness", "provenance-inventory"}:
            from .physical_registry import PhysicalMediaRegistry
            registry = PhysicalMediaRegistry(self.archive); physical = registry.list(); records = []
            for item in physical:
                captures = registry.captures(item["physical_medium_id"]); public = registry.public(item)
                records.append({"physical_medium_id": item["physical_medium_id"], "media_class": item["media_class"], "provenance": item["provenance"], "rights": item["rights"], "metadata": public.get("metadata", {}), "set": item.get("set", {}), "capture_count": len(captures), "representation_ids": sorted({x["object_id"] for x in captures if x.get("object_id")}), "partial_capture_count": sum(x.get("state") in {"PARTIAL", "COMPLETED_WITH_WARNINGS", "COMPLETE_WITH_WARNINGS"} for x in captures), "disagreeing_capture_count": sum(bool(x.get("repeat_comparison", {}).get("differing_capture_preserved")) for x in captures), "observation_count": len(registry.observations(item["physical_medium_id"]))})
            if product == "capture-status": records = [{key: value for key, value in x.items() if key not in {"metadata"}} for x in records]
            elif product == "set-completeness": records = [{"physical_set_id": x["physical_set_id"], "title": x["title"], "edition": x.get("edition"), **x["completeness"]} for x in registry.sets()]
            elif product == "provenance-inventory": records = [{"physical_medium_id": x["physical_medium_id"], "media_class": x["media_class"], "provenance": x["provenance"], "rights": x["rights"], "title": registry.public(next(y for y in physical if y["physical_medium_id"] == x["physical_medium_id"])).get("metadata", {}).get("title")} for x in records]
            rows = []
        else:
            rows = self.identity.search(platform=platform, format_id=format_id, authority=authority, hash_algorithm=hash_algorithm)
        if product in {"physical-media", "capture-status", "set-completeness", "provenance-inventory"}:
            pass
        elif product == "identity":
            records = [self._identity_row(x) | {"relationships": self.identity.relationships("sha256:" + x["sha256"])} for x in rows]
        elif product == "fixity": records = [{"object_id": "sha256:" + x["sha256"], "size": x["size"], "crc32": x["crc32"], "md5": x["md5"], "sha1": x["sha1"], "sha256": x["sha256"], "blake3": x["blake3"]} for x in rows]
        elif product == "containment": records = [{"object_id": "sha256:" + x["sha256"], "relationships": [r for r in self.identity.relationships("sha256:" + x["sha256"]) if r.get("relationship") == "CONTAINS" or r.get("object_id") == x["sha256"]]} for x in rows if any(r.get("relationship") == "CONTAINS" for r in self.identity.relationships("sha256:" + x["sha256"]))]
        else: records = [{"object_id": "sha256:" + x["sha256"], "authorities": json.loads(x["authorities"])} for x in rows if json.loads(x["authorities"])]
        records = sorted(records, key=lambda x: (x.get("object_id", ""), x.get("physical_medium_id", ""), x.get("physical_set_id", "")))
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
