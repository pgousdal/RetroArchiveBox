from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from .errors import PolicyError, RabError
from .model import Backend, Rights, SourceClass


@dataclass(frozen=True)
class SourceDefinition:
    id: str
    name: str
    source_class: SourceClass
    backend: Backend
    bulk_acquisition: str
    rights_default: Rights
    location: str | None
    enabled: bool
    mirror_authorized: bool
    platforms: tuple[str, ...]
    notes: str
    schedule: str | None
    concurrency: int
    rate_limit: int | None
    timeout: int
    retries: int
    companion_rules: dict
    metadata_rules: dict

    @classmethod
    def from_dict(cls, value: dict) -> "SourceDefinition":
        required = {"id", "name", "class", "backend", "bulk_acquisition", "rights_default"}
        missing = sorted(required - value.keys())
        if missing:
            raise RabError(f"source definition missing: {', '.join(missing)}")
        source_id = value["id"]
        if not isinstance(source_id, str) or not source_id or any(
            c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in source_id
        ):
            raise RabError(f"invalid source id: {source_id!r}")
        try:
            source_class = SourceClass(value["class"])
            backend = Backend(value["backend"])
            rights = Rights(value["rights_default"])
        except ValueError as exc:
            raise RabError(f"invalid source enum: {exc}") from exc
        bulk = value["bulk_acquisition"]
        if bulk not in {"allowed", "permission-required", "targeted-only", "prohibited"}:
            raise RabError(f"invalid bulk_acquisition: {bulk}")
        concurrency = value.get("concurrency", 2)
        timeout = value.get("timeout_seconds", 60)
        retries = value.get("retries", 3)
        if not isinstance(concurrency, int) or not 1 <= concurrency <= 16:
            raise RabError("concurrency must be between 1 and 16")
        if not isinstance(timeout, int) or timeout < 1 or not isinstance(retries, int) or retries < 0:
            raise RabError("timeout/retries must be non-negative integers")
        location = value.get("location", value.get("base_url"))
        if location and backend in {Backend.HTTP, Backend.HTTPS, Backend.RSYNC}:
            scheme = urlparse(location).scheme
            expected = {Backend.HTTP: "http", Backend.HTTPS: "https", Backend.RSYNC: "rsync"}[backend]
            if scheme != expected:
                raise RabError(f"{backend.value} source requires {expected} location")
        definition = cls(
            source_id, value["name"], source_class, backend, bulk, rights,
            location, value.get("enabled", False), value.get("mirror_authorized", False),
            tuple(value.get("platforms", [])), value.get("notes", ""), value.get("schedule"),
            concurrency, value.get("rate_limit_bytes_per_second"), timeout, retries,
            value.get("companion_rules", {}), value.get("metadata_rules", {}),
        )
        definition.validate_policy()
        return definition

    def validate_policy(self, *, bulk: bool = False) -> None:
        if self.source_class == SourceClass.COOPERATIVE_MIRROR:
            if self.bulk_acquisition == "allowed" and not self.mirror_authorized:
                raise PolicyError(f"source {self.id}: cooperative mirror requires explicit authorization")
            if bulk and not self.mirror_authorized:
                raise PolicyError(f"source {self.id}: bulk mirror is not authorized")
        if bulk and self.bulk_acquisition != "allowed":
            raise PolicyError(f"source {self.id}: bulk acquisition policy is {self.bulk_acquisition}")
        if bulk and not self.enabled:
            raise PolicyError(f"source {self.id}: source is disabled")

    def public(self) -> dict:
        return {
            "id": self.id, "name": self.name, "class": self.source_class.value,
            "backend": self.backend.value, "bulk_acquisition": self.bulk_acquisition,
            "rights_default": self.rights_default.value, "location": self.location,
            "enabled": self.enabled, "mirror_authorized": self.mirror_authorized,
            "platforms": list(self.platforms), "notes": self.notes, "schedule": self.schedule,
            "concurrency": self.concurrency, "rate_limit_bytes_per_second": self.rate_limit,
            "timeout_seconds": self.timeout, "retries": self.retries,
            "companion_rules": self.companion_rules, "metadata_rules": self.metadata_rules,
        }


class SourceRegistry:
    def __init__(self, directory: Path):
        self.directory = directory

    def load(self) -> dict[str, SourceDefinition]:
        sources: dict[str, SourceDefinition] = {}
        for path in sorted(self.directory.glob("*.json")):
            try:
                source = SourceDefinition.from_dict(json.loads(path.read_text(encoding="utf-8")))
            except (json.JSONDecodeError, OSError) as exc:
                raise RabError(f"invalid source definition {path}: {exc}") from exc
            if source.id in sources:
                raise RabError(f"duplicate source id: {source.id}")
            sources[source.id] = source
        return sources

    def get(self, source_id: str) -> SourceDefinition:
        try:
            return self.load()[source_id]
        except KeyError as exc:
            raise RabError(f"source not found: {source_id}") from exc
