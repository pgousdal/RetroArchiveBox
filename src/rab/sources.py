from __future__ import annotations

import json
from dataclasses import dataclass, field
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
    allow_redirects: bool
    staging_limit_bytes: int | None
    minimum_free_space_bytes: int
    torrent_client: str | None
    companion_rules: dict
    metadata_rules: dict
    endpoints: tuple[dict, ...] = ()
    transport_policy: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, value: dict) -> "SourceDefinition":
        required = {"id", "name", "class", "backend", "bulk_acquisition", "rights_default"}
        allowed = required | {"location", "enabled", "mirror_authorized", "platforms", "notes",
                              "schedule", "concurrency", "rate_limit_bytes_per_second",
                              "timeout_seconds", "retries", "allow_redirects", "staging_limit_bytes",
                               "minimum_free_space_bytes", "torrent_client", "companion_rules",
                               "metadata_rules", "endpoints", "transport_policy"}
        missing = sorted(required - value.keys())
        if missing:
            raise RabError(f"source definition missing: {', '.join(missing)}")
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise RabError(f"source definition has unknown fields: {', '.join(unknown)}")
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
        allow_redirects = value.get("allow_redirects", False)
        staging_limit = value.get("staging_limit_bytes")
        minimum_free = value.get("minimum_free_space_bytes", 64 * 1024 * 1024)
        if not isinstance(allow_redirects, bool):
            raise RabError("allow_redirects must be boolean")
        if staging_limit is not None and (not isinstance(staging_limit, int) or staging_limit <= 0):
            raise RabError("staging_limit_bytes must be a positive integer")
        if not isinstance(minimum_free, int) or minimum_free < 0:
            raise RabError("minimum_free_space_bytes must be non-negative")
        location = value.get("location")
        if location and backend in {Backend.HTTP, Backend.HTTPS, Backend.RSYNC}:
            scheme = urlparse(location).scheme
            expected = {Backend.HTTP: "http", Backend.HTTPS: "https", Backend.RSYNC: "rsync"}[backend]
            if scheme != expected:
                raise RabError(f"{backend.value} source requires {expected} location")
        endpoints = value.get("endpoints")
        if endpoints is None:
            endpoints = ([{"transport": backend.value, "endpoint": location, "enabled": True}]
                         if location else [])
        if not isinstance(endpoints, list) or (not endpoints and backend not in {Backend.MANUAL, Backend.PHYSICAL_MEDIA, Backend.BITTORRENT}):
            raise RabError("source endpoints must be a non-empty list")
        normalized_endpoints = []
        for endpoint in endpoints:
            if not isinstance(endpoint, dict) or "transport" not in endpoint or "endpoint" not in endpoint:
                raise RabError("source endpoint requires transport and endpoint")
            try:
                transport = Backend(endpoint["transport"])
            except ValueError as exc:
                raise RabError(f"invalid endpoint transport: {endpoint.get('transport')}") from exc
            address = endpoint["endpoint"]
            if not isinstance(address, str) or not address or any(x in address for x in ("\n", "\r")):
                raise RabError("invalid source endpoint")
            if not isinstance(endpoint.get("enabled", True), bool):
                raise RabError("source endpoint enabled must be boolean")
            if endpoint.get("priority") is not None and (not isinstance(endpoint["priority"], int) or endpoint["priority"] < 0):
                raise RabError("source endpoint priority must be a non-negative integer")
            parsed = urlparse(address)
            if parsed.username or parsed.password:
                raise PolicyError("source endpoint credentials must not be stored in Git")
            if transport in {Backend.HTTP, Backend.HTTPS, Backend.RSYNC, Backend.FTP} and parsed.scheme != transport.value:
                raise RabError(f"{transport.value} endpoint requires {transport.value} URL")
            normalized_endpoints.append({"transport": transport.value, "endpoint": address,
                                         "enabled": endpoint.get("enabled", True),
                                         "priority": endpoint.get("priority"),
                                         "notes": endpoint.get("notes", "")})
        transport_policy = value.get("transport_policy", {})
        if not isinstance(transport_policy, dict):
            raise RabError("transport_policy must be an object")
        for policy_key, policy_value in transport_policy.items():
            if policy_key in {"bootstrap", "synchronization", "preferences", "prohibited", "unavailable", "prohibited_bootstrap", "prohibited_synchronization"}:
                if not isinstance(policy_value, list) or any(not isinstance(x, str) for x in policy_value):
                    raise RabError(f"transport policy {policy_key} must be a list of strings")
        definition = cls(
            source_id, value["name"], source_class, backend, bulk, rights,
            location, value.get("enabled", False), value.get("mirror_authorized", False),
            tuple(value.get("platforms", [])), value.get("notes", ""), value.get("schedule"),
            concurrency, value.get("rate_limit_bytes_per_second"), timeout, retries,
            allow_redirects, staging_limit, minimum_free, value.get("torrent_client"),
            value.get("companion_rules", {}), value.get("metadata_rules", {}),
            tuple(normalized_endpoints), transport_policy,
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
            "allow_redirects": self.allow_redirects,
            "staging_limit_bytes": self.staging_limit_bytes,
            "minimum_free_space_bytes": self.minimum_free_space_bytes,
            "torrent_client": self.torrent_client,
            "companion_rules": self.companion_rules, "metadata_rules": self.metadata_rules,
            "endpoints": [dict(x) for x in self.endpoints], "transport_policy": self.transport_policy,
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
