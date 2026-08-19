"""Transport capability and acquisition-purpose policy selection."""
from __future__ import annotations

import shutil
from dataclasses import replace
from enum import StrEnum
from urllib.parse import urlparse
from pathlib import Path

from .errors import PolicyError, RabError
from .model import Backend


class AcquisitionPurpose(StrEnum):
    BOOTSTRAP = "bootstrap"
    SYNCHRONIZATION = "synchronization"


class TransportState(StrEnum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    PROHIBITED = "PROHIBITED"
    AMBIGUOUS = "AMBIGUOUS"
    UNSUPPORTED = "UNSUPPORTED"
    POLICY_BLOCKED = "POLICY_BLOCKED"


DEFAULT_PREFERENCES = {
    AcquisitionPurpose.BOOTSTRAP.value: ["bittorrent", "rsync", "https", "http", "ftp"],
    AcquisitionPurpose.SYNCHRONIZATION.value: ["rsync", "https", "http", "ftp", "bittorrent"],
}


class TransportResolver:
    """Explainable selection over one logical source's equivalent endpoints."""

    def __init__(self, *, torrent_client: str | None = None):
        self.torrent_client = torrent_client or "aria2c"

    def capabilities(self) -> list[dict]:
        return [self.capability(x) for x in ("bittorrent", "rsync", "https", "http", "ftp")]

    def capability(self, transport: str) -> dict:
        if transport == "bittorrent":
            executable = shutil.which(self.torrent_client)
            return {"transport": transport, "availability": "AVAILABLE" if executable else "UNAVAILABLE",
                    "executable": executable, "resume": True, "integrity": ["piece-check", "rab-hash"],
                    "metadata": True}
        if transport == "rsync":
            executable = shutil.which("rsync")
            return {"transport": transport, "availability": "AVAILABLE" if executable else "UNAVAILABLE",
                    "executable": executable, "resume": True, "integrity": ["transfer", "rab-hash"],
                    "metadata": True}
        if transport in {"http", "https"}:
            return {"transport": transport, "availability": "AVAILABLE", "resume": True,
                    "integrity": ["content-length", "rab-hash"], "metadata": False}
        if transport == "ftp":
            return {"transport": transport, "availability": "AVAILABLE", "resume": False,
                    "integrity": ["rab-hash"], "metadata": False}
        return {"transport": transport, "availability": "UNSUPPORTED", "resume": False,
                "integrity": [], "metadata": False}

    def plan(self, source, purpose: AcquisitionPurpose | str) -> dict:
        purpose = AcquisitionPurpose(purpose)
        if not source.enabled:
            return {"state": TransportState.POLICY_BLOCKED.value, "purpose": purpose.value, "source": source.id,
                    "selected": None, "candidates": list(source.endpoints),
                    "rejected": [{"reason": "source is disabled", "policy": "explicit enablement required"}],
                    "preferences": DEFAULT_PREFERENCES[purpose.value], "evidence": "source is disabled"}
        configured = source.transport_policy.get(purpose.value, source.transport_policy.get("preferences"))
        preferences = list(configured or DEFAULT_PREFERENCES[purpose.value])
        prohibited = set(source.transport_policy.get("prohibited", [])) | set(source.transport_policy.get(f"prohibited_{purpose.value}", []))
        unavailable = set(source.transport_policy.get("unavailable", []))
        candidates = [x for x in source.endpoints if x.get("enabled", True)]
        rejected = []
        ranked = []
        for endpoint in candidates:
            transport = endpoint["transport"]
            if transport in prohibited:
                rejected.append({"endpoint": endpoint, "reason": "source policy prohibits transport"}); continue
            if transport in unavailable:
                rejected.append({"endpoint": endpoint, "reason": "source declares transport unavailable"}); continue
            capability = self.capability(transport)
            if capability["availability"] != "AVAILABLE":
                rejected.append({"endpoint": endpoint, "reason": "runtime dependency unavailable", "capability": capability}); continue
            if transport not in preferences:
                rejected.append({"endpoint": endpoint, "reason": "transport is not in purpose preference order"}); continue
            ranked.append((preferences.index(transport), endpoint.get("priority") if endpoint.get("priority") is not None else 999999, endpoint, capability))
        ranked.sort(key=lambda x: (x[0], x[1], x[2]["endpoint"]))
        if not ranked:
            state = TransportState.UNAVAILABLE if rejected else TransportState.UNSUPPORTED
            return {"state": state.value, "purpose": purpose.value, "source": source.id,
                    "selected": None, "candidates": candidates, "rejected": rejected,
                    "preferences": preferences, "evidence": "no usable endpoint"}
        best_rank = ranked[0][0:2]
        tied = [x for x in ranked if x[0:2] == best_rank]
        if len(tied) > 1:
            return {"state": TransportState.AMBIGUOUS.value, "purpose": purpose.value, "source": source.id,
                    "selected": None, "candidates": [x[2] for x in tied], "rejected": rejected,
                    "preferences": preferences, "evidence": "multiple equally preferred endpoints"}
        selected = ranked[0]
        return {"state": TransportState.AVAILABLE.value, "purpose": purpose.value, "source": source.id,
                "selected": {"transport": selected[2]["transport"], "endpoint": selected[2]["endpoint"],
                              "capability": selected[3], "source_override": bool(configured)},
                "candidates": candidates, "rejected": rejected, "preferences": preferences,
                "evidence": f"selected {selected[2]['transport']} at preference rank {selected[0]}"}

    def source_for(self, source, selected: dict):
        try:
            backend = Backend(selected["transport"])
        except ValueError as exc:
            raise PolicyError("unsupported selected transport") from exc
        return replace(source, backend=backend, location=selected["endpoint"])

    def fetch(self, acquisition, source, purpose: AcquisitionPurpose | str, *, path: str,
              expected_sha256: str | None = None, expected_size: int | None = None,
              dry_run: bool = False) -> dict:
        plan = self.plan(source, purpose)
        if dry_run:
            return {"plan": plan, "dry_run": True}
        if plan["state"] != TransportState.AVAILABLE.value:
            raise PolicyError(f"acquisition transport selection failed: {plan['state']}")
        selected = plan["selected"]
        selected_source = self.source_for(source, selected)
        context = {"transport": selected["transport"], "endpoint": selected["endpoint"], "purpose": AcquisitionPurpose(purpose).value}
        if selected["transport"] in {"http", "https"}:
            return {"plan": plan, "object_id": acquisition.acquire_http(selected_source, path, expected_sha256, expected_size, context)}
        if selected["transport"] == "ftp":
            return {"plan": plan, "object_id": acquisition.acquire_ftp(selected_source, path, expected_sha256, expected_size, context)}
        if selected["transport"] == "rsync":
            return {"plan": plan, **acquisition.run_rsync(selected_source, scope=path, acquisition_context=context)}
        if selected["transport"] == "bittorrent":
            return {"plan": plan, **acquisition.acquire_torrent(selected_source, Path(path), path, acquisition_context=context)}
        raise PolicyError("selected transport has no acquisition adapter")
