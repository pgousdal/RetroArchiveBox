"""Operator-facing removable-media workflow over the existing MediaManager."""
from __future__ import annotations

import json
import re
from pathlib import Path

from .analysis import AnalysisManager
from .errors import PolicyError, RabError
from .inventory import inventory_image
from .local_ingest import ProvenanceClass
from .media import MediaManager, RepresentationKind
from .model import Rights


class RemovableManager:
    def __init__(self, archive, *, media=None):
        self.archive = archive; self.media = media or MediaManager(archive)

    def devices(self): return self.media.devices()
    def inspect(self, device): return self.media.inspect(device)
    def jobs(self): return self.media.jobs()
    def show(self, job_id): return self.media.show(job_id)

    def plan(self, device):
        info = self.inspect(device); safety = info.get("safety", "UNKNOWN")
        return {"schema": "rab-removable-capture-plan-v1", "device": device, "safety": safety, "allowed": safety == "SAFE_CANDIDATE", "representation": RepresentationKind.WHOLE_DEVICE_IMAGE.value, "method": "whole-device-dd", "expected_bytes": info.get("size"), "mounted_children": info.get("mounted_children", []), "read_only": True, "limitations": ["source must be unmounted", "whole-device capture includes partition tables, allocated and unallocated bytes"]}

    def capture(self, device, *, physical_medium_id=None, repeat_of=None, platform_hint=None, vendor=None, title=None, collection=None, media_number=None, rights=Rights.UNKNOWN, provenance=ProvenanceClass.ORIGINAL_PHYSICAL_OWNED, notes="", verification="standard"):
        plan = self.plan(device)
        if not plan["allowed"]: raise PolicyError("removable device rejected by safety policy")
        return self.media.capture(device, physical_medium_id=physical_medium_id, repeat_of=repeat_of, platform_hint=platform_hint, vendor=vendor, title=title, collection=collection, media_number=media_number, rights=rights, provenance=provenance, notes=notes, verification=verification)

    def inventory(self, capture_id):
        job = self.show(capture_id)
        return {"capture_id": capture_id, "object_id": job.get("object_id"), "inventory": job.get("inventory", {}), "representation": RepresentationKind.WHOLE_DEVICE_IMAGE.value}

    def analyze(self, capture_id, *, policy="metadata-only"):
        job = self.show(capture_id)
        if not job.get("object_id"): raise RabError("capture has no preserved object")
        result = AnalysisManager(self.archive).analyze(job["object_id"], policy=policy)
        return {"capture_id": capture_id, "object_id": job["object_id"], "inventory": job.get("inventory", {}), "analysis": result}

    @staticmethod
    def public_job(job):
        value = {key: item for key, item in job.items() if key not in {"device", "operator_notes"}}
        if isinstance(value.get("capture"), dict): value["capture"] = {key: item for key, item in value["capture"].items() if key not in {"command", "device_info"}}
        if isinstance(value.get("adapter"), dict): value["adapter"] = {key: item for key, item in value["adapter"].items() if key not in {"executable"}}
        return value
