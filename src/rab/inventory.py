"""Small, non-mounting partition/filesystem inventory for captured images."""
from __future__ import annotations

import struct
from pathlib import Path


def inventory_image(path: Path) -> dict:
    with path.open("rb") as handle:
        header = handle.read(1024 * 1024)
    partitions = []
    if len(header) >= 512 and header[510:512] == b"\x55\xaa":
        for index in range(4):
            entry = header[446 + index * 16:462 + index * 16]
            kind = entry[4]; start, sectors = struct.unpack_from("<II", entry, 8)
            if kind and sectors:
                partitions.append({"number": index + 1, "start_lba": start, "sectors": sectors, "size": sectors * 512, "type": f"mbr-{kind:02x}"})
    if header[512:520] == b"EFI PART":
        entry_size = struct.unpack_from("<I", header, 84)[0]; count = struct.unpack_from("<I", header, 80)[0]
        for index in range(min(count, 128)):
            offset = 1024 + index * entry_size
            if offset + entry_size > len(header): break
            first, last = struct.unpack_from("<QQ", header, offset + 32)
            if first <= last and first:
                partitions.append({"number": index + 1, "start_lba": first, "end_lba": last, "size": (last - first + 1) * 512, "type": "gpt"})
    observations = []
    for partition in partitions:
        sample = header[partition["start_lba"] * 512:partition["start_lba"] * 512 + 4096]
        fs = "unknown"
        if sample[3:11] == b"NTFS    ": fs = "ntfs"
        elif sample[54:62] in {b"FAT16   ", b"FAT12   "}: fs = "fat"
        elif sample[82:90] == b"FAT32   ": fs = "fat32"
        elif sample[3:11] == b"EXFAT   ": fs = "exfat"
        elif len(sample) > 1080 and sample[1080:1082] == b"\x53\xef": fs = "ext"
        observations.append({"partition": partition["number"], "filesystem": fs})
    return {"partition_table": "gpt" if header[512:520] == b"EFI PART" else "mbr" if partitions else "unknown", "partitions": partitions, "filesystems": observations, "mounted": False, "read_only_observation": True}
