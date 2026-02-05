"""Generate small disk images for filesystem-detection benchmarks (Windows-native).

This script creates a raw disk image with an MBR partition table and a single
FAT16-formatted partition. It is intentionally dependency-free (pure Python),
so it can run on Windows without WSL2.

Default output matches the benchmark expectation:
- test_assets/generated/multi_volume.img

Usage:
  poetry run python scripts/generate_test_images_windows.py
  poetry run python scripts/generate_test_images_windows.py --force
"""

from __future__ import annotations

import argparse
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


SECTOR_SIZE = 512


@dataclass(frozen=True, slots=True)
class Fat16Layout:
    bytes_per_sector: int
    sectors_per_cluster: int
    reserved_sectors: int
    num_fats: int
    root_entry_count: int
    total_sectors: int
    fat_size_sectors: int
    root_dir_sectors: int


def _ceil_div(a: int, b: int) -> int:
    return (a + (b - 1)) // b


def compute_fat16_layout(*, total_sectors: int) -> Fat16Layout:
    bytes_per_sector = SECTOR_SIZE
    sectors_per_cluster = 1
    reserved_sectors = 1
    num_fats = 2
    root_entry_count = 512

    root_dir_sectors = _ceil_div(root_entry_count * 32, bytes_per_sector)

    fat_size_sectors = 1
    for _ in range(32):
        first_data_sector = reserved_sectors + (num_fats * fat_size_sectors) + root_dir_sectors
        data_sectors = total_sectors - first_data_sector
        if data_sectors <= 0:
            raise ValueError("Partition too small for FAT16")

        cluster_count = data_sectors // sectors_per_cluster
        fat_bytes = (cluster_count + 2) * 2
        new_fat_size_sectors = _ceil_div(fat_bytes, bytes_per_sector)

        if new_fat_size_sectors == fat_size_sectors:
            break
        fat_size_sectors = new_fat_size_sectors
    else:
        raise RuntimeError("FAT16 layout did not converge")

    first_data_sector = reserved_sectors + (num_fats * fat_size_sectors) + root_dir_sectors
    data_sectors = total_sectors - first_data_sector
    cluster_count = data_sectors // sectors_per_cluster
    if not (4085 <= cluster_count <= 65525):
        raise ValueError(
            f"Computed FAT16 cluster count out of range: {cluster_count}. "
            "Increase partition size."
        )

    return Fat16Layout(
        bytes_per_sector=bytes_per_sector,
        sectors_per_cluster=sectors_per_cluster,
        reserved_sectors=reserved_sectors,
        num_fats=num_fats,
        root_entry_count=root_entry_count,
        total_sectors=total_sectors,
        fat_size_sectors=fat_size_sectors,
        root_dir_sectors=root_dir_sectors,
    )


def build_mbr_single_partition(*, start_lba: int, size_sectors: int, ptype: int) -> bytes:
    mbr = bytearray(SECTOR_SIZE)

    # Partition table entry (16 bytes) at offset 446
    # CHS values are mostly ignored by modern tooling; use "max" as common convention.
    chs_max = bytes([0xFE, 0xFF, 0xFF])
    entry = bytearray(16)
    entry[0] = 0x00  # bootable flag
    entry[1:4] = chs_max
    entry[4] = ptype
    entry[5:8] = chs_max
    entry[8:12] = struct.pack("<I", start_lba)
    entry[12:16] = struct.pack("<I", size_sectors)

    mbr[446 : 446 + 16] = entry

    # MBR signature
    mbr[510:512] = b"\x55\xAA"
    return bytes(mbr)


def build_fat16_boot_sector(*, layout: Fat16Layout, hidden_sectors: int) -> bytes:
    b = bytearray(SECTOR_SIZE)

    # Jump + OEM
    b[0:3] = b"\xEB\x3C\x90"
    b[3:11] = b"MSDOS5.0"

    # BPB
    struct.pack_into("<H", b, 11, layout.bytes_per_sector)
    struct.pack_into("<B", b, 13, layout.sectors_per_cluster)
    struct.pack_into("<H", b, 14, layout.reserved_sectors)
    struct.pack_into("<B", b, 16, layout.num_fats)
    struct.pack_into("<H", b, 17, layout.root_entry_count)
    struct.pack_into("<H", b, 19, layout.total_sectors if layout.total_sectors <= 0xFFFF else 0)
    struct.pack_into("<B", b, 21, 0xF8)  # media
    struct.pack_into("<H", b, 22, layout.fat_size_sectors)
    struct.pack_into("<H", b, 24, 63)  # sectors/track
    struct.pack_into("<H", b, 26, 255)  # heads
    struct.pack_into("<I", b, 28, hidden_sectors)
    struct.pack_into("<I", b, 32, 0 if layout.total_sectors <= 0xFFFF else layout.total_sectors)

    # EBPB
    b[36] = 0x80  # drive number
    b[37] = 0x00
    b[38] = 0x29  # boot signature
    struct.pack_into("<I", b, 39, 0xA1B2C3D4)  # volume id
    b[43:54] = b"CRYPTOANALYZ"  # 11 bytes label
    b[54:62] = b"FAT16   "

    # Signature
    b[510:512] = b"\x55\xAA"

    return bytes(b)


def write_fat16_partition(
    file: BinaryIO,
    *,
    partition_start_lba: int,
    partition_total_sectors: int,
) -> None:
    layout = compute_fat16_layout(total_sectors=partition_total_sectors)

    base = partition_start_lba * SECTOR_SIZE

    # Boot sector
    boot = build_fat16_boot_sector(layout=layout, hidden_sectors=partition_start_lba)
    file.seek(base)
    file.write(boot)

    # FATs
    fat_offset = base + (layout.reserved_sectors * SECTOR_SIZE)
    fat_bytes_total = layout.fat_size_sectors * SECTOR_SIZE

    fat = bytearray(fat_bytes_total)
    # FAT16 first two entries: media descriptor + EOC
    struct.pack_into("<H", fat, 0, 0xFFF8)
    struct.pack_into("<H", fat, 2, 0xFFFF)

    for i in range(layout.num_fats):
        file.seek(fat_offset + i * fat_bytes_total)
        file.write(fat)

    # Root directory (zeroed)
    root_dir_offset = fat_offset + (layout.num_fats * fat_bytes_total)
    root_dir_bytes = layout.root_dir_sectors * SECTOR_SIZE
    file.seek(root_dir_offset)
    file.write(b"\x00" * root_dir_bytes)

    # Data region can stay zero-filled (file was truncated)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("test_assets/generated/multi_volume.img"),
        help="Output path for the generated image.",
    )
    parser.add_argument(
        "--partition-mb",
        type=int,
        default=32,
        help="Size of the FAT16 partition (MiB).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite output file if it exists.",
    )

    args = parser.parse_args()

    output: Path = args.output
    output.parent.mkdir(parents=True, exist_ok=True)

    if output.exists() and not args.force:
        raise SystemExit(f"Refusing to overwrite existing file: {output} (use --force)")

    partition_start_lba = 2048
    partition_total_sectors = (args.partition_mb * 1024 * 1024) // SECTOR_SIZE
    if partition_total_sectors < 8192:
        raise SystemExit("partition-mb too small; use at least 4 MiB")

    # Add a bit of slack after the partition.
    total_sectors = partition_start_lba + partition_total_sectors + 2048

    mbr = build_mbr_single_partition(
        start_lba=partition_start_lba,
        size_sectors=partition_total_sectors,
        ptype=0x0E,  # FAT16 LBA
    )

    with output.open("w+b") as f:
        f.truncate(total_sectors * SECTOR_SIZE)
        f.seek(0)
        f.write(mbr)

        write_fat16_partition(
            f,
            partition_start_lba=partition_start_lba,
            partition_total_sectors=partition_total_sectors,
        )

        f.flush()
        os.fsync(f.fileno())

    print(f"Generated: {output} ({total_sectors * SECTOR_SIZE} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
