"""Utilities for generating deterministic synthetic data for tests.

This module is intentionally dependency-free and fast.

It supports:
- deterministic random/high-entropy buffers (seeded),
- low-entropy buffers (zeros/repeated bytes),
- signature injection at offsets,
- an in-memory driver compatible with detectors.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Iterable

from crypto_analyzer.core.models import FileSystemType, Volume
from crypto_analyzer.drivers import DriverError


def deterministic_random_bytes(length: int, *, seed: int) -> bytes:
    """Return deterministic pseudo-random bytes.

    We avoid `os.urandom()` to keep tests stable across runs.
    """

    rng = random.Random(seed)
    try:
        return rng.randbytes(length)  # py3.9+
    except AttributeError:  # pragma: no cover
        return bytes(rng.getrandbits(8) for _ in range(length))


def zeros(length: int) -> bytes:
    return b"\x00" * int(length)


def repeat_byte(length: int, value: int) -> bytes:
    return bytes([int(value) & 0xFF]) * int(length)


def inject_signature(base: bytes, *, offset: int, signature: bytes) -> bytes:
    buf = bytearray(base)
    end = int(offset) + len(signature)
    if end > len(buf):
        raise ValueError("Signature exceeds buffer size")
    buf[int(offset) : end] = signature
    return bytes(buf)


def make_volume(data: bytes, *, filesystem: FileSystemType = FileSystemType.UNKNOWN) -> Volume:
    return Volume(identifier="vol1", offset=0, size=len(data), filesystem=filesystem)


@dataclass
class InMemoryDriver:
    """Simple in-memory driver for unit tests.

    The encryption detectors only require the `read(offset, size)` method.
    """

    data: bytes
    fail_offsets: Iterable[int] = ()

    def read(self, offset: int, size: int) -> bytes:
        if int(offset) in set(self.fail_offsets):
            raise DriverError("synthetic read failure")
        start = max(int(offset), 0)
        end = max(start + int(size), start)
        return self.data[start:end]
