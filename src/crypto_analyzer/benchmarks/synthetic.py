"""Deterministic synthetic data helpers for benchmarks.

Kept inside `src/` so benchmarking/reporting does not depend on the test package.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from crypto_analyzer.drivers import DriverError


def deterministic_random_bytes(length: int, *, seed: int) -> bytes:
    rng = random.Random(seed)
    try:
        return rng.randbytes(int(length))  # py3.9+
    except AttributeError:  # pragma: no cover
        return bytes(rng.getrandbits(8) for _ in range(int(length)))


def zeros(length: int) -> bytes:
    return b"\x00" * int(length)


def repeat_byte(length: int, value: int) -> bytes:
    return bytes([int(value) & 0xFF]) * int(length)


@dataclass(slots=True)
class InMemoryDriver:
    """Minimal driver-like object that supports raw reads."""

    data: bytes

    def read(self, offset: int, size: int) -> bytes:
        start = max(int(offset), 0)
        end = max(start + int(size), start)
        if start > len(self.data):
            raise DriverError("read out of bounds")
        return self.data[start:end]
