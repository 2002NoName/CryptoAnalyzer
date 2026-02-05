"""Tests for synthetic data utilities.

These tests validate determinism and basic safety checks.
"""

from __future__ import annotations

import pytest

from tests.synthetic_data import deterministic_random_bytes, inject_signature, repeat_byte, zeros


def test_deterministic_random_bytes_is_repeatable() -> None:
    a = deterministic_random_bytes(1024, seed=123)
    b = deterministic_random_bytes(1024, seed=123)
    c = deterministic_random_bytes(1024, seed=124)

    assert a == b
    assert a != c


def test_low_entropy_generators() -> None:
    assert zeros(4) == b"\x00\x00\x00\x00"
    assert repeat_byte(4, 0xAA) == b"\xAA\xAA\xAA\xAA"


def test_inject_signature_inserts_at_offset() -> None:
    base = zeros(16)
    out = inject_signature(base, offset=4, signature=b"TEST")
    assert out[4:8] == b"TEST"


def test_inject_signature_raises_when_out_of_bounds() -> None:
    base = zeros(8)
    with pytest.raises(ValueError):
        inject_signature(base, offset=7, signature=b"AB")
