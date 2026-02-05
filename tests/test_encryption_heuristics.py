"""Testy heurystycznego wykrywania szyfrowania."""

from __future__ import annotations

from crypto_analyzer.core.models import EncryptionStatus, FileSystemType
from crypto_analyzer.crypto_detection import HeuristicEncryptionDetector

from tests.synthetic_data import InMemoryDriver, deterministic_random_bytes, make_volume


def test_heuristic_marks_high_entropy_unknown_fs_as_encrypted() -> None:
    data = deterministic_random_bytes(256 * 1024, seed=1337)

    detector = HeuristicEncryptionDetector(InMemoryDriver(data))
    finding = detector.analyze_volume(make_volume(data, filesystem=FileSystemType.UNKNOWN))

    assert finding.status is EncryptionStatus.ENCRYPTED
    assert finding.algorithm == "Heuristic"
    assert finding.details is not None


def test_heuristic_does_not_trigger_when_filesystem_known() -> None:
    data = deterministic_random_bytes(64 * 1024, seed=1)

    detector = HeuristicEncryptionDetector(InMemoryDriver(data))
    finding = detector.analyze_volume(make_volume(data, filesystem=FileSystemType.NTFS))

    assert finding.status is EncryptionStatus.NOT_DETECTED


def test_heuristic_returns_unknown_for_all_zeros() -> None:
    data = b"\x00" * (64 * 1024)

    detector = HeuristicEncryptionDetector(InMemoryDriver(data))
    finding = detector.analyze_volume(make_volume(data, filesystem=FileSystemType.UNKNOWN))

    assert finding.status is EncryptionStatus.UNKNOWN
