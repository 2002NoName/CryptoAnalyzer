"""Testy wykrywania różnych algorytmów szyfrowania."""

from __future__ import annotations

from crypto_analyzer.core.models import EncryptionStatus, FileSystemType, Volume
from crypto_analyzer.crypto_detection import (
    SignatureBasedDetector,
)


class DummyDriver:
    """Minimalna implementacja sterownika dla testów."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self, offset: int, size: int) -> bytes:
        return self._data[offset : offset + size]


def _make_volume(size: int) -> Volume:
    return Volume(identifier="vol1", offset=0, size=size, filesystem=FileSystemType.UNKNOWN)


def test_veracrypt_signature_detected() -> None:
    header = b"TRUE" + b"\x00" * 508
    driver = DummyDriver(header)
    detector = SignatureBasedDetector(driver, signature_ids=("veracrypt",))
    volume = _make_volume(512)

    finding = detector.analyze_volume(volume)

    assert finding.status == EncryptionStatus.ENCRYPTED
    assert finding.algorithm == "VeraCrypt"


def test_bitlocker_detector_uses_signature_subset() -> None:
    header = b"-FVE-FS-" + b"\x00" * 4088
    driver = DummyDriver(header)
    detector = SignatureBasedDetector(driver, signature_ids=("bitlocker",))
    volume = _make_volume(4096)

    finding = detector.analyze_volume(volume)

    assert finding.status == EncryptionStatus.ENCRYPTED
    assert finding.algorithm == "BitLocker"
