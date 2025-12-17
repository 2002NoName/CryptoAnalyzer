"""Testy wykrywania różnych algorytmów szyfrowania."""

from __future__ import annotations

from crypto_analyzer.core.models import EncryptionStatus, FileSystemType, Volume
from crypto_analyzer.crypto_detection import (
    BitLockerDetector,
    FileVault2Detector,
    LuksDetector,
    SignatureBasedDetector,
    VeraCryptDetector,
    load_default_signatures,
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
    detector = VeraCryptDetector(driver)
    volume = _make_volume(512)

    finding = detector.analyze_volume(volume)

    assert finding.status == EncryptionStatus.ENCRYPTED
    assert finding.algorithm == "VeraCrypt"


def test_luks_signature_detected() -> None:
    header = bytes.fromhex("4C554B53BABE") + (2).to_bytes(2, "little") + b"\x00" * 584
    driver = DummyDriver(header)
    detector = LuksDetector(driver)
    volume = _make_volume(592)

    finding = detector.analyze_volume(volume)

    assert finding.status == EncryptionStatus.ENCRYPTED
    assert finding.algorithm == "LUKS"
    assert finding.version == "2"


def test_filevault2_signature_detected() -> None:
    header = b"\x00" * 256 + bytes.fromhex("636F72657374726167") + b"\x00" * 3832
    driver = DummyDriver(header)
    detector = FileVault2Detector(driver)
    volume = _make_volume(4096)

    finding = detector.analyze_volume(volume)

    assert finding.status == EncryptionStatus.ENCRYPTED
    assert finding.algorithm == "FileVault2"


def test_multiple_signatures_fallback_to_first_match() -> None:
    """Gdy wiele sygnatur pasuje, zwracamy pierwszą dopasowaną."""
    header = b"-FVE-FS-" + b"\x00" * 4088
    driver = DummyDriver(header)
    detector = SignatureBasedDetector(driver, signatures=load_default_signatures())
    volume = _make_volume(4096)

    finding = detector.analyze_volume(volume)

    assert finding.status == EncryptionStatus.ENCRYPTED
    assert finding.algorithm == "BitLocker"


def test_bitlocker_detector_uses_signature_subset() -> None:
    header = b"-FVE-FS-" + b"\x00" * 4088
    driver = DummyDriver(header)
    detector = BitLockerDetector(driver)
    volume = _make_volume(4096)

    finding = detector.analyze_volume(volume)

    assert finding.status == EncryptionStatus.ENCRYPTED
    assert finding.algorithm == "BitLocker"
