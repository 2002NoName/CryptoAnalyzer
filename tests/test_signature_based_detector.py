"""Testy dla detektora SignatureBasedDetector (uniwersalny silnik sygnatur)."""

from __future__ import annotations

from crypto_analyzer.core.models import EncryptionStatus, FileSystemType, Volume
from crypto_analyzer.crypto_detection import SignatureBasedDetector
from crypto_analyzer.crypto_detection.signature_loader import (
    EncryptionSignature,
    SignatureMatcher,
    VersionExtractor,
)
from crypto_analyzer.drivers.base import DriverCapabilities, DriverError


class DummyDriver:
    """Minimalna implementacja interfejsu sterownika do testów."""

    name = "dummy"
    capabilities = DriverCapabilities()

    def __init__(self, data: bytes) -> None:
        self._data = data

    def enumerate_sources(self):  # pragma: no cover - nieużywane
        return []

    def open_source(self, source):  # pragma: no cover - nieużywane
        return None

    def close(self):  # pragma: no cover - nieużywane
        return None

    def list_volumes(self):  # pragma: no cover - nieużywane
        return []

    def open_filesystem(self, volume):  # pragma: no cover - nieużywane
        raise DriverError("brak implementacji")

    def read(self, offset: int, size: int) -> bytes:
        return self._data[offset : offset + size]


def test_bitlocker_signature_detected() -> None:
    header = b"\x00" * 512 + b"-FVE-FS-" + b"\x00" * 512
    driver = DummyDriver(header)
    detector = SignatureBasedDetector(driver=driver, signature_ids=("bitlocker",))
    volume = Volume(
        identifier="vol1",
        offset=0,
        size=len(header),
        filesystem=FileSystemType.UNKNOWN,
    )

    finding = detector.analyze_volume(volume)

    assert finding.status == EncryptionStatus.ENCRYPTED
    assert finding.algorithm == "BitLocker"


def test_bitlocker_signature_absent() -> None:
    header = b"\x00" * 2048
    driver = DummyDriver(header)
    detector = SignatureBasedDetector(driver=driver, signature_ids=("bitlocker",))
    volume = Volume(
        identifier="vol1",
        offset=0,
        size=len(header),
        filesystem=FileSystemType.UNKNOWN,
    )

    finding = detector.analyze_volume(volume)

    assert finding.status == EncryptionStatus.NOT_DETECTED
    assert finding.algorithm is None


def test_signature_based_detector_custom_version_extractor() -> None:
    pattern = b"TEST"
    header = bytearray(b"\x00" * 128)
    header[16:20] = pattern
    header[48:52] = (42).to_bytes(4, byteorder="little")

    signature = EncryptionSignature(
        identifier="custom",
        name="CustomEnc",
        status=EncryptionStatus.ENCRYPTED,
        matchers=[SignatureMatcher(type="equals", pattern=pattern, offset=16)],
        details="Custom signature",
        max_read=128,
        version=VersionExtractor(type="uint16-le", offset=48, length=2),
    )

    driver = DummyDriver(bytes(header))
    detector = SignatureBasedDetector(driver=driver, signatures=[signature])
    volume = Volume(
        identifier="vol1",
        offset=0,
        size=len(header),
        filesystem=FileSystemType.UNKNOWN,
    )

    finding = detector.analyze_volume(volume)

    assert finding.status == EncryptionStatus.ENCRYPTED
    assert finding.algorithm == "CustomEnc"
    assert finding.version == "42"
