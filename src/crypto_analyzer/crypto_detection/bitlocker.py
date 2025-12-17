"""Detektory szyfrowania oparte na konfiguracyjnych sygnaturach."""

from __future__ import annotations

from typing import Iterable, Sequence

from crypto_analyzer.core.models import EncryptionStatus, Volume
from crypto_analyzer.drivers import DataSourceDriver, DriverError
from .detectors import EncryptionDetector, EncryptionFinding
from .signature_loader import EncryptionSignature, load_default_signatures


class SignatureBasedDetector(EncryptionDetector):
    """Uniwersalny detektor korzystający z sygnatur z pliku konfiguracyjnego."""

    def __init__(
        self,
        driver: DataSourceDriver,
        *,
        signatures: Sequence[EncryptionSignature] | None = None,
        signature_ids: Iterable[str] | None = None,
    ) -> None:
        auto_signatures = list(signatures or load_default_signatures())
        if signature_ids is not None:
            ids = set(signature_ids)
            auto_signatures = [signature for signature in auto_signatures if signature.identifier in ids]

        if not auto_signatures:
            raise ValueError("SignatureBasedDetector wymaga co najmniej jednej sygnatury")

        self._driver = driver
        self._signatures = auto_signatures
        self._read_size = max(signature.max_read for signature in self._signatures)

    def analyze_volume(self, volume: Volume) -> EncryptionFinding:
        try:
            header = self._driver.read(volume.offset, self._read_size)
        except DriverError:
            return EncryptionFinding(status=EncryptionStatus.UNKNOWN)

        for signature in self._signatures:
            if not signature.matches(header):
                continue

            version = signature.extract_version(header)
            return EncryptionFinding(
                status=signature.status,
                algorithm=signature.name,
                version=version,
                details=signature.details,
            )

        return EncryptionFinding(status=EncryptionStatus.NOT_DETECTED)


class BitLockerDetector(SignatureBasedDetector):
    """Detektor korzystający z sygnatury BitLocker z pliku konfiguracyjnego."""

    def __init__(self, driver: DataSourceDriver) -> None:
        super().__init__(driver, signature_ids=("bitlocker",))


class VeraCryptDetector(SignatureBasedDetector):
    """Detektor korzystający z sygnatury VeraCrypt."""

    def __init__(self, driver: DataSourceDriver) -> None:
        super().__init__(driver, signature_ids=("veracrypt",))


class LuksDetector(SignatureBasedDetector):
    """Detektor korzystający z sygnatury LUKS."""

    def __init__(self, driver: DataSourceDriver) -> None:
        super().__init__(driver, signature_ids=("luks",))


class FileVault2Detector(SignatureBasedDetector):
    """Detektor korzystający z sygnatury FileVault 2 (APFS/ Core Storage)."""

    def __init__(self, driver: DataSourceDriver) -> None:
        super().__init__(driver, signature_ids=("filevault2",))


__all__ = [
    "BitLockerDetector",
    "FileVault2Detector",
    "LuksDetector",
    "SignatureBasedDetector",
    "VeraCryptDetector",
]
