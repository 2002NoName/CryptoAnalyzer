"""Detektor szyfrowania oparty na konfiguracyjnych sygnaturach.

Moduł udostępnia uniwersalny mechanizm dopasowania nagłówków (magic bytes)
do reguł z pliku `encryption_signatures.json`.
"""

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
        self._read_plan: dict[int, int] = {}
        for signature in self._signatures:
            offset = int(getattr(signature, "read_offset", 0) or 0)
            size = int(signature.max_read)
            current = self._read_plan.get(offset)
            if current is None or size > current:
                self._read_plan[offset] = size

    def analyze_volume(self, volume: Volume) -> EncryptionFinding:
        cache: dict[int, bytes] = {}

        for signature in self._signatures:
            read_offset = int(getattr(signature, "read_offset", 0) or 0)
            if read_offset not in cache:
                read_size = int(self._read_plan.get(read_offset, signature.max_read))
                try:
                    cache[read_offset] = self._driver.read(volume.offset + read_offset, read_size)
                except DriverError:
                    return EncryptionFinding(status=EncryptionStatus.UNKNOWN)

            data = cache[read_offset]

            if not signature.matches(data):
                continue

            version = signature.extract_version(data)
            return EncryptionFinding(
                status=signature.status,
                algorithm=signature.name,
                version=version,
                details=signature.details,
            )

        return EncryptionFinding(status=EncryptionStatus.NOT_DETECTED)


__all__ = ["SignatureBasedDetector"]
