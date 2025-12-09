"""Interfejsy i modele wyników detekcji szyfrowania."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from crypto_analyzer.core.models import EncryptionStatus, Volume


@dataclass(slots=True)
class EncryptionFinding:
    """Wynik analizy szyfrowania."""

    status: EncryptionStatus
    algorithm: str | None = None
    version: str | None = None
    details: str | None = None


class EncryptionDetector(Protocol):
    """Interfejs dla heurystyk wykrywających szyfrowanie."""

    def analyze_volume(self, volume: Volume) -> EncryptionFinding:
        """Analizuje wolumen w celu określenia szyfrowania."""
