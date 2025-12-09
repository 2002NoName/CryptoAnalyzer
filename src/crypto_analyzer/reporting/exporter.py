"""Interfejsy eksportu raportów."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Protocol

from crypto_analyzer.core.models import AnalysisResult


class ExportFormat(str, Enum):
    """Formaty eksportu raportów."""

    CSV = "csv"
    JSON = "json"


class ReportExporter(Protocol):
    """Interfejs dla mechanizmów eksportu."""

    def export(self, result: AnalysisResult, destination: Path, fmt: ExportFormat) -> Path:
        """Eksportuje wyniki do wybranego formatu i zwraca ścieżkę docelową."""
