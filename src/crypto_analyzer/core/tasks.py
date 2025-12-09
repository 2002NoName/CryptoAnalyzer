"""Definicje abstrakcyjnych zadań analitycznych."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class ProgressReporter(Protocol):
    """Minimalny interfejs raportowania postępu zadań."""

    def update(self, message: str, *, percentage: int | None = None) -> None:
        """Przekazuje informację o postępie."""


@dataclass(slots=True)
class AnalysisTask:
    """Bazowa klasa dla zadań wykonywanych w ramach analizy."""

    name: str

    def run(self, reporter: ProgressReporter) -> None:  # pragma: no cover - do nadpisania
        """Uruchamia zadanie; implementacje nadpisują tę metodę."""

        raise NotImplementedError
