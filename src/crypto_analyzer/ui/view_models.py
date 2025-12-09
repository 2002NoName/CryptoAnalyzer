"""Modele widoku dla interfejsu użytkownika."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List

from crypto_analyzer.core.models import DiskSource, Volume


@dataclass(slots=True)
class VolumeSelectionViewModel:
    """Reprezentuje stan ekranu wyboru wolumenów."""

    available_volumes: List[Volume] = field(default_factory=list)
    selected_ids: List[str] = field(default_factory=list)

    def toggle_volume(self, identifier: str) -> None:
        """Przełącza stan zaznaczenia wolumenu."""

        if identifier in self.selected_ids:
            self.selected_ids.remove(identifier)
        else:
            self.selected_ids.append(identifier)


@dataclass(slots=True)
class ApplicationViewModel:
    """Stan wysokopoziomowy aplikacji GUI."""

    sources: List[DiskSource] = field(default_factory=list)
    on_source_selected: Callable[[DiskSource], None] | None = None

    def select_source(self, source: DiskSource) -> None:
        """Obsługuje wybór źródła przez użytkownika."""

        if self.on_source_selected is not None:
            self.on_source_selected(source)
