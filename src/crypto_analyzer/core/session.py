"""Obsługa cyklu życia sesji analitycznej."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from .models import DiskSource, Volume


@dataclass(slots=True)
class AnalysisSession:
    """Reprezentuje pojedynczą sesję analizy dysku lub obrazu."""

    source: DiskSource
    volumes: List[Volume] = field(default_factory=list)

    def add_volume(self, volume: Volume) -> None:
        """Dodaje wolumen do sesji, unikając duplikatów."""

        if volume.identifier not in {existing.identifier for existing in self.volumes}:
            self.volumes.append(volume)
