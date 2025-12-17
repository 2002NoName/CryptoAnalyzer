"""Unit tests for AnalysisSession."""

from __future__ import annotations

from pathlib import Path

from crypto_analyzer.core.models import DiskSource, FileSystemType, SourceType, Volume
from crypto_analyzer.core.session import AnalysisSession


def test_session_add_volume_deduplicates_by_identifier() -> None:
    source = DiskSource(identifier="s", source_type=SourceType.DISK_IMAGE, display_name="s", path=Path("/tmp/a"))
    session = AnalysisSession(source=source)

    v1 = Volume(identifier="v1", offset=0, size=1, filesystem=FileSystemType.UNKNOWN)
    v1_dupe = Volume(identifier="v1", offset=100, size=2, filesystem=FileSystemType.NTFS)

    session.add_volume(v1)
    session.add_volume(v1_dupe)

    assert len(session.volumes) == 1
    assert session.volumes[0].identifier == "v1"
