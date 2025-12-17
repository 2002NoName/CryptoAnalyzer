"""Testy eksportu raportów."""

from __future__ import annotations

import json

from pathlib import PurePosixPath

from crypto_analyzer.core.models import AnalysisResult, DirectoryNode, DiskSource, FileMetadata, FileSystemType, SourceType, Volume, VolumeAnalysis
from crypto_analyzer.crypto_detection import EncryptionFinding
from crypto_analyzer.metadata import MetadataResult
from crypto_analyzer.reporting import DefaultReportExporter, ExportFormat


def _sample_analysis() -> AnalysisResult:
    source = DiskSource(identifier="image1", source_type=SourceType.DISK_IMAGE, display_name="Image 1", path=None)
    volume = Volume(identifier="vol1", offset=0, size=4096, filesystem=FileSystemType.NTFS)
    root = DirectoryNode(
        name="/",
        path=PurePosixPath("/"),
        owner="uid=0",
        created_at="2024-01-01T00:00:00+00:00",
        changed_at="2024-01-01T00:10:00+00:00",
        modified_at="2024-01-01T01:00:00+00:00",
        accessed_at="2024-01-01T02:00:00+00:00",
        attributes=("alloc",),
    )
    root.files.append(
        FileMetadata(
            name="file.txt",
            path=PurePosixPath("/file.txt"),
            size=123,
            owner="uid=0",
            created_at="2024-01-01T00:00:00+00:00",
            changed_at="2024-01-01T00:30:00+00:00",
            modified_at="2024-01-01T01:00:00+00:00",
            accessed_at="2024-01-01T02:00:00+00:00",
            attributes=("alloc", "readonly"),
        )
    )
    metadata = MetadataResult(root=root, total_files=1, total_directories=1)
    finding = EncryptionFinding(status=volume.encryption)
    analysis = AnalysisResult(source=source)
    analysis.volumes.append(VolumeAnalysis(volume=volume, filesystem=FileSystemType.NTFS, encryption=finding, metadata=metadata))
    return analysis


def test_export_json(tmp_path) -> None:
    analysis = _sample_analysis()
    exporter = DefaultReportExporter()
    destination = tmp_path / "report.json"

    exporter.export(analysis, destination, ExportFormat.JSON)

    assert destination.exists()
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["source"]["identifier"] == "image1"
    assert payload["volumes"][0]["encryption"]["status"] == analysis.volumes[0].encryption.status.value
    file_entry = payload["volumes"][0]["metadata"]["tree"]["files"][0]
    assert file_entry["attributes"] == ["alloc", "readonly"]
    assert file_entry["changed_at"] == "2024-01-01T00:30:00+00:00"

    dir_entry = payload["volumes"][0]["metadata"]["tree"]
    assert dir_entry["owner"] == "uid=0"
    assert dir_entry["attributes"] == ["alloc"]


def test_export_csv(tmp_path) -> None:
    analysis = _sample_analysis()
    exporter = DefaultReportExporter()
    destination = tmp_path / "report.csv"

    exporter.export(analysis, destination, ExportFormat.CSV)

    content = destination.read_text(encoding="utf-8").splitlines()
    assert len(content) >= 2
    header = content[0].split(",")
    assert "volume_id" in header
    assert "attributes" in header
    assert "changed_at" in header
