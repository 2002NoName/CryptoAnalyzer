"""Domyślna implementacja eksportu raportów (CSV/JSON)."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Dict, Iterable, Iterator

from crypto_analyzer.core.models import AnalysisResult, DirectoryNode, FileMetadata, VolumeAnalysis
from crypto_analyzer.crypto_detection import EncryptionFinding
from crypto_analyzer.metadata import MetadataResult
from .exporter import ExportFormat, ReportExporter


class DefaultReportExporter(ReportExporter):
    """Eksporter zapisujący wyniki analizy do plików CSV lub JSON."""

    def export(self, result: AnalysisResult, destination: Path, fmt: ExportFormat) -> Path:
        destination.parent.mkdir(parents=True, exist_ok=True)

        if fmt is ExportFormat.JSON:
            payload = self._build_json_payload(result)
            destination.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        elif fmt is ExportFormat.CSV:
            self._write_csv(result, destination)
        else:  # pragma: no cover - obsługa przyszłych formatów
            raise ValueError(f"Nieobsługiwany format eksportu: {fmt}")

        return destination

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------

    def _build_json_payload(self, result: AnalysisResult) -> Dict[str, object]:
        return {
            "source": {
                "identifier": result.source.identifier,
                "type": result.source.source_type.value,
                "display_name": result.source.display_name,
                "path": str(result.source.path) if result.source.path else None,
            },
            "totals": {
                "volumes": len(result.volumes),
                "files": result.total_files(),
                "directories": result.total_directories(),
            },
            "volumes": [self._volume_to_dict(volume) for volume in result.volumes],
        }

    def _volume_to_dict(self, analysis: VolumeAnalysis) -> Dict[str, object]:
        return {
            "identifier": analysis.volume.identifier,
            "filesystem": analysis.filesystem.value,
            "offset": analysis.volume.offset,
            "size": analysis.volume.size,
            "encryption": self._encryption_to_dict(analysis.encryption),
            "metadata": self._metadata_to_dict(analysis.metadata) if analysis.metadata else None,
        }

    def _metadata_to_dict(self, metadata: MetadataResult) -> Dict[str, object]:
        return {
            "total_files": metadata.total_files,
            "total_directories": metadata.total_directories,
            "tree": self._directory_to_dict(metadata.root),
        }

    def _directory_to_dict(self, node: DirectoryNode) -> Dict[str, object]:
        return {
            "name": node.name,
            "path": str(node.path),
            "files": [self._file_to_dict(file) for file in node.files],
            "subdirectories": [self._directory_to_dict(sub) for sub in node.subdirectories],
        }

    @staticmethod
    def _encryption_to_dict(finding: EncryptionFinding) -> Dict[str, object]:
        return {
            "status": finding.status.value,
            "algorithm": finding.algorithm,
            "version": finding.version,
            "details": finding.details,
        }

    @staticmethod
    def _file_to_dict(file: FileMetadata) -> Dict[str, object]:
        return {
            "name": file.name,
            "path": str(file.path),
            "size": file.size,
            "owner": file.owner,
            "created_at": file.created_at,
            "modified_at": file.modified_at,
            "accessed_at": file.accessed_at,
            "encryption": file.encryption.value,
        }

    # ------------------------------------------------------------------
    # CSV
    # ------------------------------------------------------------------

    def _write_csv(self, result: AnalysisResult, destination: Path) -> None:
        fieldnames = [
            "volume_id",
            "entry_type",
            "path",
            "name",
            "size",
            "owner",
            "created_at",
            "modified_at",
            "accessed_at",
            "encryption_status",
            "encryption_algorithm",
            "encryption_version",
        ]
        with destination.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for row in self._iter_csv_rows(result):
                writer.writerow(row)

    def _iter_csv_rows(self, result: AnalysisResult) -> Iterator[Dict[str, object]]:
        for analysis in result.volumes:
            encryption = analysis.encryption
            base_row = {
                "volume_id": analysis.volume.identifier,
                "encryption_status": encryption.status.value,
                "encryption_algorithm": encryption.algorithm,
                "encryption_version": encryption.version,
            }
            if analysis.metadata is None:
                yield {
                    **base_row,
                    "entry_type": "volume",
                    "path": None,
                    "name": None,
                    "size": analysis.volume.size,
                    "owner": None,
                    "created_at": None,
                    "modified_at": None,
                    "accessed_at": None,
                }
                continue

            yield from self._iter_directory_rows(analysis.metadata.root, base_row)

    def _iter_directory_rows(
        self,
        node: DirectoryNode,
        base_row: Dict[str, object],
    ) -> Iterable[Dict[str, object]]:
        yield {
            **base_row,
            "entry_type": "directory",
            "path": str(node.path),
            "name": node.name,
            "size": None,
            "owner": None,
            "created_at": None,
            "modified_at": None,
            "accessed_at": None,
        }

        for file_metadata in node.files:
            yield self._file_row(file_metadata, base_row)

        for subdirectory in node.subdirectories:
            yield from self._iter_directory_rows(subdirectory, base_row)

    @staticmethod
    def _file_row(file_metadata: FileMetadata, base_row: Dict[str, object]) -> Dict[str, object]:
        return {
            **base_row,
            "entry_type": "file",
            "path": str(file_metadata.path),
            "name": file_metadata.name,
            "size": file_metadata.size,
            "owner": file_metadata.owner,
            "created_at": file_metadata.created_at,
            "modified_at": file_metadata.modified_at,
            "accessed_at": file_metadata.accessed_at,
        }


__all__ = ["DefaultReportExporter"]
