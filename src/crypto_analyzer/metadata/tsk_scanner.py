"""Skanowanie metadanych z wykorzystaniem pytsk3."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Tuple

import pytsk3
from structlog import get_logger

from crypto_analyzer.core.models import DirectoryNode, EncryptionStatus, FileMetadata, Volume
from crypto_analyzer.drivers import DataSourceDriver, DriverError
from .scanner import MetadataResult, MetadataScanner


class TskMetadataScanner(MetadataScanner):
    """Implementacja skanera metadanych dla systemów plików obsługiwanych przez TSK."""

    def __init__(self, driver: DataSourceDriver, *, max_depth: int | None = None) -> None:
        self._driver = driver
        self._max_depth = max_depth
        self._logger = get_logger(__name__)

    def scan(self, volume: Volume) -> MetadataResult:
        try:
            fs_handle = self._driver.open_filesystem(volume)
        except DriverError as exc:
            raise DriverError(f"Nie udało się otworzyć systemu plików wolumenu {volume.identifier}") from exc

        root_node = DirectoryNode(name="/", path=PurePosixPath("/"))
        totals = self._walk_directory(fs_handle, path="/", node=root_node, depth=0)
        return MetadataResult(root=root_node, total_files=totals[0], total_directories=totals[1])

    # ------------------------------------------------------------------
    # Rekurencyjne przetwarzanie katalogów
    # ------------------------------------------------------------------

    def _walk_directory(
        self,
        fs_handle: pytsk3.FS_Info,
        *,
        path: str,
        node: DirectoryNode,
        depth: int,
    ) -> Tuple[int, int]:
        total_files = 0
        total_directories = 1  # liczymy bieżący katalog

        try:
            directory = fs_handle.open_dir(path=path)
        except IOError as exc:  # pragma: no cover - zależne od obrazu
            self._logger.warning("directory-open-failed", path=path, error=str(exc))
            return (0, 0)

        for entry in directory:
            name_bytes = entry.info.name.name
            if not name_bytes:
                continue
            name = name_bytes.decode("utf-8", "replace")
            if name in {".", ".."}:
                continue

            child_path = PurePosixPath(path) / name
            meta = entry.info.meta
            if meta is None:
                continue

            if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                child_node = DirectoryNode(name=name, path=child_path)
                node.subdirectories.append(child_node)
                if self._max_depth is None or depth < self._max_depth:
                    child_totals = self._walk_directory(
                        fs_handle,
                        path=str(child_path).replace("\\", "/"),
                        node=child_node,
                        depth=depth + 1,
                    )
                    total_files += child_totals[0]
                    total_directories += child_totals[1]
                else:
                    total_directories += 1
            else:
                metadata = FileMetadata(
                    name=name,
                    path=child_path,
                    size=int(meta.size) if meta.size is not None else 0,
                    owner=self._format_owner(meta.uid, meta.gid),
                    created_at=self._format_timestamp(meta.crtime),
                    modified_at=self._format_timestamp(meta.mtime),
                    accessed_at=self._format_timestamp(meta.atime),
                    encryption=EncryptionStatus.UNKNOWN,
                )
                node.files.append(metadata)
                total_files += 1

        return total_files, total_directories

    @staticmethod
    def _format_timestamp(value: int | None) -> str | None:
        if value is None or value <= 0:
            return None
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()

    @staticmethod
    def _format_owner(uid: int | None, gid: int | None) -> str | None:
        if uid is None and gid is None:
            return None
        uid_part = f"uid={uid}" if uid is not None else ""
        gid_part = f"gid={gid}" if gid is not None else ""
        return ",".join(part for part in (uid_part, gid_part) if part)


__all__ = ["TskMetadataScanner"]
