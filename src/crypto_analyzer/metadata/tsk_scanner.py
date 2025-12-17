"""Skanowanie metadanych z wykorzystaniem pytsk3."""

from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import PurePosixPath
import stat
import threading
from threading import Event, Lock
from typing import Callable, List, Tuple

import pytsk3
from structlog import get_logger

from crypto_analyzer.core.models import DirectoryNode, EncryptionStatus, FileMetadata, Volume
from crypto_analyzer.drivers import DataSourceDriver, DriverError
from .scanner import MetadataResult, MetadataScanCancelled, MetadataScanner


_FLAG_NAMES = (
    (getattr(pytsk3, "TSK_FS_META_FLAG_ALLOC", 0), "alloc"),
    (getattr(pytsk3, "TSK_FS_META_FLAG_UNALLOC", 0), "unalloc"),
    (getattr(pytsk3, "TSK_FS_META_FLAG_COMP", 0), "compressed"),
    (getattr(pytsk3, "TSK_FS_META_FLAG_ORPHAN", 0), "orphan"),
    (getattr(pytsk3, "TSK_FS_META_FLAG_APP", 0), "app"),
)


class _Cancelled(Exception):
    """Używane do wewnętrznego sygnalizowania anulowania."""


@dataclass(slots=True)
class _WorkItem:
    path: str
    node: DirectoryNode
    depth: int


class _ProgressTracker:
    """Śledzi postęp przetwarzania katalogów i wywołuje callback."""

    def __init__(
        self,
        callback: Callable[[int, str | None, str | None], None] | None,
        cancel_event: Event | None,
    ) -> None:
        self._callback = callback
        self._cancel_event = cancel_event
        self._processed = 0
        self._total_known = 1 if callback is not None else 0
        self._percent = 0
        self._lock = Lock()
        if self._callback is not None:
            self._callback(0, None, None)

    def add_children(self, count: int) -> None:
        if self._callback is None or count <= 0:
            return
        if self._cancel_event is not None and self._cancel_event.is_set():
            raise _Cancelled()
        with self._lock:
            self._total_known += count

    def announce(self, kind: str | None, path: str | None) -> None:
        if self._callback is None:
            return
        if self._cancel_event is not None and self._cancel_event.is_set():
            raise _Cancelled()
        with self._lock:
            percent = self._percent
        self._callback(percent, kind, path)

    def mark_processed(self, kind: str | None, path: str | None) -> None:
        if self._callback is None:
            return
        if self._cancel_event is not None and self._cancel_event.is_set():
            raise _Cancelled()
        with self._lock:
            self._processed += 1
            total = max(self._total_known, 1)
            self._percent = min(int((self._processed / total) * 100), 100)
            percent = self._percent
        self._callback(percent, kind, path)


class TskMetadataScanner(MetadataScanner):
    """Implementacja skanera metadanych dla systemów plików obsługiwanych przez TSK."""

    def __init__(self, driver: DataSourceDriver, *, max_depth: int | None = None, max_workers: int = 1) -> None:
        self._driver = driver
        self._max_depth = max_depth
        self._max_workers = max(1, max_workers)
        self._logger = get_logger(__name__)
        self._thread_local: threading.local = threading.local()

    def scan(
        self,
        volume: Volume,
        *,
        progress: Callable[[int, str | None, str | None], None] | None = None,
        cancel_event: Event | None = None,
    ) -> MetadataResult:
        try:
            fs_handle = self._driver.open_filesystem(volume)
        except DriverError as exc:
            raise DriverError(f"Nie udało się otworzyć systemu plików wolumenu {volume.identifier}") from exc

        root_node = DirectoryNode(name="/", path=PurePosixPath("/"))
        volume_encryption = volume.encryption
        tracker = _ProgressTracker(progress, cancel_event)

        try:
            if self._max_workers > 1:
                totals = self._walk_directory_parallel(
                    volume,
                    root_node,
                    volume_encryption,
                    primary_handle=fs_handle,
                    tracker=tracker,
                    cancel_event=cancel_event,
                )
            else:
                totals = self._walk_directory_recursive(
                    fs_handle,
                    path="/",
                    node=root_node,
                    depth=0,
                    volume_encryption=volume_encryption,
                    tracker=tracker,
                    cancel_event=cancel_event,
                )
        except _Cancelled as exc:
            raise MetadataScanCancelled() from exc

        # Reset lokalnego cache'u uchwytów FS po zakończeniu skanowania.
        self._thread_local = threading.local()
        return MetadataResult(root=root_node, total_files=totals[0], total_directories=totals[1])

    # ------------------------------------------------------------------
    # Rekurencyjne przetwarzanie katalogów
    # ------------------------------------------------------------------

    def _walk_directory_recursive(
        self,
        fs_handle: pytsk3.FS_Info,
        *,
        path: str,
        node: DirectoryNode,
        depth: int,
        volume_encryption: EncryptionStatus,
        tracker: _ProgressTracker,
        cancel_event: Event | None,
    ) -> Tuple[int, int]:
        self._check_cancel(cancel_event)
        tracker.announce("directory", path)

        files, directories, children = self._process_directory(
            fs_handle,
            path=path,
            node=node,
            depth=depth,
            volume_encryption=volume_encryption,
            tracker=tracker,
            cancel_event=cancel_event,
        )
        tracker.mark_processed("directory", path)

        for child in children:
            self._check_cancel(cancel_event)
            child_files, child_dirs = self._walk_directory_recursive(
                fs_handle,
                path=child.path,
                node=child.node,
                depth=child.depth,
                volume_encryption=volume_encryption,
                tracker=tracker,
                cancel_event=cancel_event,
            )
            files += child_files
            directories += child_dirs

        return files, directories

    def _walk_directory_parallel(
        self,
        volume: Volume,
        root: DirectoryNode,
        volume_encryption: EncryptionStatus,
        *,
        primary_handle: pytsk3.FS_Info,
        tracker: _ProgressTracker,
        cancel_event: Event | None,
    ) -> Tuple[int, int]:
        totals = [0, 0]

        self._check_cancel(cancel_event)
        tracker.announce("directory", "/")

        root_files, root_directories, initial_children = self._process_directory(
            primary_handle,
            path="/",
            node=root,
            depth=0,
            volume_encryption=volume_encryption,
            tracker=tracker,
            cancel_event=cancel_event,
        )
        totals[0] += root_files
        totals[1] += root_directories
        tracker.mark_processed("directory", "/")

        if not initial_children:
            return totals[0], totals[1]

        def submit_item(executor: ThreadPoolExecutor, item: _WorkItem, futures: set) -> None:
            self._check_cancel(cancel_event)
            future = executor.submit(
                self._process_item,
                item,
                volume,
                volume_encryption,
                tracker,
                cancel_event,
            )
            futures.add(future)

        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            futures: set = set()
            for child in initial_children:
                submit_item(executor, child, futures)

            while futures:
                done, _ = wait(futures, return_when=FIRST_COMPLETED)
                for future in done:
                    futures.remove(future)
                    self._check_cancel(cancel_event)
                    files, directories, children, item_path = future.result()
                    totals[0] += files
                    totals[1] += directories
                    tracker.mark_processed("directory", item_path)
                    for child in children:
                        submit_item(executor, child, futures)

        return totals[0], totals[1]

    def _process_item(
        self,
        item: _WorkItem,
        volume: Volume,
        volume_encryption: EncryptionStatus,
        tracker: _ProgressTracker,
        cancel_event: Event | None,
    ) -> Tuple[int, int, List[_WorkItem], str]:
        self._check_cancel(cancel_event)
        fs_handle = self._fs_handle_for_thread(volume)
        files, directories, children = self._process_directory(
            fs_handle,
            path=item.path,
            node=item.node,
            depth=item.depth,
            volume_encryption=volume_encryption,
            tracker=tracker,
            cancel_event=cancel_event,
        )
        return files, directories, children, item.path

    def _process_directory(
        self,
        fs_handle: pytsk3.FS_Info,
        *,
        path: str,
        node: DirectoryNode,
        depth: int,
        volume_encryption: EncryptionStatus,
        tracker: _ProgressTracker | None,
        cancel_event: Event | None,
    ) -> Tuple[int, int, List[_WorkItem]]:
        total_files = 0
        total_directories = 1
        children: List[_WorkItem] = []

        self._check_cancel(cancel_event)
        try:
            directory = fs_handle.open_dir(path=path)
        except IOError as exc:  # pragma: no cover - zależne od obrazu
            self._logger.warning("directory-open-failed", path=path, error=str(exc))
            return (0, 0, [])

        for entry in directory:
            self._check_cancel(cancel_event)
            name_bytes = entry.info.name.name
            if not name_bytes:
                continue
            name = name_bytes.decode("utf-8", "replace")
            if name in {".", ".."}:
                continue

            meta = entry.info.meta
            if meta is None:
                continue

            child_path = (PurePosixPath(path) / name).as_posix()
            if tracker is not None:
                if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    tracker.announce("directory", child_path)
                else:
                    tracker.announce("file", child_path)

            if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                child_node = DirectoryNode(
                    name=name,
                    path=PurePosixPath(child_path),
                    owner=self._format_owner(meta.uid, meta.gid),
                    created_at=self._format_timestamp(meta.crtime),
                    changed_at=self._format_timestamp(getattr(meta, "ctime", None)),
                    modified_at=self._format_timestamp(meta.mtime),
                    accessed_at=self._format_timestamp(meta.atime),
                    attributes=self._extract_attributes(meta),
                )
                node.subdirectories.append(child_node)
                if self._max_depth is None or depth < self._max_depth:
                    children.append(_WorkItem(path=child_path, node=child_node, depth=depth + 1))
                else:
                    total_directories += 1
                continue

            metadata = FileMetadata(
                name=name,
                path=PurePosixPath(child_path),
                size=int(meta.size) if meta.size is not None else 0,
                owner=self._format_owner(meta.uid, meta.gid),
                created_at=self._format_timestamp(meta.crtime),
                changed_at=self._format_timestamp(getattr(meta, "ctime", None)),
                modified_at=self._format_timestamp(meta.mtime),
                accessed_at=self._format_timestamp(meta.atime),
                attributes=self._extract_attributes(meta),
                encryption=volume_encryption,
            )
            node.files.append(metadata)
            total_files += 1

        if tracker is not None:
            tracker.add_children(len(children))

        return total_files, total_directories, children

    def _fs_handle_for_thread(self, volume: Volume) -> pytsk3.FS_Info:
        handle = getattr(self._thread_local, "fs_handle", None)
        if handle is None:
            handle = self._driver.open_filesystem(volume)
            self._thread_local.fs_handle = handle
        return handle

    @staticmethod
    def _format_timestamp(value: int | None) -> str | None:
        if value is None or value <= 0:
            return None
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()

    @staticmethod
    def _format_owner(uid: int | None, gid: int | None) -> str | None:
        if uid is None and gid is None:
            return None

        username: str | None = None
        groupname: str | None = None
        if os.name != "nt":
            try:
                import grp  # type: ignore
                import pwd  # type: ignore

                if uid is not None:
                    try:
                        username = pwd.getpwuid(int(uid)).pw_name
                    except Exception:
                        username = None
                if gid is not None:
                    try:
                        groupname = grp.getgrgid(int(gid)).gr_name
                    except Exception:
                        groupname = None
            except Exception:
                username = None
                groupname = None

        uid_part: str | None = None
        gid_part: str | None = None
        if uid is not None:
            uid_part = f"{username} (uid={uid})" if username else f"uid={uid}"
        if gid is not None:
            gid_part = f"{groupname} (gid={gid})" if groupname else f"gid={gid}"
        return ",".join(part for part in (uid_part, gid_part) if part)

    def _extract_attributes(self, meta: pytsk3.TSK_FS_META) -> Tuple[str, ...]:
        attributes: List[str] = []
        mode_repr = self._format_mode(getattr(meta, "mode", None))
        if mode_repr:
            attributes.append(f"mode:{mode_repr}")

        flags = getattr(meta, "flags", 0)
        for flag, label in _FLAG_NAMES:
            if flag and flags & flag:
                attributes.append(label)

        # Usuwamy duplikaty, zachowując kolejność.
        return tuple(dict.fromkeys(attributes))

    @staticmethod
    def _format_mode(mode: int | None) -> str | None:
        if mode is None:
            return None
        try:
            return stat.filemode(mode)
        except ValueError:  # pragma: no cover - wartości spoza zakresu POSIX
            return None

    @staticmethod
    def _check_cancel(cancel_event: Event | None) -> None:
        if cancel_event is not None and cancel_event.is_set():
            raise _Cancelled()


__all__ = ["TskMetadataScanner"]
