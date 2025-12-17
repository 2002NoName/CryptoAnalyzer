"""Testy modułu skanowania metadanych TSK."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Dict, Iterable, List

import pytsk3

from crypto_analyzer.core.models import DirectoryNode, EncryptionStatus, FileSystemType, Volume
from crypto_analyzer.metadata import TskMetadataScanner


class FakeMeta:
    def __init__(
        self,
        *,
        meta_type: int,
        size: int = 0,
        uid: int | None = None,
        gid: int | None = None,
        flags: int = 0,
        mode: int | None = None,
        crtime: int | None = None,
        ctime: int | None = None,
        mtime: int | None = None,
        atime: int | None = None,
    ) -> None:
        self.type = meta_type
        self.size = size
        self.uid = uid
        self.gid = gid
        self.flags = flags
        self.mode = mode
        self.crtime = crtime
        self.ctime = ctime
        self.mtime = mtime
        self.atime = atime


class FakeDirEntry:
    def __init__(self, name: str, meta: FakeMeta) -> None:
        self.info = SimpleNamespace(name=SimpleNamespace(name=name.encode("utf-8")), meta=meta)


class FakeDirectory:
    def __init__(self, entries: Iterable[FakeDirEntry]) -> None:
        self._entries = list(entries)

    def __iter__(self):
        return iter(self._entries)


class FakeFSInfo:
    def __init__(self, tree: Dict[str, List[FakeDirEntry]]) -> None:
        self._tree = tree

    def open_dir(self, path: str) -> FakeDirectory:
        try:
            entries = self._tree[path]
        except KeyError as exc:
            raise IOError(f"Path {path} not found") from exc
        return FakeDirectory(entries)


class StubDriver:
    """Minimalny sterownik zwracający wirtualny system plików."""

    def __init__(self, tree: Dict[str, List[FakeDirEntry]]) -> None:
        self._tree = tree

    def open_filesystem(self, volume: Volume) -> FakeFSInfo:  # type: ignore[override]
        return FakeFSInfo(self._tree)


def _build_volume() -> Volume:
    volume = Volume(identifier="vol1", offset=0, size=4096, filesystem=FileSystemType.NTFS)
    volume.encryption = EncryptionStatus.ENCRYPTED
    return volume


def _build_tree() -> Dict[str, List[FakeDirEntry]]:
    root_entries = [
        FakeDirEntry(
            "documents",
            FakeMeta(
                meta_type=pytsk3.TSK_FS_META_TYPE_DIR,
                flags=pytsk3.TSK_FS_META_FLAG_ALLOC,
                uid=0,
                gid=0,
                mtime=1_700_000_010,
            ),
        ),
        FakeDirEntry(
            "report.txt",
            FakeMeta(
                meta_type=pytsk3.TSK_FS_META_TYPE_REG,
                size=256,
                uid=1000,
                gid=1000,
                flags=pytsk3.TSK_FS_META_FLAG_ALLOC,
                mode=0o100644,
                crtime=1_700_000_000,
                ctime=1_700_000_050,
                mtime=1_700_000_100,
                atime=1_700_000_200,
            ),
        ),
    ]

    documents_entries = [
        FakeDirEntry(
            "secret.bin",
            FakeMeta(
                meta_type=pytsk3.TSK_FS_META_TYPE_REG,
                size=512,
                flags=pytsk3.TSK_FS_META_FLAG_UNALLOC,
                mode=0o100600,
            ),
        )
    ]

    return {
        "/": root_entries,
        "/documents": documents_entries,
    }


def test_scanner_collects_metadata_sequential() -> None:
    tree = _build_tree()
    driver = StubDriver(tree)
    scanner = TskMetadataScanner(driver, max_workers=1)
    volume = _build_volume()

    result = scanner.scan(volume)

    assert result.total_files == 2
    assert result.total_directories == 2  # root + documents

    root_node = result.root
    assert isinstance(root_node, DirectoryNode)
    assert len(root_node.files) == 1

    file_meta = root_node.files[0]
    assert file_meta.name == "report.txt"
    assert file_meta.size == 256
    assert file_meta.encryption == EncryptionStatus.ENCRYPTED
    assert file_meta.changed_at is not None
    assert any(attr.startswith("mode:") for attr in file_meta.attributes)
    assert "alloc" in file_meta.attributes

    documents = root_node.subdirectories[0]
    assert documents.name == "documents"
    assert documents.owner is not None
    assert "alloc" in documents.attributes
    assert len(documents.files) == 1
    child_file = documents.files[0]
    assert "unalloc" in child_file.attributes


def test_scanner_parallel_matches_sequential() -> None:
    tree = _build_tree()
    driver = StubDriver(tree)
    scanner = TskMetadataScanner(driver, max_workers=3)
    volume = _build_volume()

    result = scanner.scan(volume)

    assert result.total_files == 2
    assert result.total_directories == 2
    root_node = result.root
    assert root_node.files[0].encryption == EncryptionStatus.ENCRYPTED
    assert root_node.subdirectories[0].files[0].attributes[0].startswith("mode:")
