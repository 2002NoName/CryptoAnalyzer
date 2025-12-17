"""Pytest configuration and lightweight stubs for optional runtime deps.

These tests are intended to run in environments where heavy/native dependencies
(e.g. pytsk3, structlog, PySide6) may not be installed.

When those deps are present, the real modules are used.
When absent, we provide minimal stubs sufficient for importing the code under
unit test.
"""

from __future__ import annotations

import sys
import types


def _install_structlog_stub() -> None:
    try:
        import structlog  # noqa: F401

        return
    except Exception:
        pass

    structlog = types.ModuleType("structlog")

    class _DummyLogger:
        def bind(self, **_kw):
            return self

        def debug(self, *_a, **_kw):
            return None

        def info(self, *_a, **_kw):
            return None

        def warning(self, *_a, **_kw):
            return None

        def error(self, *_a, **_kw):
            return None

        def exception(self, *_a, **_kw):
            return None

    def get_logger(*_a, **_kw):
        return _DummyLogger()

    structlog.get_logger = get_logger  # type: ignore[attr-defined]
    structlog.configure = lambda *_a, **_kw: None  # type: ignore[attr-defined]

    processors = types.ModuleType("structlog.processors")

    class TimeStamper:  # pragma: no cover - trivial stub
        def __init__(self, *_a, **_kw):
            pass

        def __call__(self, *_a, **_kw):
            return None

    processors.TimeStamper = TimeStamper  # type: ignore[attr-defined]
    processors.StackInfoRenderer = lambda *_a, **_kw: (lambda *_a, **_kw: None)  # type: ignore[attr-defined]
    processors.format_exc_info = lambda *_a, **_kw: None  # type: ignore[attr-defined]

    stdlib = types.ModuleType("structlog.stdlib")

    class BoundLogger(_DummyLogger):
        pass

    stdlib.BoundLogger = BoundLogger  # type: ignore[attr-defined]
    stdlib.add_log_level = lambda *_a, **_kw: None  # type: ignore[attr-defined]

    class ProcessorFormatter:  # pragma: no cover - trivial stub
        @staticmethod
        def wrap_for_formatter(*_a, **_kw):
            return None

    stdlib.ProcessorFormatter = ProcessorFormatter  # type: ignore[attr-defined]

    class LoggerFactory:  # pragma: no cover - trivial stub
        def __call__(self, *_a, **_kw):
            return _DummyLogger()

    stdlib.LoggerFactory = LoggerFactory  # type: ignore[attr-defined]

    structlog.processors = processors  # type: ignore[attr-defined]
    structlog.stdlib = stdlib  # type: ignore[attr-defined]

    sys.modules.setdefault("structlog", structlog)
    sys.modules.setdefault("structlog.processors", processors)
    sys.modules.setdefault("structlog.stdlib", stdlib)


def _install_pytsk3_stub() -> None:
    try:
        import pytsk3  # noqa: F401

        return
    except Exception:
        pass

    pytsk3 = types.ModuleType("pytsk3")

    # FS meta types
    pytsk3.TSK_FS_META_TYPE_DIR = 1  # type: ignore[attr-defined]
    pytsk3.TSK_FS_META_TYPE_REG = 2  # type: ignore[attr-defined]

    # FS meta flags used by the scanner
    pytsk3.TSK_FS_META_FLAG_ALLOC = 0x01  # type: ignore[attr-defined]
    pytsk3.TSK_FS_META_FLAG_UNALLOC = 0x02  # type: ignore[attr-defined]
    pytsk3.TSK_FS_META_FLAG_COMP = 0x04  # type: ignore[attr-defined]
    pytsk3.TSK_FS_META_FLAG_ORPHAN = 0x08  # type: ignore[attr-defined]
    pytsk3.TSK_FS_META_FLAG_APP = 0x10  # type: ignore[attr-defined]

    # FS type constants for fs detection mapping
    pytsk3.TSK_FS_TYPE_NTFS = 0x0001  # type: ignore[attr-defined]
    pytsk3.TSK_FS_TYPE_EXT2 = 0x0002  # type: ignore[attr-defined]
    pytsk3.TSK_FS_TYPE_EXT3 = 0x0004  # type: ignore[attr-defined]
    pytsk3.TSK_FS_TYPE_EXT4 = 0x0008  # type: ignore[attr-defined]
    pytsk3.TSK_FS_TYPE_FAT12 = 0x0010  # type: ignore[attr-defined]
    pytsk3.TSK_FS_TYPE_FAT16 = 0x0020  # type: ignore[attr-defined]
    pytsk3.TSK_FS_TYPE_FAT32 = 0x0040  # type: ignore[attr-defined]
    pytsk3.TSK_FS_TYPE_EXFAT = 0x0080  # type: ignore[attr-defined]
    pytsk3.TSK_FS_TYPE_APFS = 0x0100  # type: ignore[attr-defined]
    pytsk3.TSK_FS_TYPE_HFS = 0x0200  # type: ignore[attr-defined]
    pytsk3.TSK_FS_TYPE_ISO9660 = 0x0400  # type: ignore[attr-defined]
    pytsk3.TSK_FS_TYPE_FFS1 = 0x0800  # type: ignore[attr-defined]
    pytsk3.TSK_FS_TYPE_FFS1B = 0x1000  # type: ignore[attr-defined]
    pytsk3.TSK_FS_TYPE_FFS2 = 0x2000  # type: ignore[attr-defined]

    class TSK_FS_META:  # pragma: no cover
        pass

    pytsk3.TSK_FS_META = TSK_FS_META  # type: ignore[attr-defined]

    class Img_Info:  # pragma: no cover
        def __init__(self, _path: str | None = None, *, url: str | None = None):
            self._path = _path
            self._url = url

        def read(self, _offset: int, size: int) -> bytes:
            return b"\x00" * int(size)

        def get_size(self) -> int:
            return 0

    pytsk3.Img_Info = Img_Info  # type: ignore[attr-defined]

    class _VolumeInfoInfo:  # pragma: no cover
        block_size = 512

    class Volume_Info:  # pragma: no cover
        def __init__(self, _img):
            self.info = _VolumeInfoInfo()

        def __iter__(self):
            return iter(())

    pytsk3.Volume_Info = Volume_Info  # type: ignore[attr-defined]

    class FS_Info:  # pragma: no cover
        def __init__(self, _img, *, offset: int = 0):
            self.offset = offset

            class _Info:
                ftype = 0

            self.info = _Info()

        def open_dir(self, *, path: str):
            raise IOError("stub")

    pytsk3.FS_Info = FS_Info  # type: ignore[attr-defined]

    sys.modules.setdefault("pytsk3", pytsk3)


_install_structlog_stub()
_install_pytsk3_stub()
