"""Logika wykrywania systemów plików i wolumenów."""

from .detector import FileSystemDetector, FileSystemSignature

__all__ = ["FileSystemDetector", "FileSystemSignature"]

try:  # pragma: no cover - zależne od obecności pytsk3
	from .tsk import TskFileSystemDetector

	__all__.append("TskFileSystemDetector")
except ImportError:  # pragma: no cover - środowisko bez pytsk3
	TskFileSystemDetector = None  # type: ignore[assignment]
