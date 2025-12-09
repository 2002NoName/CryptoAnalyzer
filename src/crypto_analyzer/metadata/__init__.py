"""Skanowanie struktur katalogów i zbieranie metadanych."""

from .scanner import MetadataResult, MetadataScanner

__all__ = ["MetadataScanner", "MetadataResult"]

try:  # pragma: no cover - zależne od obecności pytsk3
	from .tsk_scanner import TskMetadataScanner

	__all__.append("TskMetadataScanner")
except ImportError:  # pragma: no cover - środowisko bez pytsk3
	TskMetadataScanner = None  # type: ignore[assignment]
