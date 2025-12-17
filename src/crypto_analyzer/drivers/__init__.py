"""Adaptery źródeł danych (dyski fizyczne, obrazy)."""

from .base import DataSourceDriver, DriverCapabilities, DriverError

__all__ = [
	"DataSourceDriver",
	"DriverCapabilities",
	"DriverError",
]

try:  # pragma: no cover - zależne od obecności pytsk3
    from .tsk import TskImageDriver, TskPhysicalDiskDriver

    __all__.extend(["TskImageDriver", "TskPhysicalDiskDriver"])
except ImportError:  # pragma: no cover - środowisko bez pytsk3
    TskImageDriver = None  # type: ignore[assignment]
    TskPhysicalDiskDriver = None  # type: ignore[assignment]
