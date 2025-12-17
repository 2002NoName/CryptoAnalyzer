"""Adaptery źródeł danych (dyski fizyczne, obrazy)."""

from .base import DataSourceDriver, DriverCapabilities, DriverError
from .bitlocker import BitLockerUnlockingDriver
from .filevault2 import FileVault2UnlockingDriver

__all__ = [
	"DataSourceDriver",
	"DriverCapabilities",
	"DriverError",
	"BitLockerUnlockingDriver",
	"FileVault2UnlockingDriver",
]

try:  # pragma: no cover - zależne od obecności pytsk3
    from .tsk import TskImageDriver, TskPhysicalDiskDriver

    __all__.extend(["TskImageDriver", "TskPhysicalDiskDriver"])
except ImportError:  # pragma: no cover - środowisko bez pytsk3
    TskImageDriver = None  # type: ignore[assignment]
    TskPhysicalDiskDriver = None  # type: ignore[assignment]
