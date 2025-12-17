"""BitLocker unlocking adapter for TSK-based analysis.

This driver wrapper optionally uses libbde's Python bindings (pybde) to expose
decrypted volume bytes to pytsk3.

The wrapper is intentionally best-effort:
- If pybde is unavailable, it falls back to the wrapped driver.
- If unlocking fails, it falls back to the wrapped driver.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

try:  # pragma: no cover - zależne od obecności pytsk3
    import pytsk3  # type: ignore
except ImportError:  # pragma: no cover - środowisko bez pytsk3
    pytsk3 = None  # type: ignore[assignment]

from crypto_analyzer.core.models import DiskSource, Volume

from .base import DataSourceDriver, DriverCapabilities, DriverError


@dataclass(slots=True)
class _BoundedFileView:
    """A file-like view exposing a volume region from an underlying driver."""

    driver: DataSourceDriver
    base_offset: int
    size: int
    _pos: int = field(init=False, default=0)

    def __post_init__(self) -> None:
        self._pos = 0

    def read(self, size: int = -1) -> bytes:  # noqa: A003 - matches file API
        if size is None or size < 0:
            size = self.size - self._pos
        size = max(0, min(int(size), self.size - self._pos))
        if size == 0:
            return b""
        data = self.driver.read(self.base_offset + self._pos, size)
        self._pos += len(data)
        return data

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            new_pos = int(offset)
        elif whence == 1:
            new_pos = self._pos + int(offset)
        elif whence == 2:
            new_pos = self.size + int(offset)
        else:
            raise ValueError("Invalid whence")

        self._pos = max(0, min(new_pos, self.size))
        return self._pos

    def tell(self) -> int:
        return self._pos


if pytsk3 is not None:  # pragma: no cover - import-time branching

    class _PybdeImgInfo(pytsk3.Img_Info):
        """pytsk3 image backed by a pybde volume (decrypted bytes)."""

        def __init__(self, bde_volume: Any):
            super().__init__(url="")
            self._bde_volume = bde_volume

        def close(self) -> None:  # pragma: no cover - depends on pytsk3 internals
            try:
                self._bde_volume.close()
            except Exception:
                pass

        def read(self, offset: int, size: int) -> bytes:  # type: ignore[override]
            try:
                return self._bde_volume.read_buffer_at_offset(size, offset)
            except Exception as exc:
                raise IOError("Failed to read decrypted data") from exc

        def get_size(self) -> int:  # type: ignore[override]
            return int(self._bde_volume.get_size())

else:

    class _PybdeImgInfo:  # type: ignore[no-redef]
        pass


class BitLockerUnlockingDriver:
    """Driver wrapper that can unlock BitLocker volumes using a recovery key."""

    name = "bitlocker-unlocking"

    def __init__(
        self,
        wrapped: DataSourceDriver,
        *,
        recovery_keys: dict[str, str] | None = None,
        passwords: dict[str, str] | None = None,
        startup_key_paths: dict[str, str] | None = None,
    ) -> None:
        self._wrapped = wrapped
        self._recovery_keys = {k: v for k, v in (recovery_keys or {}).items() if v}
        self._passwords = {k: v for k, v in (passwords or {}).items() if v}
        self._startup_key_paths = {k: v for k, v in (startup_key_paths or {}).items() if v}
        self._unlocked: dict[str, tuple[Any, _PybdeImgInfo]] = {}

        wrapped_caps = getattr(wrapped, "capabilities", DriverCapabilities())
        self.capabilities = wrapped_caps

    # ------------------------------------------------------------------
    # Delegate base operations
    # ------------------------------------------------------------------

    def enumerate_sources(self) -> Iterable[DiskSource]:
        return self._wrapped.enumerate_sources()

    def open_source(self, source: DiskSource) -> None:
        self._unlocked.clear()
        self._wrapped.open_source(source)

    def close(self) -> None:
        for _, (bde_volume, img) in list(self._unlocked.items()):
            try:
                img.close()
            except Exception:
                pass
            try:
                bde_volume.close()
            except Exception:
                pass
        self._unlocked.clear()
        self._wrapped.close()

    def list_volumes(self) -> Iterable[Volume]:
        return self._wrapped.list_volumes()

    def read(self, offset: int, size: int) -> bytes:
        return self._wrapped.read(offset, size)

    # ------------------------------------------------------------------
    # Filesystem access (where unlocking matters)
    # ------------------------------------------------------------------

    def open_filesystem(self, volume: Volume) -> Any:
        if pytsk3 is None:
            return self._wrapped.open_filesystem(volume)
        unlocked = self._get_or_try_unlock(volume)
        if unlocked is None:
            return self._wrapped.open_filesystem(volume)
        _, img = unlocked
        try:
            return pytsk3.FS_Info(img, offset=0)
        except (IOError, RuntimeError) as exc:
            raise DriverError(f"Nie udało się otworzyć systemu plików (po odszyfrowaniu) wolumenu {volume.identifier}") from exc

    def _get_or_try_unlock(self, volume: Volume) -> tuple[Any, _PybdeImgInfo] | None:
        if volume.identifier in self._unlocked:
            return self._unlocked[volume.identifier]

        if pytsk3 is None:
            return None

        volume_id = volume.identifier
        startup_key_path = self._startup_key_paths.get(volume_id)
        recovery_key = self._recovery_keys.get(volume_id)
        password = self._passwords.get(volume_id)
        if not any((startup_key_path, recovery_key, password)):
            return None

        try:
            import pybde  # type: ignore
        except Exception:
            return None

        file_view = _BoundedFileView(
            driver=self._wrapped,
            base_offset=volume.offset,
            size=volume.size,
        )

        try:
            bde_volume = pybde.open_file_object(file_view)

            if startup_key_path:
                bde_volume.read_startup_key(startup_key_path)
            if recovery_key:
                bde_volume.set_recovery_password(recovery_key)
            if password:
                bde_volume.set_password(password)

            unlocked = bde_volume.unlock()
            if not unlocked:
                try:
                    bde_volume.close()
                except Exception:
                    pass
                return None
            img = _PybdeImgInfo(bde_volume)
            self._unlocked[volume.identifier] = (bde_volume, img)
            return self._unlocked[volume.identifier]
        except Exception:
            try:
                bde_volume.close()  # type: ignore[name-defined]
            except Exception:
                pass
            return None


__all__ = ["BitLockerUnlockingDriver"]
