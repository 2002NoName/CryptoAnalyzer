"""Heurystyczne wykrywanie szyfrowania.

Celem heurystyk jest dostarczenie "miękkiego" rozpoznania w sytuacji, gdy
sygnatury (magic bytes) nie są dostępne lub są niewystarczające.

Aktualnie implementujemy prostą, praktyczną heurystykę opartą o entropię
Shannona oraz wykrywanie danych "pustych" (np. wypełnionych zerami).

Uwaga: heurystyki są z natury niedoskonałe. W związku z tym zwracamy wynik
ENCRYPTED tylko wtedy, gdy sygnał jest silny (bardzo wysoka entropia i brak
wykrytego systemu plików).
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from crypto_analyzer.core.models import EncryptionStatus, FileSystemType, Volume
from crypto_analyzer.drivers import DataSourceDriver, DriverError

from .detectors import EncryptionDetector, EncryptionFinding


@dataclass(frozen=True, slots=True)
class HeuristicConfig:
    sample_size: int = 64 * 1024
    min_sample_size: int = 4 * 1024
    high_entropy_threshold: float = 7.85
    low_entropy_threshold: float = 1.0
    mostly_same_byte_threshold: float = 0.90
    mostly_zero_threshold: float = 0.98


class HeuristicEncryptionDetector(EncryptionDetector):
    """Detektor heurystyczny bazujący na entropii i prostych statystykach bajtów."""

    name = "heuristic"

    def __init__(self, driver: DataSourceDriver, *, config: HeuristicConfig | None = None) -> None:
        self._driver = driver
        self._config = config or HeuristicConfig()

    def analyze_volume(self, volume: Volume) -> EncryptionFinding:
        if volume.filesystem is not FileSystemType.UNKNOWN:
            return EncryptionFinding(
                status=EncryptionStatus.NOT_DETECTED,
                details=f"Heurystyka: wykryto system plików {volume.filesystem.value}",
            )

        try:
            sample = self._read_sample(volume)
        except DriverError:
            return EncryptionFinding(status=EncryptionStatus.UNKNOWN, details="Heurystyka: błąd odczytu")

        if len(sample) < self._config.min_sample_size:
            return EncryptionFinding(status=EncryptionStatus.UNKNOWN, details="Heurystyka: zbyt mała próbka")

        entropy = _shannon_entropy(sample)
        stats = _byte_stats(sample)

        if stats["zero_fraction"] >= self._config.mostly_zero_threshold and entropy <= self._config.low_entropy_threshold:
            return EncryptionFinding(
                status=EncryptionStatus.UNKNOWN,
                details=(
                    "Heurystyka: próbka wygląda na puste/wyzerowane dane "
                    f"(entropy={entropy:.2f}, zero_fraction={stats['zero_fraction']:.2f})"
                ),
            )

        if stats["max_byte_fraction"] >= self._config.mostly_same_byte_threshold and entropy <= 2.0:
            return EncryptionFinding(
                status=EncryptionStatus.NOT_DETECTED,
                details=(
                    "Heurystyka: dane mają niską zmienność "
                    f"(entropy={entropy:.2f}, max_byte_fraction={stats['max_byte_fraction']:.2f})"
                ),
            )

        if entropy >= self._config.high_entropy_threshold:
            return EncryptionFinding(
                status=EncryptionStatus.ENCRYPTED,
                algorithm="Heuristic",
                details=(
                    "Heurystyka: bardzo wysoka entropia i brak rozpoznanego FS "
                    f"(entropy={entropy:.2f}, max_byte_fraction={stats['max_byte_fraction']:.2f})"
                ),
            )

        return EncryptionFinding(
            status=EncryptionStatus.UNKNOWN,
            details=f"Heurystyka: niejednoznaczne (entropy={entropy:.2f})",
        )

    def _read_sample(self, volume: Volume) -> bytes:
        size = max(int(volume.size), 0)
        sample_size = min(self._config.sample_size, size) if size > 0 else self._config.sample_size

        offsets = [0]
        if size > 0:
            offsets.append(max((size // 2) - (sample_size // 2), 0))
            offsets.append(max(size - sample_size, 0))

        chunks: list[bytes] = []
        for off in offsets:
            if size > 0:
                max_len = max(size - off, 0)
                to_read = min(sample_size, max_len)
                if to_read <= 0:
                    continue
            else:
                to_read = sample_size
            chunks.append(self._driver.read(volume.offset + off, to_read))

        return b"".join(chunks)


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    length = len(data)
    entropy = 0.0
    for c in counts:
        if c == 0:
            continue
        p = c / length
        entropy -= p * math.log2(p)
    return entropy


def _byte_stats(data: bytes) -> dict[str, float]:
    if not data:
        return {"zero_fraction": 0.0, "max_byte_fraction": 0.0}

    counts = [0] * 256
    zero = 0
    for b in data:
        counts[b] += 1
        if b == 0:
            zero += 1

    length = len(data)
    return {
        "zero_fraction": zero / length,
        "max_byte_fraction": max(counts) / length,
    }


__all__ = ["HeuristicConfig", "HeuristicEncryptionDetector"]
