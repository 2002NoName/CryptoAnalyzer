"""Filesystem detection benchmark (optional).

This benchmark validates `TskFileSystemDetector` against generated test images.

It requires:
- real `pytsk3` available,
- a generated disk image with at least one formatted partition.

By default we look for:
- `test_assets/generated/multi_volume.img`

Tip (Windows):
- you can generate a suitable image with `scripts/generate_test_images_windows.py`.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from crypto_analyzer.core.models import FileSystemType
from crypto_analyzer.drivers import TskImageDriver
from crypto_analyzer.fs_detection import TskFileSystemDetector


@dataclass(frozen=True, slots=True)
class FileSystemBenchmarkResult:
    name: str
    image: str
    detected: dict[str, str]
    metrics: dict[str, float]

    def to_dict(self) -> dict:
        return asdict(self)


def run_filesystem_benchmark(*, image_path: Path) -> FileSystemBenchmarkResult:
    driver = TskImageDriver(image_paths=[Path(image_path)])
    try:
        sources = list(driver.enumerate_sources())
        if not sources:
            raise RuntimeError("No sources found for image")

        driver.open_source(sources[0])
        volumes = list(driver.list_volumes())
        if not volumes:
            raise RuntimeError("No volumes found in image")

        detector = TskFileSystemDetector(driver)

        detected: dict[str, str] = {}
        known = 0
        for volume in volumes:
            fs = detector.detect(volume)
            detected[volume.identifier] = fs.value
            if fs is not FileSystemType.UNKNOWN:
                known += 1

        coverage = known / max(len(volumes), 1)
        if known == 0:
            raise RuntimeError(
                "No known filesystem detected in image. "
                "Generate a proper partitioned image (e.g. via WSL2 generator or "
                "scripts/generate_test_images_windows.py) and rerun."
            )
        return FileSystemBenchmarkResult(
            name="filesystem_detection",
            image=str(image_path),
            detected=detected,
            metrics={"known_fs_coverage": float(coverage)},
        )
    finally:
        driver.close()
