"""Integration test against generated disk images (WSL2).

This test is optional:
- It runs only when pytsk3 is available AND the generated images exist.
- It validates that the analysis pipeline does not crash on UNKNOWN FS volumes.

Generate images (Windows + WSL2):
- `powershell -File scripts/generate_test_images_wsl.ps1`
"""

from __future__ import annotations

from pathlib import Path

import pytest


def _has_real_pytsk3() -> bool:
    try:
        import pytsk3  # type: ignore

        return getattr(pytsk3, "__file__", None) is not None
    except Exception:
        return False


@pytest.mark.skipif(not _has_real_pytsk3(), reason="requires real pytsk3")
def test_generated_multi_volume_image_pipeline_does_not_crash(tmp_path) -> None:
    image = Path(__file__).parent.parent / "test_assets" / "generated" / "multi_volume.img"
    if not image.exists():
        pytest.skip("generated image missing; run scripts/generate_test_images_wsl.ps1")

    from crypto_analyzer.core import AnalysisManager
    from crypto_analyzer.crypto_detection import HeuristicEncryptionDetector, SignatureBasedDetector
    from crypto_analyzer.drivers import TskImageDriver
    from crypto_analyzer.fs_detection import TskFileSystemDetector
    from crypto_analyzer.metadata import TskMetadataScanner
    from crypto_analyzer.reporting import DefaultReportExporter

    driver = TskImageDriver(image_paths=[image])
    try:
        sources = list(driver.enumerate_sources())
        assert sources, "expected at least one source"

        manager = AnalysisManager(
            driver=driver,
            filesystem_detector=TskFileSystemDetector(driver),
            encryption_detectors=[SignatureBasedDetector(driver), HeuristicEncryptionDetector(driver)],
            metadata_scanner=TskMetadataScanner(driver, max_depth=0),
            report_exporter=DefaultReportExporter(),
        )

        session = manager.start_session(sources[0])
        volume_ids = [v.identifier for v in session.volumes]
        assert volume_ids, "expected at least one volume"

        # The key assertion: pipeline completes even if some volumes are UNKNOWN FS.
        result = manager.analyze(volume_ids, collect_metadata=True)
        assert result.volumes, "expected volume analyses"
    finally:
        driver.close()
