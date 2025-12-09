"""Interfejs wiersza poleceń do uruchamiania analiz."""

from __future__ import annotations

import sys
from argparse import ArgumentParser, Namespace
from pathlib import Path

import structlog

from crypto_analyzer.core import AnalysisManager
from crypto_analyzer.crypto_detection import BitLockerDetector, SignatureBasedDetector
from crypto_analyzer.drivers import TskImageDriver
from crypto_analyzer.fs_detection import TskFileSystemDetector
from crypto_analyzer.metadata import TskMetadataScanner
from crypto_analyzer.reporting import DefaultReportExporter, ExportFormat
from crypto_analyzer.shared import configure_logging


def _build_parser() -> ArgumentParser:
    parser = ArgumentParser(
        prog="crypto-analyzer",
        description="Narzędzie do analizy dysków i obrazów dysków pod kątem szyfrowania.",
    )
    parser.add_argument(
        "image",
        type=Path,
        help="Ścieżka do obrazu dysku (RAW, E01, VHD, itp.)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("report.json"),
        help="Ścieżka do pliku wynikowego (domyślnie: report.json)",
    )
    parser.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        help="Format raportu (domyślnie: json)",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        help="Maksymalna głębokość skanowania katalogów (domyślnie: bez limitu)",
    )
    parser.add_argument(
        "--skip-metadata",
        action="store_true",
        help="Pomija zbieranie metadanych plików i katalogów",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Wyświetla szczegółowe logi",
    )
    return parser


def _run_analysis(args: Namespace) -> int:
    logger = structlog.get_logger(__name__)

    if not args.image.exists():
        logger.error("image-not-found", path=str(args.image))
        return 1

    try:
        driver = TskImageDriver(image_paths=[args.image])
        fs_detector = TskFileSystemDetector(driver)
        crypto_detectors = [SignatureBasedDetector(driver)]
        metadata_scanner = TskMetadataScanner(driver, max_depth=args.max_depth)
        exporter = DefaultReportExporter()

        manager = AnalysisManager(
            driver=driver,
            filesystem_detector=fs_detector,
            encryption_detectors=crypto_detectors,
            metadata_scanner=metadata_scanner,
            report_exporter=exporter,
        )

        logger.info("starting-analysis", image=str(args.image))
        sources = list(driver.enumerate_sources())
        if not sources:
            logger.error("no-sources-found")
            return 1

        session = manager.start_session(sources[0])
        volume_ids = [vol.identifier for vol in session.volumes]

        if not volume_ids:
            logger.warning("no-volumes-detected")
            return 0

        logger.info("analyzing-volumes", count=len(volume_ids))
        result = manager.analyze(volume_ids, collect_metadata=not args.skip_metadata)

        fmt = ExportFormat.JSON if args.format == "json" else ExportFormat.CSV
        output_path = manager.export_report(result, args.output, fmt)

        logger.info(
            "analysis-complete",
            volumes=len(result.volumes),
            files=result.total_files(),
            directories=result.total_directories(),
            report=str(output_path),
        )
        return 0

    except Exception as exc:  # pragma: no cover - obsługa błędów środowiskowych
        logger.exception("analysis-failed", error=str(exc))
        return 1
    finally:
        manager.close()


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    configure_logging(level=10 if args.verbose else 20)
    return _run_analysis(args)


if __name__ == "__main__":
    sys.exit(main())
